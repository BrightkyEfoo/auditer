import { Prisma, withTenant, type PrismaClient } from "@auditer/db";
import { dropObjects } from "./objects.js";
import { consoleLogger, type PurgeLogger } from "./logger.js";

/**
 * Retention purge — the code behind the durations published in
 * apps/web/lib/legal.ts. A duration announced in a privacy policy with nothing
 * enforcing it is not a retention policy, it is a sentence.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * SCHEDULED, since the BullMQ Job Scheduler in apps/worker/src/retention-
 * scheduler.ts. It used to live in the api as a Nest service reachable only
 * through POST /api/admin/retention/purge, and the privacy policy said so in
 * as many words. It was moved HERE, into a framework-free package, so the
 * worker can call it in-process:
 *
 *   - no internal HTTP hop between two containers that already share a
 *     database, and therefore no failure mode where the purge silently stops
 *     because the api is rolling;
 *   - no ADMIN_PURGE_TOKEN handed to a second process. The manual endpoint
 *     keeps its shared secret because it is reachable from outside; the
 *     scheduler needs no credential at all.
 *
 * Nothing here was Nest-specific: the service depended on the framework only
 * for @Injectable and Logger. The api's RetentionService is now a six-line
 * adapter over this function, so the endpoint and the scheduler run the exact
 * same code — the one property that makes "purge on demand" and "purge every
 * night" the same promise.
 * ─────────────────────────────────────────────────────────────────────────
 */

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * The published durations, in one place. Changing a number here without
 * changing the corresponding sentence in apps/web/lib/legal.ts reopens exactly
 * the gap this file was written to close.
 */
export const RETENTION = {
  /** "Journaux d'exécution des scanners et journaux techniques : 90 jours." */
  scannerLogsMs: 90 * DAY_MS,
  /** "Findings et rapports : 24 mois à compter du run." 24 months ≈ 730 days. */
  runMs: 730 * DAY_MS,
  /** "Attestations de propriété de domaine … : 24 mois." */
  attestationMs: 730 * DAY_MS,
} as const;

/**
 * Artifact types that ARE scanner execution logs, and therefore expire at 90
 * days rather than following their run to 24 months. `raw` is the scanner's own
 * output stream; `log` is the container log. `sarif`, `sbom`, `report` and
 * `pdf` are findings and deliverables — they are the 24-month family.
 */
const SCANNER_LOG_TYPES = ["log", "raw"] as const;

/** `action` written on every ActivityLog row this purge produces. */
export const PURGE_ACTIVITY_ACTION = "retention.purge";

export interface PurgeReport {
  dryRun: boolean;
  organizations: number;
  /** Runs past 24 months. Findings, scans, pillar results and reports go with them. */
  runs: number;
  /** Scanner log / raw-output artifacts past 90 days. */
  scannerLogArtifacts: number;
  /** Artifacts whose `retentionExpiresAt` has passed, whatever their type. */
  expiredArtifacts: number;
  /** Scan rows whose error payload (the scanner's messages) was blanked. */
  scanErrorsScrubbed: number;
  /** Événements de relevé (transitions de phase, notes) passés 90 jours. */
  runEvents: number;
  /** DAST authorization attestations past 24 months. */
  attestations: number;
  /** Session rows past their own expiry — the 30 days announced in the cookie policy. */
  expiredSessions: number;
  /** Objects actually removed from the bucket. */
  storageObjects: number;
  /** Wall-clock duration, so a purge that starts taking hours is visible. */
  durationMs: number;
}

/** Per-organization slice of the report, as written to `activity_logs.detail`. */
interface OrgCounts {
  runs: number;
  scannerLogArtifacts: number;
  expiredArtifacts: number;
  scanErrorsScrubbed: number;
  runEvents: number;
  attestations: number;
  storageObjects: number;
}

function emptyReport(dryRun: boolean): PurgeReport {
  return {
    dryRun,
    organizations: 0,
    runs: 0,
    scannerLogArtifacts: 0,
    expiredArtifacts: 0,
    scanErrorsScrubbed: 0,
    runEvents: 0,
    attestations: 0,
    expiredSessions: 0,
    storageObjects: 0,
    durationMs: 0,
  };
}

function emptyCounts(): OrgCounts {
  return {
    runs: 0,
    scannerLogArtifacts: 0,
    expiredArtifacts: 0,
    scanErrorsScrubbed: 0,
    runEvents: 0,
    attestations: 0,
    storageObjects: 0,
  };
}

export interface PurgeOptions {
  /**
   * RLS-constrained connection (DATABASE_APP_URL). Every tenant-scoped write
   * goes through it, inside withTenant.
   */
  prisma: PrismaClient;
  /**
   * Owner-role connection (DATABASE_URL), used for ONE query: enumerating the
   * organizations. RLS denies a cross-tenant SELECT by construction, and a
   * retention purge is cross-tenant by definition. Nothing else in this file
   * touches it — every deletion runs on the constrained connection so the
   * backstop still applies to the destructive half.
   */
  privileged: PrismaClient;
  /** Count without deleting. */
  dryRun?: boolean;
  logger?: PurgeLogger;
  /** Free-form note recorded on the ActivityLog rows: who asked for this run. */
  trigger?: string;
}

/**
 * Apply every published duration, across every organization.
 *
 * IDEMPOTENT by construction: every predicate is `createdAt < now - duration`,
 * so a second run minutes after the first finds nothing left to do and deletes
 * nothing. That is what makes it safe to retry a failed job, and what makes a
 * duplicated job harmless rather than merely unlikely.
 *
 * `dryRun` reads and counts without deleting. Worth having: the first real
 * run of a retention purge on a production database deletes years of rows,
 * and being able to see the number before it happens is the difference
 * between an operation and a gamble.
 */
export async function runRetentionPurge(opts: PurgeOptions): Promise<PurgeReport> {
  const { prisma, privileged, trigger } = opts;
  const logger = opts.logger ?? consoleLogger;
  const dryRun = opts.dryRun ?? false;
  const startedAt = Date.now();
  const now = startedAt;
  const report = emptyReport(dryRun);

  if (dryRun) {
    // Loud, every single time. A simulation that reads like a real purge in the
    // logs is how an operator concludes the policy is enforced when it is not.
    logger.warn(
      "retention purge running in DRY RUN — nothing will be deleted, and the durations " +
        "published in apps/web/lib/legal.ts are NOT being applied on this run",
    );
  }

  // Cross-tenant enumeration, on the PRIVILEGED connection by explicit
  // choice: a retention purge is an operation over every tenant at once, and
  // a tenant-scoped query can only ever see one. The warning below stays as a
  // guard against the connection being misconfigured back to a constrained
  // role, which would make the purge quietly do nothing.
  const organizations = await privileged.organization.findMany({ select: { id: true } });
  if (organizations.length === 0) {
    logger.warn(
      "retention purge found no organization — either the database is empty, or the caller " +
        "is connected with a role subject to RLS and cannot enumerate tenants",
    );
  }
  report.organizations = organizations.length;

  for (const { id } of organizations) {
    await purgeOrganization({ organizationId: id, now, dryRun, report, prisma, logger, trigger });
  }

  // Sessions are not tenant-scoped (see prisma/sql/rls.sql for why) and are
  // swept once, globally. An expired session is already refused by
  // SessionService.resolve; this removes the row so the table does not grow
  // without bound and so "durée : 30 jours" is true of the storage too.
  //
  // No ActivityLog row for this one: activity_logs carries organizationId and
  // is RLS'd, and a global sweep belongs to no tenant. It is reported on the
  // run line below instead.
  const expiredSessions = dryRun
    ? await prisma.session.count({ where: { expiresAt: { lt: new Date(now) } } })
    : (await prisma.session.deleteMany({ where: { expiresAt: { lt: new Date(now) } } })).count;
  report.expiredSessions = expiredSessions;

  report.durationMs = Date.now() - startedAt;

  // One structured line per execution, whatever the outcome — including a run
  // that deleted nothing. This is the trace that answers "did the purge run
  // last night?" without a database query, and the only trace a dry run leaves.
  logger.log(`retention purge ${dryRun ? "(dry run) " : ""}done: ${JSON.stringify(report)}`);
  return report;
}

async function purgeOrganization(args: {
  organizationId: string;
  now: number;
  dryRun: boolean;
  report: PurgeReport;
  prisma: PrismaClient;
  logger: PurgeLogger;
  trigger?: string;
}): Promise<void> {
  const { organizationId, now, dryRun, report, prisma, logger, trigger } = args;
  const runCutoff = new Date(now - RETENTION.runMs);
  const logCutoff = new Date(now - RETENTION.scannerLogsMs);
  const attestationCutoff = new Date(now - RETENTION.attestationMs);
  const stamped = new Date(now);
  const counts = emptyCounts();

  // ── Read phase: what expires, and which objects hang off it ──────────
  const plan = await withTenant(prisma, organizationId, async (tx) => {
    const staleRuns = await tx.auditRun.findMany({
      where: { organizationId, createdAt: { lt: runCutoff } },
      select: { id: true },
    });
    const runIds = staleRuns.map((r) => r.id);

    // Artifacts of the runs we are about to remove. Their ROWS cascade from
    // audit_runs, but their BYTES do not — collect the keys while the rows
    // still point at them.
    const runArtifacts =
      runIds.length > 0
        ? await tx.artifact.findMany({
            where: { organizationId, auditRunId: { in: runIds } },
            select: { storageKey: true },
          })
        : [];

    // Scanner logs on runs we are KEEPING: the 90-day clock is shorter than
    // the run's own 24 months, so these have to be picked off individually.
    const logArtifacts = await tx.artifact.findMany({
      where: {
        organizationId,
        type: { in: [...SCANNER_LOG_TYPES] },
        createdAt: { lt: logCutoff },
        ...(runIds.length > 0 ? { NOT: { auditRunId: { in: runIds } } } : {}),
      },
      select: { id: true, storageKey: true },
    });

    // Anything explicitly stamped, whatever its type. This is the column the
    // worker sets at creation time; it wins over the type-based rules above
    // because it is a deliberate per-object decision.
    const expiredArtifacts = await tx.artifact.findMany({
      where: { organizationId, retentionExpiresAt: { lte: stamped } },
      select: { id: true, storageKey: true },
    });

    const attestations = await tx.abuseEvent.count({
      where: { organizationId, createdAt: { lt: attestationCutoff } },
    });

    // Les événements des relevés qu'on GARDE : ce sont des journaux
    // d'exécution, donc l'horloge de 90 jours, plus courte que les 24 mois du
    // relevé. Ceux des relevés supprimés partent en cascade.
    const runEvents = await tx.runEvent.count({
      where: {
        organizationId,
        createdAt: { lt: logCutoff },
        ...(runIds.length > 0 ? { NOT: { auditRunId: { in: runIds } } } : {}),
      },
    });

    return { runIds, runArtifacts, logArtifacts, expiredArtifacts, attestations, runEvents };
  });

  counts.runs = plan.runIds.length;
  counts.scannerLogArtifacts = plan.logArtifacts.length;
  counts.expiredArtifacts = plan.expiredArtifacts.length;
  counts.attestations = plan.attestations;
  counts.runEvents = plan.runEvents;

  if (dryRun) {
    // Count what a real run would scrub, without touching it.
    counts.scanErrorsScrubbed = await withTenant(prisma, organizationId, (tx) =>
      tx.scan.count({
        where: {
          organizationId,
          createdAt: { lt: logCutoff },
          error: { not: Prisma.DbNull },
        },
      }),
    );
    accumulate(report, counts);
    // No ActivityLog row: a simulation must not write to the database it is
    // simulating. The numbers reach the operator through the run line.
    if (hasWork(counts)) {
      logger.log(
        `retention purge (dry run) ${organizationId}: ${JSON.stringify(counts)}`,
      );
    }
    return;
  }

  // ── Bytes first (see objects.ts for why) ─────────────────────────────
  const keys = new Set<string>([
    ...plan.runArtifacts.map((a) => a.storageKey),
    ...plan.logArtifacts.map((a) => a.storageKey),
    ...plan.expiredArtifacts.map((a) => a.storageKey),
  ]);
  counts.storageObjects = await dropObjects([...keys], logger);

  // ── Write phase ──────────────────────────────────────────────────────
  await withTenant(prisma, organizationId, async (tx) => {
    if (plan.runIds.length > 0) {
      // Cascades into scans → findings, pillar_results, reports and the
      // artifact rows whose bytes we just dropped.
      await tx.auditRun.deleteMany({ where: { id: { in: plan.runIds }, organizationId } });
    }

    const artifactIds = [
      ...plan.logArtifacts.map((a) => a.id),
      ...plan.expiredArtifacts.map((a) => a.id),
    ];
    if (artifactIds.length > 0) {
      await tx.artifact.deleteMany({ where: { id: { in: artifactIds }, organizationId } });
    }

    // The scanner's error messages live on the scan row itself, not in an
    // artifact — deleting log artifacts alone would leave the text the policy
    // calls "journaux d'exécution" sitting in `scans.error` forever. Only the
    // payload is blanked: exit code, timestamps and tool version are run
    // metadata on the 24-month clock, not logs.
    const scrubbed = await tx.scan.updateMany({
      where: {
        organizationId,
        createdAt: { lt: logCutoff },
        error: { not: Prisma.DbNull },
      },
      data: { error: Prisma.DbNull },
    });
    counts.scanErrorsScrubbed = scrubbed.count;

    // Les événements de relevé suivent la même horloge que les autres journaux
    // d'exécution. Sans cette ligne, une table qui grossit à chaque relevé ne
    // serait jamais purgée, et le texte publié — « journaux d'exécution : 90
    // jours » — cesserait d'être vrai le jour où cette table a existé.
    await tx.runEvent.deleteMany({
      where: {
        organizationId,
        createdAt: { lt: logCutoff },
        ...(plan.runIds.length > 0 ? { NOT: { auditRunId: { in: plan.runIds } } } : {}),
      },
    });

    // DAST authorization attestations, on their own 24-month clock. They
    // survive an account deletion on purpose (see AccountService) — this is
    // the only thing that ever expires them.
    await tx.abuseEvent.deleteMany({
      where: { organizationId, createdAt: { lt: attestationCutoff } },
    });

    // ── Journal ────────────────────────────────────────────────────────
    // First real use of ActivityLog, and the right one: a purge that erases a
    // customer's data without leaving a per-tenant record is a deletion nobody
    // can account for afterwards. The row lands in the SAME transaction as the
    // deletions it describes, so a rollback cannot leave a log of work that did
    // not happen — nor work with no log.
    //
    // Written only when something actually went. A daily row of zeros per
    // tenant would bury, within a month, the handful of rows that matter; the
    // "the purge ran at all" trace is the process log line, not this table.
    //
    // It is tenant-scoped and therefore visible in the customer's own JSON
    // export (AccountService.export) — which is the point: the policy says we
    // erase after 90 days and 24 months, and this is the receipt.
    if (hasWork(counts)) {
      await tx.activityLog.create({
        data: {
          organizationId,
          // null actor: the scheduler is not a person. An operator-triggered
          // run is distinguished by `detail.trigger`, not by a fake user id.
          actorUserId: null,
          action: PURGE_ACTIVITY_ACTION,
          detail: { ...counts, ...(trigger ? { trigger } : {}) } as Prisma.InputJsonValue,
        },
      });
    }
  });

  accumulate(report, counts);
  if (hasWork(counts)) {
    logger.log(`retention purge ${organizationId}: ${JSON.stringify(counts)}`);
  }
}

function hasWork(counts: OrgCounts): boolean {
  return Object.values(counts).some((n) => n > 0);
}

function accumulate(report: PurgeReport, counts: OrgCounts): void {
  report.runs += counts.runs;
  report.scannerLogArtifacts += counts.scannerLogArtifacts;
  report.expiredArtifacts += counts.expiredArtifacts;
  report.scanErrorsScrubbed += counts.scanErrorsScrubbed;
  report.attestations += counts.attestations;
  report.storageObjects += counts.storageObjects;
}
