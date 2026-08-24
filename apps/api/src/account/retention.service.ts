import { Injectable, Logger } from "@nestjs/common";
import { Prisma } from "@auditer/db";
import { PrismaService } from "../infra/prisma.service.js";
import { dropObjects } from "../common/artifact-purge.js";

/**
 * Retention purge — the code behind the durations published in
 * apps/web/lib/legal.ts. A duration announced in a privacy policy with nothing
 * enforcing it is not a retention policy, it is a sentence.
 *
 * ─────────────────────────────────────────────────────────────────────────
 * NOT SCHEDULED. Read this before trusting the numbers below.
 *
 * This project has no scheduler: no @nestjs/schedule, no cron container, no
 * BullMQ repeatable job. Adding one was deliberately NOT done here — an
 * ordonnanceur is an operational decision (where it runs, what happens when two
 * instances fire at once, how a failure is noticed) and smuggling one in behind
 * a retention fix would be the wrong place to make it.
 *
 * So the purge is triggered by hand, through
 *   POST /api/admin/retention/purge   (see retention.controller.ts)
 * and apps/web/lib/legal.ts says exactly that, in French, to the user. When a
 * scheduler does land, call purge() from it and correct the legal text in the
 * same commit — not before.
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
  /** DAST authorization attestations past 24 months. */
  attestations: number;
  /** Session rows past their own expiry — the 30 days announced in the cookie policy. */
  expiredSessions: number;
  /** Objects actually removed from the bucket. */
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
    attestations: 0,
    expiredSessions: 0,
    storageObjects: 0,
  };
}

@Injectable()
export class RetentionService {
  private readonly logger = new Logger("retention");

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Apply every published duration, across every organization.
   *
   * `dryRun` reads and counts without deleting. Worth having: the first real
   * run of a retention purge on a production database deletes years of rows,
   * and being able to see the number before it happens is the difference
   * between an operation and a gamble.
   */
  async purge(opts: { dryRun?: boolean } = {}): Promise<PurgeReport> {
    const dryRun = opts.dryRun ?? false;
    const now = Date.now();
    const report = emptyReport(dryRun);

    // Cross-tenant enumeration, on the PRIVILEGED connection by explicit
    // choice: a retention purge is an operation over every tenant at once, and
    // a tenant-scoped query can only ever see one. The warning below stays as a
    // guard against the connection being misconfigured back to a constrained
    // role, which would make the purge quietly do nothing.
    const organizations = await this.prisma.privileged.organization.findMany({
      select: { id: true },
    });
    if (organizations.length === 0) {
      this.logger.warn(
        "retention purge found no organization — either the database is empty, or the api " +
          "is connected with a role subject to RLS and cannot enumerate tenants",
      );
    }
    report.organizations = organizations.length;

    for (const { id } of organizations) {
      await this.purgeOrganization(id, now, dryRun, report);
    }

    // Sessions are not tenant-scoped (see prisma/sql/rls.sql for why) and are
    // swept once, globally. An expired session is already refused by
    // SessionService.resolve; this removes the row so the table does not grow
    // without bound and so "durée : 30 jours" is true of the storage too.
    const expiredSessions = dryRun
      ? await this.prisma.session.count({ where: { expiresAt: { lt: new Date(now) } } })
      : (await this.prisma.session.deleteMany({ where: { expiresAt: { lt: new Date(now) } } }))
          .count;
    report.expiredSessions = expiredSessions;

    this.logger.log(
      `retention purge ${dryRun ? "(dry run) " : ""}done: ${JSON.stringify(report)}`,
    );
    return report;
  }

  private async purgeOrganization(
    organizationId: string,
    now: number,
    dryRun: boolean,
    report: PurgeReport,
  ): Promise<void> {
    const runCutoff = new Date(now - RETENTION.runMs);
    const logCutoff = new Date(now - RETENTION.scannerLogsMs);
    const attestationCutoff = new Date(now - RETENTION.attestationMs);
    const stamped = new Date(now);

    // ── Read phase: what expires, and which objects hang off it ──────────
    const plan = await this.prisma.tenant(organizationId, async (tx) => {
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

      return { runIds, runArtifacts, logArtifacts, expiredArtifacts, attestations };
    });

    report.runs += plan.runIds.length;
    report.scannerLogArtifacts += plan.logArtifacts.length;
    report.expiredArtifacts += plan.expiredArtifacts.length;
    report.attestations += plan.attestations;

    if (dryRun) {
      // Count what a real run would scrub, without touching it.
      report.scanErrorsScrubbed += await this.prisma.tenant(organizationId, (tx) =>
        tx.scan.count({
          where: {
            organizationId,
            createdAt: { lt: logCutoff },
            error: { not: Prisma.DbNull },
          },
        }),
      );
      return;
    }

    // ── Bytes first (see common/artifact-purge.ts for why) ───────────────
    const keys = new Set<string>([
      ...plan.runArtifacts.map((a) => a.storageKey),
      ...plan.logArtifacts.map((a) => a.storageKey),
      ...plan.expiredArtifacts.map((a) => a.storageKey),
    ]);
    report.storageObjects += await dropObjects([...keys]);

    // ── Write phase ──────────────────────────────────────────────────────
    await this.prisma.tenant(organizationId, async (tx) => {
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
      report.scanErrorsScrubbed += scrubbed.count;

      // DAST authorization attestations, on their own 24-month clock. They
      // survive an account deletion on purpose (see AccountService) — this is
      // the only thing that ever expires them.
      await tx.abuseEvent.deleteMany({
        where: { organizationId, createdAt: { lt: attestationCutoff } },
      });
    });
  }
}
