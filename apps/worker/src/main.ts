import { Worker } from "bullmq";
import { createPrisma, withTenant } from "@auditer/db";
import { createRedis, QUEUE_NAMES, cancelFlag, type AuditJob } from "@auditer/queue";
import { kekFromEnv, open as openSecret } from "@auditer/crypto";
import {
  defaultRegistry,
  DockerGvisorRunner,
  runScan,
  aggregate,
  collectKloc,
  AiClient,
  type ScanContext,
  type RunScanResult,
} from "@auditer/audit-engine";
import type { RawFinding, Pillar, TriageStatus, Severity, ReportDocument } from "@auditer/types";
import type { ExecutiveSummary } from "@auditer/types";
import { DEFAULT_REPORT_DOCUMENT, normalizeReportDocument } from "@auditer/types";
import { getStorage } from "@auditer/storage";
import { EventPublisher } from "./events.js";
import { prepare, type Workspace } from "./workspace.js";
import { mintInstallationToken } from "./github-app.js";
import { validGitlabToken } from "./gitlab.js";
import { buildReportHtml } from "./report-html.js";
import { renderPdf } from "./pdf.js";
import { buildExecReportHtml, type ExecPillarRow } from "./report-exec.js";
import { buildDeltaReportHtml } from "./report-delta.js";
import { buildAttestationHtml } from "./report-attestation.js";
import { loadProgress, type ProgressContext } from "./delta.js";
import { startRetentionScheduler } from "./retention-scheduler.js";
import { readOsvCoverage } from "./osv-coverage.js";

/**
 * The worker: consumes `audit` jobs and drives the whole pipeline in-process —
 * clone → sandboxed scans → normalize → dedup → AI enrich → score → persist →
 * publish. (Per-pillar queue fan-out via BullMQ Flows is the v2 scaling step;
 * the pipeline shape is identical, so promotion is mechanical.)
 *
 * Runs as a standalone Node process — no HTTP. It shares the exact db/queue/
 * engine packages the api uses, so the two can never drift.
 */

const prisma = createPrisma();
const redis = createRedis();
const publisher = new EventPublisher(redis);
const registry = defaultRegistry();
const runner = new DockerGvisorRunner();
const kek = kekFromEnv();
const ai = process.env.ANTHROPIC_API_KEY
  ? new AiClient({
      onUsage: (u) => {
        void prisma.aiUsageLedger
          .create({
            data: {
              requestId: u.requestId,
              modelId: u.modelId,
              inputTokens: u.inputTokens,
              outputTokens: u.outputTokens,
              cacheReadTokens: u.cacheReadTokens,
              cacheWriteTokens: u.cacheWriteTokens,
            },
          })
          .catch(() => {});
      },
    })
  : undefined;

async function isCanceled(auditRunId: string): Promise<boolean> {
  return (await redis.get(cancelFlag(auditRunId))) === "1";
}

/** Build an https clone URL + resolve a short-lived token from the connection. */
async function resolveClone(
  organizationId: string,
  repositoryId: string,
): Promise<{ cloneUrl: string; token?: string; tokenUser?: string; ref?: string }> {
  const gitlabHost = (process.env.GITLAB_URL ?? "https://gitlab.com").replace(/^https?:\/\//, "").replace(/\/+$/, "");
  const connResolved = await withTenant(prisma, organizationId, async (tx) => {
    const repo = await tx.repository.findFirstOrThrow({ where: { id: repositoryId } });
    const conn = await tx.connection.findFirstOrThrow({ where: { id: repo.connectionId } });
    return { repo, conn };
  });
  const { repo, conn } = connResolved;

  const host = repo.provider === "github" ? "github.com" : gitlabHost;
  // A local path / file:// fullName clones directly (demo/air-gapped mirrors).
  const isLocal = repo.fullName.startsWith("/") || repo.fullName.startsWith("file://");
  const cloneUrl = isLocal ? repo.fullName : `https://${host}/${repo.fullName}.git`;
  if (isLocal) return { cloneUrl };

  if (repo.provider === "gitlab") {
    // GitLab OAuth: a fresh access token (refreshed + persisted), user "oauth2".
    const token = await validGitlabToken(prisma, kek, organizationId, conn);
    return { cloneUrl, token, tokenUser: "oauth2", ref: repo.defaultBranch };
  }

  // GitHub: prefer a fresh installation token (never persisted); else a PAT.
  let token = await mintInstallationToken(conn.installationId);
  if (!token && conn.encPat) {
    try {
      token = await openSecret(kek, conn.encPat);
    } catch {
      /* unauthenticated */
    }
  }
  return { cloneUrl, token, tokenUser: "x-access-token", ref: repo.defaultBranch };
}

/** Resolve a DAST/UX target and HARD-ENFORCE ownership verification. */
async function resolveVerifiedTarget(
  organizationId: string,
  targetId: string,
): Promise<{ url: string; scopeAllowlist?: string[] }> {
  return withTenant(prisma, organizationId, async (tx) => {
    const target = await tx.target.findFirstOrThrow({ where: { id: targetId } });
    if (target.verificationStatus !== "verified") {
      throw new Error(`target ${targetId} is not ownership-verified — refusing to scan`);
    }
    const allow = Array.isArray(target.scopeAllowlist)
      ? (target.scopeAllowlist as string[])
      : undefined;
    return { url: target.value, scopeAllowlist: allow };
  });
}

async function processAudit(job: AuditJob): Promise<void> {
  const { auditRunId, organizationId } = job;

  // Report-only re-render path (from POST /reports/:id/export).
  if (job.scopeConfig?.reportOnly) {
    await renderReport(job);
    return;
  }

  let ws: Workspace | undefined;
  const partialPillars = new Set<Pillar>();

  try {
    let ctx: ScanContext;

    if (job.repositoryId) {
      // ── Code / repo audit: clone into a hardened workspace ──
      await setStatus(auditRunId, organizationId, "cloning");
      await publisher.status(auditRunId, "cloning");
      const secretsRequested = job.pillars.includes("secrets");
      const { cloneUrl, token, tokenUser, ref } = await resolveClone(organizationId, job.repositoryId);
      ws = await prepare({ cloneUrl, ref: job.ref ?? ref, token, tokenUser, fullHistory: secretsRequested });
      await publisher.log(
        auditRunId,
        `cloned ${cloneUrl} @ ${ws.commitSha?.slice(0, 12) ?? "no-commit"} — ` +
          `${ws.manifests.length} manifeste(s)${ws.manifests.length ? ` : ${ws.manifests.join(", ")}` : ""}` +
          `, ${ws.dockerfiles.length} Dockerfile(s)`,
      );
      // Stamp the commit that was ACTUALLY analysed. Every report asserts "the
      // result holds for the commit shown above"; until now nothing wrote it,
      // so the reports printed "non déclaré" and the sentence backed nothing.
      if (ws.commitSha) {
        await withTenant(prisma, organizationId, (tx) =>
          tx.auditRun.update({
            where: { id: auditRunId },
            data: { commitSha: ws!.commitSha, ref: job.ref ?? ref ?? null },
          }),
        );
      }
      ctx = {
        auditRunId,
        organizationId,
        workspacePath: ws.path,
        manifests: ws.manifests,
        dockerfiles: ws.dockerfiles,
      };
    } else if (job.targetId) {
      // ── DAST / UX audit: verified target, no clone. Ownership is re-checked
      //    here (defense in depth) even though the api already gated it. ──
      const target = await resolveVerifiedTarget(organizationId, job.targetId);
      await publisher.log(auditRunId, `target ${target.url} (ownership verified)`);
      ctx = { auditRunId, organizationId, workspacePath: "", target };
    } else {
      throw new Error("audit needs repositoryId or targetId");
    }

    await setStatus(auditRunId, organizationId, "scanning");
    await publisher.status(auditRunId, "scanning");

    // State the dependency database BEFORE the scans, in the live trace. The
    // server ran for weeks with a single ecosystem archive on disk and nothing
    // said so — every non-npm repository simply had no dependency verdict. A
    // coverage line at the top of the run is what makes that visible while it
    // is still happening, instead of after a customer reads a clean pillar.
    if (job.pillars.includes("sca")) {
      const cov = await readOsvCoverage();
      await publisher.log(
        auditRunId,
        cov
          ? `base OSV : ${cov.covered.length} écosystème(s), ${cov.advisories} avis` +
              (cov.oldest ? `, plus ancienne archive ${cov.oldest}` : "") +
              (cov.missing.length ? ` — INDISPONIBLES : ${cov.missing.join(", ")}` : "")
          : "base OSV : provenance introuvable — le verdict sur les dépendances sera invérifiable",
      );
    }

    const adapters = registry.forPillars(job.pillars);
    const allRaw: RawFinding[] = [];
    const fpToScanId = new Map<string, string>();
    const pillarsRun = new Set<Pillar>();
    // Measurements from scanners that produce them (scc). Kept per-scan so the
    // kLOC that normalized the score is traceable to the tool that measured it.
    const measured: RunScanResult[] = [];

    for (const adapter of adapters) {
      if (await isCanceled(auditRunId)) {
        await finalize(auditRunId, organizationId, "canceled");
        return;
      }
      const startedAt = Date.now();
      await publisher.scan(auditRunId, adapter.pillar, adapter.tool, "running", undefined, {
        // The exact image, digest included. Two runs of the same commit are
        // only comparable if you can see they ran the same binary.
        image: adapter.image,
      });

      let result: RunScanResult;
      try {
        result = await runScan(adapter, runner, ctx);
      } catch (err) {
        // Infra error running the scanner → partial for this pillar, keep going.
        partialPillars.add(adapter.pillar);
        await recordScan(organizationId, auditRunId, adapter.id, adapter.pillar, adapter.tool, {
          status: "failed",
          exitClass: "fail",
          error: { message: String(err) },
        });
        await publisher.scan(auditRunId, adapter.pillar, adapter.tool, "failed", 0, {
          durationMs: Date.now() - startedAt,
          image: adapter.image,
          reason: String(err).slice(0, 200),
        });
        continue;
      }

      pillarsRun.add(adapter.pillar);
      const scanId = await recordScan(
        organizationId,
        auditRunId,
        adapter.id,
        adapter.pillar,
        adapter.tool,
        {
          status: result.skipped ? "skipped" : result.exitClass === "fail" ? "failed" : "success",
          exitCode: result.exitCode,
          exitClass: result.exitClass,
          // Scan.stats already exists as a Json column — the measurements land
          // there rather than in a new table, so the numbers behind a score stay
          // auditable per scanner without a schema change.
          stats: result.metrics,
        },
      );
      if (result.exitClass === "partial") partialPillars.add(adapter.pillar);
      if (result.metrics) measured.push(result);

      for (const f of result.findings) {
        allRaw.push(f);
        if (!fpToScanId.has(f.fingerprint)) fpToScanId.set(f.fingerprint, scanId);
      }
      // Report the state that was PERSISTED. This used to announce "success"
      // whenever the scanner had merely been reached, so a run whose engine was
      // killed showed a green line live and a failed scan in the report — the
      // customer and the record disagreed about the same event.
      const liveStatus = result.skipped
        ? ("skipped" as const)
        : result.exitClass === "fail"
          ? ("failed" as const)
          : result.exitClass === "partial"
            ? ("partial" as const)
            : ("success" as const);
      await publisher.scan(
        auditRunId,
        adapter.pillar,
        adapter.tool,
        liveStatus,
        result.findings.length,
        {
          durationMs: result.durationMs,
          exitCode: result.exitCode,
          image: adapter.image,
          reason: result.skipped
            ? "aucun fichier pertinent pour ce moteur"
            : result.timedOut
              ? "délai dépassé"
              : result.exitCode === 137
                ? "tué par la limite mémoire (SIGKILL)"
                : undefined,
        },
      );
    }

    await setStatus(auditRunId, organizationId, "analyzing");
    await publisher.status(auditRunId, "analyzing");
    await publisher.log(
      auditRunId,
      `${allRaw.length} finding(s) bruts sur ${pillarsRun.size} pilier(s) exécuté(s)` +
        (partialPillars.size > 0
          ? ` — ${partialPillars.size} pilier(s) incomplet(s) : ${[...partialPillars].join(", ")}`
          : ""),
    );

    // Load persisted triage so scoring respects false-positives across runs.
    const triage = await loadTriage(organizationId);

    // Size normalization. undefined when the quality pillar was not requested
    // (or scc failed): scoring then falls back to ASSUMED_KLOC and stamps the
    // run "assumed" — we must NOT substitute a guess here, or the report would
    // present an unnormalized score as a normalized one.
    const kloc = collectKloc(measured);

    const agg = await aggregate({
      organizationId,
      auditRunId,
      rawFindings: allRaw,
      pillarsRun: [...pillarsRun],
      partialPillars,
      kloc,
      triageByFingerprint: triage,
      ai,
      enableAi: Boolean(ai),
      // Degraded enrichment is a fact about the report, not a silent detail:
      // surface it in the run log so a relevé produced without exploitability
      // data is visibly a relevé produced without exploitability data.
      onWarning: (m) => void publisher.log(auditRunId, `vuln feeds: ${m}`),
    });

    const enriched = agg.findings.filter((f) => f.vuln?.epssScore != null).length;
    const kev = agg.findings.filter((f) => f.vuln?.kevListed).length;
    await publisher.log(
      auditRunId,
      `déduplication : ${allRaw.length} bruts → ${agg.findings.length} retenus` +
        (allRaw.length > agg.findings.length
          ? ` (${allRaw.length - agg.findings.length} regroupés entre moteurs)`
          : ""),
    );
    await publisher.log(
      auditRunId,
      agg.vulnFeedsSnapshot
        ? `exploitabilité : ${enriched} finding(s) notés EPSS, ${kev} exploité(s) dans la nature — instantané ${agg.vulnFeedsSnapshot}`
        : "exploitabilité : aucune donnée EPSS/KEV disponible — classement par gravité seule",
    );
    await publisher.log(
      auditRunId,
      `score ${agg.score.overall}/100 (${agg.score.grade}) · ` +
        agg.score.pillars.map((p) => `${p.pillar} ${p.score}`).join(" · "),
    );
    await publisher.log(
      auditRunId,
      agg.score.klocSource === "measured"
        ? `size ${agg.score.kloc.toFixed(1)} kLOC (measured by scc) — score density-normalized`
        : `size not measured (quality pillar absent) — score uses the ${agg.score.kloc} kLOC fallback, NOT normalized`,
    );

    await setStatus(auditRunId, organizationId, "reporting");
    await publisher.status(auditRunId, "reporting");

    // Persist findings + pillar results + score + report summary.
    await persistResults(organizationId, auditRunId, agg, fpToScanId);

    const finalStatus = partialPillars.size > 0 ? "completed_with_errors" : "done";
    await finalize(
      auditRunId,
      organizationId,
      finalStatus,
      agg.score.overall,
      agg.vulnFeedsSnapshot,
    );
    await publisher.done(auditRunId, finalStatus, agg.score.overall);
  } catch (err) {
    await finalize(auditRunId, organizationId, "failed");
    await publisher.log(auditRunId, `audit failed: ${String(err)}`);
    await publisher.done(auditRunId, "failed");
  } finally {
    // Shred the workspace — source code never outlives the scan.
    await ws?.cleanup().catch(() => {});
  }
}

// ── DB helpers (all tenant-scoped) ────────────────────────────────────────

async function setStatus(auditRunId: string, organizationId: string, status: string): Promise<void> {
  await withTenant(prisma, organizationId, (tx) =>
    tx.auditRun.update({
      where: { id: auditRunId },
      data: {
        status: status as never,
        ...(status === "cloning" ? { startedAt: new Date() } : {}),
      },
    }),
  );
}

async function finalize(
  auditRunId: string,
  organizationId: string,
  status: string,
  riskScore?: number,
  /**
   * Date of the EPSS/KEV snapshot that informed this run. Stamped on the run,
   * not derived at read time: the report has to state the data AS IT WAS when
   * the score was computed, otherwise re-reading an old relevé silently
   * reinterprets it against today's feeds.
   */
  vulnFeedsSnapshot?: string | null,
): Promise<void> {
  await withTenant(prisma, organizationId, (tx) =>
    tx.auditRun.update({
      where: { id: auditRunId },
      data: {
        status: status as never,
        finishedAt: new Date(),
        ...(riskScore !== undefined ? { riskScore } : {}),
        ...(vulnFeedsSnapshot ? { vulnFeedsSnapshot: new Date(vulnFeedsSnapshot) } : {}),
      },
    }),
  );
}

async function recordScan(
  organizationId: string,
  auditRunId: string,
  scannerId: string,
  pillar: Pillar,
  tool: string,
  data: {
    status: string;
    exitCode?: number;
    exitClass?: string;
    error?: unknown;
    stats?: Record<string, number>;
  },
): Promise<string> {
  return withTenant(prisma, organizationId, async (tx) => {
    const scan = await tx.scan.upsert({
      where: { auditRunId_scannerId: { auditRunId, scannerId } },
      create: {
        organizationId,
        auditRunId,
        scannerId,
        pillar,
        tool,
        status: data.status as never,
        exitCode: data.exitCode,
        exitClass: data.exitClass as never,
        error: data.error as never,
        stats: data.stats as never,
        finishedAt: new Date(),
      },
      update: {
        status: data.status as never,
        exitCode: data.exitCode,
        exitClass: data.exitClass as never,
        error: data.error as never,
        stats: data.stats as never,
        finishedAt: new Date(),
      },
    });
    return scan.id;
  });
}

async function loadTriage(organizationId: string): Promise<Map<string, TriageStatus>> {
  const rows = await withTenant(prisma, organizationId, (tx) =>
    tx.triageState.findMany({ where: { organizationId } }),
  );
  return new Map(rows.map((r) => [r.fingerprint, r.status as TriageStatus]));
}

async function persistResults(
  organizationId: string,
  auditRunId: string,
  agg: Awaited<ReturnType<typeof aggregate>>,
  fpToScanId: Map<string, string>,
): Promise<void> {
  await withTenant(prisma, organizationId, async (tx) => {
    // Fresh findings for this run.
    await tx.finding.deleteMany({ where: { auditRunId, organizationId } });

    /* ── Cross-run identity ───────────────────────────────────────────────
       `firstSeenRunId` is what turns a finding's AGE into a measurable number,
       and age is the governance metric of the progression report: a medium
       open for fourteen months says more about how an organisation handles
       risk than a critical opened yesterday.

       The column existed but nothing ever wrote it, so every finding looked
       brand new at every relevé. Recovered in ONE query over the whole batch
       rather than a lookup per finding — a run with four hundred findings
       would otherwise open four hundred round-trips inside the tenant
       transaction. The earliest row per fingerprint wins, and it carries its
       own `firstSeenRunId` forward when it has one, so the origin survives
       however many relevés separate it from today. */
    const fingerprints = [...new Set(agg.findings.map((f) => f.fingerprint))];
    const priorSeen = new Map<string, string>();
    if (fingerprints.length > 0) {
      const prior = await tx.finding.findMany({
        where: { organizationId, fingerprint: { in: fingerprints } },
        select: { fingerprint: true, firstSeenRunId: true, auditRunId: true, createdAt: true },
        orderBy: { createdAt: "asc" },
      });
      for (const p of prior) {
        if (priorSeen.has(p.fingerprint)) continue;
        priorSeen.set(p.fingerprint, p.firstSeenRunId ?? p.auditRunId);
      }
    }

    for (const f of agg.findings) {
      const scanId = fpToScanId.get(f.fingerprint);
      if (!scanId) continue;
      await tx.finding.create({
        data: {
          organizationId,
          auditRunId,
          scanId,
          pillar: f.pillar,
          tool: f.tool,
          ruleId: f.ruleId,
          severity: f.severity,
          cvssScore: f.cvssScore,
          cvssVector: f.cvssVector,
          confidence: f.confidence,
          title: f.title,
          description: f.description,
          cwe: f.cwe,
          vulnIds: f.vulnIds,
          owaspCategory: f.owaspCategory,
          location: f.location as never,
          target: f.target as never,
          package: f.package as never,
          vuln: f.vuln as never,
          // Denormalised from the blob above, on purpose: the report sorts
          // every finding by real-world exploitability, and asking Postgres to
          // order hundreds of rows through a JSON path on every read is the
          // wrong trade. Writing only the blob left these columns null, so the
          // enrichment was computed, stored, and then invisible to the one
          // consumer that exists for it.
          epssScore: f.vuln?.epssScore ?? null,
          kevListed: f.vuln?.kevListed ?? null,
          evidence: f.evidence,
          references: f.references,
          fingerprint: f.fingerprint,
          dedupeGroupId: f.dedupeGroupId,
          sourceCount: f.sourceCount,
          aiExplanation: f.ai?.explanation,
          aiRemediation: f.ai?.remediation,
          aiSuggestedFix: f.ai?.suggestedFixDiff,
          aiPriority: f.ai?.priority,
          aiConfidence: f.ai?.confidence,
          aiNeedsHuman: f.ai?.needsHuman ?? false,
          aiModel: f.ai?.model,
          triageStatus: f.triageStatus,
          // Falls back to THIS run when the fingerprint is genuinely new — the
          // age of a finding first seen today is zero, not unknown.
          firstSeenRunId: priorSeen.get(f.fingerprint) ?? auditRunId,
          lastSeenRunId: auditRunId,
        },
      });
    }

    // Pillar results.
    await tx.pillarResult.deleteMany({ where: { auditRunId } });
    for (const p of agg.score.pillars) {
      await tx.pillarResult.create({
        data: {
          auditRunId,
          pillar: p.pillar,
          score: p.score,
          grade: p.grade,
          counts: p.counts as never,
          partial: p.partial,
        },
      });
    }

    await tx.auditRun.update({
      where: { id: auditRunId },
      data: { scoringVersion: agg.score.scoringVersion },
    });

    if (agg.summary) {
      await tx.report.create({
        data: {
          organizationId,
          auditRunId,
          format: "dashboard",
          aiModel: agg.summary.model,
          summary: agg.summary as never,
          status: "ready",
          generatedAt: new Date(),
        },
      });
    }
  });
}

/**
 * Report render path (from POST /reports/:id/export). Builds a self-contained,
 * print-ready HTML document from the persisted run + findings + summary,
 * uploads it to object storage, and links it on the Report.
 *
 * ONE MISSION, FOUR DOCUMENTS. NIST SP 800-115 puts it plainly — "a report may
 * have multiple audiences, multiple report formats may be required" — and the
 * five readers of an audit do not read the same thing. Until now the api
 * accepted a `format` and the worker ignored it, so every export produced the
 * technical relevé whatever was asked for. The four deliverables:
 *
 *   technique    → report-html.ts        the full relevé, exploitable detail
 *   dirigeant    → report-exec.ts        two pages, business consequence, no jargon
 *   progression  → report-delta.ts       the comparison with the previous relevé
 *   attestation  → report-attestation.ts one page, signed, safe to circulate
 *
 * The three comparative documents pay for two extra queries (previous relevé +
 * score history); `technique` does not, and skips them.
 */
/**
 * Renders the persisted CodeLocation blob as `path:line` for the report. A
 * finding a reader cannot locate is a finding they cannot act on, and the
 * shape differs per pillar (code path vs DAST URL), so unknown shapes yield
 * null rather than a half-formed string.
 */
function locationLabel(loc: unknown): string | null {
  if (!loc || typeof loc !== "object") return null;
  const l = loc as { path?: unknown; startLine?: unknown };
  if (typeof l.path !== "string" || l.path.length === 0) return null;
  return typeof l.startLine === "number" ? `${l.path}:${l.startLine}` : l.path;
}

/** Zeroed severity tally — every document states a zero, never an absence. */
function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

function severityCounts(findings: { severity: string }[]): Record<Severity, number> {
  const out = emptySeverityCounts();
  for (const f of findings) {
    const s = f.severity as Severity;
    if (s in out) out[s] += 1;
  }
  return out;
}

/** Open findings grouped by pillar — the executive note's unit of narration. */
function countsByPillar(findings: { severity: string; pillar: string }[]): ExecPillarRow[] {
  const map = new Map<string, Record<Severity, number>>();
  for (const f of findings) {
    const row = map.get(f.pillar) ?? emptySeverityCounts();
    const s = f.severity as Severity;
    if (s in row) row[s] += 1;
    map.set(f.pillar, row);
  }
  return [...map].map(([pillar, counts]) => ({ pillar, counts }));
}

/**
 * A scan counts as coverage only if it ran to completion. `skipped` is excluded
 * on purpose — same reasoning as apps/worker/src/delta.ts: a relevance gate is
 * indistinguishable here from a gate that fired wrongly, and an attestation
 * that lists an unexecuted pillar as covered is the one error in that document
 * that cannot be walked back.
 */
function measuredPillarsOf(scans: { pillar: string; status: string }[]): string[] {
  return [...new Set(scans.filter((s) => s.status === "success" || s.status === "partial").map((s) => s.pillar))];
}

async function renderReport(job: AuditJob): Promise<void> {
  const { organizationId, auditRunId } = job;
  const reportId = (job.scopeConfig?.reportId as string) ?? undefined;
  // The api posts the deliverable under `format`. Callers written before the
  // four documents existed post a CONTAINER name (`html`, `pdf`); those
  // normalize to the technical relevé, which is what they used to receive.
  const document: ReportDocument =
    normalizeReportDocument(job.scopeConfig?.format) ?? DEFAULT_REPORT_DOCUMENT;

  // The render is deliberately split across TWO short transactions with the
  // slow work between them. Spawning a container and pushing objects takes
  // seconds; doing that inside an interactive transaction pins a database
  // connection for its whole duration and courts the transaction timeout — on
  // an operation whose only database work is a handful of reads and two
  // inserts.
  const prepared = await withTenant(prisma, organizationId, async (tx) => {
    const run = await tx.auditRun.findFirst({ where: { id: auditRunId, organizationId } });
    if (!run) return null;
    const repo = run.repositoryId
      ? await tx.repository.findFirst({ where: { id: run.repositoryId } })
      : null;
    const org = await tx.organization.findFirst({
      where: { id: organizationId },
      select: { name: true },
    });
    const pillars = await tx.pillarResult.findMany({ where: { auditRunId } });
    const scans = await tx.scan.findMany({ where: { auditRunId } });
    const findings = await tx.finding.findMany({
      where: { auditRunId, organizationId },
      orderBy: [{ severity: "asc" }, { aiPriority: "desc" }],
    });
    const reportRow = await tx.report.findFirst({
      where: { auditRunId, organizationId, format: "dashboard" },
      orderBy: { createdAt: "desc" },
    });

    // Lines of code, recovered from whichever scan actually measured them.
    // Read back from Scan.stats rather than recomputed: the report must state
    // the number that NORMALIZED THIS SCORE, not one measured later against a
    // tree that may have moved.
    const locCode = scans
      .map((s) => (s.stats as Record<string, number> | null)?.["loc.code"])
      .find((n): n is number => typeof n === "number" && n > 0);

    // Provenance of the offline dependency database. Read here rather than
    // persisted per run: the alternative was a migration for a field that only
    // the renderer consumes, and a report rendered from a run is rendered in the
    // same deployment that scanned it.
    const osvDb = await readOsvCoverage();

    const generatedAt = new Date().toISOString();
    const runAt = (run.finishedAt ?? run.createdAt).toISOString();
    const measuredPillars = measuredPillarsOf(scans);
    // Triage applied: an accepted risk and an assumed false positive are
    // decisions, not open findings, and the client-facing documents must not
    // present them as unfinished work.
    const openFindings = findings.filter((f) => f.triageStatus === "open");
    const openCounts = severityCounts(openFindings);

    // Only the comparative documents pay for the previous relevé + history.
    const progress: ProgressContext | null =
      document === "technique" ? null : await loadProgress(tx, organizationId, run);

    let html: string;
    switch (document) {
      case "dirigeant":
        html = buildExecReportHtml({
          runId: auditRunId,
          clientName: org?.name ?? null,
          projectName: repo?.fullName ?? null,
          generatedAt,
          runAt,
          riskScore: run.riskScore,
          // The letter grade comes from the persisted summary, not recomputed
          // here: the note a client already saw must not change because a
          // later export re-derived it.
          grade: (reportRow?.summary as ExecutiveSummary | null)?.overallGrade ?? null,
          counts: openCounts,
          byPillar: countsByPillar(openFindings),
          delta: progress?.delta ?? null,
          requestedPillars: run.pillars,
          measuredPillars,
        });
        break;

      case "progression":
        html = buildDeltaReportHtml({
          runId: auditRunId,
          clientName: org?.name ?? null,
          projectName: repo?.fullName ?? null,
          commitSha: run.commitSha,
          generatedAt,
          scoringVersion: run.scoringVersion,
          delta: progress!.delta,
          history: progress!.history,
          requestedPillars: run.pillars,
          measuredPillars,
        });
        break;

      case "attestation":
        html = buildAttestationHtml({
          runId: auditRunId,
          issuedAt: generatedAt,
          clientName: org?.name ?? null,
          projectName: repo?.fullName ?? null,
          ref: run.ref,
          commitSha: run.commitSha,
          // Covered / not covered are BOTH declared: the declared tooled
          // coverage is what this document offers in place of the man-days it
          // does not have, and a coverage list without its holes is marketing.
          pillarsCovered: measuredPillars,
          pillarsNotCovered: run.pillars.filter((p) => !measuredPillars.includes(p)),
          windowStart: run.startedAt?.toISOString() ?? null,
          windowEnd: run.finishedAt?.toISOString() ?? null,
          engines: scans.map((s) => ({
            tool: s.tool,
            version: s.toolVersion ?? s.imageDigest,
            pillar: s.pillar,
            status: s.status,
          })),
          vulnFeedsSnapshot: run.vulnFeedsSnapshot?.toISOString() ?? null,
          scoringVersion: run.scoringVersion,
          counts: openCounts,
          remediation: progress?.delta.hasBaseline
            ? {
                fixedSinceLast: progress.delta.fixed.length,
                newSinceLast: progress.delta.introduced.length,
                stillOpen: progress.delta.openCurrent,
                previousAt: progress.delta.previousAt,
              }
            : null,
        });
        break;

      default:
        html = buildReportHtml({
          runId: auditRunId,
          fullName: repo?.fullName ?? null,
          commitSha: run.commitSha,
          ref: run.ref,
          riskScore: run.riskScore,
          scoringVersion: run.scoringVersion,
          startedAt: run.startedAt?.toISOString() ?? null,
          finishedAt: run.finishedAt?.toISOString() ?? null,
          // What was ASKED for, which is what makes an unexecuted pillar visible.
          // Deriving this from the scans that ran would erase exactly the gap the
          // report exists to disclose.
          requestedPillars: run.pillars,
          kloc: locCode != null ? locCode / 1000 : null,
          klocMeasured: locCode != null,
          vulnFeedsSnapshot: run.vulnFeedsSnapshot?.toISOString() ?? null,
          osvDb,
          pillars: pillars.map((p) => ({ pillar: p.pillar, score: p.score, grade: p.grade })),
          summary: (reportRow?.summary as ExecutiveSummary | null) ?? null,
          findings: findings.map((f) => ({
            pillar: f.pillar,
            tool: f.tool,
            severity: f.severity,
            title: f.title,
            description: f.description,
            vulnIds: f.vulnIds,
            cvssScore: f.cvssScore,
            aiExplanation: f.aiExplanation,
            aiRemediation: f.aiRemediation,
            aiNeedsHuman: f.aiNeedsHuman,
            epssScore: f.epssScore,
            kevListed: f.kevListed,
            location: locationLabel(f.location),
          })),
          scanners: scans.map((s) => ({
            tool: s.tool,
            pillar: s.pillar,
            version: s.toolVersion,
            imageRef: s.imageDigest,
            status: s.status,
            findingCount: findings.filter((f) => f.scanId === s.id).length,
            error: s.error,
          })),
          generatedAt,
        });
        break;
    }

    // Typed as what it actually is. The renderer produces HTML today; when the
    // paged PDF renderer lands, only `ext`/`contentType` change and the
    // download endpoint follows the row instead of guessing.
    //
    // The DELIVERABLE is carried in the object key, between the uuid and the
    // extension. `Report.format` is a Prisma enum naming the container, and
    // widening it to hold four deliverable names would mean a schema migration
    // for a label; the key stays attached to the bytes it describes, and the
    // download endpoint reads the name back from it to title the file the user
    // saves. A key with no such segment predates this and reads as `technique`.
    return { html, document };
  });
  if (!prepared) return;
  const { html } = prepared;

  // ── Outside any transaction: object storage and the PDF container ──────
  const storage = getStorage();
  const key = storage
    .buildKey({ organizationId, auditRunId, type: "report", ext: "html" })
    .replace(/\.html$/, `.${document}.html`);
  const put = await storage.put(key, html, "text/html");

  // PDF is the format the deliverable is actually read and archived in — a
  // dirigeant opens a PDF, an auditor files one. Rendered from the SAME HTML,
  // so the two can never disagree about what the audit found.
  //
  // Best-effort by design: `renderPdf` returns null rather than throwing. A
  // renderer that is down must cost the customer a file format, never the
  // report itself.
  const pdf = await renderPdf(html);
  const pdfPut = pdf
    ? await storage.put(
        storage
          .buildKey({ organizationId, auditRunId, type: "pdf", ext: "pdf" })
          .replace(/\.pdf$/, `.${document}.pdf`),
        pdf,
        "application/pdf",
      )
    : null;

  const RETENTION_MS = 730 * 24 * 60 * 60 * 1000;

  await withTenant(prisma, organizationId, async (tx) => {
    const artifact = await tx.artifact.create({
      data: {
        organizationId,
        auditRunId,
        type: "report",
        storageKey: put.key,
        contentType: "text/html",
        sizeBytes: put.sizeBytes,
        checksum: put.checksum,
        // Stamp the published retention on the row at creation time. The policy
        // (apps/web/lib/legal.ts) keeps reports 24 months; a duration that is
        // only written in a document cannot be enforced, and this column is
        // what apps/api/src/account/retention.service.ts actually purges on.
        retentionExpiresAt: new Date(Date.now() + RETENTION_MS),
      },
    });

    const pdfArtifact = pdfPut
      ? await tx.artifact.create({
          data: {
            organizationId,
            auditRunId,
            // Typed as what it is. Storing a PDF under `report` — or HTML under
            // `pdf` — is what makes a row lie about its own content and the
            // download endpoint serve the wrong type.
            type: "pdf",
            storageKey: pdfPut.key,
            contentType: "application/pdf",
            sizeBytes: pdfPut.sizeBytes,
            checksum: pdfPut.checksum,
            retentionExpiresAt: new Date(Date.now() + RETENTION_MS),
          },
        })
      : null;

    if (reportId) {
      await tx.report.update({
        where: { id: reportId },
        data: {
          status: "ready",
          // Point at the PDF when there is one, at the HTML when the renderer
          // was unavailable — the download endpoint follows this row, so the
          // customer gets the best format that actually exists.
          pdfArtifactId: pdfArtifact?.id ?? artifact.id,
          generatedAt: new Date(),
        },
      });
    }
  });
  await publisher.log(auditRunId, `report rendered: ${document}`);
}

// ── Boot ──────────────────────────────────────────────────────────────────

const worker = new Worker<AuditJob>(
  QUEUE_NAMES.audit,
  async (job) => processAudit(job.data),
  {
    connection: createRedis(),
    concurrency: Number(process.env.WORKER_CONCURRENCY ?? 4),
  },
);

worker.on("failed", (job, err) => {
  // eslint-disable-next-line no-console
  console.error(`[worker] job ${job?.id} failed:`, err.message);
});
worker.on("ready", () => {
  // eslint-disable-next-line no-console
  console.log("[worker] ready, consuming audit jobs");
});

/**
 * Second job of this process: the nightly retention purge. It runs on its OWN
 * queue with its own connections and concurrency 1, so it can never take a slot
 * from an audit — see retention-scheduler.ts for the mechanism and for why the
 * schedule lives in Valkey rather than in this process.
 */
const retention = startRetentionScheduler();

async function shutdown(): Promise<void> {
  await worker.close();
  await retention.close().catch(() => {});
  await redis.quit().catch(() => {});
  await prisma.$disconnect().catch(() => {});
  process.exit(0);
}
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
