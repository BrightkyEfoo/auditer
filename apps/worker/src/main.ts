import { Worker } from "bullmq";
import { createPrisma, withTenant } from "@auditer/db";
import { createRedis, QUEUE_NAMES, cancelFlag, type AuditJob } from "@auditer/queue";
import { kekFromEnv, open as openSecret } from "@auditer/crypto";
import {
  defaultRegistry,
  DockerGvisorRunner,
  runScan,
  aggregate,
  AiClient,
  type ScanContext,
  type RunScanResult,
} from "@auditer/audit-engine";
import type { RawFinding, Pillar, TriageStatus } from "@auditer/types";
import type { ExecutiveSummary } from "@auditer/types";
import { getStorage } from "@auditer/storage";
import { EventPublisher } from "./events.js";
import { prepare, type Workspace } from "./workspace.js";
import { mintInstallationToken } from "./github-app.js";
import { validGitlabToken } from "./gitlab.js";
import { buildReportHtml } from "./report-html.js";

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
      await publisher.log(auditRunId, `cloned ${cloneUrl} (${ws.manifests.length} manifests)`);
      ctx = { auditRunId, organizationId, workspacePath: ws.path, manifests: ws.manifests };
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

    const adapters = registry.forPillars(job.pillars);
    const allRaw: RawFinding[] = [];
    const fpToScanId = new Map<string, string>();
    const pillarsRun = new Set<Pillar>();

    for (const adapter of adapters) {
      if (await isCanceled(auditRunId)) {
        await finalize(auditRunId, organizationId, "canceled");
        return;
      }
      await publisher.scan(auditRunId, adapter.pillar, adapter.tool, "running");

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
        await publisher.scan(auditRunId, adapter.pillar, adapter.tool, "failed");
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
        },
      );
      if (result.exitClass === "partial") partialPillars.add(adapter.pillar);

      for (const f of result.findings) {
        allRaw.push(f);
        if (!fpToScanId.has(f.fingerprint)) fpToScanId.set(f.fingerprint, scanId);
      }
      await publisher.scan(
        auditRunId,
        adapter.pillar,
        adapter.tool,
        result.skipped ? "skipped" : "success",
        result.findings.length,
      );
    }

    await setStatus(auditRunId, organizationId, "analyzing");
    await publisher.status(auditRunId, "analyzing");

    // Load persisted triage so scoring respects false-positives across runs.
    const triage = await loadTriage(organizationId);

    const agg = await aggregate({
      organizationId,
      auditRunId,
      rawFindings: allRaw,
      pillarsRun: [...pillarsRun],
      partialPillars,
      triageByFingerprint: triage,
      ai,
      enableAi: Boolean(ai),
    });

    await setStatus(auditRunId, organizationId, "reporting");
    await publisher.status(auditRunId, "reporting");

    // Persist findings + pillar results + score + report summary.
    await persistResults(organizationId, auditRunId, agg, fpToScanId);

    const finalStatus = partialPillars.size > 0 ? "completed_with_errors" : "done";
    await finalize(auditRunId, organizationId, finalStatus, agg.score.overall);
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
): Promise<void> {
  await withTenant(prisma, organizationId, (tx) =>
    tx.auditRun.update({
      where: { id: auditRunId },
      data: {
        status: status as never,
        finishedAt: new Date(),
        ...(riskScore !== undefined ? { riskScore } : {}),
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
  data: { status: string; exitCode?: number; exitClass?: string; error?: unknown },
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
        finishedAt: new Date(),
      },
      update: {
        status: data.status as never,
        exitCode: data.exitCode,
        exitClass: data.exitClass as never,
        error: data.error as never,
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
 * print-ready HTML report from the persisted run + findings + summary, uploads
 * it to object storage, and links it on the Report. (Binary PDF via a headless
 * Chromium container printing this exact HTML is the one remaining infra step;
 * the HTML artifact is already a complete, downloadable, print-ready report.)
 */
async function renderReport(job: AuditJob): Promise<void> {
  const { organizationId, auditRunId } = job;
  const reportId = (job.scopeConfig?.reportId as string) ?? undefined;

  await withTenant(prisma, organizationId, async (tx) => {
    const run = await tx.auditRun.findFirst({ where: { id: auditRunId, organizationId } });
    if (!run) return;
    const repo = run.repositoryId
      ? await tx.repository.findFirst({ where: { id: run.repositoryId } })
      : null;
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

    const html = buildReportHtml({
      runId: auditRunId,
      fullName: repo?.fullName ?? null,
      commitSha: run.commitSha,
      riskScore: run.riskScore,
      scoringVersion: run.scoringVersion,
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
      })),
      scanners: scans.map((s) => ({ tool: s.tool, pillar: s.pillar })),
      generatedAt: new Date().toISOString(),
    });

    const storage = getStorage();
    const key = storage.buildKey({ organizationId, auditRunId, type: "pdf", ext: "html" });
    const put = await storage.put(key, html, "text/html");
    const artifact = await tx.artifact.create({
      data: {
        organizationId,
        auditRunId,
        type: "pdf",
        storageKey: put.key,
        contentType: "text/html",
        sizeBytes: put.sizeBytes,
        checksum: put.checksum,
      },
    });

    if (reportId) {
      await tx.report.update({
        where: { id: reportId },
        data: { status: "ready", pdfArtifactId: artifact.id, generatedAt: new Date() },
      });
    }
  });
  await publisher.log(auditRunId, "report rendered (HTML artifact stored)");
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

async function shutdown(): Promise<void> {
  await worker.close();
  await redis.quit().catch(() => {});
  await prisma.$disconnect().catch(() => {});
  process.exit(0);
}
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
