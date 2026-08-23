import type {
  RawFinding,
  Finding,
  ExitClass,
  Pillar,
  RunScore,
  ExecutiveSummary,
} from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "./ports/adapter.js";
import type { SandboxRunner } from "./ports/sandbox.js";
import { CONTAINER_REPO_PATH } from "./ports/sandbox.js";
import { dedupe, type DedupResult } from "./dedup/index.js";
import { computeScore } from "./scoring/index.js";
import { AiClient } from "./ai/client.js";
import { enrichBatch } from "./ai/enrich.js";
import { synthesizeReport } from "./ai/report.js";

/**
 * The orchestrator wires the pipeline together but owns no I/O policy — the
 * worker passes in the sandbox runner, workspace path, and AI client. Two entry
 * points:
 *   - runScan()  : one scanner → sandbox → classify → parse → RawFinding[]
 *   - aggregate(): all raw findings → dedup → AI enrich → score → report
 */

export interface RunScanResult {
  scannerId: string;
  pillar: Pillar;
  tool: string;
  exitClass: ExitClass;
  exitCode: number;
  timedOut: boolean;
  durationMs: number;
  findings: RawFinding[];
  skipped: boolean;
}

/** Execute a single scanner against a prepared workspace. */
export async function runScan(
  adapter: ScannerAdapter,
  runner: SandboxRunner,
  ctx: ScanContext,
): Promise<RunScanResult> {
  const base = {
    scannerId: adapter.id,
    pillar: adapter.pillar,
    tool: adapter.tool,
  };

  if (!adapter.appliesTo(ctx)) {
    return {
      ...base,
      exitClass: "success",
      exitCode: 0,
      timedOut: false,
      durationMs: 0,
      findings: [],
      skipped: true,
    };
  }

  // Build the sandbox spec and inject the real workspace path into the repo mount.
  const spec = adapter.buildSpec(ctx);
  spec.mounts = spec.mounts.map((m) =>
    m.target === CONTAINER_REPO_PATH ? { ...m, source: ctx.workspacePath } : m,
  );

  const result = await runner.run(spec);
  const exitClass = adapter.classifyExit(result);

  // Only parse when the scan actually succeeded/partially succeeded.
  const findings =
    exitClass === "fail" ? [] : await adapter.parse(result, ctx);

  return {
    ...base,
    exitClass,
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    durationMs: result.durationMs,
    findings,
    skipped: false,
  };
}

export interface AggregateInput {
  organizationId: string;
  auditRunId: string;
  /** All raw findings from every scan in the run. */
  rawFindings: RawFinding[];
  pillarsRun: Pillar[];
  partialPillars?: Set<Pillar>;
  kloc?: number;
  /** Existing triage decisions, keyed by fingerprint (persist across runs). */
  triageByFingerprint?: Map<string, Finding["triageStatus"]>;
  ai?: AiClient;
  /** When false, skip the AI passes (dedup + score still run). */
  enableAi?: boolean;
}

export interface AggregateOutput {
  findings: Finding[];
  dedup: DedupResult;
  score: RunScore;
  summary?: ExecutiveSummary;
}

/**
 * The post-scan pipeline: deterministic dedup FIRST, then AI enrichment on the
 * representatives only, then deterministic scoring, then (optionally) the
 * executive report. Order is non-negotiable — dedup before AI controls cost and
 * stops hallucinated re-dedup; scoring is deterministic and AI never computes it.
 */
export async function aggregate(input: AggregateInput): Promise<AggregateOutput> {
  const dedup = dedupe(input.rawFindings);

  // AI enrichment on representatives only.
  const enableAi = input.enableAi ?? Boolean(input.ai);
  const enrichmentByFp = enableAi && input.ai
    ? await enrichBatch(input.ai, dedup.representatives)
    : new Map();

  // Materialize persisted Findings from representatives (one row per group).
  const findings: Finding[] = dedup.representatives.map((rep, i) => {
    const group = dedup.groups[i]!;
    const triage = input.triageByFingerprint?.get(rep.fingerprint) ?? "open";
    const ai = enrichmentByFp.get(rep.fingerprint);
    return {
      ...rep,
      id: `fnd_${input.auditRunId}_${i}`,
      organizationId: input.organizationId,
      auditRunId: input.auditRunId,
      scanId: "", // set by the worker when persisting
      ai,
      triageStatus: triage,
      dedupeGroupId: group.id,
      sourceCount: group.sourceCount,
    };
  });

  const score = computeScore({
    findings,
    kloc: input.kloc,
    pillarsRun: input.pillarsRun,
    partialPillars: input.partialPillars,
  });

  // Report synthesis over the ranked findings (top-N by severity + AI priority).
  let summary: ExecutiveSummary | undefined;
  if (enableAi && input.ai) {
    const ranked = [...findings].sort(
      (a, b) =>
        (b.ai?.priority ?? severityRank(b)) -
        (a.ai?.priority ?? severityRank(a)),
    );
    summary = await synthesizeReport(input.ai, score, ranked);
  }

  return { findings, dedup, score, summary };
}

function severityRank(f: Finding): number {
  return { critical: 90, high: 70, medium: 40, low: 20, info: 5 }[f.severity];
}
