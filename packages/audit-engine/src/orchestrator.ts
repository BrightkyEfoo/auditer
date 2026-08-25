import type {
  RawFinding,
  Finding,
  ExitClass,
  Pillar,
  RunScore,
  ExecutiveSummary,
} from "@auditer/types";
import type { ScannerAdapter, ScanContext, ScanMetrics } from "./ports/adapter.js";
import type { SandboxRunner } from "./ports/sandbox.js";
import { CONTAINER_REPO_PATH } from "./ports/sandbox.js";
import { SCC_METRIC_KEYS } from "./scanners/scc.js";
import { enrichFindingsFromFeeds } from "./enrich/vuln-feeds.js";
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
  /** Measurements, when the adapter produces any (see ScannerAdapter.measure). */
  metrics?: ScanMetrics;
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

  // Measurements share that gate: a failed tool's stdout is not a measurement.
  const metrics =
    exitClass === "fail" || !adapter.measure
      ? undefined
      : await adapter.measure(result, ctx);

  return {
    ...base,
    exitClass,
    exitCode: result.exitCode,
    timedOut: result.timedOut,
    durationMs: result.durationMs,
    findings,
    metrics,
    skipped: false,
  };
}

/**
 * Fold the per-scan measurements of a run into the kLOC the score normalizes by.
 *
 * Lives here, not in the worker, so the metric key stays private to the engine:
 * the worker should not have to know that "loc.code" is what scc calls its line
 * count. Sums across scanners because a second measuring tool (lizard, ULOC) can
 * be added without touching this. Returns undefined — never a default — when
 * nothing measured anything; choosing the fallback is scoring's job, and only
 * scoring can then label the result honestly as assumed rather than measured.
 */
export function collectKloc(
  results: readonly Pick<RunScanResult, "metrics">[],
): number | undefined {
  let code = 0;
  let measured = false;
  for (const r of results) {
    const v = r.metrics?.[SCC_METRIC_KEYS.code];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) {
      code += v;
      measured = true;
    }
  }
  return measured ? code / 1000 : undefined;
}

export interface AggregateInput {
  organizationId: string;
  auditRunId: string;
  /** All raw findings from every scan in the run. */
  rawFindings: RawFinding[];
  pillarsRun: Pillar[];
  partialPillars?: Set<Pillar>;
  /**
   * Measured thousands of lines of code (see `collectKloc`). Leave undefined
   * when no scanner measured the repo — scoring then falls back and stamps the
   * result `klocSource: "assumed"`.
   */
  kloc?: number;
  /** Existing triage decisions, keyed by fingerprint (persist across runs). */
  triageByFingerprint?: Map<string, Finding["triageStatus"]>;
  ai?: AiClient;
  /** When false, skip the AI passes (dedup + score still run). */
  enableAi?: boolean;
  /**
   * Called for every degraded-enrichment condition (missing mount, stale
   * snapshot, checksum mismatch). The worker forwards these to the run log so a
   * report produced without exploitability data says so out loud.
   */
  onWarning?: (message: string) => void;
}

export interface AggregateOutput {
  findings: Finding[];
  dedup: DedupResult;
  score: RunScore;
  summary?: ExecutiveSummary;
  /**
   * `YYYY-MM-DD` of the EPSS/KEV snapshot that informed this run, or null when
   * no enrichment happened. Persist it on the AuditRun: without it, two runs of
   * the same commit can differ and the determinism claim is unverifiable.
   */
  vulnFeedsSnapshot: string | null;
}

/**
 * The post-scan pipeline: deterministic dedup FIRST, then AI enrichment on the
 * representatives only, then deterministic scoring, then (optionally) the
 * executive report. Order is non-negotiable — dedup before AI controls cost and
 * stops hallucinated re-dedup; scoring is deterministic and AI never computes it.
 */
export async function aggregate(input: AggregateInput): Promise<AggregateOutput> {
  const dedup = dedupe(input.rawFindings);

  // Exploitability enrichment, BEFORE the model sees anything and before the
  // score is computed. Order matters twice over: the model's explanation should
  // be able to say "this one is actively exploited", and the snapshot date has
  // to be recorded alongside the score it informed — a run whose feed date is
  // unknown cannot claim a deterministic result.
  //
  // Runs on representatives only, like the AI pass: enriching the members we
  // already collapsed would spend memory to produce rows nobody reads.
  //
  // A missing or stale snapshot degrades to unenriched findings plus warnings,
  // never to a throw. A scan that fails because a data feed is a day late would
  // be a worse product than one that says so.
  const vuln = await enrichFindingsFromFeeds(dedup.representatives);
  for (const w of vuln.warnings) input.onWarning?.(w.message);

  // AI enrichment on representatives only.
  const enableAi = input.enableAi ?? Boolean(input.ai);
  const enrichmentByFp = enableAi && input.ai
    ? await enrichBatch(input.ai, dedup.representatives)
    : new Map();

  // Materialize persisted Findings from representatives (one row per group).
  const findings: Finding[] = vuln.findings.map((rep, i) => {
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
  // `score.overall === null` means no pillar was measured. There is nothing to
  // summarise, and asking a model to write an executive summary over an audit
  // that analysed nothing would produce the most confident-sounding page in the
  // whole document — about no data at all.
  if (enableAi && input.ai && score.overall !== null) {
    const ranked = [...findings].sort(
      (a, b) =>
        (b.ai?.priority ?? severityRank(b)) -
        (a.ai?.priority ?? severityRank(a)),
    );
    summary = await synthesizeReport(input.ai, score, ranked);
  }

  return { findings, dedup, score, summary, vulnFeedsSnapshot: vuln.snapshotDate };
}

function severityRank(f: Finding): number {
  return { critical: 90, high: 70, medium: 40, low: 20, info: 5 }[f.severity];
}
