// Ports
export * from "./ports/adapter.js";
export * from "./ports/sandbox.js";

// Sandbox runners
export { DockerGvisorRunner } from "./sandbox/docker-gvisor-runner.js";

// Normalization
export { normalizeSarif, type SarifLog } from "./normalize/sarif.js";
export { computeFingerprint, withFingerprints } from "./normalize/fingerprint.js";

// Pipeline
export { dedupe, type DedupResult } from "./dedup/index.js";
// Cross-run comparison. Lives here rather than in the worker because it is a
// pure function over findings — the same package that computes the score, and
// the only place in the repo with a test harness.
export {
  computeDelta,
  type DeltaFinding,
  type DeltaSnapshot,
  type DeltaEntry,
  type DeltaResult,
  type SeverityMovement,
  type ComputeDeltaInput,
} from "./delta/index.js";
export { computeScore, SCORING_VERSION } from "./scoring/index.js";
export {
  runScan,
  aggregate,
  collectKloc,
  type RunScanResult,
  type AggregateInput,
  type AggregateOutput,
} from "./orchestrator.js";

// Registry + adapters
export { ScannerRegistry, defaultRegistry } from "./registry.js";
export { GitleaksAdapter } from "./scanners/gitleaks.js";
export { OsvScannerAdapter } from "./scanners/osv-scanner.js";
export { SemgrepAdapter } from "./scanners/semgrep.js";
export { JscpdAdapter } from "./scanners/jscpd.js";
export { SccAdapter, SCC_METRIC_KEYS } from "./scanners/scc.js";
export { TrivyConfigAdapter } from "./scanners/trivy-config.js";
export { HadolintAdapter } from "./scanners/hadolint.js";
export { ZizmorAdapter } from "./scanners/zizmor.js";
export { NucleiAdapter } from "./scanners/nuclei.js";
export { LighthouseAdapter } from "./scanners/lighthouse.js";

// Vulnerability feed enrichment (EPSS + CISA KEV) — deterministic, offline,
// control-plane only. Never called from inside a scanner sandbox.
export {
  loadVulnFeeds,
  enrichWithVulnFeeds,
  enrichFindingsFromFeeds,
  prioritizeFindings,
  comparePriority,
  summarizeExploitability,
  resetVulnFeedsCache,
  parseEpssCsv,
  parseKevJson,
  VulnFeedsIndex,
  VulnFeedFormatError,
  EPSS_MATERIALITY_FLOOR,
  EPSS_HIGH_THRESHOLD,
  DEFAULT_MAX_SNAPSHOT_AGE_DAYS,
  VULN_FEEDS_PATH_ENV,
  VULN_FEEDS_MANIFEST_VERSION,
  type VulnFeedsManifest,
  type VulnFeedsWarning,
  type VulnFeedsWarningCode,
  type LoadVulnFeedsOptions,
  type LoadVulnFeedsResult,
  type VulnEnrichable,
  type VulnEnrichmentResult,
  type VulnEnrichmentStats,
  type PrioritizableFinding,
  type PrioritizeOptions,
  type ExploitabilitySummary,
  type EpssScore,
  type KevRecord,
} from "./enrich/vuln-feeds.js";
export { refreshVulnFeeds, type RefreshOptions, type RefreshResult } from "./enrich/refresh-feeds.js";

// AI layer
export { AiClient, MODELS, untrusted, type UsageRecord } from "./ai/client.js";
export { enrichFinding, enrichBatch } from "./ai/enrich.js";
export { synthesizeReport } from "./ai/report.js";
