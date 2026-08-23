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
export { computeScore, SCORING_VERSION } from "./scoring/index.js";
export {
  runScan,
  aggregate,
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
export { TrivyConfigAdapter } from "./scanners/trivy-config.js";
export { HadolintAdapter } from "./scanners/hadolint.js";
export { NucleiAdapter } from "./scanners/nuclei.js";
export { LighthouseAdapter } from "./scanners/lighthouse.js";

// AI layer
export { AiClient, MODELS, untrusted, type UsageRecord } from "./ai/client.js";
export { enrichFinding, enrichBatch } from "./ai/enrich.js";
export { synthesizeReport } from "./ai/report.js";
