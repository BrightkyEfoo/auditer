import type { Pillar, ExitClass, RawFinding, IsolationTier } from "@auditer/types";
import type { SandboxSpec, SandboxResult } from "./sandbox.js";

/**
 * ScannerAdapter — the plugin interface every pillar's tool implements. Adding
 * a scanner is: drop in one adapter + a digest-pinned image. The orchestrator
 * stays scanner-agnostic; it never knows what "gitleaks" or "osv-scanner" is.
 */

/** Context handed to an adapter for one scan. */
export interface ScanContext {
  auditRunId: string;
  organizationId: string;
  /** Absolute host path to the prepared, read-only repo workspace. */
  workspacePath: string;
  /** Detected language mix (bytes per language), for relevance gating. */
  languages?: Record<string, number>;
  /** Present manifest/lockfile basenames, for relevance gating. */
  manifests?: string[];
  /**
   * Repo-relative paths of every Dockerfile found in the checkout.
   *
   * Separate from `manifests`, which holds BASENAMES only: hadolint has no
   * recursive mode and its image is distroless, so there is no shell inside to
   * expand a glob. The adapter needs real paths or it scans nothing — it used to
   * assume `<repo>/Dockerfile` and fail on every repository that keeps its
   * Dockerfiles anywhere else.
   */
  dockerfiles?: string[];
  /** For DAST/UX only: the verified target. */
  target?: { url: string; scopeAllowlist?: string[] };
}

/**
 * Structured MEASUREMENTS a scanner produces — a flat, dotted-key bag of
 * numbers (`loc.code`, `loc.complexity`, ...). Deliberately not findings:
 * a measurement has no severity, no location and no remediation, so forcing it
 * through RawFinding would mean inventing all three.
 *
 * Flat `Record<string, number>` rather than a typed struct because the set of
 * metrics grows per tool (scc today, lizard/ULOC tomorrow) while the transport
 * — orchestrator → worker → `Scan.stats` Json column — must stay indifferent to
 * which tool produced what. Consumers look up the exact keys they understand
 * and ignore the rest.
 */
export type ScanMetrics = Record<string, number>;

export interface ScannerAdapter {
  /** Stable id — part of the (auditRunId, scannerId) idempotency key. */
  readonly id: string;
  readonly pillar: Pillar;
  readonly tool: string;
  /** Digest-pinned image ref. */
  readonly image: string;
  readonly isolationTier: IsolationTier;
  /** true only for steps that legitimately need network (install/DAST). */
  readonly needsNetwork: boolean;

  /**
   * Relevance gate: return false to skip (→ ScanStatus.skipped) when this
   * scanner has nothing to do (no matching manifest/language). Keeps "test ALL
   * CVEs" from running every tool on every repo.
   */
  appliesTo(ctx: ScanContext): boolean;

  /** Build the exact sandbox invocation for this scan. */
  buildSpec(ctx: ScanContext): SandboxSpec;

  /**
   * Classify the raw exit code. CRITICAL: many tools exit nonzero *because they
   * found issues* — that is success/partial, not fail. Only real tool/infra
   * errors are `fail` (retryable).
   */
  classifyExit(result: SandboxResult): ExitClass;

  /**
   * Parse the tool's raw output into canonical RawFindings. Prefer SARIF; the
   * shared SARIF normalizer handles most tools, so an adapter's parse() often
   * just delegates to it. Fingerprints are assigned by the normalizer.
   */
  parse(result: SandboxResult, ctx: ScanContext): Promise<RawFinding[]>;

  /**
   * OPTIONAL second output channel: measurements, not findings.
   *
   * Kept as a separate optional member rather than widening `parse` to return
   * `{ findings, metrics }` for two reasons. First, `parse`'s contract — raw
   * output in, canonical RawFindings out — is what makes the SARIF normalizer a
   * one-line delegation in most adapters; wrapping it in an envelope would churn
   * all eight adapters to serve one. Second, producing measurements is a real
   * capability distinction, not an incidental field: `typeof a.measure ===
   * "function"` says "this tool weighs the repo", which is exactly what the
   * orchestrator needs to know when deciding whether a run's score could be
   * size-normalized at all.
   *
   * Returns undefined when the output was unusable (truncated, malformed). A
   * missing measurement must never be silently replaced by a partial one — a
   * half-counted repo yields a too-small kLOC, which INFLATES the density factor
   * and quietly over-penalizes the repo.
   */
  measure?(result: SandboxResult, ctx: ScanContext): Promise<ScanMetrics | undefined>;
}
