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
  /** For DAST/UX only: the verified target. */
  target?: { url: string; scopeAllowlist?: string[] };
}

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
}
