import { z } from "zod";
import {
  Pillar,
  Severity,
  Ecosystem,
  TriageStatus,
} from "./enums.js";

/**
 * The canonical Finding — the single shape every scanner (via SARIF or native
 * JSON) is normalized into. One dedup algorithm, one renderer, one AI input,
 * one DB row read from this.
 *
 * Split into layers by provenance:
 *   - `RawFinding`     : what a ScannerAdapter emits (deterministic detection only)
 *   - `AiEnrichment`   : what Claude adds on top (never the source of a finding)
 *   - `Finding`        : the persisted union (raw + optional enrichment + triage)
 */

/** Source location in code (SAST/secrets/quality/hygiene). */
export const CodeLocation = z.object({
  path: z.string(),
  startLine: z.number().int().nonnegative().optional(),
  endLine: z.number().int().nonnegative().optional(),
  startColumn: z.number().int().nonnegative().optional(),
  endColumn: z.number().int().nonnegative().optional(),
  symbol: z.string().optional(),
  /** Git commit where a secret was introduced (secrets pillar). */
  commitSha: z.string().optional(),
});
export type CodeLocation = z.infer<typeof CodeLocation>;

/** Web target location (DAST). */
export const WebLocation = z.object({
  url: z.string(),
  method: z.string().optional(),
  param: z.string().optional(),
});
export type WebLocation = z.infer<typeof WebLocation>;

/** Vulnerable dependency descriptor (SCA). */
export const PackageRef = z.object({
  ecosystem: Ecosystem,
  name: z.string(),
  version: z.string(),
  /** purl (package URL), the cross-tool dedup key for SCA. */
  purl: z.string().optional(),
  fixedVersion: z.string().optional(),
  /** true when the vuln is on a transitive (indirect) dependency. */
  transitive: z.boolean().optional(),
});
export type PackageRef = z.infer<typeof PackageRef>;

/**
 * Enrichment fields for SCA/CVE prioritization. Populated deterministically
 * from EPSS / CISA-KEV feeds, NOT by the AI.
 */
export const VulnEnrichment = z.object({
  epssScore: z.number().min(0).max(1).optional(),
  epssPercentile: z.number().min(0).max(1).optional(),
  knownExploited: z.boolean().optional(), // CISA KEV
});
export type VulnEnrichment = z.infer<typeof VulnEnrichment>;

/**
 * Deterministic detection output from a scanner adapter. Contains NOTHING the
 * AI produced — this is the ground truth every reported finding traces back to.
 */
export const RawFinding = z.object({
  pillar: Pillar,
  /** Tool that produced it, e.g. "gitleaks", "osv-scanner". */
  tool: z.string(),
  toolVersion: z.string().optional(),
  /** Tool-native rule / check identifier. */
  ruleId: z.string(),

  severity: Severity,
  /** CVSS 0-10 when the tool provides one (authoritative for CVEs). */
  cvssScore: z.number().min(0).max(10).optional(),
  cvssVector: z.string().optional(),
  /** Tool-reported confidence 0-1, pre-AI. */
  confidence: z.number().min(0).max(1).optional(),

  title: z.string(),
  description: z.string().default(""),

  cwe: z.array(z.string()).default([]),
  /** CVE / GHSA / OSV ids. The AI may NEVER mint these — only echo verified ones. */
  vulnIds: z.array(z.string()).default([]),
  owaspCategory: z.string().optional(),

  location: CodeLocation.optional(),
  target: WebLocation.optional(),
  package: PackageRef.optional(),
  vuln: VulnEnrichment.optional(),

  /** Redacted evidence (matched string with secret masked, code snippet, etc.). */
  evidence: z.string().optional(),
  references: z.array(z.string().url()).default([]),

  /**
   * Stable content fingerprint: hash of (tool + ruleId + normalized-location
   * [+ purl/version/vulnId for SCA]). Identity across runs; survives refactors.
   * Computed by the normalizer, not the scanner.
   */
  fingerprint: z.string(),

  /** Pointer to raw tool output blob in object storage (audit trail). */
  rawRef: z.string().optional(),

  /** Tool-specific fields we don't model first-class. */
  extras: z.record(z.unknown()).optional(),
});
export type RawFinding = z.infer<typeof RawFinding>;

/**
 * What Claude returns for a single (deduped, representative) finding. Schema-
 * locked structured output. Every field is advisory — it explains and
 * prioritizes, it does not detect. `citations` must reference the raw finding.
 */
export const AiEnrichment = z.object({
  /** Plain-language explanation of the risk for a non-expert. */
  explanation: z.string(),
  /** Concrete remediation guidance. */
  remediation: z.string(),
  /** Optional unified-diff suggestion. Never auto-applied. */
  suggestedFixDiff: z.string().optional(),
  /** AI's real-world priority 0-100 (feeds scoring as a weight, not the score). */
  priority: z.number().min(0).max(100),
  /** AI confidence this is a true, exploitable finding. */
  confidence: z.number().min(0).max(1),
  /** true when the AI thinks this needs a human before trusting the verdict. */
  needsHuman: z.boolean().default(false),
  /** file:line (or url) citations grounding the explanation in the raw finding. */
  citations: z.array(z.string()).default([]),
  /** Which model produced this enrichment (for the report + audit trail). */
  model: z.string().optional(),
});
export type AiEnrichment = z.infer<typeof AiEnrichment>;

/**
 * The fully persisted finding: deterministic raw + optional AI enrichment +
 * current triage state + cross-run identity + dedup grouping.
 */
export const Finding = RawFinding.extend({
  id: z.string(),
  organizationId: z.string(),
  auditRunId: z.string(),
  scanId: z.string(),

  ai: AiEnrichment.optional(),

  triageStatus: TriageStatus.default("open"),

  dedupeGroupId: z.string().optional(),
  /** Number of distinct tools that reported this same issue (post-dedup). */
  sourceCount: z.number().int().positive().default(1),

  firstSeenRunId: z.string().optional(),
  lastSeenRunId: z.string().optional(),
});
export type Finding = z.infer<typeof Finding>;

/** A cluster of raw findings judged to be the same underlying issue. */
export const DedupeGroup = z.object({
  id: z.string(),
  representativeFingerprint: z.string(),
  memberFingerprints: z.array(z.string()),
  sourceCount: z.number().int().positive(),
  maxSeverity: Severity,
});
export type DedupeGroup = z.infer<typeof DedupeGroup>;
