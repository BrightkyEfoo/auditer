import { z } from "zod";

/**
 * Controlled vocabulary for the whole system. Every scanner adapter normalizes
 * into these values; the DB, the AI layer, and the UI all speak them.
 *
 * These are the single source of truth — Prisma enums and the ts-rest contract
 * are derived from (kept in sync with) the values here.
 */

/** The seven audit pillars. A scanner belongs to exactly one. */
export const Pillar = z.enum([
  "secrets", // Gitleaks, TruffleHog — exposed credentials over git history
  "sca", // osv-scanner, Trivy, Grype — dependency / CVE scanning
  "sast", // Semgrep + language-native — static security + code smells
  "quality", // eslint/ruff/golangci + scc/lizard/jscpd — maintainability metrics
  "hygiene", // Trivy config, Checkov, hadolint, Scorecard — IaC / repo posture
  "dast", // ZAP, nuclei, testssl — live web pen-testing (authorized targets only)
  "ux", // Lighthouse, axe-core, Claude vision — perf / a11y / UX
]);
export type Pillar = z.infer<typeof Pillar>;

/** Normalized severity. `score` (CVSS 0-10) is carried separately on Finding. */
export const Severity = z.enum(["critical", "high", "medium", "low", "info"]);
export type Severity = z.infer<typeof Severity>;

/** Deterministic ordering weight (higher = worse). Used by scoring + sorting. */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/** Lifecycle of an audit run. Drives the SSE progress stepper. */
export const AuditStatus = z.enum([
  "queued",
  "cloning",
  "scanning",
  "analyzing", // AI enrichment pass
  "reporting", // score + report assembly
  "done",
  "completed_with_errors", // partial-failure: some scanners failed, findings kept
  "failed",
  "canceled",
]);
export type AuditStatus = z.infer<typeof AuditStatus>;

/** Terminal states — no further transitions. */
export const TERMINAL_AUDIT_STATUSES: ReadonlySet<AuditStatus> = new Set([
  "done",
  "completed_with_errors",
  "failed",
  "canceled",
]);

/** Per-scanner execution status. */
export const ScanStatus = z.enum([
  "pending",
  "running",
  "success",
  "partial",
  "failed",
  "skipped", // relevance-gated out (e.g. no matching manifest/language)
]);
export type ScanStatus = z.infer<typeof ScanStatus>;

/**
 * Classification of a scanner's raw exit code. CRITICAL: many scanners exit
 * nonzero *when they find issues* — that is `success`/`partial`, NOT `fail`.
 * Only real infra/tool errors are `fail` and eligible for retry.
 */
export const ExitClass = z.enum(["success", "partial", "fail"]);
export type ExitClass = z.infer<typeof ExitClass>;

/** Sandbox isolation strength. gVisor is the day-1 default. */
export const IsolationTier = z.enum([
  "gvisor", // default — runsc, ordinary VPS
  "microvm", // Firecracker/Kata — reserved for code-executing steps (build/install/DAST)
]);
export type IsolationTier = z.infer<typeof IsolationTier>;

/** Finding triage lifecycle. Keyed on fingerprint, persists across runs. */
export const TriageStatus = z.enum([
  "open",
  "false_positive",
  "ignored",
  "fixed",
  "accepted", // acknowledged risk, intentionally not fixed
]);
export type TriageStatus = z.infer<typeof TriageStatus>;

/** VCS providers. Login OAuth and repo-access tokens are separate concerns. */
export const Provider = z.enum(["github", "gitlab"]);
export type Provider = z.infer<typeof Provider>;

/** How a VCS connection authenticates for repo access. */
export const ConnectionKind = z.enum([
  "github_app",
  "gitlab_oauth",
  "gitlab_pat",
]);
export type ConnectionKind = z.infer<typeof ConnectionKind>;

/** DAST target ownership-verification state. Enforced in the data model. */
export const VerificationStatus = z.enum([
  "unverified",
  "pending",
  "verified",
  "revoked",
]);
export type VerificationStatus = z.infer<typeof VerificationStatus>;

/** Membership roles within an organization. */
export const Role = z.enum(["owner", "admin", "member", "viewer"]);
export type Role = z.infer<typeof Role>;

/** Package ecosystems for SCA findings (purl-aligned subset). */
export const Ecosystem = z.enum([
  "npm",
  "pypi",
  "go",
  "maven",
  "gradle",
  "composer",
  "cargo",
  "rubygems",
  "nuget",
  "other",
]);
export type Ecosystem = z.infer<typeof Ecosystem>;

/** Letter grade derived from a 0-100 pillar/overall score. */
export const Grade = z.enum(["A", "B", "C", "D", "F"]);
export type Grade = z.infer<typeof Grade>;
