import { z } from "zod";
import { Grade, Severity } from "./enums.js";
import { RunScore } from "./scoring.js";

/**
 * The executive report payload. `summary` is authored by Claude (Opus tier) as
 * schema-locked JSON over the deterministic, deduped findings + the computed
 * score. It narrates; it does not invent findings or scores.
 */

export const ExecutiveSummary = z.object({
  /** 2-4 sentence overview of the audit outcome. */
  headline: z.string(),
  overallGrade: Grade,
  /** Prose risk posture statement. */
  riskPosture: z.string(),
  /** Top prioritized issues, most urgent first (references findings by title). */
  keyRisks: z.array(
    z.object({
      title: z.string(),
      severity: Severity,
      why: z.string(),
    }),
  ),
  /** Ordered remediation roadmap. */
  remediationRoadmap: z.array(
    z.object({
      step: z.string(),
      effort: z.enum(["low", "medium", "high"]),
      impact: z.enum(["low", "medium", "high"]),
    }),
  ),
  /** Model that authored the summary + a flag that AI content is labeled. */
  model: z.string(),
});
export type ExecutiveSummary = z.infer<typeof ExecutiveSummary>;

/** Everything the dashboard/PDF renders for a completed run. */
export const ReportPayload = z.object({
  auditRunId: z.string(),
  generatedAt: z.string().datetime(),
  score: RunScore,
  summary: ExecutiveSummary,
  /** Scope + methodology note (which scanners ran, DB provenance/age). */
  methodology: z.object({
    pillars: z.array(z.string()),
    scanners: z.array(
      z.object({
        tool: z.string(),
        version: z.string().optional(),
        pillar: z.string(),
        dbSnapshot: z.string().optional(), // vuln DB provenance/date — never imply 100%
      }),
    ),
  }),
});
export type ReportPayload = z.infer<typeof ReportPayload>;

/**
 * The deliverables a mission produces. NIST SP 800-115 puts it plainly — "a
 * report may have multiple audiences, multiple report formats may be required"
 * — and the reference firms all ship several documents per engagement, because
 * the five readers of an audit do not read the same thing:
 *
 *   - `technique`    : the full relevé, findings included. Exploitable content.
 *   - `dirigeant`    : two pages, business consequence and trend, no CVE, no
 *                      CVSS, no engine name. Written to be read by someone who
 *                      will never open the technical report.
 *   - `attestation`  : one page, signed, shareable. Attests to an ENGAGEMENT
 *                      and its declared tooled coverage — never to a level of
 *                      security.
 *   - `progression`  : the delta against the previous relevé. The only document
 *                      that answers the second question every executive asks:
 *                      is this getting better or worse?
 *
 * This is the DELIVERABLE, not the container. The container (HTML today, PDF
 * once the paged renderer lands) is `ReportFormat` on the Report row; the two
 * are orthogonal and conflating them is how a row ends up lying about its own
 * content.
 */
export const ReportDocument = z.enum([
  "technique",
  "dirigeant",
  "attestation",
  "progression",
]);
export type ReportDocument = z.infer<typeof ReportDocument>;

export const DEFAULT_REPORT_DOCUMENT: ReportDocument = "technique";

/**
 * Container names posted by clients written before the four documents existed
 * (apps/web still sends `{ format: "html" }`). They named a file type, not a
 * deliverable, so they all resolve to the full technical relevé — which is what
 * they used to produce. Kept as an alias rather than removed: breaking a caller
 * to tidy a vocabulary is not a trade worth making.
 */
const LEGACY_ALIASES: Record<string, ReportDocument> = {
  html: "technique",
  pdf: "technique",
};

/** Accepts a document name or a legacy container name; anything else is null. */
export function normalizeReportDocument(value: unknown): ReportDocument | null {
  if (typeof value !== "string") return null;
  const parsed = ReportDocument.safeParse(value);
  if (parsed.success) return parsed.data;
  return LEGACY_ALIASES[value] ?? null;
}

/** Reader-facing name of each deliverable, for filenames and UI labels. */
export const REPORT_DOCUMENT_LABEL: Record<ReportDocument, string> = {
  technique: "Rapport technique",
  dirigeant: "Note de direction",
  attestation: "Attestation d'audit",
  progression: "Rapport de progression",
};
