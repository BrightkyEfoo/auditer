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
