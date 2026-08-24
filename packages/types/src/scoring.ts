import { z } from "zod";
import { Pillar, Severity, Grade } from "./enums.js";

/**
 * Scoring is deterministic and versioned. Claude explains the number, it never
 * computes it. The formula: start at 100 per pillar, apply an asymptotic
 * weighted deduction per finding (severity weight, density-normalized per
 * KLOC), then clamp under hard severity ceilings (any open Critical caps the
 * grade at F). `scoringVersion` is stamped onto every AuditRun so two scans of
 * the same commit produce the same score and the number stays explainable.
 */

/**
 * Bump when the formula or weights change. Stamped per run.
 *
 * 1.1.0 — the density factor stopped being a constant. The weights and the
 * curve are untouched, but until this version nothing measured a repo's size,
 * so every run scored on the `ASSUMED_KLOC` fallback and `(1 + 1/kloc)` was
 * 1.1 for a 2 kLOC script and a 900 kLOC monolith alike. Runs stamped 1.0.0 are
 * therefore NOT comparable to 1.1.0 runs of the same commit.
 */
export const SCORING_VERSION = "1.1.0";

/**
 * Density fallback, used only when no scanner measured the repo (the quality
 * pillar was not requested, or scc failed). It is a placeholder that keeps the
 * formula defined — never a measurement. Any run using it is stamped
 * `klocSource: "assumed"` so a report can say so out loud.
 */
export const ASSUMED_KLOC = 10;

/** Whether the kLOC that normalized a score was measured or merely assumed. */
export const KlocSource = z.enum(["measured", "assumed"]);
export type KlocSource = z.infer<typeof KlocSource>;

/** Per-severity deduction weight (points removed, before asymptotic damping). */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 8,
  low: 3,
  info: 0.5,
};

/**
 * Hard ceilings: an open finding of this severity caps the pillar grade no
 * matter the raw score. Communicates risk the way real pentest reports do.
 */
export const SEVERITY_CEILING: Partial<Record<Severity, Grade>> = {
  critical: "F",
  high: "C",
};

export const GradeBand = z.object({
  min: z.number(),
  grade: Grade,
});

/** Score → letter grade thresholds (before ceilings are applied). */
export const GRADE_BANDS: ReadonlyArray<{ min: number; grade: Grade }> = [
  { min: 90, grade: "A" },
  { min: 75, grade: "B" },
  { min: 60, grade: "C" },
  { min: 40, grade: "D" },
  { min: 0, grade: "F" },
];

export const SeverityCounts = z.object({
  critical: z.number().int().nonnegative().default(0),
  high: z.number().int().nonnegative().default(0),
  medium: z.number().int().nonnegative().default(0),
  low: z.number().int().nonnegative().default(0),
  info: z.number().int().nonnegative().default(0),
});
export type SeverityCounts = z.infer<typeof SeverityCounts>;

/** Computed result for one pillar within a run. */
export const PillarResult = z.object({
  pillar: Pillar,
  score: z.number().min(0).max(100),
  grade: Grade,
  counts: SeverityCounts,
  /** true when a scanner in this pillar failed but partial findings were kept. */
  partial: z.boolean().default(false),
});
export type PillarResult = z.infer<typeof PillarResult>;

/** The run-level rollup. */
export const RunScore = z.object({
  scoringVersion: z.string(),
  overall: z.number().min(0).max(100),
  grade: Grade,
  pillars: z.array(PillarResult),
  counts: SeverityCounts,
  /**
   * The size the score was normalized by, and its provenance. Both are on the
   * record because a score whose normalization is unknown is not defensible in
   * an audit report: "B on 240 kLOC measured" and "B on an assumed 10 kLOC" are
   * different claims and a reader must be able to tell them apart.
   */
  kloc: z.number().positive(),
  klocSource: KlocSource,
});
export type RunScore = z.infer<typeof RunScore>;
