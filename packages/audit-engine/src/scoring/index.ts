import type {
  Finding,
  Pillar,
  Severity,
  Grade,
  PillarResult,
  RunScore,
  SeverityCounts,
  KlocSource,
} from "@auditer/types";
import {
  SCORING_VERSION,
  SEVERITY_WEIGHT,
  SEVERITY_CEILING,
  GRADE_BANDS,
  SEVERITY_RANK,
  ASSUMED_KLOC,
} from "@auditer/types";

/**
 * Deterministic, versioned scoring. Two scans of the same commit yield the same
 * number, and the number is explainable. Claude NEVER computes it — it only
 * explains it, and its per-finding confidence can down-weight a finding it
 * flags as a false positive.
 *
 * Formula per pillar:
 *   score = 100 - Σ dampedDeduction(finding)
 *   dampedDeduction uses an asymptotic curve so 50 lows don't drive a repo to
 *   -300; density (per KLOC) scales the weight so large repos aren't punished
 *   for absolute counts.
 * Then hard severity ceilings clamp the grade (any open Critical → F).
 */

const EMPTY_COUNTS: SeverityCounts = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  info: 0,
};

function gradeFromScore(score: number): Grade {
  for (const band of GRADE_BANDS) if (score >= band.min) return band.grade;
  return "F";
}

/** Lower of two grades (A best, F worst). */
function worseGrade(a: Grade, b: Grade): Grade {
  const order: Grade[] = ["A", "B", "C", "D", "F"];
  return order.indexOf(a) >= order.indexOf(b) ? a : b;
}

/**
 * Asymptotic deduction: each finding removes `weight`, but the total is damped
 * so the score approaches 0 rather than crashing through it. `damp` controls
 * how fast diminishing returns kick in.
 */
function dampedScore(rawDeduction: number): number {
  const DAMP = 120;
  // 100 * DAMP/(DAMP+rawDeduction): rawDeduction 0→100, 120→50, 360→25 ...
  return Math.max(0, Math.round((100 * DAMP) / (DAMP + rawDeduction)));
}

interface ScoreInput {
  findings: Pick<Finding, "pillar" | "severity" | "triageStatus" | "ai">[];
  /**
   * MEASURED thousands of lines of code (scc, via the quality pillar). Leave it
   * undefined when nothing measured the repo — do NOT pass a guess here, or the
   * result would be stamped "measured" and the report would claim a
   * normalization that never happened.
   */
  kloc?: number;
  /** Which pillars actually ran (so a skipped pillar isn't graded A by default). */
  pillarsRun: Pillar[];
  /** Pillars where a scanner failed but partial findings were kept. */
  partialPillars?: Set<Pillar>;
}

export function computeScore(input: ScoreInput): RunScore {
  // A usable measurement is a finite, strictly positive number. Anything else
  // (undefined, 0, NaN) means nobody weighed the repo — the run then uses the
  // ASSUMED_KLOC fallback and says so via klocSource, instead of silently
  // passing a placeholder off as a measurement.
  const measured =
    typeof input.kloc === "number" && Number.isFinite(input.kloc) && input.kloc > 0;
  const klocSource: KlocSource = measured ? "measured" : "assumed";
  // Floor at 1 kLOC: below that the density factor would blow past 2x and a
  // 40-line repo would be graded harder than a monolith for the same finding.
  const kloc = Math.max(measured ? input.kloc! : ASSUMED_KLOC, 1);
  const partial = input.partialPillars ?? new Set<Pillar>();

  // Only findings that are actually "open" count against the score. A finding
  // triaged false_positive/ignored/fixed does not deduct.
  const active = input.findings.filter(
    (f) => f.triageStatus === "open" || f.triageStatus === "accepted",
  );

  const byPillar = new Map<Pillar, typeof active>();
  for (const p of input.pillarsRun) byPillar.set(p, []);
  for (const f of active) {
    const arr = byPillar.get(f.pillar);
    if (arr) arr.push(f);
    else byPillar.set(f.pillar, [f]);
  }

  const pillarResults: PillarResult[] = [];
  const totalCounts: SeverityCounts = { ...EMPTY_COUNTS };

  for (const [pillar, pf] of byPillar) {
    const counts: SeverityCounts = { ...EMPTY_COUNTS };
    let rawDeduction = 0;
    let ceilingGrade: Grade | undefined;

    for (const f of pf) {
      counts[f.severity] += 1;
      totalCounts[f.severity] += 1;

      // AI confidence down-weights likely false positives (never zero out a
      // deterministic detection entirely; floor at 0.25).
      const aiWeight = f.ai ? Math.max(f.ai.confidence, 0.25) : 1;
      const densityFactor = 1 / kloc; // per-KLOC normalization
      rawDeduction += SEVERITY_WEIGHT[f.severity] * aiWeight * (1 + densityFactor);

      const ceil = SEVERITY_CEILING[f.severity];
      if (ceil) ceilingGrade = ceilingGrade ? worseGrade(ceilingGrade, ceil) : ceil;
    }

    const score = dampedScore(rawDeduction);
    let grade = gradeFromScore(score);
    if (ceilingGrade) grade = worseGrade(grade, ceilingGrade);

    pillarResults.push({
      pillar,
      score,
      grade,
      counts,
      partial: partial.has(pillar),
    });
  }

  // Overall = worst-weighted rollup: mean of pillar scores, but the overall
  // grade also inherits the worst pillar ceiling.
  const overall =
    pillarResults.length === 0
      ? 100
      : Math.round(
          pillarResults.reduce((s, p) => s + p.score, 0) / pillarResults.length,
        );
  let overallGrade = gradeFromScore(overall);
  for (const p of pillarResults) overallGrade = worseGrade(overallGrade, p.grade);

  return {
    scoringVersion: SCORING_VERSION,
    overall,
    grade: overallGrade,
    pillars: pillarResults.sort(
      (a, b) => severityWorst(b) - severityWorst(a),
    ),
    counts: totalCounts,
    kloc,
    klocSource,
  };
}

/** Sort weight so the most-critical pillar shows first. */
function severityWorst(p: PillarResult): number {
  return (
    p.counts.critical * SEVERITY_RANK.critical +
    p.counts.high * SEVERITY_RANK.high +
    p.counts.medium * SEVERITY_RANK.medium
  );
}

export { SCORING_VERSION };
