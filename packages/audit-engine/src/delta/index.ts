import { SEVERITY_WEIGHT, SEVERITY_RANK, type Severity, type TriageStatus } from "@auditer/types";

/**
 * Cross-run delta: what got fixed, what appeared, what is still open and for
 * how long. Pure and deterministic — same two snapshots in, same result out,
 * no clock read, no I/O — so it can be tested, and so a progression report
 * regenerated in six months says exactly what it said the day it was issued.
 *
 * Identity is the FINGERPRINT (packages/audit-engine/src/normalize/fingerprint.ts),
 * never the row id: ids are per-run, fingerprints survive refactors and
 * line-number drift. That is the whole reason the delta is computable at all.
 *
 * Two honesty rules are built into the algorithm rather than left to the
 * renderer, because a renderer that forgets them produces a document that
 * flatters:
 *
 *   1. A fingerprint that disappeared from a pillar THAT DID NOT RUN this time
 *      is not fixed — it is unmeasured. Counting it as fixed turns a scanner
 *      failure into progress, which is the single most flattering lie this
 *      report could tell. Those go to their own bucket.
 *   2. A finding marked `false_positive` that then vanishes is not a fix
 *      either; nothing was ever wrong. It leaves the fixed count.
 *
 * The remediation delay for criticals is an UPPER bound and is labelled as
 * one: we know the run that stopped seeing a finding, not the commit that
 * repaired it, so the measured interval always contains the real one.
 */

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"] as const;

/** Triage states that still count as an open risk. Everything else is a decision. */
function isOpen(t: TriageStatus | undefined): boolean {
  return t === undefined || t === "open";
}

const DAY_MS = 24 * 60 * 60 * 1000;

/** The minimum a finding needs to carry to take part in a delta. */
export interface DeltaFinding {
  fingerprint: string;
  severity: Severity;
  pillar: string;
  title: string;
  triageStatus?: TriageStatus;
  /**
   * ISO date of the run this fingerprint was FIRST observed in. Null when the
   * history does not reach back far enough — the report then says "au moins",
   * never a made-up age.
   */
  firstSeenAt?: string | null;
}

/** One relevé, reduced to what the comparison needs. */
export interface DeltaSnapshot {
  runId: string;
  /** ISO timestamp that dates the snapshot (the run's finish, or its creation). */
  at: string;
  findings: DeltaFinding[];
  /**
   * Pillars that actually produced a measurement in this run. Absent means
   * "unknown coverage", and the comparison then degrades safely: with no
   * coverage information every disappearance is treated as unmeasured rather
   * than as a fix.
   */
  measuredPillars?: string[];
}

export interface ComputeDeltaInput {
  current: DeltaSnapshot;
  /** The relevé to compare against. Null on a first run — a fact, not an error. */
  previous?: DeltaSnapshot | null;
}

export interface DeltaEntry extends DeltaFinding {
  /** Days between first sighting and the reference date. Null when unknown. */
  ageDays: number | null;
}

/** Open counts on both sides of the comparison, per severity. */
export interface SeverityMovement {
  severity: Severity;
  current: number;
  previous: number;
  /** current − previous. Negative is progress. */
  delta: number;
}

export interface DeltaResult {
  /** False on a first relevé: every "since last time" section must then say so. */
  hasBaseline: boolean;
  currentRunId: string;
  currentAt: string;
  previousRunId: string | null;
  previousAt: string | null;
  /** Calendar days between the two relevés. Null without a baseline. */
  elapsedDays: number | null;

  /** Present last time, gone now, from a pillar that DID run again. */
  fixed: DeltaEntry[];
  /** Open now, unseen last time. */
  introduced: DeltaEntry[];
  /** Open on both sides. Their age is the governance number. */
  persisting: DeltaEntry[];
  /**
   * Present last time, gone now, from a pillar that did NOT run again. Neither
   * fixed nor open — unknown, and shown as unknown.
   */
  unmeasured: DeltaEntry[];

  /** Current findings the team decided not to fix, on the record. */
  accepted: DeltaEntry[];
  /** Current findings the team judged wrong, on the record. */
  falsePositives: DeltaEntry[];

  counts: SeverityMovement[];
  openCurrent: number;
  openPrevious: number;

  /**
   * Direction of travel, on the SAME severity weights the score uses
   * (packages/types/src/scoring.ts). Counting findings instead would let ten
   * new `info` outweigh one closed critical.
   */
  direction: "improving" | "worsening" | "stable";
  weightedCurrent: number;
  weightedPrevious: number;

  /** Mean days from first sighting to disappearance, criticals only. Upper bound. */
  meanTimeToFixCriticalDays: number | null;
  /** How many criticals that mean is computed over — a mean over one is not a mean. */
  fixedCriticalSample: number;
  /** Longest-standing open finding, whatever its severity. */
  oldestOpen: DeltaEntry | null;
}

function diffDays(from: string, to: string): number | null {
  const a = new Date(from).getTime();
  const b = new Date(to).getTime();
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.max(0, Math.round((b - a) / DAY_MS));
}

function toEntry(f: DeltaFinding, reference: string): DeltaEntry {
  return {
    ...f,
    ageDays: f.firstSeenAt ? diffDays(f.firstSeenAt, reference) : null,
  };
}

/**
 * Deterministic ordering: worst severity first, then oldest first (an old
 * medium is a governance problem an old low is not), then title so two runs of
 * the same data never shuffle the list. Unknown ages sort last within a
 * severity — a missing age must not masquerade as a fresh finding.
 */
function bySeverityThenAge(a: DeltaEntry, b: DeltaEntry): number {
  const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
  if (sev !== 0) return sev;
  const aa = a.ageDays ?? -1;
  const bb = b.ageDays ?? -1;
  if (aa !== bb) return bb - aa;
  return a.title.localeCompare(b.title, "fr");
}

function weigh(findings: DeltaFinding[]): number {
  return findings
    .filter((f) => isOpen(f.triageStatus))
    .reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] ?? 0), 0);
}

function countOpen(findings: DeltaFinding[], severity: Severity): number {
  return findings.filter((f) => f.severity === severity && isOpen(f.triageStatus)).length;
}

/** Last fingerprint wins on collision — a run should not hold two, but if it
 *  does, the delta must still be a function of its input. */
function index(findings: DeltaFinding[]): Map<string, DeltaFinding> {
  return new Map(findings.map((f) => [f.fingerprint, f]));
}

export function computeDelta(input: ComputeDeltaInput): DeltaResult {
  const { current } = input;
  const previous = input.previous ?? null;
  const hasBaseline = previous !== null;

  const currentByFp = index(current.findings);
  const previousByFp = previous ? index(previous.findings) : new Map<string, DeltaFinding>();

  // No coverage declaration → treat coverage as unknown (rule 1 above).
  const measured = current.measuredPillars ? new Set(current.measuredPillars) : null;

  const fixed: DeltaEntry[] = [];
  const unmeasured: DeltaEntry[] = [];
  for (const [fp, f] of previousByFp) {
    if (currentByFp.has(fp)) continue;
    const entry = toEntry(f, current.at);
    if (measured === null || !measured.has(f.pillar)) {
      unmeasured.push(entry);
      continue;
    }
    // A false positive that stops being reported was never a defect to fix.
    if (f.triageStatus === "false_positive") continue;
    fixed.push(entry);
  }

  const introduced: DeltaEntry[] = [];
  const persisting: DeltaEntry[] = [];
  const accepted: DeltaEntry[] = [];
  const falsePositives: DeltaEntry[] = [];

  for (const [fp, f] of currentByFp) {
    const entry = toEntry(f, current.at);
    if (f.triageStatus === "false_positive") {
      falsePositives.push(entry);
      continue;
    }
    if (f.triageStatus === "accepted" || f.triageStatus === "ignored") {
      accepted.push(entry);
      continue;
    }
    if (!isOpen(f.triageStatus)) continue; // marked fixed but still detected
    // Without a baseline nothing can be called new: everything is simply open.
    if (hasBaseline && !previousByFp.has(fp)) introduced.push(entry);
    else persisting.push(entry);
  }

  fixed.sort(bySeverityThenAge);
  unmeasured.sort(bySeverityThenAge);
  introduced.sort(bySeverityThenAge);
  persisting.sort(bySeverityThenAge);
  accepted.sort(bySeverityThenAge);
  falsePositives.sort(bySeverityThenAge);

  const counts: SeverityMovement[] = SEVERITIES.map((severity) => {
    const cur = countOpen(current.findings, severity);
    const prev = previous ? countOpen(previous.findings, severity) : 0;
    return { severity, current: cur, previous: prev, delta: cur - prev };
  });

  const weightedCurrent = weigh(current.findings);
  const weightedPrevious = previous ? weigh(previous.findings) : 0;
  const direction: DeltaResult["direction"] = !hasBaseline
    ? "stable"
    : weightedCurrent < weightedPrevious
      ? "improving"
      : weightedCurrent > weightedPrevious
        ? "worsening"
        : "stable";

  const fixedCriticalAges = fixed
    .filter((f) => f.severity === "critical" && f.ageDays !== null)
    .map((f) => f.ageDays as number);
  const meanTimeToFixCriticalDays = fixedCriticalAges.length
    ? Math.round(fixedCriticalAges.reduce((a, b) => a + b, 0) / fixedCriticalAges.length)
    : null;

  const openNow = [...introduced, ...persisting];
  const oldestOpen =
    openNow.filter((f) => f.ageDays !== null).sort((a, b) => (b.ageDays ?? 0) - (a.ageDays ?? 0))[0] ??
    null;

  return {
    hasBaseline,
    currentRunId: current.runId,
    currentAt: current.at,
    previousRunId: previous?.runId ?? null,
    previousAt: previous?.at ?? null,
    elapsedDays: previous ? diffDays(previous.at, current.at) : null,
    fixed,
    introduced,
    persisting,
    unmeasured,
    accepted,
    falsePositives,
    counts,
    openCurrent: openNow.length,
    openPrevious: previous ? previous.findings.filter((f) => isOpen(f.triageStatus)).length : 0,
    direction,
    weightedCurrent,
    weightedPrevious,
    meanTimeToFixCriticalDays,
    fixedCriticalSample: fixedCriticalAges.length,
    oldestOpen,
  };
}
