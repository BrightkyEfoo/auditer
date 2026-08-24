import { describe, it, expect } from "vitest";
import { computeDelta, type DeltaFinding, type DeltaSnapshot } from "../delta/index.js";

/**
 * The progression report is the document that answers "is this getting better
 * or worse". Every defect guarded here is a way of answering it wrongly in the
 * flattering direction — which is the only direction that matters, because a
 * report that understates progress merely annoys, while one that invents it
 * gets someone to stand down a fix.
 */

const ALL_PILLARS = ["secrets", "sca", "sast", "quality", "hygiene"];

function f(over: Partial<DeltaFinding> & { fingerprint: string }): DeltaFinding {
  return {
    severity: "high",
    pillar: "sast",
    title: over.fingerprint,
    ...over,
  };
}

function snap(
  runId: string,
  at: string,
  findings: DeltaFinding[],
  measuredPillars: string[] = ALL_PILLARS,
): DeltaSnapshot {
  return { runId, at, findings, measuredPillars };
}

describe("computeDelta", () => {
  it("partitions fixed, new and persisting by fingerprint", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [
      f({ fingerprint: "a", firstSeenAt: "2026-05-01T00:00:00Z" }),
      f({ fingerprint: "b", firstSeenAt: "2026-05-01T00:00:00Z" }),
    ]);
    const current = snap("run-2", "2026-07-01T00:00:00Z", [
      f({ fingerprint: "b", firstSeenAt: "2026-05-01T00:00:00Z" }),
      f({ fingerprint: "c", firstSeenAt: "2026-07-01T00:00:00Z" }),
    ]);

    const d = computeDelta({ current, previous });

    expect(d.hasBaseline).toBe(true);
    expect(d.fixed.map((x) => x.fingerprint)).toEqual(["a"]);
    expect(d.introduced.map((x) => x.fingerprint)).toEqual(["c"]);
    expect(d.persisting.map((x) => x.fingerprint)).toEqual(["b"]);
    expect(d.elapsedDays).toBe(30);
  });

  it("dates the age of a persisting finding from its first sighting", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [
      f({ fingerprint: "a", firstSeenAt: "2026-01-01T00:00:00Z" }),
    ]);
    const current = snap("run-2", "2026-07-01T00:00:00Z", [
      f({ fingerprint: "a", firstSeenAt: "2026-01-01T00:00:00Z" }),
    ]);

    const d = computeDelta({ current, previous });

    expect(d.persisting[0]!.ageDays).toBe(181);
    expect(d.oldestOpen?.fingerprint).toBe("a");
  });

  it("leaves the age null rather than inventing one when history is short", () => {
    const current = snap("run-2", "2026-07-01T00:00:00Z", [f({ fingerprint: "a" })]);
    const d = computeDelta({ current, previous: null });
    expect(d.persisting[0]!.ageDays).toBeNull();
    expect(d.oldestOpen).toBeNull();
  });

  it("sorts every bucket by severity, then by age, then by title", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", []);
    const current = snap("run-2", "2026-07-01T00:00:00Z", [
      f({ fingerprint: "low-old", severity: "low", firstSeenAt: "2026-01-01T00:00:00Z" }),
      f({ fingerprint: "crit-new", severity: "critical", firstSeenAt: "2026-06-25T00:00:00Z" }),
      f({ fingerprint: "crit-old", severity: "critical", firstSeenAt: "2026-02-01T00:00:00Z" }),
      f({ fingerprint: "high", severity: "high", firstSeenAt: "2026-03-01T00:00:00Z" }),
    ]);

    const d = computeDelta({ current, previous });

    expect(d.introduced.map((x) => x.fingerprint)).toEqual([
      "crit-old",
      "crit-new",
      "high",
      "low-old",
    ]);
  });

  it("calls nothing new when there is no baseline", () => {
    const current = snap("run-1", "2026-07-01T00:00:00Z", [
      f({ fingerprint: "a" }),
      f({ fingerprint: "b" }),
    ]);

    const d = computeDelta({ current, previous: null });

    expect(d.hasBaseline).toBe(false);
    expect(d.introduced).toHaveLength(0);
    expect(d.fixed).toHaveLength(0);
    expect(d.persisting).toHaveLength(2);
    expect(d.openPrevious).toBe(0);
    expect(d.direction).toBe("stable");
  });

  /**
   * The defect this whole bucket exists for: a pillar whose scanner failed
   * makes every one of its findings vanish. Counted as fixed, a broken scanner
   * would read as a week of good work.
   */
  it("does NOT count a disappearance from an unexecuted pillar as fixed", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [
      f({ fingerprint: "dep", pillar: "sca", firstSeenAt: "2026-05-01T00:00:00Z" }),
      f({ fingerprint: "code", pillar: "sast", firstSeenAt: "2026-05-01T00:00:00Z" }),
    ]);
    // sca did not run this time.
    const current = snap("run-2", "2026-07-01T00:00:00Z", [], ["sast", "quality"]);

    const d = computeDelta({ current, previous });

    expect(d.fixed.map((x) => x.fingerprint)).toEqual(["code"]);
    expect(d.unmeasured.map((x) => x.fingerprint)).toEqual(["dep"]);
  });

  it("treats coverage as unknown when the run declares no measured pillars", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [f({ fingerprint: "a" })]);
    const current: DeltaSnapshot = { runId: "run-2", at: "2026-07-01T00:00:00Z", findings: [] };

    const d = computeDelta({ current, previous });

    expect(d.fixed).toHaveLength(0);
    expect(d.unmeasured.map((x) => x.fingerprint)).toEqual(["a"]);
  });

  it("does not credit a vanished false positive as a fix", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [
      f({ fingerprint: "a", triageStatus: "false_positive" }),
      f({ fingerprint: "b", triageStatus: "accepted" }),
    ]);
    const current = snap("run-2", "2026-07-01T00:00:00Z", []);

    const d = computeDelta({ current, previous });

    expect(d.fixed.map((x) => x.fingerprint)).toEqual(["b"]);
  });

  it("separates accepted risk and assumed false positives from what is open", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", []);
    const current = snap("run-2", "2026-07-01T00:00:00Z", [
      f({ fingerprint: "open" }),
      f({ fingerprint: "acc", triageStatus: "accepted" }),
      f({ fingerprint: "ign", triageStatus: "ignored" }),
      f({ fingerprint: "fp", triageStatus: "false_positive" }),
    ]);

    const d = computeDelta({ current, previous });

    expect(d.introduced.map((x) => x.fingerprint)).toEqual(["open"]);
    expect(d.accepted.map((x) => x.fingerprint).sort()).toEqual(["acc", "ign"]);
    expect(d.falsePositives.map((x) => x.fingerprint)).toEqual(["fp"]);
    expect(d.openCurrent).toBe(1);
  });

  it("counts open findings per severity on both sides", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [
      f({ fingerprint: "h1", severity: "high" }),
      f({ fingerprint: "h2", severity: "high" }),
      f({ fingerprint: "h3", severity: "high" }),
    ]);
    const current = snap("run-2", "2026-07-01T00:00:00Z", [
      f({ fingerprint: "h1", severity: "high" }),
    ]);

    const d = computeDelta({ current, previous });
    const high = d.counts.find((c) => c.severity === "high")!;

    expect(high.previous).toBe(3);
    expect(high.current).toBe(1);
    expect(high.delta).toBe(-2);
  });

  /** Ten new `info` must not outweigh one closed critical. */
  it("reads the direction from severity weight, not from finding count", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [
      f({ fingerprint: "crit", severity: "critical" }),
    ]);
    const current = snap(
      "run-2",
      "2026-07-01T00:00:00Z",
      Array.from({ length: 10 }, (_, i) => f({ fingerprint: `i${i}`, severity: "info" })),
    );

    const d = computeDelta({ current, previous });

    expect(d.introduced).toHaveLength(10);
    expect(d.fixed).toHaveLength(1);
    expect(d.direction).toBe("improving");
  });

  it("reports a worsening trend when weighted risk grows", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [
      f({ fingerprint: "l", severity: "low" }),
    ]);
    const current = snap("run-2", "2026-07-01T00:00:00Z", [
      f({ fingerprint: "l", severity: "low" }),
      f({ fingerprint: "c", severity: "critical" }),
    ]);

    expect(computeDelta({ current, previous }).direction).toBe("worsening");
  });

  it("averages the critical remediation delay only over criticals it can date", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [
      f({ fingerprint: "c1", severity: "critical", firstSeenAt: "2026-06-21T00:00:00Z" }),
      f({ fingerprint: "c2", severity: "critical", firstSeenAt: "2026-06-11T00:00:00Z" }),
      // Undatable: must not be averaged in as a zero-day remediation.
      f({ fingerprint: "c3", severity: "critical" }),
      f({ fingerprint: "h1", severity: "high", firstSeenAt: "2026-01-01T00:00:00Z" }),
    ]);
    const current = snap("run-2", "2026-07-01T00:00:00Z", []);

    const d = computeDelta({ current, previous });

    // (10 + 20) / 2 — the high and the undatable critical are excluded.
    expect(d.meanTimeToFixCriticalDays).toBe(15);
    expect(d.fixedCriticalSample).toBe(2);
  });

  it("returns no remediation delay rather than zero when nothing critical closed", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [f({ fingerprint: "a" })]);
    const current = snap("run-2", "2026-07-01T00:00:00Z", [f({ fingerprint: "a" })]);

    const d = computeDelta({ current, previous });

    expect(d.meanTimeToFixCriticalDays).toBeNull();
    expect(d.fixedCriticalSample).toBe(0);
  });

  it("is a pure function of its input", () => {
    const previous = snap("run-1", "2026-06-01T00:00:00Z", [f({ fingerprint: "a" })]);
    const current = snap("run-2", "2026-07-01T00:00:00Z", [f({ fingerprint: "b" })]);

    expect(computeDelta({ current, previous })).toEqual(computeDelta({ current, previous }));
    // and does not mutate what it was handed
    expect(previous.findings).toHaveLength(1);
    expect(current.findings).toHaveLength(1);
  });
});
