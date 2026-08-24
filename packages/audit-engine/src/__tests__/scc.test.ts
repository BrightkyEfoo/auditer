import { describe, it, expect } from "vitest";
import type { Finding } from "@auditer/types";
import type { SandboxResult } from "../ports/sandbox.js";
import type { ScanContext } from "../ports/adapter.js";
import { SccAdapter, SCC_METRIC_KEYS } from "../scanners/scc.js";
import { collectKloc } from "../orchestrator.js";
import { computeScore } from "../scoring/index.js";

/**
 * Guards the defect this adapter closed: `computeScore` took a `kloc` that
 * nothing ever produced, so `(1 + 1/kloc)` was 1.1 for every repo and the
 * advertised density normalization did nothing.
 */

/**
 * Verbatim shape of `scc --format json` v3.4.0, captured from the real image
 * (ghcr.io/boyter/scc:v3.4.0) run against a repo — not transcribed from docs.
 * `Files` is empty because we deliberately do not pass --by-file.
 */
const SCC_JSON = JSON.stringify([
  {
    Name: "TypeScript",
    Bytes: 459689,
    CodeBytes: 0,
    Lines: 12032,
    Code: 9790,
    Comment: 1285,
    Blank: 957,
    Complexity: 1367,
    Count: 102,
    WeightedComplexity: 0,
    Files: [],
    LineLength: null,
    ULOC: 0,
  },
  {
    Name: "JSON",
    Bytes: 13666,
    CodeBytes: 0,
    Lines: 569,
    Code: 569,
    Comment: 0,
    Blank: 0,
    Complexity: 0,
    Count: 29,
    WeightedComplexity: 0,
    Files: [],
    LineLength: null,
    ULOC: 0,
  },
  {
    Name: "Dockerfile",
    Bytes: 3829,
    CodeBytes: 0,
    Lines: 97,
    Code: 55,
    Comment: 31,
    Blank: 11,
    Complexity: 8,
    Count: 4,
    WeightedComplexity: 0,
    Files: [],
    LineLength: null,
    ULOC: 0,
  },
]);

function sandbox(partial: Partial<SandboxResult> = {}): SandboxResult {
  return {
    exitCode: 0,
    stdout: "",
    stderr: "",
    timedOut: false,
    durationMs: 12,
    ...partial,
  };
}

const CTX: ScanContext = {
  auditRunId: "run",
  organizationId: "org",
  workspacePath: "/tmp/ws",
};

describe("scc adapter", () => {
  const scc = new SccAdapter();

  it("sums the per-language code lines into the LOC metrics", async () => {
    const metrics = await scc.measure(sandbox({ stdout: SCC_JSON }), CTX);
    expect(metrics).toBeDefined();
    // 9790 + 569 + 55
    expect(metrics![SCC_METRIC_KEYS.code]).toBe(10414);
    expect(metrics![SCC_METRIC_KEYS.total]).toBe(12698);
    expect(metrics![SCC_METRIC_KEYS.files]).toBe(135);
    expect(metrics![SCC_METRIC_KEYS.complexity]).toBe(1375);
    expect(metrics![SCC_METRIC_KEYS.languages]).toBe(3);
  });

  it("turns the measured LOC into the kLOC the score normalizes by", async () => {
    const metrics = await scc.measure(sandbox({ stdout: SCC_JSON }), CTX);
    expect(collectKloc([{ metrics }])).toBeCloseTo(10.414, 5);
  });

  it("produces no findings — it measures, it does not judge", async () => {
    expect(await scc.parse(sandbox({ stdout: SCC_JSON }), CTX)).toEqual([]);
  });

  it("returns no measurement rather than a partial one on truncated output", async () => {
    // What an 8 MiB stdout cap actually produces: a JSON array cut mid-object.
    const truncated = SCC_JSON.slice(0, 400) + "]";
    expect(await scc.measure(sandbox({ stdout: truncated }), CTX)).toBeUndefined();
    expect(await scc.measure(sandbox({ stdout: "" }), CTX)).toBeUndefined();
    // An all-ignored repo is the absence of a measurement, not a zero.
    expect(
      await scc.measure(sandbox({ stdout: '[{"Name":"Text","Code":0,"Count":0}]' }), CTX),
    ).toBeUndefined();
  });

  it("treats only exit 0 as a successful count", () => {
    expect(scc.classifyExit(sandbox({ exitCode: 0 }))).toBe("success");
    expect(scc.classifyExit(sandbox({ exitCode: 1 }))).toBe("fail");
    expect(scc.classifyExit(sandbox({ timedOut: true, exitCode: 137 }))).toBe("partial");
  });

  it("skips runs with no checkout (DAST/UX targets)", () => {
    expect(scc.appliesTo(CTX)).toBe(true);
    expect(scc.appliesTo({ ...CTX, workspacePath: "" })).toBe(false);
  });

  it("asks for aggregates only — --by-file would blow the stdout cap", () => {
    const spec = scc.buildSpec(CTX);
    expect(spec.cmd).toEqual(["/bin/scc", "--format", "json", "/repo"]);
    expect(spec.cmd).not.toContain("--by-file");
    expect(spec.network.mode).toBe("none");
    expect(spec.mounts[0]!.readOnly).toBe(true);
    expect(spec.user).toBe("65534:65534");
  });
});

describe("density normalization", () => {
  function finding(pillar: Finding["pillar"], severity: Finding["severity"]): Finding {
    return {
      pillar,
      tool: "semgrep",
      ruleId: "rule.x",
      severity,
      title: "t",
      description: "",
      cwe: [],
      vulnIds: [],
      references: [],
      fingerprint: `fp_${pillar}_${severity}`,
      id: "id",
      organizationId: "org",
      auditRunId: "run",
      scanId: "scan",
      triageStatus: "open",
      sourceCount: 1,
    } as Finding;
  }

  // The same findings, over a small repo and a large one.
  const findings = [
    finding("sast", "medium"),
    finding("sast", "medium"),
    finding("sast", "low"),
    finding("quality", "low"),
  ];
  const pillarsRun = ["sast", "quality"] as const;

  it("scores a 5 kLOC repo differently from a 500 kLOC repo for identical findings", () => {
    const small = computeScore({ findings, pillarsRun: [...pillarsRun], kloc: 5 });
    const large = computeScore({ findings, pillarsRun: [...pillarsRun], kloc: 500 });

    // The proof the normalization is wired: before scc, both of these went
    // through `kloc ?? 10` and came out identical.
    const smallSast = small.pillars.find((p) => p.pillar === "sast")!;
    const largeSast = large.pillars.find((p) => p.pillar === "sast")!;
    expect(smallSast.score).not.toBe(largeSast.score);
    // Density penalizes the small repo more for the same absolute count.
    expect(smallSast.score).toBeLessThan(largeSast.score);
  });

  it("labels the kLOC measured when one was supplied", () => {
    const score = computeScore({ findings, pillarsRun: [...pillarsRun], kloc: 240.5 });
    expect(score.klocSource).toBe("measured");
    expect(score.kloc).toBe(240.5);
  });

  it("falls back and labels the kLOC assumed when nothing measured the repo", () => {
    const score = computeScore({ findings, pillarsRun: [...pillarsRun] });
    expect(score.klocSource).toBe("assumed");
    expect(score.kloc).toBe(10);
    // A zero or a NaN is an absent measurement, not a measured zero.
    expect(computeScore({ findings, pillarsRun: [...pillarsRun], kloc: 0 }).klocSource).toBe(
      "assumed",
    );
    expect(
      computeScore({ findings, pillarsRun: [...pillarsRun], kloc: Number.NaN }).klocSource,
    ).toBe("assumed");
  });

  it("carries the scc measurement end-to-end into the score", async () => {
    const metrics = await new SccAdapter().measure(sandbox({ stdout: SCC_JSON }), CTX);
    const score = computeScore({
      findings,
      pillarsRun: [...pillarsRun],
      kloc: collectKloc([{ metrics }]),
    });
    expect(score.klocSource).toBe("measured");
    expect(score.kloc).toBeCloseTo(10.414, 5);
  });
});
