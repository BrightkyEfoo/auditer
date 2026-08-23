import { describe, it, expect } from "vitest";
import type { RawFinding, Finding } from "@auditer/types";
import { computeFingerprint, withFingerprints } from "../normalize/fingerprint.js";
import { dedupe } from "../dedup/index.js";
import { computeScore } from "../scoring/index.js";

function raw(partial: Partial<RawFinding>): Omit<RawFinding, "fingerprint"> {
  return {
    pillar: "sast",
    tool: "semgrep",
    ruleId: "rule.x",
    severity: "high",
    title: "t",
    description: "",
    cwe: [],
    vulnIds: [],
    references: [],
    ...partial,
  } as Omit<RawFinding, "fingerprint">;
}

describe("fingerprint", () => {
  it("is stable across line drift within the same 5-line bucket", () => {
    const a = computeFingerprint(raw({ location: { path: "a.ts", startLine: 10 } }));
    const b = computeFingerprint(raw({ location: { path: "a.ts", startLine: 12 } }));
    expect(a).toBe(b);
  });

  it("differs across files", () => {
    const a = computeFingerprint(raw({ location: { path: "a.ts", startLine: 10 } }));
    const b = computeFingerprint(raw({ location: { path: "b.ts", startLine: 10 } }));
    expect(a).not.toBe(b);
  });

  it("folds SCA findings on purl + version + vulnId regardless of tool", () => {
    const osv = computeFingerprint(
      raw({
        pillar: "sca",
        tool: "osv-scanner",
        ruleId: "CVE-2021-1234",
        vulnIds: ["CVE-2021-1234"],
        package: { ecosystem: "npm", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" },
      }),
    );
    const trivy = computeFingerprint(
      raw({
        pillar: "sca",
        tool: "trivy",
        ruleId: "CVE-2021-1234",
        vulnIds: ["CVE-2021-1234"],
        package: { ecosystem: "npm", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" },
      }),
    );
    expect(osv).toBe(trivy);
  });
});

describe("dedupe", () => {
  it("collapses the same CVE reported by two tools into one representative", () => {
    const findings = withFingerprints([
      raw({
        pillar: "sca",
        tool: "osv-scanner",
        vulnIds: ["CVE-2021-1234"],
        severity: "high",
        package: { ecosystem: "npm", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" },
      }),
      raw({
        pillar: "sca",
        tool: "trivy",
        vulnIds: ["CVE-2021-1234"],
        severity: "critical",
        package: { ecosystem: "npm", name: "lodash", version: "4.17.20", purl: "pkg:npm/lodash@4.17.20" },
      }),
    ]);
    const res = dedupe(findings);
    expect(res.representatives).toHaveLength(1);
    // representative takes the max severity across the cluster
    expect(res.representatives[0]!.severity).toBe("critical");
    expect(res.groups[0]!.sourceCount).toBe(2);
  });
});

describe("scoring", () => {
  function finding(partial: Partial<Finding>): Finding {
    return {
      ...raw({}),
      fingerprint: "fp",
      id: "id",
      organizationId: "org",
      auditRunId: "run",
      scanId: "scan",
      triageStatus: "open",
      sourceCount: 1,
      ...partial,
    } as Finding;
  }

  it("caps the grade at F when any open Critical is present", () => {
    const score = computeScore({
      findings: [finding({ pillar: "sast", severity: "critical" })],
      pillarsRun: ["sast"],
      kloc: 50,
    });
    expect(score.grade).toBe("F");
  });

  it("does not deduct for triaged false positives", () => {
    const withFp = computeScore({
      findings: [finding({ pillar: "sast", severity: "high", triageStatus: "false_positive" })],
      pillarsRun: ["sast"],
      kloc: 50,
    });
    // No active findings → perfect pillar score.
    expect(withFp.pillars[0]!.score).toBe(100);
  });

  it("is deterministic for identical input", () => {
    const input = {
      findings: [finding({ pillar: "sast", severity: "medium" })],
      pillarsRun: ["sast" as const],
      kloc: 20,
    };
    expect(computeScore(input)).toEqual(computeScore(input));
  });
});
