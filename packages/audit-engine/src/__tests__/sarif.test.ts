import { describe, it, expect } from "vitest";
import { normalizeSarif, type SarifLog } from "../normalize/sarif.js";

const SEMGREP_SARIF: SarifLog = {
  runs: [
    {
      tool: {
        driver: {
          name: "semgrep",
          version: "1.99.0",
          rules: [
            {
              id: "javascript.express.security.audit.xss",
              name: "express-xss",
              properties: {
                tags: ["CWE-79", "security"],
                "security-severity": "8.6",
              },
              helpUri: "https://semgrep.dev/r/xss",
              fullDescription: { text: "Reflected XSS via res.send." },
            },
          ],
        },
      },
      results: [
        {
          ruleId: "javascript.express.security.audit.xss",
          ruleIndex: 0,
          level: "error",
          message: { text: "Untrusted input flows into res.send." },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/routes/user.js" },
                region: { startLine: 42, endLine: 42, snippet: { text: "res.send(req.query.q)" } },
              },
            },
          ],
        },
      ],
    },
  ],
};

describe("normalizeSarif", () => {
  it("maps a semgrep SARIF result to a canonical RawFinding", () => {
    const findings = normalizeSarif(SEMGREP_SARIF, { pillar: "sast", tool: "semgrep" });
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.pillar).toBe("sast");
    expect(f.tool).toBe("semgrep");
    expect(f.ruleId).toBe("javascript.express.security.audit.xss");
    // security-severity 8.6 → high
    expect(f.severity).toBe("high");
    expect(f.cvssScore).toBeCloseTo(8.6);
    expect(f.cwe).toContain("CWE-79");
    expect(f.location?.path).toBe("src/routes/user.js");
    expect(f.location?.startLine).toBe(42);
    expect(f.references).toContain("https://semgrep.dev/r/xss");
    expect(f.fingerprint).toMatch(/^[a-f0-9]{32}$/);
  });

  it("falls back to level-based severity when no security-severity is present", () => {
    const log: SarifLog = {
      runs: [
        {
          tool: { driver: { name: "trivy-config" } },
          results: [{ ruleId: "AVD-DS-0002", level: "warning", message: { text: "root user" } }],
        },
      ],
    };
    const [f] = normalizeSarif(log, { pillar: "hygiene", tool: "trivy-config" });
    expect(f!.severity).toBe("medium"); // warning → medium
  });

  it("returns empty for an empty SARIF log", () => {
    expect(normalizeSarif({ runs: [] }, { pillar: "sast" })).toEqual([]);
  });
});
