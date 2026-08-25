import { describe, it, expect } from "vitest";
import { extractSarif, hasSarifReport } from "../normalize/sarif-stdout.js";
import { SemgrepAdapter } from "../scanners/semgrep.js";
import { HadolintAdapter } from "../scanners/hadolint.js";
import { TrivyConfigAdapter } from "../scanners/trivy-config.js";
import type { SandboxResult } from "../ports/sandbox.js";

/**
 * The discriminator between "found something" and "crashed".
 *
 * Three engines shipped exit-1-means-success and three engines were dead in
 * production because of it: semgrep could not write $HOME, trivy could not write
 * $TMPDIR, hadolint was pointed at a file that did not exist. All three exited
 * 1 — the same code they use for "findings were found" — and every one was
 * recorded as a SUCCESSFUL scan with zero findings.
 */

const CRASHES: Record<string, string> = {
  semgrep: "Traceback (most recent call last):\n    os.mkdir(self, mode)\nOSError: [Errno 30] Read-only file system: '/.semgrep'\n",
  trivy: "2026-08-24T23:53:12Z\tFATAL\tFatal error\tfs scan error: unable to create temporary directory: mkdir /tmp/analyzer-fs-430145459: read-only file system\n",
  hadolint: "hadolint: /repo/Dockerfile: withBinaryFile: does not exist (No such file or directory)\n",
};

const SARIF = JSON.stringify({
  version: "2.1.0",
  runs: [{ tool: { driver: { name: "t" } }, results: [] }],
});

function result(exitCode: number, stdout: string): SandboxResult {
  return { exitCode, stdout, stderr: "", timedOut: false, durationMs: 1 } as SandboxResult;
}

describe("hasSarifReport", () => {
  it("reconnaît un vrai log SARIF", () => {
    expect(hasSarifReport(SARIF)).toBe(true);
    expect(hasSarifReport(`progress line\n${SARIF}\n`)).toBe(true);
  });

  it("rejette chaque plantage réellement observé en production", () => {
    for (const [tool, output] of Object.entries(CRASHES)) {
      expect(hasSarifReport(output), tool).toBe(false);
    }
  });

  it("rejette du JSON qui n'est pas du SARIF", () => {
    // A crash can still print braces; parsing is not enough on its own.
    expect(hasSarifReport('{"error": "boom"}')).toBe(false);
    expect(hasSarifReport('{"runs": "not-an-array"}')).toBe(false);
  });

  it("lit un SARIF INDENTÉ, pas seulement compact", () => {
    // The defect this locks down: the old slice looked for `{"` — a brace glued
    // to a key — so zizmor and trivy, which both pretty-print, had their reports
    // sliced from the first `{"` INSIDE the document and thrown away. trivy
    // config produced four findings on the fixture and all four were lost here.
    const pretty = JSON.stringify(
      { version: "2.1.0", runs: [{ tool: { driver: { name: "trivy" } }, results: [] }] },
      null,
      2,
    );
    expect(pretty.startsWith('{\n')).toBe(true); // the shape that used to break it
    expect(hasSarifReport(pretty)).toBe(true);
    expect(extractSarif(pretty)).toBe(pretty);
  });

  it("découpe le JSON autour des lignes de progression", () => {
    const pretty = JSON.stringify({ runs: [] }, null, 2);
    expect(extractSarif(`scanning...\n${pretty}\ndone\n`)).toBe(pretty);
  });

  it("rend null quand il n'y a aucun JSON", () => {
    expect(extractSarif("aucun json")).toBeNull();
    expect(extractSarif("   ")).toBeNull();
  });
});

describe("classifyExit — le code 1 ne suffit pas", () => {
  const cases = [
    ["semgrep", new SemgrepAdapter(), CRASHES.semgrep!],
    ["hadolint", new HadolintAdapter(), CRASHES.hadolint!],
    ["trivy-config", new TrivyConfigAdapter(), CRASHES.trivy!],
  ] as const;

  for (const [name, adapter, crash] of cases) {
    it(`${name}: code 1 sans rapport = échec`, () => {
      expect(adapter.classifyExit(result(1, crash))).toBe("fail");
    });

    it(`${name}: code 1 avec rapport = réussi`, () => {
      expect(adapter.classifyExit(result(1, SARIF))).toBe("success");
    });

    it(`${name}: code 0 AVEC rapport = réussi`, () => {
      expect(adapter.classifyExit(result(0, SARIF))).toBe("success");
    });

    it(`${name}: code 0 SANS rapport = échec`, () => {
      // The generalisation of every silent hole found: an unwritable $HOME, a
      // missing file, a report cut at 64 KiB by the log driver. All of them
      // ended in exit 0 with nothing parseable, and all were recorded as a
      // clean pillar. Output we could not read is a gap, not an absence of
      // findings.
      expect(adapter.classifyExit(result(0, ""))).toBe("fail");
      expect(adapter.classifyExit(result(0, "scanning... done"))).toBe("fail");
    });
  }
});

describe("hadolint — les chemins viennent du worker", () => {
  const adapter = new HadolintAdapter();
  const base = { auditRunId: "r", organizationId: "o", workspacePath: "/w" };

  it("ne s'applique pas sans Dockerfile", () => {
    expect(adapter.appliesTo({ ...base, dockerfiles: [] })).toBe(false);
    // The old gate keyed on a `Dockerfile` basename at the repo ROOT, which is
    // exactly the assumption that made it lint nothing.
    expect(adapter.appliesTo({ ...base, manifests: ["Dockerfile"] })).toBe(false);
  });

  it("passe chaque chemin découvert, pas un Dockerfile racine supposé", () => {
    const spec = adapter.buildSpec({
      ...base,
      dockerfiles: ["infra/docker/app.Dockerfile", "sub/dir/Dockerfile"],
    });
    expect(spec.cmd).toEqual([
      "hadolint",
      "--format",
      "sarif",
      "/repo/infra/docker/app.Dockerfile",
      "/repo/sub/dir/Dockerfile",
    ]);
  });
});
