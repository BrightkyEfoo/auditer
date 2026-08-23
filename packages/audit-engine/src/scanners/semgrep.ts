import type { ExitClass, RawFinding } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH } from "../ports/sandbox.js";
import { normalizeSarif, type SarifLog } from "../normalize/sarif.js";

/**
 * SAST pillar — Semgrep OSS with a VENDORED, version-pinned ruleset. We do NOT
 * pass `--config p/...` (which fetches from the registry at runtime and is
 * subject to ToS + relicensing drift); instead the image ships a pinned rules
 * snapshot mounted at /rules, so builds are reproducible and offline.
 *
 * Semgrep emits SARIF natively → the shared normalizer does the parse.
 * Language-native scanners (Bandit/gosec/eslint-plugin-security) are layered on
 * in v2 as sibling adapters routed by detected stack.
 */
export class SemgrepAdapter implements ScannerAdapter {
  readonly id = "semgrep";
  readonly pillar = "sast" as const;
  readonly tool = "semgrep";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false;
  // TODO(infra): pin @sha256 + bake the vendored ruleset into /rules.
  readonly image = "semgrep/semgrep:1.99.0";

  appliesTo(_ctx: ScanContext): boolean {
    return true; // any source tree is in scope for SAST
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    return {
      image: this.image,
      cmd: [
        "semgrep",
        "scan",
        "--config",
        "/rules", // vendored, offline; NEVER `p/...` (registry fetch)
        "--sarif",
        "--metrics=off",
        "--disable-version-check",
        "--quiet",
        CONTAINER_REPO_PATH,
      ],
      workdir: CONTAINER_REPO_PATH,
      mounts: [{ source: "", target: CONTAINER_REPO_PATH, readOnly: true }],
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      timeoutMs: 10 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    // semgrep: 0 = clean, 1 = findings (both success), >1 = error.
    if (result.exitCode === 0 || result.exitCode === 1) return "success";
    return "fail";
  }

  async parse(result: SandboxResult, _ctx: ScanContext): Promise<RawFinding[]> {
    const json = extractSarif(result.stdout);
    if (!json) return [];
    let log: SarifLog;
    try {
      log = JSON.parse(json) as SarifLog;
    } catch {
      return [];
    }
    return normalizeSarif(log, { pillar: "sast", tool: "semgrep" });
  }
}

/** Semgrep may print progress before the SARIF object; slice the JSON out. */
function extractSarif(s: string): string | null {
  const start = s.indexOf('{"');
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  return s.slice(start, end + 1);
}
