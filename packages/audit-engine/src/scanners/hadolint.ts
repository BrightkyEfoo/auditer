import type { ExitClass, RawFinding } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH } from "../ports/sandbox.js";
import { normalizeSarif, type SarifLog } from "../normalize/sarif.js";

/**
 * Repo-hygiene pillar — hadolint Dockerfile linting (best-practice + shellcheck).
 * Only runs when a Dockerfile is present (relevance gate). Emits SARIF.
 * hadolint is GPL — run as an unmodified separate container (which the sandbox
 * model already guarantees; we never link it).
 */
export class HadolintAdapter implements ScannerAdapter {
  readonly id = "hadolint";
  readonly pillar = "hygiene" as const;
  readonly tool = "hadolint";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false;
  readonly image = "hadolint/hadolint:2.12.0";

  appliesTo(ctx: ScanContext): boolean {
    return (ctx.manifests ?? []).includes("Dockerfile");
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    return {
      image: this.image,
      // hadolint has no recursive mode; scan the root Dockerfile. (Multi-Dockerfile
      // discovery is a v2 refinement — the worker can enumerate and pass paths.)
      cmd: ["hadolint", "--format", "sarif", `${CONTAINER_REPO_PATH}/Dockerfile`],
      workdir: CONTAINER_REPO_PATH,
      mounts: [{ source: "", target: CONTAINER_REPO_PATH, readOnly: true }],
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      timeoutMs: 2 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    // hadolint: 0 = clean, 1 = lint issues (success), other = error.
    if (result.exitCode === 0 || result.exitCode === 1) return "success";
    return "fail";
  }

  async parse(result: SandboxResult, _ctx: ScanContext): Promise<RawFinding[]> {
    const json = extractSarif(result.stdout);
    if (!json) return [];
    try {
      return normalizeSarif(JSON.parse(json) as SarifLog, {
        pillar: "hygiene",
        tool: "hadolint",
      });
    } catch {
      return [];
    }
  }
}

function extractSarif(s: string): string | null {
  const start = s.indexOf('{"');
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  return s.slice(start, end + 1);
}
