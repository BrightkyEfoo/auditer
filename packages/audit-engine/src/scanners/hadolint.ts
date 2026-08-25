import type { ExitClass, RawFinding } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH } from "../ports/sandbox.js";
import { normalizeSarif, type SarifLog } from "../normalize/sarif.js";
import { extractSarif, hasSarifReport } from "../normalize/sarif-stdout.js";

/**
 * Repo-hygiene pillar — hadolint Dockerfile linting (best-practice + shellcheck).
 * Emits SARIF. hadolint is GPL — run as an unmodified separate container (which
 * the sandbox model already guarantees; we never link it).
 */

/** hadolint accepts many files in one run and merges them into a single SARIF. */
const MAX_DOCKERFILES = 50;

export class HadolintAdapter implements ScannerAdapter {
  readonly id = "hadolint";
  readonly pillar = "hygiene" as const;
  readonly tool = "hadolint";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false;
  // hadolint 2.12.0 — pinned by digest; the SARIF this image emits carries
  // tool.driver.version 2.12.0, which is how the pin was checked against the tag
  // rather than merely trusted. Not cosign-signed (see
  // infra/docker/scanners/README.md).
  readonly image =
    "hadolint/hadolint@sha256:30a8fd2e785ab6176eed53f74769e04f125afb2f74a6c52aef7d463583b6d45e";

  appliesTo(ctx: ScanContext): boolean {
    return (ctx.dockerfiles ?? []).length > 0;
  }

  buildSpec(ctx: ScanContext): SandboxSpec {
    // The paths come from the worker's own walk of the checkout. This adapter
    // used to hardcode `<repo>/Dockerfile`, and on any repository that keeps its
    // Dockerfiles elsewhere — this one keeps them under infra/docker — hadolint
    // exited 1 with:
    //
    //   /repo/Dockerfile: withBinaryFile: does not exist
    //
    // 1 is also hadolint's code for "lint issues found", so classifyExit
    // recorded a SUCCESSFUL scan with zero findings. The Dockerfile half of the
    // hygiene pillar reported clean on files it had never opened.
    //
    // Paths, not a glob: hadolint has no recursive mode and its image is
    // distroless, so there is no shell in there to expand one.
    const files = (ctx.dockerfiles ?? [])
      .slice(0, MAX_DOCKERFILES)
      .map((rel) => `${CONTAINER_REPO_PATH}/${rel}`);
    return {
      image: this.image,
      cmd: ["hadolint", "--format", "sarif", ...files],
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
    // 0 = clean. 1 = lint issues found, AND 1 = a file could not be read; only
    // the report tells the two apart (normalize/sarif-stdout.ts).
    if (result.exitCode === 0) return "success";
    if (result.exitCode === 1) return hasSarifReport(result.stdout) ? "success" : "fail";
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
