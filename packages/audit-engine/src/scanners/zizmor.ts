import type { ExitClass, RawFinding } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH } from "../ports/sandbox.js";
import { normalizeSarif, type SarifLog } from "../normalize/sarif.js";
import { extractSarif, hasSarifReport } from "../normalize/sarif-stdout.js";

/**
 * Repo-hygiene pillar — zizmor, static analysis of GitHub Actions workflows.
 *
 * This closes a blind spot rather than deepening an existing one. Nothing in the
 * product looked at `.github/workflows` at all, and CI is where a repository is
 * most exposed: a workflow holds credentials, runs on events an outsider can
 * trigger, and interpolates attacker-controlled strings into shell. Run against
 * this repository's own `deploy.yml`, zizmor returned 52 findings — including
 * `template-injection` and `excessive-permissions`, both of which had been sitting
 * in a file reviewed many times by people looking for something else.
 *
 * Filed under hygiene, not sast: it audits how the repository is CONFIGURED,
 * which is the same question trivy-config and hadolint answer, rather than what
 * the application code does at runtime.
 *
 * Emits SARIF on stdout → shared normalizer. Fully offline with `--offline`,
 * which disables the audits that would otherwise call the GitHub API.
 */

/** Set by the workspace when `.github/workflows` holds at least one YAML file. */
const WORKFLOWS_MARKER = ".github/workflows";

export class ZizmorAdapter implements ScannerAdapter {
  readonly id = "zizmor";
  readonly pillar = "hygiene" as const;
  readonly tool = "zizmor";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false;
  // zizmor 1.29.0 — pinned by digest.
  //
  // 1.29.0 and not 1.30.0: the newest tag in the registry is `1.30.0-rc1`, a
  // release candidate. Reading the tag list as version numbers alone made it
  // look like `1.30.0` existed, which is the same mistake that put an
  // unpullable `nuclei:v3.3.7` in this codebase — a tag that parses is not a
  // tag that resolves.
  readonly image =
    "ghcr.io/zizmorcore/zizmor@sha256:863026d54f91271b10b60b67ad8054cb37120167e162482597db102b3026a284";

  appliesTo(ctx: ScanContext): boolean {
    // Gate on workflows actually being present. zizmor exits 3 "no inputs
    // collected" on a repository with none, and running it anyway would record
    // a failed scan — a hole in the hygiene pillar — for a repository that
    // simply does not use GitHub Actions.
    return (ctx.manifests ?? []).includes(WORKFLOWS_MARKER);
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    return {
      image: this.image,
      cmd: [
        "--format=sarif", // stdout; the runner keeps no files
        // Without this, zizmor runs audits that call the GitHub API to resolve
        // action references. The sandbox has no network at all, so those audits
        // would fail the run rather than degrade — the flag makes the offline
        // subset the explicit contract instead of an accident.
        "--offline",
        // `regular` and not `auditor`/`pedantic`: the other two personas
        // deliberately accept false positives and code smells. A report a
        // customer pays for cannot open with findings the tool itself labels as
        // probably-wrong.
        "--persona=regular",
        CONTAINER_REPO_PATH,
      ],
      workdir: CONTAINER_REPO_PATH,
      mounts: [{ source: "", target: CONTAINER_REPO_PATH, readOnly: true }],
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      // Workflow files are small and few; the whole audit finished in under a
      // second on this repository.
      timeoutMs: 3 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    // Verified against the pinned image: 0 with findings AND 0 without —
    // `--format=sarif` suppresses the finding-driven exit code, so a non-zero
    // status here always means the tool failed rather than that it found
    // something. 1 is mapped alongside 0 anyway, so a future version that
    // reinstates the finding exit code cannot turn results into a failed scan.
    if (result.exitCode === 0) return "success";
    if (result.exitCode === 1) return hasSarifReport(result.stdout) ? "success" : "fail";
    // 3 is "no inputs collected". `appliesTo` should have prevented it, so
    // reaching it means the gate and the repository disagree — a real failure,
    // and one that must not be smoothed into an empty clean result.
    return "fail";
  }

  async parse(result: SandboxResult, _ctx: ScanContext): Promise<RawFinding[]> {
    const json = extractSarif(result.stdout);
    if (!json) return [];
    try {
      return normalizeSarif(JSON.parse(json) as SarifLog, {
        pillar: "hygiene",
        tool: "zizmor",
      });
    } catch {
      return [];
    }
  }
}

