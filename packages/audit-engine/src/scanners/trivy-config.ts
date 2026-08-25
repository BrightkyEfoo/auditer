import type { ExitClass, RawFinding } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH, CONTAINER_SCRATCH_PATH } from "../ports/sandbox.js";
import { normalizeSarif, type SarifLog } from "../normalize/sarif.js";
import { extractSarif, hasSarifReport } from "../normalize/sarif-stdout.js";

/**
 * Repo-hygiene pillar — Trivy `config` for IaC misconfig (Terraform, K8s,
 * CloudFormation, Helm, Dockerfile). Deliberately scoped to config only; Trivy's
 * SCA/CVE capability belongs to the SCA pillar (avoid double-counting).
 * Emits SARIF → shared normalizer. Offline (policy bundle baked into the image).
 */
const IAC_HINTS = /\.(tf|ya?ml|json|hcl)$|Dockerfile|Chart\.ya?ml/i;

const TRIVY_REPORT = "/out/trivy.sarif";

export class TrivyConfigAdapter implements ScannerAdapter {
  readonly id = "trivy-config";
  readonly pillar = "hygiene" as const;
  readonly tool = "trivy-config";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false;
  // trivy 0.58.0 — pinned by digest. The misconfig policy bundle is baked INTO
  // the image, so the image reference is also the ruleset reference: a moved tag
  // would change which findings a repo produces without any repo change.
  // Cosign-signed (keyless, GitHub Actions OIDC, subject
  // github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.58.0)
  // and verified at pin time — see infra/docker/scanners/README.md.
  readonly image =
    "aquasec/trivy@sha256:b88012e2a0a309d6a8a00463d4e63e5e513377fb74eccbc8f9b0f8f81940ebeb";

  appliesTo(ctx: ScanContext): boolean {
    // Run when the repo plausibly has IaC/config to check.
    return (ctx.manifests ?? []).some((m) => IAC_HINTS.test(m)) || true;
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    return {
      image: this.image,
      // Two defects lived in this argv, and both made the hygiene pillar report
      // clean rather than report a failure:
      //
      // 1. `--skip-db-update` is not a flag of `trivy config` (it belongs to the
      //    vulnerability scanner). trivy 0.58.0 exits FATAL "unknown flag", so
      //    the scan never ran. The offline switch for the misconfig checks is
      //    `--skip-check-update`, which keeps trivy on the rego bundle baked
      //    into the image instead of pulling `mirror.gcr.io/aquasec/trivy-checks`
      //    — mandatory here, since this sandbox has no network at all.
      // 2. `--output <file>` wrote the SARIF into the scratch tmpfs while
      //    `parse` reads `result.stdout`. The report was thrown away with the
      //    container even on the runs that did execute. No `--output`: trivy
      //    writes SARIF to stdout, which is the only channel the runner keeps.
      cmd: [
        "config",
        "--format",
        "sarif",
        "--skip-check-update",
        "--quiet", // keep the progress bar out of the report
        // `--output` is back, and for the opposite reason it was removed. It
        // was dropped because `parse` read stdout while the flag wrote to the
        // scratch tmpfs, which the runner discards. The runner now MOUNTS the
        // output directory and returns the file as stdout — which is also the
        // only transport that survives a report over 64 KiB.
        "--output",
        TRIVY_REPORT,
        CONTAINER_REPO_PATH,
      ],
      outputFile: TRIVY_REPORT,
      workdir: CONTAINER_REPO_PATH,
      // TRIVY_CACHE_DIR alone was not enough, and the gap was silent. trivy
      // creates a temporary analysis directory under $TMPDIR, which defaults to
      // /tmp — read-only here:
      //
      //   FATAL  unable to create temporary directory:
      //          mkdir /tmp/analyzer-fs-430145459: read-only file system
      //
      // exit 1, no SARIF, and classifyExit mapped 1 to success. The IaC half of
      // the hygiene pillar had never produced a finding. With TMPDIR on the
      // scratch tmpfs the same command returns 16 KB of SARIF.
      env: { TRIVY_CACHE_DIR: CONTAINER_SCRATCH_PATH, TMPDIR: CONTAINER_SCRATCH_PATH },
      mounts: [{ source: "", target: CONTAINER_REPO_PATH, readOnly: true }],
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      timeoutMs: 5 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    // A SARIF engine that produced no readable SARIF did not succeed, whatever
    // its exit code says. This is the generalisation of every silent hole found
    // so far: an unwritable $HOME, a missing file, a report cut at 64 KiB by the
    // log driver — all of them ended in exit 0 or 1 with nothing parseable, and
    // all of them were recorded as a clean pillar. "Output we could not read"
    // must reach the customer as a gap, never as an absence of findings.
    if (!hasSarifReport(result.stdout)) return "fail";
    // 1 is both "misconfigurations found" and "fatal error"; only the report
    // separates them (normalize/sarif-stdout.ts).
    if (result.exitCode === 0) return "success";
    if (result.exitCode === 1) return "success"; // findings found, report present
    return "fail";
  }

  async parse(result: SandboxResult, _ctx: ScanContext): Promise<RawFinding[]> {
    const json = extractSarif(result.stdout);
    if (!json) return [];
    try {
      return normalizeSarif(JSON.parse(json) as SarifLog, {
        pillar: "hygiene",
        tool: "trivy-config",
      });
    } catch {
      return [];
    }
  }
}

