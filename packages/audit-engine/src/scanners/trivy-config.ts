import type { ExitClass, RawFinding } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH, CONTAINER_SCRATCH_PATH } from "../ports/sandbox.js";
import { normalizeSarif, type SarifLog } from "../normalize/sarif.js";

/**
 * Repo-hygiene pillar — Trivy `config` for IaC misconfig (Terraform, K8s,
 * CloudFormation, Helm, Dockerfile). Deliberately scoped to config only; Trivy's
 * SCA/CVE capability belongs to the SCA pillar (avoid double-counting).
 * Emits SARIF → shared normalizer. Offline (policy bundle baked into the image).
 */
const IAC_HINTS = /\.(tf|ya?ml|json|hcl)$|Dockerfile|Chart\.ya?ml/i;

export class TrivyConfigAdapter implements ScannerAdapter {
  readonly id = "trivy-config";
  readonly pillar = "hygiene" as const;
  readonly tool = "trivy-config";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false;
  readonly image = "aquasec/trivy:0.58.0";

  appliesTo(ctx: ScanContext): boolean {
    // Run when the repo plausibly has IaC/config to check.
    return (ctx.manifests ?? []).some((m) => IAC_HINTS.test(m)) || true;
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    return {
      image: this.image,
      cmd: [
        "config",
        "--format",
        "sarif",
        "--output",
        `${CONTAINER_SCRATCH_PATH}/trivy.sarif`,
        "--skip-db-update",
        CONTAINER_REPO_PATH,
      ],
      workdir: CONTAINER_REPO_PATH,
      env: { TRIVY_CACHE_DIR: CONTAINER_SCRATCH_PATH },
      mounts: [{ source: "", target: CONTAINER_REPO_PATH, readOnly: true }],
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      timeoutMs: 5 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    if (result.exitCode === 0 || result.exitCode === 1) return "success";
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

function extractSarif(s: string): string | null {
  const start = s.indexOf('{"');
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  return s.slice(start, end + 1);
}
