import type { ExitClass, RawFinding } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH, CONTAINER_SCRATCH_PATH } from "../ports/sandbox.js";
import { normalizeSarif, type SarifLog } from "../normalize/sarif.js";
import { extractSarif, hasSarifReport } from "../normalize/sarif-stdout.js";

/**
 * SAST pillar — Semgrep OSS against a VENDORED ruleset baked into our own image
 * at /rules (see infra/docker/scanners/semgrep).
 *
 * Two independent reasons the ruleset cannot come from upstream:
 *
 * 1. Licensing. `--config p/...` pulls Semgrep's registry rules, which carry the
 *    "Semgrep Rules License v1.0" — it forbids making the rules "available to
 *    others as a service", which is precisely what this product does. The
 *    Opengrep fork does not help: its corpus is LGPL-2.1 + Commons Clause,
 *    which forbids selling a service deriving its value from the software. Our
 *    image is built from GitLab's sast-rules, filtered to MIT/Apache-2.0 only.
 * 2. Determinism. A registry fetch at scan time means two runs of the same
 *    commit can disagree. The rules are pinned to the image digest instead.
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
  // Built by infra/docker/scanners/semgrep, not pulled from a registry: the
  // rules live inside it. Built on the deploy host, so the worker resolves it
  // from the local daemon.
  //
  // Deliberately NOT digest-pinned, unlike every third-party scanner image. A
  // digest identifies a manifest in a registry; this image was never pushed to
  // one, and the id a local `docker build` produces is host-specific — pinning
  // it here would name something that exists on exactly one machine and would
  // break the moment the image is rebuilt. Its reproducibility comes from the
  // build inputs instead (see the Dockerfile: pinned semgrep version, pinned
  // sast-rules commit). TODO(infra): push to a registry, then pin @sha256 here
  // like the others.
  readonly image = "auditer/semgrep-rules:1.99.0-2";

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
      // semgrep writes a settings file under $HOME and unpacks work into
      // $TMPDIR. With neither set, HOME resolves to `/` and the first write
      // dies on the read-only rootfs:
      //
      //   OSError: [Errno 30] Read-only file system: '/.semgrep'
      //
      // exit 1 — the same code semgrep uses for "findings were found", which
      // classifyExit mapped to success. The SAST pillar therefore reported
      // CLEAN on a scanner that crashed before reading a single file, on every
      // run since the pillar existed. With both pointed at the scratch tmpfs
      // the same command returns 1.09 MB of SARIF over 276 rules.
      env: { HOME: CONTAINER_SCRATCH_PATH, TMPDIR: CONTAINER_SCRATCH_PATH },
      mounts: [{ source: "", target: CONTAINER_REPO_PATH, readOnly: true }],
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      timeoutMs: 10 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    // semgrep: 0 = clean. 1 means BOTH "findings were found" and "I crashed",
    // so the exit code alone cannot tell them apart — the report can. See
    // normalize/sarif-stdout.ts for what this guard is paying for.
    if (result.exitCode === 0) return "success";
    if (result.exitCode === 1) return hasSarifReport(result.stdout) ? "success" : "fail";
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
