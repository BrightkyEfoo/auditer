import type { ExitClass, RawFinding, Severity } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH } from "../ports/sandbox.js";
import { withFingerprints } from "../normalize/fingerprint.js";

/**
 * Secrets pillar — Gitleaks over the FULL git history (secrets persist in
 * history even after deletion from HEAD). No network, no build: the cleanest
 * thing to prove RCE-containment on, which is why it leads the v1.
 *
 * Gitleaks emits SARIF, but its secret-specific fields (entropy, commit, masked
 * match) are richer in its native JSON report — so we parse native JSON here.
 */

// gitleaks native JSON report entry (subset)
interface GitleaksFinding {
  RuleID: string;
  Description: string;
  File: string;
  StartLine: number;
  EndLine: number;
  Secret: string;
  Match: string;
  Commit: string;
  Entropy: number;
  Tags?: string[];
}

// Write the JSON report to stdout (the runner captures stdout, not files);
// gitleaks' own progress logs go to stderr, so stdout stays clean JSON.
const REPORT_PATH = "/dev/stdout";

export class GitleaksAdapter implements ScannerAdapter {
  readonly id = "gitleaks";
  readonly pillar = "secrets" as const;
  readonly tool = "gitleaks";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false;
  // gitleaks v8.21.2 — pinned by digest so the binary that produced a report
  // cannot change under a rebuild. `v8.21.2` is a mutable pointer: upstream can
  // repoint it at any time, and two scans of the same commit would then disagree
  // for reasons that have nothing to do with the commit. Not cosign-signed —
  // gitleaks publishes no signature (see infra/docker/scanners/README.md).
  readonly image =
    "ghcr.io/gitleaks/gitleaks@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46";

  appliesTo(_ctx: ScanContext): boolean {
    // Every git repo is in scope for secret scanning.
    return true;
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    return {
      image: this.image,
      // `git` mode walks full history; JSON report streamed to stdout. The
      // worker chowns the cloned workspace to this container's uid, so git sees
      // matching ownership and doesn't trip the "dubious ownership" guard.
      cmd: [
        "git",
        CONTAINER_REPO_PATH,
        "--report-format=json",
        `--report-path=${REPORT_PATH}`,
        "--exit-code=2", // 2 = leaks found; 0 = clean; 1 = error (see classifyExit)
        "--redact",
        "--no-banner",
      ],
      workdir: CONTAINER_REPO_PATH,
      mounts: [
        { source: "", target: CONTAINER_REPO_PATH, readOnly: true }, // source filled by worker
      ],
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      timeoutMs: 10 * 60_000, // full history can be slow on large repos
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial"; // keep whatever was written
    // gitleaks: 0 = no leaks, 2 = leaks found (both are successful scans),
    // 1 = actual error.
    if (result.exitCode === 0 || result.exitCode === 2) return "success";
    return "fail";
  }

  async parse(result: SandboxResult, ctx: ScanContext): Promise<RawFinding[]> {
    // The worker copies REPORT_PATH out and passes it as stdout, OR we read the
    // artifact. Here we accept it via stdout for the vertical-slice path.
    const json = extractJson(result.stdout);
    if (!json) return [];
    let entries: GitleaksFinding[];
    try {
      entries = JSON.parse(json) as GitleaksFinding[];
    } catch {
      return [];
    }

    const raw = entries.map((e) => ({
      pillar: this.pillar,
      tool: this.tool,
      ruleId: e.RuleID,
      severity: severityForRule(e.RuleID, e.Entropy),
      title: `Exposed secret: ${e.Description || e.RuleID}`,
      description: `A secret matching rule "${e.RuleID}" was found in git history. Even if removed from HEAD, it remains in history and must be rotated.`,
      cwe: ["CWE-798"], // Use of Hard-coded Credentials
      vulnIds: [] as string[],
      location: {
        path: e.File,
        startLine: e.StartLine,
        endLine: e.EndLine,
        commitSha: e.Commit,
      },
      // Secret already redacted by --redact; store the masked match only.
      evidence: e.Match,
      references: [
        "https://cwe.mitre.org/data/definitions/798.html",
      ],
      confidence: entropyConfidence(e.Entropy),
    }));

    return withFingerprints(raw);
  }
}

/** Verified/high-signal rules get higher severity; entropy nudges it. */
function severityForRule(ruleId: string, entropy: number): Severity {
  const high = /(aws|gcp|private[-_ ]?key|token|secret|password)/i;
  if (high.test(ruleId) || entropy > 4.5) return "critical";
  if (entropy > 3.5) return "high";
  return "medium";
}

function entropyConfidence(entropy: number): number {
  return Math.max(0.4, Math.min(1, entropy / 6));
}

/** gitleaks writes to a file; the worker may relay it via stdout. Be lenient. */
function extractJson(s: string): string | null {
  const start = s.indexOf("[");
  const end = s.lastIndexOf("]");
  if (start === -1 || end === -1 || end < start) return null;
  return s.slice(start, end + 1);
}
