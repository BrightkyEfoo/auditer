import type { ExitClass, RawFinding, Severity } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH } from "../ports/sandbox.js";
import { withFingerprints } from "../normalize/fingerprint.js";

/**
 * Quality pillar — jscpd copy/paste detection (feeds the Duplication sub-score).
 * jscpd emits its own JSON (not SARIF), so this adapter parses natively and maps
 * each duplicated block to a low/info finding.
 *
 * Two defects lived here and cancelled each other into silence. The image
 * reference was `ghcr.io/kucherenko/jscpd:4.0.5`, which has NEVER existed —
 * jscpd is published on npm only, and no container image exists anywhere — so
 * every run failed on "no such image". And even with a working image it would
 * have found nothing: the command wrote its report to a file under /scratch
 * while `parse` read stdout. A scanner that fails is a hole in a pillar, and a
 * hole in a pillar reads to the customer as a clean pillar.
 *
 * Both are closed by building our own image (infra/docker/scanners/jscpd),
 * whose entrypoint runs jscpd and relays the report on stdout like every other
 * adapter here expects.
 */
interface JscpdReport {
  duplicates?: {
    format?: string;
    lines?: number;
    tokens?: number;
    firstFile?: { name?: string; start?: number; end?: number };
    secondFile?: { name?: string; start?: number; end?: number };
    fragment?: string;
  }[];
  statistics?: { total?: { percentage?: number } };
}

export class JscpdAdapter implements ScannerAdapter {
  readonly id = "jscpd";
  readonly pillar = "quality" as const;
  readonly tool = "jscpd";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false;
  // Built by infra/docker/scanners/jscpd, resolved from the local daemon.
  readonly image = "auditer/jscpd:5.0.16-1";

  appliesTo(_ctx: ScanContext): boolean {
    return true;
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    return {
      image: this.image,
      // The entrypoint owns the reporter flags and the report location; it
      // takes the path to scan and nothing else. Keeping those flags here as
      // well is how they drifted out of sync with where the report was read.
      cmd: [CONTAINER_REPO_PATH],
      workdir: CONTAINER_REPO_PATH,
      mounts: [{ source: "", target: CONTAINER_REPO_PATH, readOnly: true }],
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      timeoutMs: 5 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    // 0 normally, 1 when the duplication threshold is exceeded — that is a
    // RESULT, not an error. 65 is our wrapper reporting that jscpd produced no
    // report at all, which must be recorded as a failed scan rather than as a
    // clean pillar.
    if (result.exitCode === 0 || result.exitCode === 1) return "success";
    return "fail";
  }

  async parse(result: SandboxResult, _ctx: ScanContext): Promise<RawFinding[]> {
    const json = extractJson(result.stdout);
    if (!json) return [];
    let report: JscpdReport;
    try {
      report = JSON.parse(json) as JscpdReport;
    } catch {
      return [];
    }

    const raw = (report.duplicates ?? []).map((d) => {
      const lines = d.lines ?? 0;
      const severity: Severity = lines > 100 ? "medium" : lines > 30 ? "low" : "info";
      return {
        pillar: this.pillar,
        tool: this.tool,
        ruleId: "duplication",
        severity,
        title: `Duplicated code block (${lines} lines)`,
        description: `A ${lines}-line block is duplicated between ${d.firstFile?.name ?? "?"} and ${d.secondFile?.name ?? "?"}. Duplication raises maintenance cost and bug risk.`,
        cwe: ["CWE-1041"], // Use of Redundant Code
        vulnIds: [] as string[],
        location: {
          path: d.firstFile?.name ?? "unknown",
          startLine: d.firstFile?.start,
          endLine: d.firstFile?.end,
        },
        references: [] as string[],
        extras: { secondFile: d.secondFile, tokens: d.tokens },
      };
    });

    return withFingerprints(raw);
  }
}

function extractJson(s: string): string | null {
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  return s.slice(start, end + 1);
}
