import type { ExitClass, RawFinding, Severity } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_REPO_PATH, CONTAINER_SCRATCH_PATH } from "../ports/sandbox.js";
import { withFingerprints } from "../normalize/fingerprint.js";

/**
 * Quality pillar — jscpd copy/paste detection (feeds the Duplication sub-score).
 * jscpd emits its own JSON (not SARIF), so this adapter parses natively and maps
 * each duplicated block to a low/info finding. scc/lizard (LOC + complexity) are
 * sibling metric adapters added in v2.
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
  readonly image = "ghcr.io/kucherenko/jscpd:4.0.5";

  appliesTo(_ctx: ScanContext): boolean {
    return true;
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    return {
      image: this.image,
      cmd: [
        CONTAINER_REPO_PATH,
        "--reporters",
        "json",
        "--output",
        CONTAINER_SCRATCH_PATH,
        "--mode",
        "strict",
        "--silent",
      ],
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
    // jscpd exits 0 normally; nonzero when threshold exceeded (still a success).
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
