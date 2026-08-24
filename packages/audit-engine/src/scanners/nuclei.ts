import type { ExitClass, RawFinding, Severity } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult, NetworkPolicy } from "../ports/sandbox.js";
import { DEFAULT_HARDENING } from "../ports/sandbox.js";
import { withFingerprints } from "../normalize/fingerprint.js";

/**
 * DAST pillar — nuclei template-based probing (CVE + misconfig + exposures)
 * against an OWNERSHIP-VERIFIED target. This adapter NEVER runs unless the
 * worker has confirmed Target.verificationStatus === "verified"; on top of that,
 * the sandbox gets network ONLY through the per-audit egress-proxy scoped to the
 * target host, so a rogue template physically cannot leave scope.
 *
 * nuclei emits JSONL; parse line-by-line.
 */
interface NucleiLine {
  "template-id"?: string;
  type?: string;
  host?: string;
  "matched-at"?: string;
  info?: {
    name?: string;
    severity?: string;
    description?: string;
    tags?: string[];
    reference?: string[];
    classification?: {
      "cve-id"?: string[];
      "cwe-id"?: string[];
      "cvss-score"?: number;
    };
  };
}

export class NucleiAdapter implements ScannerAdapter {
  readonly id = "nuclei";
  readonly pillar = "dast" as const;
  readonly tool = "nuclei";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = true;
  // nuclei v3.3.8 — pinned by digest.
  //
  // This adapter used to name `v3.3.7`, a tag that was NEVER PUBLISHED: upstream
  // cut a v3.3.7 GitHub release but pushed no container for it (Docker Hub goes
  // v3.3.6 → v3.3.8). Every DAST run would have died on an unresolvable pull —
  // the kind of break a moving tag hides and a digest cannot. v3.3.8 is the next
  // patch that actually exists. Not cosign-signed (see
  // infra/docker/scanners/README.md).
  //
  // TODO(infra): the template corpus is still whatever the image shipped with;
  // bake a reviewed, pinned nuclei-templates version so template drift cannot
  // move DAST verdicts either.
  readonly image =
    "projectdiscovery/nuclei@sha256:3c37049ecfd2d3230add2e7308249f694bcb43cfe243d090d6046cd6c35ff855";

  appliesTo(ctx: ScanContext): boolean {
    return Boolean(ctx.target?.url);
  }

  buildSpec(ctx: ScanContext): SandboxSpec {
    const url = ctx.target!.url;
    const host = safeHost(url);
    const allowHosts = [host, ...(ctx.target?.scopeAllowlist ?? [])];
    const network: NetworkPolicy = {
      mode: "egress-proxy",
      proxyUrl: process.env.EGRESS_PROXY_URL ?? "http://egress-proxy:3128",
      allowHosts,
    };
    return {
      image: this.image,
      cmd: [
        "-target",
        url,
        "-jsonl",
        "-silent",
        "-rate-limit",
        "50", // be a good citizen even on our own targets
        "-severity",
        "low,medium,high,critical",
        "-disable-update-check",
      ],
      network,
      isolationTier: this.isolationTier,
      mounts: [], // no repo — target-based
      ...DEFAULT_HARDENING,
      timeoutMs: 20 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    // nuclei exits 0 whether or not it finds anything; nonzero = error.
    return result.exitCode === 0 ? "success" : "fail";
  }

  async parse(result: SandboxResult, _ctx: ScanContext): Promise<RawFinding[]> {
    const raw = result.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.startsWith("{"))
      .flatMap((line) => {
        let entry: NucleiLine;
        try {
          entry = JSON.parse(line) as NucleiLine;
        } catch {
          return [];
        }
        const info = entry.info ?? {};
        const cls = info.classification ?? {};
        const cvss = cls["cvss-score"];
        return [
          {
            pillar: this.pillar,
            tool: this.tool,
            ruleId: entry["template-id"] ?? "nuclei",
            severity: mapSeverity(info.severity, cvss),
            cvssScore: cvss,
            title: info.name ?? entry["template-id"] ?? "DAST finding",
            description: info.description ?? "",
            cwe: cls["cwe-id"] ?? [],
            vulnIds: (cls["cve-id"] ?? []).map((c) => c.toUpperCase()),
            owaspCategory: (info.tags ?? []).find((t) => /owasp/i.test(t)),
            target: {
              url: entry["matched-at"] ?? entry.host ?? "",
              method: "GET",
            },
            references: (info.reference ?? []).filter((r) => /^https?:/.test(r)),
          },
        ];
      });
    return withFingerprints(raw);
  }
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function mapSeverity(sev: string | undefined, cvss?: number): Severity {
  if (cvss !== undefined) {
    if (cvss >= 9) return "critical";
    if (cvss >= 7) return "high";
    if (cvss >= 4) return "medium";
    if (cvss > 0) return "low";
  }
  switch ((sev ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "info":
      return "info";
    default:
      return "info";
  }
}
