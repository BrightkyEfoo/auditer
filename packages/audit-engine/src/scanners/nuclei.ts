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
  // nuclei v3.4.10 — pinned by digest.
  //
  // This adapter used to name `v3.3.7`, a tag that was NEVER PUBLISHED: upstream
  // cut a v3.3.7 GitHub release but pushed no container for it (Docker Hub goes
  // v3.3.6 → v3.3.8). Every DAST run would have died on an unresolvable pull —
  // the kind of break a moving tag hides and a digest cannot. v3.4.10 is the
  // newest v3.4 patch and was confirmed pullable on the x86_64 deploy host, so
  // it is the version this pin follows. Not cosign-signed (see
  // infra/docker/scanners/README.md).
  readonly image =
    "projectdiscovery/nuclei@sha256:aeb5ea2db32a252b8135707d2ad0e89b90e19a18ea7816d38759bc51efb46b97";

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
    //
    // KNOWN SILENT HOLE — this mapping is not safe yet, and the reason is the
    // image, not the code. Upstream's Dockerfile (verified at v3.4.10) installs
    // ONLY the nuclei binary: `COPY --from=builder /app/bin/nuclei` on top of
    // alpine, no template corpus. nuclei therefore fetches nuclei-templates from
    // GitHub on first run — which this sandbox forbids twice over, since egress
    // is proxy-scoped to the audited host alone and the container runs as 65534
    // with no writable HOME. A run with zero templates probes nothing, prints
    // nothing, and exits 0, so the line above records "success" and the DAST
    // pillar reads CLEAN on a scan that never happened.
    //
    // Do not paper over this with a stdout heuristic: `-silent` suppresses the
    // template count, so there is nothing dependable to match on. The fix is to
    // bake a reviewed, pinned nuclei-templates corpus into an image we build
    // (the auditer/semgrep-rules pattern — infra/docker/scanners/semgrep) and
    // pass `-templates`, which also makes DAST verdicts reproducible instead of
    // dependent on the day the corpus was fetched.
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
