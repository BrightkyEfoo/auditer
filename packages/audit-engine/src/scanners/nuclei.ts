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
  // OUR image: nuclei v3.4.10 + nuclei-templates v10.4.8 baked in at /templates
  // (infra/docker/scanners/nuclei), because the upstream image ships the binary
  // and NO templates — see classifyExit below for what that cost us.
  //
  // The upstream base is itself pinned by digest inside that Dockerfile. It used
  // to be named here as `v3.3.7`, a tag that was NEVER PUBLISHED: upstream cut a
  // v3.3.7 GitHub release but pushed no container for it (Docker Hub goes
  // v3.3.6 → v3.3.8). Every DAST run would have died on an unresolvable pull —
  // the kind of break a moving tag hides and a digest cannot.
  readonly image = "auditer/nuclei:3.4.10-t10.4.8-1";

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
      // `-templates`, `-jsonl`, `-output`, `-no-interactsh` and
      // `-disable-update-check` belong to the image's entrypoint, not here: they
      // are output plumbing and sandbox constraints, and the wrapper is what
      // asserts a non-empty template load before any verdict is returned.
      cmd: [
        "-target",
        url,
        "-rate-limit",
        "50", // be a good citizen even on our own targets
        "-severity",
        "low,medium,high,critical",
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
    // That mapping was a SILENT HOLE until the image carried its own corpus.
    // Upstream's Dockerfile (verified at v3.4.10) installs only the binary, so
    // nuclei fetched nuclei-templates from GitHub on first run — forbidden twice
    // over here, since egress is proxy-scoped to the audited host alone and the
    // container runs as 65534 with no writable HOME. A run with zero templates
    // probes nothing, prints nothing and exits 0: the line below recorded
    // "success" and the DAST pillar read CLEAN on a scan that never happened.
    //
    // What makes exit 0 trustworthy now is not the corpus being present but the
    // entrypoint refusing to stay quiet about it: infra/docker/scanners/nuclei
    // reads back the template count nuclei reports FOR THIS RUN and exits 65
    // (count unreadable) or 66 (count zero) rather than returning an empty
    // verdict. A stdout heuristic could not have done this — `-silent` suppresses
    // the very line that carries the count, which is why the wrapper drops it.
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
