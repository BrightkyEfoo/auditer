import type { ExitClass, RawFinding, Severity, Ecosystem } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult } from "../ports/sandbox.js";
import {
  DEFAULT_HARDENING,
  CONTAINER_REPO_PATH,
} from "../ports/sandbox.js";
import { withFingerprints } from "../normalize/fingerprint.js";

/**
 * SCA / CVE pillar — osv-scanner in OFFLINE mode against lockfiles/manifests.
 * No code execution, no build: parses dependency manifests and matches against
 * a pre-baked OSV database mounted read-only. Leads the v1 alongside secrets
 * because "test all CVEs" is the owner's stated priority.
 *
 * Recall in v1 is osv-scanner alone; v2 unions Trivy + Grype and dedups on
 * purl+alias (the SCA fingerprint already folds duplicate CVE-on-package rows).
 */

// osv-scanner JSON output (subset of the v1 schema)
interface OsvVuln {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  database_specific?: { severity?: string; cwe_ids?: string[] };
  severity?: { type?: string; score?: string }[];
  affected?: {
    ranges?: { events?: { fixed?: string }[] }[];
  }[];
}
interface OsvPackage {
  package?: { name?: string; version?: string; ecosystem?: string };
  vulnerabilities?: OsvVuln[];
  groups?: { ids?: string[]; aliases?: string[] }[];
}
interface OsvResult {
  source?: { path?: string; type?: string };
  packages?: OsvPackage[];
}
interface OsvOutput {
  results?: OsvResult[];
}

const MANIFEST_HINTS = [
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "package.json",
  "requirements.txt",
  "poetry.lock",
  "Pipfile.lock",
  "go.mod",
  "go.sum",
  "pom.xml",
  "build.gradle",
  "composer.lock",
  "Cargo.lock",
  "Gemfile.lock",
  "packages.lock.json",
];

export class OsvScannerAdapter implements ScannerAdapter {
  readonly id = "osv-scanner";
  readonly pillar = "sca" as const;
  readonly tool = "osv-scanner";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = false; // offline DB mounted read-only
  // TODO(infra): pin to a cosign-verified @sha256 digest.
  readonly image = "ghcr.io/google/osv-scanner:v1.9.2";

  appliesTo(ctx: ScanContext): boolean {
    // Relevance gate: only run if a supported manifest is present.
    const present = ctx.manifests ?? [];
    return present.some((m) => MANIFEST_HINTS.includes(m));
  }

  buildSpec(_ctx: ScanContext): SandboxSpec {
    // The offline OSV DB is a host directory (refreshed out-of-band) mounted
    // read-only; OSV_DB_HOST_PATH tells the worker where it lives on the host.
    const dbHostPath = process.env.OSV_DB_HOST_PATH;
    const mounts = [{ source: "", target: CONTAINER_REPO_PATH, readOnly: true }];
    if (dbHostPath) {
      mounts.push({ source: dbHostPath, target: "/opt/osv-db", readOnly: true });
    }
    return {
      image: this.image,
      cmd: [
        "scan",
        "--experimental-offline", // no network; match against the mounted DB
        "--experimental-offline-vulnerabilities",
        "--experimental-local-db-path=/opt/osv-db",
        "--format=json",
        "--recursive",
        CONTAINER_REPO_PATH,
      ],
      workdir: CONTAINER_REPO_PATH,
      env: { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: "/opt/osv-db" },
      mounts,
      network: { mode: "none" },
      isolationTier: this.isolationTier,
      ...DEFAULT_HARDENING,
      timeoutMs: 5 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    // osv-scanner: 0 = no vulns, 1 = vulns found (both successful), >1 = error.
    if (result.exitCode === 0 || result.exitCode === 1) return "success";
    return "fail";
  }

  async parse(result: SandboxResult, _ctx: ScanContext): Promise<RawFinding[]> {
    const json = extractJson(result.stdout);
    if (!json) return [];
    let out: OsvOutput;
    try {
      out = JSON.parse(json) as OsvOutput;
    } catch {
      return [];
    }

    const raw: Omit<RawFinding, "fingerprint">[] = [];
    for (const res of out.results ?? []) {
      const sourcePath = res.source?.path ?? "manifest";
      for (const pkg of res.packages ?? []) {
        const name = pkg.package?.name ?? "unknown";
        const version = pkg.package?.version ?? "0.0.0";
        const ecosystem = mapEcosystem(pkg.package?.ecosystem);
        for (const v of pkg.vulnerabilities ?? []) {
          const cvss = extractCvss(v.severity);
          const ids = [v.id, ...(v.aliases ?? [])].filter(Boolean) as string[];
          const fixed = extractFixed(v);
          raw.push({
            pillar: this.pillar,
            tool: this.tool,
            ruleId: v.id ?? "OSV",
            severity: severityFromCvss(cvss, v.database_specific?.severity),
            cvssScore: cvss,
            title: v.summary ?? `${name}@${version}: ${v.id}`,
            description: v.details ?? v.summary ?? "",
            cwe: v.database_specific?.cwe_ids ?? [],
            vulnIds: [...new Set(ids.map((x) => x.toUpperCase()))],
            location: { path: sourcePath },
            package: {
              ecosystem,
              name,
              version,
              purl: buildPurl(ecosystem, name, version),
              fixedVersion: fixed,
            },
            references: [`https://osv.dev/vulnerability/${v.id ?? ""}`],
          });
        }
      }
    }
    return withFingerprints(raw);
  }
}

function extractJson(s: string): string | null {
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  return s.slice(start, end + 1);
}

function mapEcosystem(e?: string): Ecosystem {
  const m: Record<string, Ecosystem> = {
    npm: "npm",
    "PyPI": "pypi",
    Go: "go",
    Maven: "maven",
    "crates.io": "cargo",
    Packagist: "composer",
    RubyGems: "rubygems",
    NuGet: "nuget",
  };
  const hit = e ? m[e] : undefined;
  return hit ?? "other";
}

function buildPurl(ecosystem: Ecosystem, name: string, version: string): string {
  const type =
    ecosystem === "pypi" ? "pypi" : ecosystem === "rubygems" ? "gem" : ecosystem;
  return `pkg:${type}/${name}@${version}`;
}

function extractCvss(severity?: { type?: string; score?: string }[]): number | undefined {
  for (const s of severity ?? []) {
    if (s.type?.startsWith("CVSS") && s.score) {
      const numeric = Number.parseFloat(s.score);
      if (!Number.isNaN(numeric)) return numeric;
      // s.score may be a vector — leave numeric extraction to a later pass.
    }
  }
  return undefined;
}

function extractFixed(v: OsvVuln): string | undefined {
  for (const a of v.affected ?? []) {
    for (const r of a.ranges ?? []) {
      for (const e of r.events ?? []) {
        if (e.fixed) return e.fixed;
      }
    }
  }
  return undefined;
}

function severityFromCvss(cvss: number | undefined, dbSeverity?: string): Severity {
  if (cvss !== undefined) {
    if (cvss >= 9) return "critical";
    if (cvss >= 7) return "high";
    if (cvss >= 4) return "medium";
    if (cvss > 0) return "low";
  }
  switch ((dbSeverity ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "medium"; // unknown CVE → assume medium, never silently info
  }
}
