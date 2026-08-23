import type { ExitClass, RawFinding, Severity } from "@auditer/types";
import type { ScannerAdapter, ScanContext } from "../ports/adapter.js";
import type { SandboxSpec, SandboxResult, NetworkPolicy } from "../ports/sandbox.js";
import { DEFAULT_HARDENING, CONTAINER_SCRATCH_PATH } from "../ports/sandbox.js";
import { withFingerprints } from "../normalize/fingerprint.js";

/**
 * UX pillar — Lighthouse (performance / accessibility / best-practices / SEO)
 * against an ownership-verified target. Headless Chromium runs inside the same
 * hardened, egress-scoped sandbox (Chrome's own sandbox is off — gVisor provides
 * the isolation instead). axe-core deep a11y + Claude vision critique are v2/v3
 * depth layered as sibling adapters.
 *
 * Emits Lighthouse JSON; parse categories + failed accessibility audits.
 */
interface LhAudit {
  id?: string;
  title?: string;
  description?: string;
  score?: number | null;
  scoreDisplayMode?: string;
}
interface LhReport {
  categories?: Record<string, { id?: string; title?: string; score?: number | null; auditRefs?: { id: string }[] }>;
  audits?: Record<string, LhAudit>;
}

export class LighthouseAdapter implements ScannerAdapter {
  readonly id = "lighthouse";
  readonly pillar = "ux" as const;
  readonly tool = "lighthouse";
  readonly isolationTier = "gvisor" as const;
  readonly needsNetwork = true;
  readonly image = "femtopixel/google-lighthouse:8.6.0";

  appliesTo(ctx: ScanContext): boolean {
    return Boolean(ctx.target?.url);
  }

  buildSpec(ctx: ScanContext): SandboxSpec {
    const url = ctx.target!.url;
    const host = safeHost(url);
    const network: NetworkPolicy = {
      mode: "egress-proxy",
      proxyUrl: process.env.EGRESS_PROXY_URL ?? "http://egress-proxy:3128",
      allowHosts: [host, ...(ctx.target?.scopeAllowlist ?? [])],
    };
    return {
      image: this.image,
      cmd: [
        url,
        "--output=json",
        "--output-path=stdout",
        "--only-categories=performance,accessibility,best-practices,seo",
        '--chrome-flags=--headless --no-sandbox --disable-gpu',
      ],
      env: { HOME: CONTAINER_SCRATCH_PATH, TMPDIR: CONTAINER_SCRATCH_PATH },
      network,
      isolationTier: this.isolationTier,
      mounts: [],
      ...DEFAULT_HARDENING,
      memoryBytes: 4 * 1024 * 1024 * 1024, // Chromium is memory-hungry
      timeoutMs: 5 * 60_000,
    };
  }

  classifyExit(result: SandboxResult): ExitClass {
    if (result.timedOut) return "partial";
    return result.exitCode === 0 ? "success" : "fail";
  }

  async parse(result: SandboxResult, ctx: ScanContext): Promise<RawFinding[]> {
    const json = extractJson(result.stdout);
    if (!json) return [];
    let report: LhReport;
    try {
      report = JSON.parse(json) as LhReport;
    } catch {
      return [];
    }
    const url = ctx.target?.url ?? "";
    const raw: Omit<RawFinding, "fingerprint">[] = [];

    // 1. Category-level summary findings (perf/a11y/best-practices/seo).
    for (const [key, cat] of Object.entries(report.categories ?? {})) {
      const score = cat.score;
      if (score === null || score === undefined || score >= 0.9) continue;
      raw.push({
        pillar: this.pillar,
        tool: this.tool,
        ruleId: `category.${key}`,
        severity: scoreToSeverity(score),
        title: `${cat.title ?? key}: ${Math.round(score * 100)}/100`,
        description: `Lighthouse ${cat.title ?? key} score is ${Math.round(score * 100)}/100 (target ≥ 90).`,
        cwe: [],
        vulnIds: [],
        target: { url },
        references: [],
      });
    }

    // 2. Individual failed accessibility audits (score 0 in binary mode).
    const a11yRefs = report.categories?.accessibility?.auditRefs ?? [];
    for (const ref of a11yRefs) {
      const audit = report.audits?.[ref.id];
      if (!audit || audit.score === null || audit.score === undefined || audit.score >= 1) continue;
      raw.push({
        pillar: this.pillar,
        tool: this.tool,
        ruleId: `a11y.${audit.id ?? ref.id}`,
        severity: "medium",
        title: `Accessibility: ${audit.title ?? ref.id}`,
        description: audit.description ?? "",
        cwe: [],
        vulnIds: [],
        target: { url },
        references: [],
      });
    }

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

function scoreToSeverity(score: number): Severity {
  if (score < 0.4) return "high";
  if (score < 0.7) return "medium";
  return "low";
}

function extractJson(s: string): string | null {
  const start = s.indexOf("{");
  const end = s.lastIndexOf("}");
  if (start === -1 || end === -1 || end < start) return null;
  return s.slice(start, end + 1);
}
