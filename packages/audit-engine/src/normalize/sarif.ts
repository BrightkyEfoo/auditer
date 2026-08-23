import type { Pillar, Severity, RawFinding } from "@auditer/types";
import { withFingerprints } from "./fingerprint.js";

/**
 * SARIF 2.1.0 → canonical RawFinding[]. Most scanners (Semgrep, Trivy, Checkov,
 * hadolint, eslint via the SARIF formatter, gitleaks --report-format sarif)
 * emit SARIF natively, so Wave 2/3 adapters usually just delegate their parse()
 * to this — one normalizer, one dedup algorithm, one AI input shape.
 *
 * Minimal structural types (we read a subset of the spec).
 */

export interface SarifLog {
  runs?: SarifRun[];
}
interface SarifRun {
  tool?: { driver?: { name?: string; version?: string; rules?: SarifRule[] } };
  results?: SarifResult[];
}
interface SarifRule {
  id?: string;
  name?: string;
  properties?: { tags?: string[]; "security-severity"?: string; cwe?: string[] };
  defaultConfiguration?: { level?: string };
  help?: { text?: string; markdown?: string };
  fullDescription?: { text?: string };
  helpUri?: string;
}
interface SarifResult {
  ruleId?: string;
  ruleIndex?: number;
  level?: string;
  message?: { text?: string };
  locations?: {
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: {
        startLine?: number;
        endLine?: number;
        startColumn?: number;
        endColumn?: number;
        snippet?: { text?: string };
      };
    };
  }[];
  properties?: Record<string, unknown>;
}

export interface SarifNormalizeOpts {
  pillar: Pillar;
  /** Override the tool name (else read from the SARIF driver). */
  tool?: string;
}

/** SARIF `level` → our Severity, refined by a numeric security-severity if present. */
function mapSeverity(level: string | undefined, securitySeverity?: string): Severity {
  if (securitySeverity) {
    const n = Number.parseFloat(securitySeverity);
    if (!Number.isNaN(n)) {
      if (n >= 9) return "critical";
      if (n >= 7) return "high";
      if (n >= 4) return "medium";
      if (n > 0) return "low";
    }
  }
  switch ((level ?? "").toLowerCase()) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    case "none":
      return "info";
    default:
      return "medium";
  }
}

function extractCwe(rule?: SarifRule): string[] {
  const out = new Set<string>();
  for (const tag of rule?.properties?.tags ?? []) {
    const m = /cwe[-_ ]?(\d+)/i.exec(tag);
    if (m) out.add(`CWE-${m[1]}`);
  }
  for (const c of rule?.properties?.cwe ?? []) out.add(c);
  return [...out];
}

export function normalizeSarif(
  log: SarifLog,
  opts: SarifNormalizeOpts,
): RawFinding[] {
  const raw: Omit<RawFinding, "fingerprint">[] = [];

  for (const run of log.runs ?? []) {
    const driver = run.tool?.driver;
    const tool = opts.tool ?? driver?.name ?? "sarif";
    const rules = driver?.rules ?? [];

    for (const result of run.results ?? []) {
      const rule =
        (result.ruleIndex !== undefined ? rules[result.ruleIndex] : undefined) ??
        rules.find((r) => r.id === result.ruleId);

      const securitySeverity = rule?.properties?.["security-severity"];
      const loc = result.locations?.[0]?.physicalLocation;
      const region = loc?.region;

      raw.push({
        pillar: opts.pillar,
        tool,
        toolVersion: driver?.version,
        ruleId: result.ruleId ?? rule?.id ?? "unknown",
        severity: mapSeverity(result.level ?? rule?.defaultConfiguration?.level, securitySeverity),
        cvssScore: securitySeverity ? Number.parseFloat(securitySeverity) : undefined,
        title: rule?.name ?? result.ruleId ?? "Finding",
        description:
          result.message?.text ??
          rule?.fullDescription?.text ??
          rule?.help?.text ??
          "",
        cwe: extractCwe(rule),
        vulnIds: [],
        location: loc?.artifactLocation?.uri
          ? {
              path: loc.artifactLocation.uri,
              startLine: region?.startLine,
              endLine: region?.endLine,
              startColumn: region?.startColumn,
              endColumn: region?.endColumn,
            }
          : undefined,
        evidence: region?.snippet?.text,
        references: rule?.helpUri ? [rule.helpUri] : [],
      });
    }
  }

  return withFingerprints(raw);
}
