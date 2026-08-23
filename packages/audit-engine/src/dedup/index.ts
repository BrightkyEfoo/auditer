import type { RawFinding, Severity, DedupeGroup } from "@auditer/types";
import { SEVERITY_RANK } from "@auditer/types";

/**
 * Deterministic dedup / correlation — runs BEFORE any AI call. Collapsing
 * Semgrep+Bandit+gosec on the same line, or Trivy+OSV+Grype on the same CVE,
 * cuts AI token cost 10-40x and stops the model from unreliably re-deduping or
 * hallucinating. Only ONE compacted representative per cluster is sent to Claude.
 *
 * Two-level grouping:
 *   1. Exact fingerprint match (same identity across tools/runs).
 *   2. Cross-tool correlation:
 *        - SCA: same purl+version+vulnId (already folded by the SCA fingerprint).
 *        - code: same file + overlapping location + shared CWE.
 */

export interface DedupResult {
  /** One representative RawFinding per group (highest severity/most complete). */
  representatives: RawFinding[];
  groups: DedupeGroup[];
  /** All findings keyed by group id, for persistence of members. */
  membersByGroup: Map<string, RawFinding[]>;
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/** Completeness score to pick the best representative within a group. */
function completeness(f: RawFinding): number {
  let s = SEVERITY_RANK[f.severity] * 10;
  if (f.cvssScore !== undefined) s += 5;
  if (f.description) s += Math.min(f.description.length / 100, 5);
  if (f.cwe.length) s += 2;
  if (f.references.length) s += 1;
  return s;
}

/** Correlation key for cross-tool grouping (coarser than fingerprint). */
function correlationKey(f: RawFinding): string {
  if (f.pillar === "sca" && f.package) {
    // Already collapses across SCA tools via purl+version+vulns.
    return `sca:${f.package.purl ?? f.package.name}:${f.package.version}:${[...f.vulnIds].sort().join(",")}`;
  }
  if (f.pillar === "dast" && f.target) {
    return `dast:${f.target.url}:${f.target.param ?? ""}:${f.ruleId}`;
  }
  // code: file + coarse line bucket + primary CWE (or ruleId when no CWE).
  const line = f.location?.startLine !== undefined ? Math.floor(f.location.startLine / 5) : "?";
  const cwe = f.cwe[0] ?? f.ruleId;
  return `code:${f.location?.path ?? "?"}:${line}:${cwe}`;
}

export function dedupe(findings: RawFinding[]): DedupResult {
  // First fold exact fingerprints (identity), then correlate the survivors.
  const byFingerprint = new Map<string, RawFinding[]>();
  for (const f of findings) {
    const arr = byFingerprint.get(f.fingerprint);
    if (arr) arr.push(f);
    else byFingerprint.set(f.fingerprint, [f]);
  }

  // Group fingerprint-representatives by correlation key.
  const byCorrelation = new Map<string, RawFinding[]>();
  for (const [, group] of byFingerprint) {
    const rep = group.reduce((a, b) => (completeness(b) > completeness(a) ? b : a));
    const key = correlationKey(rep);
    const arr = byCorrelation.get(key);
    if (arr) arr.push(...group);
    else byCorrelation.set(key, [...group]);
  }

  const representatives: RawFinding[] = [];
  const groups: DedupeGroup[] = [];
  const membersByGroup = new Map<string, RawFinding[]>();

  let i = 0;
  for (const [, members] of byCorrelation) {
    const rep = members.reduce((a, b) => (completeness(b) > completeness(a) ? b : a));
    const distinctTools = new Set(members.map((m) => m.tool));
    const groupId = `grp_${i++}_${rep.fingerprint.slice(0, 8)}`;
    const maxSev = members.reduce<Severity>((s, m) => maxSeverity(s, m.severity), "info");

    representatives.push({ ...rep, severity: maxSev });
    membersByGroup.set(groupId, members);
    groups.push({
      id: groupId,
      representativeFingerprint: rep.fingerprint,
      memberFingerprints: [...new Set(members.map((m) => m.fingerprint))],
      sourceCount: distinctTools.size,
      maxSeverity: maxSev,
    });
  }

  return { representatives, groups, membersByGroup };
}
