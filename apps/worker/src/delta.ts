import type { TenantClient } from "@auditer/db";
import { computeDelta, type DeltaFinding, type DeltaResult } from "@auditer/audit-engine";
import type { Severity, TriageStatus } from "@auditer/types";

/**
 * Worker-side half of the cross-run comparison: turn persisted rows into the
 * two snapshots `computeDelta` compares, and load the score history the
 * progression report plots.
 *
 * The comparison itself lives in @auditer/audit-engine (src/delta/index.ts),
 * not here. It is a pure function over findings and it belongs in the package
 * that already owns the pure functions — and the only one in this repo with a
 * test harness. The worker has none, and installing vitest in a deployable to
 * test a function that could live next to `computeScore` would be the wrong
 * trade. This module is the part that CANNOT be pure: it reads the database.
 *
 * Everything it needs already exists in the schema — `Finding.fingerprint`,
 * `firstSeenRunId`, `lastSeenRunId`, `triageStatus`. Nothing was added for the
 * report.
 */

export { computeDelta } from "@auditer/audit-engine";
export type { DeltaResult, DeltaEntry, DeltaFinding, SeverityMovement } from "@auditer/audit-engine";

/** One point of the score history the progression report draws. */
export interface HistoryPoint {
  runId: string;
  /** ISO date of the relevé. */
  at: string;
  riskScore: number | null;
  scoringVersion: string | null;
  critical: number;
  high: number;
  /** Open findings, all severities, triage applied. */
  open: number;
  /** True for the relevé this report is about. */
  isCurrent: boolean;
}

export interface ProgressContext {
  delta: DeltaResult;
  /** Oldest first, current last. Empty history is possible and is not an error. */
  history: HistoryPoint[];
  /** Pillars that produced a measurement in the current relevé. */
  measuredPillars: string[];
}

/** Terminal states that produced findings worth comparing against. */
const COMPARABLE = ["done", "completed_with_errors"] as const;

/**
 * A scan counts as a MEASUREMENT only when it ran to completion. `skipped` is
 * deliberately excluded: a relevance gate ("no lockfile, nothing to scan") is
 * indistinguishable here from a gate that fired wrongly, and treating it as
 * coverage would let a pillar's findings vanish into the "fixed" column. The
 * conservative reading costs a line of "non mesuré" in the report; the
 * permissive one manufactures progress.
 */
const MEASURED_SCAN_STATES = new Set(["success", "partial"]);

interface RunRef {
  id: string;
  repositoryId: string | null;
  targetId: string | null;
  createdAt: Date;
  finishedAt: Date | null;
  riskScore: number | null;
  scoringVersion: string | null;
}

/** The date that dates a relevé: when it finished, else when it was created. */
function runDate(r: { finishedAt: Date | null; createdAt: Date }): string {
  return (r.finishedAt ?? r.createdAt).toISOString();
}

function isOpen(t: TriageStatus): boolean {
  return t === "open";
}

/**
 * Builds the delta for `run` against the previous comparable relevé of the same
 * subject (same repository, or same target for a DAST/UX run), plus the score
 * history behind it.
 */
export async function loadProgress(
  tx: TenantClient,
  organizationId: string,
  run: RunRef,
  options: { historyLength?: number } = {},
): Promise<ProgressContext> {
  const historyLength = Math.max(2, options.historyLength ?? 6);

  // Same SUBJECT, not merely same organisation: comparing a relevé of one repo
  // against a relevé of another would produce a delta where every finding is
  // both new and fixed.
  const subject = run.repositoryId
    ? { repositoryId: run.repositoryId }
    : run.targetId
      ? { targetId: run.targetId }
      : {};

  const earlier = await tx.auditRun.findMany({
    where: {
      organizationId,
      ...subject,
      id: { not: run.id },
      status: { in: [...COMPARABLE] },
      createdAt: { lt: run.createdAt },
    },
    orderBy: { createdAt: "desc" },
    take: historyLength - 1,
    select: {
      id: true,
      repositoryId: true,
      targetId: true,
      createdAt: true,
      finishedAt: true,
      riskScore: true,
      scoringVersion: true,
    },
  });

  const previous = earlier[0] ?? null;
  const timeline: RunRef[] = [...earlier].reverse().concat([run]);

  const runIds = timeline.map((r) => r.id);
  const rows = await tx.finding.findMany({
    where: { organizationId, auditRunId: { in: runIds } },
    select: {
      auditRunId: true,
      fingerprint: true,
      severity: true,
      pillar: true,
      title: true,
      triageStatus: true,
      firstSeenRunId: true,
    },
  });

  // Age needs a DATE, and the column holds a run id. Resolve every referenced
  // run in one query — including runs older than the history window, which is
  // precisely the case where an age is interesting.
  const firstSeenIds = [
    ...new Set(rows.map((r) => r.firstSeenRunId).filter((id): id is string => Boolean(id))),
  ];
  const unknownIds = firstSeenIds.filter((id) => !runIds.includes(id));
  const firstSeenRuns = unknownIds.length
    ? await tx.auditRun.findMany({
        where: { organizationId, id: { in: unknownIds } },
        select: { id: true, createdAt: true, finishedAt: true },
      })
    : [];
  const dateByRunId = new Map<string, string>([
    ...timeline.map((r) => [r.id, runDate(r)] as const),
    ...firstSeenRuns.map((r) => [r.id, runDate(r)] as const),
  ]);

  const byRun = new Map<string, DeltaFinding[]>(runIds.map((id) => [id, []]));
  for (const r of rows) {
    byRun.get(r.auditRunId)?.push({
      fingerprint: r.fingerprint,
      severity: r.severity as Severity,
      pillar: r.pillar,
      title: r.title,
      triageStatus: r.triageStatus as TriageStatus,
      // Null when the finding predates the column being populated, or when the
      // run it points at has been purged by retention. The report then says
      // "âge inconnu" rather than showing a finding as brand new.
      firstSeenAt: r.firstSeenRunId ? (dateByRunId.get(r.firstSeenRunId) ?? null) : null,
    });
  }

  const scans = await tx.scan.findMany({
    where: { organizationId, auditRunId: run.id },
    select: { pillar: true, status: true },
  });
  const measuredPillars = [
    ...new Set(scans.filter((s) => MEASURED_SCAN_STATES.has(s.status)).map((s) => s.pillar)),
  ];

  const delta = computeDelta({
    current: {
      runId: run.id,
      at: runDate(run),
      findings: byRun.get(run.id) ?? [],
      measuredPillars,
    },
    previous: previous
      ? {
          runId: previous.id,
          at: runDate(previous),
          findings: byRun.get(previous.id) ?? [],
        }
      : null,
  });

  const history: HistoryPoint[] = timeline.map((r) => {
    const findings = byRun.get(r.id) ?? [];
    const open = findings.filter((f) => isOpen(f.triageStatus as TriageStatus));
    return {
      runId: r.id,
      at: runDate(r),
      riskScore: r.riskScore,
      scoringVersion: r.scoringVersion,
      critical: open.filter((f) => f.severity === "critical").length,
      high: open.filter((f) => f.severity === "high").length,
      open: open.length,
      isCurrent: r.id === run.id,
    };
  });

  return { delta, history, measuredPillars };
}
