import type { Pillar } from "@auditer/types";
import { Redis } from "ioredis";

/**
 * The api↔worker contract. `api` produces jobs, `worker` consumes them. Payload
 * shapes live here as the single typed source so the two deployables can never
 * drift. Uses BullMQ Flows: an `audit` parent job fans out to N `scan` child
 * jobs, then an `aggregate` job runs the AI pass + scoring + report.
 */

export const QUEUE_NAMES = {
  audit: "audit", // parent: clone + plan + fan-out
  scan: "scan", // child: one sandboxed scanner run
  aggregate: "aggregate", // dedup + AI enrichment + score + report
} as const;
export type QueueName = (typeof QUEUE_NAMES)[keyof typeof QUEUE_NAMES];

/** Parent job: kick off an audit run. */
export interface AuditJob {
  auditRunId: string;
  organizationId: string;
  repositoryId?: string;
  targetId?: string;
  commitSha?: string;
  ref?: string;
  pillars: Pillar[];
  scopeConfig?: Record<string, unknown>;
}

/** Child job: run one scanner (adapter) in a sandbox. */
export interface ScanJob {
  auditRunId: string;
  organizationId: string;
  scannerId: string; // adapter id, e.g. "gitleaks", "osv-scanner"
  pillar: Pillar;
  /** Path (inside the worker) to the prepared, read-only repo workspace. */
  workspaceRef: string;
  /** For DAST/UX: the verified target descriptor. */
  targetRef?: string;
}

/** Aggregate job: everything after all scans complete. */
export interface AggregateJob {
  auditRunId: string;
  organizationId: string;
}

export interface JobMap {
  audit: AuditJob;
  scan: ScanJob;
  aggregate: AggregateJob;
}

/** Redis/Valkey connection tuned for BullMQ (blocking commands need this). */
export function createRedis(url = process.env.REDIS_URL ?? "redis://localhost:6379"): Redis {
  return new Redis(url, { maxRetriesPerRequest: null });
}

/** Pub/sub channel for live SSE progress of a run. */
export function auditChannel(auditRunId: string): string {
  return `audit:${auditRunId}:events`;
}

/** Cancellation flag key — a POST /cancel flips this; the worker polls it. */
export function cancelFlag(auditRunId: string): string {
  return `audit:${auditRunId}:cancel`;
}
