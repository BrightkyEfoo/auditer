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
  // Housekeeping that is not an audit: today, the nightly retention purge.
  // A SEPARATE queue on purpose — a purge sharing the `audit` queue would eat
  // one of the worker's audit slots for as long as it runs, which is exactly
  // what "la purge ne doit jamais bloquer un audit" forbids.
  maintenance: "maintenance",
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

/**
 * Maintenance job: apply the retention durations published in
 * apps/web/lib/legal.ts. Produced by the BullMQ Job Scheduler registered at
 * worker boot (apps/worker/src/retention-scheduler.ts), never by the api.
 *
 * The payload is empty by design: everything the purge needs is a cutoff
 * computed from the wall clock at execution time. Putting a date in the job
 * would freeze it at SCHEDULING time, and a job deferred by a busy audit queue
 * would then purge against a stale cutoff.
 */
export interface RetentionPurgeJob {
  /** Simulation: count what would go, delete nothing. */
  dryRun?: boolean;
}

/**
 * Identity of the daily retention scheduler.
 *
 * BullMQ keys a Job Scheduler by this id. Every worker replica upserts the SAME
 * id at boot, so N replicas converge on ONE scheduler instead of creating N —
 * this is the first of the three guarantees that one purge runs per night (see
 * apps/worker/src/retention-scheduler.ts for the other two).
 *
 * Changing this string orphans the existing scheduler in Valkey; it would keep
 * producing jobs under the old id. Rename only together with a
 * `removeJobScheduler` of the previous value.
 */
export const RETENTION_SCHEDULER_ID = "retention-purge-daily";

/**
 * 03:30 UTC = 04:30 in Douala (WAT, UTC+1) and 04:30/05:30 in France.
 * A quiet hour on both, and deliberately NOT on the hour: a cron at 00:00 or
 * 03:00 collides with every other cron on the host.
 *
 * UTC is pinned explicitly at the call site so the cadence does not shift twice
 * a year with European DST.
 */
export const RETENTION_CRON_DEFAULT = "30 3 * * *";

export interface JobMap {
  audit: AuditJob;
  scan: ScanJob;
  aggregate: AggregateJob;
  maintenance: RetentionPurgeJob;
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

/**
 * Mutual-exclusion key for the retention purge, held for the duration of one
 * execution. Declared here rather than in the worker because the api's manual
 * endpoint takes the same lock: an operator running the purge by hand at 03:30
 * must not race the scheduled one.
 */
export const RETENTION_LOCK_KEY = "retention:purge:lock";

/**
 * Run `fn` while holding an exclusive Valkey lock, or don't run it at all.
 *
 * `SET key token NX PX ttl` is a single atomic command: exactly one caller gets
 * the key, every other one gets null and returns `{ acquired: false }` without
 * waiting. Waiting would be wrong here — a purge that queued up behind another
 * purge would simply run the same idempotent sweep twice.
 *
 * Release is a compare-and-delete in Lua, not a plain DEL: if this holder
 * overran the TTL, the key now belongs to someone else and deleting it would
 * hand a third caller a lock two processes believe they hold.
 *
 * The TTL is a deadlock ceiling, not a duration budget: a worker killed mid
 * purge must not block every subsequent night. Past it the lock lapses; that is
 * acceptable because the purge is idempotent and BullMQ already delivers each
 * scheduled job to exactly one consumer — this lock is the second belt, not the
 * first.
 */
export async function withLock<T>(
  redis: Redis,
  key: string,
  ttlMs: number,
  fn: () => Promise<T>,
): Promise<{ acquired: true; result: T } | { acquired: false; result?: undefined }> {
  const token = `${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const ok = await redis.set(key, token, "PX", ttlMs, "NX");
  if (ok !== "OK") return { acquired: false };

  try {
    return { acquired: true, result: await fn() };
  } finally {
    await redis
      .eval(
        "if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end",
        1,
        key,
        token,
      )
      .catch(() => {
        /* lock lapses on its own TTL; losing the release is not worth failing a purge */
      });
  }
}
