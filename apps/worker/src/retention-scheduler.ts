import { Queue, Worker, DelayedError, type Job } from "bullmq";
import { createPrisma, type PrismaClient } from "@auditer/db";
import {
  createRedis,
  withLock,
  QUEUE_NAMES,
  RETENTION_CRON_DEFAULT,
  RETENTION_LOCK_KEY,
  RETENTION_SCHEDULER_ID,
  type RetentionPurgeJob,
} from "@auditer/queue";
import { runRetentionPurge, type PurgeLogger } from "@auditer/retention";

/**
 * The ordonnanceur the privacy policy used to admit it did not have.
 *
 * ─── WHY A BULLMQ JOB SCHEDULER, AND NOT SOMETHING ELSE ──────────────────
 *
 * The alternatives, and why each loses:
 *
 *   - `setInterval` in this process: dies with the process, and fires once PER
 *     REPLICA. Two workers would purge simultaneously; nothing coordinates them.
 *   - `@nestjs/schedule` in the api: same replica problem, plus it would put a
 *     multi-hour destructive job inside the process that serves user requests.
 *   - a cron container / host crontab: a fourth deployable and a second place
 *     to configure the database, for a job whose queue infrastructure is
 *     already running.
 *
 * BullMQ on Valkey is already the api↔worker transport, it is already
 * persistent (`valkey-server --appendonly yes` in the compose file), and it
 * gives the three properties this job needs:
 *
 *   1. SURVIVES RESTART. The schedule lives in Valkey, not in this process's
 *      memory. A worker redeploy at 03:29 does not skip the night.
 *   2. ONE SCHEDULER, N REPLICAS. `upsertJobScheduler` is keyed by id, so every
 *      replica booting with RETENTION_SCHEDULER_ID converges on the same
 *      scheduler row instead of adding one each.
 *   3. ONE CONSUMER PER JOB. Moving a job to `active` is a Lua script inside
 *      Redis — atomic by construction. Exactly one replica gets each nightly
 *      job, however many are listening.
 *
 * API NOTE — this is BullMQ 5.81.3 (checked in node_modules, not from memory).
 * The old repeatable API (`queue.add(name, data, { repeat: { pattern } })`) is
 * deprecated since 5.16 in favour of Job Schedulers and is slated for removal
 * in v6. `upsertJobScheduler` is the current call and the one used below; its
 * `repeatOpts` is the same `RepeatOptions` shape (`pattern`, `tz`, `limit`, …).
 *
 * ─── AND A THIRD BELT: THE VALKEY LOCK ───────────────────────────────────
 *
 * Points 2 and 3 above already give single execution for the SCHEDULED path.
 * The lock (packages/queue, `withLock`) exists for the paths BullMQ does not
 * cover: an operator POSTing to /api/admin/retention/purge at 03:30, a job
 * manually re-added, a stale scheduler from a previous id still producing jobs.
 * The api takes the same lock. And underneath all three, the purge is
 * idempotent — every predicate is a cutoff date — so a duplicate is harmless
 * rather than merely improbable.
 */

/** Deadlock ceiling on the lock, not an expected duration. */
const LOCK_TTL_MS = 6 * 60 * 60 * 1000;

/** How long to stand aside when the audit queue is busy. */
const DEFER_MS = 20 * 60 * 1000;

/**
 * After this long deferring, the purge runs anyway.
 *
 * A retention obligation is not negotiable against load: a host that always has
 * an audit in flight would otherwise never purge anything, and the published
 * durations would be false again — the exact defect this file closes. Two hours
 * of politeness, then the law wins, with a warning naming the reason.
 */
const MAX_DEFER_MS = 2 * 60 * 60 * 1000;

const log: PurgeLogger = {
  // eslint-disable-next-line no-console
  log: (m) => console.log(`[retention] ${m}`),
  // eslint-disable-next-line no-console
  warn: (m) => console.warn(`[retention] ${m}`),
};

/**
 * Simulation mode.
 *
 * Default is OFF — an ABSENT variable purges for real. That direction is
 * deliberate and it is the opposite of the usual fail-safe instinct: the defect
 * being fixed here is precisely "nothing runs unless someone remembers", and a
 * flag that must be remembered to make deletion happen would rebuild it. The
 * published policy must be true of a default deployment.
 *
 * To watch before deleting — which is the right thing to do on the first run
 * against a production database — set RETENTION_PURGE_DRY_RUN=1, deploy, read
 * the counters in the worker log the next morning, then remove the variable.
 * A dry run says so loudly on every execution; it cannot be mistaken for a
 * real one in the logs.
 */
function dryRunFromEnv(): boolean {
  const v = (process.env.RETENTION_PURGE_DRY_RUN ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes";
}

/**
 * Is the audit queue carrying work right now?
 *
 * `active` and `waiting` only. `delayed` is excluded on purpose: a retried job
 * scheduled for next week is not load, and counting it would defer the purge
 * every night until it fired.
 */
async function auditQueueBusy(auditQueue: Queue): Promise<number> {
  const counts = await auditQueue.getJobCounts("active", "wait", "prioritized");
  return (counts["active"] ?? 0) + (counts["wait"] ?? 0) + (counts["prioritized"] ?? 0);
}

export interface RetentionScheduler {
  close(): Promise<void>;
}

/**
 * Register the nightly schedule and start consuming it.
 *
 * Returns a handle the caller closes on SIGTERM. Safe to call on every replica
 * — that is the whole point of `upsertJobScheduler`.
 */
export function startRetentionScheduler(): RetentionScheduler {
  // Own connections, not the worker's: BullMQ blocks on one connection per
  // Worker (BRPOPLPUSH), and sharing the audit worker's would stall it.
  const schedulerConnection = createRedis();
  const workerConnection = createRedis();
  const lockRedis = createRedis();

  const maintenance = new Queue<RetentionPurgeJob>(QUEUE_NAMES.maintenance, {
    connection: schedulerConnection,
  });
  // Read-only handle on the audit queue, purely to measure load before purging.
  const audit = new Queue(QUEUE_NAMES.audit, { connection: schedulerConnection });

  // RLS-constrained connection for every deletion, and a separate owner-role
  // connection used for ONE cross-tenant SELECT. The privileged client is built
  // per execution and disconnected immediately after, so the worker does not
  // sit on an RLS-exempt connection for the 23 hours it is not purging.
  const prisma: PrismaClient = createPrisma();

  const cron = process.env.RETENTION_PURGE_CRON?.trim() || RETENTION_CRON_DEFAULT;

  // Upsert, not add: idempotent across replicas AND across deploys. Changing
  // the cron and redeploying updates the existing scheduler in place instead of
  // leaving the old cadence running beside the new one.
  void maintenance
    .upsertJobScheduler(
      RETENTION_SCHEDULER_ID,
      // tz pinned: without it BullMQ interprets the pattern in the container's
      // local zone, which would move the purge an hour twice a year on a host
      // that follows European DST.
      { pattern: cron, tz: "UTC" },
      {
        name: "retention-purge",
        data: {},
        opts: {
          // One retry, well after the failure. A purge that failed on a
          // transient S3 or Postgres error should get one more chance the same
          // night; more than that just repeats a real outage in the logs.
          attempts: 2,
          backoff: { type: "fixed", delay: 15 * 60 * 1000 },
          // Keep a month of outcomes: "did the purge run, and what did it say"
          // must be answerable from the queue as well as from the logs.
          removeOnComplete: { age: 30 * 24 * 3600, count: 60 },
          removeOnFail: { age: 90 * 24 * 3600 },
        },
      },
    )
    .then(() => {
      log.log(
        `scheduler "${RETENTION_SCHEDULER_ID}" registered — cron "${cron}" UTC` +
          (dryRunFromEnv() ? " (DRY RUN: nothing will be deleted)" : ""),
      );
    })
    .catch((err: unknown) => {
      // Not fatal to the worker: audits must keep running. But it IS the whole
      // point of this process's second job, so it is an error, not a warning.
      // eslint-disable-next-line no-console
      console.error(`[retention] failed to register scheduler: ${String(err)}`);
    });

  const worker = new Worker<RetentionPurgeJob>(
    QUEUE_NAMES.maintenance,
    async (job: Job<RetentionPurgeJob>, token?: string) => {
      // ── Stand aside while audits are in flight ──────────────────────────
      const busy = await auditQueueBusy(audit);
      const waited = Date.now() - job.timestamp;
      if (busy > 0 && waited < MAX_DEFER_MS) {
        // Deferral is stateless: `job.timestamp` is when the scheduler created
        // this job and does not move, so elapsed-since-creation IS the deferral
        // budget. No counter to persist, nothing to get out of sync.
        log.log(
          `audit queue busy (${busy} job(s)) — deferring the purge ${DEFER_MS / 60000} min ` +
            `(${Math.round(waited / 60000)} min waited so far)`,
        );
        await job.moveToDelayed(Date.now() + DEFER_MS, token);
        // The documented BullMQ signal for "I moved this job myself, do not
        // treat the handler's return as completion".
        throw new DelayedError();
      }
      if (busy > 0) {
        log.warn(
          `audit queue still busy (${busy} job(s)) after ${Math.round(waited / 60000)} min — ` +
            "purging anyway: the published retention durations do not wait on load",
        );
      }

      const dryRun = job.data.dryRun ?? dryRunFromEnv();

      // Owner-role client, opened for this run only.
      const privileged = createPrisma({ privileged: true });
      try {
        const outcome = await withLock(lockRedis, RETENTION_LOCK_KEY, LOCK_TTL_MS, () =>
          runRetentionPurge({
            prisma,
            privileged,
            dryRun,
            logger: log,
            trigger: "worker:scheduler",
          }),
        );

        if (!outcome.acquired) {
          // Someone else holds it — the admin endpoint, most likely. Not a
          // failure: the work is being done, just not by us.
          log.warn("purge skipped: the lock is held by another purge already running");
          return { skipped: "locked" };
        }
        return outcome.result;
      } finally {
        await privileged.$disconnect().catch(() => {});
      }
    },
    {
      connection: workerConnection,
      // One at a time, and on its OWN queue: the purge can never take a slot
      // from an audit, and two purges can never overlap in this process.
      concurrency: 1,
      // The purge holds no BullMQ lock renewal loop of its own; give it room to
      // run long on a large database before BullMQ declares it stalled.
      lockDuration: 30 * 60 * 1000,
    },
  );

  worker.on("failed", (job, err) => {
    // A silent failed purge is the same defect as no purge at all.
    // eslint-disable-next-line no-console
    console.error(`[retention] purge job ${job?.id} failed: ${err.message}`);
  });

  return {
    async close(): Promise<void> {
      await worker.close();
      await maintenance.close().catch(() => {});
      await audit.close().catch(() => {});
      await Promise.allSettled([
        prisma.$disconnect(),
        lockRedis.quit(),
        schedulerConnection.quit(),
        workerConnection.quit(),
      ]);
    },
  };
}
