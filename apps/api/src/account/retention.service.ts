import { Injectable, Logger, type OnModuleDestroy } from "@nestjs/common";
import {
  RETENTION,
  runRetentionPurge,
  type PurgeReport,
} from "@auditer/retention";
import { createRedis, withLock, RETENTION_LOCK_KEY } from "@auditer/queue";
import type { Redis } from "ioredis";
import { PrismaService } from "../infra/prisma.service.js";

/**
 * Retention purge, api side.
 *
 * The logic itself no longer lives here — it moved to @auditer/retention so the
 * WORKER can run it on a schedule without an internal HTTP call (see
 * apps/worker/src/retention-scheduler.ts, and packages/retention/src/purge.ts
 * for why that shape was chosen). What remains is the Nest adapter: the two
 * Prisma connections the purge needs, the api's Logger, and the same Valkey
 * lock the scheduler takes.
 *
 * The endpoint is kept, and it is not vestigial: the privacy policy promises a
 * purge "sous 30 jours" on request, and an operator answering such a request
 * must not have to wait for 03:30 UTC. It runs the exact same function the
 * scheduler runs, which is what makes the two promises one promise.
 */

/** Re-exported so `import { RETENTION } from "./retention.service.js"` still resolves. */
export { RETENTION };
export type { PurgeReport };

/**
 * Ceiling, not a budget. A manual purge on a large database can legitimately
 * run for a long while; two hours is well past anything observed and still
 * bounded enough that a killed api does not block tonight's scheduled run.
 */
const LOCK_TTL_MS = 2 * 60 * 60 * 1000;

@Injectable()
export class RetentionService implements OnModuleDestroy {
  private readonly logger = new Logger("retention");
  private readonly redis: Redis = createRedis();

  constructor(private readonly prisma: PrismaService) {}

  async onModuleDestroy(): Promise<void> {
    await this.redis.quit().catch(() => {});
  }

  /**
   * Apply every published duration, across every organization.
   *
   * Returns `null` when the lock is already held — by the nightly scheduler, or
   * by a second operator hitting the endpoint twice. The caller turns that into
   * a 409 rather than silently reporting zeros, which would read like "nothing
   * to purge" when the truth is "someone else is purging".
   */
  async purge(opts: { dryRun?: boolean } = {}): Promise<PurgeReport | null> {
    const outcome = await withLock(this.redis, RETENTION_LOCK_KEY, LOCK_TTL_MS, () =>
      runRetentionPurge({
        prisma: this.prisma,
        // Owner-role connection, for the one query that cannot be tenant-scoped:
        // enumerating the organizations. See PurgeOptions.privileged.
        privileged: this.prisma.privileged,
        dryRun: opts.dryRun,
        logger: this.logger,
        trigger: "api:admin-endpoint",
      }),
    );

    if (!outcome.acquired) {
      this.logger.warn(
        "manual retention purge refused: the lock is held (nightly scheduler, or another operator)",
      );
      return null;
    }
    return outcome.result;
  }
}
