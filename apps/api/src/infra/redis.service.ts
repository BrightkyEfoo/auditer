import { Injectable, type OnModuleDestroy } from "@nestjs/common";
import { createRedis } from "@auditer/queue";
import type { Redis } from "ioredis";

/**
 * Two Valkey connections: one general client (cancel flags, snapshots) and one
 * dedicated subscriber (SSE relay — a subscribed connection cannot issue normal
 * commands, so it must be separate).
 */
@Injectable()
export class RedisService implements OnModuleDestroy {
  readonly client: Redis = createRedis();

  /** A fresh subscriber connection (caller owns its lifecycle). */
  subscriber(): Redis {
    return createRedis();
  }

  async onModuleDestroy(): Promise<void> {
    await this.client.quit().catch(() => {});
  }
}
