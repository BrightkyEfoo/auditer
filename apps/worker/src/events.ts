import type { Redis } from "ioredis";
import { auditChannel } from "@auditer/queue";
import type { AuditEvent, AuditStatus, Pillar, ScanStatus } from "@auditer/types";

/** Distributive Omit so each union member keeps its own fields (plain Omit over
 *  a discriminated union collapses to only the shared keys). */
type WithoutSeq<T> = T extends unknown ? Omit<T, "seq"> : never;

/**
 * Publish live progress to Valkey pub/sub. The api's SSE controller subscribes
 * and relays. `seq` is a monotonic per-run counter (Redis INCR) so clients can
 * resume with Last-Event-ID after a dropped connection.
 */
export class EventPublisher {
  constructor(private readonly redis: Redis) {}

  private async nextSeq(auditRunId: string): Promise<number> {
    return this.redis.incr(`audit:${auditRunId}:seq`);
  }

  private async publish(auditRunId: string, evt: WithoutSeq<AuditEvent>): Promise<void> {
    const seq = await this.nextSeq(auditRunId);
    await this.redis.publish(auditChannel(auditRunId), JSON.stringify({ ...evt, seq }));
  }

  status(auditRunId: string, status: AuditStatus): Promise<void> {
    return this.publish(auditRunId, {
      type: "status",
      auditRunId,
      status,
      at: new Date().toISOString(),
    });
  }

  scan(
    auditRunId: string,
    pillar: Pillar,
    tool: string,
    status: ScanStatus,
    findingCount?: number,
  ): Promise<void> {
    return this.publish(auditRunId, {
      type: "scan",
      auditRunId,
      pillar,
      tool,
      status,
      findingCount,
      at: new Date().toISOString(),
    });
  }

  log(auditRunId: string, message: string): Promise<void> {
    return this.publish(auditRunId, {
      type: "log",
      auditRunId,
      message,
      at: new Date().toISOString(),
    });
  }

  done(auditRunId: string, status: AuditStatus, riskScore?: number): Promise<void> {
    return this.publish(auditRunId, {
      type: "done",
      auditRunId,
      status,
      riskScore,
      at: new Date().toISOString(),
    });
  }
}
