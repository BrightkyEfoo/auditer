import { Injectable, type OnModuleDestroy } from "@nestjs/common";
import { Queue } from "bullmq";
import { QUEUE_NAMES, createRedis, type AuditJob } from "@auditer/queue";

/**
 * BullMQ producer. `api` only ever ENQUEUES — never executes. The parent
 * `audit` job is picked up by the worker, which fans out to `scan` children and
 * then an `aggregate` job (BullMQ Flows, owned worker-side).
 */
@Injectable()
export class QueueService implements OnModuleDestroy {
  private readonly connection = createRedis();
  private readonly auditQueue = new Queue(QUEUE_NAMES.audit, {
    connection: this.connection,
    defaultJobOptions: {
      attempts: 3,
      backoff: { type: "exponential", delay: 5000 },
      removeOnComplete: 1000,
      removeOnFail: 5000,
    },
  });

  /**
   * Enqueue an audit or a report-render job. `jobId` defaults to the runId so a
   * duplicate audit trigger is idempotent — but a report re-render of an already
   * completed run must pass a distinct jobId (else BullMQ dedupes it against the
   * finished audit job and it never runs).
   */
  async enqueueAudit(job: AuditJob, jobId?: string): Promise<string> {
    const id = jobId ?? job.auditRunId;
    const added = await this.auditQueue.add("audit", job, { jobId: id });
    return added.id ?? id;
  }

  async onModuleDestroy(): Promise<void> {
    await this.auditQueue.close().catch(() => {});
    await this.connection.quit().catch(() => {});
  }
}
