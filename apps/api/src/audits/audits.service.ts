import {
  Injectable,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from "@nestjs/common";
import type { Pillar } from "@auditer/types";
import { cancelFlag } from "@auditer/queue";
import { PrismaService } from "../infra/prisma.service.js";
import { QueueService } from "../infra/queue.service.js";
import { RedisService } from "../infra/redis.service.js";
import type { AuthContext } from "../auth/auth.guard.js";

export interface CreateAuditInput {
  repositoryId?: string;
  targetId?: string;
  ref?: string;
  pillars: Pillar[];
}

/** Pillars that require a network-reachable, ownership-verified target. */
const NETWORK_PILLARS: ReadonlySet<Pillar> = new Set(["dast", "ux"]);

@Injectable()
export class AuditsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly queue: QueueService,
    private readonly redis: RedisService,
  ) {}

  /**
   * Queue an audit run. Returns immediately with a runId — the request path does
   * NO scanning. Enforces DAST/UX ownership verification in the data model
   * before anything is queued.
   */
  async create(auth: AuthContext, input: CreateAuditInput): Promise<{ runId: string; status: string }> {
    if (!input.repositoryId && !input.targetId) {
      throw new BadRequestException("repositoryId or targetId is required");
    }

    const needsTarget = input.pillars.some((p) => NETWORK_PILLARS.has(p));

    return this.prisma.tenant(auth.organizationId, async (tx) => {
      // Validate the repo/target belongs to the org (RLS also enforces this).
      if (input.repositoryId) {
        const repo = await tx.repository.findFirst({
          where: { id: input.repositoryId, organizationId: auth.organizationId },
        });
        if (!repo) throw new NotFoundException("repository not found");
      }

      if (needsTarget) {
        if (!input.targetId) {
          throw new BadRequestException("DAST/UX pillars require a targetId");
        }
        const target = await tx.target.findFirst({
          where: { id: input.targetId, organizationId: auth.organizationId },
        });
        if (!target) throw new NotFoundException("target not found");
        // HARD GATE: no active network scan without verified ownership.
        if (target.verificationStatus !== "verified") {
          throw new ForbiddenException(
            "target ownership is not verified — verify the domain before scanning",
          );
        }
      }

      const run = await tx.auditRun.create({
        data: {
          organizationId: auth.organizationId,
          repositoryId: input.repositoryId,
          targetId: input.targetId,
          ref: input.ref,
          pillars: input.pillars,
          status: "queued",
          trigger: "manual",
          createdById: auth.userId,
        },
      });

      await this.queue.enqueueAudit({
        auditRunId: run.id,
        organizationId: auth.organizationId,
        repositoryId: input.repositoryId,
        targetId: input.targetId,
        ref: input.ref,
        pillars: input.pillars,
      });

      return { runId: run.id, status: run.status };
    });
  }

  async get(auth: AuthContext, id: string) {
    const run = await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.auditRun.findFirst({ where: { id, organizationId: auth.organizationId } }),
    );
    if (!run) throw new NotFoundException("audit run not found");
    return run;
  }

  async listFindings(
    auth: AuthContext,
    id: string,
    filter: { pillar?: Pillar; severity?: string; triage?: string },
  ) {
    return this.prisma.tenant(auth.organizationId, (tx) =>
      tx.finding.findMany({
        where: {
          auditRunId: id,
          organizationId: auth.organizationId,
          ...(filter.pillar ? { pillar: filter.pillar } : {}),
          ...(filter.severity ? { severity: filter.severity as never } : {}),
          ...(filter.triage ? { triageStatus: filter.triage as never } : {}),
        },
        orderBy: [{ severity: "asc" }, { aiPriority: "desc" }],
      }),
    );
  }

  /** Cancel = flip a Redis flag the worker polls between scans. */
  async cancel(auth: AuthContext, id: string): Promise<{ ok: boolean }> {
    await this.get(auth, id); // authorize + existence
    await this.redis.client.set(cancelFlag(id), "1", "EX", 3600);
    return { ok: true };
  }
}
