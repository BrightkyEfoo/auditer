import {
  Injectable,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from "@nestjs/common";
import type { Pillar, Severity } from "@auditer/types";
import { cancelFlag } from "@auditer/queue";
import { PrismaService } from "../infra/prisma.service.js";
import { QueueService } from "../infra/queue.service.js";
import { RedisService } from "../infra/redis.service.js";
import { dropObjects } from "../common/artifact-purge.js";
import type { AuthContext } from "../auth/auth.guard.js";

export interface CreateAuditInput {
  repositoryId?: string;
  targetId?: string;
  ref?: string;
  pillars: Pillar[];
}

/** Pillars that require a network-reachable, ownership-verified target. */
const NETWORK_PILLARS: ReadonlySet<Pillar> = new Set(["dast", "ux"]);

/** Page size of the run list. Deliberately fixed — no client-controlled take. */
const LIST_LIMIT = 50;

/** Severity histogram of a run. Always all five keys, always a number. */
export type SeverityCounts = Record<Severity, number>;

function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

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

  /**
   * Recent runs for the org, with their severity histogram.
   *
   * Capped at 50 — this feeds a dashboard list, not an export, and an org with
   * a webhook on a busy repo accumulates runs faster than anyone reads them.
   */
  async list(auth: AuthContext) {
    return this.prisma.tenant(auth.organizationId, async (tx) => {
      const runs = await tx.auditRun.findMany({
        where: { organizationId: auth.organizationId },
        orderBy: { createdAt: "desc" },
        take: LIST_LIMIT,
        select: {
          id: true,
          status: true,
          pillars: true,
          riskScore: true,
          scoringVersion: true,
          createdAt: true,
          finishedAt: true,
          repository: { select: { id: true, fullName: true, provider: true } },
        },
      });
      if (runs.length === 0) return [];

      // ONE groupBy for the whole page. Counting per run would be 50 extra
      // round-trips (N+1) to render what is, on screen, five little badges.
      const grouped = await tx.finding.groupBy({
        by: ["auditRunId", "severity"],
        where: {
          organizationId: auth.organizationId,
          auditRunId: { in: runs.map((r) => r.id) },
        },
        _count: { _all: true },
      });

      const counts = new Map<string, SeverityCounts>();
      for (const row of grouped) {
        const bucket = counts.get(row.auditRunId) ?? emptyCounts();
        bucket[row.severity] = row._count._all;
        counts.set(row.auditRunId, bucket);
      }

      // Zero-fill: a run with no criticals must still report `critical: 0`, so
      // the UI never has to distinguish "none" from "not loaded".
      return runs.map((run) => ({ ...run, counts: counts.get(run.id) ?? emptyCounts() }));
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

  /**
   * Delete a run and everything it produced: scans, findings, pillar results,
   * reports and artifacts (rows via cascade, bytes explicitly).
   *
   * The cancel flag is raised FIRST and that ordering is load-bearing. A run
   * still on the worker keeps writing findings against `auditRunId`; if the row
   * disappears underneath it, the insert fails on the foreign key and BullMQ
   * retries the job forever. Cancelling first makes the worker stop at its next
   * poll, so the user's deletion does not become an ops incident.
   *
   * Triage decisions are NOT deleted: they are keyed on the fingerprint and
   * scoped to the organization, not to the run, precisely so a false-positive
   * call survives re-scans. Deleting a run must not silently un-triage the next
   * one. They go with the account, or with an explicit triage change.
   */
  async remove(auth: AuthContext, id: string): Promise<void> {
    await this.get(auth, id); // authorize + existence

    await this.redis.client.set(cancelFlag(id), "1", "EX", 3600);

    const keys = await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.artifact.findMany({
        where: { auditRunId: id, organizationId: auth.organizationId },
        select: { storageKey: true },
      }),
    );
    await dropObjects(keys.map((k) => k.storageKey));

    await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.auditRun.deleteMany({ where: { id, organizationId: auth.organizationId } }),
    );
  }
}
