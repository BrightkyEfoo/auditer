import { Controller, Get, UseGuards } from "@nestjs/common";
import type { AuditStatus } from "@auditer/types";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { PrismaService } from "../infra/prisma.service.js";

/**
 * Runs that produced a usable score. `failed` and `canceled` never got far
 * enough to score, and averaging their absent riskScore would drag the number
 * toward whatever the DB happens to store for "nothing".
 */
const SCORED_STATUSES: AuditStatus[] = ["done", "completed_with_errors"];

/** Points on the sparkline. Small on purpose — it is a shape, not a report. */
const TREND_POINTS = 12;

/**
 * Dashboard KPIs in one request. The home screen used to assemble this from
 * four separate endpoints, which meant four auth round-trips and a layout that
 * settled in stages.
 */
@Controller("api/overview")
@UseGuards(AuthGuard)
export class OverviewController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  async get(@Auth() auth: AuthContext) {
    const organizationId = auth.organizationId;

    // Sequential inside the tenant transaction: an interactive tx runs on a
    // single connection, so fanning out with Promise.all buys nothing and only
    // makes the failure modes harder to read.
    return this.prisma.tenant(organizationId, async (tx) => {
      const repos = await tx.repository.count({
        where: { organizationId, isActive: true },
      });

      const runs = await tx.auditRun.count({ where: { organizationId } });

      const lastRun = await tx.auditRun.findFirst({
        where: { organizationId },
        orderBy: { createdAt: "desc" },
        select: {
          id: true,
          status: true,
          riskScore: true,
          createdAt: true,
          repository: { select: { fullName: true } },
        },
      });

      // ── Open critical/high, counted ONCE per repository ──────────────────
      //
      // Two steps on purpose. The counts must come from each repository's most
      // recent run only: a defect that survives ten re-scans exists once, but a
      // naive count over every historical run reports it ten times and the KPI
      // grows just by scanning more often.
      //
      // Step 1 picks the newest run per repository (Postgres DISTINCT ON via
      // Prisma's `distinct` + matching orderBy). Doing this as a correlated
      // subquery in one statement would need raw SQL and would bypass the typed
      // client for no measurable gain at this size.
      //
      // NOT covered: target-only runs (DAST/UX with no repository) have nothing
      // to group by and are excluded — their findings do not reach these two
      // numbers.
      const latestPerRepo = await tx.auditRun.findMany({
        where: { organizationId, repositoryId: { not: null } },
        orderBy: [{ repositoryId: "asc" }, { createdAt: "desc" }],
        distinct: ["repositoryId"],
        select: { id: true },
      });

      let openCritical = 0;
      let openHigh = 0;
      if (latestPerRepo.length > 0) {
        // Step 2: one grouped count over exactly those runs.
        const open = await tx.finding.groupBy({
          by: ["severity"],
          where: {
            organizationId,
            auditRunId: { in: latestPerRepo.map((run) => run.id) },
            triageStatus: "open",
            severity: { in: ["critical", "high"] },
          },
          _count: { _all: true },
        });
        for (const row of open) {
          if (row.severity === "critical") openCritical = row._count._all;
          else if (row.severity === "high") openHigh = row._count._all;
        }
      }

      const scored = await tx.auditRun.aggregate({
        where: { organizationId, status: { in: SCORED_STATUSES } },
        _avg: { riskScore: true },
      });
      // null, not 0: an org that has never finished a run has no average, and
      // 0 would render as the worst possible posture.
      const avgScore =
        scored._avg.riskScore === null ? null : Math.round(scored._avg.riskScore);

      const recent = await tx.auditRun.findMany({
        where: { organizationId, status: { in: SCORED_STATUSES }, riskScore: { not: null } },
        orderBy: { createdAt: "desc" },
        take: TREND_POINTS,
        select: { id: true, createdAt: true, riskScore: true },
      });
      // Newest-first is how we page; oldest-first is how a chart reads. flatMap
      // (not map) so the riskScore narrows to number without an assertion the
      // `not: null` filter already guarantees.
      const trend = recent
        .reverse()
        .flatMap((run) =>
          run.riskScore === null
            ? []
            : [{ runId: run.id, createdAt: run.createdAt, riskScore: run.riskScore }],
        );

      return { repos, runs, lastRun, openCritical, openHigh, avgScore, trend };
    });
  }
}
