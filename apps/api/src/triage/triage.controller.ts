import { Controller, Post, Body, HttpCode, UseGuards } from "@nestjs/common";
import { z } from "zod";
import { TriageStatus } from "@auditer/types";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { PrismaService } from "../infra/prisma.service.js";
import { ZodBody } from "../common/zod.pipe.js";

const SetTriageBody = z.object({
  fingerprint: z.string(),
  status: TriageStatus,
  reason: z.string().optional(),
});

/**
 * Triage is keyed on `fingerprint`, org-scoped, and PERSISTS ACROSS RUNS — so a
 * false-positive decision survives re-scans and refactors. Upsert into
 * TriageState; the finding rows themselves reflect it at read time.
 */
@Controller("api/triage")
@UseGuards(AuthGuard)
export class TriageController {
  constructor(private readonly prisma: PrismaService) {}

  @Post()
  @HttpCode(200)
  async set(
    @Auth() auth: AuthContext,
    @Body(new ZodBody(SetTriageBody)) body: z.infer<typeof SetTriageBody>,
  ): Promise<{ ok: boolean }> {
    await this.prisma.tenant(auth.organizationId, async (tx) => {
      // Canonical triage store (keyed on fingerprint, persists across runs).
      await tx.triageState.upsert({
        where: {
          organizationId_fingerprint: {
            organizationId: auth.organizationId,
            fingerprint: body.fingerprint,
          },
        },
        create: {
          organizationId: auth.organizationId,
          fingerprint: body.fingerprint,
          status: body.status,
          reason: body.reason,
          updatedById: auth.userId,
        },
        update: {
          status: body.status,
          reason: body.reason,
          updatedById: auth.userId,
        },
      });
      // Keep the denormalized snapshot on existing findings in sync so reads and
      // scoring see the decision immediately (across every run in this org).
      await tx.finding.updateMany({
        where: { organizationId: auth.organizationId, fingerprint: body.fingerprint },
        data: { triageStatus: body.status },
      });
    });
    return { ok: true };
  }
}
