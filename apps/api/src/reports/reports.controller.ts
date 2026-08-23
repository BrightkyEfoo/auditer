import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  HttpCode,
  UseGuards,
  NotFoundException,
} from "@nestjs/common";
import { z } from "zod";
import { getStorage } from "@auditer/storage";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { PrismaService } from "../infra/prisma.service.js";
import { QueueService } from "../infra/queue.service.js";
import { ZodBody } from "../common/zod.pipe.js";

const ExportBody = z.object({ format: z.enum(["pdf", "html"]).default("pdf") });

/**
 * Report export. The actual render (Paged.js in a Playwright container) runs on
 * the worker; this endpoint creates a Report row and re-enqueues an aggregate/
 * report job. GET returns the row + a presigned download URL once ready.
 */
@Controller("api/reports")
@UseGuards(AuthGuard)
export class ReportsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly queue: QueueService,
  ) {}

  @Post(":runId/export")
  @HttpCode(202)
  async export(
    @Auth() auth: AuthContext,
    @Param("runId") runId: string,
    @Body(new ZodBody(ExportBody)) body: z.infer<typeof ExportBody>,
  ): Promise<{ reportId: string }> {
    const report = await this.prisma.tenant(auth.organizationId, async (tx) => {
      const run = await tx.auditRun.findFirst({
        where: { id: runId, organizationId: auth.organizationId },
      });
      if (!run) throw new NotFoundException("audit run not found");
      return tx.report.create({
        data: {
          organizationId: auth.organizationId,
          auditRunId: runId,
          format: body.format,
          status: "queued",
        },
      });
    });

    // Re-run the aggregate pipeline in report-only mode to render the artifact.
    await this.queue.enqueueAudit({
      auditRunId: runId,
      organizationId: auth.organizationId,
      pillars: [],
      scopeConfig: { reportOnly: true, reportId: report.id, format: body.format },
    });

    return { reportId: report.id };
  }

  @Get(":runId")
  async get(@Auth() auth: AuthContext, @Param("runId") runId: string) {
    const report = await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.report.findFirst({
        where: { auditRunId: runId, organizationId: auth.organizationId },
        orderBy: { createdAt: "desc" },
      }),
    );
    if (!report) throw new NotFoundException("report not found");

    let downloadUrl: string | null = null;
    if (report.pdfArtifactId) {
      const artifact = await this.prisma.tenant(auth.organizationId, (tx) =>
        tx.artifact.findFirst({
          where: { id: report.pdfArtifactId!, organizationId: auth.organizationId },
        }),
      );
      if (artifact) downloadUrl = await getStorage().presignGet(artifact.storageKey);
    }

    return {
      id: report.id,
      status: report.status,
      downloadUrl,
      summary: report.summary,
    };
  }
}
