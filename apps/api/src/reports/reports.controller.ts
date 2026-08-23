import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  HttpCode,
  UseGuards,
  NotFoundException,
  Res,
} from "@nestjs/common";
import type { Response } from "express";
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

    // Report-render job — distinct jobId so BullMQ doesn't dedupe it against the
    // already-completed audit job for this run.
    await this.queue.enqueueAudit(
      {
        auditRunId: runId,
        organizationId: auth.organizationId,
        pillars: [],
        scopeConfig: { reportOnly: true, reportId: report.id, format: body.format },
      },
      `report-${report.id}`,
    );

    return { reportId: report.id };
  }

  @Get(":runId")
  async get(@Auth() auth: AuthContext, @Param("runId") runId: string) {
    const { report, artifact } = await this.resolve(auth, runId);

    return {
      id: report.id,
      status: report.status,
      summary: report.summary,
      contentType: artifact?.contentType ?? null,
      sizeBytes: artifact ? Number(artifact.sizeBytes) : null,
      // A same-origin API path, NOT a presigned object-storage URL. Presigning
      // signs the endpoint the api talks to — an internal container hostname in
      // this deployment — so the browser could never resolve it. Streaming
      // through the api also keeps the bucket private and re-checks the tenant
      // on every download instead of trusting a URL that has escaped.
      downloadPath: artifact ? `/api/reports/${runId}/download` : null,
    };
  }

  /**
   * Streams the rendered report to the browser. Deliberately not a redirect to
   * storage: the object stays unreachable from outside, and authorisation is
   * evaluated here, per request, against the caller's own organisation.
   */
  @Get(":runId/download")
  async download(
    @Auth() auth: AuthContext,
    @Param("runId") runId: string,
    @Res() res: Response,
  ): Promise<void> {
    const { artifact } = await this.resolve(auth, runId);
    if (!artifact) throw new NotFoundException("report not ready");

    const body = await getStorage().get(artifact.storageKey);
    // Falling back to a generic type rather than to text/html: an unknown blob
    // must download, never render.
    const contentType = artifact.contentType ?? "application/octet-stream";
    const ext = EXT_BY_TYPE[contentType] ?? "bin";
    const stamp = new Date().toISOString().slice(0, 10);

    res.setHeader("content-type", contentType);
    res.setHeader("content-length", String(body.byteLength));
    // `attachment` so the browser saves it rather than rendering AI-authored
    // HTML in our own origin — the report embeds model output, and rendering it
    // same-origin would turn any escaping mistake into stored XSS.
    res.setHeader(
      "content-disposition",
      `attachment; filename="auditer-releve-${runId.slice(0, 8)}-${stamp}.${ext}"`,
    );
    res.setHeader("cache-control", "private, no-store");
    res.send(body);
  }

  /** Latest report for a run + its stored artifact, both tenant-scoped. */
  private async resolve(auth: AuthContext, runId: string) {
    const report = await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.report.findFirst({
        where: { auditRunId: runId, organizationId: auth.organizationId },
        orderBy: { createdAt: "desc" },
      }),
    );
    if (!report) throw new NotFoundException("report not found");

    const artifact = report.pdfArtifactId
      ? await this.prisma.tenant(auth.organizationId, (tx) =>
          tx.artifact.findFirst({
            where: { id: report.pdfArtifactId!, organizationId: auth.organizationId },
          }),
        )
      : null;

    return { report, artifact };
  }
}

/** Download filename extension, driven by the stored content type. */
const EXT_BY_TYPE: Record<string, string> = {
  "text/html": "html",
  "application/pdf": "pdf",
  "application/json": "json",
};
