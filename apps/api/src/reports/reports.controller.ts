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
import { DEFAULT_REPORT_DOCUMENT, ReportDocument, normalizeReportDocument } from "@auditer/types";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { PrismaService } from "../infra/prisma.service.js";
import { QueueService } from "../infra/queue.service.js";
import { ZodBody } from "../common/zod.pipe.js";

/**
 * `format` names the DELIVERABLE, not the file type. One mission produces four
 * documents — the technical relevé, the two-page executive note, the one-page
 * signed attestation and the progression report — because the five readers of
 * an audit do not read the same thing (NIST SP 800-115: "a report may have
 * multiple audiences, multiple report formats may be required").
 *
 * The legacy container names `html` and `pdf` are still accepted and resolve to
 * the technical relevé, which is what they used to produce: apps/web posts
 * `{ format: "html" }` today, and breaking a live caller to tidy a vocabulary
 * is not a trade worth making. `normalizeReportDocument` owns that mapping so
 * the api and the worker cannot disagree about it.
 */
const ExportBody = z.object({
  format: z
    .string()
    .default(DEFAULT_REPORT_DOCUMENT)
    .transform((v) => normalizeReportDocument(v))
    .refine((v): v is ReportDocument => v !== null, {
      message: `format must be one of ${ReportDocument.options.join(", ")} (or the legacy html/pdf)`,
    }),
});

/**
 * The container the rendered document is stored in, which is NOT the document.
 * Every deliverable is HTML today; the paged PDF renderer changes this one
 * value and nothing else. Storing the deliverable name here instead would make
 * the row lie about its own content type.
 */
const STORED_CONTAINER = "html" as const;

/**
 * Report export. The actual render runs on the worker; this endpoint creates a
 * Report row and re-enqueues a report-only job. GET returns the row + the
 * download path once ready.
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
  ): Promise<{ reportId: string; document: z.infer<typeof ReportDocument> }> {
    const report = await this.prisma.tenant(auth.organizationId, async (tx) => {
      const run = await tx.auditRun.findFirst({
        where: { id: runId, organizationId: auth.organizationId },
      });
      if (!run) throw new NotFoundException("audit run not found");
      return tx.report.create({
        data: {
          organizationId: auth.organizationId,
          auditRunId: runId,
          // The container, not the deliverable — see STORED_CONTAINER.
          format: STORED_CONTAINER,
          status: "queued",
        },
      });
    });

    // Report-render job — distinct jobId so BullMQ doesn't dedupe it against the
    // already-completed audit job for this run. The jobId carries the report id,
    // which is per-export, so requesting the attestation right after the
    // executive note enqueues two jobs rather than silently collapsing into one.
    await this.queue.enqueueAudit(
      {
        auditRunId: runId,
        organizationId: auth.organizationId,
        pillars: [],
        scopeConfig: { reportOnly: true, reportId: report.id, format: body.format },
      },
      `report-${report.id}`,
    );

    return { reportId: report.id, document: body.format };
  }

  @Get(":runId")
  async get(@Auth() auth: AuthContext, @Param("runId") runId: string) {
    const { report, artifact } = await this.resolve(auth, runId);

    return {
      id: report.id,
      status: report.status,
      summary: report.summary,
      /** Which of the four deliverables this artifact is. */
      document: artifact ? documentFromKey(artifact.storageKey) : null,
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
    // The saved file names its deliverable. A client who exported the four
    // documents of one mission otherwise ends up with four files called
    // `auditer-releve-…` and no way to tell the attestation they can circulate
    // from the technical report they must not.
    const document = documentFromKey(artifact.storageKey);

    res.setHeader("content-type", contentType);
    res.setHeader("content-length", String(body.byteLength));
    // `attachment` so the browser saves it rather than rendering AI-authored
    // HTML in our own origin — the report embeds model output, and rendering it
    // same-origin would turn any escaping mistake into stored XSS.
    res.setHeader(
      "content-disposition",
      `attachment; filename="auditer-${document}-${runId.slice(0, 8)}-${stamp}.${ext}"`,
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

/**
 * Reads the deliverable back out of the object key the worker wrote
 * (`<org>/<run>/report/<uuid>.<document>.html`, see apps/worker/src/main.ts).
 *
 * A key without that segment predates the four documents and is the technical
 * relevé — which is what those exports actually contained. Falling back rather
 * than throwing matters here: an old artifact must stay downloadable.
 */
function documentFromKey(storageKey: string): z.infer<typeof ReportDocument> {
  const m = /\.([a-z]+)\.[a-z0-9]+$/i.exec(storageKey);
  return (m ? normalizeReportDocument(m[1]) : null) ?? DEFAULT_REPORT_DOCUMENT;
}

/** Download filename extension, driven by the stored content type. */
const EXT_BY_TYPE: Record<string, string> = {
  "text/html": "html",
  "application/pdf": "pdf",
  "application/json": "json",
};
