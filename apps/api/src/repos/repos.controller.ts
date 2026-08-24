import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  HttpCode,
  UseGuards,
  NotFoundException,
} from "@nestjs/common";
import { z } from "zod";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { PrismaService } from "../infra/prisma.service.js";
import { ZodBody } from "../common/zod.pipe.js";
import { dropObjects } from "../common/artifact-purge.js";

const ImportRepoBody = z.object({
  connectionId: z.string(),
  externalRepoId: z.string(),
  fullName: z.string(),
  defaultBranch: z.string().default("main"),
  visibility: z.string().default("private"),
});

@Controller("api/repos")
@UseGuards(AuthGuard)
export class ReposController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  list(@Auth() auth: AuthContext) {
    return this.prisma.tenant(auth.organizationId, (tx) =>
      tx.repository.findMany({
        where: { organizationId: auth.organizationId, isActive: true },
        orderBy: { fullName: "asc" },
      }),
    );
  }

  @Post("import")
  @HttpCode(201)
  async import(
    @Auth() auth: AuthContext,
    @Body(new ZodBody(ImportRepoBody)) body: z.infer<typeof ImportRepoBody>,
  ) {
    return this.prisma.tenant(auth.organizationId, async (tx) => {
      const conn = await tx.connection.findFirst({
        where: { id: body.connectionId, organizationId: auth.organizationId },
      });
      if (!conn) throw new NotFoundException("connection not found");

      return tx.repository.upsert({
        where: {
          connectionId_externalRepoId: {
            connectionId: body.connectionId,
            externalRepoId: body.externalRepoId,
          },
        },
        create: {
          organizationId: auth.organizationId,
          connectionId: body.connectionId,
          provider: conn.provider,
          externalRepoId: body.externalRepoId,
          fullName: body.fullName,
          defaultBranch: body.defaultBranch,
          visibility: body.visibility,
        },
        update: { isActive: true, fullName: body.fullName },
      });
    });
  }

  /**
   * Remove an imported repository AND every run made on it.
   *
   * The runs are deleted EXPLICITLY, and that is the whole point of this
   * handler. `AuditRun.repositoryId` is `onDelete: SetNull` in the schema, so
   * dropping the repository alone would leave every run behind with a null
   * repository — visible in the list, unnameable, and still holding the
   * findings the user just asked us to erase. Deleting the runs first makes
   * their scans, findings, pillar results, reports and artifact rows cascade.
   *
   * Targets keep their SetNull: a verified domain is an asset of the
   * organization, not of the repository it happened to be linked to.
   */
  @Delete(":id")
  @HttpCode(204)
  async remove(@Auth() auth: AuthContext, @Param("id") id: string): Promise<void> {
    const keys = await this.prisma.tenant(auth.organizationId, async (tx) => {
      const repo = await tx.repository.findFirst({
        where: { id, organizationId: auth.organizationId },
      });
      if (!repo) throw new NotFoundException("repository not found");

      const runs = await tx.auditRun.findMany({
        where: { repositoryId: id, organizationId: auth.organizationId },
        select: { id: true },
      });
      if (runs.length === 0) return [];

      const artifacts = await tx.artifact.findMany({
        where: {
          organizationId: auth.organizationId,
          auditRunId: { in: runs.map((r) => r.id) },
        },
        select: { storageKey: true },
      });
      return artifacts.map((a) => a.storageKey);
    });

    await dropObjects(keys);

    await this.prisma.tenant(auth.organizationId, async (tx) => {
      await tx.auditRun.deleteMany({
        where: { repositoryId: id, organizationId: auth.organizationId },
      });
      // deleteMany, not delete: the org filter is repeated here so a race that
      // slipped the row into another tenant between the two transactions still
      // matches nothing rather than deleting it.
      await tx.repository.deleteMany({ where: { id, organizationId: auth.organizationId } });
    });
  }
}
