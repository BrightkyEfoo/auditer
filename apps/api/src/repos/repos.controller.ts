import {
  Controller,
  Post,
  Get,
  Body,
  HttpCode,
  UseGuards,
  NotFoundException,
} from "@nestjs/common";
import { z } from "zod";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { PrismaService } from "../infra/prisma.service.js";
import { ZodBody } from "../common/zod.pipe.js";

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
}
