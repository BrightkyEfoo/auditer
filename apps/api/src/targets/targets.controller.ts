import { Controller, Post, Get, Body, Param, Req, HttpCode, UseGuards } from "@nestjs/common";
import type { Request } from "express";
import { z } from "zod";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { TargetsService } from "./targets.service.js";
import { ZodBody } from "../common/zod.pipe.js";

const CreateTargetBody = z.object({
  kind: z.enum(["domain", "origin", "api"]),
  value: z.string().min(1),
  repositoryId: z.string().optional(),
});

@Controller("api/targets")
@UseGuards(AuthGuard)
export class TargetsController {
  constructor(private readonly targets: TargetsService) {}

  @Get()
  list(@Auth() auth: AuthContext) {
    return this.targets.list(auth);
  }

  @Post()
  @HttpCode(201)
  create(
    @Auth() auth: AuthContext,
    @Body(new ZodBody(CreateTargetBody)) body: z.infer<typeof CreateTargetBody>,
  ) {
    return this.targets.create(auth, body);
  }

  /** Check DNS-TXT ownership; on success the target becomes scannable. */
  @Post(":id/verify")
  @HttpCode(200)
  verify(@Auth() auth: AuthContext, @Param("id") id: string, @Req() req: Request) {
    return this.targets.verify(auth, id, {
      ip: req.ip,
      userAgent: req.header("user-agent"),
    });
  }
}
