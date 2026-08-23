import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  Query,
  HttpCode,
  UseGuards,
} from "@nestjs/common";
import { z } from "zod";
import { Pillar, Severity, TriageStatus } from "@auditer/types";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { AuditsService } from "./audits.service.js";
import { ZodBody } from "../common/zod.pipe.js";

const CreateAuditBody = z.object({
  repositoryId: z.string().optional(),
  targetId: z.string().optional(),
  ref: z.string().optional(),
  pillars: z.array(Pillar).min(1),
});

@Controller("api/audits")
@UseGuards(AuthGuard)
export class AuditsController {
  constructor(private readonly audits: AuditsService) {}

  /** 202 + runId in <100ms. No scanning happens in this request. */
  @Post()
  @HttpCode(202)
  create(
    @Auth() auth: AuthContext,
    @Body(new ZodBody(CreateAuditBody)) body: z.infer<typeof CreateAuditBody>,
  ) {
    return this.audits.create(auth, body);
  }

  /**
   * MUST stay above @Get(":id") — Nest matches routes in declaration order, so
   * a `:id` param route declared first would swallow the collection request.
   */
  @Get()
  list(@Auth() auth: AuthContext) {
    return this.audits.list(auth);
  }

  @Get(":id")
  get(@Auth() auth: AuthContext, @Param("id") id: string) {
    return this.audits.get(auth, id);
  }

  @Get(":id/findings")
  listFindings(
    @Auth() auth: AuthContext,
    @Param("id") id: string,
    @Query("pillar") pillar?: string,
    @Query("severity") severity?: string,
    @Query("triage") triage?: string,
  ) {
    return this.audits.listFindings(auth, id, {
      pillar: pillar ? Pillar.parse(pillar) : undefined,
      severity: severity ? Severity.parse(severity) : undefined,
      triage: triage ? TriageStatus.parse(triage) : undefined,
    });
  }

  @Post(":id/cancel")
  @HttpCode(200)
  cancel(@Auth() auth: AuthContext, @Param("id") id: string) {
    return this.audits.cancel(auth, id);
  }
}
