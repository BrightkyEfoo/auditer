import {
  Controller,
  Post,
  Get,
  Delete,
  Body,
  Param,
  Query,
  Res,
  HttpCode,
  UseGuards,
} from "@nestjs/common";
import type { Response } from "express";
import { getStorage } from "@auditer/storage";
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

  /** La trace persistée du relevé : une ligne par moteur prévu. */
  @Get(":id/scans")
  scans(@Auth() auth: AuthContext, @Param("id") id: string) {
    return this.audits.scans(auth, id);
  }

  /**
   * Sortie brute d'un moteur, en pièce jointe.
   *
   * `attachment` et `text/plain` sont délibérés : c'est la sortie non filtrée
   * d'un outil tiers, elle ne doit jamais être rendue dans notre propre origine.
   */
  @Get(":id/scans/:scanId/log")
  async scanLog(
    @Auth() auth: AuthContext,
    @Param("id") id: string,
    @Param("scanId") scanId: string,
    @Res() res: Response,
  ): Promise<void> {
    const artifact = await this.audits.scanLog(auth, id, scanId);
    const body = await getStorage().get(artifact.storageKey);
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.setHeader("content-length", String(body.byteLength));
    res.setHeader(
      "content-disposition",
      `attachment; filename="auditer-moteur-${scanId.slice(0, 8)}.txt"`,
    );
    res.setHeader("cache-control", "private, no-store");
    res.send(body);
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

  /** Erase a run and its findings. Irreversible — see AuditsService.remove. */
  @Delete(":id")
  @HttpCode(204)
  remove(@Auth() auth: AuthContext, @Param("id") id: string): Promise<void> {
    return this.audits.remove(auth, id);
  }
}
