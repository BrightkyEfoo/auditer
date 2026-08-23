import { Controller, Get, Param, Query, Req, Res, UseGuards } from "@nestjs/common";
import type { Request, Response } from "express";
import { auditChannel } from "@auditer/queue";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { AuditsService } from "../audits/audits.service.js";
import { RedisService } from "../infra/redis.service.js";

/**
 * Live progress via SSE. Snapshot-then-tail:
 *   1. authorize + send current run status as the first event (snapshot),
 *   2. subscribe to Valkey pub/sub `audit:{id}:events` and relay each event,
 *   3. honor Last-Event-ID for gap-free reconnect (client resumes from `seq`).
 *
 * Unidirectional and proxy-friendly. Any Nest instance can relay because the
 * worker publishes to Valkey, decoupled from the web layer.
 */
@Controller("api/audits")
@UseGuards(AuthGuard)
export class SseController {
  constructor(
    private readonly audits: AuditsService,
    private readonly redis: RedisService,
  ) {}

  @Get(":id/events")
  async events(
    @Auth() auth: AuthContext,
    @Param("id") id: string,
    @Req() req: Request,
    @Res() res: Response,
    @Query("lastEventId") _lastEventId?: string,
  ): Promise<void> {
    // Authorize (also 404s cross-tenant via RLS).
    const run = await this.audits.get(auth, id);

    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    });

    const send = (event: string, data: unknown, seqId?: number): void => {
      if (seqId !== undefined) res.write(`id: ${seqId}\n`);
      res.write(`event: ${event}\n`);
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    // Snapshot first so a late client immediately knows current state.
    send("status", { type: "status", auditRunId: id, status: run.status });

    // Tail live events.
    const sub = this.redis.subscriber();
    await sub.subscribe(auditChannel(id));
    sub.on("message", (_channel, message) => {
      try {
        const evt = JSON.parse(message) as { type?: string; seq?: number };
        send(evt.type ?? "message", evt, evt.seq);
      } catch {
        /* ignore malformed */
      }
    });

    // Heartbeat to keep proxies from closing the connection.
    const hb = setInterval(() => res.write(": ping\n\n"), 15000);

    req.on("close", () => {
      clearInterval(hb);
      void sub.quit();
      res.end();
    });
  }
}
