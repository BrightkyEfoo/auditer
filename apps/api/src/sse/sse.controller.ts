import { Controller, Get, Param, Query, Req, Res, UseGuards } from "@nestjs/common";
import type { Request, Response } from "express";
import { auditChannel } from "@auditer/queue";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { AuditsService } from "../audits/audits.service.js";
import { RedisService } from "../infra/redis.service.js";

/**
 * Live progress via SSE. Snapshot, replay, then tail:
 *   1. authorize + send current run status as the first event (snapshot),
 *   2. REJOUER les événements manqués depuis le tampon `audit:{id}:eventlog`,
 *   3. subscribe to Valkey pub/sub `audit:{id}:events` and relay each event.
 *
 * L'étape 2 manquait. Le commentaire de ce fichier annonçait pourtant « honor
 * Last-Event-ID for gap-free reconnect » alors que le paramètre était déclaré
 * `_lastEventId` — préfixé pour faire taire le compilateur, jamais lu. Le canal
 * pub/sub ne rejoue rien : toute coupure, et toute simple actualisation de
 * page, ouvrait un trou définitif dans la trace. La promesse était écrite, le
 * code faisait l'inverse.
 *
 * Sans `Last-Event-ID`, on rejoue le tampon ENTIER : c'est le cas d'un onglet
 * qui s'ouvre sur un relevé déjà commencé, et il doit voir ce qui a précédé.
 * Avec, on reprend juste après le dernier `seq` reçu.
 *
 * Le rejeu lit la table `run_events`, pas un tampon mémoire : la trace survit
 * donc au redémarrage de Valkey, à celui de l'api, et à la fermeture de
 * l'onglet. Ces lignes sont des journaux d'exécution — la purge les efface à 90
 * jours ; au-delà, l'état des moteurs reste lisible via GET
 * /api/audits/:id/scans, qui suit le relevé jusqu'à 24 mois.
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
    @Query("lastEventId") lastEventId?: string,
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
    // `at` is NOT optional: le contrat AuditEvent (packages/types/src/sse.ts)
    // l'exige sur chaque événement, et le client s'en sert pour horodater la
    // ligne de trace. Il manquait ici — `send()` prend un `unknown`, donc rien
    // ne le vérifiait — et comme cet instantané est le PREMIER message reçu à
    // chaque ouverture, la page de relevé plantait à tous les coups.
    send("status", {
      type: "status",
      auditRunId: id,
      status: run.status,
      at: new Date().toISOString(),
    });

    // Le direct est branché AVANT le rejeu, et non après.
    //
    // L'ordre est porteur : rejouer d'abord puis s'abonner laisse un intervalle
    // — le temps du LRANGE — pendant lequel un événement publié n'est ni dans
    // le tampon déjà lu, ni encore relayé. Il disparaît. C'est exactement le
    // trou que cette reprise existe pour fermer, et il serait d'autant plus
    // pernicieux qu'il ne se manifeste que sous charge.
    //
    // On s'abonne donc en premier et on met de côté ce qui arrive, le temps de
    // rejouer. Puis on vide la file en ignorant ce que le rejeu a déjà envoyé,
    // et on passe en relais direct. Le `seq` est monotone par relevé : c'est ce
    // qui rend cette déduplication sûre plutôt qu'approximative.
    let replaying = true;
    let lastSent = 0;
    const queued: { type?: string; seq?: number }[] = [];

    const relay = (evt: { type?: string; seq?: number }): void => {
      if (evt.seq !== undefined && evt.seq <= lastSent) return;
      if (evt.seq !== undefined) lastSent = evt.seq;
      send(evt.type ?? "message", evt, evt.seq);
    };

    const sub = this.redis.subscriber();
    await sub.subscribe(auditChannel(id));
    sub.on("message", (_channel, message) => {
      try {
        const evt = JSON.parse(message) as { type?: string; seq?: number };
        if (replaying) queued.push(evt);
        else relay(evt);
      } catch {
        /* ignore malformed */
      }
    });

    // Rejouer ce que le client a manqué. Le navigateur renvoie de lui-même
    // l'en-tête `Last-Event-ID` sur une reconnexion EventSource ; le paramètre
    // de requête sert aux appelants qui pilotent la reprise à la main.
    const resumeFrom = Number(req.header("last-event-id") ?? lastEventId ?? "");
    const start = Number.isFinite(resumeFrom) && resumeFrom > 0 ? resumeFrom : 0;
    try {
      const missed = await this.audits.runEvents(auth, id, start);
      for (const row of missed) {
        relay({ ...(row.payload as object), type: row.type, seq: row.seq });
      }
    } catch {
      // Une reprise illisible dégrade la trace, elle ne doit pas couper le
      // flux : le client garde le direct et rattrape le reste depuis les
      // lignes Scan.
    }

    for (const evt of queued) relay(evt);
    queued.length = 0;
    replaying = false;

    // Heartbeat to keep proxies from closing the connection.
    const hb = setInterval(() => res.write(": ping\n\n"), 15000);

    req.on("close", () => {
      clearInterval(hb);
      void sub.quit();
      res.end();
    });
  }
}
