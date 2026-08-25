import type { Redis } from "ioredis";
import { withTenant, type PrismaClient } from "@auditer/db";
import { auditChannel } from "@auditer/queue";
import type { AuditEvent, AuditStatus, Pillar, ScanStatus } from "@auditer/types";

/** Distributive Omit so each union member keeps its own fields (plain Omit over
 *  a discriminated union collapses to only the shared keys). */
type WithoutSeq<T> = T extends unknown ? Omit<T, "seq"> : never;

/**
 * Publish live progress to Valkey pub/sub. The api's SSE controller subscribes
 * and relays. `seq` is a monotonic per-run counter (Redis INCR) so clients can
 * resume with Last-Event-ID after a dropped connection.
 *
 * Chaque événement est aussi ÉCRIT EN BASE, dans `run_events`. Le pub/sub ne
 * rejoue rien : sans cette écriture, une actualisation de page ou une coupure
 * réseau d'une seconde effaçait définitivement les transitions de phase et les
 * notes d'exécution. Les lignes `Scan` sauvent l'état des moteurs, pas le récit
 * qui les entoure — et c'est ce récit que le lecteur venait chercher.
 *
 * L'organisation est liée par relevé via `bind()` plutôt que passée à chaque
 * appel : les méthodes de publication sont invoquées depuis une trentaine
 * d'endroits, et leur ajouter toutes un paramètre aurait fait passer un défaut
 * d'écriture pour un défaut de signature.
 */
export class EventPublisher {
  /** auditRunId → organizationId, pour écrire sous le bon tenant. */
  private readonly orgByRun = new Map<string, string>();

  constructor(
    private readonly redis: Redis,
    private readonly prisma: PrismaClient,
  ) {}

  /** Déclarer l'organisation d'un relevé avant toute publication le concernant. */
  bind(auditRunId: string, organizationId: string): void {
    this.orgByRun.set(auditRunId, organizationId);
  }

  /** Oublier un relevé terminé — la carte ne doit pas croître sans fin dans un
   *  worker qui tourne des semaines. */
  release(auditRunId: string): void {
    this.orgByRun.delete(auditRunId);
  }

  /**
   * Écriture durable. Best-effort de bout en bout : perdre une ligne de journal
   * ne doit jamais faire échouer le relevé qu'elle décrit. L'unicité
   * (auditRunId, seq) rend l'écriture idempotente si le job est relancé.
   */
  private async persist(
    auditRunId: string,
    seq: number,
    type: string,
    at: string,
    evt: unknown,
  ): Promise<void> {
    const organizationId = this.orgByRun.get(auditRunId);
    if (!organizationId) return;
    try {
      await withTenant(this.prisma, organizationId, (tx) =>
        tx.runEvent.create({
          data: {
            organizationId,
            auditRunId,
            seq,
            type,
            payload: evt as never,
            at: new Date(at),
          },
        }),
      );
    } catch (err) {
      console.warn(
        JSON.stringify({
          level: "warn",
          run: auditRunId,
          seq,
          message: `événement non persisté: ${String(err)}`,
        }),
      );
    }
  }

  private async nextSeq(auditRunId: string): Promise<number> {
    return this.redis.incr(`audit:${auditRunId}:seq`);
  }

  private async publish(auditRunId: string, evt: WithoutSeq<AuditEvent>): Promise<void> {
    // Mirror every event to stdout BEFORE publishing. Progress used to go only
    // to Valkey pub/sub, which is a LIVE channel: once the browser closes, the
    // record is gone. A run that failed an hour ago therefore left two lines in
    // four hours of worker logs and nothing to diagnose from — the operator had
    // strictly less information than the customer watching the page.
    //
    // One structured line per event, on stdout, where `docker logs` and any log
    // shipper can find it. It costs nothing and it is the difference between
    // reading what happened and guessing.
    console.log(JSON.stringify({ level: "info", run: auditRunId, ...evt }));

    const seq = await this.nextSeq(auditRunId);
    const full = { ...evt, seq };
    const payload = JSON.stringify(full);

    // La base d'abord : c'est la source qui survit à tout le reste.
    await this.persist(auditRunId, seq, evt.type, evt.at, full);

    await this.redis.publish(auditChannel(auditRunId), payload);
  }

  status(auditRunId: string, status: AuditStatus): Promise<void> {
    return this.publish(auditRunId, {
      type: "status",
      auditRunId,
      status,
      at: new Date().toISOString(),
    });
  }

  scan(
    auditRunId: string,
    pillar: Pillar,
    tool: string,
    status: ScanStatus,
    findingCount?: number,
    detail?: { durationMs?: number; exitCode?: number; image?: string; reason?: string },
  ): Promise<void> {
    return this.publish(auditRunId, {
      type: "scan",
      auditRunId,
      pillar,
      tool,
      status,
      findingCount,
      ...detail,
      at: new Date().toISOString(),
    });
  }

  log(auditRunId: string, message: string): Promise<void> {
    return this.publish(auditRunId, {
      type: "log",
      auditRunId,
      message,
      at: new Date().toISOString(),
    });
  }

  done(auditRunId: string, status: AuditStatus, riskScore?: number): Promise<void> {
    return this.publish(auditRunId, {
      type: "done",
      auditRunId,
      status,
      riskScore,
      at: new Date().toISOString(),
    });
  }
}
