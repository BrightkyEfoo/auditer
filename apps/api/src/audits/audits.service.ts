import {
  Injectable,
  BadRequestException,
  ForbiddenException,
  NotFoundException,
} from "@nestjs/common";
import type { Pillar, Severity } from "@auditer/types";
import { cancelFlag } from "@auditer/queue";
import { PrismaService } from "../infra/prisma.service.js";
import { QueueService } from "../infra/queue.service.js";
import { RedisService } from "../infra/redis.service.js";
import { dropObjects } from "../common/artifact-purge.js";
import type { AuthContext } from "../auth/auth.guard.js";

export interface CreateAuditInput {
  repositoryId?: string;
  targetId?: string;
  ref?: string;
  pillars: Pillar[];
}

/** Pillars that require a network-reachable, ownership-verified target. */
const NETWORK_PILLARS: ReadonlySet<Pillar> = new Set(["dast", "ux"]);

/** Page size of the run list. Deliberately fixed — no client-controlled take. */
const LIST_LIMIT = 50;

/** Taille de page par défaut des findings. Le client peut la réduire ou
 *  l'augmenter, jamais au-delà du plafond appliqué dans `listFindings`. */
const FINDINGS_PAGE_SIZE = 50;

/** Severity histogram of a run. Always all five keys, always a number. */
export type SeverityCounts = Record<Severity, number>;

function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

@Injectable()
export class AuditsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly queue: QueueService,
    private readonly redis: RedisService,
  ) {}

  /**
   * Queue an audit run. Returns immediately with a runId — the request path does
   * NO scanning. Enforces DAST/UX ownership verification in the data model
   * before anything is queued.
   */
  async create(auth: AuthContext, input: CreateAuditInput): Promise<{ runId: string; status: string }> {
    if (!input.repositoryId && !input.targetId) {
      throw new BadRequestException("repositoryId or targetId is required");
    }

    const needsTarget = input.pillars.some((p) => NETWORK_PILLARS.has(p));

    return this.prisma.tenant(auth.organizationId, async (tx) => {
      // Validate the repo/target belongs to the org (RLS also enforces this).
      if (input.repositoryId) {
        const repo = await tx.repository.findFirst({
          where: { id: input.repositoryId, organizationId: auth.organizationId },
        });
        if (!repo) throw new NotFoundException("repository not found");
      }

      if (needsTarget) {
        if (!input.targetId) {
          throw new BadRequestException("DAST/UX pillars require a targetId");
        }
        const target = await tx.target.findFirst({
          where: { id: input.targetId, organizationId: auth.organizationId },
        });
        if (!target) throw new NotFoundException("target not found");
        // HARD GATE: no active network scan without verified ownership.
        if (target.verificationStatus !== "verified") {
          throw new ForbiddenException(
            "target ownership is not verified — verify the domain before scanning",
          );
        }
      }

      const run = await tx.auditRun.create({
        data: {
          organizationId: auth.organizationId,
          repositoryId: input.repositoryId,
          targetId: input.targetId,
          ref: input.ref,
          pillars: input.pillars,
          status: "queued",
          trigger: "manual",
          createdById: auth.userId,
        },
      });

      await this.queue.enqueueAudit({
        auditRunId: run.id,
        organizationId: auth.organizationId,
        repositoryId: input.repositoryId,
        targetId: input.targetId,
        ref: input.ref,
        pillars: input.pillars,
      });

      return { runId: run.id, status: run.status };
    });
  }

  /**
   * Recent runs for the org, with their severity histogram.
   *
   * Capped at 50 — this feeds a dashboard list, not an export, and an org with
   * a webhook on a busy repo accumulates runs faster than anyone reads them.
   */
  async list(auth: AuthContext) {
    return this.prisma.tenant(auth.organizationId, async (tx) => {
      const runs = await tx.auditRun.findMany({
        where: { organizationId: auth.organizationId },
        orderBy: { createdAt: "desc" },
        take: LIST_LIMIT,
        select: {
          id: true,
          status: true,
          pillars: true,
          riskScore: true,
          scoringVersion: true,
          createdAt: true,
          finishedAt: true,
          repository: { select: { id: true, fullName: true, provider: true } },
        },
      });
      if (runs.length === 0) return [];

      // ONE groupBy for the whole page. Counting per run would be 50 extra
      // round-trips (N+1) to render what is, on screen, five little badges.
      const grouped = await tx.finding.groupBy({
        by: ["auditRunId", "severity"],
        where: {
          organizationId: auth.organizationId,
          auditRunId: { in: runs.map((r) => r.id) },
        },
        _count: { _all: true },
      });

      const counts = new Map<string, SeverityCounts>();
      for (const row of grouped) {
        const bucket = counts.get(row.auditRunId) ?? emptyCounts();
        bucket[row.severity] = row._count._all;
        counts.set(row.auditRunId, bucket);
      }

      // Zero-fill: a run with no criticals must still report `critical: 0`, so
      // the UI never has to distinguish "none" from "not loaded".
      return runs.map((run) => ({ ...run, counts: counts.get(run.id) ?? emptyCounts() }));
    });
  }

  async get(auth: AuthContext, id: string) {
    const run = await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.auditRun.findFirst({ where: { id, organizationId: auth.organizationId } }),
    );
    if (!run) throw new NotFoundException("audit run not found");
    return run;
  }

  /**
   * Les scans d'un relevé — une ligne par moteur, du plan à son issue.
   *
   * C'est la source DURABLE de la trace. Jusqu'ici elle n'existait que dans
   * l'état React de la page, alimentée par le direct : actualiser, ou perdre la
   * connexion, effaçait tout ce qui avait été dit. Les lignes étaient pourtant
   * déjà en base — personne ne les lisait.
   *
   * `error` et `stats` en font partie à dessein : le code de sortie dit qu'un
   * moteur a échoué, le payload dit POURQUOI. C'est la donnée de l'organisation
   * qui a lancé le relevé, et la purge la caviarde à 90 jours.
   */
  async scans(auth: AuthContext, id: string) {
    await this.get(auth, id); // autorise + 404 hors tenant (RLS double la garde)
    return this.prisma.tenant(auth.organizationId, (tx) =>
      tx.scan.findMany({
        where: { auditRunId: id, organizationId: auth.organizationId },
        // `createdAt` départage les moteurs pas encore démarrés, qui n'ont pas
        // de `startedAt` : sans lui, l'ordre du plan serait arbitraire.
        orderBy: [{ startedAt: "asc" }, { createdAt: "asc" }],
        select: {
          id: true,
          scannerId: true,
          pillar: true,
          tool: true,
          toolVersion: true,
          imageDigest: true,
          status: true,
          exitCode: true,
          exitClass: true,
          error: true,
          stats: true,
          rawArtifactId: true,
          startedAt: true,
          finishedAt: true,
          createdAt: true,
        },
      }),
    );
  }

  /**
   * Les événements persistés d'un relevé, après un `seq` donné.
   *
   * C'est la reprise du flux. Le canal Valkey ne rejoue rien : sans cette
   * lecture, une actualisation de page ou une coupure d'une seconde ouvrait un
   * trou définitif dans la trace — alors même que ce service annonçait honorer
   * `Last-Event-ID`.
   *
   * `seq` est monotone par relevé, donc « après N » est exact et non
   * approximatif : aucun événement n'est redonné, aucun n'est sauté.
   */
  async runEvents(auth: AuthContext, id: string, afterSeq: number) {
    return this.prisma.tenant(auth.organizationId, (tx) =>
      tx.runEvent.findMany({
        where: {
          auditRunId: id,
          organizationId: auth.organizationId,
          ...(afterSeq > 0 ? { seq: { gt: afterSeq } } : {}),
        },
        orderBy: { seq: "asc" },
        select: { seq: true, type: true, payload: true },
      }),
    );
  }

  /**
   * La sortie brute conservée d'un moteur : l'artefact `raw` de ce scan.
   *
   * Servie à travers l'api plutôt que par une URL présignée, pour la même
   * raison que les rapports : le point d'accès au stockage est un nom d'hôte
   * interne, que le navigateur ne saurait pas résoudre, et l'autorisation est
   * réévaluée ici à chaque requête au lieu d'être déléguée à une URL qui a
   * quitté le service.
   */
  async scanLog(auth: AuthContext, runId: string, scanId: string) {
    await this.get(auth, runId); // autorise le relevé
    const artifact = await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.artifact.findFirst({
        where: {
          scanId,
          auditRunId: runId,
          organizationId: auth.organizationId,
          type: "raw",
        },
        orderBy: { createdAt: "desc" },
      }),
    );
    // 404 et non 204 : « ce moteur n'a rien écrit » et « ce journal a été purgé
    // à 90 jours » sont indiscernables ici, et aucun des deux n'est un contenu.
    if (!artifact) throw new NotFoundException("scan log not found");
    return artifact;
  }

  /**
   * Une PAGE de findings, avec de quoi afficher honnêtement ce qui n'y est pas.
   *
   * La liste rendait auparavant TOUS les findings d'un relevé, et la page en
   * faisait le tri, la recherche et le décompte côté navigateur. Sur un dépôt
   * réel cela veut dire quelques milliers de lignes transférées pour en
   * afficher vingt — et une page qui rame d'autant plus que le relevé a trouvé
   * de choses, c'est-à-dire exactement quand elle est utile.
   *
   * Le filtre et la recherche sont donc remontés ici. Ce n'est pas un détail de
   * performance : une recherche appliquée à la seule page visible aurait été un
   * MENSONGE — l'utilisateur aurait lu « aucun résultat » alors que le finding
   * existait deux pages plus loin.
   *
   * `counts` couvre tout le relevé et ignore délibérément le filtre de
   * sévérité : ce sont les compteurs des boutons de sévérité eux-mêmes, et
   * cliquer « critical » ne doit pas mettre les quatre autres à zéro.
   */
  async listFindings(
    auth: AuthContext,
    id: string,
    filter: {
      pillar?: Pillar;
      severity?: string;
      triage?: string;
      q?: string;
      limit?: number;
      offset?: number;
    },
  ) {
    // Bornes dures, jamais dictées par le client : `take` non plafonné est le
    // chemin le plus court entre un paramètre d'URL et une base à genoux.
    //
    // `Number.isFinite` d'abord, et ce n'est pas de la ceinture-bretelles :
    // `Math.max(NaN, 1)` rend NaN, pas 1. Un `?limit=abc` traverserait donc les
    // deux bornes intact et arriverait tel quel chez Prisma.
    const take = Number.isFinite(filter.limit)
      ? Math.min(Math.max(filter.limit as number, 1), 200)
      : FINDINGS_PAGE_SIZE;
    const skip = Number.isFinite(filter.offset) ? Math.max(filter.offset as number, 0) : 0;

    const q = filter.q?.trim();
    const search = q
      ? {
          OR: [
            { title: { contains: q, mode: "insensitive" as const } },
            { ruleId: { contains: q, mode: "insensitive" as const } },
            // `vulnIds` est un tableau : la correspondance y est EXACTE, pas
            // préfixée. Chercher « CVE-2024 » ne remonte donc rien par ce
            // chemin, « CVE-2024-1234 » oui. Le dire plutôt que de laisser
            // croire à une recherche partielle.
            { vulnIds: { has: q } },
          ],
        }
      : {};

    const base = {
      auditRunId: id,
      organizationId: auth.organizationId,
      ...(filter.pillar ? { pillar: filter.pillar } : {}),
      ...(filter.triage ? { triageStatus: filter.triage as never } : {}),
      ...search,
    };
    const where = {
      ...base,
      ...(filter.severity ? { severity: filter.severity as never } : {}),
    };

    return this.prisma.tenant(auth.organizationId, async (tx) => {
      const [items, total, grouped, openCount] = await Promise.all([
        tx.finding.findMany({
          where,
          // `id` en dernier critère : sans départage stable, deux findings de
          // même sévérité et même priorité peuvent changer d'ordre entre deux
          // requêtes, et la pagination sauterait ou dupliquerait des lignes.
          orderBy: [{ severity: "asc" }, { aiPriority: "desc" }, { id: "asc" }],
          take,
          skip,
        }),
        tx.finding.count({ where }),
        tx.finding.groupBy({ by: ["severity"], where: base, _count: { _all: true } }),
        tx.finding.count({
          where: {
            auditRunId: id,
            organizationId: auth.organizationId,
            triageStatus: "open",
          },
        }),
      ]);

      const counts = emptyCounts();
      for (const row of grouped) {
        counts[row.severity as Severity] = row._count._all;
      }

      return { items, total, counts, openCount, limit: take, offset: skip };
    });
  }

  /** Cancel = flip a Redis flag the worker polls between scans. */
  async cancel(auth: AuthContext, id: string): Promise<{ ok: boolean }> {
    await this.get(auth, id); // authorize + existence
    await this.redis.client.set(cancelFlag(id), "1", "EX", 3600);
    return { ok: true };
  }

  /**
   * Delete a run and everything it produced: scans, findings, pillar results,
   * reports and artifacts (rows via cascade, bytes explicitly).
   *
   * The cancel flag is raised FIRST and that ordering is load-bearing. A run
   * still on the worker keeps writing findings against `auditRunId`; if the row
   * disappears underneath it, the insert fails on the foreign key and BullMQ
   * retries the job forever. Cancelling first makes the worker stop at its next
   * poll, so the user's deletion does not become an ops incident.
   *
   * Triage decisions are NOT deleted: they are keyed on the fingerprint and
   * scoped to the organization, not to the run, precisely so a false-positive
   * call survives re-scans. Deleting a run must not silently un-triage the next
   * one. They go with the account, or with an explicit triage change.
   */
  async remove(auth: AuthContext, id: string): Promise<void> {
    await this.get(auth, id); // authorize + existence

    await this.redis.client.set(cancelFlag(id), "1", "EX", 3600);

    const keys = await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.artifact.findMany({
        where: { auditRunId: id, organizationId: auth.organizationId },
        select: { storageKey: true },
      }),
    );
    await dropObjects(keys.map((k) => k.storageKey));

    await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.auditRun.deleteMany({ where: { id, organizationId: auth.organizationId } }),
    );
  }
}
