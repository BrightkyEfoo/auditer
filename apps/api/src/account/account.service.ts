import {
  Injectable,
  Logger,
  ForbiddenException,
  InternalServerErrorException,
  UnauthorizedException,
} from "@nestjs/common";
import { createHash, timingSafeEqual } from "node:crypto";
import { PrismaService } from "../infra/prisma.service.js";
import { dropObjects } from "../common/artifact-purge.js";
import type { AuthContext } from "../auth/auth.guard.js";

/**
 * Account-level rights the published documents promise: erasure (GDPR art. 17)
 * and portability (art. 20). Both are implemented here rather than in a
 * controller because both are multi-step and neither is a single query.
 *
 * The erasure path is written against the ACTUAL referential actions in
 * packages/db/prisma/schema.prisma, not against what a cascade is assumed to
 * do. Three families of rows exist and only the first one takes care of itself:
 *
 *   1. rows with a relation to Organization / AuditRun carrying
 *      `onDelete: Cascade` — memberships, invitations, connections,
 *      repositories (twice over: by org AND by connection), targets, audit
 *      runs, scans, findings, pillar results, reports, baselines, branding.
 *      Deleting the organization row is enough.
 *   2. rows that carry `organizationId` as a PLAIN COLUMN with no relation at
 *      all — triage_states, activity_logs, abuse_events, ai_usage_ledger, and
 *      sessions. Nothing cascades into them: they outlive the organization and
 *      become unreachable rows about a deleted person. They are deleted here,
 *      one by one, deliberately exhaustively.
 *   3. bytes in object storage, which Postgres cannot reach at all. See
 *      common/artifact-purge.ts.
 */
export interface DeleteAccountResult {
  ok: true;
  /** Organizations actually removed — the user's own, never someone else's. */
  organizations: number;
  /** Objects removed from the bucket. Below the row count if the bucket blinked. */
  storageObjects: number;
}

/**
 * Constant-time comparison of the typed confirmation against the account
 * address. Hashing first so the comparison is over two 32-byte digests: a raw
 * `timingSafeEqual` throws on length mismatch, and catching that throw would
 * itself leak the length of the address.
 */
function sameEmail(typed: string, actual: string): boolean {
  const a = createHash("sha256").update(typed.trim().toLowerCase()).digest();
  const b = createHash("sha256").update(actual.trim().toLowerCase()).digest();
  return timingSafeEqual(a, b);
}

@Injectable()
export class AccountService {
  private readonly logger = new Logger("account");

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Erase the account and everything the user owns.
   *
   * `confirmEmail` must be the exact address of the account. This is the
   * standard guard against the accidental click, and it is checked SERVER-SIDE:
   * a browser-side comparison protects nobody once the request is replayed by
   * hand, and this endpoint is irreversible.
   */
  async deleteAccount(auth: AuthContext, confirmEmail: string): Promise<DeleteAccountResult> {
    // `users` is not an RLS table, so this read is legitimately outside tenant().
    const user = await this.prisma.user.findUnique({
      where: { id: auth.userId },
      select: { id: true, email: true },
    });
    if (!user) throw new UnauthorizedException({ error: "account_not_found" });

    if (!sameEmail(confirmEmail, user.email)) {
      throw new ForbiddenException({ error: "confirmation_mismatch" });
    }

    const ownedOrgs = await this.ownedOrganizationIds(user.id, auth.organizationId);

    let storageObjects = 0;
    for (const organizationId of ownedOrgs) {
      storageObjects += await this.purgeOrganization(organizationId);
    }

    // Organization.owner declares NO onDelete, so Prisma emits ON DELETE
    // RESTRICT for it: an organization we failed to enumerate would make the
    // user delete below abort with a foreign-key error, halfway through an
    // irreversible operation. Check before, and say so.
    const stillOwned = await this.prisma.privileged.organization.count({
      where: { ownerUserId: user.id },
    });
    if (stillOwned > 0) {
      this.logger.error(
        `account ${user.id}: ${stillOwned} organization(s) left after purge — refusing to delete the user`,
      );
      throw new InternalServerErrorException({ error: "organizations_remaining" });
    }

    // Sessions, auth identities and any remaining membership all declare
    // `onDelete: Cascade` on userId — this single statement takes them along.
    await this.prisma.user.delete({ where: { id: user.id } });

    // Journalised in the technical log, which is the only journal that survives
    // the deletion (ActivityLog is org-scoped and went with the organization).
    // The address is deliberately NOT logged: erasing an account and keeping
    // its email in a log line would defeat the whole operation.
    this.logger.warn(
      `account deleted — user=${user.id} organizations=${ownedOrgs.length} objects=${storageObjects}`,
    );

    return { ok: true, organizations: ownedOrgs.length, storageObjects };
  }

  /**
   * Organizations this user OWNS. Membership is not ownership: a user invited
   * into someone else's organization must not take it down on the way out, so
   * the active organization is only included once ownership is confirmed.
   */
  private async ownedOrganizationIds(
    userId: string,
    activeOrganizationId: string,
  ): Promise<string[]> {
    const ids = new Set<string>();

    // Cross-tenant read, on the PRIVILEGED connection by explicit choice.
    // Deleting an account means deleting every organization it owns, and no
    // tenant-scoped query can enumerate those — by definition it can only see
    // one. The count check in deleteAccount() turns any shortfall here into a
    // loud failure rather than a half-deleted account.
    const owned = await this.prisma.privileged.organization.findMany({
      where: { ownerUserId: userId },
      select: { id: true },
    });
    for (const o of owned) ids.add(o.id);

    const active = await this.prisma.tenant(activeOrganizationId, (tx) =>
      tx.organization.findFirst({
        where: { id: activeOrganizationId, ownerUserId: userId },
        select: { id: true },
      }),
    );
    if (active) ids.add(active.id);

    return [...ids];
  }

  /**
   * Erase one organization and everything hanging off it. Returns the number of
   * storage objects removed.
   *
   * Split into several short transactions rather than one long one: a single
   * transaction holding a connection while S3 is contacted object by object is
   * how a deletion turns into a pool starvation incident.
   */
  private async purgeOrganization(organizationId: string): Promise<number> {
    // 1. Destroy the ciphertext FIRST, in its own transaction. The rows are
    //    about to disappear anyway, but if anything below fails the token must
    //    already be unusable — a revocation that depends on a later statement
    //    committing is not a revocation.
    await this.prisma.tenant(organizationId, async (tx) => {
      await tx.connection.updateMany({
        where: { organizationId },
        data: {
          encPat: null,
          encRefreshToken: null,
          tokenExpiresAt: null,
          status: "revoked",
        },
      });
      await tx.target.updateMany({
        where: { organizationId },
        data: { encAuthConfig: null, verificationToken: null },
      });
    });

    // 2. Bytes in the bucket. Read the keys while the rows still exist.
    const artifacts = await this.prisma.tenant(organizationId, (tx) =>
      tx.artifact.findMany({ where: { organizationId }, select: { storageKey: true } }),
    );
    const dropped = await dropObjects(artifacts.map((a) => a.storageKey));

    // 3. Webhook deliveries reference the connection by a plain column, outside
    //    both the cascade and RLS (see prisma/sql/rls.sql). Collect the ids
    //    before the connections go.
    const connections = await this.prisma.tenant(organizationId, (tx) =>
      tx.connection.findMany({ where: { organizationId }, select: { id: true } }),
    );

    // 4. Everything that carries organizationId WITHOUT a relation to
    //    Organization. None of this cascades; all of it would survive.
    await this.prisma.tenant(organizationId, async (tx) => {
      await tx.triageState.deleteMany({ where: { organizationId } });
      await tx.activityLog.deleteMany({ where: { organizationId } });
      await tx.aiUsageLedger.deleteMany({ where: { organizationId } });
      // Artifact only cascades through auditRunId, which is nullable — an
      // artifact not attached to a run would otherwise stay behind.
      await tx.artifact.deleteMany({ where: { organizationId } });
      // Sessions of EVERY member of this organization, not just the caller's:
      // a session row pointing at a deleted organization resolves to a tenant
      // that no longer exists.
      await tx.session.deleteMany({ where: { organizationId } });
    });

    if (connections.length > 0) {
      // webhook_events is not tenant-scoped and has no RLS policy — the
      // documented case for going through the client directly (see
      // packages/db/src/tenant.ts, systemClient).
      await this.prisma.webhookEvent.deleteMany({
        where: { connectionId: { in: connections.map((c) => c.id) } },
      });
    }

    // AbuseEvent is deliberately NOT deleted. Those rows are the DAST
    // authorization attestations the CGU promises to keep for 24 months and to
    // produce to an authority on request — they protect the target of a scan,
    // who is a third party and did not consent to their disappearance. The
    // published retention table announces this separately from the account, and
    // RetentionService expires them on their own 24-month clock.

    // 5. The organization itself. Everything in family (1) goes with it.
    await this.prisma.tenant(organizationId, (tx) =>
      tx.organization.delete({ where: { id: organizationId } }),
    );

    return dropped;
  }

  /**
   * Portability export (GDPR art. 20): everything we hold for this
   * organization, as structured JSON.
   *
   * Encrypted VCS tokens, session hashes, share-token hashes, domain
   * verification tokens and the password digest are all absent by explicit
   * `select`, never by a `delete obj.field` after the fact — a select list is
   * the only form of exclusion that survives a schema gaining a column.
   *
   * Built in memory rather than streamed. An organization's findings are
   * bounded by its runs and this endpoint is called by hand, not on a loop; a
   * streaming writer would be the right answer only once exports get big enough
   * to matter, and pretending otherwise now would cost clarity for nothing.
   */
  async exportOrganization(auth: AuthContext): Promise<Record<string, unknown>> {
    const account = await this.prisma.user.findUnique({
      where: { id: auth.userId },
      select: {
        id: true,
        email: true,
        name: true,
        avatarUrl: true,
        termsAcceptedAt: true,
        termsVersion: true,
        createdAt: true,
      },
    });

    const data = await this.prisma.tenant(auth.organizationId, async (tx) => {
      const organizationId = auth.organizationId;

      const organization = await tx.organization.findUnique({
        where: { id: organizationId },
        select: { id: true, slug: true, name: true, ownerUserId: true, createdAt: true },
      });

      const connections = await tx.connection.findMany({
        where: { organizationId },
        select: {
          id: true,
          provider: true,
          kind: true,
          installationId: true,
          externalAccountId: true,
          scopes: true,
          status: true,
          tokenExpiresAt: true,
          createdAt: true,
        },
      });

      const repositories = await tx.repository.findMany({
        where: { organizationId },
        orderBy: { fullName: "asc" },
      });

      const targets = await tx.target.findMany({
        where: { organizationId },
        select: {
          id: true,
          repositoryId: true,
          kind: true,
          value: true,
          apexDomain: true,
          verificationMethod: true,
          verificationStatus: true,
          resolvedIps: true,
          scopeAllowlist: true,
          createdAt: true,
        },
      });

      const auditRuns = await tx.auditRun.findMany({
        where: { organizationId },
        orderBy: { createdAt: "desc" },
      });

      const scans = await tx.scan.findMany({ where: { organizationId } });
      const pillarResults = await tx.pillarResult.findMany({
        where: { auditRun: { organizationId } },
      });
      const findings = await tx.finding.findMany({
        where: { organizationId },
        orderBy: [{ auditRunId: "asc" }, { severity: "asc" }],
      });

      const reports = await tx.report.findMany({
        where: { organizationId },
        select: {
          id: true,
          auditRunId: true,
          format: true,
          aiModel: true,
          summary: true,
          status: true,
          generatedAt: true,
          createdAt: true,
        },
      });

      const triageStates = await tx.triageState.findMany({ where: { organizationId } });

      // Metadata only — `storageKey` is an internal bucket path, not the user's
      // data, and handing it out invites someone to try it against the bucket.
      const artifacts = await tx.artifact.findMany({
        where: { organizationId },
        select: {
          id: true,
          auditRunId: true,
          scanId: true,
          type: true,
          contentType: true,
          sizeBytes: true,
          checksum: true,
          retentionExpiresAt: true,
          createdAt: true,
        },
      });

      const baselines = await tx.baseline.findMany({
        where: { repository: { organizationId } },
      });

      const activityLog = await tx.activityLog.findMany({
        where: { organizationId },
        orderBy: { createdAt: "desc" },
      });

      return {
        organization,
        connections,
        repositories,
        targets,
        auditRuns,
        scans,
        pillarResults,
        findings,
        reports,
        triageStates,
        artifacts,
        baselines,
        activityLog,
      };
    });

    return {
      format: "auditer.export.v1",
      generatedAt: new Date().toISOString(),
      avertissement:
        "Cet export ne contient aucun jeton d'accès : les jetons VCS sont chiffrés et " +
        "ne sont jamais exportés en clair ni en chiffré. Il ne contient pas non plus " +
        "votre code source, qui n'est jamais conservé au-delà de la durée d'un relevé.",
      account,
      ...data,
    };
  }
}
