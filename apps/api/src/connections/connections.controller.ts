import {
  Controller,
  Get,
  Post,
  Delete,
  Query,
  Param,
  Body,
  Res,
  HttpCode,
  UseGuards,
  NotFoundException,
  ConflictException,
} from "@nestjs/common";
import type { Response } from "express";
import { z } from "zod";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { PrismaService } from "../infra/prisma.service.js";
import { ZodBody } from "../common/zod.pipe.js";
import { dropObjects } from "../common/artifact-purge.js";
import { kekFromEnv, seal, open as openSecret, isUnrecoverable } from "@auditer/crypto";
import {
  installUrl,
  verifyState,
  listInstallationRepos,
  installationAccount,
} from "./github.js";
import {
  authorizeUrl as gitlabAuthorizeUrl,
  exchangeCode as gitlabExchange,
  refreshTokens as gitlabRefresh,
  fetchUser as gitlabFetchUser,
  listProjects as gitlabListProjects,
  signState as gitlabSignState,
  verifyState as gitlabVerifyState,
} from "./gitlab.js";

const kek = kekFromEnv();

const ImportBody = z.object({
  externalRepoId: z.string(),
  fullName: z.string(),
  defaultBranch: z.string().optional(),
  visibility: z.string().optional(),
  primaryLanguage: z.string().nullable().optional(),
});

/**
 * The SaaS connect flow:
 *   1. GET /github/install  → redirect the user to install the GitHub App.
 *   2. GET /github/setup    → GitHub redirects here after install with an
 *      installation_id + our signed state; we create the Connection.
 *   3. GET /:id/repos       → list the repos the installation can access.
 *   4. POST /:id/import     → import a chosen repo (ready to audit).
 */
@Controller("api/connections")
export class ConnectionsController {
  constructor(private readonly prisma: PrismaService) {}

  @Get()
  @UseGuards(AuthGuard)
  list(@Auth() auth: AuthContext) {
    return this.prisma.tenant(auth.organizationId, (tx) =>
      tx.connection.findMany({
        where: { organizationId: auth.organizationId },
        select: {
          id: true,
          provider: true,
          kind: true,
          externalAccountId: true,
          status: true,
          createdAt: true,
        },
      }),
    );
  }

  /** Start the GitHub App installation. */
  @Get("github/install")
  @UseGuards(AuthGuard)
  install(@Auth() auth: AuthContext, @Res() res: Response): void {
    res.redirect(installUrl(auth.organizationId));
  }

  /**
   * Post-install callback (configured as the App's Setup URL). Carries no
   * session — the org is recovered from the signed `state`.
   */
  @Get("github/setup")
  async setup(
    @Query("installation_id") installationId: string,
    @Query("state") state: string,
    @Res() res: Response,
  ): Promise<void> {
    const organizationId = state ? verifyState(state) : null;
    const web = process.env.WEB_URL ?? "http://localhost:3000";
    if (!organizationId || !installationId) {
      res.redirect(`${web}/?connect=error`);
      return;
    }

    const account = await installationAccount(installationId);
    await this.prisma.tenant(organizationId, (tx) =>
      tx.connection.upsert({
        // one connection per (org, installation) — re-install is idempotent
        where: { id: `gh-${installationId}` },
        create: {
          id: `gh-${installationId}`,
          organizationId,
          provider: "github",
          kind: "github_app",
          installationId,
          externalAccountId: account,
          status: "active",
        },
        update: { status: "active", externalAccountId: account },
      }),
    );
    res.redirect(`${web}/?connect=ok`);
  }

  // ── GitLab OAuth (access + rotating refresh tokens, stored encrypted) ──────

  @Get("gitlab/connect")
  @UseGuards(AuthGuard)
  connectGitlab(@Auth() auth: AuthContext, @Res() res: Response): void {
    res.redirect(gitlabAuthorizeUrl("connect", gitlabSignState(auth.organizationId)));
  }

  @Get("gitlab/callback")
  async gitlabCallback(
    @Query("code") code: string,
    @Query("state") state: string,
    @Res() res: Response,
  ): Promise<void> {
    const web = process.env.WEB_URL ?? "http://localhost:3000";
    const organizationId = state ? gitlabVerifyState(state) : null;
    if (!organizationId || !code) {
      res.redirect(`${web}/?connect=error`);
      return;
    }
    const tokens = await gitlabExchange(code, "connect");
    const user = await gitlabFetchUser(tokens.accessToken);
    await this.prisma.tenant(organizationId, (tx) =>
      tx.connection.upsert({
        where: { id: `gl-${user.id}` },
        create: {
          id: `gl-${user.id}`,
          organizationId,
          provider: "gitlab",
          kind: "gitlab_oauth",
          externalAccountId: user.username,
          encPat: undefined,
          status: "active",
        },
        update: { status: "active", externalAccountId: user.username },
      }),
    );
    // store encrypted tokens (access reused as encPat, refresh as encRefreshToken)
    await this.persistGitlabTokens(organizationId, `gl-${user.id}`, tokens);
    res.redirect(`${web}/?connect=ok`);
  }

  /** List repos for a connection — provider-aware (GitHub App vs GitLab OAuth). */
  @Get(":id/repos")
  @UseGuards(AuthGuard)
  async repos(@Auth() auth: AuthContext, @Param("id") id: string) {
    const conn = await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.connection.findFirst({ where: { id, organizationId: auth.organizationId } }),
    );
    if (!conn) throw new NotFoundException("connection not found");

    if (conn.provider === "gitlab") {
      const access = await this.validGitlabToken(auth.organizationId, conn);
      return gitlabListProjects(access);
    }
    if (!conn.installationId) throw new NotFoundException("connection not usable");
    return listInstallationRepos(conn.installationId);
  }

  // Persist (encrypt) GitLab tokens on a connection.
  private async persistGitlabTokens(
    organizationId: string,
    connectionId: string,
    tokens: { accessToken: string; refreshToken: string; expiresAt: number },
  ): Promise<void> {
    const [encAccess, encRefresh] = await Promise.all([
      seal(kek, tokens.accessToken),
      seal(kek, tokens.refreshToken),
    ]);
    await this.prisma.tenant(organizationId, (tx) =>
      tx.connection.update({
        where: { id: connectionId },
        data: {
          encPat: encAccess,
          encRefreshToken: encRefresh,
          tokenExpiresAt: new Date(tokens.expiresAt),
        },
      }),
    );
  }

  /** Return a valid GitLab access token, refreshing (and rotating) if expired. */
  private async validGitlabToken(
    organizationId: string,
    conn: { id: string; encPat: string | null; encRefreshToken: string | null; tokenExpiresAt: Date | null },
  ): Promise<string> {
    try {
      const notExpired = conn.tokenExpiresAt && conn.tokenExpiresAt.getTime() - 60_000 > Date.now();
      if (notExpired && conn.encPat) return await openSecret(kek, conn.encPat);
      if (!conn.encRefreshToken) throw new NotFoundException("gitlab connection has no token");
      const refresh = await openSecret(kek, conn.encRefreshToken);
      const tokens = await gitlabRefresh(refresh);
      await this.persistGitlabTokens(organizationId, conn.id, tokens);
      return tokens.accessToken;
    } catch (err) {
      // A secret the key can no longer open is DEAD. Re-reading it will fail
      // identically forever — which is exactly what happened here: one
      // `ExceptionsHandler` stack trace per page load, for days, while the user
      // saw a broken screen and nothing told either of them what to do.
      //
      // A vault that is merely unreachable takes the other path and is rethrown
      // untouched: an outage must never destroy a working secret.
      if (!isUnrecoverable(err)) throw err;
      await this.markReauthRequired(organizationId, conn.id);
      throw new ConflictException(
        "La connexion GitLab doit être refaite : le secret enregistré n'est plus déchiffrable. Reconnectez le compte.",
      );
    }
  }

  /**
   * Mark a connection dead and drop its unreadable ciphertexts.
   *
   * Clearing them is deliberate. They cannot be decrypted by anything, so
   * keeping them buys nothing and costs a retry on every request; and a stored
   * blob that no key opens is not a secret, it is noise that looks like one.
   * The row itself stays so the user sees WHICH connection to redo instead of
   * finding it silently gone.
   */
  private async markReauthRequired(organizationId: string, connectionId: string): Promise<void> {
    await this.prisma.tenant(organizationId, (tx) =>
      tx.connection.update({
        where: { id: connectionId },
        data: {
          status: "reauth_required",
          encPat: null,
          encRefreshToken: null,
          tokenExpiresAt: null,
        },
      }),
    );
  }

  /** Import a chosen repo so it can be audited. */
  @Post(":id/import")
  @UseGuards(AuthGuard)
  @HttpCode(201)
  async import(
    @Auth() auth: AuthContext,
    @Param("id") id: string,
    @Body(new ZodBody(ImportBody)) body: z.infer<typeof ImportBody>,
  ) {
    return this.prisma.tenant(auth.organizationId, async (tx) => {
      const conn = await tx.connection.findFirst({
        where: { id, organizationId: auth.organizationId },
      });
      if (!conn) throw new NotFoundException("connection not found");
      return tx.repository.upsert({
        where: {
          connectionId_externalRepoId: {
            connectionId: id,
            externalRepoId: body.externalRepoId,
          },
        },
        create: {
          organizationId: auth.organizationId,
          connectionId: id,
          provider: conn.provider,
          externalRepoId: body.externalRepoId,
          fullName: body.fullName,
          defaultBranch: body.defaultBranch ?? "main",
          visibility: body.visibility ?? "private",
          primaryLanguage: body.primaryLanguage,
        },
        update: { isActive: true, fullName: body.fullName },
      });
    });
  }

  /**
   * Revoke a connection: destroy the encrypted tokens, then remove the row and
   * everything that depended on this access.
   *
   * Revoking here does NOT reach into GitHub or GitLab — the installation or
   * the OAuth grant lives on their side and only the user can withdraw it
   * there. What this endpoint guarantees is the half we control: after it
   * returns, no ciphertext of yours remains in our database, so nothing here
   * can be decrypted into a working credential, whatever happens upstream.
   *
   * The imported repositories go too, and that is not incidental damage:
   * `Repository.connectionId` is `onDelete: Cascade` in the schema, so removing
   * the connection removes them whatever we do. Their runs are deleted
   * EXPLICITLY first for the same reason as in ReposController.remove — the
   * runs would otherwise survive with a null repository, holding findings the
   * user believes they just erased.
   */
  @Delete(":id")
  @UseGuards(AuthGuard)
  @HttpCode(204)
  async revoke(@Auth() auth: AuthContext, @Param("id") id: string): Promise<void> {
    const org = auth.organizationId;

    const plan = await this.prisma.tenant(org, async (tx) => {
      const conn = await tx.connection.findFirst({ where: { id, organizationId: org } });
      if (!conn) throw new NotFoundException("connection not found");

      // Overwrite the ciphertext in its own statement, before anything below
      // can fail. The row is about to disappear anyway, but a revocation that
      // only takes effect if a later statement commits is not a revocation.
      await tx.connection.update({
        where: { id },
        data: {
          encPat: null,
          encRefreshToken: null,
          tokenExpiresAt: null,
          status: "revoked",
        },
      });

      const repos = await tx.repository.findMany({
        where: { connectionId: id, organizationId: org },
        select: { id: true },
      });
      const repoIds = repos.map((r) => r.id);

      const runs =
        repoIds.length > 0
          ? await tx.auditRun.findMany({
              where: { organizationId: org, repositoryId: { in: repoIds } },
              select: { id: true },
            })
          : [];

      const artifacts =
        runs.length > 0
          ? await tx.artifact.findMany({
              where: { organizationId: org, auditRunId: { in: runs.map((r) => r.id) } },
              select: { storageKey: true },
            })
          : [];

      return { repoIds, keys: artifacts.map((a) => a.storageKey) };
    });

    await dropObjects(plan.keys);

    await this.prisma.tenant(org, async (tx) => {
      if (plan.repoIds.length > 0) {
        await tx.auditRun.deleteMany({
          where: { organizationId: org, repositoryId: { in: plan.repoIds } },
        });
      }
      await tx.connection.deleteMany({ where: { id, organizationId: org } });
    });

    // webhook_events references the connection by a plain column: no relation,
    // no cascade, and no RLS policy either (see prisma/sql/rls.sql). Left alone
    // it would keep delivery payload references for a connection that no longer
    // exists.
    await this.prisma.webhookEvent.deleteMany({ where: { connectionId: id } });
  }
}
