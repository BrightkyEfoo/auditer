import {
  Controller,
  Get,
  Post,
  Query,
  Param,
  Body,
  Res,
  HttpCode,
  UseGuards,
  NotFoundException,
} from "@nestjs/common";
import type { Response } from "express";
import { z } from "zod";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { PrismaService } from "../infra/prisma.service.js";
import { ZodBody } from "../common/zod.pipe.js";
import { kekFromEnv, seal, open as openSecret } from "@auditer/crypto";
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
    const notExpired = conn.tokenExpiresAt && conn.tokenExpiresAt.getTime() - 60_000 > Date.now();
    if (notExpired && conn.encPat) return openSecret(kek, conn.encPat);
    if (!conn.encRefreshToken) throw new NotFoundException("gitlab connection has no token");
    const refresh = await openSecret(kek, conn.encRefreshToken);
    const tokens = await gitlabRefresh(refresh);
    await this.persistGitlabTokens(organizationId, conn.id, tokens);
    return tokens.accessToken;
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
}
