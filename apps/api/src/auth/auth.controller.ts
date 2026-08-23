import {
  Controller,
  Get,
  Post,
  Query,
  Req,
  Res,
  HttpCode,
  UnauthorizedException,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { randomBytes } from "node:crypto";
import { PrismaService } from "../infra/prisma.service.js";
import { SessionService, SESSION_COOKIE, readCookie } from "./session.service.js";
import {
  authorizeUrl as gitlabAuthorizeUrl,
  exchangeCode as gitlabExchange,
  fetchUser as gitlabFetchUser,
  signState as gitlabSignState,
  verifyState as gitlabVerifyState,
} from "../connections/gitlab.js";

interface OAuthProfile {
  provider: "github" | "gitlab";
  id: string;
  login: string;
  name: string | null;
  email: string;
  avatarUrl: string | null;
}

/**
 * App login via GitHub OAuth (distinct from repo-access GitHub App tokens).
 * Flow: /github → GitHub authorize → /github/callback exchanges the code,
 * upserts the User + AuthIdentity, ensures a personal Org + owner Membership,
 * mints a cookie session, and redirects to the web app.
 *
 * This is a self-contained real session layer; better-auth can replace it behind
 * the same AuthGuard without touching any controller.
 */
@Controller("api/auth")
export class AuthController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly sessions: SessionService,
  ) {}

  private redirectUri(): string {
    // Route the callback through the WEB origin (Next proxies /api/* to the api),
    // so the session cookie is set for the origin the browser actually uses.
    const web = process.env.WEB_URL ?? "http://localhost:3000";
    return `${web}/api/auth/github/callback`;
  }

  @Get("github")
  github(@Res() res: Response): void {
    const clientId = process.env.GITHUB_APP_CLIENT_ID;
    if (!clientId) throw new UnauthorizedException("GitHub OAuth not configured");
    const state = randomBytes(16).toString("hex");
    const url = new URL("https://github.com/login/oauth/authorize");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", this.redirectUri());
    url.searchParams.set("scope", "read:user user:email");
    url.searchParams.set("state", state);
    // state cookie for CSRF (httpOnly, short-lived)
    res.setHeader(
      "Set-Cookie",
      `auditer_oauth_state=${state}; HttpOnly; SameSite=Lax; Path=/; Max-Age=600`,
    );
    res.redirect(url.toString());
  }

  @Get("github/callback")
  async callback(
    @Query("code") code: string,
    @Query("state") state: string,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const expected = readCookie(req.header("cookie"), "auditer_oauth_state");
    if (!code || !state || state !== expected) {
      throw new UnauthorizedException("invalid oauth state");
    }

    const token = await exchangeCode(code, this.redirectUri());
    const gh = await fetchGithubUser(token);
    await this.completeLogin(
      { provider: "github", ...gh },
      res,
    );
  }

  // ── GitLab login (OAuth) ──────────────────────────────────────────────────

  @Get("gitlab")
  gitlab(@Res() res: Response): void {
    if (!process.env.GITLAB_CLIENT_ID) throw new UnauthorizedException("GitLab OAuth not configured");
    // We reuse the org-signed state helper; login carries no org yet, so pass a
    // constant marker — the callback ensures the user's own org.
    res.redirect(gitlabAuthorizeUrl("login", gitlabSignState("login")));
  }

  @Get("gitlab/callback")
  async gitlabCallback(
    @Query("code") code: string,
    @Query("state") state: string,
    @Res() res: Response,
  ): Promise<void> {
    if (!code || !state || gitlabVerifyState(state) !== "login") {
      throw new UnauthorizedException("invalid oauth state");
    }
    const tokens = await gitlabExchange(code, "login");
    const gl = await gitlabFetchUser(tokens.accessToken);
    await this.completeLogin(
      {
        provider: "gitlab",
        id: gl.id,
        login: gl.username,
        name: gl.name,
        email: gl.email,
        avatarUrl: gl.avatarUrl,
      },
      res,
    );
  }

  /** Shared: upsert user + identity, ensure a personal org, set the session. */
  private async completeLogin(p: OAuthProfile, res: Response): Promise<void> {
    const { userId, organizationId } = await this.prisma.$transaction(async (tx) => {
      const user = await tx.user.upsert({
        where: { email: p.email },
        update: { name: p.name, avatarUrl: p.avatarUrl },
        create: { email: p.email, name: p.name, avatarUrl: p.avatarUrl },
      });
      await tx.authIdentity.upsert({
        where: { provider_providerAccountId: { provider: p.provider, providerAccountId: p.id } },
        update: {},
        create: { userId: user.id, provider: p.provider, providerAccountId: p.id },
      });
      let membership = await tx.membership.findFirst({ where: { userId: user.id } });
      if (!membership) {
        const slug = `${p.login}-${randomBytes(3).toString("hex")}`.toLowerCase();
        const org = await tx.organization.create({
          data: { slug, name: `${p.name ?? p.login}'s org`, ownerUserId: user.id },
        });
        membership = await tx.membership.create({
          data: { userId: user.id, organizationId: org.id, role: "owner" },
        });
      }
      return { userId: user.id, organizationId: membership.organizationId };
    });

    const sessionToken = await this.sessions.create(userId, organizationId);
    const secure = (process.env.WEB_URL ?? "").startsWith("https") ? "; Secure" : "";
    res.setHeader("Set-Cookie", [
      `${SESSION_COOKIE}=${sessionToken}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 60 * 60}${secure}`,
      `auditer_oauth_state=; Path=/; Max-Age=0`,
    ]);
    res.redirect(process.env.WEB_URL ?? "http://localhost:3000");
  }

  @Get("session")
  async session(@Req() req: Request) {
    const token = readCookie(req.header("cookie"), SESSION_COOKIE);
    if (!token) return { authenticated: false };
    const resolved = await this.sessions.resolve(token);
    if (!resolved) return { authenticated: false };
    return { authenticated: true, ...resolved };
  }

  @Post("logout")
  @HttpCode(200)
  async logout(@Req() req: Request, @Res() res: Response): Promise<void> {
    const token = readCookie(req.header("cookie"), SESSION_COOKIE);
    if (token) await this.sessions.destroy(token);
    res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Path=/; Max-Age=0`);
    res.json({ ok: true });
  }
}

// ── GitHub helpers ──────────────────────────────────────────────────────────

async function exchangeCode(code: string, redirectUri: string): Promise<string> {
  const res = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      client_id: process.env.GITHUB_APP_CLIENT_ID,
      client_secret: process.env.GITHUB_APP_CLIENT_SECRET,
      code,
      redirect_uri: redirectUri,
    }),
  });
  const data = (await res.json()) as { access_token?: string; error?: string };
  if (!data.access_token) throw new UnauthorizedException(`oauth exchange failed: ${data.error ?? "unknown"}`);
  return data.access_token;
}

interface GithubUser {
  id: string;
  login: string;
  name: string | null;
  email: string;
  avatarUrl: string | null;
}

async function fetchGithubUser(token: string): Promise<GithubUser> {
  const headers = { authorization: `Bearer ${token}`, accept: "application/vnd.github+json" };
  const user = (await (await fetch("https://api.github.com/user", { headers })).json()) as {
    id: number;
    login: string;
    name: string | null;
    email: string | null;
    avatar_url: string | null;
  };
  let email = user.email;
  if (!email) {
    const emails = (await (await fetch("https://api.github.com/user/emails", { headers })).json()) as {
      email: string;
      primary: boolean;
      verified: boolean;
    }[];
    email = emails.find((e) => e.primary && e.verified)?.email ?? emails[0]?.email ?? `${user.login}@users.noreply.github.com`;
  }
  return {
    id: String(user.id),
    login: user.login,
    name: user.name,
    email,
    avatarUrl: user.avatar_url,
  };
}
