import {
  Controller,
  Get,
  Post,
  Body,
  Query,
  Req,
  Res,
  HttpCode,
  HttpException,
  HttpStatus,
  ConflictException,
  UnauthorizedException,
} from "@nestjs/common";
import type { Request, Response } from "express";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import type { TenantClient } from "@auditer/db";
import { PrismaService } from "../infra/prisma.service.js";
import { ZodBody } from "../common/zod.pipe.js";
import { SessionService, SESSION_COOKIE, readCookie } from "./session.service.js";
import {
  hashPassword,
  verifyPassword,
  decoyVerify,
  allowCredentialAttempt,
} from "./password.js";
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
 * Minimum length is the only strength rule we enforce. Composition rules
 * ("one digit, one symbol") push users toward predictable mangling; length is
 * what actually costs an offline attacker, and 12 is the NIST floor for a
 * secret with no other factor behind it.
 */
const MIN_PASSWORD_LENGTH = 12;

/**
 * Version of the terms a new account accepts. Bump this whenever the published
 * documents change materially: existing rows keep the version they actually
 * agreed to, which is the whole point of storing it rather than a boolean.
 * Must match the `version` field of the documents in apps/web/lib/legal.ts.
 */
const CURRENT_TERMS_VERSION = "1.0";

/**
 * Caller address. Express only trusts X-Forwarded-For when `trust proxy` is
 * set, which it is not here — behind Caddy that would make `req.ip` the proxy
 * for everyone, collapsing the rate limiter into a single global bucket. So we
 * read the header ourselves and take the FIRST hop, the one the edge appended.
 */
function clientIp(req: Request): string {
  const fwd = req.header("x-forwarded-for");
  const first = fwd?.split(",")[0]?.trim();
  return first || req.ip || req.socket.remoteAddress || "unknown";
}

const RegisterBody = z.object({
  // Normalize before validating: a pasted address often carries whitespace and
  // mixed case, and the row is keyed on email — "A@b.com " must not become a
  // second account next to "a@b.com".
  email: z.string().trim().toLowerCase().email("a valid email address is required"),
  password: z
    .string()
    .min(MIN_PASSWORD_LENGTH, `password must be at least ${MIN_PASSWORD_LENGTH} characters`),
  name: z.string().trim().min(1).optional(),
  // Consent is a server-side fact or it is nothing. A checkbox validated only
  // in the browser proves nothing after the fact, so the client must assert it
  // explicitly and we record WHICH version was accepted, WHEN, and from where.
  acceptedTerms: z.literal(true, {
    errorMap: () => ({ message: "the terms of use must be accepted" }),
  }),
  termsVersion: z.string().trim().min(1).max(16).default(CURRENT_TERMS_VERSION),
});

const LoginBody = z.object({
  email: z.string().trim().toLowerCase().email("a valid email address is required"),
  password: z.string().min(1),
});

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
        create: {
          email: p.email,
          name: p.name,
          avatarUrl: p.avatarUrl,
          // OAuth sign-up has no checkbox: the provider's consent screen is the
          // only click. Acceptance is therefore recorded as of first sign-in,
          // with the terms version in force at that moment — weaker evidence
          // than an explicit tick, but dated and attributable, which a silent
          // account creation would not be.
          termsAcceptedAt: new Date(),
          termsVersion: CURRENT_TERMS_VERSION,
        },
      });
      await tx.authIdentity.upsert({
        where: { provider_providerAccountId: { provider: p.provider, providerAccountId: p.id } },
        update: {},
        create: { userId: user.id, provider: p.provider, providerAccountId: p.id },
      });
      const organizationId = await ensurePersonalOrg(tx, user.id, p.login, p.name);
      return { userId: user.id, organizationId };
    });

    await this.issueSession(userId, organizationId, res);
    res.redirect(process.env.WEB_URL ?? "http://localhost:3000");
  }

  // ── Email + password ──────────────────────────────────────────────────────

  /**
   * Sign-up. Answers JSON, not a redirect: the web form posts this with fetch
   * and needs to render field errors in place, unlike the OAuth callbacks which
   * are top-level browser navigations.
   */
  @Post("register")
  @HttpCode(200)
  async register(
    @Req() req: Request,
    @Res() res: Response,
    @Body(new ZodBody(RegisterBody)) body: z.infer<typeof RegisterBody>,
  ): Promise<void> {
    this.throttle(req);

    // Hash before opening the transaction — scrypt burns tens of milliseconds
    // of CPU and must not pin a database connection while it runs.
    const passwordHash = await hashPassword(body.password);

    let created: { userId: string; organizationId: string };
    try {
      created = await this.prisma.$transaction(async (tx) => {
        const existing = await tx.user.findUnique({ where: { email: body.email } });
        // Sign-up is the one place where telling the truth about an existing
        // address is right: the user needs to know to log in instead, and the
        // address is one they already control (or can discover) either way.
        if (existing) throw new ConflictException({ error: "email_taken" });

        const user = await tx.user.create({
          data: {
            email: body.email,
            name: body.name ?? null,
            passwordHash,
            termsAcceptedAt: new Date(),
            termsVersion: body.termsVersion,
            // Recorded for the same reason a paper contract records a place:
            // it is what makes the acceptance attributable later. Kept as the
            // raw remote address, never used to profile.
            termsAcceptedIp: clientIp(req),
          },
        });
        // The login identity, kept separate from repo-access Connections. Keyed
        // on the normalized email so a later OAuth login on the same address
        // lands on this user instead of forking a second one.
        await tx.authIdentity.create({
          data: { userId: user.id, provider: "email", providerAccountId: body.email },
        });
        const organizationId = await ensurePersonalOrg(
          tx,
          user.id,
          slugLoginFromEmail(body.email),
          body.name ?? null,
        );
        return { userId: user.id, organizationId };
      });
    } catch (err) {
      // Two concurrent sign-ups for the same address: the findUnique above lost
      // the race, and the unique index is the real authority.
      if (isUniqueViolation(err)) throw new ConflictException({ error: "email_taken" });
      throw err;
    }

    await this.issueSession(created.userId, created.organizationId, res);
    res.json({ ok: true });
  }

  /**
   * Sign-in. Every failure returns the SAME 401 body whether the address is
   * unknown, has no password (OAuth-only account), or the password is wrong —
   * anything else turns this endpoint into an account-existence oracle.
   */
  @Post("login")
  @HttpCode(200)
  async login(
    @Req() req: Request,
    @Res() res: Response,
    @Body(new ZodBody(LoginBody)) body: z.infer<typeof LoginBody>,
  ): Promise<void> {
    this.throttle(req);

    // Read + verify outside any transaction: the KDF dominates this request and
    // holding a connection through it would starve the pool under a burst.
    // `users` is not a tenant table, so it is legitimately read outside tenant().
    const user = await this.prisma.user.findUnique({ where: { email: body.email } });
    if (!user?.passwordHash) {
      // Spend the same KDF round we would have spent on a real digest, so
      // response time does not leak whether the account exists.
      await decoyVerify(body.password);
      throw new UnauthorizedException({ error: "invalid_credentials" });
    }
    if (!(await verifyPassword(body.password, user.passwordHash))) {
      throw new UnauthorizedException({ error: "invalid_credentials" });
    }

    // An account can predate its org (invited, then never onboarded), so resolve
    // it through the same path the OAuth login uses rather than assuming one.
    const organizationId = await this.prisma.$transaction((tx) =>
      ensurePersonalOrg(tx, user.id, slugLoginFromEmail(user.email), user.name),
    );

    await this.issueSession(user.id, organizationId, res);
    res.json({ ok: true });
  }

  /** 429 once an IP burns its credential budget. See password.ts for the caveats. */
  private throttle(req: Request): void {
    const ip = clientIp(req);
    if (!allowCredentialAttempt(ip)) {
      throw new HttpException({ error: "rate_limited" }, HttpStatus.TOO_MANY_REQUESTS);
    }
  }

  /** Mint the session and emit the exact same cookie pair as the OAuth path. */
  private async issueSession(
    userId: string,
    organizationId: string,
    res: Response,
  ): Promise<void> {
    const sessionToken = await this.sessions.create(userId, organizationId);
    const secure = (process.env.WEB_URL ?? "").startsWith("https") ? "; Secure" : "";
    res.setHeader("Set-Cookie", [
      `${SESSION_COOKIE}=${sessionToken}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${30 * 24 * 60 * 60}${secure}`,
      `auditer_oauth_state=; Path=/; Max-Age=0`,
    ]);
  }

  /**
   * Whoami. Returns the user and the active org alongside the ids so the web
   * shell can paint the account menu and the org name on first load instead of
   * firing two more round-trips behind every navigation.
   *
   * Unauthenticated stays `{ authenticated: false }` and nothing else — an
   * expired session must not leak who it used to belong to.
   */
  @Get("session")
  async session(@Req() req: Request) {
    const token = readCookie(req.header("cookie"), SESSION_COOKIE);
    if (!token) return { authenticated: false };
    const resolved = await this.sessions.resolve(token);
    if (!resolved) return { authenticated: false };

    const user = await this.prisma.user.findUnique({
      where: { id: resolved.userId },
      select: { id: true, email: true, name: true, avatarUrl: true },
    });
    // `organizations` IS RLS-scoped, so this read goes through tenant() — a
    // direct findUnique would come back empty under the app role.
    const org = await this.prisma.tenant(resolved.organizationId, (tx) =>
      tx.organization.findUnique({
        where: { id: resolved.organizationId },
        select: { id: true, name: true, slug: true },
      }),
    );

    return { authenticated: true, ...resolved, user, org };
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

// ── Onboarding helpers ──────────────────────────────────────────────────────

/**
 * Return the user's organization, creating a personal one on first sight.
 *
 * Shared by every login path (GitHub, GitLab, email) so the slug is minted in
 * exactly one place. The random suffix is not decoration: logins collide across
 * providers and across email domains — the "alice" on GitHub and the owner of
 * alice@example.com are two different people, and `slug` is unique.
 */
async function ensurePersonalOrg(
  tx: TenantClient,
  userId: string,
  login: string,
  name: string | null,
): Promise<string> {
  let membership = await tx.membership.findFirst({ where: { userId } });
  if (!membership) {
    const slug = `${login}-${randomBytes(3).toString("hex")}`.toLowerCase();
    const org = await tx.organization.create({
      data: { slug, name: `${name ?? login}'s org`, ownerUserId: userId },
    });
    membership = await tx.membership.create({
      data: { userId, organizationId: org.id, role: "owner" },
    });
  }
  return membership.organizationId;
}

/**
 * Slug-safe stand-in for the OAuth `login` handle. Email local parts allow `+`,
 * dots and quoted forms that have no business in a URL, so keep only what a
 * slug can carry and never emit an empty string.
 */
function slugLoginFromEmail(email: string): string {
  const local = email.split("@")[0] ?? "";
  const cleaned = local.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return cleaned || "user";
}

/** Prisma unique-constraint violation, duck-typed to avoid an instanceof across the generated client. */
function isUniqueViolation(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: unknown }).code === "P2002";
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
