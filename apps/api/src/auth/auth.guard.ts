import {
  Injectable,
  type CanActivate,
  type ExecutionContext,
  UnauthorizedException,
  createParamDecorator,
} from "@nestjs/common";
import type { Request } from "express";
import { SessionService, SESSION_COOKIE, readCookie } from "./session.service.js";

/**
 * Request auth context. Resolves the current user + active organization and
 * attaches it to the request. Downstream services pass `organizationId` into
 * PrismaService.tenant() so RLS scopes every query.
 *
 * Primary path: validate the cookie session (SessionService). This single
 * chokepoint is where better-auth would slot in later with no controller change.
 *
 * Dev fallback: `x-user-id` / `x-org-id` headers. This is a COMPLETE auth
 * bypass — anyone who can reach the api can claim any organization — so it is
 * gated twice, and the two gates are independent on purpose:
 *
 *   1. AUTH_DEV_HEADERS must be exactly "1" (opt-in, never a default), and
 *   2. NODE_ENV must not be "production".
 *
 * The second gate exists because the first one is a string that travels through
 * a compose file, a CI secret and a shell — three places where it can silently
 * become empty and fall back to a default. A production deploy that loses the
 * variable must fail closed, not open.
 */
export interface AuthContext {
  userId: string;
  organizationId: string;
}

const CUID_RE = /^[a-z0-9]{20,40}$/i;

/** Evaluated per request, not at import time, so tests can flip the env. */
function devHeadersAllowed(): boolean {
  return process.env.AUTH_DEV_HEADERS === "1" && process.env.NODE_ENV !== "production";
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly sessions: SessionService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request & { auth?: AuthContext }>();

    // 1. Cookie session (the real path).
    const token = readCookie(req.header("cookie"), SESSION_COOKIE);
    if (token) {
      const resolved = await this.sessions.resolve(token);
      if (resolved) {
        req.auth = resolved;
        return true;
      }
    }

    // 2. Dev header fallback — opt-in AND non-production only.
    if (devHeadersAllowed()) {
      const userId = req.header("x-user-id");
      const organizationId = req.header("x-org-id");
      if (userId && organizationId && CUID_RE.test(organizationId)) {
        req.auth = { userId, organizationId };
        return true;
      }
    }

    throw new UnauthorizedException("missing or invalid session");
  }
}

/** Inject the resolved AuthContext into a controller handler. */
export const Auth = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthContext => {
    const req = ctx.switchToHttp().getRequest<Request & { auth?: AuthContext }>();
    if (!req.auth) throw new UnauthorizedException();
    return req.auth;
  },
);
