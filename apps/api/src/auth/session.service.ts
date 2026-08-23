import { Injectable } from "@nestjs/common";
import { createHash, randomBytes } from "node:crypto";
import { PrismaService } from "../infra/prisma.service.js";

/**
 * Opaque cookie sessions. We store only a SHA-256 of the token, never the token
 * itself. A session binds a user to an active organization; the AuthGuard reads
 * it and hands (userId, organizationId) to the tenant layer.
 */
export const SESSION_COOKIE = "auditer_session";
const TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export interface Resolved {
  userId: string;
  organizationId: string;
}

@Injectable()
export class SessionService {
  constructor(private readonly prisma: PrismaService) {}

  private hash(token: string): string {
    return createHash("sha256").update(token).digest("hex");
  }

  /** Create a session; returns the raw token to set as the cookie value. */
  async create(userId: string, organizationId: string): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    await this.prisma.session.create({
      data: {
        tokenHash: this.hash(token),
        userId,
        organizationId,
        expiresAt: new Date(Date.now() + TTL_MS),
      },
    });
    return token;
  }

  async resolve(token: string): Promise<Resolved | null> {
    const s = await this.prisma.session.findUnique({
      where: { tokenHash: this.hash(token) },
    });
    if (!s || s.expiresAt.getTime() < Date.now()) return null;
    return { userId: s.userId, organizationId: s.organizationId };
  }

  async destroy(token: string): Promise<void> {
    await this.prisma.session
      .deleteMany({ where: { tokenHash: this.hash(token) } })
      .catch(() => {});
  }
}

/** Minimal cookie parse (avoids a cookie-parser dependency). */
export function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return undefined;
}
