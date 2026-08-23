import type { PrismaClient } from "@auditer/db";
import { withTenant } from "@auditer/db";
import { type Kek, seal, open as openSecret } from "@auditer/crypto";

/**
 * GitLab OAuth token handling for cloning. Access tokens are ~2h and refresh
 * tokens rotate, so before each clone we refresh if needed and persist the new
 * pair (encrypted). Mirrors the api-side logic; kept here so the worker never
 * depends on the api.
 */

function gitlabBase(): string {
  return (process.env.GITLAB_URL ?? "https://gitlab.com").replace(/\/+$/, "");
}

interface Tokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

async function refresh(refreshToken: string): Promise<Tokens> {
  const res = await fetch(`${gitlabBase()}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_id: process.env.GITLAB_CLIENT_ID,
      client_secret: process.env.GITLAB_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    }),
  });
  if (!res.ok) throw new Error(`gitlab refresh ${res.status}`);
  const d = (await res.json()) as { access_token: string; refresh_token: string; expires_in: number };
  return {
    accessToken: d.access_token,
    refreshToken: d.refresh_token,
    expiresAt: Date.now() + (d.expires_in ?? 7200) * 1000,
  };
}

/** Return a valid GitLab access token for cloning, refreshing if expired. */
export async function validGitlabToken(
  prisma: PrismaClient,
  kek: Kek,
  organizationId: string,
  conn: {
    id: string;
    encPat: string | null;
    encRefreshToken: string | null;
    tokenExpiresAt: Date | null;
  },
): Promise<string | undefined> {
  const fresh = conn.tokenExpiresAt && conn.tokenExpiresAt.getTime() - 60_000 > Date.now();
  if (fresh && conn.encPat) return openSecret(kek, conn.encPat);
  if (!conn.encRefreshToken) return conn.encPat ? openSecret(kek, conn.encPat) : undefined;

  const refreshTok = await openSecret(kek, conn.encRefreshToken);
  const t = await refresh(refreshTok);
  const [encAccess, encRefresh] = await Promise.all([
    seal(kek, t.accessToken),
    seal(kek, t.refreshToken),
  ]);
  await withTenant(prisma, organizationId, (tx) =>
    tx.connection.update({
      where: { id: conn.id },
      data: {
        encPat: encAccess,
        encRefreshToken: encRefresh,
        tokenExpiresAt: new Date(t.expiresAt),
      },
    }),
  );
  return t.accessToken;
}
