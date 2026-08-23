import { signState, verifyState } from "./github.js";

/**
 * GitLab OAuth helpers. Unlike GitHub (App installation → short-lived
 * installation tokens), GitLab uses OAuth: the user authorizes and we receive
 * an access token (~2h) + a rotating refresh token, which we store encrypted
 * and refresh on demand. Works for gitlab.com and self-managed instances via
 * GITLAB_URL.
 */

export { signState, verifyState };

export function gitlabBase(): string {
  return (process.env.GITLAB_URL ?? "https://gitlab.com").replace(/\/+$/, "");
}

function redirectUri(kind: "login" | "connect"): string {
  const web = process.env.WEB_URL ?? "http://localhost:3000";
  return kind === "login"
    ? `${web}/api/auth/gitlab/callback`
    : `${web}/api/connections/gitlab/callback`;
}

/** Authorize URL. `connect` requests repo scopes; `login` just identity. */
export function authorizeUrl(kind: "login" | "connect", state: string): string {
  const clientId = process.env.GITLAB_CLIENT_ID ?? "";
  const scope = kind === "connect" ? "read_api read_repository" : "read_user";
  const u = new URL(`${gitlabBase()}/oauth/authorize`);
  u.searchParams.set("client_id", clientId);
  u.searchParams.set("redirect_uri", redirectUri(kind));
  u.searchParams.set("response_type", "code");
  u.searchParams.set("scope", scope);
  u.searchParams.set("state", state);
  return u.toString();
}

export interface OAuthTokens {
  accessToken: string;
  refreshToken: string;
  /** epoch ms when the access token expires. */
  expiresAt: number;
}

async function tokenRequest(body: Record<string, string>): Promise<OAuthTokens> {
  const res = await fetch(`${gitlabBase()}/oauth/token`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      client_id: process.env.GITLAB_CLIENT_ID,
      client_secret: process.env.GITLAB_CLIENT_SECRET,
      ...body,
    }),
  });
  if (!res.ok) throw new Error(`gitlab oauth ${res.status}: ${await res.text()}`);
  const d = (await res.json()) as {
    access_token: string;
    refresh_token: string;
    expires_in: number;
  };
  return {
    accessToken: d.access_token,
    refreshToken: d.refresh_token,
    expiresAt: Date.now() + (d.expires_in ?? 7200) * 1000,
  };
}

export function exchangeCode(code: string, kind: "login" | "connect"): Promise<OAuthTokens> {
  return tokenRequest({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri(kind),
  });
}

export function refreshTokens(refreshToken: string): Promise<OAuthTokens> {
  return tokenRequest({ grant_type: "refresh_token", refresh_token: refreshToken });
}

export interface GitlabUser {
  id: string;
  username: string;
  name: string | null;
  email: string;
  avatarUrl: string | null;
}

export async function fetchUser(accessToken: string): Promise<GitlabUser> {
  const res = await fetch(`${gitlabBase()}/api/v4/user`, {
    headers: { authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error(`gitlab user ${res.status}`);
  const u = (await res.json()) as {
    id: number;
    username: string;
    name: string | null;
    email: string | null;
    avatar_url: string | null;
  };
  return {
    id: String(u.id),
    username: u.username,
    name: u.name,
    email: u.email ?? `${u.username}@users.noreply.gitlab.com`,
    avatarUrl: u.avatar_url,
  };
}

export interface GitlabRepo {
  externalRepoId: string;
  fullName: string;
  defaultBranch: string;
  visibility: string;
  primaryLanguage: string | null;
}

/** List projects the user is a member of. */
export async function listProjects(accessToken: string): Promise<GitlabRepo[]> {
  const out: GitlabRepo[] = [];
  let page = 1;
  for (;;) {
    const res = await fetch(
      `${gitlabBase()}/api/v4/projects?membership=true&simple=true&per_page=100&page=${page}&order_by=last_activity_at`,
      { headers: { authorization: `Bearer ${accessToken}` } },
    );
    if (!res.ok) throw new Error(`gitlab projects ${res.status}`);
    const data = (await res.json()) as {
      id: number;
      path_with_namespace: string;
      default_branch: string | null;
      visibility: string;
    }[];
    for (const p of data) {
      out.push({
        externalRepoId: String(p.id),
        fullName: p.path_with_namespace,
        defaultBranch: p.default_branch ?? "main",
        visibility: p.visibility,
        primaryLanguage: null,
      });
    }
    if (data.length < 100 || page >= 10) break;
    page += 1;
  }
  return out;
}
