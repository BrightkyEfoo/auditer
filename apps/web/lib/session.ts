import { cookies } from "next/headers";

/**
 * Server-side session read. The browser never talks to the api directly for
 * this — the page is rendered on the server, so we forward the request cookies
 * to the api and get the identity before the first byte is sent. That is what
 * lets the app shell render already-authenticated instead of flashing a
 * logged-out state.
 */
export interface SessionUser {
  id: string;
  email: string;
  name: string | null;
  avatarUrl: string | null;
}
export interface SessionOrg {
  id: string;
  name: string;
  slug: string;
}
export interface Session {
  userId: string;
  organizationId: string;
  user?: SessionUser;
  org?: SessionOrg;
}

function apiBase(): string {
  return process.env.API_URL ?? "http://localhost:3001";
}

export async function getSession(): Promise<Session | null> {
  const jar = await cookies();
  const cookie = jar.toString();
  if (!cookie) return null;
  try {
    const res = await fetch(`${apiBase()}/api/auth/session`, {
      headers: { cookie },
      cache: "no-store",
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { authenticated?: boolean } & Session;
    return data.authenticated ? data : null;
  } catch {
    // The api being unreachable must degrade to "logged out", never to a 500
    // on the marketing pages.
    return null;
  }
}

/** Fetches an api route server-side with the caller's cookies attached. */
export async function apiGet<T>(path: string): Promise<T | null> {
  const jar = await cookies();
  try {
    const res = await fetch(`${apiBase()}/api${path}`, {
      headers: { cookie: jar.toString() },
      cache: "no-store",
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}
