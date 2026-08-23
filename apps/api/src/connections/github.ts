import { createAppAuth } from "@octokit/auth-app";
import { createHmac } from "node:crypto";

/**
 * GitHub App helpers for the SaaS connect flow. The App (not a PAT) is how a
 * SaaS gets scoped, revocable access to a user's repos: the user *installs* the
 * App on their org/selected repos, and we mint short-lived installation tokens
 * on demand — never storing a long-lived credential.
 */

function secret(): string {
  return process.env.BETTER_AUTH_SECRET ?? "dev-secret";
}

/** Sign the orgId into the install `state` so the post-install callback (which
 *  carries no session) can attribute the installation to the right org. */
export function signState(organizationId: string): string {
  const mac = createHmac("sha256", secret()).update(organizationId).digest("hex").slice(0, 16);
  return Buffer.from(`${organizationId}.${mac}`).toString("base64url");
}

export function verifyState(state: string): string | null {
  try {
    const [org, mac] = Buffer.from(state, "base64url").toString("utf8").split(".");
    if (!org || !mac) return null;
    const expected = createHmac("sha256", secret()).update(org).digest("hex").slice(0, 16);
    return mac === expected ? org : null;
  } catch {
    return null;
  }
}

/** URL that starts the App installation (user picks org + repos on GitHub). */
export function installUrl(organizationId: string): string {
  const slug = process.env.GITHUB_APP_SLUG ?? "";
  const state = signState(organizationId);
  return `https://github.com/apps/${slug}/installations/new?state=${state}`;
}

/** Mint a short-lived installation token (never persisted). */
export async function installationToken(installationId: string): Promise<string> {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY?.replace(/\\n/g, "\n");
  if (!appId || !privateKey) throw new Error("GitHub App not configured");
  const auth = createAppAuth({ appId, privateKey });
  const { token } = await auth({ type: "installation", installationId: Number(installationId) });
  return token;
}

export interface GithubRepo {
  externalRepoId: string;
  fullName: string;
  defaultBranch: string;
  visibility: string;
  primaryLanguage: string | null;
}

/** List the repos this installation can access (what the user selected). */
export async function listInstallationRepos(installationId: string): Promise<GithubRepo[]> {
  const token = await installationToken(installationId);
  const out: GithubRepo[] = [];
  let page = 1;
  for (;;) {
    const res = await fetch(
      `https://api.github.com/installation/repositories?per_page=100&page=${page}`,
      { headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json" } },
    );
    if (!res.ok) throw new Error(`github repositories ${res.status}`);
    const data = (await res.json()) as {
      repositories: {
        id: number;
        full_name: string;
        default_branch: string;
        private: boolean;
        language: string | null;
      }[];
    };
    for (const r of data.repositories) {
      out.push({
        externalRepoId: String(r.id),
        fullName: r.full_name,
        defaultBranch: r.default_branch,
        visibility: r.private ? "private" : "public",
        primaryLanguage: r.language,
      });
    }
    if (data.repositories.length < 100) break;
    page += 1;
  }
  return out;
}

/** Fetch the installation's account (org/user) login for display. */
export async function installationAccount(installationId: string): Promise<string | null> {
  const appId = process.env.GITHUB_APP_ID;
  const privateKey = process.env.GITHUB_APP_PRIVATE_KEY?.replace(/\\n/g, "\n");
  if (!appId || !privateKey) return null;
  try {
    const auth = createAppAuth({ appId, privateKey });
    const { token } = await auth({ type: "app" });
    const res = await fetch(`https://api.github.com/app/installations/${installationId}`, {
      headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json" },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { account?: { login?: string } };
    return data.account?.login ?? null;
  } catch {
    return null;
  }
}
