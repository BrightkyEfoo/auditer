/**
 * Thin client for the api. Same-origin (/api/* is rewritten to the NestJS api),
 * so cookies flow. Dev identity is injected via headers here; in production the
 * web BFF attaches the real better-auth session and these headers go away.
 */

const DEV_ORG = process.env.NEXT_PUBLIC_DEV_ORG_ID ?? "";
const DEV_USER = process.env.NEXT_PUBLIC_DEV_USER_ID ?? "";

function devHeaders(): Record<string, string> {
  // TODO(auth): remove once better-auth session is wired end-to-end.
  return DEV_ORG && DEV_USER
    ? { "x-org-id": DEV_ORG, "x-user-id": DEV_USER }
    : {};
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...devHeaders(),
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
  return res.json() as Promise<T>;
}

export interface Repo {
  id: string;
  fullName: string;
  provider: string;
  defaultBranch: string;
  primaryLanguage: string | null;
}

export interface AuditRun {
  id: string;
  status: string;
  pillars: string[];
  riskScore: number | null;
  scoringVersion: string | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface Finding {
  id: string;
  pillar: string;
  tool: string;
  ruleId: string;
  severity: string;
  cvssScore: number | null;
  title: string;
  description: string;
  cwe: string[];
  vulnIds: string[];
  evidence: string | null;
  fingerprint: string;
  sourceCount: number;
  triageStatus: string;
  aiExplanation: string | null;
  aiRemediation: string | null;
  aiPriority: number | null;
  aiConfidence: number | null;
  aiNeedsHuman: boolean;
}

export interface Connection {
  id: string;
  provider: string;
  kind: string;
  externalAccountId: string | null;
  status: string;
}

export interface RemoteRepo {
  externalRepoId: string;
  fullName: string;
  defaultBranch: string;
  visibility: string;
  primaryLanguage: string | null;
}

export const api = {
  listRepos: () => req<Repo[]>("/repos"),
  listConnections: () => req<Connection[]>("/connections"),
  listConnectionRepos: (connectionId: string) =>
    req<RemoteRepo[]>(`/connections/${connectionId}/repos`),
  importConnectionRepo: (connectionId: string, repo: RemoteRepo) =>
    req<Repo>(`/connections/${connectionId}/import`, {
      method: "POST",
      body: JSON.stringify(repo),
    }),
  createAudit: (body: { repositoryId?: string; targetId?: string; pillars: string[] }) =>
    req<{ runId: string; status: string }>("/audits", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  getAudit: (id: string) => req<AuditRun>(`/audits/${id}`),
  listFindings: (id: string) => req<Finding[]>(`/audits/${id}/findings`),
  setTriage: (fingerprint: string, status: string) =>
    req<{ ok: boolean }>("/triage", {
      method: "POST",
      body: JSON.stringify({ fingerprint, status }),
    }),
  exportReport: (runId: string) =>
    req<{ reportId: string }>(`/reports/${runId}/export`, {
      method: "POST",
      body: JSON.stringify({ format: "pdf" }),
    }),
};

/** SSE URL for a run's live progress (dev headers can't ride EventSource; the
 *  api authorizes via the same rewrite + cookie/session in production). */
export function eventsUrl(runId: string): string {
  return `/api/audits/${runId}/events`;
}
