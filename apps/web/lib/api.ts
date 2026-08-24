/**
 * Browser client for the api. Same-origin: /api/* is rewritten to the NestJS
 * api by next.config.mjs, so the session cookie rides along on its own and
 * there is no token handling in the browser at all.
 */

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
  return res.json() as Promise<T>;
}

/**
 * Same request, no body expected. The deletion endpoints answer 204, and
 * `res.json()` on an empty body throws — which would report every successful
 * deletion as a failure.
 */
async function reqVoid(path: string, init?: RequestInit): Promise<void> {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${body}`);
  }
}

export interface Repo {
  id: string;
  fullName: string;
  provider: string;
  defaultBranch: string;
  primaryLanguage: string | null;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
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

export interface AuditRunSummary extends AuditRun {
  repository: { id: string; fullName: string; provider: string } | null;
  counts: SeverityCounts;
}

export interface Overview {
  repos: number;
  runs: number;
  lastRun: {
    id: string;
    status: string;
    riskScore: number | null;
    createdAt: string;
    repository: { fullName: string } | null;
  } | null;
  openCritical: number;
  openHigh: number;
  avgScore: number | null;
  trend: Array<{ runId: string; createdAt: string; riskScore: number }>;
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
  overview: () => req<Overview>("/overview"),
  listRepos: () => req<Repo[]>("/repos"),
  listAudits: () => req<AuditRunSummary[]>("/audits"),
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
      body: JSON.stringify({ format: "html" }),
    }),
  getReport: (runId: string) => req<Report>(`/reports/${runId}`),

  /* ── Effacement et portabilité ─────────────────────────────────────────
     Les quatre suppressions annoncées dans la politique de confidentialité,
     plus l'export. Toutes sont irréversibles côté serveur : l'appelant DOIT
     demander une confirmation explicite avant de les appeler. */

  /** Supprime un dépôt importé et tous ses relevés. */
  deleteRepo: (id: string) => reqVoid(`/repos/${id}`, { method: "DELETE" }),
  /** Supprime un relevé, ses findings, ses rapports et ses artefacts. */
  deleteAudit: (id: string) => reqVoid(`/audits/${id}`, { method: "DELETE" }),
  /** Révoque une connexion : détruit le jeton chiffré, retire les dépôts liés. */
  deleteConnection: (id: string) => reqVoid(`/connections/${id}`, { method: "DELETE" }),
  /** Supprime le compte. `confirmEmail` est vérifié côté serveur. */
  deleteAccount: (confirmEmail: string) =>
    req<{ ok: true; organizations: number; storageObjects: number }>("/account", {
      method: "DELETE",
      body: JSON.stringify({ confirmEmail }),
    }),
};

/**
 * Export JSON du compte et de l'organisation. C'est un lien, pas un fetch : le
 * serveur répond en pièce jointe et le navigateur enregistre le fichier sans
 * qu'on ait à le charger en mémoire ni à fabriquer un blob.
 */
export const ACCOUNT_EXPORT_PATH = "/api/account/export";

export interface Report {
  id: string;
  status: string;
  summary: unknown;
  contentType: string | null;
  sizeBytes: number | null;
  /** Same-origin api path; null until the render has finished. */
  downloadPath: string | null;
}

/** SSE endpoint for a run's live progress (cookie-authorised like the rest). */
export function eventsUrl(runId: string): string {
  return `/api/audits/${runId}/events`;
}

/* ── Shared display helpers ─────────────────────────────────────────────── */

/** Score → letter grade. Mirrors the engine's scale; the number is authoritative. */
export function grade(score: number | null): string {
  if (score === null) return "—";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  if (score >= 50) return "E";
  return "F";
}

export function gradeTone(score: number | null): string {
  if (score === null) return "text-mute";
  if (score >= 80) return "text-acid";
  if (score >= 60) return "text-medium";
  if (score >= 50) return "text-high";
  return "text-critical";
}

export const STATUS_FR: Record<string, string> = {
  queued: "en file",
  cloning: "clonage",
  scanning: "analyse",
  analyzing: "corrélation",
  reporting: "rédaction",
  done: "terminé",
  completed_with_errors: "terminé, erreurs",
  failed: "échec",
  canceled: "annulé",
};

export const SEVERITY_FR: Record<string, string> = {
  critical: "critique",
  high: "élevé",
  medium: "moyen",
  low: "faible",
  info: "info",
};

export const TRIAGE_FR: Record<string, string> = {
  open: "ouvert",
  false_positive: "faux positif",
  ignored: "ignoré",
  accepted: "accepté",
  fixed: "corrigé",
};

/** Relative time in French, for run timestamps. */
export function ago(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "à l'instant";
  const m = Math.floor(s / 60);
  if (m < 60) return `il y a ${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `il y a ${h} h`;
  const d = Math.floor(h / 24);
  if (d < 30) return `il y a ${d} j`;
  return new Date(iso).toLocaleDateString("fr-FR", { day: "2-digit", month: "short", year: "numeric" });
}
