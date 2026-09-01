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

/**
 * Une exécution de moteur, telle que la base la conserve.
 *
 * C'est la trace DURABLE d'un relevé : elle survit à une actualisation, à une
 * coupure réseau et à la fermeture de l'onglet, contrairement aux événements du
 * flux qui ne vivent que le temps de la connexion.
 *
 * `status: "pending"` est un moteur inscrit au plan et pas encore démarré —
 * c'est ce qui rend l'avancement calculable, et vrai.
 */
export interface Scan {
  id: string;
  scannerId: string;
  pillar: string;
  tool: string;
  toolVersion: string | null;
  imageDigest: string | null;
  status: "pending" | "running" | "success" | "partial" | "failed" | "skipped";
  exitCode: number | null;
  exitClass: string | null;
  /** Ce que le moteur a dit en échouant. Caviardé par la purge à 90 jours. */
  error: unknown;
  stats: unknown;
  /** Sortie brute conservée, quand il y en a une. */
  rawArtifactId: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  createdAt: string;
}

export interface FindingQuery {
  severity?: string;
  triage?: string;
  pillar?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

export interface FindingPage {
  items: Finding[];
  /** Nombre de findings correspondant au filtre courant, toutes pages confondues. */
  total: number;
  /** Histogramme du relevé, INDÉPENDANT du filtre de sévérité : ce sont les
   *  compteurs des boutons eux-mêmes, et en sélectionner un ne doit pas mettre
   *  les autres à zéro. */
  counts: Record<string, number>;
  /** Findings non triés du relevé entier. */
  openCount: number;
  limit: number;
  offset: number;
}

export interface Connection {
  id: string;
  provider: string;
  kind: string;
  externalAccountId: string | null;
  status: string;
}

/**
 * Cible d'un pilier réseau (DAST/UX). Elle n'est scannable qu'une fois
 * `verificationStatus === "verified"` : l'api refuse la mise en file et le
 * worker revérifie avant de lancer quoi que ce soit. Le jeton est la valeur
 * exacte à publier en TXT sur `apexDomain`.
 */
export interface Target {
  id: string;
  kind: "domain" | "origin" | "api";
  value: string;
  apexDomain: string | null;
  verificationMethod: string | null;
  verificationStatus: "unverified" | "pending" | "verified" | "revoked";
  verificationToken: string | null;
  resolvedIps: string[];
  repositoryId: string | null;
  createdAt: string;
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
  /* ── Cibles réseau ─────────────────────────────────────────────────────
     Le relevé réseau vise un HÔTE, pas un dépôt : c'est un tiers tant que sa
     propriété n'est pas prouvée. D'où ces trois appels, et pas un raccourci. */

  listTargets: () => req<Target[]>("/targets"),
  createTarget: (body: { kind: "domain" | "origin" | "api"; value: string; repositoryId?: string }) =>
    req<Target>("/targets", { method: "POST", body: JSON.stringify(body) }),
  /** Relit le TXT. `verified: false` renvoie l'enregistrement attendu en clair. */
  verifyTarget: (id: string) =>
    req<{ verified: boolean; hint?: string }>(`/targets/${id}/verify`, { method: "POST" }),

  createAudit: (body: { repositoryId?: string; targetId?: string; pillars: string[] }) =>
    req<{ runId: string; status: string }>("/audits", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  getAudit: (id: string) => req<AuditRun>(`/audits/${id}`),
  /** La trace persistée du relevé — une ligne par moteur prévu. */
  listScans: (id: string) => req<Scan[]>(`/audits/${id}/scans`),
  /**
   * Demande l'arrêt d'un relevé en cours.
   *
   * Lève un drapeau que le worker consulte ENTRE deux moteurs : un scanner déjà
   * lancé va au bout. L'interface doit le dire — un bouton qui promet un arrêt
   * immédiat mentirait sur ce que fait le système.
   */
  cancelAudit: (id: string) =>
    req<{ ok: boolean }>(`/audits/${id}/cancel`, { method: "POST" }),
  /**
   * Une PAGE de findings. Le filtre, la recherche et le décompte sont côté
   * serveur — appliquer une recherche à la seule page visible ferait dire
   * « aucun résultat » alors que le finding existe deux pages plus loin.
   */
  listFindings: (id: string, params: FindingQuery = {}) => {
    const qs = new URLSearchParams();
    if (params.severity) qs.set("severity", params.severity);
    if (params.triage) qs.set("triage", params.triage);
    if (params.pillar) qs.set("pillar", params.pillar);
    if (params.q) qs.set("q", params.q);
    if (params.limit != null) qs.set("limit", String(params.limit));
    if (params.offset != null) qs.set("offset", String(params.offset));
    const suffix = qs.toString();
    return req<FindingPage>(`/audits/${id}/findings${suffix ? `?${suffix}` : ""}`);
  },
  setTriage: (fingerprint: string, status: string) =>
    req<{ ok: boolean }>("/triage", {
      method: "POST",
      body: JSON.stringify({ fingerprint, status }),
    }),
  /**
   * `document` names the DELIVERABLE, not the file type — one run produces four.
   * The api still accepts the legacy container names, but nothing new should
   * send them.
   */
  exportReport: (runId: string, document: ReportDocument = "technique") =>
    req<{ reportId: string; document: ReportDocument }>(`/reports/${runId}/export`, {
      method: "POST",
      body: JSON.stringify({ format: document }),
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

/** The four deliverables of a run. Mirrors ReportDocument in @auditer/types. */
export type ReportDocument = "technique" | "dirigeant" | "attestation" | "progression";

export interface Report {
  id: string;
  status: string;
  summary: unknown;
  /** Which of the four this artifact is; null until one has been rendered. */
  document: ReportDocument | null;
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
