import { initContract } from "@ts-rest/core";
import { z } from "zod";
import {
  Pillar,
  Severity,
  AuditStatus,
  TriageStatus,
  Provider,
} from "@auditer/types";

/**
 * The single API contract. `apps/api` implements it (nestjs-endpoints), `apps/web`
 * consumes it via a generated typed client. One Zod source → end-to-end type
 * safety with zero codegen drift.
 */

const c = initContract();

// ── Shared DTOs ───────────────────────────────────────────────────────────

const RepositoryDto = z.object({
  id: z.string(),
  fullName: z.string(),
  provider: Provider,
  defaultBranch: z.string(),
  visibility: z.string(),
  primaryLanguage: z.string().nullable(),
  isActive: z.boolean(),
});

const AuditRunDto = z.object({
  id: z.string(),
  repositoryId: z.string().nullable(),
  targetId: z.string().nullable(),
  status: AuditStatus,
  pillars: z.array(Pillar),
  commitSha: z.string().nullable(),
  riskScore: z.number().nullable(),
  scoringVersion: z.string().nullable(),
  startedAt: z.string().nullable(),
  finishedAt: z.string().nullable(),
  createdAt: z.string(),
});

const FindingDto = z.object({
  id: z.string(),
  pillar: Pillar,
  tool: z.string(),
  ruleId: z.string(),
  severity: Severity,
  cvssScore: z.number().nullable(),
  title: z.string(),
  description: z.string(),
  cwe: z.array(z.string()),
  vulnIds: z.array(z.string()),
  location: z.unknown().nullable(),
  target: z.unknown().nullable(),
  package: z.unknown().nullable(),
  evidence: z.string().nullable(),
  fingerprint: z.string(),
  sourceCount: z.number(),
  triageStatus: TriageStatus,
  aiExplanation: z.string().nullable(),
  aiRemediation: z.string().nullable(),
  aiPriority: z.number().nullable(),
  aiConfidence: z.number().nullable(),
  aiNeedsHuman: z.boolean(),
});

const ErrorDto = z.object({ message: z.string(), code: z.string().optional() });

// ── Contract ──────────────────────────────────────────────────────────────

export const contract = c.router(
  {
    // Repos
    importRepo: {
      method: "POST",
      path: "/repos/import",
      body: z.object({
        connectionId: z.string(),
        externalRepoId: z.string(),
        fullName: z.string(),
      }),
      responses: { 201: RepositoryDto, 400: ErrorDto, 401: ErrorDto },
      summary: "Import a repository from a connected VCS provider.",
    },
    listRepos: {
      method: "GET",
      path: "/repos",
      responses: { 200: z.array(RepositoryDto), 401: ErrorDto },
    },

    // Audits — POST returns 202 + runId immediately; work runs on the worker.
    createAudit: {
      method: "POST",
      path: "/audits",
      body: z.object({
        repositoryId: z.string().optional(),
        targetId: z.string().optional(),
        ref: z.string().optional(),
        pillars: z.array(Pillar).min(1),
      }),
      responses: {
        202: z.object({ runId: z.string(), status: AuditStatus }),
        400: ErrorDto,
        401: ErrorDto,
        403: ErrorDto, // e.g. DAST target not verified
      },
      summary: "Queue an audit run. Returns 202 + runId in <100ms.",
    },
    getAudit: {
      method: "GET",
      path: "/audits/:id",
      pathParams: z.object({ id: z.string() }),
      responses: { 200: AuditRunDto, 404: ErrorDto },
    },
    listFindings: {
      method: "GET",
      path: "/audits/:id/findings",
      pathParams: z.object({ id: z.string() }),
      query: z.object({
        pillar: Pillar.optional(),
        severity: Severity.optional(),
        triage: TriageStatus.optional(),
      }),
      responses: { 200: z.array(FindingDto), 404: ErrorDto },
    },
    cancelAudit: {
      method: "POST",
      path: "/audits/:id/cancel",
      pathParams: z.object({ id: z.string() }),
      body: z.object({}),
      responses: { 200: z.object({ ok: z.boolean() }), 404: ErrorDto },
    },

    // Triage — keyed on fingerprint, persists across runs.
    setTriage: {
      method: "POST",
      path: "/triage",
      body: z.object({
        fingerprint: z.string(),
        status: TriageStatus,
        reason: z.string().optional(),
      }),
      responses: { 200: z.object({ ok: z.boolean() }), 400: ErrorDto },
    },

    // Reports
    exportReport: {
      method: "POST",
      path: "/reports/:runId/export",
      pathParams: z.object({ runId: z.string() }),
      body: z.object({ format: z.enum(["pdf", "html"]).default("pdf") }),
      responses: {
        202: z.object({ reportId: z.string() }),
        404: ErrorDto,
      },
    },
    getReport: {
      method: "GET",
      path: "/reports/:runId",
      pathParams: z.object({ runId: z.string() }),
      responses: {
        200: z.object({
          id: z.string(),
          status: z.string(),
          downloadUrl: z.string().nullable(),
          summary: z.unknown().nullable(),
        }),
        404: ErrorDto,
      },
    },
  },
  {
    pathPrefix: "/api",
    commonResponses: { 500: ErrorDto },
  },
);

export type Contract = typeof contract;
export { RepositoryDto, AuditRunDto, FindingDto, ErrorDto };
