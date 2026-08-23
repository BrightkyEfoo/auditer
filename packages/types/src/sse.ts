import { z } from "zod";
import { AuditStatus, ScanStatus, Pillar } from "./enums.js";

/**
 * Live progress events published by the worker to Valkey pub/sub and relayed to
 * the browser over SSE. Snapshot-then-tail: a late client gets a Postgres
 * snapshot, then live events keyed by monotonic `seq` for Last-Event-ID resume.
 */

export const AuditEvent = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("status"),
    seq: z.number().int(),
    auditRunId: z.string(),
    status: AuditStatus,
    at: z.string().datetime(),
  }),
  z.object({
    type: z.literal("scan"),
    seq: z.number().int(),
    auditRunId: z.string(),
    pillar: Pillar,
    tool: z.string(),
    status: ScanStatus,
    findingCount: z.number().int().nonnegative().optional(),
    at: z.string().datetime(),
  }),
  z.object({
    type: z.literal("log"),
    seq: z.number().int(),
    auditRunId: z.string(),
    message: z.string(),
    at: z.string().datetime(),
  }),
  z.object({
    type: z.literal("done"),
    seq: z.number().int(),
    auditRunId: z.string(),
    status: AuditStatus,
    riskScore: z.number().optional(),
    at: z.string().datetime(),
  }),
]);
export type AuditEvent = z.infer<typeof AuditEvent>;
