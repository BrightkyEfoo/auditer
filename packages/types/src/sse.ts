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
    /* ── What the run is actually DOING, not just that it is doing it ──
       A progress line saying "osv-scanner — running" for eleven minutes tells
       the reader nothing about whether it is working or stuck, and tells an
       operator nothing at all once it has failed. These fields are what turn
       the live view into something you can diagnose from. */
    /** Wall-clock of the scan, filled on the terminal event. */
    durationMs: z.number().int().nonnegative().optional(),
    /** Raw process exit code — the difference between "found nothing" and
     *  "was killed" is exit 0 versus exit 137, and nothing else shows it. */
    exitCode: z.number().int().optional(),
    /** The exact image reference, digest included: which binary produced this. */
    image: z.string().optional(),
    /** Why a scanner did not run, when it did not. */
    reason: z.string().optional(),
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
