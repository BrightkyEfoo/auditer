import {
  Controller,
  Post,
  Query,
  Req,
  HttpCode,
  ConflictException,
  NotFoundException,
} from "@nestjs/common";
import type { Request } from "express";
import { createHash, timingSafeEqual } from "node:crypto";
import { RetentionService, type PurgeReport } from "./retention.service.js";

/**
 * Manual trigger for the retention purge.
 *
 * Deliberately NOT behind AuthGuard: this is an operator action across every
 * tenant, not a user action inside one, and giving it a user session would mean
 * inventing an admin role the product does not have. It authenticates with a
 * pre-shared secret in `ADMIN_PURGE_TOKEN`.
 *
 * Absent or short variable ⇒ the route 404s. Failing closed matters more here
 * than anywhere else in the api: this endpoint deletes across all
 * organizations, and an empty-string default would have made
 * `x-admin-token: ` a valid credential.
 *
 * Wrong token also 404s rather than 403 — an unauthenticated caller learns
 * nothing about whether the route exists.
 *
 * This is no longer the only trigger: a BullMQ Job Scheduler in the worker
 * (apps/worker/src/retention-scheduler.ts) runs the same purge every night. The
 * endpoint stays because the privacy policy promises a purge "sous 30 jours" on
 * request, and an operator answering one must not have to wait for 03:30 UTC.
 * Both paths call the same function and take the same Valkey lock, so they
 * cannot run at once. Run it:
 *
 *   curl -X POST -H "x-admin-token: $ADMIN_PURGE_TOKEN" \
 *        "$API_URL/api/admin/retention/purge?dryRun=1"
 */
const MIN_TOKEN_LENGTH = 16;

function assertOperator(req: Request): void {
  const expected = process.env.ADMIN_PURGE_TOKEN;
  if (!expected || expected.length < MIN_TOKEN_LENGTH) throw new NotFoundException();

  // Digest both sides: timingSafeEqual throws on a length mismatch, and the
  // throw itself would leak the length of the configured secret.
  const got = createHash("sha256").update(req.header("x-admin-token") ?? "").digest();
  const want = createHash("sha256").update(expected).digest();
  if (!timingSafeEqual(got, want)) throw new NotFoundException();
}

@Controller("api/admin/retention")
export class RetentionController {
  constructor(private readonly retention: RetentionService) {}

  @Post("purge")
  @HttpCode(200)
  async purge(@Req() req: Request, @Query("dryRun") dryRun?: string): Promise<PurgeReport> {
    assertOperator(req);
    const report = await this.retention.purge({
      dryRun: dryRun === "1" || dryRun === "true",
    });
    // Lock held elsewhere. 409 rather than an empty report: a body full of
    // zeros would read as "nothing had expired", which is the opposite of
    // "someone else is purging right now".
    if (!report) {
      throw new ConflictException("a retention purge is already running");
    }
    return report;
  }
}
