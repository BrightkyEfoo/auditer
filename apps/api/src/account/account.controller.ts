import {
  Controller,
  Get,
  Delete,
  Body,
  Res,
  HttpCode,
  UseGuards,
} from "@nestjs/common";
import type { Response } from "express";
import { z } from "zod";
import { AuthGuard, Auth, type AuthContext } from "../auth/auth.guard.js";
import { SESSION_COOKIE } from "../auth/session.service.js";
import { AccountService } from "./account.service.js";
import { ZodBody } from "../common/zod.pipe.js";

/**
 * The confirmation is the account's own email address, retyped. Normalized the
 * same way sign-up normalizes it (trim + lowercase) so a copy-paste that picked
 * up a trailing space is not read as a mismatch — the guard exists against the
 * accidental click, not against clumsy clipboards.
 */
const DeleteAccountBody = z.object({
  confirmEmail: z
    .string()
    .trim()
    .toLowerCase()
    .email("the exact email address of the account is required"),
});

@Controller("api/account")
@UseGuards(AuthGuard)
export class AccountController {
  constructor(private readonly account: AccountService) {}

  /**
   * Portability export. Served as an attachment, never inline: the payload
   * embeds model-authored text and finding evidence, and rendering that in our
   * own origin would turn any escaping mistake into stored XSS — the same
   * reasoning as the report download in reports.controller.ts.
   */
  @Get("export")
  async export(@Auth() auth: AuthContext, @Res() res: Response): Promise<void> {
    const payload = await this.account.exportOrganization(auth);
    const stamp = new Date().toISOString().slice(0, 10);

    res.setHeader("content-type", "application/json; charset=utf-8");
    res.setHeader(
      "content-disposition",
      `attachment; filename="auditer-export-${stamp}.json"`,
    );
    res.setHeader("cache-control", "private, no-store");
    res.send(JSON.stringify(payload, null, 2));
  }

  /**
   * Irreversible. Answers 200 with a small body rather than 204 so the browser
   * can tell "deleted" from "the proxy ate the request", and clears the session
   * cookie on the way out — the session row is already gone, but leaving the
   * cookie in place would show the user a logged-in shell over a dead account.
   */
  @Delete()
  @HttpCode(200)
  async remove(
    @Auth() auth: AuthContext,
    @Body(new ZodBody(DeleteAccountBody)) body: z.infer<typeof DeleteAccountBody>,
    @Res() res: Response,
  ): Promise<void> {
    const result = await this.account.deleteAccount(auth, body.confirmEmail);
    res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Path=/; Max-Age=0`);
    res.json(result);
  }
}
