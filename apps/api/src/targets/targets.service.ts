import { Injectable, BadRequestException, NotFoundException } from "@nestjs/common";
import { randomBytes } from "node:crypto";
import { resolveTxt, resolve4 } from "node:dns/promises";
import { PrismaService } from "../infra/prisma.service.js";
import type { AuthContext } from "../auth/auth.guard.js";

/**
 * DAST/UX targets + ownership verification — the legal gate. No active scan runs
 * against a host we don't prove the user controls. Verification is enforced in
 * the DATA MODEL (Target.verificationStatus), not the UI: the audits endpoint
 * refuses to queue a network pillar unless status === "verified", and the worker
 * re-checks it. At verify time we also resolve + pin the target's IPs so a later
 * DNS-rebinding swap can be detected.
 *
 * Method: DNS-TXT. The user adds `auditer-verification=<token>` at the apex
 * domain; we resolve TXT and match. (meta-tag / .well-known file methods are
 * v2 additions with the same gate.)
 */
@Injectable()
export class TargetsService {
  constructor(private readonly prisma: PrismaService) {}

  async create(
    auth: AuthContext,
    input: { kind: "domain" | "origin" | "api"; value: string; repositoryId?: string },
  ) {
    const host = extractHost(input.value);
    if (!host) throw new BadRequestException("value must be a URL or hostname");
    const apex = apexDomain(host);
    const token = `auditer-verification=${randomBytes(16).toString("hex")}`;

    return this.prisma.tenant(auth.organizationId, (tx) =>
      tx.target.create({
        data: {
          organizationId: auth.organizationId,
          repositoryId: input.repositoryId,
          kind: input.kind,
          value: input.value,
          apexDomain: apex,
          verificationMethod: "dns-txt",
          verificationStatus: "pending",
          verificationToken: token,
          createdById: auth.userId,
        },
      }),
    );
  }

  async list(auth: AuthContext) {
    return this.prisma.tenant(auth.organizationId, (tx) =>
      tx.target.findMany({ where: { organizationId: auth.organizationId } }),
    );
  }

  /** Verify ownership via DNS-TXT, then pin resolved IPs. */
  async verify(auth: AuthContext, id: string, req: { ip?: string; userAgent?: string }) {
    const target = await this.prisma.tenant(auth.organizationId, (tx) =>
      tx.target.findFirst({ where: { id, organizationId: auth.organizationId } }),
    );
    if (!target) throw new NotFoundException("target not found");
    if (!target.verificationToken || !target.apexDomain) {
      throw new BadRequestException("target has no pending verification");
    }

    const ok = await checkDnsTxt(target.apexDomain, target.verificationToken);
    if (!ok) {
      return { verified: false, hint: `add a TXT record at ${target.apexDomain}: ${target.verificationToken}` };
    }

    // Pin the IPs the verified host currently resolves to (rebinding defense).
    const ips = await safeResolve4(extractHost(target.value) ?? target.apexDomain);

    await this.prisma.tenant(auth.organizationId, async (tx) => {
      await tx.target.update({
        where: { id },
        data: { verificationStatus: "verified", resolvedIps: ips },
      });
      // Immutable authorization affirmation.
      await tx.abuseEvent.create({
        data: {
          organizationId: auth.organizationId,
          actor: auth.userId,
          eventType: "dast_authorization_affirmed",
          target: target.value,
          ip: req.ip,
          detail: { userAgent: req.userAgent, method: "dns-txt", ips } as never,
        },
      });
    });

    return { verified: true };
  }
}

function extractHost(value: string): string | null {
  try {
    return new URL(value.includes("://") ? value : `https://${value}`).host;
  } catch {
    return /^[a-z0-9.-]+$/i.test(value) ? value : null;
  }
}

/** Naive eTLD+1. TODO(prod): use the Public Suffix List for correctness. */
function apexDomain(host: string): string {
  const labels = host.split(".").filter(Boolean);
  return labels.length <= 2 ? host : labels.slice(-2).join(".");
}

async function checkDnsTxt(apex: string, token: string): Promise<boolean> {
  try {
    const records = await resolveTxt(apex);
    return records.some((chunks) => chunks.join("").includes(token));
  } catch {
    return false;
  }
}

async function safeResolve4(host: string): Promise<string[]> {
  try {
    return await resolve4(host);
  } catch {
    return [];
  }
}
