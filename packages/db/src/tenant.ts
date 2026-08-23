import { Prisma, PrismaClient } from "../generated/client/index.js";

/**
 * Tenant-scoped transaction wrapper.
 *
 * RLS policies (prisma/sql/rls.sql) compare `organization_id` to the
 * `app.current_org_id` GUC. This wrapper opens an interactive transaction,
 * sets that GUC with SET LOCAL (transaction-scoped, auto-reset on commit),
 * and runs the caller's work against a transaction client that is now
 * physically unable to read or write another tenant's rows.
 *
 * Every request that touches tenant data MUST go through here. Direct
 * `prisma.finding.findMany(...)` outside a tenant tx will be denied by RLS
 * (deny-by-default) when connected as the app role — that is the point.
 */

/** cuid ids only — refuse anything that isn't, so it can't be SQL-smuggled. */
const ORG_ID_RE = /^[a-z0-9]{20,40}$/i;

export type TenantClient = Prisma.TransactionClient;

export async function withTenant<T>(
  prisma: PrismaClient,
  organizationId: string,
  fn: (tx: TenantClient) => Promise<T>,
): Promise<T> {
  if (!ORG_ID_RE.test(organizationId)) {
    throw new Error(`withTenant: invalid organizationId "${organizationId}"`);
  }

  return prisma.$transaction(async (tx) => {
    // set_config(key, value, is_local=true) is SET LOCAL as a parameterized
    // call — safe against injection, unlike interpolating into `SET LOCAL`.
    await tx.$executeRaw`SELECT set_config('app.current_org_id', ${organizationId}, true)`;
    return fn(tx);
  });
}

/**
 * Escape hatch for genuinely cross-tenant/system work (webhooks pre-tenant
 * resolution, background reconciliation). Runs as-is with no org GUC — so RLS
 * denies all tenant tables. Only use for tables that are not tenant-scoped
 * (webhook_events) or when connected as the owner role in migrations/jobs.
 */
export function systemClient(prisma: PrismaClient): PrismaClient {
  return prisma;
}
