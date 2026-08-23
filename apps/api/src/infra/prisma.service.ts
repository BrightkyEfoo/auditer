import { Injectable, type OnModuleInit, type OnModuleDestroy } from "@nestjs/common";
import { PrismaClient, withTenant, type TenantClient } from "@auditer/db";

/**
 * Prisma provider. Connects as the RLS-constrained app role. Every tenant-scoped
 * operation MUST go through `tenant()` so the `app.current_org_id` GUC is set
 * and RLS applies — a raw query outside a tenant tx is denied by default.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  async onModuleInit(): Promise<void> {
    await this.$connect();
  }
  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }

  /** Run work scoped to an organization (RLS-enforced). */
  tenant<T>(organizationId: string, fn: (tx: TenantClient) => Promise<T>): Promise<T> {
    return withTenant(this, organizationId, fn);
  }
}
