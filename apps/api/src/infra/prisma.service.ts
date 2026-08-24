import { Injectable, type OnModuleInit, type OnModuleDestroy } from "@nestjs/common";
import { createPrisma, PrismaClient, withTenant, type TenantClient } from "@auditer/db";

/**
 * Prisma provider for the api.
 *
 * It used to be `extends PrismaClient` with no datasource override, which means
 * it connected with `DATABASE_URL` — the OWNER role, which is exempt from row
 * level security. The api, the one process that serves untrusted requests, was
 * therefore the only one NOT subject to the deny-by-default backstop, while the
 * file's own comment and the public security page both claimed otherwise. The
 * worker was always correct; the api was not.
 *
 * So there are now two connections, named for what they are:
 *
 *   - the default client (this instance) connects as the RLS-constrained app
 *     role. Every tenant-scoped operation goes through `tenant()`, which sets
 *     `app.current_org_id`; anything touching a tenant table OUTSIDE that
 *     wrapper now returns nothing instead of everything. That is the point.
 *
 *   - `privileged` connects as the owner and bypasses RLS. It exists for the
 *     one operation that genuinely cannot be tenant-scoped: creating a user's
 *     first organization, where there is no organization to scope to yet and
 *     the policy's WITH CHECK would reject the insert. Reach for it only when
 *     you can name that reason.
 *
 * Non-tenant tables (`users`, `auth_identities`, `sessions`) carry no policy, so
 * the app role reads and writes them normally — sign-in still works on the
 * constrained connection.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  /**
   * Owner-role connection. RLS does not apply here. Every use is a deliberate
   * exception and should say why in a comment at the call site.
   */
  readonly privileged: PrismaClient;

  constructor() {
    // Explicit datasource: the generated client defaults to DATABASE_URL, so
    // omitting this is what silently produced an owner-role connection.
    super({
      datasources: {
        db: { url: process.env.DATABASE_APP_URL ?? process.env.DATABASE_URL ?? "" },
      },
    });
    this.privileged = createPrisma({ privileged: true });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
  }
  async onModuleDestroy(): Promise<void> {
    await Promise.allSettled([this.$disconnect(), this.privileged.$disconnect()]);
  }

  /** Run work scoped to an organization (RLS-enforced). */
  tenant<T>(organizationId: string, fn: (tx: TenantClient) => Promise<T>): Promise<T> {
    return withTenant(this, organizationId, fn);
  }
}
