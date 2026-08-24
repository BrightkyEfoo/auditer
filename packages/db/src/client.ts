import { PrismaClient } from "../generated/client/index.js";

/**
 * Singleton PrismaClient. The app connects as the RLS-constrained role
 * (DATABASE_APP_URL); migrations connect as the owner (DATABASE_URL) which
 * bypasses RLS to run DDL.
 */
declare global {
  // eslint-disable-next-line no-var
  var __auditerPrisma: PrismaClient | undefined;
}

export interface CreatePrismaOptions {
  /**
   * Connect as the OWNER role, which is exempt from row level security.
   *
   * Reserved for the operations that cannot be tenant-scoped by construction —
   * creating a user's first organization, and DDL. Everything else must use the
   * default connection: RLS is the backstop that catches a forgotten WHERE, and
   * it only catches it on a role that is subject to it.
   */
  privileged?: boolean;
}

export function createPrisma(options: CreatePrismaOptions = {}): PrismaClient {
  const url = options.privileged
    ? (process.env.DATABASE_URL ?? process.env.DATABASE_APP_URL)
    : (process.env.DATABASE_APP_URL ?? process.env.DATABASE_URL);
  return new PrismaClient({
    datasources: url ? { db: { url } } : undefined,
    log:
      process.env.NODE_ENV === "development"
        ? ["warn", "error"]
        : ["error"],
  });
}

export const prisma: PrismaClient =
  globalThis.__auditerPrisma ?? createPrisma();

if (process.env.NODE_ENV !== "production") {
  globalThis.__auditerPrisma = prisma;
}
