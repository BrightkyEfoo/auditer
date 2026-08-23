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

export function createPrisma(): PrismaClient {
  const url = process.env.DATABASE_APP_URL ?? process.env.DATABASE_URL;
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
