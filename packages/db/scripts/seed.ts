/**
 * Dev seed. Connects as the OWNER role (DATABASE_URL) which bypasses RLS, so it
 * can create the first org/user without a tenant GUC. Prints the org + user ids
 * to paste into apps/web/.env as NEXT_PUBLIC_DEV_ORG_ID / _USER_ID and to send
 * as x-org-id / x-user-id while better-auth isn't wired yet.
 *
 * Run: pnpm --filter @auditer/db seed
 */
import { PrismaClient } from "../generated/client/index.js";

const prisma = new PrismaClient({
  datasources: { db: { url: process.env.DATABASE_URL } },
});

// A public repo to exercise the slice. Override with SEED_REPO=owner/name.
const SEED_REPO = process.env.SEED_REPO ?? "auditer-samples/vulnerable-node-demo";

async function main(): Promise<void> {
  const user = await prisma.user.upsert({
    where: { email: "dev@auditer.local" },
    update: {},
    create: { email: "dev@auditer.local", name: "Dev User" },
  });

  const org = await prisma.organization.upsert({
    where: { slug: "dev-org" },
    update: {},
    create: { slug: "dev-org", name: "Dev Org", ownerUserId: user.id },
  });

  await prisma.membership.upsert({
    where: { userId_organizationId: { userId: user.id, organizationId: org.id } },
    update: {},
    create: { userId: user.id, organizationId: org.id, role: "owner" },
  });

  // A GitHub connection with no stored token → clones public repos only.
  const conn = await prisma.connection.findFirst({
    where: { organizationId: org.id, provider: "github" },
  });
  const connection =
    conn ??
    (await prisma.connection.create({
      data: {
        organizationId: org.id,
        provider: "github",
        kind: "github_app",
        status: "active",
      },
    }));

  await prisma.repository.upsert({
    where: {
      connectionId_externalRepoId: {
        connectionId: connection.id,
        externalRepoId: "seed-1",
      },
    },
    update: { fullName: SEED_REPO, isActive: true },
    create: {
      organizationId: org.id,
      connectionId: connection.id,
      provider: "github",
      externalRepoId: "seed-1",
      fullName: SEED_REPO,
      defaultBranch: "main",
      visibility: "public",
    },
  });

  // eslint-disable-next-line no-console
  console.log("\nSeed complete. Put these in apps/web/.env:\n");
  // eslint-disable-next-line no-console
  console.log(`NEXT_PUBLIC_DEV_ORG_ID=${org.id}`);
  // eslint-disable-next-line no-console
  console.log(`NEXT_PUBLIC_DEV_USER_ID=${user.id}`);
  // eslint-disable-next-line no-console
  console.log(`\nSeed repo: ${SEED_REPO} (override with SEED_REPO=owner/name)\n`);
}

main()
  .catch((e) => {
    // eslint-disable-next-line no-console
    console.error(e);
    process.exit(1);
  })
  .finally(() => prisma.$disconnect());
