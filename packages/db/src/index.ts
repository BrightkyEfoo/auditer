export * from "../generated/client/index.js";
export { prisma, createPrisma } from "./client.js";
export { withTenant, systemClient, type TenantClient } from "./tenant.js";
