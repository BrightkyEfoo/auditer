# Single monorepo image, built once. The compose runs three services off it with
# different commands (api / worker / web). Includes git for the worker's clone
# step. The worker reaches Docker over TCP via the socket-proxy (no docker CLI
# needed here).
FROM node:22-bookworm-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates postgresql-client \
  && rm -rf /var/lib/apt/lists/*
RUN corepack enable
WORKDIR /app

FROM base AS build
ENV NEXT_TELEMETRY_DISABLED=1
COPY . .
# --ignore-scripts sidesteps pnpm 11's CI build-approval gate. Prisma is
# generated explicitly below (fetches its own engine), and the skipped scripts
# are only optional native accelerators with JS fallbacks (esbuild/sharp/ssh2…).
RUN pnpm install --frozen-lockfile=false --prod=false --ignore-scripts
RUN pnpm --filter @auditer/db generate
# Build packages + api + worker (tsc/nest) and the web (next build).
RUN pnpm --filter '@auditer/api...' --filter '@auditer/worker...' build
RUN pnpm --filter @auditer/web build

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=build /app /app
# default command overridden per-service in compose
CMD ["node", "apps/api/dist/main.js"]
