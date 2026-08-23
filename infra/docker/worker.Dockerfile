# Worker image. Needs git (repo clone) and the Docker CLI is NOT required —
# the worker talks to the socket-proxy over TCP via dockerode. Build context is
# the repo root; use `turbo prune --scope=@auditer/worker` to slim it in CI.
FROM node:22-bookworm-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
  && rm -rf /var/lib/apt/lists/*
RUN corepack enable
WORKDIR /app

FROM base AS build
COPY . .
RUN pnpm install --frozen-lockfile --prod=false
RUN pnpm --filter @auditer/db generate \
  && pnpm --filter @auditer/worker... build

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=build /app /app
# non-root; the worker itself is unprivileged (it only asks the proxy to spawn
# hardened scanner containers).
USER node
CMD ["node", "apps/worker/dist/main.js"]
