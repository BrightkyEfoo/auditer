# API image. HTTP only — no scanner/Docker deps (kept lean on purpose; the
# audit-engine's heavy paths are lazy and live in the worker image).
FROM node:22-bookworm-slim AS base
RUN corepack enable
WORKDIR /app

FROM base AS build
COPY . .
RUN pnpm install --frozen-lockfile --prod=false
RUN pnpm --filter @auditer/db generate \
  && pnpm --filter @auditer/api... build

FROM base AS runtime
ENV NODE_ENV=production
COPY --from=build /app /app
USER node
EXPOSE 3001
CMD ["node", "apps/api/dist/main.js"]
