# auditer

Multi-pillar audit SaaS — connect a repo, run **secrets · CVE/deps · SAST/quality · repo hygiene · DAST · UX** audits, get a triaged, AI-explained report (dashboard + PDF).

Hybrid engine: proven OSS scanners detect; **Claude** triages, dedups, prioritizes, explains, and writes the report. Every finding traces back to a deterministic rule — the AI never invents findings or computes scores.

## Architecture

Turborepo + pnpm monorepo, Node 22, TypeScript.

```
apps/
  web/     Next.js 15 — dashboard, live SSE run view, findings explorer, triage, PDF export
  api/     NestJS 11 — HTTP, auth, enqueues jobs, SSE relay (returns 202+runId in <100ms; never scans)
  worker/  Node/BullMQ consumer — clone → sandboxed scan → normalize → dedup → AI enrich → score → persist
packages/
  audit-engine/  framework-agnostic core: ScannerAdapter + SandboxRunner ports, SARIF normalize,
                 fingerprint, dedup, deterministic scoring, AI layer, orchestrator, Wave-1 adapters
  db/            Prisma schema + RLS policies + tenant tx wrapper (organizationId on every row)
  types/         canonical Finding/Report Zod schemas + enums (the shared spine)
  contracts/     ts-rest + Zod API contract    queue/  BullMQ payloads
  storage/       S3 wrapper (MinIO→R2/S3)      crypto/ OpenBao envelope encryption
  config/        shared tsconfig/eslint
infra/
  compose/       full stack (postgres/valkey/minio/socket-proxy/openbao)
  docker/        app + scanner image notes (gVisor, cosign pinning)
```

**Security spine:** the worker runs every scanner in an ephemeral, hardened,
no-network **gVisor** container spawned **through a docker-socket-proxy** (never
the raw host socket). RCE is assumed inside every sandbox. VCS tokens are
envelope-encrypted (OpenBao). Postgres **RLS** is a deny-by-default tenant
backstop behind app-layer scoping. Source code is never persisted.

## Status

**All 7 pillars implemented behind the shared pipeline; everything builds &
typechecks; deterministic core has passing tests.**

| Pillar | Scanner(s) | Network | Status |
|---|---|---|---|
| secrets | Gitleaks (full history) | no | ✓ |
| sca / CVE | osv-scanner (offline) | no | ✓ |
| sast | Semgrep (vendored rules, SARIF) | no | ✓ |
| quality | jscpd (duplication) | no | ✓ |
| hygiene | Trivy-config + hadolint (SARIF) | no | ✓ |
| dast | nuclei (verified target, egress-scoped) | yes | ✓ |
| ux | Lighthouse (perf/a11y/best-practices) | yes | ✓ |

Also wired: **GitHub OAuth login** (cookie session, `AuthGuard` chokepoint),
**GitHub App installation-token** minting for private-repo clones, **DAST target
ownership verification** (DNS-TXT + IP-pin + egress SSRF backstop), **AI
enrichment + executive report** (Haiku→Sonnet→Opus 5), and **HTML report
artifact** export. Adding scanners to a pillar (the v2 ensemble) or new pillars
is just another `ScannerAdapter` behind the identical pipeline.

Remaining infra step: binary-PDF render (headless-Chromium printing the HTML
report) — the HTML artifact is already complete and print-ready.

## Run (local dev)

Prereqs: Node 22, pnpm, Docker (with gVisor for real isolation; `SANDBOX_RUNTIME=runc` in dev without it).

```sh
pnpm install
cp .env.example .env            # fill ANTHROPIC_API_KEY to enable AI enrichment

# 1. Infra
docker compose -f infra/compose/docker-compose.yml up -d

# 2. Schema + RLS + seed
pnpm --filter @auditer/db bootstrap     # prisma migrate deploy + RLS + RLS assertion
#   Schema changes go through `migrate:dev`; `prisma db push` is banned here —
#   see packages/db/README.md for why.
pnpm --filter @auditer/db seed          # prints NEXT_PUBLIC_DEV_ORG_ID / _USER_ID
#   → paste those into apps/web/.env

# 3. Apps (three terminals, or `pnpm dev`)
pnpm --filter @auditer/api dev
pnpm --filter @auditer/worker dev
pnpm --filter @auditer/web dev          # http://localhost:3000
```

## Verify the slice (end-to-end)

1. **Login/seed** → the dev org/repo exist; web lists the repo.
2. **Trigger** an audit (secrets + CVE) → `POST /api/audits` returns **202 + runId** instantly.
3. **Live SSE** → the run view streams cloning → scanning → analyzing → reporting; the
   worker spawns a **gVisor** container via the socket-proxy (non-root, read-only,
   `--network=none`, destroyed after).
4. **Findings** → Gitleaks secret + osv CVE normalized → deduped → AI-explained → scored
   (open Critical caps the grade at F); `ai_usage_ledger` records the request.
5. **Triage** a finding false-positive → persists on its `fingerprint`, survives re-runs.
6. **Export PDF** → report artifact (PDF render via Playwright container is the next infra step).

## Tests

```sh
pnpm --filter @auditer/audit-engine test    # deterministic pipeline: fingerprint / dedup / scoring
```

## Notes / open items

- **Deployment** target TBD (default: this compose stack on Coolify; architecture is deployment-agnostic).
- **Claude model IDs** pinned per the `claude-api` skill: Haiku 4.5 (bulk) → Sonnet 5 (judge) → Opus 5 (report synthesis).
- **Auth**: real GitHub OAuth cookie sessions on the existing schema, behind the `AuthGuard` chokepoint (better-auth can replace it there). Dev fallback headers require `AUTH_DEV_HEADERS=1`.
- **PDF**: HTML report artifact is generated and stored; binary PDF via headless Chromium is the one remaining infra step.
- **MinIO** is AGPL — consumed only over the S3 protocol; swappable to R2/S3/SeaweedFS by env.
- Replace scanner image tags with **cosign-verified `@sha256` digests** before production (see `infra/docker/scanners/README.md`), and bake **gVisor** + the per-audit **egress allowlist** on the host.
