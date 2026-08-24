#!/usr/bin/env bash
# Refresh the offline EPSS + CISA-KEV snapshot used to prioritize findings.
#
# The real work lives in packages/audit-engine/src/enrich/refresh-feeds.ts, not
# here, so that the download validation runs through the SAME parsers the audit
# pipeline uses at read time — one definition of "a valid feed", type-checked by
# `pnpm build` instead of drifting in an untested shell script.
#
# Runs on the control-plane HOST (cron / ops shell). It must never run inside a
# scanner container: those have no network by design.
#
# Usage:
#   VULN_FEEDS_HOST_PATH=/home/brightky/auditer-vuln-feeds \
#     bash infra/scripts/refresh-vuln-feeds.sh
#   bash infra/scripts/refresh-vuln-feeds.sh --dir=/srv/feeds --keep=30
#
# Suggested cron (EPSS republishes daily, KEV several times a week):
#   17 4 * * *  cd /srv/auditer && bash infra/scripts/refresh-vuln-feeds.sh >> /var/log/auditer-feeds.log 2>&1
#
# Exit codes: 0 refreshed, 1 failed. On failure the previous snapshot stays
# `current`, so a bad download degrades to yesterday's data rather than to none.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENTRY="$ROOT/packages/audit-engine/dist/enrich/refresh-feeds.js"

# Build on demand: the script is run by ops on a host where dist/ may be stale
# or absent, and a silent run against an old build would defeat the point of
# sharing the parsers.
if [ ! -f "$ENTRY" ]; then
  echo "[vuln-feeds] building @auditer/audit-engine (dist missing)" >&2
  (cd "$ROOT" && pnpm --filter @auditer/audit-engine build)
fi

exec node "$ENTRY" "$@"
