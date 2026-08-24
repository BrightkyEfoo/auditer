#!/usr/bin/env bash
# Drift guard between prisma/sql/rls.sql and the newest _rls migration.
#
# WHY. The policies live in two places on purpose: prisma/sql/rls.sql is the one
# human-edited file (several comments across the repo cite that path, and
# reading the current policy set out of a chain of migrations would be worse
# than reading one file), while the migration is the frozen copy that actually
# runs on a database. Two copies means they can drift, and the drift is
# invisible: editing rls.sql alone changes nothing in production, because
# `migrate deploy` never looks at that file. This makes the mistake mechanical
# instead of a matter of remembering.
#
# The fix when it fails is never to edit the migration — `migrate deploy`
# refuses a file whose checksum moved. Create a new migration directory
# `<timestamp>_rls_<what_changed>` containing the FULL new rls.sql, marker line
# included.

set -euo pipefail

cd "$(dirname "$0")/.."

# Timestamp-prefixed names sort chronologically, so the last match is the
# migration that most recently restated the policy set.
latest=$(ls -d prisma/migrations/*_rls* 2>/dev/null | tail -1 || true)
if [ -z "$latest" ]; then
  echo "rls-check: no _rls migration found — RLS would never be applied to a fresh database" >&2
  exit 1
fi

# The header above the marker is commentary and is expected to differ; the body
# below it must be byte-identical.
if ! sed -n '/>>> BEGIN verbatim copy/,$p' "$latest/migration.sql" | tail -n +2 \
     | diff -u - prisma/sql/rls.sql; then
  echo "rls-check: $latest/migration.sql has drifted from prisma/sql/rls.sql (diff above)" >&2
  echo "rls-check: ship a NEW <timestamp>_rls_<change> migration with the full file; never edit an applied one" >&2
  exit 1
fi

echo "rls-check: $latest matches prisma/sql/rls.sql"
