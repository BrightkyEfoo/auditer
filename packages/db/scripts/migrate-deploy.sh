#!/usr/bin/env bash
# Schema deployment — replaces `prisma db push --accept-data-loss`.
#
# WHY THIS SCRIPT INSTEAD OF A ONE-LINER IN THE WORKFLOW. It has to serve two
# databases that need opposite treatment, and the discrimination between them is
# three lines of SQL that do not survive being nested inside
# `ssh "... bash -lc '...'"` — SQL literals need single quotes, and the workflow
# has already spent both quoting levels. Keeping it here also means it can be
# read, reviewed and run by hand against a suspect database.
#
# THE TWO DATABASES.
#
#   (a) The existing production one. Its schema was built by successive
#       `db push` runs, so the tables are there and populated but there is no
#       `_prisma_migrations` table at all — Prisma has never seen it. Running
#       the baseline migration there would CREATE TABLE over live data and die
#       on the first statement. It must be RECORDED as applied, not executed.
#
#   (b) A database that starts empty — a fresh developer machine, CI, a second
#       environment. There the baseline must actually run.
#
# HOW THEY ARE TOLD APART, and why this particular test. `prisma migrate deploy`
# creates `_prisma_migrations` BEFORE it runs anything, so the absence of that
# table is proof that no migration was ever attempted here. Combined with the
# presence of a schema table, absent history means exactly one thing: case (a).
# Testing "is the baseline recorded" instead would be wrong — a first migration
# that failed HALFWAY leaves partial tables behind, and that database would then
# get its broken state stamped as good. With this test it does not: history
# exists, so nothing is resolved and `migrate deploy` refuses loudly, which is
# the correct outcome for a half-applied schema.
#
# IDEMPOTENT. Run it twice, ten times, on either database:
#   - the resolve happens at most once, because it is what creates the history;
#   - `migrate deploy` applies only what is pending and is a no-op afterwards;
#   - the RLS migration is written to converge rather than fail (see its header),
#     so applying it to production — which already had the policies from the old
#     `psql -f` step — restates them instead of erroring, and that restatement is
#     the point: nobody could prove that file had been replayed since the last
#     schema change.
#
# NOTHING HERE CAN DROP A COLUMN. That is the whole reason for the change:
# `--accept-data-loss` let the deploy silently discard a column whenever the
# schema and the database disagreed. A migration that would lose data now has to
# be written, read and merged by a human first.

set -euo pipefail

cd "$(dirname "$0")/.."

# The prisma CLI reads the repo-root .env by itself, but psql and pg_isready
# below do not — and without this the local `pnpm --filter @auditer/db bootstrap`
# would silently fall through to the container-side hostname and hang. Only
# fills the variable when the environment has not already set it, so the
# compose-provided value always wins on a server.
if [ -z "${DATABASE_URL:-}" ] && [ -f ../../.env ]; then
  DATABASE_URL=$(sed -n 's/^[[:space:]]*DATABASE_URL[[:space:]]*=[[:space:]]*//p' ../../.env | tail -1 | tr -d "\"'")
fi

DB_URL="${DATABASE_URL:-postgresql://auditer:auditer@postgres:5432/auditer}"
PRISMA="${PRISMA_BIN:-node_modules/.bin/prisma}"

# Kept in sync with the directory name under prisma/migrations/. Hard-coded on
# purpose: "the baseline" is a specific historical file, not "whichever
# migration happens to sort first" — globbing it would let a future rename
# quietly re-point the resolve at the wrong migration.
BASELINE="20260824120000_baseline"

export DATABASE_URL="$DB_URL"

# Bounded wait: a deploy that rebuilt the images can reach this step while
# postgres is still coming back up, and a connection refused here fails the
# whole deploy for a reason that resolves itself in two seconds.
for _ in $(seq 1 30); do
  if pg_isready -d "$DB_URL" -q; then break; fi
  sleep 1
done

psql_q() { psql "$DB_URL" -v ON_ERROR_STOP=1 -tAc "$1" | tr -d '[:space:]'; }

# to_regclass returns NULL rather than raising when the relation is absent —
# the only catalog lookup that is safe to write as a plain expression.
history_present=$(psql_q "SELECT to_regclass('public._prisma_migrations') IS NOT NULL")
schema_present=$(psql_q "SELECT to_regclass('public.organizations') IS NOT NULL")

if [ "$history_present" = "f" ] && [ "$schema_present" = "t" ]; then
  echo "migrate-deploy: schema present, no migration history — recording $BASELINE as already applied"
  "$PRISMA" migrate resolve --applied "$BASELINE"
else
  echo "migrate-deploy: history_present=$history_present schema_present=$schema_present — nothing to baseline"
fi

"$PRISMA" migrate deploy

# Read-only assertion, deliberately AFTER the migrations: it is the guard that
# a newly added tenant table did not ship without a policy. It fails the deploy
# rather than letting the gap through, which the old ordering could not do —
# rls.sql was applied blind and nothing ever looked at the result.
psql "$DB_URL" -v ON_ERROR_STOP=1 -f prisma/sql/rls-verify.sql
