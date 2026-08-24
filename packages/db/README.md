# @auditer/db — schema, migrations, Row-Level Security

Prisma 6 on PostgreSQL 16. The canonical data model is `prisma/schema.prisma`;
everything the database actually contains got there through a file in
`prisma/migrations/`.

## `prisma db push` is banned on this project

It used to be how the deploy applied the schema
(`prisma db push --skip-generate --accept-data-loss` in `.github/workflows/deploy.yml`).
It is gone, the `push` npm script is gone, and it must not come back. Three
reasons, in order of how much they cost:

1. **`--accept-data-loss` means what it says.** `db push` reconciles the
   database to the schema by whatever route it finds, including `DROP COLUMN`.
   Rename a field, roll an app version back, land two branches that disagree —
   each one produces a divergence, and the flag pre-authorises destroying data
   to close it. Nobody reads the plan, because there is no plan to read.
2. **No history means no reproducibility.** `db push` leaves no record of what
   it did. A second environment cannot be brought to the same state, a
   regression cannot be dated, and "does staging match production?" has no
   answer. A migration directory is a reviewable diff in a pull request; a
   `db push` is a side effect on one server.
3. **It cannot be rehearsed.** A migration runs on a shadow database in
   `migrate dev` and on CI before it ever touches production. `db push` is only
   ever tested by running it on the thing you were trying not to break.

The rule predates this package — see the repository's `CLAUDE.md`, "MIGRATIONS,
jamais `prisma db push`". The deployment simply did not follow it.

## Changing the schema

```sh
# 1. Edit prisma/schema.prisma.
# 2. Generate + apply the migration against your local database:
pnpm --filter @auditer/db migrate:dev --name add_finding_owner
# 3. Read prisma/migrations/<timestamp>_add_finding_owner/migration.sql.
#    This is the file that will run on production. If it contains a DROP that
#    you did not intend, fix it NOW — before it is committed and checksummed.
# 4. Commit schema.prisma and the migration directory together.
```

`migrate dev` needs to create and drop a shadow database, so the local role
needs `CREATEDB` (the compose superuser has it). It replays the whole history
on that shadow database, which is a free check that the baseline is still
replayable from empty.

Never edit a migration that has been applied anywhere. `migrate deploy`
checksums each file and refuses one that moved — correctly, since the databases
that already ran it would never see the change. A mistake in an applied
migration is corrected by a new migration.

## The baseline

`prisma/migrations/20260824120000_baseline/` is the schema as it stood the day
the project left `db push`: 1 extension, 13 enums, 22 tables, 13 unique
indexes, 22 indexes, 22 foreign keys. It was produced mechanically:

```sh
prisma migrate diff --from-empty --to-schema-datamodel prisma/schema.prisma --script
```

Production already had all of it, and no `_prisma_migrations` table at all, so
that migration is **recorded as applied there rather than executed** — running
it would `CREATE TABLE` over live rows. On a database that starts empty it runs
normally. `scripts/migrate-deploy.sh` decides which of the two it is looking at;
its header explains how and why the test it uses is the safe one.

## Row-Level Security

RLS is the deny-by-default backstop behind the app's `organizationId` filtering:
if a `WHERE` is ever forgotten, Postgres still refuses the other tenant's rows.
It used to be applied by a `psql -f prisma/sql/rls.sql` bolted onto the end of
the deploy, which is exactly as reliable as it sounds — nothing tied it to the
schema, so a table could ship without a policy and no signal would be produced.

It is now part of the migration history. Three files, one job each:

| File | Role |
| --- | --- |
| `prisma/sql/rls.sql` | the single human-edited source; idempotent by construction |
| `prisma/migrations/*_rls*/migration.sql` | the frozen, checksummed copy that actually runs |
| `prisma/sql/rls-verify.sql` | read-only assertion, run after every `migrate deploy` |

**To change a policy or add a tenant table**: edit `prisma/sql/rls.sql` (add the
table to `tenant_tables`), then create a migration directory
`<timestamp>_rls_<what_changed>/` whose `migration.sql` is a header comment, the
marker line `-- >>> BEGIN verbatim copy of prisma/sql/rls.sql ...`, and then the
**whole** new `rls.sql` — not a delta. The file converges the entire policy set
in one pass, so replaying it wholesale is both the smallest thing to review and
the only version that cannot leave a table half-covered.

```sh
pnpm --filter @auditer/db rls:check    # fails if rls.sql and the newest _rls migration drifted
pnpm --filter @auditer/db rls:verify   # fails if a live database has an unguarded tenant table
```

`rls:check` is the guard against editing `rls.sql` and forgetting the migration
— a mistake that changes nothing in production and produces no error, which is
the worst shape a mistake can have. `rls:verify` is the guard against adding a
model with an `organizationId` and forgetting `tenant_tables`; the deploy runs
it on every pass and fails on any table that is not RLS-enabled, FORCEd and
policied, or if the `auditer_app` role is missing (without that role the app
would connect as the owner, which bypasses RLS entirely).

Two tables carry an `organizationId` and are deliberately exempt, listed in both
`rls.sql` and `rls-verify.sql`: `sessions` (the row that *establishes* the
tenant — a GUC-keyed policy would make every login resolve to zero rows) and
`ai_usage_ledger` (ops accounting written outside any tenant context).

## Deploying

```sh
pnpm --filter @auditer/db bootstrap    # = bash scripts/migrate-deploy.sh
```

The same script the deploy workflow runs. It is idempotent on both an existing
and a brand-new database: baseline-resolve at most once, `migrate deploy` for
whatever is pending, RLS assertion at the end. Running it ten times in a row
changes nothing after the first.
