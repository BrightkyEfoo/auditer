-- Row-Level Security, brought into the migration history.
--
-- ── WHY A SEPARATE MIGRATION AND NOT FOLDED INTO THE BASELINE ────────────
--
-- Both options were on the table. This one wins for three reasons.
--
-- 1. The baseline is MACHINE-GENERATED (`prisma migrate diff --from-empty`).
--    Keeping it byte-for-byte reproducible from schema.prisma is what makes it
--    reviewable — anyone can regenerate it and diff. Hand-written policy SQL
--    pasted into that file destroys that property: the next person who
--    regenerates it to check a doubt silently drops every policy.
--
-- 2. Production must treat the two DIFFERENTLY, and that is only possible if
--    they are two rows in `_prisma_migrations`. The existing database already
--    has the tables, so the baseline must be marked applied WITHOUT running.
--    But its policies came from a `psql -f` that nobody can prove was replayed
--    after the last schema change — so this one must actually RUN there. One
--    combined migration cannot be half-skipped. Two can, and
--    scripts/migrate-deploy.sh does exactly that: resolve the baseline, apply
--    this one for real.
--
-- 3. That last move is only safe because the SQL below is IDEMPOTENT, and it is
--    idempotent by construction, not by luck: CREATE ROLE is guarded by a
--    pg_roles lookup, the helper is CREATE OR REPLACE, GRANT is naturally
--    repeatable, ALTER TABLE ... ENABLE ROW LEVEL SECURITY is a no-op when
--    already enabled, and every policy is DROP POLICY IF EXISTS'd before being
--    recreated. Running it against a database that already has the policies
--    converges instead of failing.
--
-- ── HOW POLICIES CHANGE FROM NOW ON ──────────────────────────────────────
--
-- `prisma migrate deploy` applies each migration exactly once and refuses a
-- file whose checksum moved, so this directory is frozen. A policy change is a
-- NEW migration directory named `<timestamp>_rls_<what_changed>` holding the
-- FULL new content of prisma/sql/rls.sql — not a delta. Because the file
-- converges the entire policy set, replaying the whole thing is both the
-- simplest diff to review and the only version that cannot leave a table
-- half-covered.
--
-- prisma/sql/rls.sql stays the single human-edited source (several comments
-- across the repo point at that path, and reading "the current policies" out of
-- a chain of migrations would be worse than reading one file). The copy below
-- is verbatim; scripts/rls-check.sh fails the build if the two ever drift.
--
-- ── WHAT THIS DOES NOT DO ────────────────────────────────────────────────
--
-- It does not make a future tenant table policy-covered on its own. Adding a
-- table with an organizationId and forgetting to extend `tenant_tables` still
-- produces a table that RLS does not guard. What closes that gap is
-- prisma/sql/rls-verify.sql, run after every `migrate deploy` (see
-- scripts/migrate-deploy.sh): it fails the deploy on any unguarded
-- organizationId table rather than letting the hole ship quietly.

-- >>> BEGIN verbatim copy of prisma/sql/rls.sql — do not edit here, edit there
-- Row-Level Security: deny-by-default tenant isolation.
--
-- App code scopes queries by organizationId (primary defense). RLS is the
-- backstop: if a WHERE is ever forgotten, Postgres still refuses to return
-- another tenant's rows. Enforced against the DATABASE_APP_URL role only —
-- the migration/owner role bypasses RLS to run DDL.
--
-- The app opens every tenant request inside a transaction that runs
--   SET LOCAL app.current_org_id = '<org>'
-- (see src/tenant.ts). Policies compare organization_id to that GUC.
--
-- SOURCE OF TRUTH, but NOT what runs on a server. This file is the one place a
-- human edits the policy set; the copy that actually executes is the newest
-- prisma/migrations/*_rls*/migration.sql, because `prisma migrate deploy` only
-- ever runs files it has checksummed. Editing here alone changes nothing in
-- production — scripts/rls-check.sh fails the build to say so, and the fix is a
-- NEW `<timestamp>_rls_<change>` migration carrying this file in full.
--
-- IDEMPOTENT BY CONSTRUCTION, and that is load-bearing rather than incidental:
-- it is what lets the whole file be replayed as a migration against a database
-- that already has the policies (the production one, policed until now by a
-- `psql -f` nobody could prove had been replayed). CREATE ROLE is guarded by a
-- pg_roles lookup, the helper is CREATE OR REPLACE, GRANT is repeatable,
-- ENABLE ROW LEVEL SECURITY is a no-op when already on, and each policy is
-- DROP ... IF EXISTS'd before being recreated. Keep every future addition to
-- this file idempotent too, or that replay stops being safe.
--
-- The hand-maintained `tenant_tables` list below is checked against the real
-- catalog by prisma/sql/rls-verify.sql after every deploy: a new table carrying
-- organizationId that is missing from the list fails the deploy.

-- ── App role (non-owner; RLS applies to it) ──────────────────────────────
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auditer_app') THEN
    CREATE ROLE auditer_app LOGIN PASSWORD 'auditer_app';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO auditer_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO auditer_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auditer_app;

-- ── Helper: current tenant from the request-scoped GUC ───────────────────
CREATE OR REPLACE FUNCTION current_org_id() RETURNS text
  LANGUAGE sql STABLE AS $$
  SELECT current_setting('app.current_org_id', true)
$$;

-- ── Enable + policy on every tenant-scoped table ─────────────────────────
-- FORCE so even the table owner is subject to RLS when connected as the app.
DO $$
DECLARE
  t text;
  -- Only tables that carry organizationId directly. pillar_results is scoped
  -- transitively via audit_runs (RLS'd); ai_usage_ledger is nullable ops data
  -- written outside a tenant context — both intentionally excluded.
  --
  -- `sessions` is excluded even though it carries organizationId, and that is a
  -- deliberate ordering constraint, not an oversight: the session row is what
  -- ESTABLISHES the tenant. Resolving it happens before any org is known, so a
  -- deny-by-default policy keyed on the GUC would make every login resolve to
  -- zero rows and lock the product out entirely. The row is reachable only by
  -- the SHA-256 of a 32-byte random token, and the app never lists sessions —
  -- lookup is always findUnique on tokenHash. Any future query that filters
  -- sessions by anything else must scope by userId explicitly.
  tenant_tables text[] := ARRAY[
    'organizations','memberships','invitations','connections','repositories',
    'targets','audit_runs','scans','findings','triage_states',
    'reports','branding_profiles','artifacts','activity_logs','abuse_events'
  ];
  org_col text;
BEGIN
  FOREACH t IN ARRAY tenant_tables LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);

    -- organizations keys on id; everything else on organizationId. Prisma keeps
    -- camelCase column names (only table names are @@map'd to snake_case), and
    -- %I below quotes the identifier correctly.
    IF t = 'organizations' THEN
      org_col := 'id';
    ELSE
      org_col := 'organizationId';
    END IF;

    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I
         USING (%I = current_org_id())
         WITH CHECK (%I = current_org_id())',
      t, org_col, org_col
    );
  END LOOP;
END
$$;
