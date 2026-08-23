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
-- Applied via `prisma migrate` as a raw-SQL step. Idempotent.

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
