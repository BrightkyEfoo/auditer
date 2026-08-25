-- Row-Level Security : rejeu intégral pour inclure `run_events`.
--
-- La nouvelle table porte organizationId. Sans politique, elle échapperait à
-- l'isolation entre organisations — et rls-verify.sql ferait échouer le
-- déploiement en la trouvant dans le catalogue mais absente de la liste
-- `tenant_tables`. Cette garde existe exactement pour ce cas.
--
-- Le fichier source est idempotent par construction : chaque politique est
-- DROP ... IF EXISTS'd avant d'être recréée, ENABLE ROW LEVEL SECURITY est sans
-- effet quand elle est déjà active. C'est ce qui rend ce rejeu sûr sur une base
-- de production déjà policée par la migration précédente.
--
-- Ne pas éditer sous le marqueur : `migrate deploy` refuse un fichier dont la
-- somme de contrôle a bougé. Toute évolution passe par une NOUVELLE migration.

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
    'targets','audit_runs','scans','run_events','findings','triage_states',
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
