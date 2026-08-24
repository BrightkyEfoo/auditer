-- RLS assertion — read-only. Changes nothing, fails loudly.
--
-- WHY THIS FILE EXISTS. rls.sql enumerates the tenant tables by hand
-- (`tenant_tables text[] := ARRAY[...]`). A hand-written list is only correct
-- until the next model lands: adding a table with an organizationId and
-- forgetting to extend the array produces a table Postgres does not guard, and
-- NOTHING anywhere fails. The tenant leak that follows is invisible until a
-- customer sees another customer's findings. This turns that silent gap into a
-- red deploy.
--
-- It runs after `prisma migrate deploy` (scripts/migrate-deploy.sh), i.e. on
-- EVERY deploy, which is the property the old `psql -f rls.sql` step never had:
-- the migration that adds the table and the check that the table is covered are
-- then evaluated in the same breath.
--
-- Run with -v ON_ERROR_STOP=1 so the RAISE below actually stops the caller.

DO $$
DECLARE
  -- Deliberate exclusions, each justified in prisma/sql/rls.sql. Repeated here
  -- rather than derived, so that dropping a table OUT of the policy set is an
  -- edit in two places — the friction is the point.
  --
  --   sessions        the row that ESTABLISHES the tenant; a GUC-keyed policy
  --                   would make every login resolve to zero rows.
  --   ai_usage_ledger nullable ops accounting, written outside a tenant context.
  exempt text[] := ARRAY['sessions', 'ai_usage_ledger'];
  offenders text;
BEGIN
  -- Tables that OUGHT to be guarded: anything in public carrying an
  -- organizationId column, plus `organizations` itself (it keys on id, so the
  -- column rule alone would miss precisely the root of the tenancy tree).
  WITH expected AS (
    SELECT c.oid, c.relname
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'r'
       AND NOT (c.relname = ANY (exempt))
       AND (
         c.relname = 'organizations'
         OR EXISTS (
           SELECT 1 FROM pg_attribute a
            WHERE a.attrelid = c.oid
              AND a.attname = 'organizationId'
              AND a.attnum > 0
              AND NOT a.attisdropped
         )
       )
  )
  SELECT string_agg(
           format('%s (%s)', e.relname,
                  concat_ws(', ',
                    CASE WHEN NOT c.relrowsecurity      THEN 'RLS disabled' END,
                    CASE WHEN NOT c.relforcerowsecurity THEN 'not FORCEd'   END,
                    CASE WHEN p.polname IS NULL         THEN 'no tenant_isolation policy' END)),
           '; ' ORDER BY e.relname)
    INTO offenders
    FROM expected e
    JOIN pg_class c ON c.oid = e.oid
    LEFT JOIN pg_policy p ON p.polrelid = e.oid AND p.polname = 'tenant_isolation'
   WHERE NOT c.relrowsecurity
      OR NOT c.relforcerowsecurity
      OR p.polname IS NULL;

  IF offenders IS NOT NULL THEN
    RAISE EXCEPTION
      'RLS gap: % — add the table to tenant_tables in prisma/sql/rls.sql and ship a new _rls migration carrying the whole file',
      offenders;
  END IF;

  -- The policies are worthless if the role they constrain is absent: the app
  -- would silently fall back to connecting as the owner, which BYPASSES RLS.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'auditer_app') THEN
    RAISE EXCEPTION 'RLS gap: role auditer_app is missing — DATABASE_APP_URL would connect as an RLS-exempt owner';
  END IF;

  RAISE NOTICE 'rls-verify: every tenant table is RLS-enabled, FORCEd and policied; auditer_app exists';
END
$$;
