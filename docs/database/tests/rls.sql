-- Suite: rls
-- Proves ADR 0012, the database part of NT-TEN-01: row-level security on every tenant-owned table, a
-- separate role for the system scope, and two narrow SECURITY DEFINER lookups for the work that happens
-- before a tenant is known. The structure is read from the catalog, so a new table without a policy
-- fails here. The checks that need real logins and separate connections (a reused connection, a
-- poisoned pool, concurrent claimers) run from scripts/db-test.sh after this file.
--
-- How a check is made. Fixtures are written by the table owner (a superuser in the test cluster, which
-- bypasses row-level security by its nature, so it can arrange the data). Every attempt on that data is
-- then made as a group role (SET LOCAL ROLE) inside a subtransaction that is always rolled back, with
-- the tenant setting that Store::begin would make. The group roles stand for the logins of the
-- deployment, which are members of them.

-- ---------------------------------------------------------------------------------------------
-- 1. The roles.

-- What is wrong with a role that is supposed to be an unprivileged group. An empty string means nothing.
CREATE FUNCTION dbtest.group_role_problems(p_role text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  r pg_roles%ROWTYPE;
  problems text := '';
  n bigint;
BEGIN
  SELECT * INTO r FROM pg_roles WHERE rolname = p_role;
  IF NOT FOUND THEN
    RETURN p_role || ' does not exist; ';
  END IF;
  IF r.rolcanlogin THEN problems := problems || 'can log in; '; END IF;
  IF r.rolsuper THEN problems := problems || 'is a superuser; '; END IF;
  IF r.rolbypassrls THEN problems := problems || 'has BYPASSRLS; '; END IF;
  IF r.rolcreaterole THEN problems := problems || 'can create roles; '; END IF;
  IF r.rolcreatedb THEN problems := problems || 'can create databases; '; END IF;
  IF r.rolreplication THEN problems := problems || 'can replicate; '; END IF;
  SELECT count(*) INTO n FROM pg_class WHERE relowner = r.oid;
  IF n > 0 THEN problems := problems || format('owns %s relations (tables, views, sequences or indexes); ', n); END IF;
  SELECT count(*) INTO n FROM pg_namespace WHERE nspowner = r.oid;
  IF n > 0 THEN problems := problems || format('owns %s schemas; ', n); END IF;
  SELECT count(*) INTO n FROM pg_database WHERE datdba = r.oid;
  IF n > 0 THEN problems := problems || format('owns %s databases; ', n); END IF;
  IF has_schema_privilege(p_role, 'public', 'CREATE') THEN problems := problems || 'can create objects in the public schema; '; END IF;
  IF has_database_privilege(p_role, current_database(), 'CREATE') THEN problems := problems || 'can create schemas in the database; '; END IF;
  SELECT count(*) INTO n FROM pg_auth_members WHERE member = r.oid;
  IF n > 0 THEN problems := problems || format('is a member of %s roles; ', n); END IF;
  RETURN problems;
END
$$;

-- Every member, direct or through other roles, of the four groups. Superusers are not listed as members
-- by this walk: the walk follows pg_auth_members only, because PostgreSQL treats a superuser as a member
-- of everything and that would hide the grants that were really made.
CREATE FUNCTION dbtest.group_members() RETURNS TABLE (grp text, member text, can_login boolean, is_super boolean, bypass_rls boolean)
LANGUAGE sql AS $$
  WITH RECURSIVE walk(grp_oid, member_oid) AS (
    SELECT g.oid, a.member
      FROM pg_roles g JOIN pg_auth_members a ON a.roleid = g.oid
     WHERE g.rolname IN ('factory_app', 'factory_system', 'factory_lookup', 'factory_resolver')
    UNION
    SELECT w.grp_oid, a.member FROM walk w JOIN pg_auth_members a ON a.roleid = w.member_oid
  )
  SELECT g.rolname::text, m.rolname::text, m.rolcanlogin, m.rolsuper, m.rolbypassrls
    FROM walk w JOIN pg_roles g ON g.oid = w.grp_oid JOIN pg_roles m ON m.oid = w.member_oid
$$;

-- Pairs of groups that no role may belong to together. Permissive policies are combined with OR, so a
-- login in both factory_app and factory_system would see every row. factory_resolver is for the login
-- that authenticates requests and must not also be the engine's system login. factory_lookup owns the
-- two lookup functions and nobody may be it.
CREATE FUNCTION dbtest.membership_conflicts() RETURNS text LANGUAGE sql AS $$
  SELECT coalesce(string_agg(DISTINCT a.member || ' is a member of both ' || least(a.grp, b.grp) || ' and ' || greatest(a.grp, b.grp), '; '), '')
       || coalesce((SELECT '; ' || string_agg(DISTINCT member || ' is a member of factory_lookup', '; ') FROM dbtest.group_members() WHERE grp = 'factory_lookup' AND NOT is_super), '')
    FROM dbtest.group_members() a
    JOIN dbtest.group_members() b ON a.member = b.member AND a.grp < b.grp
   WHERE a.grp IN ('factory_app', 'factory_system', 'factory_resolver') AND b.grp IN ('factory_app', 'factory_system', 'factory_resolver')
     AND (a.grp, b.grp) <> ('factory_app', 'factory_resolver')
$$;

DO $$
DECLARE
  g text;
BEGIN
  FOREACH g IN ARRAY ARRAY['factory_app', 'factory_system', 'factory_lookup', 'factory_resolver'] LOOP
    PERFORM dbtest.expect_eq(g || ' is a NOLOGIN group with no superuser, BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION, owns nothing and cannot create in public',
      dbtest.group_role_problems(g), '');
  END LOOP;
  PERFORM dbtest.expect_eq('no login belongs to both factory_app and factory_system, to factory_system and factory_resolver, or to factory_lookup',
    dbtest.membership_conflicts(), '');
  PERFORM dbtest.expect_eq('no member of any group is a superuser or has BYPASSRLS',
    (SELECT coalesce(string_agg(grp || ':' || member, ', '), '') FROM dbtest.group_members() WHERE is_super OR bypass_rls), '');
END
$$;

-- Control: the check is not vacuous. A login in two incompatible groups is reported, and so is a member of
-- the lookup owner and a member with BYPASSRLS. Everything is rolled back.
DO $$
DECLARE
  seen text;
BEGIN
  BEGIN
    CREATE ROLE dbtest_both LOGIN IN ROLE factory_app, factory_system;
    seen := dbtest.membership_conflicts();
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN SQLSTATE 'XX998' THEN NULL;
  END;
  PERFORM dbtest.expect_true('control: a login in both factory_app and factory_system is reported', seen LIKE '%dbtest_both is a member of both factory_app and factory_system%', seen);

  BEGIN
    CREATE ROLE dbtest_lookup_member LOGIN IN ROLE factory_lookup;
    seen := dbtest.membership_conflicts();
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN SQLSTATE 'XX998' THEN NULL;
  END;
  PERFORM dbtest.expect_true('control: a login that is a member of factory_lookup is reported', seen LIKE '%dbtest_lookup_member is a member of factory_lookup%', seen);

  BEGIN
    CREATE ROLE dbtest_bypasser LOGIN BYPASSRLS IN ROLE factory_app;
    seen := (SELECT coalesce(string_agg(grp || ':' || member, ', '), '') FROM dbtest.group_members() WHERE is_super OR bypass_rls);
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN SQLSTATE 'XX998' THEN NULL;
  END;
  PERFORM dbtest.expect_eq('control: a group member with BYPASSRLS is reported', seen, 'factory_app:dbtest_bypasser');

  BEGIN
    ALTER ROLE factory_system BYPASSRLS;
    seen := dbtest.group_role_problems('factory_system');
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN SQLSTATE 'XX998' THEN NULL;
  END;
  PERFORM dbtest.expect_true('control: BYPASSRLS on a group role is reported', seen LIKE '%has BYPASSRLS%', seen);
END
$$;
