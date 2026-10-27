-- Row-level security, part 1 of 4: the roles (ADR 0012, section 3 and 4).
--
-- Four NOLOGIN group roles. A deployment creates its logins as members of them (docs/database/tenancy.md):
--
--   factory_app       tenant work. The policies of part 2 show it the rows of one tenant at a time.
--   factory_system    the engine's cross-tenant loops: find claimable stage runs, expired leases and
--                     unpublished events. Part 3 gives it a read-only view of the columns those loops
--                     need and nothing else. It is NOT a bypass: it has no BYPASSRLS, and its policies
--                     list the tables and commands it may use.
--   factory_lookup    owns the two SECURITY DEFINER lookups of part 4 and nothing else. Nobody is a member.
--   factory_resolver  may run those two lookups. The login that authenticates API requests belongs to it.
--
-- None is a superuser, none bypasses row-level security, none owns a table, none can log in. A login
-- may not belong to both factory_app and factory_system: permissive policies are combined with OR, so
-- such a login would see every row. The `rls` database test checks the memberships of the database it
-- runs on, and the storage crate checks its own role at start-up (docs/database/for-the-storage-crate.md).
--
-- Roles are cluster wide. As in the foundation migration, an existing role of the same name is kept if
-- it has no unsafe attribute, and the migration stops if it has one.
DO $$
DECLARE
  group_name text;
  r pg_catalog.pg_roles%ROWTYPE;
BEGIN
  FOREACH group_name IN ARRAY ARRAY['factory_system', 'factory_lookup', 'factory_resolver'] LOOP
    SELECT * INTO r FROM pg_catalog.pg_roles WHERE rolname = group_name;
    IF NOT FOUND THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS', group_name);
    ELSIF r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolcanlogin THEN
      RAISE EXCEPTION 'the existing role % has too many powers (superuser, createrole, createdb, replication, bypassrls or login)', group_name;
    END IF;
  END LOOP;
END
$$;

-- factory_app already has USAGE on the schema. The other groups need it to reach what part 3 and 4 grant.
GRANT USAGE ON SCHEMA public TO factory_system, factory_lookup, factory_resolver;
