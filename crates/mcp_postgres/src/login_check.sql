-- Whether the login of the server is fit to serve, as one row (Inspector::check_login).
--
-- An allowlist of what the login is, not a list of what it must not be (TR-1 of
-- docs/reviews/troubleshooter-security-review.md). The observer's policies are USING (true) on
-- every tenant, so any table privilege the login holds beyond the group's is a cross-tenant read.
WITH me AS (
  SELECT r.oid, r.rolname, r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolreplication
    FROM pg_catalog.pg_roles r WHERE r.rolname = current_user
), here AS (
  SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()
), grp AS (
  SELECT g.oid FROM pg_catalog.pg_roles g WHERE g.rolname = 'factory_observer'
), visible AS (
  SELECT c.oid, n.nspname, c.relname, c.relkind
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%'
     AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
)
SELECT me.rolname::text AS login,
       me.rolsuper AS superuser,
       me.rolbypassrls AS bypassrls,
       me.rolcreaterole AS createrole,
       me.rolcreatedb AS createdb,
       me.rolreplication AS replication,
       coalesce((SELECT pg_catalog.pg_has_role(me.oid, grp.oid, 'MEMBER') FROM grp), false) AS observer,
       -- Direct memberships besides the group: everything the login holds must come through the group.
       coalesce((SELECT pg_catalog.string_agg(g.rolname::text, ', ' ORDER BY g.rolname)
                   FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
                  WHERE m.member = me.oid AND g.rolname <> 'factory_observer'), '') AS other_groups,
       -- The roles whose privileges the group itself passes on. After migration 003100: none.
       coalesce((SELECT pg_catalog.string_agg(g.rolname::text, ', ' ORDER BY g.rolname)
                   FROM pg_catalog.pg_roles g, grp
                  WHERE g.oid <> grp.oid AND pg_catalog.pg_has_role(grp.oid, g.oid, 'USAGE')), '') AS group_inherits,
       -- Predefined roles by effective membership. pg_read_all_stats by its privileges: migration 002900, run
       -- again for another database of the cluster, grants it to the NOINHERIT group for a moment, and that
       -- grant passes nothing on.
       coalesce((SELECT pg_catalog.string_agg(g.rolname::text, ', ' ORDER BY g.rolname)
                   FROM pg_catalog.pg_roles g
                  WHERE g.rolname LIKE 'pg\_%' AND g.oid <> me.oid
                    AND CASE WHEN g.rolname = 'pg_read_all_stats'
                             THEN pg_catalog.pg_has_role(me.oid, g.oid, 'USAGE')
                             ELSE pg_catalog.pg_has_role(me.oid, g.oid, 'MEMBER') END), '') AS predefined,
       -- Ownership of anything in this database (or of a shared object such as a database), by the login or a
       -- role it is a member of.
       EXISTS (SELECT 1 FROM pg_catalog.pg_shdepend d, here
                WHERE d.deptype = 'o' AND d.refclassid = 'pg_catalog.pg_authid'::pg_catalog.regclass
                  AND (d.dbid = here.oid OR d.dbid = 0)
                  AND pg_catalog.pg_has_role(me.oid, d.refobjid, 'MEMBER')) AS owns,
       -- The property itself, whatever role or PUBLIC grant gives it: a column readable by the login that the
       -- migrations did not grant to the group by name (a PUBLIC grant counts as more, since has_column_privilege
       -- would show it for the group too), and a table the login may write. An extension's own relations, such as
       -- the pg_stat_statements view, are not the factory's and are left out.
       coalesce((SELECT pg_catalog.string_agg(DISTINCT v.nspname || '.' || v.relname, ', ')
                   FROM visible v JOIN pg_catalog.pg_attribute a ON a.attrelid = v.oid, grp
                  WHERE v.relkind <> 'S' AND a.attnum > 0 AND NOT a.attisdropped
                    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend e
                                     WHERE e.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                                       AND e.objid = v.oid AND e.deptype = 'e')
                    AND pg_catalog.has_column_privilege(v.oid, a.attnum, 'SELECT')
                    AND NOT EXISTS (SELECT 1 FROM pg_catalog.aclexplode(a.attacl) x
                                     WHERE x.grantee = grp.oid AND x.privilege_type = 'SELECT')
                    AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class t, pg_catalog.aclexplode(t.relacl) x
                                     WHERE t.oid = v.oid AND x.grantee = grp.oid AND x.privilege_type = 'SELECT')), '') AS reads_more,
       coalesce((SELECT pg_catalog.string_agg(v.nspname || '.' || v.relname, ', ' ORDER BY v.nspname, v.relname)
                   FROM visible v
                  WHERE v.relkind <> 'S'
                    AND pg_catalog.has_table_privilege(v.oid, 'INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')), '') AS writes,
       coalesce((SELECT pg_catalog.string_agg(v.nspname || '.' || v.relname, ', ' ORDER BY v.nspname, v.relname)
                   FROM visible v
                  WHERE CASE WHEN v.relkind = 'S' THEN pg_catalog.has_sequence_privilege(v.oid, 'USAGE, UPDATE') ELSE false END), '') AS sequences
  FROM me
