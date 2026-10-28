-- The start-up check of a connection pool's role (ADR 0012, section 6). The storage crate runs it once per
-- pool, as the login of that pool, and refuses to become ready when the answer is wrong. The `rls` suite
-- runs the same text as three real logins and as a superuser, so the query in the storage notes is the
-- one that was tried.
--
-- One row, eight columns, in this order:
--   superuser, bypassrls, owns_relations   all three must be false for every pool
--   tenant_group                           true for the tenant pool of the worker, false for the others
--   system_group                           true for the system pool, false for the others
--   resolver_group                         true for the API pool only
--   lookup_group                           false for every pool
--   api_group                              true for the API pool only (factory_api_app, finding API-3)
-- A tenant pool is ready when it is not a superuser, does not bypass, owns nothing, is in factory_app and
-- is not in factory_system. The system pool is the mirror image. The API pool is in factory_api_app and
-- factory_resolver and in neither factory_app nor factory_system. A superuser is a member of every group in
-- PostgreSQL's eyes, so the first column is read first.
SELECT r.rolsuper AS superuser,
       r.rolbypassrls AS bypassrls,
       EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.relowner = r.oid) AS owns_relations,
       pg_catalog.pg_has_role(current_user, 'factory_app', 'MEMBER') AS tenant_group,
       pg_catalog.pg_has_role(current_user, 'factory_system', 'MEMBER') AS system_group,
       pg_catalog.pg_has_role(current_user, 'factory_resolver', 'MEMBER') AS resolver_group,
       pg_catalog.pg_has_role(current_user, 'factory_lookup', 'MEMBER') AS lookup_group,
       pg_catalog.pg_has_role(current_user, 'factory_api_app', 'MEMBER') AS api_group
  FROM pg_catalog.pg_roles r
 WHERE r.rolname = current_user;
