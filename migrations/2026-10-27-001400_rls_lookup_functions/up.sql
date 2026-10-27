-- Row-level security, part 4 of 4: the two lookups that happen before a tenant is known (ADR 0012, section 4).
--
-- Authenticating an API token and binding a webhook to a repository cannot name a tenant. Finding the
-- tenant is their job. Two SECURITY DEFINER functions do it, instead of a policy that admits every row of
-- api_tokens and repositories to a session:
--
--   resolve_token(p_token_hash bytea, p_audience text)           -> (tenant_id, principal_id)
--   resolve_installation(p_installation_id bigint, p_github_repository_id bigint)
--                                                                -> (tenant_id, repository_id)
--
-- They return identifiers and nothing else, and zero rows with no reason for every kind of miss (not
-- found, expired, revoked, wrong audience, disabled principal, disabled tenant, disabled repository).
--
-- How they are made safe:
--   * They are owned by factory_lookup, a NOLOGIN role that owns nothing else and has no members. The
--     role is bound by row-level security like any other: it has its own read-only policies, on the columns
--     these functions read and no others. A function owned by the table owner would see no row at all,
--     because FORCE ROW LEVEL SECURITY binds the owner (measured and recorded in docs/database/tenancy.md).
--   * Each pins `search_path = pg_catalog, pg_temp` and qualifies every table with `public.`, so a
--     temporary table or a schema earlier on the caller's path cannot stand in for a real one.
--   * PUBLIC cannot execute them. Only factory_resolver can, and the login that authenticates API
--     requests is a member of it. The tenant role (factory_app) cannot: a compromised worker could
--     otherwise test token hashes or ask which tenant holds an installation.
--
-- The installation lookup takes the GitHub repository id as well as the installation id. One installation
-- covers many repositories, so the installation alone does not name one. The pair does, because
-- repositories.github_repository_id is unique across tenants. The port sketch in the slice plan names
-- resolve_installation(installation) only; the storage notes say what changes.
--
-- The view active_api_tokens, "the one place that says what a usable token is", now also requires that
-- the tenant is not disabled. It is read by the tenant role under its own policies and by the lookup
-- under factory_lookup's. Nothing used tenants.disabled_at before this migration.

-- 0. A precondition, stated before anything is changed. Handing the functions to factory_lookup (step 4) needs
--    the right to become that role. A superuser has it. So does the role that created factory_lookup, on
--    PostgreSQL 16 and later, because creating a role grants its creator the ADMIN option on it. A migration
--    role that did not create the roles, and is not a superuser, cannot continue.
DO $$
BEGIN
  IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user)
     AND current_setting('server_version_num')::int >= 160000
     AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m
                      WHERE m.roleid = 'factory_lookup'::regrole AND m.member = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
                        AND m.admin_option) THEN
    RAISE EXCEPTION 'run this migration as a superuser, or as the role that created factory_lookup: it must grant factory_lookup to itself for a moment to hand it the two lookup functions (docs/database/migration-safety.md)';
  END IF;
END
$$;

-- 1. What factory_lookup may read, column by column, and the policies that let it read every row of them.
GRANT SELECT (id, disabled_at) ON tenants TO factory_lookup;
GRANT SELECT (tenant_id, id, disabled_at) ON principals TO factory_lookup;
GRANT SELECT (tenant_id, id, principal_id, token_hash, audience, expires_at, revoked_at) ON api_tokens TO factory_lookup;
GRANT SELECT (tenant_id, id, github_installation_id, github_repository_id, enabled) ON repositories TO factory_lookup;

CREATE POLICY lookup_read ON tenants AS PERMISSIVE FOR SELECT TO factory_lookup USING (true);
CREATE POLICY lookup_read ON principals AS PERMISSIVE FOR SELECT TO factory_lookup USING (true);
CREATE POLICY lookup_read ON api_tokens AS PERMISSIVE FOR SELECT TO factory_lookup USING (true);
CREATE POLICY lookup_read ON repositories AS PERMISSIVE FOR SELECT TO factory_lookup USING (true);

-- 2. The usable-token view, with the tenant check. Same columns, same order.
CREATE OR REPLACE VIEW active_api_tokens WITH (security_invoker = true) AS
SELECT t.tenant_id, t.id, t.principal_id, t.token_hash, t.audience, t.expires_at
  FROM api_tokens t
  JOIN principals p ON p.tenant_id = t.tenant_id AND p.id = t.principal_id
  JOIN tenants n ON n.id = t.tenant_id
 WHERE t.revoked_at IS NULL
   AND t.expires_at > now()
   AND p.disabled_at IS NULL
   AND n.disabled_at IS NULL;

GRANT SELECT ON active_api_tokens TO factory_lookup;

-- 3. The functions.
CREATE FUNCTION resolve_token(p_token_hash bytea, p_audience text)
RETURNS TABLE (tenant_id uuid, principal_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT t.tenant_id, t.principal_id
    FROM public.active_api_tokens t
   WHERE t.token_hash = p_token_hash AND t.audience = p_audience
$$;

CREATE FUNCTION resolve_installation(p_installation_id bigint, p_github_repository_id bigint)
RETURNS TABLE (tenant_id uuid, repository_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $$
  SELECT r.tenant_id, r.id
    FROM public.repositories r
    JOIN public.tenants n ON n.id = r.tenant_id
   WHERE r.github_installation_id = p_installation_id
     AND r.github_repository_id = p_github_repository_id
     AND r.enabled
     AND n.disabled_at IS NULL
$$;

-- 4. Ownership and execution. Handing a function to another role needs the right to become that role and,
--    for a role that is not a superuser, CREATE on the schema. Both are given for these statements only and
--    taken back. (A superuser migration needs neither; the statements are harmless to it.) The privileges
--    are set while the membership still exists, because only the owner, or a member of it, may grant them.
GRANT factory_lookup TO CURRENT_USER;
GRANT CREATE ON SCHEMA public TO factory_lookup;

ALTER FUNCTION resolve_token(bytea, text) OWNER TO factory_lookup;
ALTER FUNCTION resolve_installation(bigint, bigint) OWNER TO factory_lookup;

REVOKE ALL ON FUNCTION resolve_token(bytea, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION resolve_installation(bigint, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resolve_token(bytea, text) TO factory_resolver;
GRANT EXECUTE ON FUNCTION resolve_installation(bigint, bigint) TO factory_resolver;

REVOKE CREATE ON SCHEMA public FROM factory_lookup;
REVOKE factory_lookup FROM CURRENT_USER;
