-- The person who enables a repository is not the person who attested its project map, unless the repository was
-- registered as a single-maintainer one (finding REG-6 of docs/reviews/engine-registration-and-status-security-review.md;
-- the product owner decided on 2026-11-03).
--
-- Before this migration one person with the designations of both acts could register, attest and enable a repository
-- in three calls, so the gate "a person looked at the map, and a second person approved it" was a flag. The table
-- already records who enabled a repository and for which commit (enabled_by_principal_id and
-- enabled_project_map_commit, migration 2026-11-02-002500), so this migration needs no column for that.
--
-- What this migration does:
--
--   1. One column on repositories: single_maintainer, boolean, NOT NULL, default false. False is the strict rule.
--      True lets the same person attest the map and enable the repository. It exists so that a project owner who
--      works alone can still run the factory. The flag is for a repository, not a tenant, and it is a statement made
--      at registration by an operator: the audit record of the registration says so (apps/api records
--      `single_maintainer=true` in the subject of `repository.registered`).
--   2. The flag is written at registration and never after. The API login gets INSERT on the column and no UPDATE
--      on it. The worker's group has no UPDATE on it either. The trigger repositories_project_map_guard refuses
--      a change of the flag from a login of either group, which is the second guard behind the grants. The table
--      owner is an administrator and not a login of the factory; it may change the flag, and that leaves no audit
--      record, so a change by hand has to write one by hand (docs/guides/onboarding.md, "A single-maintainer repository").
--   3. The rule itself, in the trigger and in a CHECK: an enabled repository whose enabler is the attestor of its map
--      is refused unless single_maintainer. The trigger answers first with a clear error. The CHECK is the second
--      guard, binding for every role, the owner and a superuser included. A repository that was enabled without
--      saying who enabled it (a privileged writer, the enabler is empty) is not judged: nobody is named.
--   4. Repositories that are enabled now and whose enabler is their attestor are switched off, with a NOTICE and a
--      rise of their version, because the rule would refuse them. NO AUDIT RECORD is written for this switch-off, as
--      for the ones in migrations 2026-11-02-002400 and 2026-11-02-002500: the audit chain does not say who or what
--      switched them off, only this file and the NOTICE do. A deployment note should carry the count. A project
--      owner who works alone sets single_maintainer by hand for such a repository (the administrator path of item 2)
--      or has another person enable it.
--
-- Residual risk, stated plainly: the rule protects against a person who holds both designations. It does not protect
-- against a holder of the API database login, who can still name any active human of the tenant as the enabler
-- (finding REG-2). Migration 2026-11-03-002700 closes that for the acts that widen the factory's reach.
--
-- Expand only: one column with a constant default, which PostgreSQL 11 and later adds without a rewrite, and one
-- constraint. The constraint is added NOT VALID and then validated in this transaction. As in migration
-- 2026-11-02-002400, the two steps in one transaction give no benefit over one, because the lock of ADD CONSTRAINT is
-- held to the commit. The table is small, and the validation is a scan under that lock.

SET LOCAL lock_timeout = '5s';

-- 1.
ALTER TABLE repositories ADD COLUMN single_maintainer boolean NOT NULL DEFAULT false;

-- 4. The table forces row-level security, which binds its owner too, so the owner would see no row. The setting is
--    lifted for this one statement and put back (the same step as migration 2026-11-02-002500). The trigger of
--    migration 2026-11-02-002500 empties the record of the enabling when the repository is switched off.
ALTER TABLE repositories NO FORCE ROW LEVEL SECURITY;
DO $$
DECLARE
  switched_off bigint;
BEGIN
  UPDATE repositories SET enabled = false, version = version + 1
   WHERE enabled AND enabled_by_principal_id IS NOT NULL
     AND enabled_by_principal_id = project_map_attested_by_principal_id;
  GET DIAGNOSTICS switched_off = ROW_COUNT;
  IF switched_off > 0 THEN
    RAISE NOTICE '% repositories were enabled by the person who attested their project map and are now disabled; another person enables each one again, or an administrator sets single_maintainer', switched_off;
  END IF;
END
$$;
ALTER TABLE repositories FORCE ROW LEVEL SECURITY;

-- 3. IS NOT NULL is spelled out where a CHECK would accept NULL by accident.
ALTER TABLE repositories ADD CONSTRAINT repositories_enabler_differs_from_attestor
  CHECK (single_maintainer
         OR enabled_by_principal_id IS NULL
         OR project_map_attested_by_principal_id IS NULL
         OR enabled_by_principal_id <> project_map_attested_by_principal_id) NOT VALID;
ALTER TABLE repositories VALIDATE CONSTRAINT repositories_enabler_differs_from_attestor;

-- 2 and 3. The guard of the project map, with the two rules added at the end. The body before them is the one of
--    migration 2026-11-02-002500, unchanged.
CREATE OR REPLACE FUNCTION repositories_project_map_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  map_moved boolean;
BEGIN
  map_moved := TG_OP = 'UPDATE'
    AND (NEW.project_map_commit IS DISTINCT FROM OLD.project_map_commit
         OR NEW.project_map_attested_by_principal_id IS DISTINCT FROM OLD.project_map_attested_by_principal_id);

  IF NEW.project_map_attested_by_principal_id IS NULL THEN
    NEW.project_map_attested_at := NULL;
  ELSIF TG_OP = 'INSERT' OR map_moved THEN
    IF NOT EXISTS (SELECT 1 FROM public.principals p
                    WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.project_map_attested_by_principal_id
                      AND p.kind = 'human' AND p.disabled_at IS NULL) THEN
      RAISE EXCEPTION 'the project map must be attested by an active human principal of the tenant'
        USING ERRCODE = '23514', CONSTRAINT = 'repositories_map_attestor_is_an_active_human', TABLE = 'repositories';
    END IF;
    NEW.project_map_attested_at := now();
  ELSE
    NEW.project_map_attested_at := OLD.project_map_attested_at;
  END IF;

  -- A repository that is enabled does not stay enabled over another map or another attestor. The person who
  -- enabled it did not see this map. Whatever the statement said about enabled is overruled.
  IF map_moved AND OLD.enabled THEN
    NEW.enabled := false;
  END IF;

  IF NOT NEW.enabled THEN
    NEW.enabled_project_map_commit := NULL;
    NEW.enabled_by_principal_id := NULL;
    NEW.enabled_at := NULL;
  ELSIF TG_OP = 'INSERT' OR NOT OLD.enabled THEN
    -- Enabled now. The writer may say which commit it means; the CHECK then holds it to the commit on file.
    IF NEW.enabled_project_map_commit IS NULL THEN
      NEW.enabled_project_map_commit := NEW.project_map_commit;
    END IF;
    IF NEW.enabled_by_principal_id IS NOT NULL AND NOT EXISTS (
         SELECT 1 FROM public.principals p
          WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.enabled_by_principal_id
            AND p.kind = 'human' AND p.disabled_at IS NULL) THEN
      RAISE EXCEPTION 'a repository must be enabled by an active human principal of the tenant'
        USING ERRCODE = '23514', CONSTRAINT = 'repositories_enabler_is_an_active_human', TABLE = 'repositories';
    END IF;
    NEW.enabled_at := now();
  ELSE
    -- Still enabled, and the map did not move: the record of the enabling does not move either.
    NEW.enabled_project_map_commit := OLD.enabled_project_map_commit;
    NEW.enabled_by_principal_id := OLD.enabled_by_principal_id;
    NEW.enabled_at := OLD.enabled_at;
  END IF;

  -- REG-6, item 2: the flag is written at registration and never after, by a login of the factory. The grants say
  -- the same; this is the second guard. An administrator (the owner, a superuser) is not a login of the factory.
  IF TG_OP = 'UPDATE' AND NEW.single_maintainer IS DISTINCT FROM OLD.single_maintainer
     AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                  WHERE r.rolname IN (session_user, current_user) AND NOT r.rolsuper
                    AND (pg_catalog.pg_has_role(r.oid, 'factory_api_app'::pg_catalog.regrole::pg_catalog.oid, 'MEMBER')
                         OR pg_catalog.pg_has_role(r.oid, 'factory_app'::pg_catalog.regrole::pg_catalog.oid, 'MEMBER'))) THEN
    RAISE EXCEPTION 'single_maintainer is written when the repository is registered and not changed after'
      USING ERRCODE = '23514', CONSTRAINT = 'repositories_single_maintainer_is_set_at_registration', TABLE = 'repositories';
  END IF;

  -- REG-6, item 3: the person who enabled the repository is not the person who attested its map.
  IF NEW.enabled AND NOT NEW.single_maintainer AND NEW.enabled_by_principal_id IS NOT NULL
     AND NEW.enabled_by_principal_id = NEW.project_map_attested_by_principal_id THEN
    RAISE EXCEPTION 'the person who enables a repository must not be the person who attested its project map'
      USING ERRCODE = '23514', CONSTRAINT = 'repositories_enabler_differs_from_attestor', TABLE = 'repositories';
  END IF;
  RETURN NEW;
END
$$;

-- 2. The API login writes the flag when it registers a repository. Nobody is granted UPDATE on it.
GRANT INSERT (single_maintainer) ON repositories TO factory_api_app;
