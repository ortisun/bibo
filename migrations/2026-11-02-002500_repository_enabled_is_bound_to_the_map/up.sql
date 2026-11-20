-- A repository stays enabled only for the project map that a person enabled it for (finding REG-1 of
-- docs/reviews/engine-registration-and-status-security-review.md).
--
-- Before this migration, attesting another map commit on a repository that was already enabled left it enabled.
-- The approver who enabled it never saw the new commit, and the person who replaced it needed only the weaker
-- operator designation. The rule belongs in the table, so that a writer which skips the API (a script, a
-- mis-scoped login, a later code path) cannot skip it.
--
-- What this migration does:
--
--   1. Three nullable columns that record what was enabled: the map commit the enabler meant
--      (enabled_project_map_commit), the principal who enabled it (enabled_by_principal_id) and the time, taken
--      from the database clock (enabled_at). They are set when `enabled` turns true and emptied when it turns
--      false.
--   2. repositories_project_map_guard now also decides the enabled flag. When the repository is enabled and the
--      commit or the attestor of its project map changes, the trigger sets enabled to false, whatever the
--      statement said. It stamps the three columns of item 1, refuses an enabler who is not an active human
--      principal of the tenant, and keeps the record unchanged while the repository stays enabled.
--   3. Two CHECK constraints, the second guard behind the trigger, binding for every role (the owner and a
--      superuser too): the record is complete or empty and exists exactly when the repository is enabled
--      (repositories_enabled_record_is_complete), and an enabled repository is enabled for the commit that is
--      attested now (repositories_enabled_project_map_commit_matches).
--   4. The writer may state the commit it means. When it does, the second constraint holds it to the attested
--      commit, so an enable that names another commit than the one on file is refused by the table. When it
--      does not, the trigger records the commit on file. The API and the Store always state it.
--   5. Repositories that are enabled now are switched off, with a NOTICE and a rise of their version. None of
--      them has a record of what it was enabled for, so none can be shown to be enabled for the map on file. A
--      person enables each one again and names the commit. NO AUDIT RECORD is written for this switch-off, as
--      for the one in migration 2026-11-02-002400: the audit chain does not say who or what switched them off,
--      only this file and the NOTICE do. A deployment note should carry the count.
--   6. The login of the API and the worker's group may write enabled_project_map_commit and
--      enabled_by_principal_id. Nobody may write enabled_at: the database stamps it.
--
-- Residual risk, stated plainly: this migration makes the enabled flag follow the map. It does not make the
-- enabler a different person from the attestor (a decision for the product owner), and the enabler column is a
-- parameter of the caller, as the attestor is. Whoever holds the credentials of the API database login can still
-- name any active human principal of the tenant (finding REG-2, open).
--
-- Expand only: three nullable columns and constraints on them. Nothing is dropped.

SET LOCAL lock_timeout = '5s';

-- The table forces row-level security, which binds its owner too, so the owner would see no row. The setting is
-- lifted for this one statement and put back (the same step as migration 2026-11-02-002400).
ALTER TABLE repositories NO FORCE ROW LEVEL SECURITY;
DO $$
DECLARE
  switched_off bigint;
BEGIN
  UPDATE repositories SET enabled = false, version = version + 1 WHERE enabled;
  GET DIAGNOSTICS switched_off = ROW_COUNT;
  IF switched_off > 0 THEN
    RAISE NOTICE '% repositories were enabled with no record of the map they were enabled for and are now disabled; enable each one again and name the commit', switched_off;
  END IF;
END
$$;
ALTER TABLE repositories FORCE ROW LEVEL SECURITY;

-- 1.
ALTER TABLE repositories
  ADD COLUMN enabled_project_map_commit text,
  ADD COLUMN enabled_by_principal_id uuid,
  ADD COLUMN enabled_at timestamptz;

ALTER TABLE repositories ADD CONSTRAINT repositories_enabled_by_fkey
  FOREIGN KEY (tenant_id, enabled_by_principal_id) REFERENCES principals (tenant_id, id);

-- 3. The names sort after repositories_enabled_needs_project_map, so a repository enabled with no map is still
--    refused by that constraint first. IS NOT NULL is spelled out where a CHECK would accept NULL by accident.
ALTER TABLE repositories ADD CONSTRAINT repositories_enabled_project_map_commit_matches
  CHECK (enabled_project_map_commit IS NULL
         OR (enabled AND enabled_project_map_commit = project_map_commit));
ALTER TABLE repositories ADD CONSTRAINT repositories_enabled_record_is_complete
  CHECK ((enabled_project_map_commit IS NULL) = (enabled_at IS NULL)
     AND (enabled_by_principal_id IS NULL OR enabled_project_map_commit IS NOT NULL)
     AND (NOT enabled OR enabled_project_map_commit IS NOT NULL));

-- 2. The guard of the project map also decides the enabled flag. The attestation part is the one of migration
--    2026-11-02-002400, unchanged.
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
  RETURN NEW;
END
$$;

-- 6. The record of the enabling. The time is never granted.
GRANT UPDATE (enabled_project_map_commit, enabled_by_principal_id) ON repositories TO factory_app, factory_api_app;
