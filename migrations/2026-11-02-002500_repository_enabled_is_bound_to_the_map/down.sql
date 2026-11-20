-- Takes the record of the enabling back out and gives the guard of the project map its earlier body, which
-- leaves `enabled` alone when the map changes.
--
-- Rows that the up migration switched off stay switched off: the earlier state is not recorded anywhere. The
-- record of who enabled which commit is lost with its columns.

REVOKE UPDATE (enabled_project_map_commit, enabled_by_principal_id) ON repositories FROM factory_app, factory_api_app;

CREATE OR REPLACE FUNCTION repositories_project_map_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.project_map_attested_by_principal_id IS NULL THEN
    NEW.project_map_attested_at := NULL;
  ELSIF TG_OP = 'INSERT'
     OR NEW.project_map_attested_by_principal_id IS DISTINCT FROM OLD.project_map_attested_by_principal_id
     OR NEW.project_map_commit IS DISTINCT FROM OLD.project_map_commit THEN
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
  RETURN NEW;
END
$$;

ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_record_is_complete;
ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_project_map_commit_matches;
ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_by_fkey;

ALTER TABLE repositories
  DROP COLUMN enabled_at,
  DROP COLUMN enabled_by_principal_id,
  DROP COLUMN enabled_project_map_commit;
