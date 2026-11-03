-- Takes the single-maintainer flag and the rule that depends on it back out, and gives the guard of the project map
-- the body it had in migration 2026-11-02-002500.
--
-- Rows that the up migration switched off stay switched off: the earlier state is not recorded anywhere. The flag
-- is lost with its column, so a repository that was registered as a single-maintainer one is a plain repository
-- again, which the earlier rules allowed.

REVOKE INSERT (single_maintainer) ON repositories FROM factory_api_app;

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

  IF map_moved AND OLD.enabled THEN
    NEW.enabled := false;
  END IF;

  IF NOT NEW.enabled THEN
    NEW.enabled_project_map_commit := NULL;
    NEW.enabled_by_principal_id := NULL;
    NEW.enabled_at := NULL;
  ELSIF TG_OP = 'INSERT' OR NOT OLD.enabled THEN
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
    NEW.enabled_project_map_commit := OLD.enabled_project_map_commit;
    NEW.enabled_by_principal_id := OLD.enabled_by_principal_id;
    NEW.enabled_at := OLD.enabled_at;
  END IF;
  RETURN NEW;
END
$$;

ALTER TABLE repositories DROP CONSTRAINT repositories_enabler_differs_from_attestor;
ALTER TABLE repositories DROP COLUMN single_maintainer;
