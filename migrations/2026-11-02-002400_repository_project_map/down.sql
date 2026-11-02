-- Takes the project map back out. The API login may write the audit actions of migration 2026-10-29-002200 again
-- and no repository action, and it writes nothing to the repositories table.
--
-- Rows that the up migration switched off stay switched off: the earlier state is not recorded anywhere.

CREATE OR REPLACE FUNCTION audit_events_api_actions() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
              WHERE r.rolname IN (session_user, current_user) AND NOT r.rolsuper
                AND pg_catalog.pg_has_role(r.oid, 'factory_api_app'::pg_catalog.regrole::pg_catalog.oid, 'MEMBER'))
     AND NEW.action <> ALL (ARRAY[
            'decision.requested', 'decision.dependency_requested', 'decision.stage_requested', 'decision.denied',
            'decision.denied_summary', 'decision.denied_suppressed', 'job.submitted', 'job.received_from_webhook',
            'webhook.accepted', 'webhook.duplicate_delivery', 'webhook.rejected', 'webhook.unbound',
            'webhook.audit_dropped', 'webhook_accepted_or_rejected.granted',
            'webhook_accepted_or_rejected.denied']) THEN
    RAISE EXCEPTION 'the API login may not write an audit record with this action or this actor'
      USING ERRCODE = '42501', TABLE = 'audit_events';
  END IF;
  RETURN NEW;
END
$$;

REVOKE UPDATE (project_map_commit, project_map_attested_by_principal_id) ON repositories FROM factory_app;
REVOKE UPDATE (enabled, project_map_commit, project_map_attested_by_principal_id, version)
  ON repositories FROM factory_api_app;
REVOKE INSERT (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
  ON repositories FROM factory_api_app;

DROP TRIGGER repositories_project_map_guard ON repositories;
DROP FUNCTION repositories_project_map_guard();

ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_needs_project_map;
ALTER TABLE repositories DROP CONSTRAINT repositories_project_map_attested_by_fkey;
ALTER TABLE repositories DROP CONSTRAINT repositories_project_map_attestation_complete;
ALTER TABLE repositories DROP CONSTRAINT repositories_project_map_commit_check;

ALTER TABLE repositories
  DROP COLUMN project_map_attested_at,
  DROP COLUMN project_map_attested_by_principal_id,
  DROP COLUMN project_map_commit;
ALTER TABLE repositories ALTER COLUMN enabled SET DEFAULT true;
