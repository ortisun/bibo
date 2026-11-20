-- Gives the API login its column grants on repositories and its four audit actions back, and takes the second
-- guard out. After this the API writes register, attest and enable directly again, with no signed request, which is
-- the state of migration 2026-11-03-002600 (finding REG-2 open).
--
-- Requests that the API appended and the worker has not applied are left in the audit log as they are. Nothing
-- reads them any more, and they are harmless.

DROP TRIGGER repositories_api_may_only_disable ON repositories;
DROP FUNCTION repositories_api_may_only_disable();

GRANT INSERT (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, single_maintainer)
  ON repositories TO factory_api_app;
GRANT UPDATE (project_map_commit, project_map_attested_by_principal_id, enabled_project_map_commit, enabled_by_principal_id)
  ON repositories TO factory_api_app;

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
            'webhook_accepted_or_rejected.denied',
            'repository.registered', 'repository.map_attested', 'repository.enabled', 'repository.disabled']) THEN
    RAISE EXCEPTION 'the API login may not write an audit record with this action or this actor'
      USING ERRCODE = '42501', TABLE = 'audit_events';
  END IF;
  RETURN NEW;
END
$$;
