-- Takes the new action off the list: the API login may write the actions of migration 2026-10-29-002100
-- again, and not decision.stage_requested.
CREATE OR REPLACE FUNCTION audit_events_api_actions() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
              WHERE r.rolname IN (session_user, current_user) AND NOT r.rolsuper
                AND pg_catalog.pg_has_role(r.oid, 'factory_api_app'::pg_catalog.regrole::pg_catalog.oid, 'MEMBER'))
     AND NEW.action <> ALL (ARRAY[
            'decision.requested', 'decision.dependency_requested', 'decision.denied', 'decision.denied_summary',
            'decision.denied_suppressed', 'job.submitted', 'job.received_from_webhook', 'webhook.accepted',
            'webhook.duplicate_delivery', 'webhook.rejected', 'webhook.unbound', 'webhook.audit_dropped',
            'webhook_accepted_or_rejected.granted', 'webhook_accepted_or_rejected.denied']) THEN
    RAISE EXCEPTION 'the API login may not write an audit record with this action or this actor'
      USING ERRCODE = '42501', TABLE = 'audit_events';
  END IF;
  RETURN NEW;
END
$$;
