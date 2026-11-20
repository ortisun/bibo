-- Takes the new guard away and gives the audit trigger its earlier body back (migration 2026-11-03-002700).
--
-- Repositories that the up script switched off because they were enabled with no recorded enabler stay switched off;
-- their audit records stay in the log, as every audit record does. After this the API login may again write a
-- `repository.disabled` record in the name of any actor and any words, and an unsigned `repository.change_requested`
-- record (findings RH-5 and RH-8 open).

DROP TRIGGER repositories_strict_enabler_guard ON repositories;
DROP FUNCTION repositories_strict_enabler_guard();

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
            'repository.change_requested', 'repository.disabled']) THEN
    RAISE EXCEPTION 'the API login may not write an audit record with this action or this actor'
      USING ERRCODE = '42501', TABLE = 'audit_events';
  END IF;
  RETURN NEW;
END
$$;
