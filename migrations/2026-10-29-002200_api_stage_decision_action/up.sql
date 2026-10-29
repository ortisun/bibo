-- The API records one more kind of request from a person: a decision about a stage run that is not an
-- approval of a pull request. Letting a blocked stage run go again (`unblock`), a decision on the
-- project's own build code (`approve-project-build-code`) and a decision on a translation warning
-- (`ack-translation-warning`) are all recorded as `decision.stage_requested`, signed with the key the
-- API holds, and applied by the worker's step (crates/composition/src/stage_decisions.rs).
--
-- Migration 2026-10-29-002100 limits the API login to the audit actions the API writes, as a second
-- layer behind the signed word, and says that a new action the API writes needs a new migration that
-- replaces the function, with its line in the api_privileges suite. That is this one. The function is
-- replaced and the trigger that calls it is left as it is. The rest of the list is the same, and the
-- worker's actions (decision.applied, decision.rejected, decision.marker_ignored, intake.rejected)
-- are still not on it.

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
