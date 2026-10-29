-- What the login of the HTTP API may write to the audit log (findings RR-8 and RR-21 of
-- docs/reviews/authority-api-supply-chain-security-rereview.md).
--
-- Migration 2026-10-28-002000 gave the API login INSERT on audit_events: the API records the requests of
-- people (decision.requested), the jobs it accepts and the webhook deliveries it sees. That grant is on the
-- whole table, so the login could also write a row that says anything: another action, another actor. The
-- worker reads this log to find the requests of people and the records that end them, so a row in the name of
-- the worker (a decision.rejected that names a signed request) or a long queue of junk rows (decision.requested
-- with no word) was a way for whoever held that login to silence or starve a decision, the cancel and the
-- pause among them.
--
-- The worker now signs its markers and keeps junk from taking room (crates/composition/src/decisions.rs), so
-- those rows no longer work. This trigger takes the possibility away at the database, as a second layer: a
-- member of factory_api_app may insert only the actions the API writes. The actor is not limited: the storage
-- contract suite writes a platform event of the receiver as a component of the system, and nothing the hook
-- reads is decided by the actor type alone (a request needs a person, and a marker needs the worker's word).
--
-- A trigger and not a restrictive policy: the rls suite keeps the whole set of policies on a list and refuses
-- a restrictive one (docs/database/tenancy.md), and the privilege model of this schema already puts its
-- second layers in triggers (audit_events_no_change). The trigger fires before audit_events_assign (BEFORE
-- INSERT triggers run in the order of their names), so a refused row takes no advisory lock and no number of
-- the chain.
--
-- The check looks at the login that connected (session_user) and at the role in force (current_user): a
-- member of the group is held to the list also when a function that runs with the rights of its owner writes
-- on its behalf. factory_app, factory_system and the owner are not members and are not held. A superuser is
-- left out of the membership test, because pg_has_role says yes for a superuser and every role: an
-- administrator who writes a row by hand is not the API (and the other suites do). A superuser who sets the
-- role factory_api_app is held, because the role in force is then the group itself.
--
-- The last two are the names the engine gives a webhook event of the platform (Engine::record_platform_event, the
-- receiver's path for an event that has no tenant and no job); the API writes the first twelve itself.
--
-- A new action the API writes needs a new migration that replaces this function, with its line in the
-- api_privileges suite. That is the point: the list is a review surface.

CREATE FUNCTION audit_events_api_actions() RETURNS trigger
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

CREATE TRIGGER audit_events_api_actions BEFORE INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_api_actions();
