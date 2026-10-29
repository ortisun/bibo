-- Takes the list of actions back: the API login may insert any audit row again, as it could after migration
-- 2026-10-28-002000 (findings RR-8 and RR-21 reopen at the database; the worker still signs its markers).
DROP TRIGGER audit_events_api_actions ON audit_events;
DROP FUNCTION audit_events_api_actions();
