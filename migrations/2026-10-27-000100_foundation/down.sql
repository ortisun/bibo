-- Reverse of the foundation migration. The factory_app role is cluster wide and may be used by
-- other databases or hold grants elsewhere, so it is left in place. Re-running the up migration
-- finds it and carries on.
DROP FUNCTION IF EXISTS reject_modification();
DROP FUNCTION IF EXISTS bump_guard();
DROP FUNCTION IF EXISTS enforce_status_transition();
DROP TABLE IF EXISTS state_machine_edges;
DROP TABLE IF EXISTS state_machine_transitions;
DROP TABLE IF EXISTS state_machine_states;
REVOKE USAGE ON SCHEMA public FROM factory_app;
