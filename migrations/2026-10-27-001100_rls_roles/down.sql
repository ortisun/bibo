-- The roles are cluster wide and may carry grants in other databases, so they stay, as factory_app does.
-- Only the schema privilege this migration granted is taken back.
REVOKE USAGE ON SCHEMA public FROM factory_system, factory_lookup, factory_resolver;
