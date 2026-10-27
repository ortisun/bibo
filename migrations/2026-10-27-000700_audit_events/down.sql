DROP FUNCTION IF EXISTS audit_verify_chain(uuid);
DROP TABLE IF EXISTS audit_events;
DROP FUNCTION IF EXISTS audit_events_assign();
DROP FUNCTION IF EXISTS audit_canonical_json(text, text, text, uuid, timestamptz, text, uuid, uuid, text, text, text, bigint, uuid, text, uuid);
DROP FUNCTION IF EXISTS audit_json_string(text);
