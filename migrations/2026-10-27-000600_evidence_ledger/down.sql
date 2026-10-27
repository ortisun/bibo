DROP FUNCTION IF EXISTS ledger_verify_chain(uuid, uuid);
DROP VIEW IF EXISTS ledger_assurance_levels;
DROP VIEW IF EXISTS ledger_current_claims;
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_ledger_head_fk;
-- The function takes the table's row type as an argument, so it must go before the table.
DROP FUNCTION IF EXISTS ledger_document_matches(ledger_entries);
-- Dropping the table removes its triggers. TRUNCATE and DELETE triggers do not fire on DROP.
DROP TABLE IF EXISTS ledger_entries;
DROP FUNCTION IF EXISTS ledger_entries_guard();
DROP FUNCTION IF EXISTS ledger_entry_hash(text, text);
