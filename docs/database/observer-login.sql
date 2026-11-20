-- The login of the troubleshooter and of apps/mcp-postgres (ADR 0021, decision 4). Run once per cluster, as a
-- superuser or a role with CREATEROLE and the ADMIN option on factory_observer, after migrations
-- 2026-11-20-002900_observer_role and 2026-11-20-003100_observer_hardening, from the root of a checkout (it calls
-- scripts/scram-verifier.py):
--
--   psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -v password_file=/run/secrets/factory_troubleshooter_password \
--        -f docs/database/observer-login.sql
--
-- The file holds the password on one line (mode 0600). The same file is the one apps/mcp-postgres names in
-- its `password_file` setting.
--
-- The password never enters the SQL text (TR-10 of docs/reviews/troubleshooter-security-review.md). The text of
-- CREATE ROLE is kept by the server log (log_statement = ddl or all) and by pg_stat_statements, so the script
-- computes the SCRAM-SHA-256 verifier on this machine (scripts/scram-verifier.py, Python's standard library only)
-- and the server stores that as it is. The verifier is a salted hash: it lets nobody log in, but a weak password
-- could be guessed from it offline, so use a random one (`openssl rand -hex 24`). The server must keep
-- password_encryption = scram-sha-256 (the default) for later password changes.

\set verifier `python3 scripts/scram-verifier.py :'password_file'`

CREATE ROLE factory_troubleshooter LOGIN PASSWORD :'verifier' CONNECTION LIMIT 4 IN ROLE factory_observer
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Every transaction is read-only unless the session asks otherwise, and the server always opens
-- BEGIN READ ONLY anyway. The timeouts bound what one question can cost the factory's database.
ALTER ROLE factory_troubleshooter SET default_transaction_read_only = on;
ALTER ROLE factory_troubleshooter SET statement_timeout = '5s';
ALTER ROLE factory_troubleshooter SET lock_timeout = '1s';
ALTER ROLE factory_troubleshooter SET idle_in_transaction_session_timeout = '10s';

\unset verifier

-- Check: the login belongs to factory_observer and to nothing else, and its password is stored as a verifier.
SELECT g.rolname AS member_of
  FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
 WHERE m.member = 'factory_troubleshooter'::regrole;
SELECT left(rolpassword, 14) = 'SCRAM-SHA-256$' AS stored_as_scram_verifier
  FROM pg_catalog.pg_authid WHERE rolname = 'factory_troubleshooter';
