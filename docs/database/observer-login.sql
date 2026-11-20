-- The login of the troubleshooter and of apps/mcp-postgres (ADR 0021, decision 4). Run once per cluster, as a
-- superuser or a role with CREATEROLE and the ADMIN option on factory_observer, after migration
-- 2026-11-20-002900_observer_role. The password is read from a file and never typed on a command line:
--
--   psql "$ADMIN_URL" -v ON_ERROR_STOP=1 -v password_file=/run/secrets/factory_troubleshooter_password \
--        -f docs/database/observer-login.sql
--
-- The file holds the password on one line (mode 0600). The same file is the one apps/mcp-postgres names in
-- its `password_file` setting.

\set password `cat :'password_file'`

CREATE ROLE factory_troubleshooter LOGIN PASSWORD :'password' CONNECTION LIMIT 4 IN ROLE factory_observer
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

-- Every transaction is read-only unless the session asks otherwise, and the server always opens
-- BEGIN READ ONLY anyway. The timeouts bound what one question can cost the factory's database.
ALTER ROLE factory_troubleshooter SET default_transaction_read_only = on;
ALTER ROLE factory_troubleshooter SET statement_timeout = '5s';
ALTER ROLE factory_troubleshooter SET lock_timeout = '1s';
ALTER ROLE factory_troubleshooter SET idle_in_transaction_session_timeout = '10s';

\unset password

-- Check: the login belongs to factory_observer and to nothing else.
SELECT g.rolname AS member_of
  FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
 WHERE m.member = 'factory_troubleshooter'::regrole;
