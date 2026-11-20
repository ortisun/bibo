-- Hardening of the read-only observer of ADR 0021 (decision 4), after the independent security review of
-- 2026-11-20 (docs/reviews/troubleshooter-security-review.md, findings TR-3, TR-4 and TR-11). Migration 002900 is
-- applied and frozen, so the changes come here.
--
-- 1. TR-3. factory_observer loses pg_read_all_stats. With it, free SQL read the raw query text of every session of the
--    cluster (an operator's psql, a migration, a CREATE ROLE ... PASSWORD) and could rename or transform the column
--    past the server's literal scrubbing. Without it, pg_stat_activity shows `<insufficient privilege>` for another
--    role's query and NULL for its state and waits. What the curated tools need comes from three SECURITY DEFINER
--    functions instead, owned by factory_observer_stats, a NOLOGIN role whose only membership is pg_read_all_stats
--    and which owns nothing else:
--
--      observer_activity()     the sessions of this database (and the background processes), oldest transaction first
--      observer_lock_waits()   each waiting session of this database with the session that blocks it
--      observer_statements()   pg_stat_statements of this database, when the extension is installed; else no row
--
--    Each returns its query text through observer_normalize_query: quoted strings, dollar-quoted strings, numbers and
--    the text of comments become `?`, and the result is cut to 2000 characters (statement texts: 1000). Each pins
--    `search_path = pg_catalog, pg_temp`, takes no argument, and shows only this database's sessions. PUBLIC cannot
--    execute them; factory_observer can.
--
--    factory_observer becomes NOINHERIT. The group has no membership after this migration, so nothing changes for it
--    today. It matters when a later database in the same cluster runs migration 002900, which grants pg_read_all_stats
--    to factory_observer again until its own copy of this migration takes it back: a grant made while the group is
--    NOINHERIT passes no privilege on (PostgreSQL 16 and later take the grant's INHERIT option from the member's
--    attribute), so no observer login sees raw query texts in that moment.
--
-- 2. TR-4. Advisory locks. The functions are executable by PUBLIC, and a read-only transaction may take them, so the
--    observer could hold the audit chain lock of every tenant (`factory.audit_events:<tenant>`) and stall every audit
--    write for the statement timeout. EXECUTE on every pg_advisory_* and pg_try_advisory_* function is revoked from
--    PUBLIC in this database. The one the factory uses, pg_advisory_xact_lock(bigint) in the trigger
--    audit_events_assign, which runs as the role that inserts the audit event, is granted back to the two groups that
--    insert audit events (factory_app and factory_api_app) and to the owner of the audit table, which writes audit
--    events in data repairs (migration 002800). The troubleshooter (migration 003000, apps/troubleshooter) keeps one
--    active instance with a session lock taken and released by its factory_app login, so
--    pg_try_advisory_lock(bigint) and pg_advisory_unlock(bigint) are granted back to factory_app as well. A superuser
--    needs no grant. Function privileges are per database, so this changes nothing in another database of the cluster.
--
-- 3. TR-11. The observer loses the GitHub ids (repositories.github_installation_id and github_repository_id, the same
--    two columns of webhook_deliveries). The id of a public repository resolves to its name through GitHub's API, and
--    the name is what 002900 withholds because it names a customer. No curated tool reads them; the factory's own
--    repositories.id stays, and it is opaque outside the factory.
--
-- Who may run it: a superuser. Revoking EXECUTE on functions of pg_catalog needs their owner, and granting
-- pg_read_all_stats needs the ADMIN option on it; migration 002900 already needed the latter. The migration checks
-- the effect and stops instead of continuing with a warning.

DO $$
BEGIN
  IF NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN
    RAISE EXCEPTION 'run migration 2026-11-20-003100_observer_hardening as a superuser: it revokes EXECUTE on functions of pg_catalog and grants pg_read_all_stats';
  END IF;
END
$$;

-- 1. The definer role and the read-all-stats membership move.
DO $$
DECLARE
  r pg_catalog.pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO r FROM pg_catalog.pg_roles WHERE rolname = 'factory_observer_stats';
  IF NOT FOUND THEN
    CREATE ROLE factory_observer_stats NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT;
  ELSIF r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolcanlogin THEN
    RAISE EXCEPTION 'the existing role factory_observer_stats has too many powers (superuser, createrole, createdb, replication, bypassrls or login)';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
     WHERE m.member = 'factory_observer_stats'::regrole AND g.rolname <> 'pg_read_all_stats'
  ) THEN
    RAISE EXCEPTION 'the existing role factory_observer_stats is a member of another role; it may only be a member of pg_read_all_stats';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid = 'factory_observer_stats'::regrole) THEN
    RAISE EXCEPTION 'the role factory_observer_stats has members; nobody may hold it';
  END IF;
END
$$;

GRANT pg_read_all_stats TO factory_observer_stats;
ALTER ROLE factory_observer_stats INHERIT;
REVOKE pg_read_all_stats FROM factory_observer;
ALTER ROLE factory_observer NOINHERIT;
GRANT USAGE ON SCHEMA public TO factory_observer_stats;

-- The normalizer: the literals and comments of a query text become `?`, and the text is cut. It mirrors
-- factory_mcp_postgres::sql::scrub_literals, and also replaces comments. Double-quoted identifiers are kept as they
-- are, so a quote inside one does not start a string. An unterminated literal or comment runs to the end of the text.
CREATE FUNCTION observer_normalize_query(p_text text, p_max integer) RETURNS text
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog, pg_temp AS $fn$
DECLARE
  ch text[];
  n integer;
  i integer := 1;
  run_start integer := 1;
  j integer;
  k integer;
  depth integer;
  c text;
  nxt text;
  prev_word boolean;
  tag text;
  escapes boolean;
  parts text[] := ARRAY[]::text[];
BEGIN
  IF p_text IS NULL THEN
    RETURN NULL;
  END IF;
  -- The input is cut first, so the cost of one call is bounded whatever the text.
  ch := pg_catalog.regexp_split_to_array(pg_catalog.left(p_text, LEAST(4096, GREATEST(p_max, 0) * 2)), '');
  n := coalesce(pg_catalog.array_length(ch, 1), 0);
  WHILE i <= n LOOP
    c := ch[i];
    IF c NOT IN ('"', '''', '-', '/', '$') AND pg_catalog.ascii(c) NOT BETWEEN 48 AND 57 THEN
      i := i + 1;
      CONTINUE;
    END IF;
    nxt := CASE WHEN i < n THEN ch[i + 1] ELSE '' END;
    -- Whether the character before belongs to a word, a parameter or a dollar tag.
    prev_word := i > 1 AND ch[i - 1] ~ '[[:alnum:]_$]';
    IF c = '"' THEN
      -- A quoted identifier: kept, and skipped as a whole.
      j := i + 1;
      WHILE j <= n LOOP
        IF ch[j] = '"' AND j < n AND ch[j + 1] = '"' THEN
          j := j + 2;
        ELSIF ch[j] = '"' THEN
          EXIT;
        ELSE
          j := j + 1;
        END IF;
      END LOOP;
      i := j + 1;
    ELSIF c = '''' THEN
      escapes := i > 1 AND ch[i - 1] IN ('e', 'E') AND (i < 3 OR ch[i - 2] !~ '[[:alnum:]_]');
      parts := parts || (pg_catalog.array_to_string(ch[run_start:i - 1], '') || '?');
      j := i + 1;
      WHILE j <= n LOOP
        IF escapes AND ch[j] = '\' THEN
          j := j + 2;
        ELSIF ch[j] = '''' AND j < n AND ch[j + 1] = '''' THEN
          j := j + 2;
        ELSIF ch[j] = '''' THEN
          EXIT;
        ELSE
          j := j + 1;
        END IF;
      END LOOP;
      i := j + 1;
      run_start := i;
    ELSIF c = '-' AND nxt = '-' THEN
      parts := parts || (pg_catalog.array_to_string(ch[run_start:i - 1], '') || '-- ?');
      j := i + 2;
      WHILE j <= n AND ch[j] <> E'\n' LOOP
        j := j + 1;
      END LOOP;
      i := j;
      run_start := i;
    ELSIF c = '/' AND nxt = '*' THEN
      parts := parts || (pg_catalog.array_to_string(ch[run_start:i - 1], '') || '/* ? */');
      depth := 1;
      j := i + 2;
      WHILE j <= n AND depth > 0 LOOP
        IF ch[j] = '/' AND j < n AND ch[j + 1] = '*' THEN
          depth := depth + 1;
          j := j + 2;
        ELSIF ch[j] = '*' AND j < n AND ch[j + 1] = '/' THEN
          depth := depth - 1;
          j := j + 2;
        ELSE
          j := j + 1;
        END IF;
      END LOOP;
      i := j;
      run_start := i;
    ELSIF c = '$' AND NOT prev_word AND coalesce(pg_catalog.ascii(nxt), 0) NOT BETWEEN 48 AND 57 THEN
      -- A dollar quote opens with a dollar, an optional tag and a dollar; a parameter ($1) is not one.
      j := i + 1;
      WHILE j <= n AND ch[j] ~ '[[:alnum:]_]' LOOP
        j := j + 1;
      END LOOP;
      IF j <= n AND ch[j] = '$' THEN
        tag := pg_catalog.array_to_string(ch[i:j], '');
        parts := parts || (pg_catalog.array_to_string(ch[run_start:i - 1], '') || '?');
        k := 0;
        j := j + 1;
        WHILE j <= n LOOP
          IF ch[j] = '$' AND pg_catalog.array_to_string(ch[j:j + pg_catalog.length(tag) - 1], '') = tag THEN
            k := j;
            EXIT;
          END IF;
          j := j + 1;
        END LOOP;
        IF k = 0 THEN
          i := n + 1;
        ELSE
          i := k + pg_catalog.length(tag);
        END IF;
        run_start := i;
      ELSE
        i := i + 1;
      END IF;
    ELSIF pg_catalog.ascii(c) BETWEEN 48 AND 57 AND NOT prev_word THEN
      parts := parts || (pg_catalog.array_to_string(ch[run_start:i - 1], '') || '?');
      j := i;
      WHILE j <= n AND ch[j] ~ '[[:alnum:]._]' LOOP
        j := j + 1;
      END LOOP;
      i := j;
      run_start := i;
    ELSE
      i := i + 1;
    END IF;
  END LOOP;
  parts := parts || pg_catalog.array_to_string(ch[run_start:n], '');
  RETURN pg_catalog.left(pg_catalog.array_to_string(parts, ''), GREATEST(p_max, 0));
END
$fn$;

CREATE FUNCTION observer_activity()
RETURNS TABLE (pid integer, login text, application_name text, backend_type text, state text, wait_event_type text,
               wait_event text, backend_start timestamptz, xact_start timestamptz, query_start timestamptz,
               state_change timestamptz, backend_xmin text, query text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT a.pid, a.usename::text, pg_catalog.left(a.application_name, 64), a.backend_type, a.state,
         a.wait_event_type, a.wait_event, a.backend_start, a.xact_start, a.query_start, a.state_change,
         a.backend_xmin::text, public.observer_normalize_query(a.query, 2000)
    FROM pg_catalog.pg_stat_activity a
   WHERE a.pid <> pg_catalog.pg_backend_pid()
     AND (a.datid IS NULL OR a.datid = (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()))
   ORDER BY a.xact_start NULLS LAST, a.backend_start
$$;

CREATE FUNCTION observer_lock_waits()
RETURNS TABLE (blocked_pid integer, blocked_login text, wait_event_type text, wait_event text, blocked_since timestamptz,
               blocked_query text, blocking_pid integer, blocking_login text, blocking_state text,
               blocking_xact_start timestamptz, blocking_query text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT blocked.pid, blocked.usename::text, blocked.wait_event_type, blocked.wait_event, blocked.query_start,
         public.observer_normalize_query(blocked.query, 1000), blocking.pid, blocking.usename::text, blocking.state,
         blocking.xact_start, public.observer_normalize_query(blocking.query, 1000)
    FROM pg_catalog.pg_stat_activity blocked
   CROSS JOIN LATERAL pg_catalog.unnest(pg_catalog.pg_blocking_pids(blocked.pid)) AS b(pid)
    JOIN pg_catalog.pg_stat_activity blocking ON blocking.pid = b.pid
   WHERE blocked.datid = (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database())
   ORDER BY blocked.query_start NULLS LAST
$$;

-- pg_stat_statements lives in the schema it was created in, if at all, so the statement is built when the function
-- runs. Its name is quoted with format('%I'); nothing of the caller enters it.
CREATE FUNCTION observer_statements()
RETURNS TABLE (login text, calls bigint, total_exec_ms double precision, mean_exec_ms double precision, rows bigint,
               query text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  home text;
BEGIN
  SELECT n.nspname INTO home
    FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
   WHERE e.extname = 'pg_stat_statements';
  IF home IS NULL THEN
    RETURN;
  END IF;
  RETURN QUERY EXECUTE pg_catalog.format(
    'SELECT pg_catalog.pg_get_userbyid(s.userid)::text, s.calls, s.total_exec_time, s.mean_exec_time, s.rows, '
    '       public.observer_normalize_query(s.query, 1000) '
    '  FROM %I.pg_stat_statements s '
    ' WHERE s.dbid = (SELECT d.oid FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()) '
    ' ORDER BY s.total_exec_time DESC LIMIT 50', home);
END
$$;

ALTER FUNCTION observer_normalize_query(text, integer) OWNER TO factory_observer_stats;
ALTER FUNCTION observer_activity() OWNER TO factory_observer_stats;
ALTER FUNCTION observer_lock_waits() OWNER TO factory_observer_stats;
ALTER FUNCTION observer_statements() OWNER TO factory_observer_stats;
REVOKE ALL ON FUNCTION observer_normalize_query(text, integer), observer_activity(), observer_lock_waits(),
                       observer_statements() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION observer_normalize_query(text, integer), observer_activity(), observer_lock_waits(),
                          observer_statements() TO factory_observer;

-- 2. Advisory locks: nobody but the factory's writers and a superuser.
DO $$
DECLARE
  f regprocedure;
  audit_owner text;
BEGIN
  FOR f IN
    SELECT p.oid::regprocedure FROM pg_catalog.pg_proc p
     WHERE p.pronamespace = 'pg_catalog'::regnamespace
       AND (p.proname LIKE 'pg\_advisory\_%' OR p.proname LIKE 'pg\_try\_advisory\_%')
     ORDER BY p.oid
  LOOP
    EXECUTE pg_catalog.format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
  END LOOP;
  SELECT pg_catalog.pg_get_userbyid(c.relowner) INTO audit_owner
    FROM pg_catalog.pg_class c WHERE c.oid = 'public.audit_events'::regclass;
  GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) TO factory_app, factory_api_app;
  GRANT EXECUTE ON FUNCTION pg_catalog.pg_try_advisory_lock(bigint), pg_catalog.pg_advisory_unlock(bigint) TO factory_app;
  EXECUTE pg_catalog.format('GRANT EXECUTE ON FUNCTION pg_catalog.pg_advisory_xact_lock(bigint) TO %I', audit_owner);
  -- The effect, checked: a REVOKE by a role that may not revoke is only a warning.
  IF pg_catalog.has_function_privilege('factory_observer', 'pg_catalog.pg_advisory_xact_lock(bigint)', 'EXECUTE')
     OR pg_catalog.has_function_privilege('factory_observer', 'pg_catalog.pg_try_advisory_lock(bigint)', 'EXECUTE')
     OR NOT pg_catalog.has_function_privilege('factory_app', 'pg_catalog.pg_advisory_xact_lock(bigint)', 'EXECUTE')
     OR NOT pg_catalog.has_function_privilege('factory_api_app', 'pg_catalog.pg_advisory_xact_lock(bigint)', 'EXECUTE')
     OR NOT pg_catalog.has_function_privilege('factory_app', 'pg_catalog.pg_try_advisory_lock(bigint)', 'EXECUTE')
     OR NOT pg_catalog.has_function_privilege('factory_app', 'pg_catalog.pg_advisory_unlock(bigint)', 'EXECUTE')
     OR pg_catalog.has_function_privilege('factory_observer', 'pg_catalog.pg_advisory_unlock(bigint)', 'EXECUTE')
  THEN
    RAISE EXCEPTION 'the advisory lock functions did not end with the intended privileges';
  END IF;
END
$$;

-- 3. The GitHub ids.
REVOKE SELECT (github_installation_id, github_repository_id) ON repositories FROM factory_observer;
REVOKE SELECT (github_installation_id, github_repository_id) ON webhook_deliveries FROM factory_observer;
