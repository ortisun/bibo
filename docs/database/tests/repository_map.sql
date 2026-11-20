-- Suite: repository_map
-- Proves the rules of migration 2026-11-02-002400 (ADR 0016, "What is not built", item 1): a repository cannot be
-- enabled until a person has attested the commit that holds its project map, and the database says so for every
-- role, the table owner and a superuser included.
--
-- The attestation is made by a person. Nothing in the database or in the engine looks at the repository, and
-- these checks do not pretend that it does: they prove who is recorded, when, and what the data cannot hold.
--
-- Every refusal here has a sibling that proves the check can fail: the statement that is refused for one
-- missing piece is accepted when the piece is there, and a control at the end switches the constraint off and
-- shows that the refused statement then goes through.

SELECT dbtest.mk_tenant(1), dbtest.mk_tenant(2);

-- A second active person in tenant 1 from the start. Since migration 2026-11-03-002800 a login of the factory cannot enable a
-- strict repository without naming an enabler (finding RH-8), and the enabler is not the attestor (1002) in these tests.
INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES (dbtest.u(1), dbtest.u(1004), 'human', 7104, 'person-two');

-- ---------------------------------------------------------------------------------------------
-- 1. What a new row looks like.

DO $$
BEGIN
  PERFORM dbtest.expect_eq('the default of enabled is false', (SELECT column_default FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'repositories' AND column_name = 'enabled'), 'false');
  PERFORM dbtest.expect_eq('a repository written without saying so starts disabled',
    (SELECT enabled FROM repositories WHERE id = dbtest.u(1001)), false);
  PERFORM dbtest.expect_eq('a new repository has no project map, no attestor and no time',
    (SELECT count(*) FROM repositories WHERE project_map_commit IS NOT NULL
        OR project_map_attested_by_principal_id IS NOT NULL OR project_map_attested_at IS NOT NULL), 0::bigint);
  PERFORM dbtest.expect_eq('a new repository starts at level L0 with no protection result',
    (SELECT autonomy_ceiling || ':' || protection_preflight_passed FROM repositories WHERE id = dbtest.u(1001)), 'L0:false');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Enabling needs a map commit. The check is in the table, so it holds for every role.

DO $$
DECLARE
  enable_it text := format($q$UPDATE repositories SET enabled = true, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001));
  enable_with_map text := format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('c', 40),
      project_map_attested_by_principal_id = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1001));
BEGIN
  PERFORM dbtest.expect_error('the table owner cannot enable a repository that has no project map', enable_it,
    '23514', NULL, 'repositories_enabled_needs_project_map');
  PERFORM dbtest.expect_error('the worker role cannot enable a repository that has no project map', enable_it,
    '23514', 'factory_app', 'repositories_enabled_needs_project_map', NULL, 1);
  PERFORM dbtest.expect_error('the login of the API cannot enable a repository that has no project map (it cannot enable at all: section 12)', enable_it,
    '42501', 'factory_api_app', NULL, NULL, 1);
  PERFORM dbtest.expect_error('a row cannot be inserted enabled with no project map',
    format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, enabled)
              VALUES (%L, %L, 9101, 8101, 'org1/second', 'main', true)$q$, dbtest.u(1), dbtest.u(1010)),
    '23514', NULL, 'repositories_enabled_needs_project_map');
  PERFORM dbtest.expect_ok('the same update is accepted when it carries the map commit and its attestor (the sibling of the refusals)',
    enable_with_map);
  PERFORM dbtest.expect_ok('the worker group may enable a repository with a map commit and an enabler who is not the attestor (the sibling of the refusals)',
    replace(enable_with_map, 'enabled = true,', format('enabled = true, enabled_by_principal_id = %L,', dbtest.u(1004))), 'factory_app', 1);
  PERFORM dbtest.expect_ok('a repository can stay disabled with no map (the invariant is one way only)',
    format($q$UPDATE repositories SET enabled = false, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)));
END
$$;

-- Take the map away from a repository that is enabled: the same invariant, from the other side.
SELECT dbtest.exec(format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('c', 40),
  project_map_attested_by_principal_id = %L, enabled_by_principal_id = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$,
  dbtest.u(1002), dbtest.u(1004), dbtest.u(1), dbtest.u(1001)));

DO $$
BEGIN
  -- Since migration 2026-11-02-002500 the guard switches the repository off when its map moves, so the statement
  -- that used to be refused here succeeds and leaves the repository disabled. The refusal is still the table's
  -- second guard: section 10 drops the guard and shows the CHECK stop the same statement.
  PERFORM dbtest.expect_eq('the map removed from a repository that is enabled switches the repository off',
    dbtest.run_as(format($q$UPDATE repositories SET project_map_commit = NULL, project_map_attested_by_principal_id = NULL, version = version + 1
               WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)), 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_ok('the map can be removed once the repository is disabled',
    format($q$UPDATE repositories SET enabled = false, project_map_commit = NULL, project_map_attested_by_principal_id = NULL, version = version + 1
               WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. The commit is 40 lowercase hexadecimal characters, and nothing else.

CREATE FUNCTION dbtest.set_map(p_commit text) RETURNS text LANGUAGE sql AS $$
  SELECT format($q$UPDATE repositories SET project_map_commit = %L, project_map_attested_by_principal_id = %L, version = version + 1
                    WHERE tenant_id = %L AND id = %L$q$, p_commit, dbtest.u(1002), dbtest.u(1), dbtest.u(1001))
$$;

DO $$
DECLARE
  bad text;
BEGIN
  FOREACH bad IN ARRAY ARRAY[
    '', ' ', repeat('a', 39), repeat('a', 41), repeat('A', 40), repeat('g', 40), repeat('a', 39) || 'G',
    repeat('a', 64), repeat('a', 40) || E'\n', E'\n' || repeat('a', 40), ' ' || repeat('a', 40), repeat('a', 40) || ' ',
    'sha256:' || repeat('a', 33), 'refs/heads/main', 'HEAD', 'main', repeat('a', 20) || repeat('é', 20)] LOOP
    PERFORM dbtest.expect_error('the map commit ' || quote_literal(replace(replace(left(bad, 12), E'\n', '<newline>'), ' ', '<space>')) || ' (' || length(bad) || ' characters) is refused',
      dbtest.set_map(bad), '23514', NULL, 'repositories_project_map_commit_check');
  END LOOP;
  PERFORM dbtest.expect_ok('forty lowercase hexadecimal characters are accepted', dbtest.set_map('0123456789abcdef0123456789abcdef01234567'));
  PERFORM dbtest.expect_ok('forty of one digit are accepted', dbtest.set_map(repeat('0', 40)));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. The attestation is complete or empty, and it comes from an active human of the tenant.

-- These checks use the repository of tenant 2, which has no map yet. A disabled person is added to tenant 2.
INSERT INTO principals (tenant_id, id, kind, github_user_id, login)
  VALUES (dbtest.u(2), dbtest.u(2004), 'human', 7204, 'person-gone');
UPDATE principals SET disabled_at = now() WHERE id = dbtest.u(2004);

CREATE FUNCTION dbtest.attest_as(p_attestor uuid) RETURNS text LANGUAGE sql AS $$
  SELECT format($q$UPDATE repositories SET project_map_commit = repeat('a', 40), project_map_attested_by_principal_id = %L, version = version + 1
                    WHERE tenant_id = %L AND id = %L$q$, p_attestor, dbtest.u(2), dbtest.u(2001))
$$;

DO $$
BEGIN
  PERFORM dbtest.expect_error('a map commit with no attestor is refused',
    format($q$UPDATE repositories SET project_map_commit = repeat('a', 40), version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(2), dbtest.u(2001)),
    '23514', NULL, 'repositories_project_map_attestation_complete');
  PERFORM dbtest.expect_error('an attestor with no map commit is refused',
    format($q$UPDATE repositories SET project_map_attested_by_principal_id = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(2002), dbtest.u(2), dbtest.u(2001)),
    '23514', NULL, 'repositories_project_map_attestation_complete');
  PERFORM dbtest.expect_error('a service principal cannot attest a map',
    dbtest.attest_as(dbtest.u(2003)), '23514', NULL, 'repositories_map_attestor_is_an_active_human');
  PERFORM dbtest.expect_error('a disabled person cannot attest a map',
    dbtest.attest_as(dbtest.u(2004)), '23514', NULL, 'repositories_map_attestor_is_an_active_human');
  PERFORM dbtest.expect_error('a person of another tenant cannot attest a map',
    dbtest.attest_as(dbtest.u(1002)), '23514', NULL, 'repositories_map_attestor_is_an_active_human');
  PERFORM dbtest.expect_error('an attestor that does not exist is refused',
    dbtest.attest_as(dbtest.u(2999)), '23514', NULL, 'repositories_map_attestor_is_an_active_human');
  PERFORM dbtest.expect_ok('an active person of the tenant can attest a map (the sibling of the refusals)',
    dbtest.attest_as(dbtest.u(2002)));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 5. The time is the database's, and it moves only when the attestation changes.

SELECT dbtest.exec(format($q$UPDATE repositories SET project_map_commit = repeat('d', 40), project_map_attested_by_principal_id = %L,
  project_map_attested_at = '2001-01-01T00:00:00Z', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1001)));

CREATE TEMP TABLE stamped AS
  SELECT project_map_attested_at AS at FROM repositories WHERE id = dbtest.u(1001);
SELECT pg_sleep(0.05);

DO $$
BEGIN
  PERFORM dbtest.expect_true('a time written by the caller is replaced by the time of the database',
    (SELECT at > now() - interval '1 minute' FROM stamped));
END
$$;

SELECT dbtest.exec(format($q$UPDATE repositories SET enabled = false, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)));
SELECT dbtest.exec(format($q$UPDATE repositories SET project_map_attested_at = '2002-02-02T00:00:00Z', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)));

DO $$
BEGIN
  PERFORM dbtest.expect_true('the time stays when the attestation does not change, even if the caller writes another one',
    (SELECT r.project_map_attested_at = s.at FROM repositories r, stamped s WHERE r.id = dbtest.u(1001)));
END
$$;

SELECT dbtest.exec(format($q$UPDATE repositories SET project_map_commit = repeat('e', 40), version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)));

DO $$
BEGIN
  PERFORM dbtest.expect_true('the time moves when another commit is attested',
    (SELECT r.project_map_attested_at > s.at FROM repositories r, stamped s WHERE r.id = dbtest.u(1001)));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 6. The optimistic version: an update must raise it by exactly one (bump_guard).

DO $$
BEGIN
  PERFORM dbtest.expect_error('an update that does not raise the version is refused',
    format($q$UPDATE repositories SET project_map_commit = repeat('f', 40) WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)),
    '23514', NULL, 'repositories_version_bump');
  PERFORM dbtest.expect_error('an update that raises the version by two is refused',
    format($q$UPDATE repositories SET project_map_commit = repeat('f', 40), version = version + 2 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)),
    '23514', NULL, 'repositories_version_bump');
  PERFORM dbtest.expect_ok('an update that raises the version by one is accepted (the sibling)',
    format($q$UPDATE repositories SET project_map_commit = repeat('f', 40), version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 7. The login of the API after migration 2026-11-03-002700 (finding REG-2): it registers nothing, attests nothing
--    and enables nothing. It may switch a repository off, and section 12 proves each of those, with its controls.
--    What stays here is the part that does not depend on the login: the worker's group registers a repository with
--    the defaults, changes the map by column grants, and cannot touch the other columns.

DO $$
DECLARE
  register text := format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
                              VALUES (%L, %L, 9201, 8201, 'org1/third', 'main')$q$, dbtest.u(1), dbtest.u(1011));
BEGIN
  PERFORM dbtest.expect_eq('the worker group can register a repository for the tenant it named',
    dbtest.run_as(register, 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('what the columns leave to the defaults is disabled, level L0 and no protection result',
    (SELECT string_agg(column_name || '=' || column_default, ', ' ORDER BY column_name) FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'repositories'
        AND column_name IN ('enabled', 'autonomy_ceiling', 'protection_preflight_passed')),
    'autonomy_ceiling=''L0''::text, enabled=false, protection_preflight_passed=false');
  PERFORM dbtest.expect_true('the worker group cannot register a repository for another tenant than the one it named',
    dbtest.run_as(replace(register, dbtest.u(1)::text, dbtest.u(2)::text), 'factory_app', 1) LIKE 'ERR:42501:new row violates row-level security policy%');
  PERFORM dbtest.expect_true('with no tenant named the worker group registers nothing',
    dbtest.run_as(register, 'factory_app', 0) LIKE 'ERR:42501:%');
  PERFORM dbtest.expect_true('the GitHub repository of another tenant cannot be registered (the global key answers with a unique violation)',
    dbtest.run_as(format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
        VALUES (%L, %L, 9201, 8002, 'org1/stolen', 'main')$q$, dbtest.u(1), dbtest.u(1012)), 'factory_app', 1) LIKE 'ERR:23505:%');
END
$$;

DO $$
DECLARE
  map_it text := format($q$UPDATE repositories SET project_map_commit = repeat('9', 40), project_map_attested_by_principal_id = %L, version = version + 1
                             WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1001));
  col text;
BEGIN
  PERFORM dbtest.expect_eq('the worker group can attest a map on a repository of its tenant', dbtest.run_as(map_it, 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the worker group attesting for a repository of another tenant changes nothing (the row is not visible)',
    dbtest.run_as(replace(map_it, dbtest.u(1)::text, dbtest.u(2)::text), 'factory_app', 1), 'rows=0');
  PERFORM dbtest.expect_true('the worker group cannot write the time of the attestation (the database does)',
    dbtest.run_as(format($q$UPDATE repositories SET project_map_attested_at = now(), version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)),
                  'factory_app', 1) LIKE 'ERR:42501:permission denied for table repositories');
  FOREACH col IN ARRAY ARRAY['full_name', 'github_installation_id', 'github_repository_id', 'tenant_id', 'id', 'single_maintainer'] LOOP
    PERFORM dbtest.expect_true('the worker group cannot update ' || col,
      dbtest.run_as(format($q$UPDATE repositories SET %I = %I, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, col, col, dbtest.u(1), dbtest.u(1001)),
                    'factory_app', 1) LIKE 'ERR:42501:permission denied for table repositories', col);
  END LOOP;
  PERFORM dbtest.expect_true('the worker group cannot delete a repository',
    dbtest.run_as(format($q$DELETE FROM repositories WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)), 'factory_app', 1)
      LIKE 'ERR:42501:permission denied for table repositories');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 8. Another tenant sees nothing of the map, and a disabled repository is not found by its installation.

SELECT dbtest.exec(format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('7', 40), project_map_attested_by_principal_id = %L,
  enabled_by_principal_id = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1004), dbtest.u(1), dbtest.u(1001)));

DO $$
BEGIN
  PERFORM dbtest.expect_eq('a session of the tenant sees its own map', dbtest.run_as('SELECT 1 FROM repositories WHERE project_map_commit IS NOT NULL', 'factory_api_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('a session of another tenant sees no map at all', dbtest.run_as('SELECT 1 FROM repositories WHERE project_map_commit IS NOT NULL', 'factory_api_app', 2), 'rows=0');
  PERFORM dbtest.expect_eq('the worker role of another tenant sees no map at all', dbtest.run_as('SELECT 1 FROM repositories WHERE project_map_commit IS NOT NULL', 'factory_app', 2), 'rows=0');
  PERFORM dbtest.expect_eq('with no tenant named nothing is seen', dbtest.run_as('SELECT 1 FROM repositories', 'factory_api_app', 0), 'rows=0');
  PERFORM dbtest.expect_eq('an enabled repository with a map is found by its installation (the webhook binding)',
    dbtest.run_as(format($q$SELECT 1 FROM resolve_installation(9001, 8001) WHERE repository_id = %L$q$, dbtest.u(1001)), 'factory_resolver'), 'rows=1');
  PERFORM dbtest.expect_eq('the same repository disabled again is not found (the sibling)',
    dbtest.run_as('SELECT 1 FROM resolve_installation(9001, 8001)', 'factory_resolver', NULL,
                  format($q$UPDATE repositories SET enabled = false, version = version + 1 WHERE id = %L$q$, dbtest.u(1001))), 'rows=0');
  PERFORM dbtest.expect_eq('a repository registered and never enabled is not found by its installation',
    dbtest.run_as('SELECT 1 FROM resolve_installation(9002, 8002)', 'factory_resolver'), 'rows=0');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 9. Controls: each rule is switched off for one statement, and the statement it refused then goes through.
--    A rule that cannot be shown to matter is not a rule (catalog principle 2).

DO $$
DECLARE
  enable_it text := format($q$UPDATE repositories SET enabled = true, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(2), dbtest.u(2001));
BEGIN
  -- Since migration 2026-11-02-002500 a repository with no map is also stopped by the record of the enabling, which
  -- cannot be complete without a commit. So the two are dropped together to show that the check matters.
  PERFORM dbtest.expect_true('control: with the check dropped, the record of the enabling still refuses a repository with no map',
    dbtest.run_as(enable_it, 'factory_app', 2, 'ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_needs_project_map')
      LIKE 'ERR:23514:%repositories_enabled_record_is_complete%');
  PERFORM dbtest.expect_true('control: with the check and the record dropped, a repository with no map is enabled',
    dbtest.run_as(enable_it, 'factory_app', 2, 'ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_needs_project_map; ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_record_is_complete') = 'rows=1');
  PERFORM dbtest.expect_true('control: with the format check dropped, a branch name is taken for a commit',
    dbtest.run_as(dbtest.set_map('main'), 'factory_app', 1, 'ALTER TABLE repositories DROP CONSTRAINT repositories_project_map_commit_check') = 'rows=1');
  PERFORM dbtest.expect_true('control: with the guard dropped, a service principal attests a map and a caller writes the time (as the worker group)',
    dbtest.run_as(format($q$UPDATE repositories SET enabled = false, enabled_project_map_commit = NULL, enabled_by_principal_id = NULL, enabled_at = NULL,
                            version = version + 1 WHERE tenant_id = %1$L AND id = %2$L;
                            UPDATE repositories SET project_map_commit = repeat('a', 40), project_map_attested_by_principal_id = %3$L,
                            project_map_attested_at = '2001-01-01T00:00:00Z', version = version + 1 WHERE tenant_id = %1$L AND id = %2$L$q$,
                         dbtest.u(1), dbtest.u(1001), dbtest.u(1003)), 'factory_app', 1,
                  'DROP TRIGGER repositories_project_map_guard ON repositories; GRANT UPDATE (project_map_attested_at, enabled_at) ON repositories TO factory_app') = 'rows=1');
  PERFORM dbtest.expect_true('control: with the grant given back, the worker group sets the autonomy ceiling',
    dbtest.run_as(format($q$UPDATE repositories SET autonomy_ceiling = 'L3', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)),
                  'factory_app', 1, 'GRANT UPDATE (autonomy_ceiling) ON repositories TO factory_app') = 'rows=1');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 10. A repository stays enabled only for the map it was enabled for (migration 2026-11-02-002500, finding REG-1).
--     The table decides this itself, so a writer that skips the API cannot skip the rule. Every statement below is
--     raw SQL as the login of the API or the group of the worker. dbtest.after runs one statement in a
--     subtransaction, reads the repository as the same role, reports what it saw and rolls everything back.
--     The report reads: enabled=<flag> for=<first four characters of the commit it was enabled for> by=<enabler>
--     at=<none, or now for a time within the last minute>.

CREATE FUNCTION dbtest.after(p_stmt text, p_role text, p_tenant int, p_repository uuid, p_setup text DEFAULT NULL) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
  res text;
  st text;
  cn text;
BEGIN
  BEGIN
    IF p_setup IS NOT NULL THEN
      EXECUTE p_setup;
    END IF;
    PERFORM dbtest.become(p_role, p_tenant);
    EXECUTE p_stmt;
    SELECT format('enabled=%s for=%s by=%s at=%s', r.enabled::text, coalesce(left(r.enabled_project_map_commit, 4), '-'),
                  coalesce(r.enabled_by_principal_id::text, '-'),
                  CASE WHEN r.enabled_at IS NULL THEN 'none' WHEN r.enabled_at > now() - interval '1 minute' THEN 'now' ELSE 'old' END)
      INTO res FROM repositories r WHERE r.id = p_repository;
    RAISE EXCEPTION 'rollback' USING ERRCODE = 'XX998';
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS st = RETURNED_SQLSTATE, cn = CONSTRAINT_NAME;
    IF st <> 'XX998' THEN
      res := 'ERR:' || st || ':' || coalesce(cn, '');
    END IF;
  END;
  RETURN res;
END
$$;

-- Tenant 1 gets a disabled person (the second person is made at the top of this file). Repository 1020 has the map 'aaaa...' attested by person 1002.
INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES (dbtest.u(1), dbtest.u(1005), 'human', 7105, 'person-gone');
UPDATE principals SET disabled_at = now() WHERE id = dbtest.u(1005);
-- It is a single-maintainer repository, because sections 10a to 10c enable it by the person who attested the map and
-- test the rule of REG-1, not the rule of REG-6 (section 11 tests that one on repositories of its own).
INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch,
                          project_map_commit, project_map_attested_by_principal_id, single_maintainer)
  VALUES (dbtest.u(1), dbtest.u(1020), 9301, 8301, 'org1/enabled-for-a-map', 'main', repeat('a', 40), dbtest.u(1002), true);

-- 10a. What enabling records, on the repository that is still disabled.

DO $$
DECLARE
  repo uuid := dbtest.u(1020);
  one uuid := dbtest.u(1002);
  scope text := format('WHERE tenant_id = %L AND id = %L', dbtest.u(1), dbtest.u(1020));
  enable_for_a text := format($q$UPDATE repositories SET enabled = true, enabled_project_map_commit = repeat('a', 40), enabled_by_principal_id = %L,
                                  version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1020));
BEGIN
  PERFORM dbtest.expect_eq('the worker group enables a repository for the commit it names (the first writer); the database records who and when',
    dbtest.after(enable_for_a, 'factory_app', 1, repo), format('enabled=true for=aaaa by=%s at=now', one));
  PERFORM dbtest.expect_eq('the worker group enables it the same way',
    dbtest.after(enable_for_a, 'factory_app', 1, repo), format('enabled=true for=aaaa by=%s at=now', one));
  PERFORM dbtest.expect_eq('a writer that names no commit is bound to the commit on file, and the enabler stays empty',
    dbtest.after('UPDATE repositories SET enabled = true, version = version + 1 ' || scope, 'factory_app', 1, repo),
    'enabled=true for=aaaa by=- at=now');
  PERFORM dbtest.expect_eq('an enable that names another commit than the one on file is refused by the table',
    dbtest.after(replace(enable_for_a, 'enabled_project_map_commit = repeat(''a'', 40)', 'enabled_project_map_commit = repeat(''b'', 40)'),
                 'factory_app', 1, repo),
    'ERR:23514:repositories_enabled_project_map_commit_matches');
  PERFORM dbtest.expect_eq('a service principal cannot be the enabler',
    dbtest.after(replace(enable_for_a, one::text, dbtest.u(1003)::text), 'factory_app', 1, repo),
    'ERR:23514:repositories_enabler_is_an_active_human');
  PERFORM dbtest.expect_eq('a disabled person cannot be the enabler',
    dbtest.after(replace(enable_for_a, one::text, dbtest.u(1005)::text), 'factory_app', 1, repo),
    'ERR:23514:repositories_enabler_is_an_active_human');
  PERFORM dbtest.expect_eq('a person of another tenant cannot be the enabler',
    dbtest.after(replace(enable_for_a, one::text, dbtest.u(2002)::text), 'factory_app', 1, repo),
    'ERR:23514:repositories_enabler_is_an_active_human');
  PERFORM dbtest.expect_true('the worker group cannot write the time of the enabling (the database does)',
    dbtest.run_as('UPDATE repositories SET enabled_at = now(), version = version + 1 ' || scope, 'factory_app', 1)
      LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_true('the worker group cannot write it either (again)',
    dbtest.run_as('UPDATE repositories SET enabled_at = now(), version = version + 1 ' || scope, 'factory_app', 1)
      LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_eq('a repository that is disabled keeps no record, whatever the statement writes',
    dbtest.after(format($q$UPDATE repositories SET enabled_project_map_commit = repeat('a', 40), enabled_by_principal_id = %L,
                            version = version + 1 %s$q$, one, scope), 'factory_app', 1, repo),
    'enabled=false for=- by=- at=none');
END
$$;

-- 10b. Enabled for 'aaaa...' by person 1002. The owner writes a time of 2001 to show that the database replaces it.

SELECT dbtest.exec(format($q$UPDATE repositories SET enabled = true, enabled_project_map_commit = repeat('a', 40), enabled_by_principal_id = %L,
  enabled_at = '2001-01-01T00:00:00Z', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1020)));

DO $$
DECLARE
  repo uuid := dbtest.u(1020);
  one uuid := dbtest.u(1002);
  two uuid := dbtest.u(1004);
  scope text := format('WHERE tenant_id = %L AND id = %L', dbtest.u(1), dbtest.u(1020));
  kept text := format('enabled=true for=aaaa by=%s at=now', dbtest.u(1002));
  off text := 'enabled=false for=- by=- at=none';
BEGIN
  PERFORM dbtest.expect_eq('a time written by the caller is replaced by the time of the database',
    dbtest.after('SELECT 1', 'factory_app', 1, repo), kept);

  -- The rule of REG-1: the map moves, the repository is switched off, and the record goes with it.
  PERFORM dbtest.expect_eq('REG-1: attesting another commit on an enabled repository switches it off (worker group)',
    dbtest.after(format($q$UPDATE repositories SET project_map_commit = repeat('b', 40), project_map_attested_by_principal_id = %L,
                            version = version + 1 %s$q$, one, scope), 'factory_app', 1, repo), off);
  PERFORM dbtest.expect_eq('REG-1: the same, as the worker group',
    dbtest.after(format($q$UPDATE repositories SET project_map_commit = repeat('b', 40), project_map_attested_by_principal_id = %L,
                            version = version + 1 %s$q$, one, scope), 'factory_app', 1, repo), off);
  PERFORM dbtest.expect_eq('REG-1: another person attesting the same commit switches it off too',
    dbtest.after(format($q$UPDATE repositories SET project_map_attested_by_principal_id = %L, version = version + 1 %s$q$, two, scope),
                 'factory_app', 1, repo), off);
  PERFORM dbtest.expect_eq('REG-1: a statement that says enabled = true with another commit is overruled',
    dbtest.after(format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('b', 40), enabled_project_map_commit = repeat('b', 40),
                            project_map_attested_by_principal_id = %L, version = version + 1 %s$q$, one, scope), 'factory_app', 1, repo), off);
  PERFORM dbtest.expect_eq('REG-1: removing the map switches the repository off, and the attestation goes with it',
    dbtest.after(format($q$UPDATE repositories SET project_map_commit = NULL, project_map_attested_by_principal_id = NULL,
                            version = version + 1 %s$q$, scope), 'factory_app', 1, repo), off);
  PERFORM dbtest.expect_eq('the sibling: attesting the same commit by the same person changes nothing',
    dbtest.after(format($q$UPDATE repositories SET project_map_commit = repeat('a', 40), project_map_attested_by_principal_id = %L,
                            version = version + 1 %s$q$, one, scope), 'factory_app', 1, repo), kept);
  PERFORM dbtest.expect_eq('while it stays enabled, a writer cannot rewrite who or for which commit',
    dbtest.after(format($q$UPDATE repositories SET enabled_by_principal_id = %L, enabled_project_map_commit = repeat('a', 40),
                            version = version + 1 %s$q$, two, scope), 'factory_app', 1, repo), kept);

  -- Disabling by hand empties the record, and nothing the statement writes keeps it.
  PERFORM dbtest.expect_eq('disabling empties the record of the enabling',
    dbtest.after('UPDATE repositories SET enabled = false, version = version + 1 ' || scope, 'factory_app', 1, repo), off);
  PERFORM dbtest.expect_eq('a record written in the statement that disables is not kept',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, enabled_by_principal_id = %L, version = version + 1 %s$q$, two, scope),
                 'factory_app', 1, repo), off);

  -- A repository that is disabled may be mapped again and enabled again, in one statement or in two.
  PERFORM dbtest.expect_eq('the sibling: from disabled, another commit attested and enabled for in one statement is enabled for that commit',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                 format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('b', 40), enabled_project_map_commit = repeat('b', 40),
                            project_map_attested_by_principal_id = %L, enabled_by_principal_id = %L, version = version + 1 %s$q$, two, two, scope),
                 'factory_app', 1, repo), format('enabled=true for=bbbb by=%s at=now', two));
  PERFORM dbtest.expect_eq('the sibling: from disabled, attesting another commit leaves it disabled',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                 format($q$UPDATE repositories SET project_map_commit = repeat('b', 40), project_map_attested_by_principal_id = %L,
                            version = version + 1 %s$q$, two, scope), 'factory_app', 1, repo), off);
END
$$;

-- 10c. Controls. Each rule is switched off for one statement, and the statement it refused then goes through. A rule
--      that cannot be shown to matter is not a rule (catalog principle 2).

DO $$
DECLARE
  repo uuid := dbtest.u(1020);
  one uuid := dbtest.u(1002);
  scope text := format('WHERE tenant_id = %L AND id = %L', dbtest.u(1), dbtest.u(1020));
  re_attest text := format($q$UPDATE repositories SET project_map_commit = repeat('b', 40), project_map_attested_by_principal_id = %L,
                               version = version + 1 %s$q$, dbtest.u(1002), format('WHERE tenant_id = %L AND id = %L', dbtest.u(1), dbtest.u(1020)));
  -- With the trigger gone nothing empties the record, so the statement that disables does it by hand.
  disable_by_hand text := format($q$UPDATE repositories SET enabled = false, enabled_project_map_commit = NULL, enabled_by_principal_id = NULL,
                                   enabled_at = NULL, version = version + 1 %s$q$, format('WHERE tenant_id = %L AND id = %L', dbtest.u(1), dbtest.u(1020)));
  grant_time text := 'GRANT UPDATE (enabled_at) ON repositories TO factory_app';
  drop_guard text := 'DROP TRIGGER repositories_project_map_guard ON repositories';
  drop_matches text := 'ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_project_map_commit_matches';
  drop_complete text := 'ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_record_is_complete';
BEGIN
  PERFORM dbtest.expect_eq('control: with the trigger dropped, the CHECK is the second guard and refuses the re-attestation of an enabled repository',
    dbtest.after(re_attest, 'factory_app', 1, repo, drop_guard), 'ERR:23514:repositories_enabled_project_map_commit_matches');
  PERFORM dbtest.expect_eq('control: with the trigger and that CHECK dropped, the repository stays enabled over a map nobody enabled it for (REG-1)',
    dbtest.after(re_attest, 'factory_app', 1, repo, drop_guard || ';' || drop_matches), format('enabled=true for=aaaa by=%s at=now', one));
  PERFORM dbtest.expect_eq('control: with the CHECK dropped, an enable that names another commit goes through',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                 format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('b', 40), project_map_attested_by_principal_id = %L,
                            enabled_project_map_commit = repeat('c', 40), version = version + 1 %s$q$, one, scope),
                 'factory_app', 1, repo, drop_matches), 'enabled=true for=cccc by=- at=now');
  PERFORM dbtest.expect_eq('control: with the trigger dropped, a service principal is accepted as the enabler',
    dbtest.after(disable_by_hand || ';' ||
                 format($q$UPDATE repositories SET enabled = true, enabled_project_map_commit = repeat('a', 40), enabled_at = now(),
                            enabled_by_principal_id = %L, version = version + 1 %s$q$, dbtest.u(1003), scope),
                 'factory_app', 1, repo, drop_guard || ';' || grant_time),
    format('enabled=true for=aaaa by=%s at=now', dbtest.u(1003)));
  PERFORM dbtest.expect_eq('control: with the trigger dropped, a plain enable leaves no record and the CHECK refuses it',
    dbtest.after(disable_by_hand || ';' ||
                 format($q$UPDATE repositories SET enabled = true, version = version + 1 %s$q$, scope), 'factory_app', 1, repo, drop_guard || ';' || grant_time),
    'ERR:23514:repositories_enabled_record_is_complete');
  PERFORM dbtest.expect_eq('control: with the trigger and the completeness CHECK dropped, it is enabled with no record',
    dbtest.after(disable_by_hand || ';' ||
                 format($q$UPDATE repositories SET enabled = true, version = version + 1 %s$q$, scope), 'factory_app', 1, repo, drop_guard || ';' || drop_complete || ';' || grant_time),
    'enabled=true for=- by=- at=none');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 11. The enabler of a repository is not the attestor of its map, unless the repository is a single-maintainer one
--     (migration 2026-11-03-002600, finding REG-6). The flag is written at registration and never after. Every
--     statement is raw SQL as the login of the API, the group of the worker or the owner, and dbtest.after reports
--     what the row looks like afterwards (see section 10 for the format).

INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch,
                          project_map_commit, project_map_attested_by_principal_id)
  VALUES (dbtest.u(1), dbtest.u(1030), 9401, 8401, 'org1/strict', 'main', repeat('d', 40), dbtest.u(1002));
INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch,
                          project_map_commit, project_map_attested_by_principal_id, single_maintainer)
  VALUES (dbtest.u(1), dbtest.u(1031), 9402, 8402, 'org1/single-maintainer', 'main', repeat('d', 40), dbtest.u(1002), true);

CREATE FUNCTION dbtest.enable_by(p_repository uuid, p_by uuid) RETURNS text LANGUAGE sql AS $$
  SELECT format($q$UPDATE repositories SET enabled = true, enabled_project_map_commit = repeat('d', 40), enabled_by_principal_id = %L,
                          version = version + 1 WHERE tenant_id = %L AND id = %L$q$, p_by, dbtest.u(1), p_repository)
$$;

-- 11a. The flag, and the rule.

DO $$
DECLARE
  strict_repo uuid := dbtest.u(1030);
  single_repo uuid := dbtest.u(1031);
  attestor uuid := dbtest.u(1002);
  other uuid := dbtest.u(1004);
  refused text := 'ERR:23514:repositories_enabler_differs_from_attestor';
BEGIN
  PERFORM dbtest.expect_eq('the flag is a boolean that cannot be empty and is false unless a registration says otherwise',
    (SELECT data_type || ':' || is_nullable || ':' || column_default FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'repositories' AND column_name = 'single_maintainer'), 'boolean:NO:false');
  PERFORM dbtest.expect_eq('a repository written without the flag is a strict one',
    (SELECT single_maintainer FROM repositories WHERE id = strict_repo), false);
  PERFORM dbtest.expect_eq('REG-6: the person who attested the map cannot enable the repository (worker group)',
    dbtest.after(dbtest.enable_by(strict_repo, attestor), 'factory_app', 1, strict_repo), refused);
  PERFORM dbtest.expect_eq('REG-6: nor as the group of the worker',
    dbtest.after(dbtest.enable_by(strict_repo, attestor), 'factory_app', 1, strict_repo), refused);
  PERFORM dbtest.expect_error('REG-6: nor as the table owner (the rule is in the table)',
    dbtest.enable_by(strict_repo, attestor), '23514', NULL, 'repositories_enabler_differs_from_attestor');
  PERFORM dbtest.expect_error('REG-6: nor in the statement that inserts the row already enabled (as the owner, because the logins cannot insert these columns)',
    format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch,
                          project_map_commit, project_map_attested_by_principal_id, enabled, enabled_by_principal_id)
                       VALUES (%L, %L, 9403, 8403, 'org1/strict-insert', 'main', repeat('d', 40), %L, true, %L)$q$,
                      dbtest.u(1), dbtest.u(1032), attestor, attestor),
    '23514', NULL, 'repositories_enabler_differs_from_attestor');
  PERFORM dbtest.expect_eq('the sibling: another active person of the tenant can enable it, and the record names them',
    dbtest.after(dbtest.enable_by(strict_repo, other), 'factory_app', 1, strict_repo), format('enabled=true for=dddd by=%s at=now', other));
  PERFORM dbtest.expect_eq('the sibling: a single-maintainer repository can be enabled by the person who attested the map',
    dbtest.after(dbtest.enable_by(single_repo, attestor), 'factory_app', 1, single_repo), format('enabled=true for=dddd by=%s at=now', attestor));
  PERFORM dbtest.expect_eq('the sibling: so can the group of the worker enable it',
    dbtest.after(dbtest.enable_by(single_repo, attestor), 'factory_app', 1, single_repo), format('enabled=true for=dddd by=%s at=now', attestor));
END
$$;

-- 11b. Who may write the flag. The API login inserts it at registration and updates it never.

DO $$
DECLARE
  single_repo uuid := dbtest.u(1031);
  scope text := format('WHERE tenant_id = %L AND id = %L', dbtest.u(1), dbtest.u(1031));
  register text := format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, single_maintainer)
                              VALUES (%L, %L, 9404, 8404, 'org1/api-single_repo', 'main', true)$q$, dbtest.u(1), dbtest.u(1033));
BEGIN
  PERFORM dbtest.expect_eq('the worker group registers a repository as a single-maintainer one (at registration, from a signed request)', dbtest.run_as(register, 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_true('the worker group cannot write the flag of another tenant than the one it named',
    dbtest.run_as(replace(register, dbtest.u(1)::text, dbtest.u(2)::text), 'factory_app', 1) LIKE 'ERR:42501:%');
  PERFORM dbtest.expect_true('the API login cannot register a repository at all, with the flag or without it (section 12)',
    dbtest.run_as(register, 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_true('the API login cannot change the flag afterwards (no grant)',
    dbtest.run_as('UPDATE repositories SET single_maintainer = false, version = version + 1 ' || scope, 'factory_api_app', 1)
      LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_true('the group of the worker cannot change it either (no grant)',
    dbtest.run_as('UPDATE repositories SET single_maintainer = false, version = version + 1 ' || scope, 'factory_app', 1)
      LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_eq('control: with the grant given, a trigger still refuses the API login (the second guard; migration 2026-11-03-002700 refuses it first)',
    dbtest.after('UPDATE repositories SET single_maintainer = false, version = version + 1 ' || scope, 'factory_api_app', 1, single_repo,
                 'GRANT UPDATE (single_maintainer) ON repositories TO factory_api_app'),
    'ERR:42501:');
  PERFORM dbtest.expect_eq('control: with the grant given, the trigger still refuses the group of the worker',
    dbtest.after('UPDATE repositories SET single_maintainer = false, version = version + 1 ' || scope, 'factory_app', 1, single_repo,
                 'GRANT UPDATE (single_maintainer) ON repositories TO factory_app'),
    'ERR:23514:repositories_single_maintainer_is_set_at_registration');
  PERFORM dbtest.expect_eq('control: with the grant given and both triggers dropped, the API login changes the flag',
    dbtest.run_as('UPDATE repositories SET single_maintainer = false, version = version + 1 ' || scope, 'factory_api_app', 1,
                  'GRANT UPDATE (single_maintainer) ON repositories TO factory_api_app; DROP TRIGGER repositories_project_map_guard ON repositories; DROP TRIGGER repositories_api_may_only_disable ON repositories'),
    'rows=1');
  PERFORM dbtest.expect_ok('the table owner, who is an administrator and not a login of the factory, can change the flag (the documented path)',
    'UPDATE repositories SET single_maintainer = false, version = version + 1 ' || scope);
END
$$;

-- 11c. Controls: the CHECK is the second guard behind the trigger, and without both the pair goes through.

DO $$
DECLARE
  strict_repo uuid := dbtest.u(1030);
  attestor uuid := dbtest.u(1002);
  drop_guard text := 'DROP TRIGGER repositories_project_map_guard ON repositories';
  drop_check text := 'ALTER TABLE repositories DROP CONSTRAINT repositories_enabler_differs_from_attestor';
  -- With the trigger gone nothing stamps the time of the enabling, so the statement writes it and the grant is given.
  grant_time text := 'GRANT UPDATE (enabled_at) ON repositories TO factory_app';
  with_time text := replace(dbtest.enable_by(dbtest.u(1030), dbtest.u(1002)), 'enabled = true,', 'enabled = true, enabled_at = now(),');
BEGIN
  PERFORM dbtest.expect_eq('control: with the trigger dropped, the CHECK refuses the attestor as the enabler',
    dbtest.after(with_time, 'factory_app', 1, strict_repo, drop_guard || ';' || grant_time), 'ERR:23514:repositories_enabler_differs_from_attestor');
  PERFORM dbtest.expect_eq('control: with the trigger and the CHECK dropped, the attestor enables a strict repository (REG-6)',
    dbtest.after(with_time, 'factory_app', 1, strict_repo, drop_guard || ';' || drop_check || ';' || grant_time),
    format('enabled=true for=dddd by=%s at=now', attestor));
  PERFORM dbtest.expect_eq('control: with only the CHECK dropped, the trigger still refuses',
    dbtest.after(dbtest.enable_by(strict_repo, attestor), 'factory_app', 1, strict_repo, drop_check), 'ERR:23514:repositories_enabler_differs_from_attestor');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 12. Register, attest and enable are signed requests that the worker applies (migration 2026-11-03-002700, finding
--     REG-2). The login of the API can append the request and can switch a repository off, and it can do nothing else to
--     the table. Each refusal has a sibling that is accepted and a control that drops the guard and shows the guard matters.

INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch,
                          project_map_commit, project_map_attested_by_principal_id, single_maintainer)
  VALUES (dbtest.u(1), dbtest.u(1040), 9501, 8501, 'org1/api-guard', 'main', repeat('e', 40), dbtest.u(1002), true);
SELECT dbtest.exec(format($q$UPDATE repositories SET enabled = true, enabled_by_principal_id = %L, version = version + 1
                              WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1040)));

CREATE FUNCTION dbtest.api_audit(p_action text, p_subject text DEFAULT 'subject') RETURNS text LANGUAGE sql AS $$
  SELECT format($q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason,
                       policy_hash, correlation_id)
                       VALUES (%L, %L, 'human', 'p1', %L, %L, 'record', 'because', %L, %L)$q$,
                dbtest.u(1), gen_random_uuid(), p_action, p_subject, dbtest.sha('policy'), gen_random_uuid())
$$;

-- The words the API writes, as migration 2026-11-03-002800 judges them (finding RH-5).
CREATE FUNCTION dbtest.disabled_words(p_repository uuid) RETURNS text LANGUAGE sql AS $$
  SELECT 'repository ' || p_repository::text || ' disabled'
$$;
CREATE FUNCTION dbtest.request_words(p_kind text, p_repository uuid) RETURNS text LANGUAGE sql AS $$
  SELECT 'change kind=' || p_kind || ' repository=' || p_repository::text
      || CASE p_kind WHEN 'register' THEN ' installation=7001 github_repository=8001 single_maintainer=false'
                     ELSE ' commit=' || repeat('a', 40) END
      || ' payload=' || dbtest.sha('detail') || ' at=2026-11-03T10:00:00.123456789Z mac=' || repeat('b', 64)
$$;

DO $$
DECLARE
  repo uuid := dbtest.u(1040);
  scope text := format('WHERE tenant_id = %L AND id = %L', dbtest.u(1), dbtest.u(1040));
  register text := format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
                              VALUES (%L, %L, 9502, 8502, 'org1/api-register', 'main')$q$, dbtest.u(1), dbtest.u(1041));
  col text;
  denied text := 'ERR:42501:permission denied for table repositories';
BEGIN
  -- It cannot register, attest or enable: no grant.
  PERFORM dbtest.expect_true('REG-2: the API login cannot register a repository', dbtest.run_as(register, 'factory_api_app', 1) LIKE denied);
  FOREACH col IN ARRAY ARRAY['project_map_commit', 'project_map_attested_by_principal_id', 'enabled_project_map_commit',
                             'enabled_by_principal_id', 'autonomy_ceiling', 'protection_preflight_passed', 'single_maintainer'] LOOP
    PERFORM dbtest.expect_true('REG-2: the API login cannot update ' || col,
      dbtest.run_as(format($q$UPDATE repositories SET %I = %I, version = version + 1 %s$q$, col, col, scope), 'factory_api_app', 1) LIKE denied, col);
  END LOOP;
  PERFORM dbtest.expect_true('REG-2: the API login cannot enable a repository that is off',
    dbtest.run_as(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                  format($q$UPDATE repositories SET enabled = true, version = version + 1 %s$q$, scope), 'factory_api_app', 1)
      LIKE 'ERR:42501:the API login may only switch a repository off');
  -- It may switch a repository off, and a switch-off of a repository that is off.
  PERFORM dbtest.expect_eq('the sibling: the API login switches an enabled repository off', dbtest.run_as(
    format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope), 'factory_api_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the sibling: and the repository is off, with the record of the enabling emptied',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope), 'factory_api_app', 1, repo),
    'enabled=false for=- by=- at=none');
  PERFORM dbtest.expect_eq('the sibling: switching off a repository that is off is allowed and raises the version',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                 format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope), 'factory_api_app', 1, repo),
    'enabled=false for=- by=- at=none');
  -- The second guard: the grant of `enabled` alone would let it switch ON, and the trigger does not.
  PERFORM dbtest.expect_true('control: with the trigger dropped, the grant of `enabled` alone lets the API login switch a repository on',
    dbtest.run_as(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                  format($q$UPDATE repositories SET enabled = true, version = version + 1 %s$q$, scope), 'factory_api_app', 1,
                  'DROP TRIGGER repositories_api_may_only_disable ON repositories') LIKE 'rows=%');
  PERFORM dbtest.expect_true('control: with the column granted back, the trigger still refuses the API login a change of the map',
    dbtest.run_as(format($q$UPDATE repositories SET project_map_commit = repeat('1', 40), version = version + 1 %s$q$, scope), 'factory_api_app', 1,
                  'GRANT UPDATE (project_map_commit) ON repositories TO factory_api_app')
      LIKE 'ERR:42501:the API login may only switch a repository off');
  PERFORM dbtest.expect_true('control: with the column granted back and the trigger dropped, the API login changes the map (REG-2)',
    dbtest.run_as(format($q$UPDATE repositories SET project_map_commit = repeat('1', 40), version = version + 1 %s$q$, scope), 'factory_api_app', 1,
                  'GRANT UPDATE (project_map_commit) ON repositories TO factory_api_app; DROP TRIGGER repositories_api_may_only_disable ON repositories') LIKE 'rows=%');
  PERFORM dbtest.expect_true('control: with the column granted back, the trigger refuses a change of the name as well (the whole row is compared)',
    dbtest.run_as(format($q$UPDATE repositories SET full_name = 'org1/renamed', version = version + 1 %s$q$, scope), 'factory_api_app', 1,
                  'GRANT UPDATE (full_name) ON repositories TO factory_api_app')
      LIKE 'ERR:42501:the API login may only switch a repository off');
  PERFORM dbtest.expect_true('a switch-off that also changes the name is refused (a change with the off, not an off alone)',
    dbtest.run_as(format($q$UPDATE repositories SET enabled = false, full_name = 'org1/renamed', version = version + 1 %s$q$, scope), 'factory_api_app', 1,
                  'GRANT UPDATE (full_name) ON repositories TO factory_api_app')
      LIKE 'ERR:42501:the API login may only switch a repository off');
  -- The worker's group and the owner are not bound by it: they apply the requests.
  PERFORM dbtest.expect_eq('the worker group is not bound by the trigger of the API login: it enables a repository',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                 format($q$UPDATE repositories SET enabled = true, enabled_project_map_commit = repeat('e', 40), enabled_by_principal_id = %L, version = version + 1 %s$q$, dbtest.u(1002), scope),
                 'factory_app', 1, repo), format('enabled=true for=eeee by=%s at=now', dbtest.u(1002)));
  -- The audit actions: the request, and the disable; not the three acts that widen the reach.
  PERFORM dbtest.expect_ok('REG-2: the API login may append a repository.change_requested record',
    dbtest.api_audit('repository.change_requested', dbtest.request_words('enable', repo)), 'factory_api_app', 1);
  PERFORM dbtest.expect_ok('and a repository.disabled record', dbtest.api_audit('repository.disabled', dbtest.disabled_words(repo)), 'factory_api_app', 1);
  FOREACH col IN ARRAY ARRAY['repository.registered', 'repository.map_attested', 'repository.enabled', 'repository.change_applied'] LOOP
    PERFORM dbtest.expect_error('REG-2: the API login may not write ' || col, dbtest.api_audit(col), '42501', 'factory_api_app', NULL, NULL, 1);
  END LOOP;
  PERFORM dbtest.expect_ok('the worker group writes the result of a request: ' || 'repository.registered',
    dbtest.api_audit('repository.registered'), 'factory_app', 1);
END
$$;


-- ---------------------------------------------------------------------------------------------
-- 13. The audit rows of the API login are a person's, in the API's words (migration 2026-11-03-002800, finding RH-5).
--     Before it, the login could write a `repository.disabled` row as the system or as anyone, with any words, and an
--     unsigned `repository.change_requested` row. Each refusal has a sibling that is accepted and a control that drops the
--     trigger and shows the refused row then goes through. The keyed word is the worker's and the status route's to check:
--     SQL has no key, so a well-formed row with a made-up word is accepted here by design.

DO $$
DECLARE
  repo uuid := dbtest.u(1040);
  as_actor text;
  kind text;
  words text;
  refused text := 'ERR:42501:the API login may write a repository audit record only as a person and in the words the API writes';
  listed text := 'ERR:42501:the API login may not write an audit record with this action or this actor';
  write_as text := $q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason,
                          policy_hash, correlation_id)
                          VALUES (%L, %L, %L, 'p1', %L, %L, %L, 'because', %L, %L)$q$;
BEGIN
  -- repository.disabled
  PERFORM dbtest.expect_eq('RH-5: the API login writes repository.disabled as a person, in the words the API writes',
    dbtest.run_as(dbtest.api_audit('repository.disabled', dbtest.disabled_words(repo)), 'factory_api_app', 1), 'rows=1');
  FOREACH as_actor IN ARRAY ARRAY['system', 'service', 'anonymous'] LOOP
    PERFORM dbtest.expect_eq('RH-5: it cannot write repository.disabled as ' || as_actor,
      dbtest.run_as(format(write_as, dbtest.u(1), gen_random_uuid(), as_actor, 'repository.disabled',
                           dbtest.disabled_words(repo), 'record', dbtest.sha('policy'), gen_random_uuid()), 'factory_api_app', 1), refused);
  END LOOP;
  FOREACH words IN ARRAY ARRAY[
      'subject', 'repository ' || repo::text, 'repository ' || repo::text || ' disabled and more',
      'request=' || repo::text || ' repository ' || repo::text || ' disabled', upper(dbtest.disabled_words(repo)),
      'repository not-a-uuid disabled', dbtest.disabled_words(repo) || E'\n'] LOOP
    PERFORM dbtest.expect_eq('RH-5: it cannot write repository.disabled with the words ' || quote_literal(words),
      dbtest.run_as(dbtest.api_audit('repository.disabled', words), 'factory_api_app', 1), refused);
  END LOOP;
  PERFORM dbtest.expect_eq('RH-5: it cannot write repository.disabled with the decision deny',
    dbtest.run_as(format(write_as, dbtest.u(1), gen_random_uuid(), 'human', 'repository.disabled',
                         dbtest.disabled_words(repo), 'deny', dbtest.sha('policy'), gen_random_uuid()), 'factory_api_app', 1), refused);

  -- repository.change_requested
  FOREACH kind IN ARRAY ARRAY['register', 'attest', 'enable'] LOOP
    PERFORM dbtest.expect_eq('RH-5: the API login writes a ' || kind || ' request in the words the API writes',
      dbtest.run_as(dbtest.api_audit('repository.change_requested', dbtest.request_words(kind, repo)), 'factory_api_app', 1), 'rows=1');
  END LOOP;
  FOREACH as_actor IN ARRAY ARRAY['system', 'service', 'anonymous'] LOOP
    PERFORM dbtest.expect_eq('RH-5: it cannot write a request as ' || as_actor,
      dbtest.run_as(format(write_as, dbtest.u(1), gen_random_uuid(), as_actor, 'repository.change_requested',
                           dbtest.request_words('enable', repo), 'record', dbtest.sha('policy'), gen_random_uuid()), 'factory_api_app', 1), refused);
  END LOOP;
  FOREACH words IN ARRAY ARRAY[
      'subject', replace(dbtest.request_words('enable', repo), 'kind=enable', 'kind=delete'),
      replace(dbtest.request_words('enable', repo), ' mac=' || repeat('b', 64), ''),
      replace(dbtest.request_words('enable', repo), repeat('b', 64), repeat('b', 63)),
      replace(dbtest.request_words('enable', repo), repeat('b', 64), repeat('B', 64)),
      replace(dbtest.request_words('enable', repo), repeat('a', 40), repeat('a', 39)),
      replace(dbtest.request_words('enable', repo), ' at=2026-11-03T10:00:00.123456789Z', ''),
      dbtest.request_words('enable', repo) || ' extra=words',
      replace(dbtest.request_words('register', repo), 'single_maintainer=false', 'single_maintainer=maybe'),
      replace(dbtest.request_words('enable', repo), 'payload=sha256:', 'payload=sha1:')] LOOP
    PERFORM dbtest.expect_eq('RH-5: it cannot write a request with the words ' || left(quote_literal(words), 70),
      dbtest.run_as(dbtest.api_audit('repository.change_requested', words), 'factory_api_app', 1), refused);
  END LOOP;

  -- The worker's own effect record is not the API's, and the group of the worker is not bound by the guard.
  PERFORM dbtest.expect_eq('RH-5: the API login cannot write repository.disabled_by_attestation, the worker''s record of an effect',
    dbtest.run_as(format(write_as, dbtest.u(1), gen_random_uuid(), 'system', 'repository.disabled_by_attestation',
                         'request=' || repo::text || ' repository ' || repo::text || ' disabled', 'record', dbtest.sha('policy'), gen_random_uuid()),
                  'factory_api_app', 1), listed);
  PERFORM dbtest.expect_eq('the sibling: the worker group writes repository.disabled_by_attestation as the system',
    dbtest.run_as(format(write_as, dbtest.u(1), gen_random_uuid(), 'system', 'repository.disabled_by_attestation',
                         'request=' || repo::text || ' repository ' || repo::text || ' disabled', 'record', dbtest.sha('policy'), gen_random_uuid()),
                  'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the sibling: the worker group is not bound by the guard of the API login',
    dbtest.run_as(format(write_as, dbtest.u(1), gen_random_uuid(), 'system', 'repository.disabled',
                         'anything', 'record', dbtest.sha('policy'), gen_random_uuid()), 'factory_app', 1), 'rows=1');

  -- Controls: the trigger is the only thing that stops these rows.
  PERFORM dbtest.expect_eq('control: with the trigger dropped, the API login writes repository.disabled as the system (RH-5)',
    dbtest.run_as(format(write_as, dbtest.u(1), gen_random_uuid(), 'system', 'repository.disabled',
                         'request=' || repo::text || ' repository ' || repo::text || ' disabled', 'record', dbtest.sha('policy'), gen_random_uuid()),
                  'factory_api_app', 1, 'DROP TRIGGER audit_events_api_actions ON audit_events'), 'rows=1');
  PERFORM dbtest.expect_eq('control: with the trigger dropped, it writes a request with no word (RH-5)',
    dbtest.run_as(dbtest.api_audit('repository.change_requested', 'subject'), 'factory_api_app', 1,
                  'DROP TRIGGER audit_events_api_actions ON audit_events'), 'rows=1');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 14. A strict repository that is enabled names its enabler (migration 2026-11-03-002800, finding RH-8). The guard binds
--     the logins of the factory (the API group, the worker group); the table owner and a superuser are administrators, as for
--     the flag single_maintainer (section 11b). Before it, one INSERT by the group of the worker enabled a strict repository
--     with no enabler.

DO $$
DECLARE
  attestor uuid := dbtest.u(1002);
  other uuid := dbtest.u(1004);
  insert_enabled text := $q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch,
                          project_map_commit, project_map_attested_by_principal_id, enabled, enabled_by_principal_id, single_maintainer)
                          VALUES (%L, %L, %s, %s, %L, 'main', repeat('f', 40), %L, true, %s, %s)$q$;
  rejected text := 'ERR:23514:%strict%must say who enabled it%';
BEGIN
  PERFORM dbtest.expect_true('RH-8: the group of the worker cannot insert an enabled strict repository with no enabler',
    dbtest.run_as(format(insert_enabled, dbtest.u(1), dbtest.u(1050), 9601, 8601, 'org1/no-enabler', attestor, 'NULL', 'false'), 'factory_app', 1) LIKE rejected);
  PERFORM dbtest.expect_eq('the sibling: with an enabler who is not the attestor it is accepted',
    dbtest.run_as(format(insert_enabled, dbtest.u(1), dbtest.u(1051), 9602, 8602, 'org1/with-enabler', attestor, quote_literal(other), 'false'), 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the sibling: a single-maintainer repository may be enabled with no recorded enabler (the strict rule is the one that needs it)',
    dbtest.run_as(format(insert_enabled, dbtest.u(1), dbtest.u(1052), 9603, 8603, 'org1/single-no-enabler', attestor, 'NULL', 'true'), 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the sibling: a strict repository that is not enabled needs no enabler',
    dbtest.run_as(replace(format(insert_enabled, dbtest.u(1), dbtest.u(1053), 9604, 8604, 'org1/off', attestor, 'NULL', 'false'), 'true, NULL', 'false, NULL'), 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the table owner, an administrator and not a login of the factory, is not bound by it (the documented path, as for the flag)',
    dbtest.try_stmt(format(insert_enabled, dbtest.u(1), dbtest.u(1055), 9606, 8606, 'org1/owner-no-enabler', attestor, 'NULL', 'false')), 'ok');
  -- The update path: enabling a registered strict repository without naming the enabler.
  PERFORM dbtest.expect_true('RH-8: an UPDATE that enables a strict repository and names no enabler is refused (worker group)',
    dbtest.run_as(format($q$UPDATE repositories SET enabled = true, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1030)),
                  'factory_app', 1) LIKE rejected);
  PERFORM dbtest.expect_eq('the sibling: the same UPDATE naming a person who is not the attestor is accepted',
    dbtest.run_as(format($q$UPDATE repositories SET enabled = true, enabled_by_principal_id = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$,
                         other, dbtest.u(1), dbtest.u(1030)), 'factory_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('control: with the trigger dropped, the worker group inserts an enabled strict repository with no enabler (RH-8)',
    dbtest.run_as(format(insert_enabled, dbtest.u(1), dbtest.u(1054), 9605, 8605, 'org1/no-enabler-2', attestor, 'NULL', 'false'), 'factory_app', 1,
                  'DROP TRIGGER repositories_strict_enabler_guard ON repositories'), 'rows=1');
END
$$;
