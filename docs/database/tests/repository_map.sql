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
  PERFORM dbtest.expect_error('the login of the API cannot enable a repository that has no project map', enable_it,
    '23514', 'factory_api_app', 'repositories_enabled_needs_project_map', NULL, 1);
  PERFORM dbtest.expect_error('a row cannot be inserted enabled with no project map',
    format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, enabled)
              VALUES (%L, %L, 9101, 8101, 'org1/second', 'main', true)$q$, dbtest.u(1), dbtest.u(1010)),
    '23514', NULL, 'repositories_enabled_needs_project_map');
  PERFORM dbtest.expect_ok('the same update is accepted when it carries the map commit and its attestor (the sibling of the refusals)',
    enable_with_map);
  PERFORM dbtest.expect_ok('the login of the API may enable a repository with a map commit',
    enable_with_map, 'factory_api_app', 1);
  PERFORM dbtest.expect_ok('a repository can stay disabled with no map (the invariant is one way only)',
    format($q$UPDATE repositories SET enabled = false, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)));
END
$$;

-- Take the map away from a repository that is enabled: the same invariant, from the other side.
SELECT dbtest.exec(format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('c', 40),
  project_map_attested_by_principal_id = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1001)));

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
-- 7. The login of the API: six columns to register, four columns to change, one tenant.

DO $$
DECLARE
  register text := format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
                              VALUES (%L, %L, 9201, 8201, 'org1/third', 'main')$q$, dbtest.u(1), dbtest.u(1011));
BEGIN
  PERFORM dbtest.expect_eq('the API login can register a repository for the tenant it named',
    dbtest.run_as(register, 'factory_api_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('what the six columns leave to the defaults is disabled, level L0 and no protection result',
    (SELECT string_agg(column_name || '=' || column_default, ', ' ORDER BY column_name) FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = 'repositories'
        AND column_name IN ('enabled', 'autonomy_ceiling', 'protection_preflight_passed')),
    'autonomy_ceiling=''L0''::text, enabled=false, protection_preflight_passed=false');
  PERFORM dbtest.expect_true('the API login cannot register a repository for another tenant than the one it named',
    dbtest.run_as(replace(register, dbtest.u(1)::text, dbtest.u(2)::text), 'factory_api_app', 1) LIKE 'ERR:42501:new row violates row-level security policy%');
  PERFORM dbtest.expect_true('with no tenant named the API login registers nothing',
    dbtest.run_as(register, 'factory_api_app', 0) LIKE 'ERR:42501:%');
  PERFORM dbtest.expect_true('the API login cannot register a repository already enabled',
    dbtest.run_as(format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, enabled)
        VALUES (%L, %L, 9201, 8201, 'org1/third', 'main', true)$q$, dbtest.u(1), dbtest.u(1011)), 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_true('the API login cannot register a repository with a higher autonomy ceiling',
    dbtest.run_as(format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, autonomy_ceiling)
        VALUES (%L, %L, 9201, 8201, 'org1/third', 'main', 'L3')$q$, dbtest.u(1), dbtest.u(1011)), 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_true('the API login cannot register a repository with a passed protection result',
    dbtest.run_as(format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, protection_preflight_passed)
        VALUES (%L, %L, 9201, 8201, 'org1/third', 'main', true)$q$, dbtest.u(1), dbtest.u(1011)), 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_true('the API login cannot register a repository with the map already attested',
    dbtest.run_as(format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, project_map_attested_at)
        VALUES (%L, %L, 9201, 8201, 'org1/third', 'main', now())$q$, dbtest.u(1), dbtest.u(1011)), 'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_true('the GitHub repository of another tenant cannot be registered (the global key answers with a unique violation)',
    dbtest.run_as(format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
        VALUES (%L, %L, 9201, 8002, 'org1/stolen', 'main')$q$, dbtest.u(1), dbtest.u(1012)), 'factory_api_app', 1) LIKE 'ERR:23505:%');
END
$$;

DO $$
DECLARE
  map_it text := format($q$UPDATE repositories SET project_map_commit = repeat('9', 40), project_map_attested_by_principal_id = %L, version = version + 1
                             WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1001));
  col text;
BEGIN
  PERFORM dbtest.expect_eq('the API login can attest a map on a repository of its tenant', dbtest.run_as(map_it, 'factory_api_app', 1), 'rows=1');
  PERFORM dbtest.expect_eq('the API login attesting for a repository of another tenant changes nothing (the row is not visible)',
    dbtest.run_as(replace(map_it, dbtest.u(1)::text, dbtest.u(2)::text), 'factory_api_app', 1), 'rows=0');
  PERFORM dbtest.expect_true('the API login cannot write the time of the attestation (the database does)',
    dbtest.run_as(format($q$UPDATE repositories SET project_map_attested_at = now(), version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)),
                  'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table repositories');
  FOREACH col IN ARRAY ARRAY['autonomy_ceiling', 'protection_preflight_passed', 'default_branch', 'full_name',
                             'github_installation_id', 'github_repository_id', 'bypass_attested_by_principal_id', 'bypass_attested_at', 'tenant_id', 'id'] LOOP
    PERFORM dbtest.expect_true('the API login cannot update ' || col,
      dbtest.run_as(format($q$UPDATE repositories SET %I = %I, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, col, col, dbtest.u(1), dbtest.u(1001)),
                    'factory_api_app', 1) LIKE 'ERR:42501:permission denied for table repositories', col);
  END LOOP;
  PERFORM dbtest.expect_true('the API login cannot delete a repository',
    dbtest.run_as(format($q$DELETE FROM repositories WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)), 'factory_api_app', 1)
      LIKE 'ERR:42501:permission denied for table repositories');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 8. Another tenant sees nothing of the map, and a disabled repository is not found by its installation.

SELECT dbtest.exec(format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('7', 40), project_map_attested_by_principal_id = %L,
  version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1001)));

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
    dbtest.run_as(dbtest.set_map('main'), 'factory_api_app', 1, 'ALTER TABLE repositories DROP CONSTRAINT repositories_project_map_commit_check') = 'rows=1');
  PERFORM dbtest.expect_true('control: with the guard dropped, a service principal attests a map and a caller writes the time',
    dbtest.run_as(format($q$UPDATE repositories SET enabled = false, enabled_project_map_commit = NULL, enabled_by_principal_id = NULL, enabled_at = NULL,
                            version = version + 1 WHERE tenant_id = %1$L AND id = %2$L;
                            UPDATE repositories SET project_map_commit = repeat('a', 40), project_map_attested_by_principal_id = %3$L,
                            project_map_attested_at = '2001-01-01T00:00:00Z', version = version + 1 WHERE tenant_id = %1$L AND id = %2$L$q$,
                         dbtest.u(1), dbtest.u(1001), dbtest.u(1003)), 'factory_api_app', 1,
                  'DROP TRIGGER repositories_project_map_guard ON repositories; GRANT UPDATE (project_map_attested_at, enabled_at) ON repositories TO factory_api_app') = 'rows=1');
  PERFORM dbtest.expect_true('control: with the grant given back, the API login sets the autonomy ceiling',
    dbtest.run_as(format($q$UPDATE repositories SET autonomy_ceiling = 'L3', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1001)),
                  'factory_api_app', 1, 'GRANT UPDATE (autonomy_ceiling) ON repositories TO factory_api_app') = 'rows=1');
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

-- Tenant 1 gets a second person and a disabled one. Repository 1020 has the map 'aaaa...' attested by person 1002.
INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES (dbtest.u(1), dbtest.u(1004), 'human', 7104, 'person-two');
INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES (dbtest.u(1), dbtest.u(1005), 'human', 7105, 'person-gone');
UPDATE principals SET disabled_at = now() WHERE id = dbtest.u(1005);
INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch,
                          project_map_commit, project_map_attested_by_principal_id)
  VALUES (dbtest.u(1), dbtest.u(1020), 9301, 8301, 'org1/enabled-for-a-map', 'main', repeat('a', 40), dbtest.u(1002));

-- 10a. What enabling records, on the repository that is still disabled.

DO $$
DECLARE
  repo uuid := dbtest.u(1020);
  one uuid := dbtest.u(1002);
  scope text := format('WHERE tenant_id = %L AND id = %L', dbtest.u(1), dbtest.u(1020));
  enable_for_a text := format($q$UPDATE repositories SET enabled = true, enabled_project_map_commit = repeat('a', 40), enabled_by_principal_id = %L,
                                  version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1002), dbtest.u(1), dbtest.u(1020));
BEGIN
  PERFORM dbtest.expect_eq('the API login enables a repository for the commit it names; the database records who and when',
    dbtest.after(enable_for_a, 'factory_api_app', 1, repo), format('enabled=true for=aaaa by=%s at=now', one));
  PERFORM dbtest.expect_eq('the worker group enables it the same way',
    dbtest.after(enable_for_a, 'factory_app', 1, repo), format('enabled=true for=aaaa by=%s at=now', one));
  PERFORM dbtest.expect_eq('a writer that names no commit is bound to the commit on file, and the enabler stays empty',
    dbtest.after('UPDATE repositories SET enabled = true, version = version + 1 ' || scope, 'factory_api_app', 1, repo),
    'enabled=true for=aaaa by=- at=now');
  PERFORM dbtest.expect_eq('an enable that names another commit than the one on file is refused by the table',
    dbtest.after(replace(enable_for_a, 'enabled_project_map_commit = repeat(''a'', 40)', 'enabled_project_map_commit = repeat(''b'', 40)'),
                 'factory_api_app', 1, repo),
    'ERR:23514:repositories_enabled_project_map_commit_matches');
  PERFORM dbtest.expect_eq('a service principal cannot be the enabler',
    dbtest.after(replace(enable_for_a, one::text, dbtest.u(1003)::text), 'factory_api_app', 1, repo),
    'ERR:23514:repositories_enabler_is_an_active_human');
  PERFORM dbtest.expect_eq('a disabled person cannot be the enabler',
    dbtest.after(replace(enable_for_a, one::text, dbtest.u(1005)::text), 'factory_api_app', 1, repo),
    'ERR:23514:repositories_enabler_is_an_active_human');
  PERFORM dbtest.expect_eq('a person of another tenant cannot be the enabler',
    dbtest.after(replace(enable_for_a, one::text, dbtest.u(2002)::text), 'factory_api_app', 1, repo),
    'ERR:23514:repositories_enabler_is_an_active_human');
  PERFORM dbtest.expect_true('the API login cannot write the time of the enabling (the database does)',
    dbtest.run_as('UPDATE repositories SET enabled_at = now(), version = version + 1 ' || scope, 'factory_api_app', 1)
      LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_true('the worker group cannot write it either',
    dbtest.run_as('UPDATE repositories SET enabled_at = now(), version = version + 1 ' || scope, 'factory_app', 1)
      LIKE 'ERR:42501:permission denied for table repositories');
  PERFORM dbtest.expect_eq('a repository that is disabled keeps no record, whatever the statement writes',
    dbtest.after(format($q$UPDATE repositories SET enabled_project_map_commit = repeat('a', 40), enabled_by_principal_id = %L,
                            version = version + 1 %s$q$, one, scope), 'factory_api_app', 1, repo),
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
    dbtest.after('SELECT 1', 'factory_api_app', 1, repo), kept);

  -- The rule of REG-1: the map moves, the repository is switched off, and the record goes with it.
  PERFORM dbtest.expect_eq('REG-1: attesting another commit on an enabled repository switches it off (API login)',
    dbtest.after(format($q$UPDATE repositories SET project_map_commit = repeat('b', 40), project_map_attested_by_principal_id = %L,
                            version = version + 1 %s$q$, one, scope), 'factory_api_app', 1, repo), off);
  PERFORM dbtest.expect_eq('REG-1: the same, as the worker group',
    dbtest.after(format($q$UPDATE repositories SET project_map_commit = repeat('b', 40), project_map_attested_by_principal_id = %L,
                            version = version + 1 %s$q$, one, scope), 'factory_app', 1, repo), off);
  PERFORM dbtest.expect_eq('REG-1: another person attesting the same commit switches it off too',
    dbtest.after(format($q$UPDATE repositories SET project_map_attested_by_principal_id = %L, version = version + 1 %s$q$, two, scope),
                 'factory_api_app', 1, repo), off);
  PERFORM dbtest.expect_eq('REG-1: a statement that says enabled = true with another commit is overruled',
    dbtest.after(format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('b', 40), enabled_project_map_commit = repeat('b', 40),
                            project_map_attested_by_principal_id = %L, version = version + 1 %s$q$, one, scope), 'factory_api_app', 1, repo), off);
  PERFORM dbtest.expect_eq('REG-1: removing the map switches the repository off, and the attestation goes with it',
    dbtest.after(format($q$UPDATE repositories SET project_map_commit = NULL, project_map_attested_by_principal_id = NULL,
                            version = version + 1 %s$q$, scope), 'factory_api_app', 1, repo), off);
  PERFORM dbtest.expect_eq('the sibling: attesting the same commit by the same person changes nothing',
    dbtest.after(format($q$UPDATE repositories SET project_map_commit = repeat('a', 40), project_map_attested_by_principal_id = %L,
                            version = version + 1 %s$q$, one, scope), 'factory_api_app', 1, repo), kept);
  PERFORM dbtest.expect_eq('while it stays enabled, a writer cannot rewrite who or for which commit',
    dbtest.after(format($q$UPDATE repositories SET enabled_by_principal_id = %L, enabled_project_map_commit = repeat('a', 40),
                            version = version + 1 %s$q$, two, scope), 'factory_api_app', 1, repo), kept);

  -- Disabling by hand empties the record, and nothing the statement writes keeps it.
  PERFORM dbtest.expect_eq('disabling empties the record of the enabling',
    dbtest.after('UPDATE repositories SET enabled = false, version = version + 1 ' || scope, 'factory_api_app', 1, repo), off);
  PERFORM dbtest.expect_eq('a record written in the statement that disables is not kept',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, enabled_by_principal_id = %L, version = version + 1 %s$q$, two, scope),
                 'factory_api_app', 1, repo), off);

  -- A repository that is disabled may be mapped again and enabled again, in one statement or in two.
  PERFORM dbtest.expect_eq('the sibling: from disabled, another commit attested and enabled for in one statement is enabled for that commit',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                 format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('b', 40), enabled_project_map_commit = repeat('b', 40),
                            project_map_attested_by_principal_id = %L, enabled_by_principal_id = %L, version = version + 1 %s$q$, two, two, scope),
                 'factory_api_app', 1, repo), format('enabled=true for=bbbb by=%s at=now', two));
  PERFORM dbtest.expect_eq('the sibling: from disabled, attesting another commit leaves it disabled',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                 format($q$UPDATE repositories SET project_map_commit = repeat('b', 40), project_map_attested_by_principal_id = %L,
                            version = version + 1 %s$q$, two, scope), 'factory_api_app', 1, repo), off);
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
  grant_time text := 'GRANT UPDATE (enabled_at) ON repositories TO factory_api_app';
  drop_guard text := 'DROP TRIGGER repositories_project_map_guard ON repositories';
  drop_matches text := 'ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_project_map_commit_matches';
  drop_complete text := 'ALTER TABLE repositories DROP CONSTRAINT repositories_enabled_record_is_complete';
BEGIN
  PERFORM dbtest.expect_eq('control: with the trigger dropped, the CHECK is the second guard and refuses the re-attestation of an enabled repository',
    dbtest.after(re_attest, 'factory_api_app', 1, repo, drop_guard), 'ERR:23514:repositories_enabled_project_map_commit_matches');
  PERFORM dbtest.expect_eq('control: with the trigger and that CHECK dropped, the repository stays enabled over a map nobody enabled it for (REG-1)',
    dbtest.after(re_attest, 'factory_api_app', 1, repo, drop_guard || ';' || drop_matches), format('enabled=true for=aaaa by=%s at=now', one));
  PERFORM dbtest.expect_eq('control: with the CHECK dropped, an enable that names another commit goes through',
    dbtest.after(format($q$UPDATE repositories SET enabled = false, version = version + 1 %s$q$, scope) || ';' ||
                 format($q$UPDATE repositories SET enabled = true, project_map_commit = repeat('b', 40), project_map_attested_by_principal_id = %L,
                            enabled_project_map_commit = repeat('c', 40), version = version + 1 %s$q$, one, scope),
                 'factory_api_app', 1, repo, drop_matches), 'enabled=true for=cccc by=- at=now');
  PERFORM dbtest.expect_eq('control: with the trigger dropped, a service principal is accepted as the enabler',
    dbtest.after(disable_by_hand || ';' ||
                 format($q$UPDATE repositories SET enabled = true, enabled_project_map_commit = repeat('a', 40), enabled_at = now(),
                            enabled_by_principal_id = %L, version = version + 1 %s$q$, dbtest.u(1003), scope),
                 'factory_api_app', 1, repo, drop_guard || ';' || grant_time),
    format('enabled=true for=aaaa by=%s at=now', dbtest.u(1003)));
  PERFORM dbtest.expect_eq('control: with the trigger dropped, a plain enable leaves no record and the CHECK refuses it',
    dbtest.after(disable_by_hand || ';' ||
                 format($q$UPDATE repositories SET enabled = true, version = version + 1 %s$q$, scope), 'factory_api_app', 1, repo, drop_guard || ';' || grant_time),
    'ERR:23514:repositories_enabled_record_is_complete');
  PERFORM dbtest.expect_eq('control: with the trigger and the completeness CHECK dropped, it is enabled with no record',
    dbtest.after(disable_by_hand || ';' ||
                 format($q$UPDATE repositories SET enabled = true, version = version + 1 %s$q$, scope), 'factory_api_app', 1, repo, drop_guard || ';' || drop_complete || ';' || grant_time),
    'enabled=true for=- by=- at=none');
END
$$;
