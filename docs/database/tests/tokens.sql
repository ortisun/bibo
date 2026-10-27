-- Suite: tokens
-- Proves that API tokens are stored only as a hash, expire, are bound to an audience, can be revoked and
-- never un-revoked, and that the schema holds no secret in a readable column. The hashes below are
-- random bytes made up for the test. No real token or key appears anywhere.

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_tenant(2);
  -- A second human of tenant 1 who is disabled.
  INSERT INTO principals (tenant_id, id, kind, github_user_id, login, disabled_at)
    VALUES (dbtest.u(1), dbtest.u(1010), 'human', 7010, 'former-colleague', now());
END
$$;

CREATE FUNCTION dbtest.token_sql(
  p_id uuid, p_hash bytea, p_audience text DEFAULT 'factory-api', p_principal uuid DEFAULT dbtest.u(1002),
  p_created text DEFAULT 'now()', p_expires text DEFAULT 'now() + interval ''1 day''', p_tenant uuid DEFAULT dbtest.u(1)
) RETURNS text LANGUAGE sql AS $$
  SELECT format($q$INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, label, created_at, expires_at)
                   VALUES (%L, %L, %L, %L, %L, 'test token', %s, %s)$q$, p_tenant, p_id, p_principal, p_hash, p_audience, p_created, p_expires)
$$;

-- ---------------------------------------------------------------------------------------------
-- 1. Only a 32-byte hash fits. A plaintext token does not.

DO $$
BEGIN
  PERFORM dbtest.exec(dbtest.token_sql(dbtest.u(1), decode(repeat('11', 32), 'hex')), 'factory_app');
  PERFORM dbtest.expect_eq('a token stored as a 32-byte hash is accepted', (SELECT count(*) FROM api_tokens), 1::bigint);
  PERFORM dbtest.expect_error('a 31-byte value is not a SHA-256 hash',
    dbtest.token_sql(dbtest.u(2), decode(repeat('22', 31), 'hex')), '23514', 'factory_app', 'api_tokens_token_hash_check');
  PERFORM dbtest.expect_error('a 33-byte value is not a SHA-256 hash',
    dbtest.token_sql(dbtest.u(2), decode(repeat('22', 33), 'hex')), '23514', 'factory_app', 'api_tokens_token_hash_check');
  PERFORM dbtest.expect_error('the readable form of a job token (sfjt_ followed by 43 characters) does not fit the hash column',
    dbtest.token_sql(dbtest.u(2), convert_to('sfjt_' || repeat('A', 43), 'UTF8')), '23514', 'factory_app', 'api_tokens_token_hash_check');
  PERFORM dbtest.expect_error('the same hash cannot be stored twice, not even under another tenant (lookup by hash must be unambiguous)',
    dbtest.token_sql(dbtest.u(2), decode(repeat('11', 32), 'hex'), p_principal => dbtest.u(2002), p_tenant => dbtest.u(2)), '23505', 'factory_app', 'api_tokens_token_hash_key');
END
$$;

-- No readable secret has a column: a catalog scan, so a future column cannot slip in unnoticed.
DO $$
DECLARE
  suspicious text;
BEGIN
  SELECT string_agg(table_name || '.' || column_name, ', ' ORDER BY table_name, column_name) INTO suspicious
    FROM information_schema.columns
   WHERE table_schema = 'public'
     AND (column_name ~* '(secret|password|passwd|credential|private|api_key|apikey|bearer|plaintext)'
          OR (column_name ~* 'token' AND column_name <> 'token_hash'));
  PERFORM dbtest.expect_eq('no column is named like a secret, a password or a readable token (only token_hash)', coalesce(suspicious, ''), '');
  PERFORM dbtest.expect_eq('token_hash is binary, not text',
    (SELECT data_type FROM information_schema.columns WHERE table_name = 'api_tokens' AND column_name = 'token_hash'), 'bytea');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Expiry, audience and the shape of the record.

DO $$
BEGIN
  PERFORM dbtest.expect_error('a token that expires before it is created is refused',
    dbtest.token_sql(dbtest.u(3), decode(repeat('33', 32), 'hex'), p_expires => 'now() - interval ''1 hour'''), '23514', 'factory_app');
  PERFORM dbtest.expect_error('a token with no expiry is refused',
    dbtest.token_sql(dbtest.u(3), decode(repeat('33', 32), 'hex'), p_expires => 'NULL'), '23502', 'factory_app');
  PERFORM dbtest.expect_error('a token with no audience is refused',
    format($q$INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, expires_at) VALUES (%L, %L, %L, %L, now() + interval '1 day')$q$,
           dbtest.u(1), dbtest.u(3), dbtest.u(1002), decode(repeat('33', 32), 'hex')), '23502', 'factory_app');
  PERFORM dbtest.expect_error('an audience that is not a slug is refused',
    dbtest.token_sql(dbtest.u(3), decode(repeat('33', 32), 'hex'), 'Admin API'), '23514', 'factory_app', 'api_tokens_audience_check');
  PERFORM dbtest.expect_error('a token cannot belong to a person of another tenant',
    dbtest.token_sql(dbtest.u(3), decode(repeat('33', 32), 'hex'), p_principal => dbtest.u(2002)), '23503', 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. What counts as a usable token: not revoked, not expired, owner not disabled, right audience.

DO $$
BEGIN
  -- Tokens 11 (active, factory-api), 12 (active, factory-cli), 13 (expired), 14 (revoked), 15 (disabled owner).
  PERFORM dbtest.exec(dbtest.token_sql(dbtest.u(12), decode(repeat('12', 32), 'hex'), 'factory-cli'), 'factory_app');
  PERFORM dbtest.exec(dbtest.token_sql(dbtest.u(13), decode(repeat('13', 32), 'hex'), p_created => 'now() - interval ''2 days''', p_expires => 'now() - interval ''1 day'''), 'factory_app');
  PERFORM dbtest.exec(dbtest.token_sql(dbtest.u(14), decode(repeat('14', 32), 'hex')), 'factory_app');
  PERFORM dbtest.exec(dbtest.token_sql(dbtest.u(15), decode(repeat('15', 32), 'hex'), p_principal => dbtest.u(1010)), 'factory_app');
  PERFORM dbtest.exec(format($q$UPDATE api_tokens SET revoked_at = now() WHERE id = %L$q$, dbtest.u(14)), 'factory_app');
END
$$;

DO $$
DECLARE
  q text := $q$SELECT count(*) FROM active_api_tokens WHERE token_hash = %L AND audience = %L$q$;
  n bigint;
BEGIN
  EXECUTE format(q, decode(repeat('11', 32), 'hex'), 'factory-api') INTO n;
  PERFORM dbtest.expect_eq('the active token is found by its hash and audience', n, 1::bigint);
  EXECUTE format(q, decode(repeat('11', 32), 'hex'), 'factory-cli') INTO n;
  PERFORM dbtest.expect_eq('the same token presented to another audience is not found', n, 0::bigint);
  EXECUTE format(q, decode(repeat('12', 32), 'hex'), 'factory-cli') INTO n;
  PERFORM dbtest.expect_eq('a token for the cli audience is found for the cli audience', n, 1::bigint);
  EXECUTE format(q, decode(repeat('13', 32), 'hex'), 'factory-api') INTO n;
  PERFORM dbtest.expect_eq('an expired token is not found', n, 0::bigint);
  EXECUTE format(q, decode(repeat('14', 32), 'hex'), 'factory-api') INTO n;
  PERFORM dbtest.expect_eq('a revoked token is not found', n, 0::bigint);
  EXECUTE format(q, decode(repeat('15', 32), 'hex'), 'factory-api') INTO n;
  PERFORM dbtest.expect_eq('a token whose owner is disabled is not found', n, 0::bigint);
  EXECUTE format(q, decode(repeat('99', 32), 'hex'), 'factory-api') INTO n;
  PERFORM dbtest.expect_eq('a hash that was never stored is not found', n, 0::bigint);
  PERFORM dbtest.expect_ok('the application role can authenticate through the view', 'SELECT tenant_id, principal_id FROM active_api_tokens LIMIT 1', 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. Revocation is final, and the application role can change only what it should.

DO $$
DECLARE
  t uuid := dbtest.u(11);
BEGIN
  PERFORM dbtest.expect_error('a revoked token cannot be un-revoked',
    format($q$UPDATE api_tokens SET revoked_at = NULL WHERE id = %L$q$, dbtest.u(14)), '23514', 'factory_app', 'api_tokens_revocation_is_final');
  PERFORM dbtest.expect_error('the time of revocation cannot be rewritten',
    format($q$UPDATE api_tokens SET revoked_at = now() + interval '1 day' WHERE id = %L$q$, dbtest.u(14)), '23514', 'factory_app', 'api_tokens_revocation_is_final');
  PERFORM dbtest.expect_error('not even the owner can un-revoke a token',
    format($q$UPDATE api_tokens SET revoked_at = NULL WHERE id = %L$q$, dbtest.u(14)), '23514', NULL, 'api_tokens_revocation_is_final');
  PERFORM dbtest.expect_ok('the application role can record that a token was used',
    format($q$UPDATE api_tokens SET last_used_at = now() WHERE id = %L$q$, t), 'factory_app');
  PERFORM dbtest.expect_ok('the application role can revoke a token',
    format($q$UPDATE api_tokens SET revoked_at = now() WHERE id = %L$q$, t), 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot extend a token (expires_at has no column grant)',
    format($q$UPDATE api_tokens SET expires_at = now() + interval '10 years' WHERE id = %L$q$, t), '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot change the audience of a token',
    format($q$UPDATE api_tokens SET audience = 'factory-admin' WHERE id = %L$q$, t), '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot swap the hash of a token',
    format($q$UPDATE api_tokens SET token_hash = %L WHERE id = %L$q$, decode(repeat('77', 32), 'hex'), t), '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot reassign a token to another person',
    format($q$UPDATE api_tokens SET principal_id = %L WHERE id = %L$q$, dbtest.u(1003), t), '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot delete tokens', 'DELETE FROM api_tokens', '42501', 'factory_app');
END
$$;

-- A principal carries identity only. Authority comes from the allowlist in protected configuration.
DO $$
DECLARE
  roles text;
BEGIN
  SELECT string_agg(column_name, ', ' ORDER BY column_name) INTO roles
    FROM information_schema.columns
   WHERE table_schema = 'public' AND table_name = 'principals'
     AND column_name ~* '(role|designation|permission|admin|authority|allow)';
  PERFORM dbtest.expect_eq('principals has no column that could grant authority (it comes from the protected allowlist)', coalesce(roles, ''), '');
  PERFORM dbtest.expect_error('a human principal must have a GitHub user id',
    format($q$INSERT INTO principals (tenant_id, id, kind) VALUES (%L, %L, 'human')$q$, dbtest.u(1), dbtest.u(1011)), '23514', 'factory_app');
  PERFORM dbtest.expect_error('a service principal must not have a GitHub user id',
    format($q$INSERT INTO principals (tenant_id, id, kind, github_user_id) VALUES (%L, %L, 'service', 5)$q$, dbtest.u(1), dbtest.u(1011)), '23514', 'factory_app');
  PERFORM dbtest.expect_error('the same GitHub user cannot be two principals of one tenant',
    format($q$INSERT INTO principals (tenant_id, id, kind, github_user_id) VALUES (%L, %L, 'human', 7001)$q$, dbtest.u(1), dbtest.u(1011)), '23505', 'factory_app');
END
$$;
