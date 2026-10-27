-- Suite: tenancy
-- Proves ADR 0007 rule 4 as it is implemented in this baseline: tenant_id on every tenant-owned
-- table, foreign keys that name the tenant on both sides, unique keys that include the tenant, and
-- no way to point at another tenant's row. The structure is read from the catalog, so a new table
-- cannot skip the rules. Row-level security is deliberately NOT enabled (ADR 0007); the last section
-- shows the candidate design working on this schema inside a transaction that is rolled back.

-- ---------------------------------------------------------------------------------------------
-- 1. Structure, from the catalog.

-- Tables with a tenant_id column are the tenant-owned tables. Every other table must be a known
-- piece of shared reference data.
CREATE TEMP TABLE tenant_owned AS
SELECT c.relname AS tbl, c.oid AS oid
  FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
 WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r';

DO $$
DECLARE
  untenanted text;
  nullable text;
  bad_pk text;
  n int;
BEGIN
  SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO untenanted
    FROM pg_class c
   WHERE c.relnamespace = 'public'::regnamespace AND c.relkind = 'r'
     AND c.relname NOT IN (SELECT tbl FROM tenant_owned)
     AND c.relname NOT IN ('tenants', 'state_machine_states', 'state_machine_transitions', 'state_machine_edges', '__diesel_schema_migrations');
  PERFORM dbtest.expect_eq('every table is tenant-owned or one of the four known shared tables (tenants, three state machine tables)', coalesce(untenanted, ''), '');

  SELECT count(*) INTO n FROM tenant_owned;
  PERFORM dbtest.expect_eq('the catalog found the 17 tenant-owned tables (a new table must be added to this test deliberately)', n, 17);

  SELECT string_agg(t.tbl, ', ') INTO nullable
    FROM tenant_owned t JOIN pg_attribute a ON a.attrelid = t.oid AND a.attname = 'tenant_id'
   WHERE NOT a.attnotnull;
  PERFORM dbtest.expect_eq('tenant_id is NOT NULL on every tenant-owned table', coalesce(nullable, ''), '');

  SELECT string_agg(t.tbl, ', ') INTO bad_pk
    FROM tenant_owned t
    JOIN pg_constraint pk ON pk.conrelid = t.oid AND pk.contype = 'p'
   WHERE (SELECT a.attname FROM pg_attribute a WHERE a.attrelid = t.oid AND a.attnum = pk.conkey[1]) <> 'tenant_id';
  PERFORM dbtest.expect_eq('tenant_id is the first column of the primary key of every tenant-owned table', coalesce(bad_pk, ''), '');

  SELECT string_agg(t.tbl, ', ') INTO bad_pk
    FROM tenant_owned t WHERE NOT EXISTS (SELECT 1 FROM pg_constraint pk WHERE pk.conrelid = t.oid AND pk.contype = 'p');
  PERFORM dbtest.expect_eq('every tenant-owned table has a primary key', coalesce(bad_pk, ''), '');
END
$$;

-- Every foreign key between two tenant-owned tables joins tenant_id to tenant_id.
DO $$
DECLARE
  offenders text;
  checked int;
BEGIN
  SELECT count(*) INTO checked
    FROM pg_constraint fk
    JOIN tenant_owned child ON child.oid = fk.conrelid
    JOIN tenant_owned parent ON parent.oid = fk.confrelid
   WHERE fk.contype = 'f';

  SELECT string_agg(child.tbl || '.' || fk.conname, ', ' ORDER BY child.tbl, fk.conname) INTO offenders
    FROM pg_constraint fk
    JOIN tenant_owned child ON child.oid = fk.conrelid
    JOIN tenant_owned parent ON parent.oid = fk.confrelid
   WHERE fk.contype = 'f'
     AND NOT EXISTS (
       SELECT 1
         FROM unnest(fk.conkey, fk.confkey) AS k(child_col, parent_col)
         JOIN pg_attribute ca ON ca.attrelid = fk.conrelid AND ca.attnum = k.child_col
         JOIN pg_attribute pa ON pa.attrelid = fk.confrelid AND pa.attnum = k.parent_col
        WHERE ca.attname = 'tenant_id' AND pa.attname = 'tenant_id');
  PERFORM dbtest.expect_eq(format('all %s foreign keys between tenant-owned tables join tenant_id to tenant_id', checked), coalesce(offenders, ''), '');

  -- Every tenant-owned table also points at the tenants table.
  SELECT string_agg(t.tbl, ', ') INTO offenders
    FROM tenant_owned t
   WHERE NOT EXISTS (SELECT 1 FROM pg_constraint fk
                      WHERE fk.conrelid = t.oid AND fk.contype = 'f' AND fk.confrelid = 'public.tenants'::regclass);
  PERFORM dbtest.expect_eq('every tenant-owned table has a foreign key to tenants', coalesce(offenders, ''), '');
END
$$;

-- Every unique constraint and unique index on a tenant-owned table includes tenant_id, except two
-- that are not scoped on purpose because the lookup happens before the tenant is known.
DO $$
DECLARE
  offenders text;
  exceptions text;
  allowed text[] := ARRAY['repositories_github_repository_id_key', 'api_tokens_token_hash_key'];
  checked int;
BEGIN
  SELECT count(*) INTO checked
    FROM pg_index i JOIN tenant_owned t ON t.oid = i.indrelid WHERE i.indisunique;

  SELECT string_agg(ic.relname, ', ' ORDER BY ic.relname) INTO offenders
    FROM pg_index i
    JOIN tenant_owned t ON t.oid = i.indrelid
    JOIN pg_class ic ON ic.oid = i.indexrelid
   WHERE i.indisunique
     AND ic.relname <> ALL (allowed)
     AND NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey::int2[]) AND a.attname = 'tenant_id');
  PERFORM dbtest.expect_eq(format('all %s unique indexes on tenant-owned tables include tenant_id (apart from the listed exceptions)', checked), coalesce(offenders, ''), '');

  SELECT string_agg(ic.relname, ', ' ORDER BY ic.relname) INTO exceptions
    FROM pg_index i JOIN tenant_owned t ON t.oid = i.indrelid JOIN pg_class ic ON ic.oid = i.indexrelid
   WHERE i.indisunique
     AND NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey::int2[]) AND a.attname = 'tenant_id');
  PERFORM dbtest.expect_eq('the unique keys without a tenant are exactly the two documented ones (repository binding, token hash)',
    coalesce(exceptions, ''), 'api_tokens_token_hash_key, repositories_github_repository_id_key');
END
$$;

-- This baseline does not use row-level security (ADR 0007, rule 4). State it so a change is deliberate.
DO $$
DECLARE
  with_rls text;
BEGIN
  SELECT string_agg(relname, ', ') INTO with_rls
    FROM pg_class WHERE relnamespace = 'public'::regnamespace AND relkind = 'r' AND (relrowsecurity OR relforcerowsecurity);
  PERFORM dbtest.expect_eq('row-level security is off on every table in the baseline (ADR 0007: decided for Slice 4)', coalesce(with_rls, ''), '');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Behaviour: a row cannot point at another tenant's row. Tenant 1 and tenant 2 each have a
-- repository, principals, a job, a stage run, an artifact and a webhook delivery.

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_tenant(2);
  PERFORM dbtest.mk_job(1, 1);
  PERFORM dbtest.mk_job(2, 1);
  PERFORM dbtest.mk_job(1, 2);
  PERFORM dbtest.mk_stage_run(1, 1, 1);
  PERFORM dbtest.mk_stage_run(2, 1, 1);
  PERFORM dbtest.mk_stage_run(1, 2, 2);
  INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend)
    VALUES (dbtest.u(1), dbtest.sha('a1'), 10, 'text/plain', 'local-fs'),
           (dbtest.u(2), dbtest.sha('a2'), 10, 'text/plain', 'local-fs');
  INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256)
    VALUES (dbtest.u(1), dbtest.u(1700), 'delivery-tenant-one', 'issues', 9001, dbtest.sha('b1')),
           (dbtest.u(2), dbtest.u(2700), 'delivery-tenant-two', 'issues', 9002, dbtest.sha('b2'));
END
$$;

DO $$
DECLARE
  t1 uuid := dbtest.u(1);
  as_app text := 'factory_app';
BEGIN
  PERFORM dbtest.expect_error('jobs: a job of tenant 1 cannot use a repository of tenant 2',
    format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id)
              VALUES (%L, %L, %L, %L, 'production', 'L1', ARRAY['INTAKE'], %L)$q$, t1, dbtest.u(1190), dbtest.u(2001), dbtest.u(1002), dbtest.u(1590)),
    '23503', as_app);
  PERFORM dbtest.expect_error('jobs: a job of tenant 1 cannot name a requester of tenant 2',
    format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id)
              VALUES (%L, %L, %L, %L, 'production', 'L1', ARRAY['INTAKE'], %L)$q$, t1, dbtest.u(1190), dbtest.u(1001), dbtest.u(2002), dbtest.u(1590)),
    '23503', as_app);
  PERFORM dbtest.expect_error('jobs: a job of tenant 1 cannot come from a webhook delivery of tenant 2',
    format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id, webhook_delivery_id)
              VALUES (%L, %L, %L, %L, 'production', 'L1', ARRAY['INTAKE'], %L, %L)$q$, t1, dbtest.u(1190), dbtest.u(1001), dbtest.u(1002), dbtest.u(1590), dbtest.u(2700)),
    '23503', as_app);
  PERFORM dbtest.expect_error('jobs: the normalized request of a job of tenant 1 cannot be an artifact of tenant 2',
    format($q$UPDATE jobs SET normalized_request_sha256 = %L, version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.sha('a2'), t1, dbtest.u(1101)),
    '23503', as_app);
  PERFORM dbtest.expect_error('stage_runs: a stage run of tenant 1 cannot belong to a job of tenant 2',
    format($q$INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number) VALUES (%L, %L, %L, 'INTAKE', 5)$q$, t1, dbtest.u(1290), dbtest.u(2101)),
    '23503', as_app);
  PERFORM dbtest.expect_error('attempts: an attempt of tenant 1 cannot belong to a stage run of tenant 2',
    format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_epoch, lease_owner, lease_expires_at, deadline_at)
              VALUES (%L, %L, %L, %L, 1, 1, 'w', now() + interval '1 minute', now() + interval '1 hour')$q$, t1, dbtest.u(1390), dbtest.u(2101), dbtest.u(2201)),
    '23503', as_app);
  PERFORM dbtest.expect_error('ledger: an entry of tenant 1 cannot be filed under a job of tenant 2',
    format('SELECT dbtest.insert_entry(1, %L, %L, 1, NULL)', dbtest.u(2101), dbtest.u(2201)), '23503', as_app);
  PERFORM dbtest.expect_error('outbox: an event of tenant 1 cannot name a job of tenant 2',
    format($q$INSERT INTO outbox (tenant_id, event_id, event_type, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id, correlation_id, occurred_at, producer, payload)
              VALUES (%L, %L, 'job.admitted', %L, 'job', %L, 2, 'J01', %L, now(), 'workflow.engine', '{}')$q$, t1, dbtest.u(1490), dbtest.u(2101), dbtest.u(2101), dbtest.u(1590)),
    '23503', as_app);
  PERFORM dbtest.expect_error('api_tokens: a token of tenant 1 cannot belong to a principal of tenant 2',
    format($q$INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, expires_at) VALUES (%L, %L, %L, %L, 'factory-api', now() + interval '1 day')$q$,
           t1, dbtest.u(1890), dbtest.u(2002), decode(repeat('ab', 32), 'hex')), '23503', as_app);
  PERFORM dbtest.expect_error('original_requests: a request text of tenant 1 cannot be attached to a job of tenant 2',
    format($q$INSERT INTO original_requests (tenant_id, id, job_id, revision, source, request_text, content_sha256)
              VALUES (%L, %L, %L, 1, 'api', 'hello', %L)$q$, t1, dbtest.u(1990), dbtest.u(2101),
           'sha256:' || encode(sha256(convert_to('hello', 'UTF8')), 'hex')), '23503', as_app);
  PERFORM dbtest.expect_error('stage_run_artifacts: a run of tenant 1 cannot link an artifact of tenant 2',
    format($q$INSERT INTO stage_run_artifacts (tenant_id, job_id, stage_run_id, direction, role, content_sha256)
              VALUES (%L, %L, %L, 'input', 'spec', %L)$q$, t1, dbtest.u(1101), dbtest.u(1201), dbtest.sha('a2')), '23503', as_app);
  PERFORM dbtest.expect_error('artifacts: an artifact of tenant 1 cannot name a creating stage run of tenant 2',
    format($q$INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend, created_by_job_id, created_by_stage_run_id)
              VALUES (%L, %L, 1, 'text/plain', 'local-fs', %L, %L)$q$, t1, dbtest.sha('a3'), dbtest.u(2101), dbtest.u(2201)), '23503', as_app);
  PERFORM dbtest.expect_error('audit_events: an audit event of tenant 1 cannot name a job of tenant 2',
    format($q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id, job_id)
              VALUES (%L, %L, 'service', 'api', 'job.admitted', 'job', 'allow', 'ok', %L, %L, %L)$q$, t1, dbtest.u(1991), dbtest.sha('p'), dbtest.u(1590), dbtest.u(2101)),
    '23503', as_app);
  PERFORM dbtest.expect_error('approvals: an approval of tenant 1 cannot be recorded by a person of tenant 2',
    format($q$INSERT INTO approvals (tenant_id, id, job_id, stage_run_id, decision, approver_principal_id, approver_github_user_id, approver_designation,
                allowlist_version_hash, policy_hash, reason, channel, expires_at, pr_head_sha, tree_hash, base_sha, evidence_manifest_hash, spec_version)
              VALUES (%L, %L, %L, %L, 'approve', %L, 7002, 'approver', %L, %L, 'Reviewed.', 'cli', now() + interval '1 day', %L, %L, %L, %L, 1)$q$,
           t1, dbtest.u(1995), dbtest.u(1101), dbtest.u(1201), dbtest.u(2002), dbtest.sha('al'), dbtest.sha('po'), repeat('a', 40), repeat('b', 40), repeat('c', 40), dbtest.sha('em')),
    '23503', as_app);
END
$$;

-- The "no such row" probe above used a sentinel error to count rows. Check that directly.
DO $$
BEGIN
  PERFORM dbtest.expect_eq('a tenant-1 scoped lookup of a tenant-2 job id returns no row',
    (SELECT count(*) FROM jobs WHERE tenant_id = dbtest.u(1) AND id = dbtest.u(2101)), 0::bigint);
  PERFORM dbtest.expect_eq('a tenant-scoped lookup of its own job id returns the row',
    (SELECT count(*) FROM jobs WHERE tenant_id = dbtest.u(1) AND id = dbtest.u(1101)), 1::bigint);
END
$$;

-- Same tenant, wrong parent: the keys also pin a child to the right job, not only the right tenant.
DO $$
DECLARE
  t1 uuid := dbtest.u(1);
BEGIN
  PERFORM dbtest.expect_error('ledger: an entry of job 1101 cannot name a stage run of job 1102',
    format('SELECT dbtest.insert_entry(1, %L, %L, 1, NULL)', dbtest.u(1101), dbtest.u(1202)), '23503', 'factory_app');
  PERFORM dbtest.expect_error('stage_run_artifacts: a link cannot name a job that does not own the run',
    format($q$INSERT INTO stage_run_artifacts (tenant_id, job_id, stage_run_id, direction, role, content_sha256)
              VALUES (%L, %L, %L, 'input', 'spec', %L)$q$, t1, dbtest.u(1102), dbtest.u(1201), dbtest.sha('a1')), '23503', 'factory_app');
  PERFORM dbtest.expect_error('attempts: an attempt cannot name a job that does not own the run',
    format($q$INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_epoch, lease_owner, lease_expires_at, deadline_at)
              VALUES (%L, %L, %L, %L, 1, 1, 'w', now() + interval '1 minute', now() + interval '1 hour')$q$, t1, dbtest.u(1390), dbtest.u(1102), dbtest.u(1201)),
    '23503', 'factory_app');
  PERFORM dbtest.expect_error('audit_events: an audit event cannot name a stage run that belongs to another job',
    format($q$INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id, job_id, stage_run_id)
              VALUES (%L, %L, 'service', 'api', 'job.admitted', 'job', 'allow', 'ok', %L, %L, %L, %L)$q$, t1, dbtest.u(1991), dbtest.sha('p'), dbtest.u(1590), dbtest.u(1102), dbtest.u(1201)),
    '23503', 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. Unique keys are per tenant: the same value is allowed in two tenants and refused inside one.

DO $$
BEGIN
  PERFORM dbtest.expect_ok('the same X-GitHub-Delivery id is allowed in another tenant',
    format($q$INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256)
              VALUES (%L, %L, 'delivery-tenant-one', 'issues', 9002, %L)$q$, dbtest.u(2), dbtest.u(2701), dbtest.sha('other body')), 'factory_app');
  PERFORM dbtest.expect_error('the same delivery id is refused inside one tenant',
    format($q$INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256)
              VALUES (%L, %L, 'delivery-tenant-one', 'issues', 9001, %L)$q$, dbtest.u(1), dbtest.u(1701), dbtest.sha('another body')), '23505', 'factory_app');
  PERFORM dbtest.expect_ok('the same artifact hash is allowed in another tenant',
    format($q$INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend) VALUES (%L, %L, 10, 'text/plain', 'local-fs')$q$, dbtest.u(2), dbtest.sha('a1')), 'factory_app');
  PERFORM dbtest.expect_error('the same artifact hash is refused inside one tenant',
    format($q$INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend) VALUES (%L, %L, 10, 'text/plain', 'local-fs')$q$, dbtest.u(1), dbtest.sha('a1')), '23505', 'factory_app');
  PERFORM dbtest.expect_error('the same GitHub repository cannot be registered by two tenants (the binding is global)',
    format($q$INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
              VALUES (%L, %L, 9002, 8001, 'org2/other', 'main')$q$, dbtest.u(2), dbtest.u(2090)), '23505', 'factory_app', 'repositories_github_repository_id_key');
END
$$;

DO $$
BEGIN
  -- idempotency_key is set when a job is created; the owner sets it here because the application role
  -- cannot change it after insert.
  UPDATE jobs SET idempotency_key = 'same-key', version = version + 1 WHERE tenant_id = dbtest.u(1) AND id = dbtest.u(1101);
  UPDATE jobs SET idempotency_key = 'same-key', version = version + 1 WHERE tenant_id = dbtest.u(2) AND id = dbtest.u(2101);
  PERFORM dbtest.pass('the same job idempotency key is allowed in two tenants');
  PERFORM dbtest.expect_error('the same job idempotency key is refused inside one tenant',
    format($q$UPDATE jobs SET idempotency_key = 'same-key', version = version + 1 WHERE tenant_id = %L AND id = %L$q$, dbtest.u(1), dbtest.u(1102)),
    '23505', NULL, 'jobs_tenant_id_idempotency_key_key');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. Row-level security: the candidate design from ADR 0007, tried on this schema and rolled back.
-- This is evidence for the later ADR, not part of the baseline. FORCE ROW LEVEL SECURITY with a
-- per-transaction setting; a separate BYPASSRLS role stands for the engine's system scope.

BEGIN;

CREATE ROLE rls_spike_engine NOLOGIN BYPASSRLS;
GRANT SELECT ON jobs TO rls_spike_engine;
GRANT USAGE ON SCHEMA dbtest TO rls_spike_engine;
-- The application role has no DELETE in the baseline. Grant it inside the spike only, to show that a
-- policy limits a DELETE to the session's tenant.
GRANT DELETE ON jobs TO factory_app;
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY jobs_by_tenant ON jobs
  USING (tenant_id = nullif(current_setting('factory.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('factory.tenant_id', true), '')::uuid);

SET LOCAL ROLE factory_app;
SELECT set_config('factory.tenant_id', dbtest.u(1)::text, true);

DO $$
BEGIN
  PERFORM dbtest.expect_eq('[RLS spike] a session set to tenant 1 sees only tenant 1 jobs',
    (SELECT array_agg(DISTINCT tenant_id) FROM jobs), ARRAY[dbtest.u(1)]);
  PERFORM dbtest.expect_eq('[RLS spike] even a query that asks for a tenant 2 job by id sees nothing',
    (SELECT count(*) FROM jobs WHERE id = dbtest.u(2101)), 0::bigint);
END
$$;

DO $$
DECLARE
  n bigint;
BEGIN
  UPDATE jobs SET version = version + 1 WHERE id = dbtest.u(2101);
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM dbtest.expect_eq('[RLS spike] an UPDATE of a tenant 2 job by id changes zero rows', n, 0::bigint);
  DELETE FROM jobs WHERE id = dbtest.u(2101);
  GET DIAGNOSTICS n = ROW_COUNT;
  PERFORM dbtest.expect_eq('[RLS spike] a DELETE of a tenant 2 job by id deletes zero rows', n, 0::bigint);
END
$$;

SELECT set_config('factory.tenant_id', '', true);
SELECT dbtest.expect_eq('[RLS spike] with no tenant set the policy fails closed: zero rows', (SELECT count(*) FROM jobs), 0::bigint);

RESET ROLE;
SET LOCAL ROLE rls_spike_engine;
SELECT dbtest.expect_eq('[RLS spike] the engine role with BYPASSRLS (system scope) sees every tenant', (SELECT count(DISTINCT tenant_id) FROM jobs), 2::bigint);
RESET ROLE;

ROLLBACK;

SELECT dbtest.expect_eq('the spike left nothing behind: row-level security is off again',
  (SELECT count(*) FROM pg_class WHERE relnamespace = 'public'::regnamespace AND (relrowsecurity OR relforcerowsecurity)), 0::bigint);
SELECT dbtest.expect_eq('the spike left no role behind', (SELECT count(*) FROM pg_roles WHERE rolname = 'rls_spike_engine'), 0::bigint);
