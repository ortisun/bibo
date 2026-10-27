-- Suite: plans
-- Generates 10,000 rows in each of the large tables with a realistic mix (most work is finished, a few
-- percent is live), runs ANALYZE, and checks that the claim, sweep, timeline and ledger-tail queries use
-- index scans and never a sequential scan of the big table. Each plan is printed as a NOTICE that starts
-- with "plan |" so it can be recorded in docs/database/query-plans.md.
--
-- The mix of rows is what makes the partial indexes worth having: about 1.6% of stage runs are READY,
-- about 1.6% of attempts are live, and 1% of outbox rows are unpublished.

-- ---------------------------------------------------------------------------------------------
-- 1. Data. Five tenants, 2,000 jobs, 10,000 stage runs and attempts, 10,000 ledger entries (valid hash
-- chains), 10,000 outbox events, 10,000 audit events. Bulk status changes run with triggers off
-- (a superuser setting) because they stand for months of earlier work; the inserts that matter for
-- integrity (ledger, audit, outbox) go through every trigger and constraint.

SELECT dbtest.mk_tenant(t) FROM generate_series(1, 5) AS t;

INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id, created_at)
SELECT dbtest.u(1 + n % 5), dbtest.u(100000 + n), dbtest.u((1 + n % 5) * 1000 + 1), dbtest.u((1 + n % 5) * 1000 + 2),
       'production', 'L1', ARRAY['INTAKE'], dbtest.u(200000 + n), now() - make_interval(mins => 3000 - n)
  FROM generate_series(1, 2000) AS n;

INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number)
SELECT dbtest.u(1 + n % 5), dbtest.u(300000 + n * 5 + k), dbtest.u(100000 + n),
       (ARRAY['INTAKE', 'REPOSITORY_INTELLIGENCE', 'SPECIFICATION', 'ARCHITECTURE', 'TASK_PLANNING'])[k], 1
  FROM generate_series(1, 2000) AS n, generate_series(1, 5) AS k;

DO $$
BEGIN
  SET LOCAL session_replication_role = replica;

  -- Jobs: 90% completed, 8% active, 1% paused, 1% failed. Version 6, so five events each can follow.
  -- The job number n is the order of creation (created_at was set from n).
  UPDATE jobs SET version = 6,
         status = CASE WHEN x.n % 100 < 90 THEN 'COMPLETED' WHEN x.n % 100 < 98 THEN 'ACTIVE' WHEN x.n % 100 = 98 THEN 'PAUSED' ELSE 'FAILED' END,
         terminal_at = CASE WHEN x.n % 100 < 90 OR x.n % 100 = 99 THEN now() END
    FROM (SELECT tenant_id, id, row_number() OVER (ORDER BY created_at) AS n FROM jobs) x
   WHERE jobs.tenant_id = x.tenant_id AND jobs.id = x.id;

  -- Stage runs follow their job: finished jobs have finished runs; an active job has two passed runs,
  -- one READY run (the claimable one), one RUNNING run and one PENDING run; a paused job has one passed run.
  UPDATE stage_runs s SET
         status = x.new_status,
         gate_outcome = CASE WHEN x.new_status = 'PASSED' THEN 'PASSED' END,
         finished_at = CASE WHEN x.new_status = 'PASSED' THEN now() END,
         lease_epoch = CASE WHEN x.new_status = 'RUNNING' THEN 1 ELSE 0 END,
         not_before = now() - interval '1 minute',
         version = 2
    FROM (SELECT r.tenant_id, r.id,
                 CASE
                   WHEN j.status IN ('COMPLETED', 'FAILED') THEN 'PASSED'
                   WHEN j.status = 'ACTIVE' AND r.stage_kind IN ('INTAKE', 'REPOSITORY_INTELLIGENCE') THEN 'PASSED'
                   WHEN j.status = 'ACTIVE' AND r.stage_kind = 'SPECIFICATION' THEN 'READY'
                   WHEN j.status = 'ACTIVE' AND r.stage_kind = 'ARCHITECTURE' THEN 'RUNNING'
                   WHEN j.status = 'PAUSED' AND r.stage_kind = 'INTAKE' THEN 'PASSED'
                   ELSE 'PENDING' END AS new_status
            FROM stage_runs r JOIN jobs j ON j.tenant_id = r.tenant_id AND j.id = r.job_id) x
   WHERE s.tenant_id = x.tenant_id AND s.id = x.id;

  -- One attempt for every stage run that ever ran. Finished runs get a finished attempt. A RUNNING run
  -- gets a live one; every tenth of those has an expired lease and every twentieth a CANCELLING attempt.
  INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, status, lease_owner, lease_epoch, lease_expires_at, deadline_at,
                        teardown_deadline_at, created_at, ended_at)
  SELECT s.tenant_id, dbtest.u(500000 + row_number() OVER ()), s.job_id, s.id, 1,
         CASE WHEN s.status = 'PASSED' THEN 'CANCELLED' WHEN rn % 20 = 0 THEN 'CANCELLING' ELSE 'RUNNING' END,
         CASE WHEN s.status = 'PASSED' THEN NULL ELSE 'worker-' || (rn % 8) END,
         GREATEST(s.lease_epoch, 1),
         CASE WHEN s.status = 'PASSED' THEN NULL WHEN rn % 10 = 0 THEN now() - interval '5 minutes' ELSE now() + interval '30 seconds' END,
         CASE WHEN s.status = 'PASSED' THEN now() - interval '1 hour' WHEN rn % 7 = 0 THEN now() - interval '1 minute' ELSE now() + interval '1 hour' END,
         CASE WHEN s.status = 'RUNNING' AND rn % 20 = 0 THEN now() - interval '10 seconds' END,
         now() - interval '3 hours',
         CASE WHEN s.status = 'PASSED' THEN now() - interval '2 hours' END
    FROM (SELECT s.*, row_number() OVER (ORDER BY s.id) AS rn FROM stage_runs s WHERE s.status IN ('PASSED', 'RUNNING')) s;
END
$$;

-- Ledger: 100 jobs with 100 valid entries each, through every trigger.
DO $$
DECLARE
  j int;
  q int;
BEGIN
  FOR j IN 1..100 LOOP
    FOR q IN 1..100 LOOP
      PERFORM dbtest.append_entry(1 + j % 5, dbtest.u(100000 + j), dbtest.u(300000 + j * 5 + 1), q);
    END LOOP;
  END LOOP;
END
$$;

-- Outbox: five events per job, one per version 2 to 6, each naming the transition that emits it.
INSERT INTO outbox (tenant_id, event_id, event_type, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id, correlation_id, occurred_at, producer, payload)
SELECT j.tenant_id, gen_random_uuid(), v.event_type, j.id, 'job', j.id, v.version, v.transition, j.correlation_id, now(), 'workflow.engine', '{}'
  FROM jobs j
 CROSS JOIN (VALUES (2, 'job.admitted', 'J01'), (3, 'job.paused', 'J05'), (4, 'job.resumed', 'J06'), (5, 'job.paused', 'J05'), (6, 'job.resumed', 'J06')) AS v(version, event_type, transition);

DO $$
BEGIN
  SET LOCAL session_replication_role = replica;
  UPDATE outbox SET published_at = now(), publish_attempts = 1 WHERE seq % 100 <> 0;
END
$$;

-- Audit: 10,000 events across the five tenants, a fifth of them tied to a job.
INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id, job_id)
SELECT dbtest.u(1 + n % 5), dbtest.u(700000 + n), 'service', 'engine', 'gate.result', 'gate:' || n, 'record', 'The gate recorded its result.',
       dbtest.sha('policy'), dbtest.u(200000 + (n % 2000) + 1),
       -- job m belongs to tenant 1 + m % 5, so pick an m of the event's own tenant
       CASE WHEN n % 7 = 0 THEN dbtest.u(100000 + 5 * ((n / 5) % 399) + 5 + (n % 5)) END
  FROM generate_series(1, 10000) AS n;

-- Artifacts and links, tokens, so the lookups by hash have something to search.
INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend)
SELECT dbtest.u(1), dbtest.sha('artifact-' || n), 100 + n, 'text/plain', 'local-fs' FROM generate_series(1, 2000) AS n;
INSERT INTO stage_run_artifacts (tenant_id, job_id, stage_run_id, direction, role, content_sha256)
SELECT s.tenant_id, s.job_id, s.id, 'input', 'spec', dbtest.sha('artifact-' || (1 + (row_number() OVER (ORDER BY s.id)) % 2000))
  FROM stage_runs s WHERE s.tenant_id = dbtest.u(1) LIMIT 2000;
INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, expires_at)
SELECT dbtest.u(1), dbtest.u(800000 + n), dbtest.u(1002), sha256(convert_to('token-' || n, 'UTF8')), 'factory-api', now() + interval '1 day' FROM generate_series(1, 200) AS n;

ANALYZE;

-- The sizes the criterion asks for.
DO $$
BEGIN
  PERFORM dbtest.expect_true('stage_runs holds 10,000 generated rows', (SELECT count(*) FROM stage_runs) >= 10000);
  PERFORM dbtest.expect_true('attempts holds at least 9,000 generated rows (one for every run that ran)', (SELECT count(*) FROM attempts) >= 9000);
  PERFORM dbtest.expect_true('ledger_entries holds 10,000 generated rows', (SELECT count(*) FROM ledger_entries) >= 10000);
  PERFORM dbtest.expect_true('outbox holds 10,000 generated rows', (SELECT count(*) FROM outbox) >= 10000);
  PERFORM dbtest.expect_true('audit_events holds 10,000 generated rows', (SELECT count(*) FROM audit_events) >= 10000);
  PERFORM dbtest.expect_true('the generated audit chains verify', (SELECT bool_and(audit_verify_chain(dbtest.u(t)) IS NULL) FROM generate_series(1, 5) t));
  PERFORM dbtest.expect_true('the generated ledger chains are sound (the verifier only notes that no job head was set, which it reports as 0)',
    (SELECT bool_and(ledger_verify_chain(dbtest.u(1 + j % 5), dbtest.u(100000 + j)) = 0) FROM generate_series(1, 100) j));
  PERFORM dbtest.expect_eq('about 1.6 percent of stage runs are READY', (SELECT count(*) FROM stage_runs WHERE status = 'READY'), 160::bigint);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. Plans.

CREATE FUNCTION dbtest.explain(q text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  line text;
  out text := '';
BEGIN
  FOR line IN EXECUTE 'EXPLAIN (COSTS OFF) ' || q LOOP
    out := out || line || E'\n';
  END LOOP;
  RETURN out;
END
$$;

-- The query must use an index scan on the index named (a plain, backward, only or bitmap index scan)
-- and must not scan the named table sequentially.
CREATE FUNCTION dbtest.expect_plan(label text, q text, idx text, tbl text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  txt text := dbtest.explain(q);
BEGIN
  RAISE NOTICE E'plan | %\n%', label, txt;
  IF txt !~ ('(Index (Only )?Scan( Backward)? using ' || idx || '[ \n]|Bitmap Index Scan on ' || idx || '[ \n])') THEN
    PERFORM dbtest.fail(label, 'the plan does not use index ' || idx);
  END IF;
  IF txt ~ ('Seq Scan on ' || tbl || '[ \n]') THEN
    PERFORM dbtest.fail(label, 'the plan scans ' || tbl || ' sequentially');
  END IF;
  PERFORM dbtest.pass(label || ' uses ' || idx);
END
$$;

DO $$
DECLARE
  t text := dbtest.u(2)::text;
  jb text := dbtest.u(100000 + 7)::text;   -- a job of tenant 3 (1 + 7 % 5)
  tj text := dbtest.u(3)::text;
BEGIN
  -- Claim: READY runs of ACTIVE jobs, oldest first, locked without waiting.
  PERFORM dbtest.expect_plan('claim: READY stage runs whose back-off has passed, FOR NO KEY UPDATE SKIP LOCKED',
    $q$SELECT s.tenant_id, s.id FROM stage_runs s
         JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
        WHERE s.status = 'READY' AND s.not_before <= now()
        ORDER BY s.not_before LIMIT 10 FOR NO KEY UPDATE OF s SKIP LOCKED$q$,
    'stage_runs_claim_idx', 'stage_runs');

  -- Sweep: expired leases, passed deadlines, overdue teardowns.
  PERFORM dbtest.expect_plan('sweep: attempts whose lease expired',
    $q$SELECT tenant_id, id FROM attempts WHERE status IN ('STARTING', 'RUNNING') AND lease_expires_at < now()
        ORDER BY lease_expires_at LIMIT 100 FOR UPDATE SKIP LOCKED$q$,
    'attempts_lease_expiry_idx', 'attempts');
  PERFORM dbtest.expect_plan('sweep: attempts past their deadline',
    $q$SELECT tenant_id, id FROM attempts WHERE status IN ('STARTING', 'RUNNING') AND deadline_at < now()
        ORDER BY deadline_at LIMIT 100 FOR UPDATE SKIP LOCKED$q$,
    'attempts_deadline_idx', 'attempts');
  PERFORM dbtest.expect_plan('sweep: cancelling attempts past their teardown deadline',
    $q$SELECT tenant_id, id FROM attempts WHERE status = 'CANCELLING' AND teardown_deadline_at < now()
        ORDER BY teardown_deadline_at LIMIT 100 FOR UPDATE SKIP LOCKED$q$,
    'attempts_teardown_idx', 'attempts');

  -- Timeline of one job: events, ledger entries and stage runs, each by tenant and job.
  PERFORM dbtest.expect_plan('timeline: outbox events of one job in order',
    format($q$SELECT event_type, aggregate_version FROM outbox WHERE tenant_id = %L AND job_id = %L ORDER BY seq$q$, tj, jb),
    'outbox_job_timeline_idx', 'outbox');
  PERFORM dbtest.expect_plan('timeline: ledger entries of one job in order',
    format($q$SELECT sequence, claim_kind FROM ledger_entries WHERE tenant_id = %L AND job_id = dbtest.u(100000 + 7) ORDER BY sequence$q$, tj),
    'ledger_entries_pkey', 'ledger_entries');
  PERFORM dbtest.expect_plan('timeline: stage runs of one job',
    format($q$SELECT stage_kind, status FROM stage_runs WHERE tenant_id = %L AND job_id = %L ORDER BY stage_kind$q$, tj, jb),
    'stage_runs_tenant_id_job_id_stage_kind_run_number_key', 'stage_runs');
  PERFORM dbtest.expect_plan('timeline: audit events of one job',
    format($q$SELECT sequence, action FROM audit_events WHERE tenant_id = %L AND job_id = %L ORDER BY sequence$q$, tj, jb),
    'audit_events_job_idx', 'audit_events');

  -- Ledger tail: the head of one job's chain.
  PERFORM dbtest.expect_plan('ledger tail: the last entry of one job',
    format($q$SELECT sequence, entry_hash FROM ledger_entries WHERE tenant_id = %L AND job_id = %L ORDER BY sequence DESC LIMIT 1$q$, tj, dbtest.u(100000 + 7)::text),
    'ledger_entries_pkey', 'ledger_entries');
  PERFORM dbtest.expect_plan('ledger tail: the audit chain head of one tenant',
    format($q$SELECT sequence, hash FROM audit_events WHERE tenant_id = %L ORDER BY sequence DESC LIMIT 1$q$, tj),
    'audit_events_pkey', 'audit_events');

  -- Other hot paths named in the design.
  PERFORM dbtest.expect_plan('relay: unpublished outbox rows in order, FOR UPDATE SKIP LOCKED',
    $q$SELECT seq, event_id FROM outbox WHERE published_at IS NULL ORDER BY seq LIMIT 100 FOR UPDATE SKIP LOCKED$q$,
    'outbox_unpublished_idx', 'outbox');
  PERFORM dbtest.expect_plan('authentication: a token by its hash',
    $q$SELECT tenant_id, principal_id FROM active_api_tokens WHERE token_hash = sha256(convert_to('token-17', 'UTF8')) AND audience = 'factory-api'$q$,
    'api_tokens_token_hash_key', 'api_tokens');
  PERFORM dbtest.expect_plan('invalidation: stage runs that consumed one artifact hash',
    format($q$SELECT stage_run_id FROM stage_run_artifacts WHERE tenant_id = %L AND content_sha256 = %L AND direction = 'input'$q$, dbtest.u(1)::text, dbtest.sha('artifact-17')),
    'stage_run_artifacts_hash_idx', 'stage_run_artifacts');
  PERFORM dbtest.expect_plan('lookup: one job by (tenant, id)',
    format($q$SELECT status FROM jobs WHERE tenant_id = %L AND id = %L$q$, tj, jb), 'jobs_(pkey|tenant_id_id_execution_mode_key)', 'jobs');
END
$$;

-- With only 2,000 jobs the planner joins the claim candidates to jobs with a hash join over a sequential
-- scan of jobs. That is the right choice at this size. This forced variant shows the key lookup on jobs
-- that the planner will use once jobs is large and the 160 candidates are the cheap side of the join.
DO $$
BEGIN
  SET LOCAL enable_hashjoin = off;
  SET LOCAL enable_mergejoin = off;
  PERFORM dbtest.expect_plan('claim, with hash and merge joins disabled: the join to jobs is a key lookup',
    $q$SELECT s.tenant_id, s.id FROM stage_runs s
         JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
        WHERE s.status = 'READY' AND s.not_before <= now()
        ORDER BY s.not_before LIMIT 10 FOR NO KEY UPDATE OF s SKIP LOCKED$q$,
    'jobs_(open_idx|pkey|tenant_id_id_execution_mode_key)', 'jobs');
END
$$;

-- A lookup that forgot the tenant still runs fast: PostgreSQL 18 can skip-scan the composite key. So a
-- missing tenant predicate is a correctness hazard that no slow query would ever reveal. That is why the
-- storage layer takes a TenantScope on every call (ADR 0007) and why the tests above do not rely on
-- performance to notice it.
DO $$
DECLARE
  txt text := dbtest.explain(format($q$SELECT status FROM jobs WHERE id = %L$q$, dbtest.u(100000 + 7)::text));
BEGIN
  RAISE NOTICE E'plan | for contrast: a job looked up by id alone (no tenant) is still an index scan, so nothing would look wrong\n%', txt;
  PERFORM dbtest.pass('recorded the plan of a lookup that forgot the tenant, for contrast');
END
$$;
