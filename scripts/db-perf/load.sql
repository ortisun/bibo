-- scripts/db-perf/load.sql - deterministic synthetic data for the database performance harness.
--
-- Run by scripts/db-perf.sh as the superuser, on a database that holds the migrated schema and nothing else:
--
--   psql -v ON_ERROR_STOP=1 -v rows=100000 -v njobs=10000 -f scripts/db-perf/load.sql
--
-- Nothing here is random. Every identifier, hash, size and time offset is a function of a counter, so two runs make
-- the same rows (the leases and not_before times are relative to now(), as they have to be). There is no network.
--
-- The shape (see docs/database/performance.md for why):
--   * 50 tenants with a skewed size: one tenant holds 55 percent of the jobs, four hold 5 percent each, 45 hold about
--     0.55 percent each. The same row counts in every table follow the jobs.
--   * Each job has 10 stage runs. 90 percent of the jobs are COMPLETED, 8 percent ACTIVE (one READY run, one RUNNING
--     run with a live attempt), 1 percent PAUSED (a READY run of a job that must not be claimed), 1 percent FAILED.
--   * stage_runs, attempts, ledger_entries, outbox, audit_events and artifacts each hold at least :rows rows.
--   * Every ledger chain and every audit chain is written through the real triggers, so the hashes verify.
--   * Payloads have realistic sizes: about 1.2 KB of canonical JSON per ledger entry, about 350 bytes of JSON per
--     outbox event, a sentence of reason per audit event.
-- The bulk inserts of jobs, runs, attempts and outbox rows run with triggers off (session_replication_role = replica),
-- as the plans suite does, because they stand for months of earlier work. The ledger and the audit log do not.

\set ON_ERROR_STOP on
SET synchronous_commit = off;

CREATE SCHEMA perf;

-- ---------------------------------------------------------------------------------------------
-- 1. Pure helpers.

-- A non-negative 60-bit number from a text. Stable across runs and across PostgreSQL versions (md5).
CREATE FUNCTION perf.hx(s text) RETURNS bigint LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT ('x' || substr(md5(s), 1, 15))::bit(60)::bigint
$$;

-- A time ordered identifier, shaped like the version 7 identifiers the application makes: the first 48 bits are the
-- counter, so rows created later have larger keys, and the rest comes from a hash.
CREATE FUNCTION perf.uid(kind text, n bigint) RETURNS uuid LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT (lpad(to_hex(n), 12, '0') || '7' || substr(md5(kind || ':' || n), 1, 3) || '8' || substr(md5(kind || ':' || n), 4, 15))::uuid
$$;

CREATE FUNCTION perf.sha(kind text, n bigint) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT 'sha256:' || encode(sha256(convert_to(kind || ':' || n, 'UTF8')), 'hex')
$$;

-- The first ten stage kinds of the pipeline. A job in this data runs these.
CREATE FUNCTION perf.kind_of(k int) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT (ARRAY['INTAKE', 'REPOSITORY_INTELLIGENCE', 'SPECIFICATION', 'DOMAIN_DISCOVERY', 'ARCHITECTURE', 'TASK_PLANNING',
                'IMPLEMENTATION', 'VALIDATION', 'REVIEW', 'DOCUMENTING'])[k]
$$;

-- The class of a job number: C completed, A active, P paused, F failed (the same split as the plans suite).
CREATE FUNCTION perf.class_of(n int) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE WHEN n % 100 < 90 THEN 'C' WHEN n % 100 < 98 THEN 'A' WHEN n % 100 = 98 THEN 'P' ELSE 'F' END
$$;

-- The status a stage run k of a job of class c has, and whether it ever had an attempt.
CREATE FUNCTION perf.run_status(c text, k int) RETURNS text LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE c
    WHEN 'C' THEN 'PASSED'
    WHEN 'A' THEN CASE WHEN k <= 5 THEN 'PASSED' WHEN k = 6 THEN 'READY' WHEN k = 7 THEN 'RUNNING' ELSE 'PENDING' END
    WHEN 'P' THEN CASE WHEN k <= 3 THEN 'PASSED' WHEN k = 4 THEN 'READY' ELSE 'PENDING' END
    ELSE CASE WHEN k <= 5 THEN 'PASSED' WHEN k = 6 THEN 'FAILED' ELSE 'CANCELLED' END
  END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. The plan: tenants and jobs. These two tables are the key the measurement script reads; they are not product
-- tables and the logins have no access to them.

CREATE TABLE perf.tenant_plan (
  idx   int PRIMARY KEY,
  id    uuid NOT NULL,
  start int NOT NULL,        -- the first value of a hash in 0..9999 that falls to this tenant
  jobs  int NOT NULL DEFAULT 0,
  repos int NOT NULL DEFAULT 0
);
INSERT INTO perf.tenant_plan (idx, id, start)
SELECT idx, perf.uid('tenant', idx),
       CASE WHEN idx = 1 THEN 0
            WHEN idx <= 5 THEN 5500 + 500 * (idx - 2)
            ELSE 7500 + ((idx - 6) * 2500) / 45 END
  FROM generate_series(1, 50) AS idx;

CREATE TABLE perf.job_plan AS
SELECT n::int AS n,
       (SELECT max(t.idx) FROM perf.tenant_plan t WHERE t.start <= perf.hx('t' || n) % 10000)::int AS tenant_idx,
       perf.class_of(n::int) AS class,
       -- ledger entries of the job: 6 to 14, and 200 for every five hundredth job (a long, much reworked job)
       CASE WHEN n % 500 = 0 THEN 200 ELSE 6 + (perf.hx('l' || n) % 9)::int END AS ledger_entries
  FROM generate_series(1, :njobs) AS n;
ALTER TABLE perf.job_plan ADD PRIMARY KEY (n);
UPDATE perf.tenant_plan t SET jobs = (SELECT count(*) FROM perf.job_plan j WHERE j.tenant_idx = t.idx);
UPDATE perf.tenant_plan SET repos = greatest(2, round(jobs / 5.0)::int);
ALTER TABLE perf.job_plan ADD COLUMN tenant_id uuid, ADD COLUMN job_id uuid;
UPDATE perf.job_plan j SET tenant_id = t.id, job_id = perf.uid('job', j.n) FROM perf.tenant_plan t WHERE t.idx = j.tenant_idx;

-- ---------------------------------------------------------------------------------------------
-- 3. Tenants, principals, repositories.

INSERT INTO tenants (id, slug, display_name)
SELECT id, 'perf-t' || lpad(idx::text, 2, '0'), 'Perf tenant ' || idx FROM perf.tenant_plan;

INSERT INTO principals (tenant_id, id, kind, github_user_id, login)
SELECT id, perf.uid('pri', idx * 10 + 1), 'human', 700000 + idx, 'person' || idx FROM perf.tenant_plan;
INSERT INTO principals (tenant_id, id, kind)
SELECT id, perf.uid('pri', idx * 10 + 2), 'service' FROM perf.tenant_plan;

-- Enabled, with a project map attested by the first person of the tenant. The table refuses an enabled repository
-- without a map (migration 2026-11-02-002400), and the hot query of the webhook binding looks for enabled ones.
INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch,
                          enabled, project_map_commit, project_map_attested_by_principal_id)
SELECT t.id, perf.uid('repo', t.idx * 1000000 + k), 9000 + t.idx, 100000 + t.idx * 100000 + k,
       'org' || t.idx || '/repo-' || k, 'main',
       true, repeat('a', 40), perf.uid('pri', t.idx * 10 + 1)
  FROM perf.tenant_plan t, LATERAL generate_series(1, t.repos) AS k;

-- ---------------------------------------------------------------------------------------------
-- 4. Jobs, stage runs, attempts, artifacts, links, outbox. Final values go in directly, so the heap holds no dead
-- versions from a second pass.

SET session_replication_role = replica;

INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, status, version, execution_mode, autonomy_level,
                  pipeline_scope, correlation_id, idempotency_key, created_at, updated_at, terminal_at)
SELECT j.tenant_id, j.job_id, perf.uid('repo', j.tenant_idx * 1000000 + 1 + (j.n % t.repos)), perf.uid('pri', j.tenant_idx * 10 + 1),
       CASE j.class WHEN 'C' THEN 'COMPLETED' WHEN 'A' THEN 'ACTIVE' WHEN 'P' THEN 'PAUSED' ELSE 'FAILED' END,
       CASE WHEN j.class = 'C' THEN 3 ELSE 2 END,
       'production', 'L1',
       ARRAY['INTAKE', 'REPOSITORY_INTELLIGENCE', 'SPECIFICATION', 'DOMAIN_DISCOVERY', 'ARCHITECTURE', 'TASK_PLANNING',
             'IMPLEMENTATION', 'VALIDATION', 'REVIEW', 'DOCUMENTING'],
       perf.uid('corr', j.n), 'idem-' || j.n,
       timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes',
       timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + interval '3 hours',
       CASE WHEN j.class IN ('C', 'F') THEN timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + interval '3 hours' END
  FROM perf.job_plan j JOIN perf.tenant_plan t ON t.idx = j.tenant_idx
 ORDER BY j.n;

-- run_key = n * 100 + k. Run 1 and 2 reach version 5 (four events), run 3 version 2 (one event), the others stay at 1 or 2.
INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number, status, version, lease_epoch, not_before, gate_outcome,
                        created_at, updated_at, finished_at)
SELECT j.tenant_id, perf.uid('run', j.n * 100 + k), j.job_id, perf.kind_of(k), 1, perf.run_status(j.class, k),
       CASE WHEN k <= 2 THEN 5 WHEN k = 3 THEN 2 ELSE 1 END,
       CASE WHEN perf.run_status(j.class, k) IN ('PASSED', 'FAILED', 'RUNNING') THEN 1 ELSE 0 END,
       CASE WHEN perf.run_status(j.class, k) = 'READY' THEN now() - interval '2 days' + j.n * interval '10 seconds'
            ELSE timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute' END,
       CASE perf.run_status(j.class, k) WHEN 'PASSED' THEN 'PASSED' WHEN 'FAILED' THEN 'FAILED' END,
       timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute',
       timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute' + interval '5 minutes',
       CASE WHEN perf.run_status(j.class, k) IN ('PASSED', 'FAILED', 'CANCELLED')
            THEN timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute' + interval '5 minutes' END
  FROM perf.job_plan j, generate_series(1, 10) AS k
 ORDER BY j.n, k;

-- Artifacts: one output per run that succeeded, and one specification document per job. About 105,000 rows.
INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend, created_by_job_id, created_by_stage_run_id, created_at)
SELECT j.tenant_id, perf.sha('out', j.n * 100 + k), 2000 + perf.hx('a' || (j.n * 100 + k)) % 200000, 'application/json', 'local-fs',
       j.job_id, perf.uid('run', j.n * 100 + k), timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute'
  FROM perf.job_plan j, generate_series(1, 10) AS k
 WHERE perf.run_status(j.class, k) = 'PASSED'
 ORDER BY j.n, k;
INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend, created_by_job_id, created_by_stage_run_id, created_at)
SELECT j.tenant_id, perf.sha('spec', j.n), 4000 + perf.hx('s' || j.n) % 50000, 'text/markdown', 'local-fs', j.job_id, perf.uid('run', j.n * 100 + 3),
       timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + interval '3 minutes'
  FROM perf.job_plan j
 ORDER BY j.n;

-- Attempts. Attempt number 1 of a succeeded run failed for 6 percent of the runs, so those runs have two attempts.
-- A RUNNING run has a live attempt; every tenth of those holds a lease that expired five minutes ago.
INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, status, version, lease_owner, lease_epoch, lease_expires_at,
                      last_heartbeat_at, deadline_at, failure_class, output_sha256, created_at, updated_at, ended_at)
SELECT j.tenant_id, perf.uid('att', (j.n * 100 + k) * 10 + a), j.job_id, perf.uid('run', j.n * 100 + k), a,
       CASE WHEN perf.run_status(j.class, k) = 'RUNNING' THEN 'RUNNING'
            WHEN perf.run_status(j.class, k) = 'FAILED' THEN 'FAILED'
            WHEN a = 1 AND retried THEN 'FAILED'
            ELSE 'SUCCEEDED' END,
       2,
       CASE WHEN perf.run_status(j.class, k) = 'RUNNING' THEN 'worker-' || (j.n % 8) END,
       1,
       CASE WHEN perf.run_status(j.class, k) = 'RUNNING'
            THEN CASE WHEN j.n % 10 = 0 THEN now() - interval '5 minutes' ELSE now() + interval '30 seconds' END END,
       CASE WHEN perf.run_status(j.class, k) = 'RUNNING' THEN now() - interval '10 seconds' END,
       CASE WHEN perf.run_status(j.class, k) = 'RUNNING'
            THEN CASE WHEN j.n % 7 = 0 THEN now() - interval '1 minute' ELSE now() + interval '1 hour' END
            ELSE timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute' + interval '1 hour' END,
       CASE WHEN perf.run_status(j.class, k) = 'FAILED' OR (a = 1 AND retried) THEN 'TOOL_ERROR' END,
       CASE WHEN perf.run_status(j.class, k) = 'PASSED' AND NOT (a = 1 AND retried) THEN perf.sha('out', j.n * 100 + k) END,
       timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute',
       timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute' + interval '3 minutes',
       CASE WHEN perf.run_status(j.class, k) <> 'RUNNING'
            THEN timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute' + interval '3 minutes' END
  FROM perf.job_plan j, generate_series(1, 10) AS k,
       LATERAL (SELECT perf.run_status(j.class, k) = 'PASSED' AND perf.hx('r' || (j.n * 100 + k)) % 100 < 6 AS retried) r,
       LATERAL generate_series(1, CASE WHEN perf.run_status(j.class, k) IN ('PENDING', 'READY', 'CANCELLED') THEN 0 WHEN r.retried THEN 2 ELSE 1 END) AS a
 ORDER BY j.n, k, a;

-- Links between runs and artifacts: the output of each run that has one, and the previous run's output as the input.
INSERT INTO stage_run_artifacts (tenant_id, job_id, stage_run_id, direction, role, content_sha256, created_at)
SELECT j.tenant_id, j.job_id, perf.uid('run', j.n * 100 + k), 'output', 'result', perf.sha('out', j.n * 100 + k),
       timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute'
  FROM perf.job_plan j, generate_series(1, 10) AS k
 WHERE perf.run_status(j.class, k) = 'PASSED'
 ORDER BY j.n, k;
INSERT INTO stage_run_artifacts (tenant_id, job_id, stage_run_id, direction, role, content_sha256, created_at)
SELECT j.tenant_id, j.job_id, perf.uid('run', j.n * 100 + k), 'input', 'previous', perf.sha('out', j.n * 100 + k - 1),
       timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + k * interval '1 minute'
  FROM perf.job_plan j, generate_series(2, 10) AS k
 WHERE perf.run_status(j.class, k - 1) = 'PASSED' AND perf.run_status(j.class, k) IN ('PASSED', 'RUNNING', 'FAILED')
 ORDER BY j.n, k;

-- The outbox. Per job: job.admitted; for stage runs 1 and 2 the four events ready, started, gating, passed; for stage run 3
-- stage_run.ready; and job.completed for a completed job. 99 percent are published (every hundredth is not).
INSERT INTO outbox (tenant_id, event_id, event_type, event_version, job_id, aggregate_type, aggregate_id, aggregate_version,
                    transition_id, correlation_id, occurred_at, producer, traceparent, payload, payload_schema_name, payload_schema_version,
                    created_at, published_at, publish_attempts)
SELECT e.tenant_id, perf.uid('evt', e.ord), e.event_type, 1, e.job_id, e.agg, e.agg_id, e.ver, e.tr,
       perf.uid('corr', e.n), e.at, 'workflow.engine',
       '00-' || substr(md5('tp' || e.ord), 1, 32) || '-' || substr(md5('sp' || e.ord), 1, 16) || '-01',
       jsonb_build_object('stage', e.stage, 'summary', 'The ' || e.event_type || ' event of job ' || e.n || '.',
                          'notes', repeat('Recorded by the engine. ', 8), 'refs', jsonb_build_array(perf.sha('out', e.n * 100 + 1), perf.sha('out', e.n * 100 + 2))),
       'event.payload', 1, e.at, CASE WHEN e.ord % 100 <> 0 THEN e.at + interval '2 seconds' END, CASE WHEN e.ord % 100 <> 0 THEN 1 ELSE 0 END
  FROM (
    SELECT row_number() OVER (ORDER BY j.n, s.ord) AS ord, j.n, j.tenant_id, j.job_id, s.event_type, s.agg, s.agg_id, s.ver, s.tr, s.stage,
           timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + s.ord * interval '10 seconds' AS at
      FROM perf.job_plan j,
      LATERAL (
        SELECT 0 AS ord, 'job.admitted' AS event_type, 'job' AS agg, j.job_id AS agg_id, 2 AS ver, 'J01' AS tr, 'job' AS stage
        UNION ALL SELECT 1 + (k - 1) * 4 + q, 'stage_run.' || (ARRAY['ready', 'started', 'gating', 'passed'])[q], 'stage_run',
                         perf.uid('run', j.n * 100 + k), 1 + q, (ARRAY['S01', 'S03', 'S04', 'S08'])[q], perf.kind_of(k)
                    FROM generate_series(1, 2) k, generate_series(1, 4) q
        UNION ALL SELECT 9, 'stage_run.ready', 'stage_run', perf.uid('run', j.n * 100 + 3), 2, 'S01', perf.kind_of(3)
        UNION ALL SELECT 10, 'job.completed', 'job', j.job_id, 3, 'J13', 'job' WHERE j.class = 'C'
      ) s
  ) e
 ORDER BY e.ord;

SET session_replication_role = origin;

-- ---------------------------------------------------------------------------------------------
-- 5. The evidence ledger, through the real triggers: one chain per job. The document is the one the application writes (about
-- 1.2 KB), the hash is SHA-256 over the previous hash, a newline and the document, and the trigger checks both.

CREATE FUNCTION perf.ledger_doc(p_job uuid, p_run uuid, p_att uuid, p_seq bigint, p_prev text, p_entry uuid, p_at timestamptz, p_n bigint) RETURNS text
LANGUAGE sql AS $$
  SELECT (jsonb_strip_nulls(jsonb_build_object(
    'schema_version', 1,
    'metadata', jsonb_build_object(
      'entry_id', p_entry, 'job_id', p_job, 'stage_run_id', p_run, 'attempt_id', p_att, 'sequence', p_seq,
      'recorded_at', to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), 'execution_mode', 'production',
      'recorded_by', jsonb_build_object('component', 'workflow.gate-evaluator', 'fidelity', 'real')),
    'claim', jsonb_build_object(
      'statement', 'The gate for this stage passed on the job branch: the build, the tests and the lint check all returned zero, and '
                   || 'the report hash matches the stored report. ' || repeat('The evidence is attached. ', 4),
      'kind', 'measured_fact', 'assurance_level', 'VERIFIED_IN_SANDBOX'),
    'evidence', jsonb_build_array(
      jsonb_build_object('kind', 'artifact', 'sha256', perf.sha('out', p_n), 'media_type', 'application/json', 'size_bytes', 4096),
      jsonb_build_object('kind', 'artifact', 'sha256', perf.sha('out', p_n + 1), 'media_type', 'application/json', 'size_bytes', 8192),
      jsonb_build_object('kind', 'command', 'argv', jsonb_build_array('cargo', 'nextest', 'run', '--workspace'), 'exit_code', 0)),
    'confidence', jsonb_build_object('level', 'high', 'rationale', 'The gate report hash matches the stored report and the sandbox was real.'),
    'invalidates', '[]'::jsonb
  )) || jsonb_build_object('prev_entry_hash', p_prev))::text
$$;

DO $$
DECLARE
  j record;
  q int;
  k int;
  prev text;
  doc text;
  h text;
  entry uuid;
  at timestamptz;
  run uuid;
  att uuid;
  status text;
BEGIN
  FOR j IN SELECT * FROM perf.job_plan ORDER BY n LOOP
    prev := NULL;
    FOR q IN 1..j.ledger_entries LOOP
      k := 1 + (q - 1) % 10;
      status := perf.run_status(j.class, k);
      run := perf.uid('run', j.n::bigint * 100 + k);
      att := CASE WHEN status IN ('PASSED', 'FAILED', 'RUNNING') THEN perf.uid('att', (j.n::bigint * 100 + k) * 10 + 1) END;
      entry := perf.uid('led', j.n::bigint * 1000 + q);
      at := timestamptz '2026-06-01 00:00:00+00' + j.n * interval '14 minutes' + q * interval '30 seconds';
      doc := perf.ledger_doc(j.job_id, run, att, q, prev, entry, at, j.n::bigint * 100 + k);
      h := 'sha256:' || encode(sha256(convert_to(coalesce(prev, '') || E'\n' || doc, 'UTF8')), 'hex');
      INSERT INTO ledger_entries (tenant_id, job_id, sequence, entry_id, stage_run_id, attempt_id, recorded_at, execution_mode, recorded_component,
                                  recorded_fidelity, claim_kind, assurance_level, confidence_level, invalidates, prev_entry_hash, entry_hash, canonical_json)
      VALUES (j.tenant_id, j.job_id, q, entry, run, att, at, 'production', 'workflow.gate-evaluator', 'real', 'measured_fact', 'VERIFIED_IN_SANDBOX',
              'high', '{}', prev, h, doc);
      prev := h;
    END LOOP;
    -- The head of the chain on the job row, as the store keeps it. The deferred foreign key checks it at commit.
    SET LOCAL session_replication_role = replica;
    UPDATE jobs SET ledger_head_sequence = j.ledger_entries, ledger_head_hash = prev WHERE tenant_id = j.tenant_id AND id = j.job_id;
    SET LOCAL session_replication_role = origin;
  END LOOP;
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 6. The audit log, through the trigger that assigns the sequence and the hash. Ten events per job, in job order, so the
-- tenants' chains grow interleaved, as they would. Eight of the ten name the job.

INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, job_id, correlation_id)
SELECT j.tenant_id, perf.uid('aud', j.n::bigint * 100 + e), 'service', 'engine',
       (ARRAY['gate.result', 'job.admitted', 'stage.started', 'stage.finished', 'approval.recorded'])[1 + e % 5],
       'job:' || j.n || ':event:' || e, (ARRAY['record', 'allow', 'record', 'record', 'allow'])[1 + e % 5],
       'The engine recorded the decision for stage ' || e || ' of the job after the gate result was stored.',
       perf.sha('policy', 1), CASE WHEN e <= 8 THEN j.job_id END, perf.uid('corr', j.n)
  FROM perf.job_plan j, generate_series(1, 10) AS e
 ORDER BY j.n, e;

-- ---------------------------------------------------------------------------------------------
-- 7. Tokens, so the authentication lookup has something to search. One service token per tenant and a few per large tenant.

INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, expires_at)
SELECT t.id, perf.uid('tok', t.idx * 100 + k), perf.uid('pri', t.idx * 10 + 2), sha256(convert_to('perf-token-' || t.idx || '-' || k, 'UTF8')),
       'factory-api', now() + interval '30 days'
  FROM perf.tenant_plan t, generate_series(1, CASE WHEN t.idx <= 5 THEN 40 ELSE 2 END) AS k;

-- ---------------------------------------------------------------------------------------------
-- 8. Statistics and visibility maps, as a database that has been running for a while would have them.

RESET synchronous_commit;
VACUUM (ANALYZE);
CHECKPOINT;
