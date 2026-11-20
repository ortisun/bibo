-- scripts/db-perf/partition_prototype.sql - small, throwaway prototypes behind docs/database/retention-and-partitioning.md.
--
-- Run by `scripts/db-perf.sh --prototype partitions` on the scratch cluster, on a database that holds the migrated schema and the
-- synthetic data of load.sql, as the superuser (it switches to the real roles with SET ROLE where a role matters). It changes
-- nothing outside that scratch database. Every claim in the proposal that rests on a test is a line here that starts with
-- "proto |"; the line says what was tried and what PostgreSQL answered. Nothing here is a migration, and nothing here is run by CI.
--
-- What it tries:
--   A. the ledger, partitioned by RANGE (job_id) (job ids are time ordered, a chain never leaves its partition);
--   B. the audit log, partitioned by RANGE (created_at) (refused) and by HASH (tenant_id);
--   C. the outbox, partitioned by RANGE (created_at) (refused), and the alternative: a maintenance role that deletes published rows;
--   D. the artifact metadata, partitioned by HASH (tenant_id).

\set ON_ERROR_STOP on
\pset pager off
SET client_min_messages = notice;

CREATE FUNCTION perf.note(label text, result text) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  RAISE NOTICE 'proto | % | %', label, result;
END
$$;

-- The uuid that starts job number n, and with it a range boundary. The first 48 bits of perf.uid are the counter.
CREATE FUNCTION perf.job_bound(n bigint) RETURNS uuid LANGUAGE sql IMMUTABLE AS $$
  SELECT (substr(lpad(to_hex(n), 12, '0'), 1, 8) || '-' || substr(lpad(to_hex(n), 12, '0'), 9, 4) || '-0000-0000-000000000000')::uuid
$$;

-- Run a statement as a role and tenant, and say how many rows it saw or what failed.
CREATE FUNCTION perf.try_as(p_role text, p_tenant uuid, stmt text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
BEGIN
  EXECUTE format('SET LOCAL ROLE %I', p_role);
  PERFORM set_config('factory.tenant_id', coalesce(p_tenant::text, ''), true);
  BEGIN
    EXECUTE 'SELECT count(*) FROM (' || stmt || ') x' INTO n;
    RESET ROLE;
    RETURN 'rows=' || n;
  EXCEPTION WHEN others THEN
    RESET ROLE;
    RETURN 'error: ' || SQLERRM;
  END;
END
$$;

-- The same for a statement that writes: says how many rows it changed or what failed.
CREATE FUNCTION perf.try_dml_as(p_role text, p_tenant uuid, stmt text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
BEGIN
  EXECUTE format('SET LOCAL ROLE %I', p_role);
  PERFORM set_config('factory.tenant_id', coalesce(p_tenant::text, ''), true);
  BEGIN
    EXECUTE stmt;
    GET DIAGNOSTICS n = ROW_COUNT;
    RESET ROLE;
    RETURN 'rows=' || n;
  EXCEPTION WHEN others THEN
    RESET ROLE;
    RETURN 'error: ' || SQLERRM;
  END;
END
$$;

-- ---------------------------------------------------------------------------------------------
-- A. The ledger, partitioned by RANGE (job_id)

CREATE TABLE proto_ledger (LIKE ledger_entries INCLUDING DEFAULTS) PARTITION BY RANGE (job_id);

DO $$
BEGIN
  BEGIN
    ALTER TABLE proto_ledger ADD CONSTRAINT proto_ledger_entry_uk UNIQUE (tenant_id, entry_id);
    PERFORM perf.note('A1 UNIQUE (tenant_id, entry_id) on a ledger partitioned by job_id', 'accepted');
  EXCEPTION WHEN others THEN
    PERFORM perf.note('A1 UNIQUE (tenant_id, entry_id) on a ledger partitioned by job_id', 'refused: ' || SQLERRM);
  END;
  BEGIN
    ALTER TABLE proto_ledger ADD CONSTRAINT proto_ledger_pk PRIMARY KEY (tenant_id, job_id, sequence);
    PERFORM perf.note('A2 PRIMARY KEY (tenant_id, job_id, sequence)', 'accepted: the key already holds the partition key');
  END;
END
$$;
ALTER TABLE proto_ledger ADD CONSTRAINT proto_ledger_entry_uk UNIQUE (tenant_id, job_id, entry_id);
ALTER TABLE proto_ledger ADD CONSTRAINT proto_ledger_hash_uk UNIQUE (tenant_id, job_id, sequence, entry_hash);

-- Four ranges of jobs, and a default for the future.
DO $$
DECLARE
  nj bigint := (SELECT count(*) FROM perf.job_plan);
  q bigint := (SELECT count(*) FROM perf.job_plan) / 4;
  i int;
BEGIN
  FOR i IN 0..3 LOOP
    EXECUTE format('CREATE TABLE proto_ledger_p%s PARTITION OF proto_ledger FOR VALUES FROM (%L) TO (%L)',
                   i, perf.job_bound(1 + i * q), perf.job_bound(CASE WHEN i = 3 THEN nj + 1 ELSE 1 + (i + 1) * q END));
  END LOOP;
  CREATE TABLE proto_ledger_default PARTITION OF proto_ledger DEFAULT;
END
$$;

-- The rows, copied before the triggers exist (the guard was run when they were first written).
INSERT INTO proto_ledger SELECT * FROM ledger_entries;
CREATE TRIGGER ledger_entries_guard BEFORE INSERT ON proto_ledger FOR EACH ROW EXECUTE FUNCTION ledger_entries_guard();
CREATE TRIGGER ledger_entries_no_change BEFORE UPDATE OR DELETE ON proto_ledger FOR EACH ROW EXECUTE FUNCTION reject_modification();
ALTER TABLE proto_ledger ADD FOREIGN KEY (tenant_id, job_id, execution_mode) REFERENCES jobs (tenant_id, id, execution_mode);
ALTER TABLE proto_ledger ADD FOREIGN KEY (tenant_id, job_id, stage_run_id) REFERENCES stage_runs (tenant_id, job_id, id);
ALTER TABLE proto_ledger ADD FOREIGN KEY (tenant_id, job_id, prev_sequence, prev_entry_hash) REFERENCES proto_ledger (tenant_id, job_id, sequence, entry_hash);
SELECT perf.note('A3 the self-referencing foreign key (the link to the predecessor) on the partitioned ledger', 'accepted');
ALTER TABLE jobs ADD CONSTRAINT proto_jobs_head_fk FOREIGN KEY (tenant_id, id, ledger_head_sequence, ledger_head_hash)
  REFERENCES proto_ledger (tenant_id, job_id, sequence, entry_hash) DEFERRABLE INITIALLY DEFERRED;
SELECT perf.note('A4 the job head foreign key, from jobs to the partitioned ledger', 'accepted');
ANALYZE proto_ledger;

-- Row-level security on the parent, as migration 12 does it, and the grants of migration 9.
ALTER TABLE proto_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE proto_ledger FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON proto_ledger TO factory_app
  USING (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT ON proto_ledger TO factory_app;

DO $$
DECLARE
  t1 uuid := (SELECT id FROM perf.tenant_plan WHERE idx = 1);
  t2 uuid := (SELECT id FROM perf.tenant_plan WHERE idx = 2);
  j1 uuid := (SELECT job_id FROM perf.job_plan WHERE tenant_idx = 1 ORDER BY n LIMIT 1);
  total bigint := (SELECT count(*) FROM proto_ledger);
  mine bigint := (SELECT count(*) FROM proto_ledger WHERE tenant_id = t1);
BEGIN
  PERFORM perf.note('A5 rows copied into the partitioned ledger', total || ' (the table it copies holds ' || (SELECT count(*) FROM ledger_entries) || ')');
  PERFORM perf.note('A6 the application role through the parent, tenant 1 sees only its rows', perf.try_as('factory_app', t1, 'SELECT 1 FROM proto_ledger') || ' of expected rows=' || mine);
  PERFORM perf.note('A7 the application role through the parent, tenant 2 asking for tenant 1''s job', perf.try_as('factory_app', t2, format('SELECT 1 FROM proto_ledger WHERE tenant_id = %L AND job_id = %L', t1, j1)));
  PERFORM perf.note('A8 no tenant setting', perf.try_as('factory_app', NULL, 'SELECT 1 FROM proto_ledger'));
  PERFORM perf.note('A9 the application role may not touch a partition it was not granted', perf.try_as('factory_app', t1, 'SELECT 1 FROM proto_ledger_p0'));
END
$$;

-- A grant on the partition, the way a later "GRANT ... ON ALL TABLES" would add one, bypasses the policy of the parent.
GRANT SELECT ON proto_ledger_p0 TO factory_app;
DO $$
DECLARE
  t2 uuid := (SELECT id FROM perf.tenant_plan WHERE idx = 2);
BEGIN
  PERFORM perf.note('A10 SELECT granted on a partition, rows of OTHER tenants visible through it (tenant 2 session, partition without its own policy)',
                    perf.try_as('factory_app', t2, 'SELECT 1 FROM proto_ledger_p0 WHERE tenant_id <> ''' || t2 || ''''));
END
$$;
ALTER TABLE proto_ledger_p0 ENABLE ROW LEVEL SECURITY;
ALTER TABLE proto_ledger_p0 FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON proto_ledger_p0 TO factory_app
  USING (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid);
DO $$
DECLARE
  t2 uuid := (SELECT id FROM perf.tenant_plan WHERE idx = 2);
BEGIN
  PERFORM perf.note('A11 the same read once the partition has ENABLE, FORCE and its own policy', perf.try_as('factory_app', t2, 'SELECT 1 FROM proto_ledger_p0 WHERE tenant_id <> ''' || t2 || ''''));
END
$$;
REVOKE SELECT ON proto_ledger_p0 FROM factory_app;

-- Pruning: a query that names the tenant and the job touches one partition.
CREATE FUNCTION perf.plan_text(stmt text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE l text; o text := '';
BEGIN
  FOR l IN EXECUTE 'EXPLAIN (COSTS OFF) ' || stmt LOOP o := o || l || ' / '; END LOOP;
  RETURN o;
END
$$;
DO $$
DECLARE
  j1 record;
BEGIN
  SELECT tenant_id, job_id INTO j1 FROM perf.job_plan WHERE n = 7777 OR n = (SELECT max(n) FROM perf.job_plan) ORDER BY n LIMIT 1;
  PERFORM perf.note('A12 plan, ledger tail of one job (tenant and job named)', perf.plan_text(format(
    'SELECT sequence, entry_hash FROM proto_ledger WHERE tenant_id = %L AND job_id = %L ORDER BY sequence DESC LIMIT 1', j1.tenant_id, j1.job_id)));
  PERFORM perf.note('A13 plan, the same query without the job (a scan of every partition)', perf.plan_text(format(
    'SELECT sequence, entry_hash FROM proto_ledger WHERE tenant_id = %L ORDER BY sequence DESC LIMIT 1', j1.tenant_id)));
END
$$;

-- A chain is verified by the same function as before, pointed at the new table (the function names ledger_entries, so a
-- real migration would rename the tables; here the walk is repeated by hand).
DO $$
DECLARE
  bad bigint;
BEGIN
  SELECT count(*) INTO bad FROM (
    SELECT tenant_id, job_id, sequence, entry_hash,
           lag(entry_hash) OVER (PARTITION BY tenant_id, job_id ORDER BY sequence) AS lag_hash,
           lag(sequence) OVER (PARTITION BY tenant_id, job_id ORDER BY sequence) AS lag_seq,
           prev_entry_hash, canonical_json
      FROM proto_ledger) w
   WHERE sequence <> coalesce(lag_seq, 0) + 1 OR prev_entry_hash IS DISTINCT FROM lag_hash
      OR entry_hash <> ledger_entry_hash(prev_entry_hash, canonical_json);
  PERFORM perf.note('A14 every chain of the partitioned ledger verifies (broken links, gaps, wrong hashes counted)', bad::text);
END
$$;

-- Append through the parent as the application role: the hash trigger fires, the partition is chosen, the policy checks the row.
-- Two inserts: a good one, then one with a wrong hash that the guard must refuse.
CREATE FUNCTION perf.proto_append(p_tag text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
  j record;
  doc text;
  h text;
  prev text;
  seq bigint;
  r text;
BEGIN
  SELECT p.tenant_id, p.job_id, p.n INTO j FROM perf.job_plan p WHERE p.tenant_idx = 2 ORDER BY p.n LIMIT 1;
  SELECT sequence, entry_hash INTO seq, prev FROM proto_ledger WHERE tenant_id = j.tenant_id AND job_id = j.job_id ORDER BY sequence DESC LIMIT 1;
  doc := perf.ledger_doc(j.job_id, perf.uid('run', j.n * 100 + 1), NULL, seq + 1, prev, perf.uid('protoentry' || p_tag, j.n), timestamptz '2026-10-28 12:00:00+00', j.n);
  h := 'sha256:' || encode(sha256(convert_to(prev || E'\n' || doc, 'UTF8')), 'hex');
  r := perf.try_dml_as('factory_app', j.tenant_id, format($q$INSERT INTO proto_ledger (tenant_id, job_id, sequence, entry_id, stage_run_id, recorded_at, execution_mode, recorded_component,
        recorded_fidelity, claim_kind, assurance_level, confidence_level, invalidates, prev_entry_hash, entry_hash, canonical_json)
        VALUES (%L, %L, %s, %L, %L, %L, 'production', 'workflow.gate-evaluator', 'real', 'measured_fact', 'VERIFIED_IN_SANDBOX', 'high', '{}', %L, %L, %L)$q$,
        j.tenant_id, j.job_id, seq + 1, perf.uid('protoentry' || p_tag, j.n), perf.uid('run', j.n * 100 + 1), timestamptz '2026-10-28 12:00:00+00', prev, h, doc));
  PERFORM perf.note(p_tag || ': a good append through the parent as the application role', substr(r, 1, 160));
  IF r = 'rows=1' THEN
    r := perf.try_dml_as('factory_app', j.tenant_id, format($q$INSERT INTO proto_ledger (tenant_id, job_id, sequence, entry_id, stage_run_id, recorded_at, execution_mode, recorded_component,
          recorded_fidelity, claim_kind, assurance_level, confidence_level, invalidates, prev_entry_hash, entry_hash, canonical_json)
          VALUES (%L, %L, %s, %L, %L, %L, 'production', 'workflow.gate-evaluator', 'real', 'measured_fact', 'VERIFIED_IN_SANDBOX', 'high', '{}', %L, %L, %L)$q$,
          j.tenant_id, j.job_id, seq + 2, perf.uid('protoentry2' || p_tag, j.n), perf.uid('run', j.n * 100 + 1), timestamptz '2026-10-28 12:00:00+00', h, 'sha256:' || repeat('0', 64),
          perf.ledger_doc(j.job_id, perf.uid('run', j.n * 100 + 1), NULL, seq + 2, h, perf.uid('protoentry2' || p_tag, j.n), timestamptz '2026-10-28 12:00:00+00', j.n)));
    PERFORM perf.note(p_tag || ': an append with a wrong hash', substr(r, 1, 160));
  END IF;
END
$$;

-- First with the guard function of the real table, as it is.
SELECT perf.proto_append('A15 guard function unchanged');

-- The guard of the real table calls ledger_document_matches(e ledger_entries), a function typed on the row of THAT table. The
-- partitioned copy needs a guard that hands the function a ledger_entries record built from its own row.
DROP TRIGGER ledger_entries_guard ON proto_ledger;
CREATE FUNCTION proto_ledger_guard() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  found_earlier integer;
BEGIN
  NEW.prev_sequence := CASE WHEN NEW.sequence = 1 THEN NULL ELSE NEW.sequence - 1 END;
  IF NOT public.ledger_document_matches(jsonb_populate_record(NULL::public.ledger_entries, to_jsonb(NEW))) THEN
    RAISE EXCEPTION 'the document in canonical_json is not valid or does not match the entry columns' USING ERRCODE = '23514';
  END IF;
  IF NEW.entry_hash IS DISTINCT FROM public.ledger_entry_hash(NEW.prev_entry_hash, NEW.canonical_json) THEN
    RAISE EXCEPTION 'entry_hash does not equal the hash of the previous hash and the canonical document' USING ERRCODE = '23514';
  END IF;
  IF cardinality(NEW.invalidates) > 0 THEN
    SELECT count(*) INTO found_earlier FROM public.proto_ledger e
     WHERE e.tenant_id = NEW.tenant_id AND e.job_id = NEW.job_id AND e.sequence < NEW.sequence AND e.entry_id = ANY (NEW.invalidates);
    IF found_earlier <> cardinality(NEW.invalidates) THEN
      RAISE EXCEPTION 'invalidates must name distinct earlier entries of the same job' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER ledger_entries_guard BEFORE INSERT ON proto_ledger FOR EACH ROW EXECUTE FUNCTION proto_ledger_guard();
SELECT perf.proto_append('A16 guard rewritten to take the columns');

-- Archiving a partition: DETACH, with the two foreign keys that point INTO the ledger.
DO $$
BEGIN
  BEGIN
    ALTER TABLE proto_ledger DETACH PARTITION proto_ledger_p0;
    PERFORM perf.note('A17 DETACH PARTITION of the oldest range with both foreign keys in place', 'accepted');
  EXCEPTION WHEN others THEN
    PERFORM perf.note('A17 DETACH PARTITION of the oldest range with both foreign keys in place', 'refused: ' || SQLERRM);
  END;
  BEGIN
    DROP TABLE proto_ledger_p0;
    PERFORM perf.note('A18 DROP TABLE of that partition', 'accepted (rows gone)');
  EXCEPTION WHEN others THEN
    PERFORM perf.note('A18 DROP TABLE of that partition', 'refused: ' || SQLERRM);
  END;
  BEGIN
    DELETE FROM proto_ledger WHERE job_id < perf.job_bound(5);
    PERFORM perf.note('A19 DELETE of old entries as the owner', 'accepted');
  EXCEPTION WHEN others THEN
    PERFORM perf.note('A19 DELETE of old entries as the owner (the no-change trigger)', 'refused: ' || SQLERRM);
  END;
END
$$;
-- Take away the job head key (the proposal replaces it by a check made when the head moves).
ALTER TABLE jobs DROP CONSTRAINT proto_jobs_head_fk;
DO $$
BEGIN
  BEGIN
    ALTER TABLE proto_ledger DETACH PARTITION proto_ledger_p0;
    PERFORM perf.note('A20 DETACH PARTITION once the job head key is gone, the self reference still in place', 'accepted');
  EXCEPTION WHEN others THEN
    PERFORM perf.note('A20 DETACH PARTITION once the job head key is gone, the self reference still in place', 'refused: ' || SQLERRM);
  END;
END
$$;
-- Take away the self reference too (the link to the predecessor would be checked by the insert trigger instead).
DO $$
DECLARE
  fk text;
  n bigint;
BEGIN
  SELECT conname INTO fk FROM pg_constraint WHERE conrelid = 'proto_ledger'::regclass AND contype = 'f' AND confrelid = 'proto_ledger'::regclass;
  EXECUTE format('ALTER TABLE proto_ledger DROP CONSTRAINT %I', fk);
  PERFORM perf.note('A21 the self referencing key dropped', fk);
  ALTER TABLE proto_ledger DETACH PARTITION proto_ledger_p0;
  SELECT count(*) INTO n FROM proto_ledger_p0;
  PERFORM perf.note('A22 DETACH PARTITION with neither key', 'accepted: ' || n || ' entries now stand alone in a table that can be exported, verified and dropped; the remaining chains of other jobs are untouched');
  PERFORM perf.note('A23 the detached entries still verify among themselves (broken links, gaps, wrong hashes counted)', (SELECT count(*) FROM (
    SELECT sequence, prev_entry_hash, entry_hash, canonical_json,
           lag(entry_hash) OVER (PARTITION BY tenant_id, job_id ORDER BY sequence) AS lag_hash, lag(sequence) OVER (PARTITION BY tenant_id, job_id ORDER BY sequence) AS lag_seq
      FROM proto_ledger_p0) w
   WHERE sequence <> coalesce(lag_seq, 0) + 1 OR prev_entry_hash IS DISTINCT FROM lag_hash OR entry_hash <> ledger_entry_hash(prev_entry_hash, canonical_json))::text);
EXCEPTION WHEN others THEN
  PERFORM perf.note('A21-A23 drop the self reference and detach', 'failed: ' || SQLERRM);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- B. The audit log

DO $$
BEGIN
  BEGIN
    CREATE TABLE proto_audit_time (LIKE audit_events INCLUDING DEFAULTS, PRIMARY KEY (tenant_id, sequence)) PARTITION BY RANGE (created_at);
    PERFORM perf.note('B1 audit_events partitioned by RANGE (created_at) with PRIMARY KEY (tenant_id, sequence)', 'accepted');
  EXCEPTION WHEN others THEN
    PERFORM perf.note('B1 audit_events partitioned by RANGE (created_at) with PRIMARY KEY (tenant_id, sequence)', 'refused: ' || SQLERRM);
  END;
END
$$;

CREATE TABLE proto_audit (LIKE audit_events INCLUDING DEFAULTS, PRIMARY KEY (tenant_id, sequence)) PARTITION BY HASH (tenant_id);
CREATE TABLE proto_audit_h0 PARTITION OF proto_audit FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE proto_audit_h1 PARTITION OF proto_audit FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE proto_audit_h2 PARTITION OF proto_audit FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE proto_audit_h3 PARTITION OF proto_audit FOR VALUES WITH (MODULUS 4, REMAINDER 3);
INSERT INTO proto_audit SELECT * FROM audit_events;
ALTER TABLE proto_audit ADD UNIQUE (tenant_id, event_id);
ALTER TABLE proto_audit ADD UNIQUE (tenant_id, sequence, hash);
ALTER TABLE proto_audit ADD FOREIGN KEY (tenant_id, prev_sequence, prev_hash) REFERENCES proto_audit (tenant_id, sequence, hash);
CREATE TRIGGER audit_events_assign BEFORE INSERT ON proto_audit FOR EACH ROW EXECUTE FUNCTION audit_events_assign();
CREATE TRIGGER audit_events_no_change BEFORE UPDATE OR DELETE ON proto_audit FOR EACH ROW EXECUTE FUNCTION reject_modification();
ALTER TABLE proto_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE proto_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON proto_audit TO factory_app USING (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT ON proto_audit TO factory_app;
ANALYZE proto_audit;
DO $$
DECLARE
  t1 uuid := (SELECT id FROM perf.tenant_plan WHERE idx = 1);
BEGIN
  PERFORM perf.note('B2 audit_events hash partitioned by tenant: the plan of the tail query', perf.plan_text(format('SELECT sequence, hash FROM proto_audit WHERE tenant_id = %L ORDER BY sequence DESC LIMIT 1', t1)));
  PERFORM perf.note('B3 an audit insert through the parent as the application role (the trigger takes the tenant lock and hashes)',
    perf.try_dml_as('factory_app', t1, format($q$INSERT INTO proto_audit (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id)
      VALUES (%L, %L, 'service', 'engine', 'gate.result', 'proto', 'record', 'A prototype event.', %L, %L)$q$, t1, perf.uid('protoaud', 1), perf.sha('policy', 1), perf.uid('corr', 1))));
  PERFORM perf.note('B4 the chain of every tenant still verifies on the partitioned copy (rows counted that break the link)',
    (SELECT count(*) FROM (SELECT sequence, prev_hash, hash, lag(hash) OVER (PARTITION BY tenant_id ORDER BY sequence) AS lag_hash, lag(sequence) OVER (PARTITION BY tenant_id ORDER BY sequence) AS lag_seq FROM proto_audit) w
       WHERE sequence <> coalesce(lag_seq, 0) + 1 OR prev_hash IS DISTINCT FROM lag_hash)::text);
END
$$;

-- A multi-column range on (tenant_id, sequence): the one key the audit primary key already holds. Each tenant's chain can then
-- be cut in ranges of sequence numbers, and a whole tenant can sit in a partition of its own.
DO $$
BEGIN
  CREATE TABLE proto_audit_range (LIKE audit_events INCLUDING DEFAULTS, PRIMARY KEY (tenant_id, sequence)) PARTITION BY RANGE (tenant_id, sequence);
  PERFORM perf.note('B5 audit_events partitioned by RANGE (tenant_id, sequence) with PRIMARY KEY (tenant_id, sequence)', 'accepted');
EXCEPTION WHEN others THEN
  PERFORM perf.note('B5 audit_events partitioned by RANGE (tenant_id, sequence)', 'refused: ' || SQLERRM);
END
$$;
DO $$
DECLARE
  t1 uuid := (SELECT id FROM perf.tenant_plan WHERE idx = 1);
  t2 uuid := (SELECT id FROM perf.tenant_plan WHERE idx = 2);
BEGIN
  -- tenant 1: sequences 1 to 20,000 in one partition, the rest of tenant 1 in the next; every other tenant in a default partition
  EXECUTE format('CREATE TABLE proto_audit_range_t1_a PARTITION OF proto_audit_range FOR VALUES FROM (%L, 1) TO (%L, 20001)', t1, t1);
  EXECUTE format('CREATE TABLE proto_audit_range_t1_b PARTITION OF proto_audit_range FOR VALUES FROM (%L, 20001) TO (%L, 9223372036854775807)', t1, t1);
  CREATE TABLE proto_audit_range_rest PARTITION OF proto_audit_range DEFAULT;
  INSERT INTO proto_audit_range SELECT * FROM audit_events;
  PERFORM perf.note('B6 rows of tenant 1 by range partition (first 20,000 sequences, the rest, everyone else)',
    (SELECT count(*) FROM proto_audit_range_t1_a) || ' / ' || (SELECT count(*) FROM proto_audit_range_t1_b) || ' / ' || (SELECT count(*) FROM proto_audit_range_rest));
  PERFORM perf.note('B7 plan of the tail query of tenant 1 on the range partitioned log', perf.plan_text(format('SELECT sequence, hash FROM proto_audit_range WHERE tenant_id = %L ORDER BY sequence DESC LIMIT 1', t1)));
  PERFORM perf.note('B8 plan of the tail query of tenant 2 (in the default partition)', perf.plan_text(format('SELECT sequence, hash FROM proto_audit_range WHERE tenant_id = %L ORDER BY sequence DESC LIMIT 1', t2)));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- C. The outbox

DO $$
BEGIN
  BEGIN
    CREATE TABLE proto_outbox_time (LIKE outbox INCLUDING DEFAULTS, PRIMARY KEY (tenant_id, event_id)) PARTITION BY RANGE (created_at);
    PERFORM perf.note('C1 outbox partitioned by RANGE (created_at) with PRIMARY KEY (tenant_id, event_id)', 'accepted');
  EXCEPTION WHEN others THEN
    PERFORM perf.note('C1 outbox partitioned by RANGE (created_at) with PRIMARY KEY (tenant_id, event_id)', 'refused: ' || SQLERRM);
  END;
END
$$;

-- The alternative: a role that may delete published events older than the retention, and nothing else.
CREATE ROLE proto_maintenance NOLOGIN NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA public TO proto_maintenance;
GRANT SELECT (seq, tenant_id, published_at, created_at), DELETE ON outbox TO proto_maintenance;
CREATE POLICY maintenance_find ON outbox FOR SELECT TO proto_maintenance USING (published_at IS NOT NULL AND published_at < now() - interval '30 days');
CREATE POLICY maintenance_prune ON outbox FOR DELETE TO proto_maintenance USING (published_at IS NOT NULL AND published_at < now() - interval '30 days');
DO $$
DECLARE
  total bigint := (SELECT count(*) FROM outbox);
  unpublished bigint := (SELECT count(*) FROM outbox WHERE published_at IS NULL);
  old_published bigint := (SELECT count(*) FROM outbox WHERE published_at < now() - interval '30 days');
  seen bigint;
  deleted bigint;
  verdict text;
BEGIN
  PERFORM perf.note('C2 the outbox before pruning', total || ' rows, ' || unpublished || ' unpublished, ' || old_published || ' published more than 30 days ago');
  EXECUTE 'SET LOCAL ROLE proto_maintenance';
  PERFORM set_config('factory.tenant_id', '', true);
  SELECT count(*) INTO seen FROM outbox;
  BEGIN
    DELETE FROM outbox WHERE published_at IS NULL;
    GET DIAGNOSTICS deleted = ROW_COUNT;
    verdict := deleted || ' rows deleted (expected 0)';
  EXCEPTION WHEN others THEN
    verdict := 'refused: ' || SQLERRM;
  END;
  RESET ROLE;
  PERFORM perf.note('C3 the maintenance role sees only the rows it may prune', seen::text);
  PERFORM perf.note('C4 the maintenance role deletes unpublished events', verdict);
END
$$;
DO $$
DECLARE
  n bigint;
  total bigint := 0;
  t0 timestamptz := clock_timestamp();
BEGIN
  EXECUTE 'SET LOCAL ROLE proto_maintenance';
  LOOP
    DELETE FROM outbox WHERE seq IN (SELECT seq FROM outbox WHERE published_at < now() - interval '30 days' ORDER BY seq LIMIT 5000);
    GET DIAGNOSTICS n = ROW_COUNT;
    total := total + n;
    EXIT WHEN n = 0;
  END LOOP;
  RESET ROLE;
  PERFORM perf.note('C5 batched delete (5,000 at a time) of published events older than 30 days, as the maintenance role', total || ' rows in ' || round(extract(epoch FROM clock_timestamp() - t0)::numeric, 2) || ' s');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- D. The artifact metadata

CREATE TABLE proto_artifacts (LIKE artifacts INCLUDING DEFAULTS, PRIMARY KEY (tenant_id, content_sha256)) PARTITION BY HASH (tenant_id);
CREATE TABLE proto_artifacts_h0 PARTITION OF proto_artifacts FOR VALUES WITH (MODULUS 4, REMAINDER 0);
CREATE TABLE proto_artifacts_h1 PARTITION OF proto_artifacts FOR VALUES WITH (MODULUS 4, REMAINDER 1);
CREATE TABLE proto_artifacts_h2 PARTITION OF proto_artifacts FOR VALUES WITH (MODULUS 4, REMAINDER 2);
CREATE TABLE proto_artifacts_h3 PARTITION OF proto_artifacts FOR VALUES WITH (MODULUS 4, REMAINDER 3);
INSERT INTO proto_artifacts SELECT * FROM artifacts;
ANALYZE proto_artifacts;
DO $$
DECLARE
  t1 uuid := (SELECT id FROM perf.tenant_plan WHERE idx = 1);
BEGIN
  PERFORM perf.note('D1 artifact lookup by tenant and hash on the hash partitioned copy', perf.plan_text(format('SELECT * FROM proto_artifacts WHERE tenant_id = %L AND content_sha256 = %L', t1, perf.sha('out', 101))));
  PERFORM perf.note('D2 a foreign key INTO the partitioned artifact table (as attempts.output_sha256 has)', 'tried below');
END
$$;
DO $$
BEGIN
  CREATE TABLE proto_fk_child (tenant_id uuid, sha text, FOREIGN KEY (tenant_id, sha) REFERENCES proto_artifacts (tenant_id, content_sha256));
  PERFORM perf.note('D3 composite foreign key (tenant_id, content_sha256) to the hash partitioned artifact table', 'accepted');
EXCEPTION WHEN others THEN
  PERFORM perf.note('D3 composite foreign key (tenant_id, content_sha256) to the hash partitioned artifact table', 'refused: ' || SQLERRM);
END
$$;
