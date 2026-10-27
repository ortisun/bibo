-- Suite: contracts
-- Proves the rows can carry the contracts they were designed for. Part 1 maps every required field of
-- the evidence-ledger-entry and domain-event schemas to a column or to the stored document, and fails
-- if the schemas gain a required field the tables do not know. Part 2 stores the real valid example
-- documents from schemas/examples in the ledger and the outbox.

-- ---------------------------------------------------------------------------------------------
-- 1. Field coverage. 'columns' names table.column pairs that must exist; 'document' means the field is
-- stored inside ledger_entries.canonical_json (and is checked there by ledger_document_matches where
-- the database needs it); 'constant' is a fixed envelope value that is not stored.

CREATE TEMP TABLE field_map (schema_name text, field text, storage text, columns text[]);
INSERT INTO field_map VALUES
  ('evidence-ledger-entry', 'schema_version', 'constant', NULL),
  ('evidence-ledger-entry', 'metadata', 'columns', ARRAY['ledger_entries.tenant_id']),
  ('evidence-ledger-entry', 'claim', 'columns', ARRAY['ledger_entries.claim_kind', 'ledger_entries.assurance_level', 'ledger_entries.canonical_json']),
  ('evidence-ledger-entry', 'evidence', 'document', ARRAY['ledger_entries.canonical_json']),
  ('evidence-ledger-entry', 'confidence', 'columns', ARRAY['ledger_entries.confidence_level', 'ledger_entries.canonical_json']),
  ('evidence-ledger-entry', 'prev_entry_hash', 'columns', ARRAY['ledger_entries.prev_entry_hash']),
  ('evidence-ledger-entry', 'entry_hash', 'columns', ARRAY['ledger_entries.entry_hash']),
  ('evidence-ledger-entry.metadata', 'entry_id', 'columns', ARRAY['ledger_entries.entry_id']),
  ('evidence-ledger-entry.metadata', 'job_id', 'columns', ARRAY['ledger_entries.job_id']),
  ('evidence-ledger-entry.metadata', 'stage_run_id', 'columns', ARRAY['ledger_entries.stage_run_id']),
  ('evidence-ledger-entry.metadata', 'sequence', 'columns', ARRAY['ledger_entries.sequence']),
  ('evidence-ledger-entry.metadata', 'recorded_at', 'columns', ARRAY['ledger_entries.recorded_at']),
  ('evidence-ledger-entry.metadata', 'recorded_by', 'columns', ARRAY['ledger_entries.recorded_component', 'ledger_entries.recorded_fidelity']),
  ('evidence-ledger-entry.metadata', 'execution_mode', 'columns', ARRAY['ledger_entries.execution_mode']),
  ('evidence-ledger-entry.metadata.recorded_by', 'component', 'columns', ARRAY['ledger_entries.recorded_component']),
  ('evidence-ledger-entry.metadata.recorded_by', 'fidelity', 'columns', ARRAY['ledger_entries.recorded_fidelity']),
  ('domain-event', 'schema_version', 'constant', NULL),
  ('domain-event', 'event_id', 'columns', ARRAY['outbox.event_id']),
  ('domain-event', 'event_type', 'columns', ARRAY['outbox.event_type']),
  ('domain-event', 'event_version', 'columns', ARRAY['outbox.event_version']),
  ('domain-event', 'tenant_id', 'columns', ARRAY['outbox.tenant_id']),
  ('domain-event', 'job_id', 'columns', ARRAY['outbox.job_id']),
  ('domain-event', 'aggregate', 'columns', ARRAY['outbox.aggregate_type', 'outbox.aggregate_id', 'outbox.aggregate_version']),
  ('domain-event', 'transition_id', 'columns', ARRAY['outbox.transition_id']),
  ('domain-event', 'correlation_id', 'columns', ARRAY['outbox.correlation_id']),
  ('domain-event', 'causation_id', 'columns', ARRAY['outbox.causation_id']),
  ('domain-event', 'occurred_at', 'columns', ARRAY['outbox.occurred_at']),
  ('domain-event', 'producer', 'columns', ARRAY['outbox.producer']),
  ('domain-event', 'payload', 'columns', ARRAY['outbox.payload']),
  ('domain-event.aggregate', 'type', 'columns', ARRAY['outbox.aggregate_type']),
  ('domain-event.aggregate', 'id', 'columns', ARRAY['outbox.aggregate_id']),
  ('domain-event.aggregate', 'version', 'columns', ARRAY['outbox.aggregate_version']);

DO $$
DECLARE
  missing text;
  stale text;
  absent text;
BEGIN
  SELECT string_agg(e.schema_name || '.' || e.field, ', ' ORDER BY e.schema_name, e.field) INTO missing
    FROM dbtest.expected_schema_fields e
    LEFT JOIN field_map m ON m.schema_name = e.schema_name AND m.field = e.field
   WHERE m.field IS NULL;
  PERFORM dbtest.expect_eq('every required field of the two schemas has a place in the tables (a new required field fails here)', coalesce(missing, ''), '');

  SELECT string_agg(m.schema_name || '.' || m.field, ', ' ORDER BY m.schema_name, m.field) INTO stale
    FROM field_map m
    LEFT JOIN dbtest.expected_schema_fields e ON m.schema_name = e.schema_name AND m.field = e.field
   WHERE e.field IS NULL;
  PERFORM dbtest.expect_eq('the field map lists no field that the schemas do not require (nothing stale)', coalesce(stale, ''), '');

  SELECT string_agg(c, ', ' ORDER BY c) INTO absent
    FROM (SELECT unnest(columns) AS c FROM field_map WHERE columns IS NOT NULL) x
   WHERE NOT EXISTS (SELECT 1 FROM information_schema.columns ic
                      WHERE ic.table_schema = 'public' AND ic.table_name || '.' || ic.column_name = x.c);
  PERFORM dbtest.expect_eq('every column named in the field map exists', coalesce(absent, ''), '');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. The valid ledger examples are stored as they are (each re-sequenced as entry 1 of its job).
-- The job and stage run ids come from the document. The hash is computed here, not taken from the file.

DO $$
DECLARE
  tenant uuid := dbtest.u(9);
  ex record;
  doc jsonb;
  job uuid;
  run uuid;
  attempt uuid;
  stored int := 0;
BEGIN
  INSERT INTO tenants (id, slug, display_name) VALUES (tenant, 'contracts', 'Contract examples');
  INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
    VALUES (tenant, dbtest.u(9001), 9909, 8909, 'org9/repo', 'main');
  INSERT INTO principals (tenant_id, id, kind, github_user_id) VALUES (tenant, dbtest.u(9002), 'human', 7909);

  FOR ex IN SELECT * FROM dbtest.example_documents WHERE kind = 'ledger' ORDER BY name LOOP
    doc := ex.doc::jsonb;
    job := (doc #>> '{metadata,job_id}')::uuid;
    run := (doc #>> '{metadata,stage_run_id}')::uuid;
    attempt := (doc #>> '{metadata,attempt_id}')::uuid;
    INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id)
      VALUES (tenant, job, dbtest.u(9001), dbtest.u(9002), doc #>> '{metadata,execution_mode}', 'L1', ARRAY['INTAKE'], gen_random_uuid());
    INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number) VALUES (tenant, run, job, 'VALIDATION', 1);
    IF attempt IS NOT NULL THEN
      PERFORM dbtest.set_status('stage_runs', 9, run, 'READY');
      PERFORM dbtest.set_status('stage_runs', 9, run, 'RUNNING', ', lease_epoch = lease_epoch + 1');
      INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
        VALUES (tenant, attempt, job, run, 1, 'worker-a', 1, now() + interval '1 minute', now() + interval '1 hour');
    END IF;

    INSERT INTO ledger_entries (tenant_id, job_id, sequence, entry_id, stage_run_id, attempt_id, recorded_at, execution_mode,
                                recorded_component, recorded_fidelity, claim_kind, assurance_level, confidence_level, invalidates,
                                prev_entry_hash, entry_hash, canonical_json)
    VALUES (tenant, job, 1, (doc #>> '{metadata,entry_id}')::uuid, run, attempt, (doc #>> '{metadata,recorded_at}')::timestamptz,
            doc #>> '{metadata,execution_mode}', doc #>> '{metadata,recorded_by,component}', doc #>> '{metadata,recorded_by,fidelity}',
            doc #>> '{claim,kind}', doc #>> '{claim,assurance_level}', doc #>> '{confidence,level}', '{}', NULL,
            dbtest.ledger_hash(NULL, ex.doc), ex.doc);
    stored := stored + 1;
    PERFORM dbtest.pass('the valid example ' || ex.name || ' is stored in the ledger as it is');
  END LOOP;
  PERFORM dbtest.expect_true('at least three ledger examples were stored (production fact, test-mode fake, human judgment)', stored >= 3);
END
$$;

-- The production example with its recorder changed to a fake one is refused: a production job takes no
-- fake evidence. (The assurance level is dropped from the copy so that only this rule is broken.)
DO $$
DECLARE
  ex record := (SELECT e FROM dbtest.example_documents e WHERE kind = 'ledger' AND name = 'sandbox-verification-first-entry.json');
  doc jsonb := ex.doc::jsonb;
  bad jsonb;
BEGIN
  bad := jsonb_set(doc #- '{claim,assurance_level}', '{metadata,recorded_by,fidelity}', '"fake"');
  PERFORM dbtest.expect_error('the production example with its recorder changed to fake is refused',
    format($q$INSERT INTO ledger_entries (tenant_id, job_id, sequence, entry_id, stage_run_id, attempt_id, recorded_at, execution_mode, recorded_component,
              recorded_fidelity, claim_kind, confidence_level, entry_hash, canonical_json)
              VALUES (%L, %L, 1, %L, %L, %L, %L, 'production', %L, 'fake', 'measured_fact', 'high', %L, %L)$q$,
           dbtest.u(9), (doc #>> '{metadata,job_id}')::uuid, (doc #>> '{metadata,entry_id}')::uuid, (doc #>> '{metadata,stage_run_id}')::uuid,
           (doc #>> '{metadata,attempt_id}')::uuid, doc #>> '{metadata,recorded_at}', doc #>> '{metadata,recorded_by,component}',
           dbtest.ledger_hash(NULL, bad::text), bad::text),
    '23514', NULL, 'ledger_entries_fake_only_in_test');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. The valid domain events are stored in the outbox as they are. The tenant, job and aggregate ids
-- come from the document; the foreign key to the state machine checks the event type against the
-- transition.

DO $$
DECLARE
  ex record;
  doc jsonb;
  tenant uuid;
  job uuid;
  agg uuid;
  agg_type text;
  n int := 0;
BEGIN
  FOR ex IN SELECT * FROM dbtest.example_documents WHERE kind = 'event' ORDER BY name LOOP
    doc := ex.doc::jsonb;
    tenant := (doc ->> 'tenant_id')::uuid;
    job := (doc ->> 'job_id')::uuid;
    agg := (doc #>> '{aggregate,id}')::uuid;
    agg_type := doc #>> '{aggregate,type}';
    INSERT INTO tenants (id, slug, display_name) VALUES (tenant, 'events-' || n, 'Event examples') ON CONFLICT DO NOTHING;
    INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
      VALUES (tenant, gen_random_uuid(), 9910 + n, 8910 + n, 'org10/repo' || n, 'main') ON CONFLICT DO NOTHING;
    INSERT INTO principals (tenant_id, id, kind, github_user_id) VALUES (tenant, gen_random_uuid(), 'human', 7910 + n) ON CONFLICT DO NOTHING;
    INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id)
      SELECT tenant, job, r.id, p.id, 'production', 'L1', ARRAY['INTAKE'], (doc ->> 'correlation_id')::uuid
        FROM repositories r, principals p WHERE r.tenant_id = tenant AND p.tenant_id = tenant LIMIT 1
      ON CONFLICT DO NOTHING;
    IF agg_type = 'stage_run' THEN
      INSERT INTO stage_runs (tenant_id, id, job_id, stage_kind, run_number) VALUES (tenant, agg, job, 'VALIDATION', 1) ON CONFLICT DO NOTHING;
    END IF;
    -- An event may only announce a version its aggregate has reached. Raise the version with harmless edits.
    LOOP
      EXIT WHEN (CASE agg_type
                   WHEN 'job' THEN (SELECT x.version FROM jobs x WHERE x.tenant_id = tenant AND x.id = agg)
                   ELSE (SELECT x.version FROM stage_runs x WHERE x.tenant_id = tenant AND x.id = agg) END) >= (doc #>> '{aggregate,version}')::bigint;
      IF agg_type = 'job' THEN
        UPDATE jobs SET policy_hash = NULL, version = version + 1 WHERE tenant_id = tenant AND id = agg;
      ELSE
        UPDATE stage_runs SET max_attempts = max_attempts, version = version + 1 WHERE tenant_id = tenant AND id = agg;
      END IF;
    END LOOP;
    INSERT INTO outbox (tenant_id, event_id, event_type, event_version, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id,
                        reason_code, correlation_id, causation_id, occurred_at, producer, traceparent, payload, payload_schema_name, payload_schema_version)
    VALUES (tenant, (doc ->> 'event_id')::uuid, doc ->> 'event_type', (doc ->> 'event_version')::int, job, agg_type, agg,
            (doc #>> '{aggregate,version}')::bigint, doc ->> 'transition_id', doc ->> 'reason_code', (doc ->> 'correlation_id')::uuid,
            (doc ->> 'causation_id')::uuid, (doc ->> 'occurred_at')::timestamptz, doc ->> 'producer', doc ->> 'traceparent',
            doc -> 'payload', doc #>> '{payload_schema,name}', (doc #>> '{payload_schema,version}')::int);
    n := n + 1;
    PERFORM dbtest.pass('the valid event example ' || ex.name || ' is stored in the outbox as it is');
  END LOOP;
  PERFORM dbtest.expect_true('both event examples were stored', n = 2);
END
$$;
