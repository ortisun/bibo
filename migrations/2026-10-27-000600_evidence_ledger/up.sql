-- The evidence ledger (ADR 0008): one append-only, hash-chained list of claims per job.
--
-- What the database enforces, in layers:
--   1. The application role has SELECT and INSERT only (last migration).
--   2. Triggers refuse UPDATE, DELETE and TRUNCATE for every role, the owner included.
--   3. Each entry points at its predecessor by (job, sequence - 1, entry hash) through a foreign key,
--      so a gap, a fork or a forged link cannot be inserted. Sequence 1 has no predecessor.
--   4. A trigger recomputes the entry hash from the stored canonical document and checks that the
--      queryable columns agree with that document, so the columns cannot say one thing and the
--      hashed text another.
--   5. The job and its execution mode are joined by a foreign key, so a job in production mode can
--      never receive an entry from a fake or simulated recorder (invariant INV-08).
-- What it does not enforce: that canonical_json is RFC 8785 canonical, and that the claim satisfies
-- the evidence-ledger-entry JSON Schema. Those belong to the domain code. A superuser can still
-- rewrite the whole chain (see docs/database/not-covered.md).

CREATE TABLE ledger_entries (
  tenant_id          uuid   NOT NULL REFERENCES tenants (id),
  job_id             uuid   NOT NULL,
  sequence           bigint NOT NULL,
  entry_id           uuid   NOT NULL,
  stage_run_id       uuid   NOT NULL,
  attempt_id         uuid,
  -- recorded_at is part of the hashed document, so the application supplies it. inserted_at is the
  -- database clock and is not hashed; a large gap between the two is worth an alert.
  recorded_at        timestamptz NOT NULL,
  inserted_at        timestamptz NOT NULL DEFAULT now(),
  execution_mode     text   NOT NULL,
  recorded_component text   NOT NULL,
  recorded_fidelity  text   NOT NULL,
  claim_kind         text   NOT NULL,
  assurance_level    text,
  confidence_level   text   NOT NULL,
  -- Earlier entries this one withdraws. Mirrors the document and is checked against it.
  invalidates        uuid[] NOT NULL DEFAULT '{}',
  -- Derived by the trigger (sequence - 1) so the application cannot disagree with its own sequence.
  prev_sequence      bigint,
  prev_entry_hash    text,
  entry_hash         text   NOT NULL,
  -- The exact text that was hashed: the entry without entry_hash, as canonical JSON.
  canonical_json     text   NOT NULL,
  PRIMARY KEY (tenant_id, job_id, sequence),
  UNIQUE (tenant_id, entry_id),
  -- The target of the chain link and of the job's head pointer.
  UNIQUE (tenant_id, job_id, sequence, entry_hash),
  FOREIGN KEY (tenant_id, job_id, execution_mode) REFERENCES jobs (tenant_id, id, execution_mode),
  FOREIGN KEY (tenant_id, job_id, stage_run_id) REFERENCES stage_runs (tenant_id, job_id, id),
  FOREIGN KEY (tenant_id, job_id, stage_run_id, attempt_id) REFERENCES attempts (tenant_id, job_id, stage_run_id, id),
  FOREIGN KEY (tenant_id, job_id, prev_sequence, prev_entry_hash)
    REFERENCES ledger_entries (tenant_id, job_id, sequence, entry_hash),
  CONSTRAINT ledger_entries_sequence_check CHECK (sequence >= 1),
  CONSTRAINT ledger_entries_first_has_no_predecessor CHECK ((sequence = 1) = (prev_entry_hash IS NULL)),
  CONSTRAINT ledger_entries_hashes_check CHECK (
    entry_hash ~ '^sha256:[0-9a-f]{64}$' AND (prev_entry_hash IS NULL OR prev_entry_hash ~ '^sha256:[0-9a-f]{64}$')),
  CONSTRAINT ledger_entries_execution_mode_check CHECK (execution_mode IN ('production', 'test')),
  CONSTRAINT ledger_entries_component_check CHECK (recorded_component ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
  CONSTRAINT ledger_entries_fidelity_check CHECK (recorded_fidelity IN ('real', 'simulated', 'fake')),
  CONSTRAINT ledger_entries_claim_kind_check CHECK (
    claim_kind IN ('measured_fact', 'simulation_result', 'assumption', 'hypothesis', 'expert_judgment')),
  CONSTRAINT ledger_entries_assurance_level_check CHECK (assurance_level IS NULL OR assurance_level IN (
    'SPECIFIED', 'IMPLEMENTED', 'VERIFIED_IN_SANDBOX', 'VERIFIED_IN_SIMULATOR', 'VERIFIED_ON_DEVICE',
    'PAPER_VALIDATED', 'PRODUCTION_READY')),
  CONSTRAINT ledger_entries_confidence_check CHECK (confidence_level IN ('low', 'medium', 'high')),
  CONSTRAINT ledger_entries_document_size_check CHECK (octet_length(canonical_json) BETWEEN 2 AND 262144),
  -- The rules of evidence-ledger-entry.schema.json that concern the queryable columns:
  -- a fake or simulated recorder is allowed in test mode only, and never supports an assurance level.
  CONSTRAINT ledger_entries_fake_only_in_test CHECK (recorded_fidelity = 'real' OR execution_mode = 'test'),
  CONSTRAINT ledger_entries_assurance_needs_real CHECK (assurance_level IS NULL OR recorded_fidelity = 'real'),
  CONSTRAINT ledger_entries_assumption_has_no_assurance CHECK (
    claim_kind NOT IN ('assumption', 'hypothesis') OR assurance_level IS NULL)
);
-- Claims of one stage run, for the gate ("every acceptance criterion has an entry").
CREATE INDEX ledger_entries_stage_run_idx ON ledger_entries (tenant_id, job_id, stage_run_id, sequence);

-- Does the stored document say what the queryable columns say? One function, used by the insert
-- trigger and by the chain verifier, so the two cannot drift apart. Any malformed document counts
-- as "no": a cast that fails is a mismatch, never an error that escapes.
CREATE FUNCTION ledger_document_matches(e ledger_entries) RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, public AS $$
DECLARE
  doc jsonb;
  meta jsonb;
  doc_invalidates uuid[];
BEGIN
  doc := e.canonical_json::jsonb;
  meta := doc -> 'metadata';
  SELECT coalesce(array_agg(t.v::uuid ORDER BY t.o), '{}'::uuid[]) INTO doc_invalidates
    FROM jsonb_array_elements_text(coalesce(doc -> 'invalidates', '[]'::jsonb)) WITH ORDINALITY AS t(v, o);
  RETURN coalesce(
        jsonb_typeof(doc) = 'object'
    AND NOT (doc ? 'entry_hash')
    AND doc ->> 'schema_version' = '1'
    AND (meta ->> 'entry_id')::uuid = e.entry_id
    AND (meta ->> 'job_id')::uuid = e.job_id
    AND (meta ->> 'stage_run_id')::uuid = e.stage_run_id
    AND (meta ->> 'attempt_id')::uuid IS NOT DISTINCT FROM e.attempt_id
    AND (meta ->> 'sequence')::bigint = e.sequence
    AND (meta ->> 'recorded_at')::timestamptz = e.recorded_at
    AND meta ->> 'execution_mode' = e.execution_mode
    AND meta #>> '{recorded_by,component}' = e.recorded_component
    AND meta #>> '{recorded_by,fidelity}' = e.recorded_fidelity
    AND doc #>> '{claim,kind}' = e.claim_kind
    AND (doc #>> '{claim,assurance_level}') IS NOT DISTINCT FROM e.assurance_level
    AND doc #>> '{confidence,level}' = e.confidence_level
    AND coalesce(doc -> 'prev_entry_hash', 'null'::jsonb) = coalesce(to_jsonb(e.prev_entry_hash), 'null'::jsonb)
    AND doc_invalidates = e.invalidates,
    false);
EXCEPTION WHEN data_exception OR invalid_text_representation THEN
  RETURN false;
END
$$;

CREATE FUNCTION ledger_entry_hash(p_prev_entry_hash text, p_canonical_json text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
  -- The chain formula of ADR 0008: SHA-256 over the previous entry's hash text (empty for the first
  -- entry), a newline, and the canonical JSON of this entry without its entry_hash.
  SELECT 'sha256:' || encode(sha256(convert_to(coalesce(p_prev_entry_hash, '') || E'\n' || p_canonical_json, 'UTF8')), 'hex')
$$;

CREATE FUNCTION ledger_entries_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  found_earlier integer;
BEGIN
  NEW.prev_sequence := CASE WHEN NEW.sequence = 1 THEN NULL ELSE NEW.sequence - 1 END;

  IF NOT public.ledger_document_matches(NEW) THEN
    RAISE EXCEPTION 'the document in canonical_json is not valid or does not match the entry columns'
      USING ERRCODE = '23514', CONSTRAINT = 'ledger_entries_document_matches_columns', TABLE = 'ledger_entries';
  END IF;

  IF NEW.entry_hash IS DISTINCT FROM public.ledger_entry_hash(NEW.prev_entry_hash, NEW.canonical_json) THEN
    RAISE EXCEPTION 'entry_hash does not equal the hash of the previous hash and the canonical document'
      USING ERRCODE = '23514', CONSTRAINT = 'ledger_entries_hash_matches_document', TABLE = 'ledger_entries';
  END IF;

  -- Withdrawal appends; it names earlier entries of the same job and nothing else.
  IF cardinality(NEW.invalidates) > 0 THEN
    SELECT count(*) INTO found_earlier
      FROM public.ledger_entries e
     WHERE e.tenant_id = NEW.tenant_id AND e.job_id = NEW.job_id
       AND e.sequence < NEW.sequence AND e.entry_id = ANY (NEW.invalidates);
    IF found_earlier <> cardinality(NEW.invalidates) THEN
      RAISE EXCEPTION 'invalidates must name distinct earlier entries of the same job'
        USING ERRCODE = '23514', CONSTRAINT = 'ledger_entries_invalidates_earlier_entries', TABLE = 'ledger_entries';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER ledger_entries_guard BEFORE INSERT ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION ledger_entries_guard();

-- Append-only, second layer (the first is the missing UPDATE and DELETE grant).
CREATE TRIGGER ledger_entries_no_change BEFORE UPDATE OR DELETE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION reject_modification();
CREATE TRIGGER ledger_entries_no_truncate BEFORE TRUNCATE ON ledger_entries
  FOR EACH STATEMENT EXECUTE FUNCTION reject_modification();

-- The job's head pointer must name a real entry of that job. Checked at commit, so the entry and the
-- job update can be written in either order inside the transaction.
ALTER TABLE jobs
  ADD CONSTRAINT jobs_ledger_head_fk
  FOREIGN KEY (tenant_id, id, ledger_head_sequence, ledger_head_hash)
  REFERENCES ledger_entries (tenant_id, job_id, sequence, entry_hash)
  DEFERRABLE INITIALLY DEFERRED;

-- Claims that no later entry withdraws.
CREATE VIEW ledger_current_claims WITH (security_invoker = true) AS
SELECT e.tenant_id, e.job_id, e.sequence, e.entry_id, e.stage_run_id, e.attempt_id, e.recorded_at,
       e.execution_mode, e.recorded_component, e.recorded_fidelity, e.claim_kind, e.assurance_level,
       e.confidence_level, e.entry_hash
  FROM ledger_entries e
 WHERE NOT EXISTS (
         SELECT 1 FROM ledger_entries l
          WHERE l.tenant_id = e.tenant_id AND l.job_id = e.job_id
            AND l.sequence > e.sequence AND e.entry_id = ANY (l.invalidates));

-- Assurance levels a job has earned: current claims recorded by a real component (invariants
-- INV-07 and INV-08). The levels are not ordered, so this is a set.
CREATE VIEW ledger_assurance_levels WITH (security_invoker = true) AS
SELECT c.tenant_id, c.job_id, c.assurance_level, count(*) AS supporting_claims
  FROM ledger_current_claims c
 WHERE c.assurance_level IS NOT NULL AND c.recorded_fidelity = 'real'
 GROUP BY c.tenant_id, c.job_id, c.assurance_level;

-- Walk one job's chain and return the sequence of the first bad entry, or NULL when the chain is
-- sound: a gap, a broken link, a hash that does not match its stored document, columns that do not
-- match the document, or a job head that does not name the last entry (0 means the head is behind
-- entries that exist). The Rust verifier does the same and also checks RFC 8785 form.
CREATE FUNCTION ledger_verify_chain(p_tenant uuid, p_job uuid) RETURNS bigint
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  WITH walked AS (
    SELECT x AS entry, x.sequence,
           lag(x.sequence) OVER w AS lag_sequence, lag(x.entry_hash) OVER w AS lag_hash
      FROM public.ledger_entries x
     WHERE x.tenant_id = p_tenant AND x.job_id = p_job
    WINDOW w AS (ORDER BY x.sequence)
  ), bad AS (
    SELECT sequence FROM walked
     WHERE sequence <> coalesce(lag_sequence, 0) + 1
        OR (entry).prev_entry_hash IS DISTINCT FROM lag_hash
        OR (entry).entry_hash <> public.ledger_entry_hash((entry).prev_entry_hash, (entry).canonical_json)
        OR NOT public.ledger_document_matches(entry)
    UNION ALL
    SELECT j.ledger_head_sequence
      FROM public.jobs j
     WHERE j.tenant_id = p_tenant AND j.id = p_job
       AND j.ledger_head_sequence <> coalesce((SELECT max(w.sequence) FROM walked w), 0)
  )
  SELECT min(sequence) FROM bad
$$;
