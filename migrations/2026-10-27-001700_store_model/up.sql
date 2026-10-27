-- ports v1.1 (ADR 0014, decision 2): what the complete Store model needs from the tables, so that no operation
-- has to invent a value for a column.
--
--   1. stage_runs.failing_set_sha256        GateRecord::failing_set_sha256, for the stagnation detector.
--   2. A BLOCKED stage run records BLOCKED  S11 and S21 both record the BLOCKED gate outcome (stage_run_effects_rule).
--   3. repositories.bypass_attested_*       The organization admin's attestation that the App is on no bypass list
--                                           (ADR 0014, decision 7). Nullable. The database stamps the time.
--   4. task_nodes: attempt and commit rules TaskNodeEffects: the attempt is set on T02 and cleared on T04 and T05,
--                                           the commit is required on T03.
--   5. jobs: a ledger append does not bump the job's version
--                                           append_ledger_entry returns the chain head and no version, while
--                                           transition_job takes the version the caller read. If an append moved
--                                           the job's version, every transition after an append in the same
--                                           transaction would be a Conflict that the caller cannot foresee.
--                                           The fake store has always behaved this way; this makes PostgreSQL agree.
--
-- Expand only: nullable columns, constraints added NOT VALID and then validated (no table is rewritten, and
-- the validation allows reads and writes), a trigger function that accepts everything the old one accepted.

SET LOCAL lock_timeout = '5s';

-- 1. The digest of the set of failures behind a FAILED gate outcome (IS NOT NULL is spelled out: a CHECK accepts NULL). A digest, not an artifact: the stagnation
--    detector compares digests without reading an artifact inside a transaction. Frozen with the rest of a terminal
--    row by stage_runs_guard (it compares every column).
ALTER TABLE stage_runs ADD COLUMN failing_set_sha256 text;
ALTER TABLE stage_runs ADD CONSTRAINT stage_runs_failing_set_hash_check
  CHECK (failing_set_sha256 IS NULL OR failing_set_sha256 ~ '^sha256:[0-9a-f]{64}$') NOT VALID;
ALTER TABLE stage_runs ADD CONSTRAINT stage_runs_failing_set_needs_failed_outcome
  CHECK (failing_set_sha256 IS NULL OR (gate_outcome IS NOT NULL AND gate_outcome = 'FAILED')) NOT VALID;
ALTER TABLE stage_runs VALIDATE CONSTRAINT stage_runs_failing_set_hash_check;
ALTER TABLE stage_runs VALIDATE CONSTRAINT stage_runs_failing_set_needs_failed_outcome;
GRANT UPDATE (failing_set_sha256) ON stage_runs TO factory_app;

-- 2. BLOCKED is entered by S11 (from GATING) and S21 (from RUNNING). Both record the BLOCKED outcome.
--    IS NOT NULL is spelled out: a CHECK accepts NULL.
ALTER TABLE stage_runs ADD CONSTRAINT stage_runs_blocked_has_outcome
  CHECK (status <> 'BLOCKED' OR (gate_outcome IS NOT NULL AND gate_outcome = 'BLOCKED')) NOT VALID;
ALTER TABLE stage_runs VALIDATE CONSTRAINT stage_runs_blocked_has_outcome;

-- 3. The attestation of an organization admin. Both columns or neither. The attestor is an active human principal
--    of the same tenant (a service cannot attest), and the time is the database's: whatever the caller writes
--    is replaced. To attest again, clear it and set it.
ALTER TABLE repositories
  ADD COLUMN bypass_attested_by_principal_id uuid,
  ADD COLUMN bypass_attested_at timestamptz;
ALTER TABLE repositories ADD CONSTRAINT repositories_bypass_attestation_pair
  CHECK ((bypass_attested_by_principal_id IS NULL) = (bypass_attested_at IS NULL)) NOT VALID;
ALTER TABLE repositories ADD CONSTRAINT repositories_bypass_attested_by_fkey
  FOREIGN KEY (tenant_id, bypass_attested_by_principal_id) REFERENCES principals (tenant_id, id) NOT VALID;
ALTER TABLE repositories VALIDATE CONSTRAINT repositories_bypass_attestation_pair;
ALTER TABLE repositories VALIDATE CONSTRAINT repositories_bypass_attested_by_fkey;
GRANT UPDATE (bypass_attested_by_principal_id, bypass_attested_at) ON repositories TO factory_app;

CREATE FUNCTION repositories_attestation_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.bypass_attested_by_principal_id IS NULL THEN
    NEW.bypass_attested_at := NULL;
  ELSIF TG_OP = 'INSERT' OR NEW.bypass_attested_by_principal_id IS DISTINCT FROM OLD.bypass_attested_by_principal_id THEN
    IF NOT EXISTS (SELECT 1 FROM public.principals p
                    WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.bypass_attested_by_principal_id
                      AND p.kind = 'human' AND p.disabled_at IS NULL) THEN
      RAISE EXCEPTION 'the attestation must come from an active human principal of the tenant'
        USING ERRCODE = '23514', CONSTRAINT = 'repositories_attestor_is_an_active_human', TABLE = 'repositories';
    END IF;
    NEW.bypass_attested_at := now();
  ELSE
    NEW.bypass_attested_at := OLD.bypass_attested_at;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER repositories_attestation_guard BEFORE INSERT OR UPDATE ON repositories
  FOR EACH ROW EXECUTE FUNCTION repositories_attestation_guard();

-- 4. What a task node carries in each state. RUNNING has the attempt that took it (T02). PENDING, READY and FAILED
--    have none (T04 and T05 clear it; T06 and T01 start without one). SUCCEEDED has the commit that finished it
--    (T03), and only SUCCEEDED has one.
ALTER TABLE task_nodes ADD CONSTRAINT task_nodes_running_has_attempt
  CHECK (status <> 'RUNNING' OR current_attempt_id IS NOT NULL) NOT VALID;
ALTER TABLE task_nodes ADD CONSTRAINT task_nodes_idle_has_no_attempt
  CHECK (status NOT IN ('PENDING', 'READY', 'FAILED') OR current_attempt_id IS NULL) NOT VALID;
ALTER TABLE task_nodes ADD CONSTRAINT task_nodes_commit_iff_succeeded
  CHECK ((status = 'SUCCEEDED') = (commit_sha IS NOT NULL)) NOT VALID;
ALTER TABLE task_nodes VALIDATE CONSTRAINT task_nodes_running_has_attempt;
ALTER TABLE task_nodes VALIDATE CONSTRAINT task_nodes_idle_has_no_attempt;
ALTER TABLE task_nodes VALIDATE CONSTRAINT task_nodes_commit_iff_succeeded;

-- 5. The job's compare and swap. An update raises the version by exactly one, as for every aggregate, with one
--    exception: moving the ledger head pointer alone (ledger_head_sequence and ledger_head_hash, nothing else)
--    may leave the version where it is, or raise it by one. Either way the head only moves forward. The two
--    writers do not disturb each other: the chain is guarded by the primary key of ledger_entries and its
--    foreign key to the predecessor, so two appends cannot take one position, and a transition of the job still
--    compares the version it read.
CREATE FUNCTION jobs_bump_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  head_columns text[] := ARRAY['ledger_head_sequence', 'ledger_head_hash', 'version', 'updated_at'];
BEGIN
  IF NEW.ledger_head_sequence < OLD.ledger_head_sequence THEN
    RAISE EXCEPTION 'the ledger head of a job only moves forward (% to %)', OLD.ledger_head_sequence, NEW.ledger_head_sequence
      USING ERRCODE = '23514', CONSTRAINT = 'jobs_ledger_head_only_moves_forward', TABLE = 'jobs';
  END IF;
  IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
    IF NOT (NEW.version IS NOT DISTINCT FROM OLD.version
            AND NEW.ledger_head_sequence > OLD.ledger_head_sequence
            AND (to_jsonb(NEW) - head_columns) = (to_jsonb(OLD) - head_columns)) THEN
      RAISE EXCEPTION 'jobs version must rise by exactly one (was %, update set %), or stay when only the ledger head moves', OLD.version, NEW.version
        USING ERRCODE = '23514', CONSTRAINT = 'jobs_version_bump', TABLE = 'jobs';
    END IF;
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END
$$;
DROP TRIGGER jobs_bump ON jobs;
CREATE TRIGGER jobs_bump BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION jobs_bump_guard();
