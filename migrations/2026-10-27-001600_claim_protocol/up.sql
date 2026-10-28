-- ports v1.1 (ADR 0014, decision 1): the database side of the claim protocol.
--
-- The protocol, in the order the engine runs it:
--   1. The system role finds READY stage runs of ACTIVE jobs (find_claim_candidates) and due attempts
--      (find_due_attempts), with FOR NO KEY UPDATE SKIP LOCKED. It writes nothing.
--   2. A tenant transaction calls start_attempt: it moves READY -> RUNNING with lease_epoch + 1 and inserts
--      the attempt, which carries the lease. The lease lives on the attempt; the stage run keeps only the
--      fencing counter. A retry (S05) therefore waits for no lease: the failed attempt is terminal in the
--      transaction that moves the run back to READY, and nothing else holds anything.
--   3. postpone_stage_run moves not_before while the run stays READY.
--
-- What this migration adds so that the database enforces the protocol and not only the engine:
--   * stage_runs_guard also refuses (a) a change of not_before except while the run is READY, and (b) any
--     update that keeps the status and changes more than not_before or max_attempts. The postponement is the
--     one update of a stage run, apart from a raised budget, that is not a status move.
--   * A stage run that is not RUNNING (or SUPERSEDED, whose attempts are being cancelled) has no live attempt,
--     checked at commit. S04, S05, S06, S07, S21 and S19 all end the attempt in the same transaction; this
--     is the rule that makes "a retry waits for no lease" a fact of the data.
--   * The limit on attempts counts the attempts since the last human answer (INV-10, guard G_RETRY_ALLOWED).
--     The earlier trigger counted all of them, which would refuse the first attempt after an answer to an
--     escalation. The attempt numbers keep rising; the stage run remembers how many attempts came before the
--     last answer (S13) and the trigger subtracts them.
--   * The facts about an attempt's sandbox only move forward: leaked never goes back to false, and the
--     sandbox id never changes once set (ports: record_sandbox).
--   * The claim index is ordered by (not_before, id), the order find_claim_candidates promises.
--
-- Correction to a comment in an earlier migration (earlier migrations are not edited, see
-- docs/database/migration-safety.md): migration 5 says the claim is FOR UPDATE SKIP LOCKED. It is
-- FOR NO KEY UPDATE SKIP LOCKED (ADR 0007 as revised; the `lease` suite shows why). The catalog comment on
-- the claim index below carries the correct text.
--
-- Expand only: one column with a constant default, one index replaced by a superset, and triggers that are
-- stricter about writes that no deployed code makes.

SET LOCAL lock_timeout = '5s';

-- 1. How many attempts came before the last human answer (S13). Set by the trigger below; no role may write it.
ALTER TABLE stage_runs ADD COLUMN attempts_before_last_answer integer NOT NULL DEFAULT 0;
ALTER TABLE stage_runs ADD CONSTRAINT stage_runs_attempts_before_last_answer_check CHECK (attempts_before_last_answer >= 0);

-- 2. The claim index in the order the port promises, with the tie-break that makes the order total.
CREATE INDEX stage_runs_claim_order_idx ON stage_runs (not_before, id) WHERE status = 'READY';
DROP INDEX stage_runs_claim_idx;
COMMENT ON INDEX stage_runs_claim_order_idx IS
  'find_claim_candidates: READY runs in (not_before, id) order, read with FOR NO KEY UPDATE SKIP LOCKED by the system role (ADR 0014). Replaces stage_runs_claim_idx, which had not_before alone.';

-- 3. The guard on stage run updates (the migration 10 version, extended).
CREATE OR REPLACE FUNCTION stage_runs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  masked text[] := ARRAY['status', 'version', 'updated_at', 'superseded_at'];
  postponement text[] := ARRAY['not_before', 'max_attempts', 'version', 'updated_at'];
BEGIN
  IF EXISTS (SELECT 1 FROM public.state_machine_states s
              WHERE s.machine = 'stage_run' AND s.status = OLD.status AND s.is_terminal) THEN
    IF NEW.status IS DISTINCT FROM OLD.status
       AND EXISTS (SELECT 1
                     FROM public.state_machine_edges e
                     JOIN public.state_machine_transitions t ON t.machine = e.machine AND t.transition_id = e.transition_id
                    WHERE e.machine = 'stage_run' AND e.from_status = OLD.status
                      AND t.event = 'supersede' AND t.to_status = NEW.status)
       AND (to_jsonb(NEW) - masked) = (to_jsonb(OLD) - masked) THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'stage run % is % and terminal: it cannot be edited except to become SUPERSEDED from a state that allows it (PASSED or SKIPPED)', OLD.id, OLD.status
      USING ERRCODE = '23514', CONSTRAINT = 'stage_runs_terminal_is_immutable', TABLE = 'stage_runs';
  END IF;

  IF NEW.lease_epoch IS DISTINCT FROM OLD.lease_epoch THEN
    IF NOT (OLD.status = 'READY' AND NEW.status = 'RUNNING' AND NEW.lease_epoch = OLD.lease_epoch + 1) THEN
      RAISE EXCEPTION 'lease_epoch may only rise by one, together with READY to RUNNING (% to %, epoch % to %)',
        OLD.status, NEW.status, OLD.lease_epoch, NEW.lease_epoch
        USING ERRCODE = '23514', CONSTRAINT = 'stage_runs_lease_epoch_moves_with_claim', TABLE = 'stage_runs';
    END IF;
  ELSIF OLD.status = 'READY' AND NEW.status = 'RUNNING' THEN
    RAISE EXCEPTION 'claiming a stage run must raise lease_epoch by one'
      USING ERRCODE = '23514', CONSTRAINT = 'stage_runs_lease_epoch_moves_with_claim', TABLE = 'stage_runs';
  END IF;

  -- A back-off or a postponement is a value of not_before on a run that is READY (S01, S05, S13 and S17 move
  -- into READY with one; postpone_stage_run changes it while the run stays READY). Anywhere else it is a bug.
  IF NEW.not_before IS DISTINCT FROM OLD.not_before AND NEW.status <> 'READY' THEN
    RAISE EXCEPTION 'not_before may only change on a run that is READY (% to %)', OLD.status, NEW.status
      USING ERRCODE = '23514', CONSTRAINT = 'stage_runs_not_before_only_when_ready', TABLE = 'stage_runs';
  END IF;

  -- The only updates that keep the status are the postponement of a READY run (not_before) and a raised budget
  -- (max_attempts, an approver's decision; the application role has that column grant). Nothing else changes
  -- without a status move.
  IF NEW.status = OLD.status AND (to_jsonb(NEW) - postponement) <> (to_jsonb(OLD) - postponement) THEN
    RAISE EXCEPTION 'a stage run changes through a status move; the updates that keep the status move not_before while READY, or change max_attempts'
      USING ERRCODE = '23514', CONSTRAINT = 'stage_runs_update_is_a_move_or_a_postponement', TABLE = 'stage_runs';
  END IF;

  -- The attempts used since the last human answer start counting again at S13 (WAITING_FOR_HUMAN -> READY).
  IF OLD.status = 'WAITING_FOR_HUMAN' AND NEW.status = 'READY' THEN
    NEW.attempts_before_last_answer := (SELECT coalesce(max(a.attempt_number), 0)
                                          FROM public.attempts a
                                         WHERE a.tenant_id = NEW.tenant_id AND a.stage_run_id = NEW.id);
  ELSIF NEW.attempts_before_last_answer IS DISTINCT FROM OLD.attempts_before_last_answer THEN
    RAISE EXCEPTION 'attempts_before_last_answer is set by the database when a human answer moves the run to READY'
      USING ERRCODE = '23514', CONSTRAINT = 'stage_runs_answer_window_is_derived', TABLE = 'stage_runs';
  END IF;
  RETURN NEW;
END
$$;

-- 4. The attempt limit counts the attempts since the last human answer.
CREATE OR REPLACE FUNCTION attempts_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  limit_attempts smallint;
  window_start integer;
  previous integer;
BEGIN
  SELECT s.max_attempts, s.attempts_before_last_answer INTO limit_attempts, window_start
    FROM public.stage_runs s WHERE s.tenant_id = NEW.tenant_id AND s.id = NEW.stage_run_id;
  SELECT coalesce(max(a.attempt_number), 0) INTO previous
    FROM public.attempts a WHERE a.tenant_id = NEW.tenant_id AND a.stage_run_id = NEW.stage_run_id;
  IF NEW.attempt_number <> previous + 1 THEN
    RAISE EXCEPTION 'attempt_number must be % (the next one), not %', previous + 1, NEW.attempt_number
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_numbered_in_sequence', TABLE = 'attempts';
  END IF;
  IF NEW.attempt_number - window_start > limit_attempts THEN
    RAISE EXCEPTION 'stage run allows % attempts since the last human answer, this would be number % (the window starts after attempt %)',
      limit_attempts, NEW.attempt_number, window_start
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_within_stage_run_limit', TABLE = 'attempts';
  END IF;
  RETURN NEW;
END
$$;

-- 5. Sandbox facts only move forward (the earlier guard is migration 5; this adds two rules to it).
CREATE OR REPLACE FUNCTION attempts_update_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  masked text[] := ARRAY['version', 'updated_at', 'sandbox_id', 'sandbox_leaked'];
BEGIN
  IF NEW.lease_epoch IS DISTINCT FROM OLD.lease_epoch THEN
    RAISE EXCEPTION 'the lease epoch of an attempt never changes'
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_lease_epoch_is_fixed', TABLE = 'attempts';
  END IF;
  IF OLD.sandbox_leaked AND NOT NEW.sandbox_leaked THEN
    RAISE EXCEPTION 'a sandbox that was recorded as leaked cannot be recorded as gone by a later write'
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_sandbox_leaked_only_rises', TABLE = 'attempts';
  END IF;
  IF OLD.sandbox_id IS NOT NULL AND NEW.sandbox_id IS DISTINCT FROM OLD.sandbox_id THEN
    RAISE EXCEPTION 'an attempt has one sandbox; its id cannot change once recorded'
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_sandbox_id_is_fixed', TABLE = 'attempts';
  END IF;
  IF EXISTS (SELECT 1 FROM public.state_machine_states s
              WHERE s.machine = 'attempt' AND s.status = OLD.status AND s.is_terminal)
     AND (to_jsonb(NEW) - masked) <> (to_jsonb(OLD) - masked) THEN
    RAISE EXCEPTION 'attempt % is % and terminal: only sandbox teardown facts can still be recorded', OLD.id, OLD.status
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_terminal_is_immutable', TABLE = 'attempts';
  END IF;
  RETURN NEW;
END
$$;

-- 5b. The epoch check of migration 5 judged the row as it was when the event was queued. A transaction that
--     creates an attempt, ends it and starts the run again (a recovery that does several steps at once, or a
--     test) failed at commit for an attempt that is no longer live. It now reads the row as it stands at
--     commit. The rule is the same: a live attempt holds the run's current epoch.
CREATE OR REPLACE FUNCTION attempts_epoch_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  now_status text;
  now_epoch bigint;
  current_epoch bigint;
BEGIN
  SELECT a.status, a.lease_epoch INTO now_status, now_epoch
    FROM public.attempts a WHERE a.tenant_id = NEW.tenant_id AND a.id = NEW.id;
  IF now_status IN ('STARTING', 'RUNNING', 'CANCELLING') THEN
    SELECT s.lease_epoch INTO current_epoch
      FROM public.stage_runs s WHERE s.tenant_id = NEW.tenant_id AND s.id = NEW.stage_run_id;
    IF now_epoch IS DISTINCT FROM current_epoch THEN
      RAISE EXCEPTION 'attempt % holds lease epoch % but the stage run is at epoch %', NEW.id, now_epoch, current_epoch
        USING ERRCODE = '23514', CONSTRAINT = 'attempts_live_attempt_has_current_epoch', TABLE = 'attempts';
    END IF;
  END IF;
  RETURN NULL;
END
$$;

-- 6. A stage run that is not RUNNING has no live attempt, checked at commit so that the statements of one
--    decision can come in any order. Two triggers, one function: moving the run, and making an attempt live.
--    SUPERSEDED is exempt because superseding a run asks its attempts to cancel and they take their grace
--    period to do it (state-machine.json, S20).
CREATE FUNCTION stage_run_live_attempt_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  run_tenant uuid;
  run_id uuid;
  run_status text;
BEGIN
  IF TG_TABLE_NAME = 'attempts' THEN
    IF NEW.status NOT IN ('STARTING', 'RUNNING', 'CANCELLING') THEN
      RETURN NULL;
    END IF;
    run_tenant := NEW.tenant_id;
    run_id := NEW.stage_run_id;
  ELSE
    run_tenant := NEW.tenant_id;
    run_id := NEW.id;
  END IF;
  SELECT s.status INTO run_status FROM public.stage_runs s WHERE s.tenant_id = run_tenant AND s.id = run_id;
  IF run_status IS NULL OR run_status IN ('RUNNING', 'SUPERSEDED') THEN
    RETURN NULL;
  END IF;
  IF EXISTS (SELECT 1 FROM public.attempts a
              WHERE a.tenant_id = run_tenant AND a.stage_run_id = run_id AND a.status IN ('STARTING', 'RUNNING', 'CANCELLING')) THEN
    RAISE EXCEPTION 'stage run % is % but still has a live attempt: end the attempt in the same transaction as the move', run_id, run_status
      USING ERRCODE = '23514', CONSTRAINT = 'stage_runs_live_attempt_needs_running_run', TABLE = 'stage_runs';
  END IF;
  RETURN NULL;
END
$$;
CREATE CONSTRAINT TRIGGER stage_runs_live_attempt_check AFTER INSERT OR UPDATE OF status ON stage_runs
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stage_run_live_attempt_check();
CREATE CONSTRAINT TRIGGER attempts_live_attempt_check AFTER INSERT OR UPDATE OF status ON attempts
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION stage_run_live_attempt_check();
