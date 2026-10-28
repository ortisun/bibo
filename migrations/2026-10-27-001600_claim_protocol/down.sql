DROP TRIGGER attempts_live_attempt_check ON attempts;
DROP TRIGGER stage_runs_live_attempt_check ON stage_runs;
DROP FUNCTION stage_run_live_attempt_check();

-- The functions as migrations 5 and 10 left them.
CREATE OR REPLACE FUNCTION attempts_epoch_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  current_epoch bigint;
BEGIN
  IF NEW.status IN ('STARTING', 'RUNNING', 'CANCELLING') THEN
    SELECT s.lease_epoch INTO current_epoch
      FROM public.stage_runs s WHERE s.tenant_id = NEW.tenant_id AND s.id = NEW.stage_run_id;
    IF NEW.lease_epoch IS DISTINCT FROM current_epoch THEN
      RAISE EXCEPTION 'attempt % holds lease epoch % but the stage run is at epoch %', NEW.id, NEW.lease_epoch, current_epoch
        USING ERRCODE = '23514', CONSTRAINT = 'attempts_live_attempt_has_current_epoch', TABLE = 'attempts';
    END IF;
  END IF;
  RETURN NULL;
END
$$;

CREATE OR REPLACE FUNCTION attempts_update_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  masked text[] := ARRAY['version', 'updated_at', 'sandbox_id', 'sandbox_leaked'];
BEGIN
  IF NEW.lease_epoch IS DISTINCT FROM OLD.lease_epoch THEN
    RAISE EXCEPTION 'the lease epoch of an attempt never changes'
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_lease_epoch_is_fixed', TABLE = 'attempts';
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

CREATE OR REPLACE FUNCTION attempts_insert_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  limit_attempts smallint;
  previous integer;
BEGIN
  SELECT s.max_attempts INTO limit_attempts
    FROM public.stage_runs s WHERE s.tenant_id = NEW.tenant_id AND s.id = NEW.stage_run_id;
  SELECT coalesce(max(a.attempt_number), 0) INTO previous
    FROM public.attempts a WHERE a.tenant_id = NEW.tenant_id AND a.stage_run_id = NEW.stage_run_id;
  IF NEW.attempt_number <> previous + 1 THEN
    RAISE EXCEPTION 'attempt_number must be % (the next one), not %', previous + 1, NEW.attempt_number
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_numbered_in_sequence', TABLE = 'attempts';
  END IF;
  IF NEW.attempt_number > limit_attempts THEN
    RAISE EXCEPTION 'stage run allows % attempts, this would be number %', limit_attempts, NEW.attempt_number
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_within_stage_run_limit', TABLE = 'attempts';
  END IF;
  RETURN NEW;
END
$$;

CREATE OR REPLACE FUNCTION stage_runs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  masked text[] := ARRAY['status', 'version', 'updated_at', 'superseded_at'];
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
  RETURN NEW;
END
$$;

CREATE INDEX stage_runs_claim_idx ON stage_runs (not_before) WHERE status = 'READY';
DROP INDEX stage_runs_claim_order_idx;
ALTER TABLE stage_runs DROP CONSTRAINT stage_runs_attempts_before_last_answer_check;
ALTER TABLE stage_runs DROP COLUMN attempts_before_last_answer;
