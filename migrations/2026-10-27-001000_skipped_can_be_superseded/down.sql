-- Reverse of the revision: SKIPPED is terminal again, and only PASSED can become SUPERSEDED.
-- A SKIPPED run that was already superseded stays SUPERSEDED (the status value is still legal), so
-- the data needs no change. The function below is the body of the earlier migration.
DELETE FROM state_machine_edges WHERE machine = 'stage_run' AND from_status = 'SKIPPED' AND transition_id = 'S20';

CREATE OR REPLACE FUNCTION stage_runs_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  masked text[] := ARRAY['status', 'version', 'updated_at', 'superseded_at'];
BEGIN
  IF EXISTS (SELECT 1 FROM public.state_machine_states s
              WHERE s.machine = 'stage_run' AND s.status = OLD.status AND s.is_terminal) THEN
    IF OLD.status = 'PASSED' AND NEW.status = 'SUPERSEDED'
       AND (to_jsonb(NEW) - masked) = (to_jsonb(OLD) - masked) THEN
      RETURN NEW;
    END IF;
    RAISE EXCEPTION 'stage run % is % and terminal: it cannot be edited except PASSED to SUPERSEDED', OLD.id, OLD.status
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
