-- ADR 0010, decision 2: a skipped stage run satisfies the stages that require it, so it must be
-- supersedable. The skip decision was made on recorded inputs. When an input changes, the engine makes
-- the decision again in a new run, and the old SKIPPED run must not stay in place or it would go on
-- satisfying its dependants while the new run is still PENDING.
--
-- docs/architecture/state-machine.json changed in exactly one way that the database mirrors: the supersede
-- transition S20 gained the source state SKIPPED. The guard names (G_UPSTREAM_PASSED and the others), the
-- actors and the invalidation table are not stored here. The `statuses` test re-derives the three
-- reference tables from the JSON and fails on any difference.
--
-- This is a new migration. Nothing in the earlier ones is amended.

-- 1. The reference row. state_machine_edges is the single place that says which moves are legal, and
--    enforce_status_transition already reads it, so the status trigger accepts the move from here on.
INSERT INTO state_machine_edges (machine, from_status, transition_id) VALUES ('stage_run', 'SKIPPED', 'S20');

-- 2. The terminal-row trigger. The earlier version named PASSED in its body. This one asks the reference
--    data: a terminal run may change only along a supersede edge, and only the status, the version, the
--    update time and the supersede time may differ. A state that the JSON later marks supersedable then
--    needs one INSERT into state_machine_edges and no new function. Everything else that leaves a
--    terminal state stays refused (invariant INV-04).
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
