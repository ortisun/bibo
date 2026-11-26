-- ADR 0038: a lease renewal leaves the version of the attempt where it is.
--
-- bump_guard refuses any update that does not raise the version by exactly one, so a heartbeat
-- (AttemptOps::heartbeat) raised attempts.version. A cancel moves the running attempt with a compare
-- and swap on the version it read. A heartbeat that committed between that read and the move made
-- the cancel fail, and under load the cancel never got through (the liveness test of the worker).
--
-- The version counts changes of state. The lease has its own fences: the owner and the epoch, and
-- for the sweeper the database clock in the same UPDATE (lease_expires_at < now()). So, as
-- jobs_bump_guard does for the ledger head (migration 17), attempts_bump_guard lets an update that
-- changes only lease_expires_at and last_heartbeat_at keep the version. A raise by one is still
-- accepted, which is the renewal of the earlier code. Every other update must still raise the
-- version by exactly one, and an update that changes nothing must still raise it.
--
-- Compatible with the earlier code: no row and no column changes, and its renewal still runs. The
-- down script puts bump_guard back.

SET LOCAL lock_timeout = '5s';

CREATE FUNCTION attempts_bump_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  lease_columns text[] := ARRAY['lease_expires_at', 'last_heartbeat_at', 'version', 'updated_at'];
BEGIN
  IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
    IF NOT (NEW.version IS NOT DISTINCT FROM OLD.version
            AND NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at
            AND (to_jsonb(NEW) - lease_columns) = (to_jsonb(OLD) - lease_columns)) THEN
      RAISE EXCEPTION 'attempts version must rise by exactly one (was %, update set %), or stay when only the lease is renewed', OLD.version, NEW.version
        USING ERRCODE = '23514', CONSTRAINT = 'attempts_version_bump', TABLE = 'attempts';
    END IF;
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

DROP TRIGGER attempts_bump ON attempts;
CREATE TRIGGER attempts_bump BEFORE UPDATE ON attempts FOR EACH ROW EXECUTE FUNCTION attempts_bump_guard();
