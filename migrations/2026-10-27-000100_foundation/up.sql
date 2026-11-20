-- Foundation: the application role, the state machine reference data, and the generic trigger
-- functions that later migrations attach to tables.
--
-- Design notes live in docs/database/. In short:
--   * The application connects as members of factory_app. It does not own any object, is not a
--     superuser and does not bypass row-level security. Its grants are all in the last migration.
--   * The state machine tables below are seeded from docs/architecture/state-machine.json. The
--     `statuses` database test re-derives them from the JSON and fails on any difference.
--   * Trigger functions run with the caller's rights and a fixed search_path. None is SECURITY DEFINER.

-- A schema that anyone can create objects in lets a caller shadow a function name. PostgreSQL 15
-- and later already revoke this. The statement keeps older servers safe too.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Roles are cluster wide. Create the role if the DBA has not already, and refuse to continue if an
-- existing role of that name has powers the design rules out.
DO $$
DECLARE
  r pg_catalog.pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO r FROM pg_catalog.pg_roles WHERE rolname = 'factory_app';
  IF NOT FOUND THEN
    CREATE ROLE factory_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  ELSIF r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication THEN
    RAISE EXCEPTION 'the existing role factory_app has too many powers (superuser, createrole, createdb, replication or bypassrls)';
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO factory_app;

-- ---------------------------------------------------------------------------------------------
-- State machine reference data. Statuses on the tables below are checked with CHECK constraints
-- that carry the same lists. These tables add what a CHECK cannot say: which moves are legal,
-- which states start a row, and which event each move emits.

CREATE TABLE state_machine_states (
  machine     text    NOT NULL CHECK (machine IN ('job', 'stage_run', 'attempt', 'task_node')),
  status      text    NOT NULL CHECK (status ~ '^[A-Z][A-Z_]*$'),
  is_initial  boolean NOT NULL,
  is_terminal boolean NOT NULL,
  PRIMARY KEY (machine, status)
);
-- Exactly one initial state per machine.
CREATE UNIQUE INDEX state_machine_one_initial ON state_machine_states (machine) WHERE is_initial;

CREATE TABLE state_machine_transitions (
  machine       text NOT NULL,
  transition_id text NOT NULL CHECK (transition_id ~ '^[JSAT][0-9]{2}$'),
  event         text NOT NULL,
  to_status     text NOT NULL,
  emits         text CHECK (emits IS NULL OR emits ~ '^[a-z][a-z_]*\.[a-z][a-z_]*$'),
  PRIMARY KEY (machine, transition_id),
  -- The outbox points at (machine, transition_id, emits) so an event cannot name a transition it
  -- does not belong to.
  UNIQUE (machine, transition_id, emits),
  FOREIGN KEY (machine, to_status) REFERENCES state_machine_states (machine, status)
);

CREATE TABLE state_machine_edges (
  machine       text NOT NULL,
  from_status   text NOT NULL,
  transition_id text NOT NULL,
  PRIMARY KEY (machine, from_status, transition_id),
  FOREIGN KEY (machine, from_status) REFERENCES state_machine_states (machine, status),
  FOREIGN KEY (machine, transition_id) REFERENCES state_machine_transitions (machine, transition_id)
);

-- Generated from docs/architecture/state-machine.json (schema_version 1).
INSERT INTO state_machine_states (machine, status, is_initial, is_terminal) VALUES
  ('job', 'RECEIVED', true, false),
  ('job', 'ACTIVE', false, false),
  ('job', 'WAITING_FOR_HUMAN', false, false),
  ('job', 'PAUSED', false, false),
  ('job', 'BLOCKED', false, false),
  ('job', 'CANCELLING', false, false),
  ('job', 'COMPLETED', false, true),
  ('job', 'FAILED', false, true),
  ('job', 'CANCELLED', false, true),
  ('job', 'REJECTED', false, true),
  ('stage_run', 'PENDING', true, false),
  ('stage_run', 'READY', false, false),
  ('stage_run', 'RUNNING', false, false),
  ('stage_run', 'GATING', false, false),
  ('stage_run', 'WAITING_FOR_HUMAN', false, false),
  ('stage_run', 'BLOCKED', false, false),
  ('stage_run', 'PASSED', false, true),
  ('stage_run', 'REWORK_REQUESTED', false, true),
  ('stage_run', 'FAILED', false, true),
  ('stage_run', 'SKIPPED', false, true),
  ('stage_run', 'SUPERSEDED', false, true),
  ('stage_run', 'CANCELLED', false, true),
  ('attempt', 'STARTING', true, false),
  ('attempt', 'RUNNING', false, false),
  ('attempt', 'CANCELLING', false, false),
  ('attempt', 'SUCCEEDED', false, true),
  ('attempt', 'FAILED', false, true),
  ('attempt', 'TIMED_OUT', false, true),
  ('attempt', 'LEASE_LOST', false, true),
  ('attempt', 'CANCELLED', false, true),
  ('task_node', 'PENDING', true, false),
  ('task_node', 'READY', false, false),
  ('task_node', 'RUNNING', false, false),
  ('task_node', 'SUCCEEDED', false, true),
  ('task_node', 'FAILED', false, false),
  ('task_node', 'CANCELLED', false, true);

INSERT INTO state_machine_transitions (machine, transition_id, event, to_status, emits) VALUES
  ('job', 'J01', 'admit', 'ACTIVE', 'job.admitted'),
  ('job', 'J02', 'reject_at_admission', 'REJECTED', 'job.rejected'),
  ('job', 'J03', 'stage_needs_human', 'WAITING_FOR_HUMAN', 'job.waiting_for_human'),
  ('job', 'J04', 'human_wait_resolved', 'ACTIVE', 'job.resumed'),
  ('job', 'J05', 'pause', 'PAUSED', 'job.paused'),
  ('job', 'J06', 'resume', 'ACTIVE', 'job.resumed'),
  ('job', 'J07', 'block', 'BLOCKED', 'job.blocked'),
  ('job', 'J08', 'unblock', 'ACTIVE', 'job.unblocked'),
  ('job', 'J09', 'request_cancel', 'CANCELLING', 'job.cancel_requested'),
  ('job', 'J10', 'cancellation_complete', 'CANCELLED', 'job.cancelled'),
  ('job', 'J11', 'fail_job', 'FAILED', 'job.failed'),
  ('job', 'J12', 'reject_job', 'REJECTED', 'job.rejected'),
  ('job', 'J13', 'complete', 'COMPLETED', 'job.completed'),
  ('stage_run', 'S01', 'preconditions_met', 'READY', 'stage_run.ready'),
  ('stage_run', 'S02', 'mark_not_applicable', 'SKIPPED', 'stage_run.skipped'),
  ('stage_run', 'S03', 'start', 'RUNNING', 'stage_run.started'),
  ('stage_run', 'S04', 'attempt_succeeded', 'GATING', 'stage_run.gating'),
  ('stage_run', 'S05', 'attempt_failed_retryable', 'READY', 'stage_run.retry_scheduled'),
  ('stage_run', 'S06', 'attempt_failed_final', 'FAILED', 'stage_run.failed'),
  ('stage_run', 'S07', 'escalate_to_human', 'WAITING_FOR_HUMAN', 'stage_run.waiting_for_human'),
  ('stage_run', 'S08', 'gate_passed', 'PASSED', 'stage_run.passed'),
  ('stage_run', 'S09', 'gate_requires_rework', 'REWORK_REQUESTED', 'stage_run.rework_requested'),
  ('stage_run', 'S10', 'gate_needs_human', 'WAITING_FOR_HUMAN', 'stage_run.waiting_for_human'),
  ('stage_run', 'S11', 'gate_blocks', 'BLOCKED', 'stage_run.blocked'),
  ('stage_run', 'S12', 'gate_failed_final', 'FAILED', 'stage_run.failed'),
  ('stage_run', 'S13', 'human_answered', 'READY', 'stage_run.ready'),
  ('stage_run', 'S14', 'human_approved', 'PASSED', 'stage_run.passed'),
  ('stage_run', 'S15', 'human_requested_rework', 'REWORK_REQUESTED', 'stage_run.rework_requested'),
  ('stage_run', 'S16', 'human_rejected', 'FAILED', 'stage_run.failed'),
  ('stage_run', 'S17', 'unblocked_rerun', 'READY', 'stage_run.ready'),
  ('stage_run', 'S18', 'override_accepted', 'PASSED', 'stage_run.passed'),
  ('stage_run', 'S19', 'cancel', 'CANCELLED', 'stage_run.cancelled'),
  ('stage_run', 'S20', 'supersede', 'SUPERSEDED', 'stage_run.superseded'),
  ('attempt', 'A01', 'sandbox_ready', 'RUNNING', 'attempt.running'),
  ('attempt', 'A02', 'provision_failed', 'FAILED', 'attempt.failed'),
  ('attempt', 'A03', 'heartbeat', 'RUNNING', NULL),
  ('attempt', 'A04', 'report_success', 'SUCCEEDED', 'attempt.succeeded'),
  ('attempt', 'A05', 'report_failure', 'FAILED', 'attempt.failed'),
  ('attempt', 'A06', 'deadline_exceeded', 'TIMED_OUT', 'attempt.timed_out'),
  ('attempt', 'A07', 'lease_expired', 'LEASE_LOST', 'attempt.lease_lost'),
  ('attempt', 'A08', 'request_cancel', 'CANCELLING', 'attempt.cancel_requested'),
  ('attempt', 'A09', 'teardown_complete', 'CANCELLED', 'attempt.cancelled'),
  ('attempt', 'A10', 'teardown_deadline', 'CANCELLED', 'attempt.cancelled'),
  ('task_node', 'T01', 'dependencies_satisfied', 'READY', 'task_node.ready'),
  ('task_node', 'T02', 'start', 'RUNNING', 'task_node.started'),
  ('task_node', 'T03', 'task_succeeded', 'SUCCEEDED', 'task_node.succeeded'),
  ('task_node', 'T04', 'task_failed', 'FAILED', 'task_node.failed'),
  ('task_node', 'T05', 'attempt_interrupted', 'READY', 'task_node.ready'),
  ('task_node', 'T06', 'retry_task', 'READY', 'task_node.ready'),
  ('task_node', 'T07', 'cancel', 'CANCELLED', 'task_node.cancelled');

INSERT INTO state_machine_edges (machine, from_status, transition_id) VALUES
  ('job', 'RECEIVED', 'J01'),
  ('job', 'RECEIVED', 'J02'),
  ('job', 'ACTIVE', 'J03'),
  ('job', 'WAITING_FOR_HUMAN', 'J04'),
  ('job', 'ACTIVE', 'J05'),
  ('job', 'WAITING_FOR_HUMAN', 'J05'),
  ('job', 'PAUSED', 'J06'),
  ('job', 'ACTIVE', 'J07'),
  ('job', 'BLOCKED', 'J08'),
  ('job', 'ACTIVE', 'J09'),
  ('job', 'WAITING_FOR_HUMAN', 'J09'),
  ('job', 'PAUSED', 'J09'),
  ('job', 'BLOCKED', 'J09'),
  ('job', 'CANCELLING', 'J10'),
  ('job', 'ACTIVE', 'J11'),
  ('job', 'ACTIVE', 'J12'),
  ('job', 'WAITING_FOR_HUMAN', 'J12'),
  ('job', 'ACTIVE', 'J13'),
  ('stage_run', 'PENDING', 'S01'),
  ('stage_run', 'PENDING', 'S02'),
  ('stage_run', 'READY', 'S02'),
  ('stage_run', 'READY', 'S03'),
  ('stage_run', 'RUNNING', 'S04'),
  ('stage_run', 'RUNNING', 'S05'),
  ('stage_run', 'RUNNING', 'S06'),
  ('stage_run', 'RUNNING', 'S07'),
  ('stage_run', 'GATING', 'S08'),
  ('stage_run', 'GATING', 'S09'),
  ('stage_run', 'GATING', 'S10'),
  ('stage_run', 'GATING', 'S11'),
  ('stage_run', 'GATING', 'S12'),
  ('stage_run', 'WAITING_FOR_HUMAN', 'S13'),
  ('stage_run', 'WAITING_FOR_HUMAN', 'S14'),
  ('stage_run', 'WAITING_FOR_HUMAN', 'S15'),
  ('stage_run', 'BLOCKED', 'S15'),
  ('stage_run', 'WAITING_FOR_HUMAN', 'S16'),
  ('stage_run', 'BLOCKED', 'S17'),
  ('stage_run', 'BLOCKED', 'S18'),
  ('stage_run', 'PENDING', 'S19'),
  ('stage_run', 'READY', 'S19'),
  ('stage_run', 'RUNNING', 'S19'),
  ('stage_run', 'GATING', 'S19'),
  ('stage_run', 'WAITING_FOR_HUMAN', 'S19'),
  ('stage_run', 'BLOCKED', 'S19'),
  ('stage_run', 'PENDING', 'S20'),
  ('stage_run', 'READY', 'S20'),
  ('stage_run', 'RUNNING', 'S20'),
  ('stage_run', 'GATING', 'S20'),
  ('stage_run', 'WAITING_FOR_HUMAN', 'S20'),
  ('stage_run', 'BLOCKED', 'S20'),
  ('stage_run', 'PASSED', 'S20'),
  ('attempt', 'STARTING', 'A01'),
  ('attempt', 'STARTING', 'A02'),
  ('attempt', 'RUNNING', 'A03'),
  ('attempt', 'RUNNING', 'A04'),
  ('attempt', 'RUNNING', 'A05'),
  ('attempt', 'STARTING', 'A06'),
  ('attempt', 'RUNNING', 'A06'),
  ('attempt', 'STARTING', 'A07'),
  ('attempt', 'RUNNING', 'A07'),
  ('attempt', 'STARTING', 'A08'),
  ('attempt', 'RUNNING', 'A08'),
  ('attempt', 'CANCELLING', 'A09'),
  ('attempt', 'CANCELLING', 'A10'),
  ('task_node', 'PENDING', 'T01'),
  ('task_node', 'READY', 'T02'),
  ('task_node', 'RUNNING', 'T03'),
  ('task_node', 'RUNNING', 'T04'),
  ('task_node', 'RUNNING', 'T05'),
  ('task_node', 'FAILED', 'T06'),
  ('task_node', 'PENDING', 'T07'),
  ('task_node', 'READY', 'T07'),
  ('task_node', 'RUNNING', 'T07'),
  ('task_node', 'FAILED', 'T07');

-- ---------------------------------------------------------------------------------------------
-- Generic trigger functions. Error conventions, used by every trigger in these migrations:
--   * SQLSTATE 23514 (check_violation) with a CONSTRAINT name: a rule about the data was broken.
--     Diesel reports it as DatabaseErrorKind::CheckViolation, with the constraint name available.
--   * SQLSTATE 42501 (insufficient_privilege): the table is append-only and the statement was a
--     modification. Raised by the second layer behind the missing grant.

-- Applied to every machine table. TG_ARGV[0] is the machine name in state_machine_states.
--   * A new row must start in the machine's initial state.
--   * A status change must follow a legal edge of the machine.
CREATE FUNCTION enforce_status_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  machine_name text := TG_ARGV[0];
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (SELECT 1 FROM public.state_machine_states s
                    WHERE s.machine = machine_name AND s.status = NEW.status AND s.is_initial) THEN
      RAISE EXCEPTION 'a new % row must start in its initial state, not in %', machine_name, NEW.status
        USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_initial_state', TABLE = TG_TABLE_NAME;
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF NOT EXISTS (SELECT 1
                     FROM public.state_machine_edges e
                     JOIN public.state_machine_transitions t
                       ON t.machine = e.machine AND t.transition_id = e.transition_id
                    WHERE e.machine = machine_name AND e.from_status = OLD.status AND t.to_status = NEW.status) THEN
      RAISE EXCEPTION '% % to % is not a legal transition', machine_name, OLD.status, NEW.status
        USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_legal_transition', TABLE = TG_TABLE_NAME;
    END IF;
  END IF;
  RETURN NEW;
END
$$;

-- Applied to every aggregate table with a version column. A row changes only by a compare-and-swap
-- update that raises the version by exactly one. The caller writes `WHERE id = $1 AND version = $2`
-- and sets version = $2 + 1; this trigger refuses an update that forgot to, so a missing bump cannot
-- silently disable the compare-and-swap for the next writer. It also stamps updated_at from the
-- database clock, so a caller cannot back-date a change.
CREATE FUNCTION bump_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
    RAISE EXCEPTION '% version must rise by exactly one (was %, update set %)', TG_TABLE_NAME, OLD.version, NEW.version
      USING ERRCODE = '23514', CONSTRAINT = TG_TABLE_NAME || '_version_bump', TABLE = TG_TABLE_NAME;
  END IF;
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

-- Applied to tables that must never change or shrink once written (BEFORE UPDATE OR DELETE, and
-- BEFORE TRUNCATE at statement level). The first layer is that the application role has no grant.
-- This is the second layer: it also stops the table owner.
CREATE FUNCTION reject_modification() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION '% is append-only: % is not allowed', TG_TABLE_NAME, TG_OP
    USING ERRCODE = '42501', TABLE = TG_TABLE_NAME;
END
$$;
