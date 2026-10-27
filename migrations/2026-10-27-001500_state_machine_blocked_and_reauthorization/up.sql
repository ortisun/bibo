-- ports v1.1 (ADR 0014, decision 8): two new stage run transitions in docs/architecture/state-machine.json.
--
--   S21  RUNNING -> BLOCKED            attempt_blocked          emits stage_run.blocked
--   S22  READY   -> WAITING_FOR_HUMAN  require_reauthorization  emits stage_run.waiting_for_human
--
-- The guard names (G_ENVIRONMENT_BLOCKED, G_REAUTHORIZATION_REQUIRED) and the actors are not stored here,
-- as for every other transition. The `statuses` suite re-derives the three reference tables from the JSON
-- and fails on any difference. Both emitted event names already exist for other transitions, so the outbox
-- needs no change: its foreign key points at (machine, transition_id, emits), and these rows make
-- (stage_run, S21, stage_run.blocked) and (stage_run, S22, stage_run.waiting_for_human) legal events.
--
-- enforce_status_transition reads state_machine_edges, so RUNNING -> BLOCKED and READY -> WAITING_FOR_HUMAN
-- become legal status moves from this migration on. This is an expand step: no row, constraint or column
-- is removed, and code that does not know the two moves never makes them.
--
-- A new migration, as for every change after the baseline. Nothing in the earlier ones is amended.

INSERT INTO state_machine_transitions (machine, transition_id, event, to_status, emits) VALUES
  ('stage_run', 'S21', 'attempt_blocked', 'BLOCKED', 'stage_run.blocked'),
  ('stage_run', 'S22', 'require_reauthorization', 'WAITING_FOR_HUMAN', 'stage_run.waiting_for_human');

INSERT INTO state_machine_edges (machine, from_status, transition_id) VALUES
  ('stage_run', 'RUNNING', 'S21'),
  ('stage_run', 'READY', 'S22');
