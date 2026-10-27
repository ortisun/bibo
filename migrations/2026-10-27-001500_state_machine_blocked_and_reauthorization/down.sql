DELETE FROM state_machine_edges WHERE machine = 'stage_run' AND transition_id IN ('S21', 'S22');
DELETE FROM state_machine_transitions WHERE machine = 'stage_run' AND transition_id IN ('S21', 'S22');
