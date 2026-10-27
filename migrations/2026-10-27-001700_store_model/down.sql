DROP TRIGGER jobs_bump ON jobs;
CREATE TRIGGER jobs_bump BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION bump_guard();
DROP FUNCTION jobs_bump_guard();

ALTER TABLE task_nodes DROP CONSTRAINT task_nodes_commit_iff_succeeded;
ALTER TABLE task_nodes DROP CONSTRAINT task_nodes_idle_has_no_attempt;
ALTER TABLE task_nodes DROP CONSTRAINT task_nodes_running_has_attempt;

DROP TRIGGER repositories_attestation_guard ON repositories;
DROP FUNCTION repositories_attestation_guard();
REVOKE UPDATE (bypass_attested_by_principal_id, bypass_attested_at) ON repositories FROM factory_app;
ALTER TABLE repositories DROP CONSTRAINT repositories_bypass_attested_by_fkey;
ALTER TABLE repositories DROP CONSTRAINT repositories_bypass_attestation_pair;
ALTER TABLE repositories DROP COLUMN bypass_attested_at, DROP COLUMN bypass_attested_by_principal_id;

ALTER TABLE stage_runs DROP CONSTRAINT stage_runs_blocked_has_outcome;
REVOKE UPDATE (failing_set_sha256) ON stage_runs FROM factory_app;
ALTER TABLE stage_runs DROP CONSTRAINT stage_runs_failing_set_needs_failed_outcome;
ALTER TABLE stage_runs DROP CONSTRAINT stage_runs_failing_set_hash_check;
ALTER TABLE stage_runs DROP COLUMN failing_set_sha256;
