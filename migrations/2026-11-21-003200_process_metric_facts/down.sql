-- Takes back the facts of the process metrics. The history the two tables and the four columns held is lost.
ALTER POLICY tenant_isolation ON attempts TO factory_app;
ALTER POLICY tenant_isolation ON task_nodes TO factory_app;
REVOKE SELECT ON task_nodes, attempts FROM factory_api_app;

DROP TABLE IF EXISTS pull_requests;
DROP FUNCTION IF EXISTS pull_requests_guard();
DROP TABLE IF EXISTS task_runs;

ALTER TABLE attempts DROP CONSTRAINT IF EXISTS attempts_metered_needs_an_end;
ALTER TABLE attempts DROP CONSTRAINT IF EXISTS attempts_metered_check;
ALTER TABLE attempts DROP COLUMN IF EXISTS model_requests;
ALTER TABLE attempts DROP COLUMN IF EXISTS cost_micro_usd;
ALTER TABLE attempts DROP COLUMN IF EXISTS output_tokens;
ALTER TABLE attempts DROP COLUMN IF EXISTS input_tokens;
