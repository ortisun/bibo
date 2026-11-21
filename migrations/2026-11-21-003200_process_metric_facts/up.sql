-- The facts four process metrics need (ADR 0029, docs/architecture/process-metrics-and-improvement.md, section
-- "Where the facts of query version 2 are stored"; the operations are ports v1.5, docs/architecture/ports-v1.5.md):
--
--   1. attempts: four columns   What the model broker metered for the token of the attempt: input tokens, output
--                               tokens, cost in millionths of a US dollar and the number of model requests. Written
--                               by the move that ends the attempt (AttemptEnd::metered). Until now only the cost was
--                               kept, in the payload of an outbox event.
--   2. task_runs                One row for each time an attempt ran the builder on a task node: the runtime, the
--                               model and the tier the router chose, and what the broker metered for that run.
--   3. pull_requests            One row for each pull request a delivery stage opened, and what became of it: merged
--                               or closed without a merge, with the time the code host gives and the time the
--                               factory recorded it. The factory never merges, so a step of the worker reads the fate.
--   4. The API reads four more tables: task_nodes, attempts, task_runs and pull_requests. The process snapshot
--                               (GET /v1/process-metrics/snapshot) runs in the API and reads them.
--
-- "Not known" is NULL and is never zero. The four metered columns are NULL together when the meter was not read
-- (the sweeper ended the attempt, or the broker could not be reached). A value is at most 2^53 - 1
-- (9007199254740991), the valid range of a count and of an amount of money in the metrics.
--
-- Expand only: nullable columns and new tables. Code of the version before writes none of them and reads none of
-- them, and still works (docs/database/migration-safety.md, "Version N-1 code on version N schema").

SET LOCAL lock_timeout = '5s';

-- 1. What an attempt used. The constraints are validated in this transaction: the columns are new and empty, so
--    the scan finds nothing to refuse, and Diesel holds the lock of ADD CONSTRAINT to the commit either way
--    (finding REG-7).
ALTER TABLE attempts ADD COLUMN input_tokens bigint;
ALTER TABLE attempts ADD COLUMN output_tokens bigint;
ALTER TABLE attempts ADD COLUMN cost_micro_usd bigint;
ALTER TABLE attempts ADD COLUMN model_requests bigint;
ALTER TABLE attempts ADD CONSTRAINT attempts_metered_check CHECK (
  (input_tokens IS NULL AND output_tokens IS NULL AND cost_micro_usd IS NULL AND model_requests IS NULL)
  OR (input_tokens IS NOT NULL AND output_tokens IS NOT NULL AND cost_micro_usd IS NOT NULL
      AND model_requests IS NOT NULL
      AND input_tokens BETWEEN 0 AND 9007199254740991
      AND output_tokens BETWEEN 0 AND 9007199254740991
      AND cost_micro_usd BETWEEN 0 AND 9007199254740991
      AND model_requests BETWEEN 0 AND 9007199254740991));
-- Only an attempt that has ended has a metered use. The terminal guard of the table (attempts_update_guard) then
-- keeps it: a terminal row takes no change but the facts of its sandbox.
ALTER TABLE attempts ADD CONSTRAINT attempts_metered_needs_an_end CHECK (input_tokens IS NULL OR ended_at IS NOT NULL);

GRANT UPDATE (input_tokens, output_tokens, cost_micro_usd, model_requests) ON attempts TO factory_app;
-- Counts and an amount computed by the broker: operational (docs/database/observer-columns.txt).
GRANT SELECT (input_tokens, output_tokens, cost_micro_usd, model_requests) ON attempts TO factory_observer;

-- 2. The runs of a task. The two foreign keys share the stage run, so the task node and the attempt belong to the
--    same stage run of the same job and tenant.
CREATE TABLE task_runs (
  tenant_id      uuid NOT NULL REFERENCES tenants (id),
  task_node_id   uuid NOT NULL,
  attempt_id     uuid NOT NULL,
  job_id         uuid NOT NULL,
  stage_run_id   uuid NOT NULL,
  -- The runtime and the model as the routing policy names them, and the tier of the route.
  runtime        text NOT NULL CHECK (runtime ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
  model          text NOT NULL CHECK (length(model) BETWEEN 1 AND 200),
  model_tier     text NOT NULL CHECK (model_tier IN ('small', 'standard', 'large')),
  input_tokens   bigint,
  output_tokens  bigint,
  cost_micro_usd bigint,
  model_requests bigint,
  recorded_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, task_node_id, attempt_id),
  FOREIGN KEY (tenant_id, stage_run_id, task_node_id) REFERENCES task_nodes (tenant_id, stage_run_id, id),
  FOREIGN KEY (tenant_id, job_id, stage_run_id, attempt_id) REFERENCES attempts (tenant_id, job_id, stage_run_id, id),
  CONSTRAINT task_runs_metered_check CHECK (
    (input_tokens IS NULL AND output_tokens IS NULL AND cost_micro_usd IS NULL AND model_requests IS NULL)
    OR (input_tokens IS NOT NULL AND output_tokens IS NOT NULL AND cost_micro_usd IS NOT NULL
        AND model_requests IS NOT NULL
        AND input_tokens BETWEEN 0 AND 9007199254740991
        AND output_tokens BETWEEN 0 AND 9007199254740991
        AND cost_micro_usd BETWEEN 0 AND 9007199254740991
        AND model_requests BETWEEN 0 AND 9007199254740991))
);
CREATE INDEX task_runs_stage_run_idx ON task_runs (tenant_id, stage_run_id, recorded_at, attempt_id);

-- A row is written once: no UPDATE and no DELETE for anyone.
GRANT SELECT, INSERT ON task_runs TO factory_app;
GRANT SELECT (tenant_id, task_node_id, attempt_id, job_id, stage_run_id, runtime, model, model_tier, input_tokens,
              output_tokens, cost_micro_usd, model_requests, recorded_at)
  ON task_runs TO factory_observer;

-- 3. The pull requests the factory opened. The key is the repository and the number: a job can open a second one
--    when a person closed the first and the work was sent back.
CREATE TABLE pull_requests (
  tenant_id        uuid NOT NULL REFERENCES tenants (id),
  repository_id    uuid NOT NULL,
  pr_number        bigint NOT NULL CHECK (pr_number BETWEEN 1 AND 9007199254740991),
  job_id           uuid NOT NULL,
  -- When the factory recorded that it was opened, by the database clock.
  opened_at        timestamptz NOT NULL DEFAULT now(),
  fate             text NOT NULL DEFAULT 'open' CHECK (fate IN ('open', 'merged', 'closed')),
  -- When it was merged or closed, as the code host says.
  decided_at       timestamptz,
  -- When the factory recorded the fate, by the database clock. A window of a snapshot is cut by this time.
  fate_recorded_at timestamptz,
  -- When the factory last asked the code host about it, whatever the answer.
  last_checked_at  timestamptz,
  PRIMARY KEY (tenant_id, repository_id, pr_number),
  FOREIGN KEY (tenant_id, job_id) REFERENCES jobs (tenant_id, id),
  FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories (tenant_id, id),
  CONSTRAINT pull_requests_fate_has_its_times CHECK (
    (fate = 'open' AND decided_at IS NULL AND fate_recorded_at IS NULL)
    OR (fate <> 'open' AND decided_at IS NOT NULL AND fate_recorded_at IS NOT NULL))
);
CREATE INDEX pull_requests_job_idx ON pull_requests (tenant_id, job_id, opened_at, pr_number);
-- The worker's pass: the open ones, the longest wait first. Partial, so it holds only what is still followed.
CREATE INDEX pull_requests_to_check_idx ON pull_requests (tenant_id, last_checked_at NULLS FIRST, opened_at)
  WHERE fate = 'open';

-- The first decision is final, and what identifies the row never changes. The application sets the fate with a
-- statement that names `fate = 'open'`; this is the last line, for a statement that does not.
CREATE FUNCTION pull_requests_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.repository_id IS DISTINCT FROM OLD.repository_id
     OR NEW.pr_number IS DISTINCT FROM OLD.pr_number OR NEW.job_id IS DISTINCT FROM OLD.job_id
     OR NEW.opened_at IS DISTINCT FROM OLD.opened_at THEN
    RAISE EXCEPTION 'the identity of a pull request record never changes'
      USING ERRCODE = '23514', CONSTRAINT = 'pull_requests_identity_is_fixed', TABLE = 'pull_requests';
  END IF;
  IF OLD.fate <> 'open'
     AND (NEW.fate IS DISTINCT FROM OLD.fate OR NEW.decided_at IS DISTINCT FROM OLD.decided_at
          OR NEW.fate_recorded_at IS DISTINCT FROM OLD.fate_recorded_at) THEN
    RAISE EXCEPTION 'pull request % of repository % is %: the first decision is final', OLD.pr_number,
                    OLD.repository_id, OLD.fate
      USING ERRCODE = '23514', CONSTRAINT = 'pull_requests_fate_is_final', TABLE = 'pull_requests';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER pull_requests_guard BEFORE UPDATE ON pull_requests FOR EACH ROW EXECUTE FUNCTION pull_requests_guard();

GRANT SELECT, INSERT ON pull_requests TO factory_app;
GRANT UPDATE (fate, decided_at, fate_recorded_at, last_checked_at) ON pull_requests TO factory_app;
-- Identifiers, a number, a closed set of states and times: operational.
GRANT SELECT (tenant_id, repository_id, pr_number, job_id, opened_at, fate, decided_at, fate_recorded_at,
              last_checked_at)
  ON pull_requests TO factory_observer;

DO $$
DECLARE
  tenant_table text;
BEGIN
  FOREACH tenant_table IN ARRAY ARRAY['task_runs', 'pull_requests'] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format($policy$
      CREATE POLICY tenant_isolation ON public.%I
        AS PERMISSIVE FOR ALL TO factory_app, factory_api_app
        USING (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid)
    $policy$, tenant_table);
    EXECUTE format(
      'CREATE POLICY observer_read ON public.%I AS PERMISSIVE FOR SELECT TO factory_observer USING (true)',
      tenant_table);
  END LOOP;
END
$$;

-- 4. The API reads what the process snapshot needs. Migration 2026-10-28-002000 made the API's group narrow on
--    the write side (finding API-3); migration 2026-10-29-002300 added three tables to read, for the evidence a
--    person sees. These are four more, SELECT and nothing else: the login still updates nothing and deletes
--    nothing, and row-level security holds it to the tenant its transaction named. The snapshot it serves holds
--    totals and medians only. The suite api_privileges lists the grants both ways.
GRANT SELECT ON task_nodes, attempts, task_runs, pull_requests TO factory_api_app;
ALTER POLICY tenant_isolation ON task_nodes TO factory_app, factory_api_app;
ALTER POLICY tenant_isolation ON attempts TO factory_app, factory_api_app;
