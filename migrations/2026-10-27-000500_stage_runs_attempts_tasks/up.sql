-- Stage runs, attempts with leases, and the task graph.
--
-- Concurrency model (ADR 0001 and 0007):
--   * every row has a version; a writer updates with `WHERE id = $1 AND version = $2` and sets
--     version = $2 + 1. bump_guard refuses an update that does not raise the version by one;
--   * claiming work is `SELECT ... FOR UPDATE SKIP LOCKED` on READY stage runs, then READY to RUNNING
--     with lease_epoch + 1, then an attempt row. Two safety nets sit under that code: a partial
--     unique index allows one active attempt per stage run, and the lease epoch can only move
--     with the READY to RUNNING transition;
--   * a worker's write names its lease epoch and is rejected when the epoch is not current;
--   * lease expiry and deadlines are compared with now() inside the query, never with a worker clock.

CREATE TABLE stage_runs (
  tenant_id       uuid     NOT NULL REFERENCES tenants (id),
  id              uuid     NOT NULL,
  job_id          uuid     NOT NULL,
  stage_kind      text     NOT NULL,
  -- Rework creates a new run of the same kind; it never reopens an old one.
  run_number      integer  NOT NULL,
  status          text     NOT NULL DEFAULT 'PENDING',
  version         bigint   NOT NULL DEFAULT 1,
  -- Fencing counter. Raised by one each time the run goes READY to RUNNING. Attempts carry the
  -- epoch they were granted at.
  lease_epoch     bigint   NOT NULL DEFAULT 0,
  max_attempts    smallint NOT NULL DEFAULT 3,
  -- The earliest time this run may be claimed. A retry back-off is a later value here.
  not_before      timestamptz NOT NULL DEFAULT now(),
  -- The run this one replaced after a rework request.
  rework_of_stage_run_id uuid,
  stage_contract_sha256  text,
  -- Recorded in the same transaction as the status change (invariant INV-03).
  gate_outcome           text,
  gate_report_sha256     text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  finished_at     timestamptz,
  superseded_at   timestamptz,
  PRIMARY KEY (tenant_id, id),
  -- Targets for foreign keys that must agree with the run on the job.
  UNIQUE (tenant_id, job_id, id),
  UNIQUE (tenant_id, job_id, stage_kind, run_number),
  FOREIGN KEY (tenant_id, job_id) REFERENCES jobs (tenant_id, id),
  FOREIGN KEY (tenant_id, job_id, rework_of_stage_run_id) REFERENCES stage_runs (tenant_id, job_id, id),
  FOREIGN KEY (tenant_id, stage_contract_sha256) REFERENCES artifacts (tenant_id, content_sha256),
  FOREIGN KEY (tenant_id, gate_report_sha256) REFERENCES artifacts (tenant_id, content_sha256),
  CONSTRAINT stage_runs_status_check CHECK (status IN (
    'PENDING', 'READY', 'RUNNING', 'GATING', 'WAITING_FOR_HUMAN', 'BLOCKED',
    'PASSED', 'REWORK_REQUESTED', 'FAILED', 'SKIPPED', 'SUPERSEDED', 'CANCELLED')),
  CONSTRAINT stage_runs_stage_kind_check CHECK (stage_kind IN (
    'INTAKE', 'REPOSITORY_INTELLIGENCE', 'SPECIFICATION', 'DOMAIN_DISCOVERY', 'ARCHITECTURE',
    'TASK_PLANNING', 'IMPLEMENTATION', 'VALIDATION', 'REVIEW', 'DOCUMENTING',
    'DOCUMENTATION_REVIEW', 'DELIVERY', 'APPROVAL', 'MERGE')),
  CONSTRAINT stage_runs_run_number_check CHECK (run_number >= 1),
  CONSTRAINT stage_runs_version_check CHECK (version >= 1),
  CONSTRAINT stage_runs_lease_epoch_check CHECK (lease_epoch >= 0),
  CONSTRAINT stage_runs_max_attempts_check CHECK (max_attempts BETWEEN 1 AND 20),
  CONSTRAINT stage_runs_gate_outcome_check CHECK (
    gate_outcome IS NULL OR gate_outcome IN ('PASSED', 'FAILED', 'BLOCKED', 'NOT_APPLICABLE')),
  CONSTRAINT stage_runs_hashes_check CHECK (
    (stage_contract_sha256 IS NULL OR stage_contract_sha256 ~ '^sha256:[0-9a-f]{64}$')
    AND (gate_report_sha256 IS NULL OR gate_report_sha256 ~ '^sha256:[0-9a-f]{64}$')),
  -- Terminal states are taken from state-machine.json.
  CONSTRAINT stage_runs_terminal_check CHECK (
    (status IN ('PASSED', 'REWORK_REQUESTED', 'FAILED', 'SKIPPED', 'SUPERSEDED', 'CANCELLED'))
    = (finished_at IS NOT NULL)),
  CONSTRAINT stage_runs_superseded_check CHECK ((status = 'SUPERSEDED') = (superseded_at IS NOT NULL)),
  -- A run passes on a gate outcome. PASSED after an override keeps the gate outcome BLOCKED (S18).
  -- IS NOT NULL is spelled out: a CHECK accepts NULL, and `false OR NULL` is NULL.
  CONSTRAINT stage_runs_passed_has_outcome CHECK (status <> 'PASSED' OR (gate_outcome IS NOT NULL AND gate_outcome IN ('PASSED', 'BLOCKED'))),
  CONSTRAINT stage_runs_skipped_has_outcome CHECK (status <> 'SKIPPED' OR (gate_outcome IS NOT NULL AND gate_outcome = 'NOT_APPLICABLE'))
);
-- The claim query: READY runs ordered by availability. Not tenant scoped on purpose: the engine
-- claims across tenants under the system scope (ports: Store::begin_system).
CREATE INDEX stage_runs_claim_idx ON stage_runs (not_before) WHERE status = 'READY';

-- Rules that depend on the old row. Terminal runs are frozen (invariant INV-04) except for the one
-- supersede move; the lease epoch moves only with a claim.
CREATE FUNCTION stage_runs_guard() RETURNS trigger
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

CREATE TRIGGER stage_runs_bump BEFORE UPDATE ON stage_runs FOR EACH ROW EXECUTE FUNCTION bump_guard();
CREATE TRIGGER stage_runs_guard BEFORE UPDATE ON stage_runs FOR EACH ROW EXECUTE FUNCTION stage_runs_guard();
CREATE TRIGGER stage_runs_status_machine BEFORE INSERT OR UPDATE ON stage_runs
  FOR EACH ROW EXECUTE FUNCTION enforce_status_transition('stage_run');

-- Now that stage runs exist, tie the artifact's creating run to a run of the same tenant and job.
ALTER TABLE artifacts
  ADD CONSTRAINT artifacts_created_by_stage_run_fk
  FOREIGN KEY (tenant_id, created_by_job_id, created_by_stage_run_id)
  REFERENCES stage_runs (tenant_id, job_id, id);

-- Which artifacts a run consumed and produced, by hash. When an input changes, the runs that
-- consumed the old hash are the ones to supersede (state-machine.json, invalidation_rules).
CREATE TABLE stage_run_artifacts (
  tenant_id      uuid NOT NULL REFERENCES tenants (id),
  job_id         uuid NOT NULL,
  stage_run_id   uuid NOT NULL,
  direction      text NOT NULL CHECK (direction IN ('input', 'output')),
  role           text NOT NULL CHECK (role ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
  content_sha256 text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, stage_run_id, direction, role),
  FOREIGN KEY (tenant_id, job_id, stage_run_id) REFERENCES stage_runs (tenant_id, job_id, id),
  FOREIGN KEY (tenant_id, content_sha256) REFERENCES artifacts (tenant_id, content_sha256)
);
-- "Which runs consumed this hash" for invalidation.
CREATE INDEX stage_run_artifacts_hash_idx ON stage_run_artifacts (tenant_id, content_sha256, direction);

CREATE TABLE attempts (
  tenant_id        uuid     NOT NULL REFERENCES tenants (id),
  id               uuid     NOT NULL,
  job_id           uuid     NOT NULL,
  stage_run_id     uuid     NOT NULL,
  attempt_number   integer  NOT NULL,
  status           text     NOT NULL DEFAULT 'STARTING',
  version          bigint   NOT NULL DEFAULT 1,
  -- The worker that holds the lease, and the epoch the lease was granted at.
  lease_owner      text,
  lease_epoch      bigint   NOT NULL,
  lease_expires_at timestamptz,
  last_heartbeat_at timestamptz,
  deadline_at      timestamptz NOT NULL,
  -- Set while CANCELLING: when teardown stops waiting and force-kills (transition A10).
  teardown_deadline_at timestamptz,
  failure_class    text,
  output_sha256    text,
  sandbox_id       text,
  -- A sandbox that could not be confirmed gone (guard G_ALL_ATTEMPTS_TERMINAL).
  sandbox_leaked   boolean  NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  ended_at         timestamptz,
  PRIMARY KEY (tenant_id, id),
  -- Targets for the ledger, which names the attempt together with its run and job.
  UNIQUE (tenant_id, job_id, stage_run_id, id),
  UNIQUE (tenant_id, stage_run_id, attempt_number),
  FOREIGN KEY (tenant_id, job_id, stage_run_id) REFERENCES stage_runs (tenant_id, job_id, id),
  FOREIGN KEY (tenant_id, output_sha256) REFERENCES artifacts (tenant_id, content_sha256),
  CONSTRAINT attempts_status_check CHECK (status IN (
    'STARTING', 'RUNNING', 'CANCELLING', 'SUCCEEDED', 'FAILED', 'TIMED_OUT', 'LEASE_LOST', 'CANCELLED')),
  CONSTRAINT attempts_attempt_number_check CHECK (attempt_number >= 1),
  CONSTRAINT attempts_version_check CHECK (version >= 1),
  CONSTRAINT attempts_lease_epoch_check CHECK (lease_epoch >= 1),
  CONSTRAINT attempts_lease_owner_check CHECK (lease_owner IS NULL OR length(lease_owner) BETWEEN 1 AND 128),
  CONSTRAINT attempts_failure_class_check CHECK (failure_class IS NULL OR failure_class IN (
    'TOOL_ERROR', 'INVALID_OUTPUT', 'BUDGET_EXHAUSTED', 'POLICY_DENIED', 'PROVIDER_ERROR', 'SANDBOX_ERROR', 'INTERNAL')),
  CONSTRAINT attempts_output_hash_check CHECK (output_sha256 IS NULL OR output_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  CONSTRAINT attempts_deadline_check CHECK (deadline_at > created_at),
  -- An attempt that is alive has an owner and a lease expiry.
  CONSTRAINT attempts_active_has_lease CHECK (
    status NOT IN ('STARTING', 'RUNNING', 'CANCELLING') OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
  -- ended_at is set exactly when the status is terminal (terminal states from state-machine.json).
  CONSTRAINT attempts_terminal_check CHECK (
    (status IN ('SUCCEEDED', 'FAILED', 'TIMED_OUT', 'LEASE_LOST', 'CANCELLED')) = (ended_at IS NOT NULL)),
  -- A failure has a class and only a failure has one. A success names its output artifact.
  CONSTRAINT attempts_failed_has_class CHECK ((status = 'FAILED') = (failure_class IS NOT NULL)),
  CONSTRAINT attempts_succeeded_has_output CHECK (status <> 'SUCCEEDED' OR output_sha256 IS NOT NULL),
  CONSTRAINT attempts_cancelling_has_teardown CHECK (status <> 'CANCELLING' OR teardown_deadline_at IS NOT NULL)
);
-- At most one live attempt per stage run: the database backstop for "exactly one claim wins".
CREATE UNIQUE INDEX attempts_one_active_per_stage_run ON attempts (tenant_id, stage_run_id)
  WHERE status IN ('STARTING', 'RUNNING', 'CANCELLING');
-- The sweeper. Not tenant scoped on purpose (system scope). Partial, so they stay small: terminal
-- attempts are the vast majority of rows and are not indexed here.
CREATE INDEX attempts_lease_expiry_idx ON attempts (lease_expires_at) WHERE status IN ('STARTING', 'RUNNING');
CREATE INDEX attempts_deadline_idx ON attempts (deadline_at) WHERE status IN ('STARTING', 'RUNNING');
CREATE INDEX attempts_teardown_idx ON attempts (teardown_deadline_at) WHERE status = 'CANCELLING';

-- Attempts are numbered 1, 2, 3 within a stage run and cannot exceed the run's limit
-- (invariant INV-10), whatever the caller believes the limit is.
CREATE FUNCTION attempts_insert_guard() RETURNS trigger
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
CREATE TRIGGER attempts_insert_guard BEFORE INSERT ON attempts FOR EACH ROW EXECUTE FUNCTION attempts_insert_guard();

-- A live attempt holds the stage run's current lease epoch. Checked at commit, so the order of the
-- claim's statements inside the transaction does not matter. A stale worker that writes to an
-- attempt after the run moved on fails here even if the caller forgot the epoch in its WHERE clause.
CREATE FUNCTION attempts_epoch_check() RETURNS trigger
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
CREATE CONSTRAINT TRIGGER attempts_epoch_check AFTER INSERT OR UPDATE ON attempts
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION attempts_epoch_check();

-- A lease cannot be set far ahead of the database clock. The caller should write
-- `lease_expires_at = now() + interval '...'` in SQL, so skew between worker hosts cannot stretch a
-- lease (ADR 0007, rule 7). This bound is the backstop for a caller that writes its own clock: a
-- worker that is hours ahead, or hostile, still cannot hold a lease for longer than an hour.
CREATE FUNCTION attempts_lease_bound() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.lease_expires_at > now() + interval '1 hour' THEN
    RAISE EXCEPTION 'a lease may not expire more than one hour after the database time (asked for %)', NEW.lease_expires_at
      USING ERRCODE = '23514', CONSTRAINT = 'attempts_lease_within_bound', TABLE = 'attempts';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER attempts_lease_bound BEFORE INSERT OR UPDATE ON attempts FOR EACH ROW EXECUTE FUNCTION attempts_lease_bound();

-- A finished attempt keeps its result: a worker that was presumed dead (LEASE_LOST, TIMED_OUT, ...)
-- cannot write a late result onto it (invariant INV-05), whatever its WHERE clause said. Only the
-- facts about tearing down its sandbox may still arrive. The epoch an attempt was granted never changes.
CREATE FUNCTION attempts_update_guard() RETURNS trigger
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
CREATE TRIGGER attempts_update_guard BEFORE UPDATE ON attempts FOR EACH ROW EXECUTE FUNCTION attempts_update_guard();

CREATE TRIGGER attempts_bump BEFORE UPDATE ON attempts FOR EACH ROW EXECUTE FUNCTION bump_guard();
CREATE TRIGGER attempts_status_machine BEFORE INSERT OR UPDATE ON attempts
  FOR EACH ROW EXECUTE FUNCTION enforce_status_transition('attempt');

-- The task graph of an IMPLEMENTATION run (task-dag.schema.json). The plan itself is an artifact;
-- these rows carry the execution state of each node.
CREATE TABLE task_nodes (
  tenant_id     uuid    NOT NULL REFERENCES tenants (id),
  id            uuid    NOT NULL,
  job_id        uuid    NOT NULL,
  stage_run_id  uuid    NOT NULL,
  task_key      text    NOT NULL,
  plan_sha256   text    NOT NULL,
  status        text    NOT NULL DEFAULT 'PENDING',
  version       bigint  NOT NULL DEFAULT 1,
  retry_count   smallint NOT NULL DEFAULT 0,
  current_attempt_id uuid,
  commit_sha    text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  finished_at   timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, stage_run_id, id),
  UNIQUE (tenant_id, stage_run_id, task_key),
  FOREIGN KEY (tenant_id, job_id, stage_run_id) REFERENCES stage_runs (tenant_id, job_id, id),
  FOREIGN KEY (tenant_id, job_id, stage_run_id, current_attempt_id) REFERENCES attempts (tenant_id, job_id, stage_run_id, id),
  FOREIGN KEY (tenant_id, plan_sha256) REFERENCES artifacts (tenant_id, content_sha256),
  CONSTRAINT task_nodes_status_check CHECK (status IN ('PENDING', 'READY', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
  CONSTRAINT task_nodes_task_key_check CHECK (task_key ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
  CONSTRAINT task_nodes_version_check CHECK (version >= 1),
  CONSTRAINT task_nodes_retry_count_check CHECK (retry_count >= 0),
  CONSTRAINT task_nodes_plan_hash_check CHECK (plan_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  CONSTRAINT task_nodes_commit_sha_check CHECK (commit_sha IS NULL OR commit_sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
  -- FAILED is not terminal for a task: it can be retried (T06). Terminal: SUCCEEDED and CANCELLED.
  CONSTRAINT task_nodes_terminal_check CHECK ((status IN ('SUCCEEDED', 'CANCELLED')) = (finished_at IS NOT NULL))
);
CREATE TRIGGER task_nodes_bump BEFORE UPDATE ON task_nodes FOR EACH ROW EXECUTE FUNCTION bump_guard();
CREATE TRIGGER task_nodes_status_machine BEFORE INSERT OR UPDATE ON task_nodes
  FOR EACH ROW EXECUTE FUNCTION enforce_status_transition('task_node');

CREATE TABLE task_node_dependencies (
  tenant_id       uuid NOT NULL REFERENCES tenants (id),
  stage_run_id    uuid NOT NULL,
  task_node_id    uuid NOT NULL,
  depends_on_task_node_id uuid NOT NULL,
  PRIMARY KEY (tenant_id, task_node_id, depends_on_task_node_id),
  -- Both ends belong to the same stage run, so a dependency cannot reach into another run or tenant.
  FOREIGN KEY (tenant_id, stage_run_id, task_node_id) REFERENCES task_nodes (tenant_id, stage_run_id, id),
  FOREIGN KEY (tenant_id, stage_run_id, depends_on_task_node_id) REFERENCES task_nodes (tenant_id, stage_run_id, id),
  CHECK (task_node_id <> depends_on_task_node_id)
);
CREATE INDEX task_node_dependencies_reverse_idx ON task_node_dependencies (tenant_id, depends_on_task_node_id);

-- The graph is acyclic. The planner validator checks this too; this is the backstop.
CREATE FUNCTION task_node_dependencies_acyclic() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF EXISTS (
    WITH RECURSIVE reach(node) AS (
      SELECT NEW.depends_on_task_node_id
      UNION
      SELECT d.depends_on_task_node_id
        FROM public.task_node_dependencies d JOIN reach r ON d.task_node_id = r.node
       WHERE d.tenant_id = NEW.tenant_id
    )
    SELECT 1 FROM reach WHERE node = NEW.task_node_id
  ) THEN
    RAISE EXCEPTION 'dependency % -> % would close a cycle', NEW.task_node_id, NEW.depends_on_task_node_id
      USING ERRCODE = '23514', CONSTRAINT = 'task_node_dependencies_acyclic', TABLE = 'task_node_dependencies';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER task_node_dependencies_acyclic BEFORE INSERT ON task_node_dependencies
  FOR EACH ROW EXECUTE FUNCTION task_node_dependencies_acyclic();
