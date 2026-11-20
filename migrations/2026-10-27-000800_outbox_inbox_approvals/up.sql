-- The transactional outbox, the consumer inbox, and human approvals.

-- ADR 0004. A state change, its ledger entries and its domain event commit together in one
-- transaction. The relay (Slice 2) publishes unpublished rows and marks them. Delivery is at least
-- once; consumers deduplicate on event_id with the inbox below.
CREATE TABLE outbox (
  -- Global row order for the relay. It can have gaps and commit out of order, so consumers order
  -- by aggregate_version and never by arrival.
  seq               bigint GENERATED ALWAYS AS IDENTITY,
  tenant_id         uuid   NOT NULL REFERENCES tenants (id),
  event_id          uuid   NOT NULL,
  event_type        text   NOT NULL,
  event_version     integer NOT NULL DEFAULT 1,
  job_id            uuid   NOT NULL,
  aggregate_type    text   NOT NULL,
  aggregate_id      uuid   NOT NULL,
  aggregate_version bigint NOT NULL,
  -- The transition in state-machine.json that produced the event: the machine-readable reason.
  transition_id     text   NOT NULL,
  reason_code       text,
  correlation_id    uuid   NOT NULL,
  causation_id      uuid,
  occurred_at       timestamptz NOT NULL,
  producer          text   NOT NULL,
  traceparent       text,
  -- Identifiers and hashes only. Never prompts, source code, model output or secrets.
  payload           jsonb  NOT NULL,
  payload_schema_name    text,
  payload_schema_version integer,
  created_at        timestamptz NOT NULL DEFAULT now(),
  published_at      timestamptz,
  publish_attempts  integer NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, event_id),
  -- One event per aggregate version: replaying a transition after a crash cannot emit it twice.
  CONSTRAINT outbox_one_event_per_aggregate_version UNIQUE (tenant_id, aggregate_type, aggregate_id, aggregate_version),
  FOREIGN KEY (tenant_id, job_id) REFERENCES jobs (tenant_id, id),
  -- The event type must be the one the named transition of that machine emits.
  FOREIGN KEY (aggregate_type, transition_id, event_type)
    REFERENCES state_machine_transitions (machine, transition_id, emits),
  CONSTRAINT outbox_event_type_check CHECK (event_type ~ '^[a-z][a-z_]*\.[a-z][a-z_]*$' AND event_type <> 'attempt.heartbeat'),
  CONSTRAINT outbox_event_type_matches_aggregate CHECK (split_part(event_type, '.', 1) = aggregate_type),
  CONSTRAINT outbox_aggregate_type_check CHECK (aggregate_type IN ('job', 'stage_run', 'attempt', 'task_node')),
  CONSTRAINT outbox_event_version_check CHECK (event_version >= 1),
  CONSTRAINT outbox_aggregate_version_check CHECK (aggregate_version >= 1),
  CONSTRAINT outbox_transition_id_check CHECK (transition_id ~ '^[JSAT][0-9]{2}$'),
  CONSTRAINT outbox_reason_code_check CHECK (reason_code IS NULL OR reason_code ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
  CONSTRAINT outbox_producer_check CHECK (producer ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
  CONSTRAINT outbox_traceparent_check CHECK (traceparent IS NULL OR traceparent ~ '^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'),
  CONSTRAINT outbox_payload_check CHECK (jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 16384),
  CONSTRAINT outbox_payload_schema_check CHECK ((payload_schema_name IS NULL) = (payload_schema_version IS NULL)),
  CONSTRAINT outbox_publish_attempts_check CHECK (publish_attempts >= 0)
);
-- The relay: unpublished rows in order. Partial, so it holds only the backlog.
CREATE INDEX outbox_unpublished_idx ON outbox (seq) WHERE published_at IS NULL;
-- The job timeline.
CREATE INDEX outbox_job_timeline_idx ON outbox (tenant_id, job_id, seq);

-- An event is a fact. Only the relay's bookkeeping may change: published_at once, publish_attempts
-- upwards. Column grants limit the application role to those two columns; this trigger also stops
-- the second change and any other column for every role.
CREATE FUNCTION outbox_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  bookkeeping text[] := ARRAY['published_at', 'publish_attempts'];
BEGIN
  IF (to_jsonb(NEW) - bookkeeping) <> (to_jsonb(OLD) - bookkeeping)
     OR (OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at)
     OR NEW.publish_attempts < OLD.publish_attempts THEN
    RAISE EXCEPTION 'an outbox event cannot change; only published_at (once) and publish_attempts (up) may'
      USING ERRCODE = '23514', CONSTRAINT = 'outbox_event_is_immutable', TABLE = 'outbox';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER outbox_guard BEFORE UPDATE ON outbox FOR EACH ROW EXECUTE FUNCTION outbox_guard();

-- aggregate_id points at a row of one of four tables, chosen by aggregate_type, so no foreign key can
-- check it. This does: the aggregate exists in the same tenant, belongs to the event's job, and has
-- reached the version the event announces. It is checked at commit, so the status update and the event
-- can be written in either order inside the decision's transaction.
CREATE FUNCTION outbox_aggregate_check() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  actual_version bigint;
  actual_job uuid;
BEGIN
  IF NEW.aggregate_type = 'job' THEN
    SELECT x.version, x.id INTO actual_version, actual_job
      FROM public.jobs x WHERE x.tenant_id = NEW.tenant_id AND x.id = NEW.aggregate_id;
  ELSIF NEW.aggregate_type = 'stage_run' THEN
    SELECT x.version, x.job_id INTO actual_version, actual_job
      FROM public.stage_runs x WHERE x.tenant_id = NEW.tenant_id AND x.id = NEW.aggregate_id;
  ELSIF NEW.aggregate_type = 'attempt' THEN
    SELECT x.version, x.job_id INTO actual_version, actual_job
      FROM public.attempts x WHERE x.tenant_id = NEW.tenant_id AND x.id = NEW.aggregate_id;
  ELSE
    SELECT x.version, x.job_id INTO actual_version, actual_job
      FROM public.task_nodes x WHERE x.tenant_id = NEW.tenant_id AND x.id = NEW.aggregate_id;
  END IF;
  IF actual_version IS NULL THEN
    RAISE EXCEPTION 'the % % named by the event does not exist in this tenant', NEW.aggregate_type, NEW.aggregate_id
      USING ERRCODE = '23514', CONSTRAINT = 'outbox_aggregate_exists', TABLE = 'outbox';
  END IF;
  IF actual_job <> NEW.job_id THEN
    RAISE EXCEPTION 'the % % named by the event belongs to another job', NEW.aggregate_type, NEW.aggregate_id
      USING ERRCODE = '23514', CONSTRAINT = 'outbox_aggregate_belongs_to_job', TABLE = 'outbox';
  END IF;
  IF NEW.aggregate_version > actual_version THEN
    RAISE EXCEPTION 'the event announces version % but the % is only at version %', NEW.aggregate_version, NEW.aggregate_type, actual_version
      USING ERRCODE = '23514', CONSTRAINT = 'outbox_aggregate_has_reached_version', TABLE = 'outbox';
  END IF;
  RETURN NULL;
END
$$;
CREATE CONSTRAINT TRIGGER outbox_aggregate_check AFTER INSERT ON outbox
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION outbox_aggregate_check();

-- Consumer idempotency (ADR 0004). A consumer writes its inbox row in the same transaction as its
-- effects inside PostgreSQL; a second delivery of the same event hits the primary key and is dropped.
-- No foreign key to the outbox: the outbox will be trimmed on its own schedule.
CREATE TABLE inbox (
  tenant_id    uuid NOT NULL REFERENCES tenants (id),
  consumer     text NOT NULL CHECK (consumer ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
  event_id     uuid NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, consumer, event_id)
);

-- A human decision on a job, bound to exactly what the human saw (policies/approval.yaml,
-- approval_binding). The binding columns are what make "approved" mean "approved this head commit
-- with this evidence". An approval is a record: it is never edited, only invalidated once.
CREATE TABLE approvals (
  tenant_id               uuid NOT NULL REFERENCES tenants (id),
  id                      uuid NOT NULL,
  job_id                  uuid NOT NULL,
  stage_run_id            uuid NOT NULL,
  decision                text NOT NULL,
  approver_principal_id   uuid NOT NULL,
  -- Always 'human': together with the foreign key below it keeps a service principal from approving.
  approver_kind           text NOT NULL DEFAULT 'human',
  approver_github_user_id bigint NOT NULL CHECK (approver_github_user_id > 0),
  approver_designation    text NOT NULL CHECK (approver_designation ~ '^[a-z][a-z_]{0,31}$'),
  -- Hash of the allowlist version that was read for this decision.
  allowlist_version_hash  text NOT NULL CHECK (allowlist_version_hash ~ '^sha256:[0-9a-f]{64}$'),
  -- The binding. All required when the decision is approve.
  pr_head_sha             text CHECK (pr_head_sha IS NULL OR pr_head_sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
  tree_hash               text CHECK (tree_hash IS NULL OR tree_hash ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
  base_sha                text CHECK (base_sha IS NULL OR base_sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'),
  evidence_manifest_hash  text CHECK (evidence_manifest_hash IS NULL OR evidence_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
  spec_version            integer CHECK (spec_version IS NULL OR spec_version >= 1),
  policy_hash             text NOT NULL CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  reason                  text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
  channel                 text NOT NULL CHECK (channel IN ('dashboard', 'cli', 'github_comment')),
  created_at              timestamptz NOT NULL DEFAULT now(),
  expires_at              timestamptz NOT NULL,
  invalidated_at          timestamptz,
  invalidation_reason     text CHECK (invalidation_reason IS NULL OR length(invalidation_reason) BETWEEN 1 AND 1000),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, job_id, stage_run_id) REFERENCES stage_runs (tenant_id, job_id, id),
  -- One key says three things: the approver is a principal of this tenant, a human (a service has no
  -- GitHub id and cannot match), and the recorded GitHub user id is that principal's own.
  FOREIGN KEY (tenant_id, approver_principal_id, approver_kind, approver_github_user_id)
    REFERENCES principals (tenant_id, id, kind, github_user_id),
  CONSTRAINT approvals_decision_check CHECK (decision IN ('approve', 'reject', 'rework', 'pause', 'cancel')),
  CONSTRAINT approvals_approver_is_human CHECK (approver_kind = 'human'),
  CONSTRAINT approvals_approve_is_bound CHECK (
    decision <> 'approve'
    OR (pr_head_sha IS NOT NULL AND tree_hash IS NOT NULL AND base_sha IS NOT NULL
        AND evidence_manifest_hash IS NOT NULL AND spec_version IS NOT NULL)),
  CONSTRAINT approvals_expiry_check CHECK (expires_at > created_at),
  CONSTRAINT approvals_invalidation_check CHECK ((invalidated_at IS NULL) = (invalidation_reason IS NULL))
);
-- The same person cannot record the same decision twice for the same head commit.
CREATE UNIQUE INDEX approvals_one_decision_per_head ON approvals (tenant_id, stage_run_id, approver_principal_id, decision, pr_head_sha)
  WHERE pr_head_sha IS NOT NULL;
CREATE INDEX approvals_job_idx ON approvals (tenant_id, job_id, created_at);

CREATE FUNCTION approvals_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  invalidation text[] := ARRAY['invalidated_at', 'invalidation_reason'];
BEGIN
  IF (to_jsonb(NEW) - invalidation) <> (to_jsonb(OLD) - invalidation)
     OR (OLD.invalidated_at IS NOT NULL AND (NEW.invalidated_at IS DISTINCT FROM OLD.invalidated_at
                                             OR NEW.invalidation_reason IS DISTINCT FROM OLD.invalidation_reason)) THEN
    RAISE EXCEPTION 'an approval cannot be edited; it can be invalidated once'
      USING ERRCODE = '23514', CONSTRAINT = 'approvals_record_is_immutable', TABLE = 'approvals';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER approvals_guard BEFORE UPDATE ON approvals FOR EACH ROW EXECUTE FUNCTION approvals_guard();
