-- Jobs and the original request text.
--
-- A job is one request (docs/architecture/state-machine.md). The text a person wrote is untrusted,
-- so it lives in its own table with a content hash (ADR 0007, rule 8). Everything else in the system
-- refers to the normalized request, which is an artifact named by hash.

CREATE TABLE jobs (
  tenant_id              uuid   NOT NULL REFERENCES tenants (id),
  id                     uuid   NOT NULL,
  repository_id          uuid   NOT NULL,
  requester_principal_id uuid   NOT NULL,
  status                 text   NOT NULL DEFAULT 'RECEIVED',
  version                bigint NOT NULL DEFAULT 1,
  -- 'test' jobs may carry fake or simulated evidence; 'production' jobs may not (invariant INV-08).
  execution_mode         text   NOT NULL,
  autonomy_level         text   NOT NULL,
  -- The stage kinds this job must pass (guard G_PIPELINE_SCOPE_COMPLETE).
  pipeline_scope         text[] NOT NULL,
  -- Shared by every event, ledger entry and audit event of the job.
  correlation_id         uuid   NOT NULL,
  -- Set for jobs created through the API or CLI; a retry with the same key finds the first job.
  idempotency_key        text,
  -- Set for jobs created from a webhook. At most one job can come from one delivery.
  webhook_delivery_id    uuid,
  policy_hash            text,
  -- The output of INTAKE. Null until intake has run.
  normalized_request_sha256 text,
  -- Head of the evidence ledger chain. Moved by the same compare-and-swap as any other job state
  -- (ADR 0008). The foreign key that makes it point at a real entry comes with the ledger table.
  ledger_head_sequence   bigint NOT NULL DEFAULT 0,
  ledger_head_hash       text,
  created_at             timestamptz NOT NULL DEFAULT now(),
  updated_at             timestamptz NOT NULL DEFAULT now(),
  terminal_at            timestamptz,
  PRIMARY KEY (tenant_id, id),
  -- Targets of foreign keys from the ledger, which must agree with the job on the execution mode.
  UNIQUE (tenant_id, id, execution_mode),
  UNIQUE (tenant_id, correlation_id),
  UNIQUE (tenant_id, idempotency_key),
  UNIQUE (tenant_id, webhook_delivery_id),
  FOREIGN KEY (tenant_id, repository_id) REFERENCES repositories (tenant_id, id),
  FOREIGN KEY (tenant_id, requester_principal_id) REFERENCES principals (tenant_id, id),
  FOREIGN KEY (tenant_id, webhook_delivery_id) REFERENCES webhook_deliveries (tenant_id, id),
  FOREIGN KEY (tenant_id, normalized_request_sha256) REFERENCES artifacts (tenant_id, content_sha256),
  CONSTRAINT jobs_status_check CHECK (status IN (
    'RECEIVED', 'ACTIVE', 'WAITING_FOR_HUMAN', 'PAUSED', 'BLOCKED', 'CANCELLING',
    'COMPLETED', 'FAILED', 'CANCELLED', 'REJECTED')),
  CONSTRAINT jobs_version_check CHECK (version >= 1),
  CONSTRAINT jobs_execution_mode_check CHECK (execution_mode IN ('production', 'test')),
  CONSTRAINT jobs_autonomy_level_check CHECK (autonomy_level IN ('L0', 'L1', 'L2', 'L3')),
  CONSTRAINT jobs_pipeline_scope_check CHECK (
    cardinality(pipeline_scope) BETWEEN 1 AND 14
    AND pipeline_scope <@ ARRAY['INTAKE', 'REPOSITORY_INTELLIGENCE', 'SPECIFICATION', 'DOMAIN_DISCOVERY',
      'ARCHITECTURE', 'TASK_PLANNING', 'IMPLEMENTATION', 'VALIDATION', 'REVIEW', 'DOCUMENTING',
      'DOCUMENTATION_REVIEW', 'DELIVERY', 'APPROVAL', 'MERGE']::text[]),
  CONSTRAINT jobs_idempotency_key_check CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 128),
  CONSTRAINT jobs_policy_hash_check CHECK (policy_hash IS NULL OR policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  CONSTRAINT jobs_ledger_head_check CHECK (
    ledger_head_sequence >= 0
    AND (ledger_head_sequence = 0) = (ledger_head_hash IS NULL)
    AND (ledger_head_hash IS NULL OR ledger_head_hash ~ '^sha256:[0-9a-f]{64}$')),
  -- terminal_at is set exactly when the status is terminal (terminal states from state-machine.json).
  CONSTRAINT jobs_terminal_check CHECK (
    (status IN ('COMPLETED', 'FAILED', 'CANCELLED', 'REJECTED')) = (terminal_at IS NOT NULL))
);
-- Open jobs of a tenant: the job quota in admission, and the engine looking for work.
CREATE INDEX jobs_open_idx ON jobs (tenant_id, id)
  WHERE status NOT IN ('COMPLETED', 'FAILED', 'CANCELLED', 'REJECTED');
-- Dashboard listing, newest first, with keyset pagination.
CREATE INDEX jobs_listing_idx ON jobs (tenant_id, created_at DESC, id DESC);

CREATE TRIGGER jobs_bump BEFORE UPDATE ON jobs FOR EACH ROW EXECUTE FUNCTION bump_guard();
CREATE TRIGGER jobs_status_machine BEFORE INSERT OR UPDATE ON jobs
  FOR EACH ROW EXECUTE FUNCTION enforce_status_transition('job');

-- The request exactly as received. Editing the source creates a new revision with a new hash, and
-- the earlier text stays as the record of what was authorized (control C-05).
CREATE TABLE original_requests (
  tenant_id    uuid   NOT NULL REFERENCES tenants (id),
  id           uuid   NOT NULL,
  job_id       uuid   NOT NULL,
  revision     integer NOT NULL CHECK (revision >= 1),
  source       text   NOT NULL CHECK (source IN ('github_issue', 'api', 'cli')),
  -- A pointer such as an issue URL. Untrusted like the text.
  source_ref   text   CHECK (source_ref IS NULL OR length(source_ref) <= 2048),
  author_github_user_id bigint CHECK (author_github_user_id > 0),
  -- Title and body as one text, exactly as received. Never put in an instruction channel.
  request_text text   NOT NULL CHECK (octet_length(request_text) BETWEEN 1 AND 1048576),
  -- The database checks this against request_text, so the hash cannot drift from the text.
  content_sha256 text NOT NULL,
  captured_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, job_id, revision),
  FOREIGN KEY (tenant_id, job_id) REFERENCES jobs (tenant_id, id),
  CONSTRAINT original_requests_hash_matches_text CHECK (
    content_sha256 = 'sha256:' || encode(sha256(convert_to(request_text, 'UTF8')), 'hex'))
);
CREATE TRIGGER original_requests_no_update BEFORE UPDATE ON original_requests
  FOR EACH ROW EXECUTE FUNCTION reject_modification();
CREATE TRIGGER original_requests_no_truncate BEFORE TRUNCATE ON original_requests
  FOR EACH STATEMENT EXECUTE FUNCTION reject_modification();
