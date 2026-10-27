-- Artifact metadata and webhook deliveries.

-- One row per tenant and content hash (ADR 0008). The bytes live behind the ArtifactStore port,
-- addressed by hash. A blob may be shared on disk, but a tenant reaches it only through its own
-- row here, so one tenant cannot learn that another holds a given blob.
CREATE TABLE artifacts (
  tenant_id      uuid   NOT NULL REFERENCES tenants (id),
  content_sha256 text   NOT NULL CHECK (content_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  size_bytes     bigint NOT NULL CHECK (size_bytes >= 0),
  media_type     text   NOT NULL CHECK (media_type ~ '^[a-z]+/[a-z0-9.+-]+$'),
  -- The label says which backend holds the bytes, so "local-fs" is never mistaken for S3.
  backend        text   NOT NULL CHECK (backend IN ('local-fs', 's3-compatible')),
  retention_class text  NOT NULL DEFAULT 'standard' CHECK (retention_class ~ '^[a-z][a-z0-9_]{0,31}$'),
  -- The stage run that first stored it. The foreign key to stage_runs is added with that table.
  created_by_job_id       uuid,
  created_by_stage_run_id uuid,
  created_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, content_sha256),
  CHECK ((created_by_job_id IS NULL) = (created_by_stage_run_id IS NULL))
);

-- One row per verified GitHub delivery. The receiver verifies the signature first (control C-01)
-- and only then writes here, so every row is a delivery that was authentic when it arrived.
CREATE TABLE webhook_deliveries (
  tenant_id            uuid   NOT NULL REFERENCES tenants (id),
  id                   uuid   NOT NULL,
  -- X-GitHub-Delivery. Unique per tenant. GitHub keeps the same id when it redelivers.
  delivery_id          text   NOT NULL CHECK (length(delivery_id) BETWEEN 8 AND 128),
  event_name           text   NOT NULL CHECK (event_name ~ '^[a-z_]{1,64}$'),
  action               text   CHECK (action IS NULL OR action ~ '^[a-z_]{1,64}$'),
  github_installation_id bigint NOT NULL CHECK (github_installation_id > 0),
  github_repository_id bigint CHECK (github_repository_id > 0),
  sender_github_user_id bigint CHECK (sender_github_user_id > 0),
  -- SHA-256 of the raw request body. The signature covers the body and not the headers, so a
  -- captured body replayed under a fresh delivery header is a new delivery id but the same hash.
  body_sha256          text   NOT NULL CHECK (body_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  -- Hash of event, action, installation, repository, subject node, subject updated_at and sender
  -- (policies/security.yaml, webhook.semantic_idempotency). Null when the event has no subject.
  semantic_key         text   CHECK (semantic_key IS NULL OR semantic_key ~ '^sha256:[0-9a-f]{64}$'),
  received_at          timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, delivery_id),
  UNIQUE (tenant_id, body_sha256),
  UNIQUE (tenant_id, semantic_key)
);
-- Retention (30 days, policy webhook.dedupe) scans by age.
CREATE INDEX webhook_deliveries_received_idx ON webhook_deliveries (received_at);
