-- The audit log (policies/security.yaml, audit; threat T-31; control C-37).
--
-- Separate from the evidence ledger. The ledger records claims about the work and is chained per job;
-- the audit log records who did what and what the policy decided, and is chained per tenant.
-- Differences that matter:
--   * the DATABASE assigns sequence, created_at, the previous link, the canonical text and the hash.
--     Whatever the caller supplies for those columns is overwritten (negative test NT-AUD-04);
--   * the application role may INSERT and SELECT only (last migration), and triggers refuse UPDATE,
--     DELETE and TRUNCATE for every role as a second layer;
--   * writers of one tenant take a transaction-scoped advisory lock while the row is built, so the
--     chain has no gaps and no forks. The lock lasts to the end of the writer's transaction, so a
--     transaction should write its audit rows last, shortly before it commits.

CREATE FUNCTION audit_json_string(p_value text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
  SELECT CASE WHEN p_value IS NULL THEN 'null' ELSE to_json(p_value)::text END
$$;

-- The text that is hashed: one JSON object, keys in alphabetical order, no whitespace, strings
-- escaped as JSON requires. Every value is a string, null or an integer, so the text is stable and an
-- outside verifier can rebuild it without PostgreSQL. It is not claimed to be RFC 8785 for all inputs.
CREATE FUNCTION audit_canonical_json(
  p_action text, p_actor_id text, p_actor_type text, p_correlation_id uuid, p_created_at timestamptz,
  p_decision text, p_event_id uuid, p_job_id uuid, p_policy_hash text, p_prev_hash text, p_reason text,
  p_sequence bigint, p_stage_run_id uuid, p_subject text, p_tenant_id uuid
) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  SELECT '{"action":' || public.audit_json_string(p_action)
      || ',"actor_id":' || public.audit_json_string(p_actor_id)
      || ',"actor_type":' || public.audit_json_string(p_actor_type)
      || ',"correlation_id":' || public.audit_json_string(p_correlation_id::text)
      || ',"created_at":' || public.audit_json_string(to_char(p_created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))
      || ',"decision":' || public.audit_json_string(p_decision)
      || ',"event_id":' || public.audit_json_string(p_event_id::text)
      || ',"job_id":' || public.audit_json_string(p_job_id::text)
      || ',"policy_hash":' || public.audit_json_string(p_policy_hash)
      || ',"prev_hash":' || public.audit_json_string(p_prev_hash)
      || ',"reason":' || public.audit_json_string(p_reason)
      || ',"sequence":' || p_sequence::text
      || ',"stage_run_id":' || public.audit_json_string(p_stage_run_id::text)
      || ',"subject":' || public.audit_json_string(p_subject)
      || ',"tenant_id":' || public.audit_json_string(p_tenant_id::text)
      || '}'
$$;

CREATE TABLE audit_events (
  tenant_id      uuid   NOT NULL REFERENCES tenants (id),
  -- Assigned by the trigger: the next number in the tenant's chain, starting at 1, with no gaps.
  sequence       bigint NOT NULL,
  event_id       uuid   NOT NULL,
  actor_type     text   NOT NULL,
  actor_id       text   NOT NULL,
  action         text   NOT NULL,
  subject        text   NOT NULL,
  decision       text   NOT NULL,
  reason         text   NOT NULL,
  -- Hash of the policy bundle that decided. The all-zero hash means that no policy was loaded.
  policy_hash    text   NOT NULL,
  job_id         uuid,
  stage_run_id   uuid,
  correlation_id uuid   NOT NULL,
  -- Database clock at the moment of insert. Never the caller's.
  created_at     timestamptz NOT NULL,
  prev_sequence  bigint,
  prev_hash      text,
  canonical_json text   NOT NULL,
  hash           text   NOT NULL,
  PRIMARY KEY (tenant_id, sequence),
  UNIQUE (tenant_id, event_id),
  UNIQUE (tenant_id, sequence, hash),
  FOREIGN KEY (tenant_id, prev_sequence, prev_hash) REFERENCES audit_events (tenant_id, sequence, hash),
  FOREIGN KEY (tenant_id, job_id) REFERENCES jobs (tenant_id, id),
  FOREIGN KEY (tenant_id, job_id, stage_run_id) REFERENCES stage_runs (tenant_id, job_id, id),
  CONSTRAINT audit_events_sequence_check CHECK (sequence >= 1),
  CONSTRAINT audit_events_first_has_no_predecessor CHECK ((sequence = 1) = (prev_hash IS NULL)),
  CONSTRAINT audit_events_actor_type_check CHECK (actor_type IN ('human', 'service', 'system', 'anonymous')),
  CONSTRAINT audit_events_actor_id_check CHECK (length(actor_id) BETWEEN 1 AND 200),
  CONSTRAINT audit_events_action_check CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$' AND length(action) <= 100),
  CONSTRAINT audit_events_subject_check CHECK (length(subject) BETWEEN 1 AND 500),
  CONSTRAINT audit_events_decision_check CHECK (decision IN ('allow', 'deny', 'record')),
  CONSTRAINT audit_events_reason_check CHECK (length(reason) BETWEEN 1 AND 1000),
  CONSTRAINT audit_events_policy_hash_check CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
  CONSTRAINT audit_events_hashes_check CHECK (
    hash ~ '^sha256:[0-9a-f]{64}$' AND (prev_hash IS NULL OR prev_hash ~ '^sha256:[0-9a-f]{64}$')),
  CONSTRAINT audit_events_stage_run_needs_job CHECK (stage_run_id IS NULL OR job_id IS NOT NULL)
);
CREATE INDEX audit_events_job_idx ON audit_events (tenant_id, job_id, sequence) WHERE job_id IS NOT NULL;

CREATE FUNCTION audit_events_assign() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  last_sequence bigint;
  last_hash text;
BEGIN
  -- One writer per tenant at a time. The lock is released when the transaction ends.
  PERFORM pg_advisory_xact_lock(hashtextextended('factory.audit_events:' || NEW.tenant_id::text, 0));

  SELECT a.sequence, a.hash INTO last_sequence, last_hash
    FROM public.audit_events a
   WHERE a.tenant_id = NEW.tenant_id
   ORDER BY a.sequence DESC LIMIT 1;

  NEW.sequence := coalesce(last_sequence, 0) + 1;
  NEW.prev_sequence := last_sequence;
  NEW.prev_hash := last_hash;
  NEW.created_at := clock_timestamp();
  NEW.canonical_json := public.audit_canonical_json(
    NEW.action, NEW.actor_id, NEW.actor_type, NEW.correlation_id, NEW.created_at, NEW.decision,
    NEW.event_id, NEW.job_id, NEW.policy_hash, NEW.prev_hash, NEW.reason, NEW.sequence,
    NEW.stage_run_id, NEW.subject, NEW.tenant_id);
  NEW.hash := 'sha256:' || encode(sha256(convert_to(coalesce(NEW.prev_hash, '') || E'\n' || NEW.canonical_json, 'UTF8')), 'hex');
  RETURN NEW;
END
$$;
CREATE TRIGGER audit_events_assign BEFORE INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_assign();

CREATE TRIGGER audit_events_no_change BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_modification();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_modification();

-- Walk one tenant's chain. Returns the sequence of the first entry that has a gap before it, a broken
-- link, a stored text that does not match its columns, or a hash that does not match its text. NULL
-- means sound. It cannot see rows deleted from the end: compare the head with the external anchor.
CREATE FUNCTION audit_verify_chain(p_tenant uuid) RETURNS bigint
LANGUAGE sql STABLE SET search_path = pg_catalog, public AS $$
  WITH walked AS (
    SELECT a.*, lag(a.sequence) OVER w AS lag_sequence, lag(a.hash) OVER w AS lag_hash
      FROM public.audit_events a
     WHERE a.tenant_id = p_tenant
    WINDOW w AS (ORDER BY a.sequence)
  )
  SELECT min(sequence) FROM walked
   WHERE sequence <> coalesce(lag_sequence, 0) + 1
      OR prev_hash IS DISTINCT FROM lag_hash
      OR canonical_json <> public.audit_canonical_json(
           action, actor_id, actor_type, correlation_id, created_at, decision, event_id, job_id,
           policy_hash, prev_hash, reason, sequence, stage_run_id, subject, tenant_id)
      OR hash <> 'sha256:' || encode(sha256(convert_to(coalesce(prev_hash, '') || E'\n' || canonical_json, 'UTF8')), 'hex')
$$;
