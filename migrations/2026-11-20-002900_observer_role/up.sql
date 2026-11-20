-- A read-only group for the troubleshooter and the PostgreSQL MCP server (ADR 0021, decision 4).
--
--   factory_observer  reads named operational columns of the operational tables across every tenant, and the
--                     statistics views. It writes nothing, owns nothing, creates nothing and cannot log in.
--
-- What it may read, and why only that:
--
--   * Column grants, never a table grant. A column is granted when it is an identifier, a state, a kind, a
--     timestamp, a counter, a closed code or a reason code: what a person needs to see that a job is stuck, a
--     lease expired or a stage fails again and again. It never gets a column that holds a request text, a
--     specification, an issue body, a token or token digest, a key, a signature, a chain hash, a free text
--     written by a person, a GitHub login or user id, or the payload of an event. Tables made only of such
--     columns (original_requests, stage_run_artifacts, task_node_dependencies) get nothing.
--   * The list of every column of a granted table, each marked operational or sensitive, is
--     docs/database/observer-columns.txt. The test `observer_columns` of crates/mcp_postgres lists what this
--     group can read in a migrated database and fails when the two differ: a column added later to a granted
--     table is neither granted nor classified, so the test stops the build until a person classifies it.
--   * One policy per table under row-level security, `observer_read`, FOR SELECT TO factory_observer USING
--     (true). The troubleshooter looks across tenants, read-only; FORCE ROW LEVEL SECURITY would otherwise show
--     it nothing. The policy gives no write: the group has no INSERT, UPDATE or DELETE privilege anywhere, and
--     there is no policy for any other command. The reference tables (the three state machine tables and the
--     Diesel version table) have no row-level security and need no policy.
--   * Member of pg_read_all_stats, for pg_stat_activity, pg_locks with the query of other sessions and
--     pg_stat_statements when the server loads it. Not of pg_signal_backend, pg_read_all_data or any other
--     predefined role: it cannot end another role's session, read a file or read a table it was not granted.
--   * No EXECUTE is granted on any function. The functions PUBLIC may execute stay as they are; a function
--     that writes fails in the read-only transaction the server opens, and on the missing table privilege.
--
-- The login. Passwords are deployment data, so the login is not made here. A deployment creates it as below
-- (docs/database/observer-login.sql has the same statements, ready to run with psql):
--
--   CREATE ROLE factory_troubleshooter LOGIN PASSWORD '...' CONNECTION LIMIT 4 IN ROLE factory_observer
--     NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
--   ALTER ROLE factory_troubleshooter SET default_transaction_read_only = on;
--   ALTER ROLE factory_troubleshooter SET statement_timeout = '5s';
--   ALTER ROLE factory_troubleshooter SET lock_timeout = '1s';
--   ALTER ROLE factory_troubleshooter SET idle_in_transaction_session_timeout = '10s';
--
-- The login must belong to factory_observer and nothing else. In factory_app or factory_system it would add
-- write privileges; the observer policies are permissive and would widen what those groups see.
--
-- Roles are cluster wide. As in migrations 1 and 11, an existing role of the same name is kept if it has no
-- unsafe attribute, and the migration stops if it has one.
DO $$
DECLARE
  r pg_catalog.pg_roles%ROWTYPE;
BEGIN
  SELECT * INTO r FROM pg_catalog.pg_roles WHERE rolname = 'factory_observer';
  IF NOT FOUND THEN
    CREATE ROLE factory_observer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  ELSIF r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolcanlogin THEN
    RAISE EXCEPTION 'the existing role factory_observer has too many powers (superuser, createrole, createdb, replication, bypassrls or login)';
  END IF;
  -- A group that was given more before this migration ran would carry it into the troubleshooter.
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid
     WHERE m.member = 'factory_observer'::regrole AND g.rolname <> 'pg_read_all_stats'
  ) THEN
    RAISE EXCEPTION 'the existing role factory_observer is a member of another role; it may only be a member of pg_read_all_stats';
  END IF;
END
$$;

GRANT pg_read_all_stats TO factory_observer;
GRANT USAGE ON SCHEMA public TO factory_observer;

-- The reference tables: no tenant data, no row-level security.
GRANT SELECT ON state_machine_states, state_machine_transitions, state_machine_edges TO factory_observer;
DO $$
BEGIN
  IF to_regclass('public.__diesel_schema_migrations') IS NOT NULL THEN
    GRANT SELECT (version, run_on) ON public.__diesel_schema_migrations TO factory_observer;
  END IF;
END
$$;

-- Tenants: not the slug or the display name, which name a customer.
GRANT SELECT (id, kind, created_at, disabled_at) ON tenants TO factory_observer;

-- Repositories: not the full name (a customer's repository), not the project map commits or who attested them.
GRANT SELECT (tenant_id, id, github_installation_id, github_repository_id, default_branch, enabled,
              protection_preflight_passed, autonomy_ceiling, version, single_maintainer, created_at, updated_at,
              bypass_attested_at, project_map_attested_at, enabled_at)
  ON repositories TO factory_observer;

-- Principals: not the GitHub login or user id of a person.
GRANT SELECT (tenant_id, id, kind, created_at, disabled_at) ON principals TO factory_observer;

-- API tokens: when they expire and who holds them. Never the token digest or the label.
GRANT SELECT (tenant_id, id, principal_id, audience, created_at, expires_at, revoked_at, last_used_at)
  ON api_tokens TO factory_observer;

-- The artifact index: the content address, size and kind. Not the content, which this table does not hold.
GRANT SELECT (tenant_id, content_sha256, size_bytes, media_type, backend, retention_class, created_by_job_id,
              created_by_stage_run_id, created_at)
  ON artifacts TO factory_observer;

-- Webhook deliveries: not the sender, the body digest or the semantic key.
GRANT SELECT (tenant_id, id, delivery_id, event_name, action, github_installation_id, github_repository_id,
              received_at)
  ON webhook_deliveries TO factory_observer;

-- Jobs: not the idempotency key (chosen by a client), the request digest or the ledger head hash.
GRANT SELECT (tenant_id, id, repository_id, requester_principal_id, status, version, execution_mode,
              autonomy_level, pipeline_scope, correlation_id, webhook_delivery_id, policy_hash,
              ledger_head_sequence, created_at, updated_at, terminal_at)
  ON jobs TO factory_observer;

-- Stage runs: not the contract, gate report or failing set digests.
GRANT SELECT (tenant_id, id, job_id, stage_kind, run_number, status, version, lease_epoch, max_attempts,
              not_before, rework_of_stage_run_id, gate_outcome, attempts_before_last_answer, created_at,
              updated_at, finished_at, superseded_at)
  ON stage_runs TO factory_observer;

-- Attempts: not the output digest.
GRANT SELECT (tenant_id, id, job_id, stage_run_id, attempt_number, status, version, lease_owner, lease_epoch,
              lease_expires_at, last_heartbeat_at, deadline_at, teardown_deadline_at, failure_class, sandbox_id,
              sandbox_leaked, created_at, updated_at, ended_at)
  ON attempts TO factory_observer;

-- Task nodes: not the task key (written by the planner), the plan digest or the commit.
GRANT SELECT (tenant_id, id, job_id, stage_run_id, status, version, retry_count, current_attempt_id, created_at,
              updated_at, finished_at)
  ON task_nodes TO factory_observer;

-- Ledger entries: the kind of claim and when. Not the entry, its hashes or what it invalidates.
GRANT SELECT (tenant_id, job_id, sequence, entry_id, stage_run_id, attempt_id, recorded_at, inserted_at,
              execution_mode, recorded_component, recorded_fidelity, claim_kind, assurance_level, confidence_level)
  ON ledger_entries TO factory_observer;

-- Audit events: the action, decision and reason code. Not the actor's identity, the subject, the entry or the chain.
GRANT SELECT (tenant_id, sequence, event_id, actor_type, action, decision, reason, job_id, stage_run_id,
              correlation_id, created_at)
  ON audit_events TO factory_observer;

-- The outbox: the event's envelope and its delivery. Not the payload.
GRANT SELECT (seq, tenant_id, event_id, event_type, event_version, job_id, aggregate_type, aggregate_id,
              aggregate_version, transition_id, reason_code, correlation_id, causation_id, occurred_at, producer,
              traceparent, created_at, published_at, publish_attempts)
  ON outbox TO factory_observer;

GRANT SELECT (tenant_id, consumer, event_id, processed_at) ON inbox TO factory_observer;

-- Approvals: the decision, its channel and its life. Not the approver, the reason a person wrote, or the hashes
-- and commits the approval binds.
GRANT SELECT (tenant_id, id, job_id, stage_run_id, decision, approver_kind, channel, created_at, expires_at,
              invalidated_at, invalidation_reason)
  ON approvals TO factory_observer;

DO $$
DECLARE
  observed_table text;
BEGIN
  FOREACH observed_table IN ARRAY ARRAY[
    'tenants', 'repositories', 'principals', 'api_tokens', 'artifacts', 'webhook_deliveries', 'jobs',
    'stage_runs', 'attempts', 'task_nodes', 'ledger_entries', 'audit_events', 'outbox', 'inbox', 'approvals'
  ] LOOP
    EXECUTE format(
      'CREATE POLICY observer_read ON public.%I AS PERMISSIVE FOR SELECT TO factory_observer USING (true)',
      observed_table);
  END LOOP;
END
$$;
