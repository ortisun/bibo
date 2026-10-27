-- What the application role may do. Every grant is listed here, in one place, so a reviewer can read
-- the whole privilege model in one file. The role owns nothing, so it cannot ALTER, DROP or TRUNCATE
-- any table, create triggers, or change a column default.
--
-- Rules followed below:
--   * Reference data (the state machine) is read-only.
--   * Records of fact (ledger, audit, original request, artifacts, webhook deliveries, inbox, task
--     dependencies, run-artifact links) are INSERT and SELECT only: no UPDATE, no DELETE.
--   * Aggregates that move through states get UPDATE on the columns that move, never on the key,
--     the tenant, the creation time or a hash that names history.
--   * Nobody gets DELETE. Retention and archival will use a separate maintenance role, designed
--     with the outbox retention work (ADR 0004).
--   * Tenants are created by the owner role during onboarding; the application only reads them.

-- Reference data.
GRANT SELECT ON state_machine_states, state_machine_transitions, state_machine_edges TO factory_app;

GRANT SELECT ON tenants TO factory_app;

GRANT SELECT, INSERT ON repositories TO factory_app;
GRANT UPDATE (default_branch, enabled, protection_preflight_passed, autonomy_ceiling, version) ON repositories TO factory_app;

GRANT SELECT, INSERT ON principals TO factory_app;
GRANT UPDATE (login, disabled_at) ON principals TO factory_app;

-- A token's hash, audience and expiry never change. It can be revoked and its use recorded.
GRANT SELECT, INSERT ON api_tokens TO factory_app;
GRANT UPDATE (revoked_at, last_used_at) ON api_tokens TO factory_app;
GRANT SELECT ON active_api_tokens TO factory_app;

GRANT SELECT, INSERT ON artifacts, stage_run_artifacts, webhook_deliveries, original_requests TO factory_app;

GRANT SELECT, INSERT ON jobs TO factory_app;
GRANT UPDATE (status, version, policy_hash, normalized_request_sha256, ledger_head_sequence, ledger_head_hash, terminal_at)
  ON jobs TO factory_app;

GRANT SELECT, INSERT ON stage_runs TO factory_app;
GRANT UPDATE (status, version, lease_epoch, max_attempts, not_before, stage_contract_sha256, gate_outcome,
              gate_report_sha256, finished_at, superseded_at)
  ON stage_runs TO factory_app;

-- lease_epoch on an attempt is fixed when the attempt is created.
GRANT SELECT, INSERT ON attempts TO factory_app;
GRANT UPDATE (status, version, lease_owner, lease_expires_at, last_heartbeat_at, deadline_at, teardown_deadline_at,
              failure_class, output_sha256, sandbox_id, sandbox_leaked, ended_at)
  ON attempts TO factory_app;

GRANT SELECT, INSERT ON task_nodes TO factory_app;
GRANT UPDATE (status, version, retry_count, current_attempt_id, commit_sha, finished_at) ON task_nodes TO factory_app;
GRANT SELECT, INSERT ON task_node_dependencies TO factory_app;

-- The ledger and the audit log: INSERT and SELECT only (NT-AUD-01).
GRANT SELECT, INSERT ON ledger_entries, audit_events TO factory_app;
GRANT SELECT ON ledger_current_claims, ledger_assurance_levels TO factory_app;

-- The outbox keeps its row once written; the relay marks it published.
GRANT SELECT, INSERT ON outbox TO factory_app;
GRANT UPDATE (published_at, publish_attempts) ON outbox TO factory_app;
GRANT SELECT, INSERT ON inbox TO factory_app;

GRANT SELECT, INSERT ON approvals TO factory_app;
GRANT UPDATE (invalidated_at, invalidation_reason) ON approvals TO factory_app;
