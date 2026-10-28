-- Rows written on the schema BEFORE the migrations of ports v1.1 (migrations 1 to 14), by the statements that the
-- code of that time made, so that the data-preserving upgrade test of scripts/db-test.sh (the `migrations` suite)
-- has something to keep. Every tenant-owned table gets rows. Loaded after 00_helpers.sql.

SELECT dbtest.mk_tenant(1);
SELECT dbtest.mk_job(1, 1);
SELECT dbtest.set_status('jobs', 1, dbtest.u(1101), 'ACTIVE');

INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend)
VALUES (dbtest.u(1), dbtest.sha('report'), 10, 'application/json', 'local-fs'),
       (dbtest.u(1), dbtest.sha('plan'), 20, 'application/json', 'local-fs'),
       (dbtest.u(1), dbtest.sha('input'), 30, 'text/plain', 'local-fs');

-- Six stage runs of the job in six states.
SELECT dbtest.mk_stage_run(1, 1, 1, 'INTAKE');
SELECT dbtest.mk_stage_run(1, 1, 2, 'REPOSITORY_INTELLIGENCE');
SELECT dbtest.mk_stage_run(1, 1, 3, 'SPECIFICATION');
SELECT dbtest.mk_stage_run(1, 1, 4, 'ARCHITECTURE');
SELECT dbtest.mk_stage_run(1, 1, 5, 'TASK_PLANNING');
SELECT dbtest.mk_stage_run(1, 1, 6, 'IMPLEMENTATION');
-- 1201 PASSED
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1201), 'READY');
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1201), 'RUNNING', ', lease_epoch = lease_epoch + 1');
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1201), 'GATING');
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1201), 'PASSED', ', gate_outcome = ''PASSED'', gate_report_sha256 = ' || quote_literal(dbtest.sha('report')) || ', finished_at = now()');
-- 1202 READY, claimable
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1202), 'READY');
-- 1203 RUNNING with a live attempt
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1203), 'READY');
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1203), 'RUNNING', ', lease_epoch = lease_epoch + 1');
INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
VALUES (dbtest.u(1), dbtest.u(1301), dbtest.u(1101), dbtest.u(1203), 1, 'worker-a', 1, now() + interval '30 seconds', now() + interval '1 hour');
-- 1204 WAITING_FOR_HUMAN after a failed attempt
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1204), 'READY');
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1204), 'RUNNING', ', lease_epoch = lease_epoch + 1');
INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
VALUES (dbtest.u(1), dbtest.u(1302), dbtest.u(1101), dbtest.u(1204), 1, 'worker-b', 1, now() + interval '30 seconds', now() + interval '1 hour');
SELECT dbtest.set_status('attempts', 1, dbtest.u(1302), 'FAILED', ', failure_class = ''TOOL_ERROR'', ended_at = now()');
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1204), 'WAITING_FOR_HUMAN');
-- 1205 SKIPPED
SELECT dbtest.set_status('stage_runs', 1, dbtest.u(1205), 'SKIPPED', ', gate_outcome = ''NOT_APPLICABLE'', finished_at = now()');
-- 1206 PENDING stays as it is, and holds the task graph.
INSERT INTO task_nodes (tenant_id, id, job_id, stage_run_id, task_key, plan_sha256)
VALUES (dbtest.u(1), dbtest.u(1401), dbtest.u(1101), dbtest.u(1206), 't-001', dbtest.sha('plan')),
       (dbtest.u(1), dbtest.u(1402), dbtest.u(1101), dbtest.u(1206), 't-002', dbtest.sha('plan'));
INSERT INTO task_node_dependencies (tenant_id, stage_run_id, task_node_id, depends_on_task_node_id)
VALUES (dbtest.u(1), dbtest.u(1206), dbtest.u(1402), dbtest.u(1401));
INSERT INTO stage_run_artifacts (tenant_id, job_id, stage_run_id, direction, role, content_sha256)
VALUES (dbtest.u(1), dbtest.u(1101), dbtest.u(1202), 'input', 'spec', dbtest.sha('input'));

-- The ledger, with the head moved in the same update as the old code did (version raised by one).
SELECT dbtest.append_entry(1, dbtest.u(1101), dbtest.u(1201), 1);
SELECT dbtest.append_entry(1, dbtest.u(1101), dbtest.u(1201), 2);
UPDATE jobs SET ledger_head_sequence = 2, ledger_head_hash = (SELECT entry_hash FROM ledger_entries WHERE job_id = dbtest.u(1101) AND sequence = 2), version = version + 1
 WHERE id = dbtest.u(1101);

SELECT dbtest.audit(1, 1);
SELECT dbtest.audit(1, 2);
INSERT INTO outbox (tenant_id, event_id, event_type, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id, correlation_id, occurred_at, producer, payload)
VALUES (dbtest.u(1), dbtest.u(1901), 'job.admitted', dbtest.u(1101), 'job', dbtest.u(1101), 2, 'J01', dbtest.u(1501), now(), 'workflow.engine', '{}');
INSERT INTO inbox (tenant_id, consumer, event_id) VALUES (dbtest.u(1), 'dashboard', dbtest.u(1901));
INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256)
VALUES (dbtest.u(1), dbtest.u(1701), 'delivery-1', 'issues', 9001, dbtest.sha('body'));
INSERT INTO original_requests (tenant_id, id, job_id, revision, source, request_text, content_sha256)
VALUES (dbtest.u(1), dbtest.u(1801), dbtest.u(1101), 1, 'api', 'Add a retry.', 'sha256:' || encode(sha256(convert_to('Add a retry.', 'UTF8')), 'hex'));
INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, expires_at)
VALUES (dbtest.u(1), dbtest.u(1951), dbtest.u(1002), sha256(convert_to('token', 'UTF8')), 'factory-api', now() + interval '1 day');
INSERT INTO approvals (tenant_id, id, job_id, stage_run_id, decision, approver_principal_id, approver_github_user_id, approver_designation,
                       allowlist_version_hash, policy_hash, reason, channel, expires_at, pr_head_sha, tree_hash, base_sha, evidence_manifest_hash, spec_version)
VALUES (dbtest.u(1), dbtest.u(1961), dbtest.u(1101), dbtest.u(1201), 'approve', dbtest.u(1002), 7001, 'approver', dbtest.sha('allowlist'), dbtest.sha('policy'),
        'Reviewed the evidence.', 'cli', now() + interval '72 hours', repeat('a', 40), repeat('b', 40), repeat('c', 40), dbtest.sha('manifest'), 1);
