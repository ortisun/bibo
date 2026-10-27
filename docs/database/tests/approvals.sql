-- Suite: approvals
-- Proves that an approval is bound to what the human saw (head SHA, tree, base, evidence manifest,
-- policy, spec version), that only a human principal can approve, that a record cannot be edited,
-- and that the same decision cannot be recorded twice for one head commit.

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_tenant(2);
  PERFORM dbtest.mk_job(1, 1);
  PERFORM dbtest.mk_job(1, 2);
  PERFORM dbtest.mk_stage_run(1, 1, 1, 'APPROVAL');
  PERFORM dbtest.mk_stage_run(1, 2, 2, 'APPROVAL');
END
$$;

-- An approval insert. Principal 1002 is a human of tenant 1 (GitHub id 7001), 1003 is a service.
CREATE FUNCTION dbtest.approval_sql(
  p_id uuid, p_decision text DEFAULT 'approve', p_head text DEFAULT repeat('a', 40), p_principal uuid DEFAULT dbtest.u(1002),
  p_tree text DEFAULT repeat('b', 40), p_base text DEFAULT repeat('c', 40), p_manifest text DEFAULT dbtest.sha('manifest'), p_spec text DEFAULT '3',
  p_kind text DEFAULT 'human', p_stage_run uuid DEFAULT dbtest.u(1201), p_job uuid DEFAULT dbtest.u(1101),
  p_expires text DEFAULT 'now() + interval ''72 hours''', p_tenant uuid DEFAULT dbtest.u(1), p_gh bigint DEFAULT 7001
) RETURNS text LANGUAGE sql AS $$
  SELECT format($q$INSERT INTO approvals (tenant_id, id, job_id, stage_run_id, decision, approver_principal_id, approver_kind, approver_github_user_id,
                     approver_designation, allowlist_version_hash, pr_head_sha, tree_hash, base_sha, evidence_manifest_hash, spec_version,
                     policy_hash, reason, channel, expires_at)
                   VALUES (%L, %L, %L, %L, %L, %L, %L, %s, 'approver', %L, %L, %L, %L, %L, %s, %L, 'Reviewed the evidence manifest and the diff.', 'cli', %s)$q$,
                p_tenant, p_id, p_job, p_stage_run, p_decision, p_principal, p_kind, p_gh, dbtest.sha('allowlist'), p_head, p_tree, p_base, p_manifest,
                p_spec, dbtest.sha('policy'), p_expires)
$$;

-- ---------------------------------------------------------------------------------------------
-- 1. A complete approval by a human is accepted.

DO $$
BEGIN
  PERFORM dbtest.exec(dbtest.approval_sql(dbtest.u(1)), 'factory_app');
  PERFORM dbtest.expect_eq('a bound approval by a human principal is accepted', (SELECT count(*) FROM approvals), 1::bigint);
  PERFORM dbtest.expect_true('it carries the head SHA, tree, base, manifest hash and spec version it was bound to',
    (SELECT pr_head_sha = repeat('a', 40) AND tree_hash = repeat('b', 40) AND base_sha = repeat('c', 40)
            AND evidence_manifest_hash = dbtest.sha('manifest') AND spec_version = 3 FROM approvals));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. An approve decision must be bound to everything the human saw.

DO $$
BEGIN
  PERFORM dbtest.expect_error('approve without a head SHA is refused', dbtest.approval_sql(dbtest.u(2), p_head => NULL), '23514', 'factory_app', 'approvals_approve_is_bound');
  PERFORM dbtest.expect_error('approve without a tree hash is refused', dbtest.approval_sql(dbtest.u(2), p_tree => NULL), '23514', 'factory_app', 'approvals_approve_is_bound');
  PERFORM dbtest.expect_error('approve without a base SHA is refused', dbtest.approval_sql(dbtest.u(2), p_base => NULL), '23514', 'factory_app', 'approvals_approve_is_bound');
  PERFORM dbtest.expect_error('approve without an evidence manifest hash is refused', dbtest.approval_sql(dbtest.u(2), p_manifest => NULL), '23514', 'factory_app', 'approvals_approve_is_bound');
  PERFORM dbtest.expect_error('approve without a spec version is refused', dbtest.approval_sql(dbtest.u(2), p_spec => 'NULL'), '23514', 'factory_app', 'approvals_approve_is_bound');
  PERFORM dbtest.expect_ok('reject needs no binding (nothing is being authorized)', dbtest.approval_sql(dbtest.u(3), 'reject', NULL, p_tree => NULL, p_base => NULL, p_manifest => NULL, p_spec => 'NULL'), 'factory_app');
  PERFORM dbtest.expect_error('a short or upper-case head SHA is refused', dbtest.approval_sql(dbtest.u(2), p_head => 'ABCDEF'), '23514', 'factory_app');
  PERFORM dbtest.expect_error('a head SHA of the wrong length is refused', dbtest.approval_sql(dbtest.u(2), p_head => repeat('a', 41)), '23514', 'factory_app');
  PERFORM dbtest.expect_ok('a 64-character (SHA-256 object format) head SHA is accepted', dbtest.approval_sql(dbtest.u(2), p_head => repeat('a', 64)), 'factory_app');
  PERFORM dbtest.expect_error('an evidence manifest hash that is not sha256:<hex> is refused', dbtest.approval_sql(dbtest.u(2), p_manifest => 'abc'), '23514', 'factory_app');
  PERFORM dbtest.expect_error('an unknown decision is refused',
    dbtest.approval_sql(dbtest.u(2), 'merge'), '23514', 'factory_app', 'approvals_decision_check');
  PERFORM dbtest.expect_error('an approval that expires before it is created is refused',
    dbtest.approval_sql(dbtest.u(2), p_expires => 'now() - interval ''1 hour'''), '23514', 'factory_app', 'approvals_expiry_check');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. Only a human principal of the same tenant can approve.

DO $$
BEGIN
  PERFORM dbtest.expect_error('a service principal cannot approve (the foreign key demands a human)',
    dbtest.approval_sql(dbtest.u(4), p_principal => dbtest.u(1003)), '23503', 'factory_app');
  PERFORM dbtest.expect_error('a service principal cannot approve by claiming to be a service either',
    dbtest.approval_sql(dbtest.u(4), p_principal => dbtest.u(1003), p_kind => 'service'), '23514', 'factory_app', 'approvals_approver_is_human');
  PERFORM dbtest.expect_error('the recorded GitHub user id must be the one the principal has',
    dbtest.approval_sql(dbtest.u(4), p_head => repeat('9', 40), p_gh => 7999), '23503', 'factory_app');
  PERFORM dbtest.expect_error('a human of another tenant cannot approve',
    dbtest.approval_sql(dbtest.u(4), p_principal => dbtest.u(2002)), '23503', 'factory_app');
  PERFORM dbtest.expect_error('a principal that does not exist cannot approve',
    dbtest.approval_sql(dbtest.u(4), p_principal => dbtest.u(99999)), '23503', 'factory_app');
  PERFORM dbtest.expect_error('an approval cannot name a stage run that belongs to another job',
    dbtest.approval_sql(dbtest.u(4), p_stage_run => dbtest.u(1202)), '23503', 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. The same person cannot record the same decision twice for one head commit; a new commit or a
-- different decision is a different record.

DO $$
BEGIN
  PERFORM dbtest.expect_error('the same approval of the same head by the same person is refused',
    dbtest.approval_sql(dbtest.u(5)), '23505', 'factory_app', 'approvals_one_decision_per_head');
  PERFORM dbtest.expect_ok('the same person can approve a new head commit', dbtest.approval_sql(dbtest.u(5), p_head => repeat('d', 40)), 'factory_app');
  PERFORM dbtest.expect_ok('the same person can also reject the same head', dbtest.approval_sql(dbtest.u(5), 'reject'), 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 5. An approval is a record. It can be invalidated once and never edited.

DO $$
DECLARE
  a uuid := dbtest.u(1);
BEGIN
  PERFORM dbtest.expect_error('the application role cannot change the decision (no column grant)',
    format($q$UPDATE approvals SET decision = 'reject' WHERE id = %L$q$, a), '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot move the binding to another head commit (no column grant)',
    format($q$UPDATE approvals SET pr_head_sha = %L WHERE id = %L$q$, repeat('e', 40), a), '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot extend an approval (no column grant)',
    format($q$UPDATE approvals SET expires_at = now() + interval '10 days' WHERE id = %L$q$, a), '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot delete an approval', 'DELETE FROM approvals', '42501', 'factory_app');
  PERFORM dbtest.expect_error('the owner cannot edit an approval either (trigger)',
    format($q$UPDATE approvals SET decision = 'reject' WHERE id = %L$q$, a), '23514', NULL, 'approvals_record_is_immutable');
  PERFORM dbtest.expect_error('an invalidation needs a reason',
    format($q$UPDATE approvals SET invalidated_at = now() WHERE id = %L$q$, a), '23514', 'factory_app', 'approvals_invalidation_check');

  PERFORM dbtest.exec(format($q$UPDATE approvals SET invalidated_at = now(), invalidation_reason = 'A new commit landed on the head branch.' WHERE id = %L$q$, a), 'factory_app');
  PERFORM dbtest.expect_true('an approval can be invalidated once', (SELECT invalidated_at IS NOT NULL FROM approvals WHERE id = a));
  PERFORM dbtest.expect_error('an invalidation cannot be changed',
    format($q$UPDATE approvals SET invalidation_reason = 'A different reason.' WHERE id = %L$q$, a), '23514', 'factory_app', 'approvals_record_is_immutable');
  PERFORM dbtest.expect_error('an invalidation cannot be undone',
    format($q$UPDATE approvals SET invalidated_at = NULL, invalidation_reason = NULL WHERE id = %L$q$, a), '23514', 'factory_app', 'approvals_record_is_immutable');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 6. The predicate for "this approval still counts" (the storage layer's query): bound to the current head,
-- not invalidated, not expired.

DO $$
BEGIN
  PERFORM dbtest.exec(dbtest.approval_sql(dbtest.u(7), p_head => repeat('a', 64)), 'factory_app');
END
$$;

DO $$
DECLARE
  q text := $q$SELECT count(*) FROM approvals
                WHERE tenant_id = %L AND job_id = %L AND decision = 'approve' AND pr_head_sha = %L
                  AND invalidated_at IS NULL AND expires_at > now()$q$;
  n bigint;
BEGIN
  EXECUTE format(q, dbtest.u(1), dbtest.u(1101), repeat('a', 64)) INTO n;
  PERFORM dbtest.expect_eq('the 64-character head approval counts for a job whose head is that commit', n, 1::bigint);
  EXECUTE format(q, dbtest.u(1), dbtest.u(1101), repeat('f', 40)) INTO n;
  PERFORM dbtest.expect_eq('no approval counts for a head commit nobody approved', n, 0::bigint);
  EXECUTE format(q, dbtest.u(1), dbtest.u(1101), repeat('a', 40)) INTO n;
  PERFORM dbtest.expect_eq('the invalidated approval of the first head does not count', n, 0::bigint);
  EXECUTE format(q, dbtest.u(2), dbtest.u(1101), repeat('a', 64)) INTO n;
  PERFORM dbtest.expect_eq('and an approval never counts under another tenant', n, 0::bigint);
END
$$;
