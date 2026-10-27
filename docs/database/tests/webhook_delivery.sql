-- Suite: webhook_delivery
-- Proves that a second delivery with the same delivery id violates a unique constraint and is handled
-- without creating a second job or outbox row (supports NT-WH-04). Also covers the two other ways a
-- delivery can repeat: the same signed body under a fresh delivery header, and the same event under a
-- new delivery id. The 50-way concurrent replay runs from scripts/db-test.sh after this file.

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
END
$$;

-- The receiver, as the storage layer is expected to write it: record the delivery, and only when the
-- insert took effect create the job and admit it with its event, all in one transaction. A repeat
-- conflicts on one of the unique keys, ON CONFLICT DO NOTHING absorbs it, and nothing else is written.
CREATE FUNCTION dbtest.receive_delivery(p_tenant int, p_delivery text, p_body text, p_semantic text DEFAULT NULL) RETURNS boolean
LANGUAGE plpgsql AS $$
DECLARE
  d uuid;
  j uuid := gen_random_uuid();
  tenant uuid := dbtest.u(p_tenant);
BEGIN
  INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, action, github_installation_id, github_repository_id,
                                  sender_github_user_id, body_sha256, semantic_key)
  VALUES (tenant, gen_random_uuid(), p_delivery, 'issues', 'labeled', 9000 + p_tenant, 8000 + p_tenant, 7000 + p_tenant,
          dbtest.sha(p_body), dbtest.sha(coalesce(p_semantic, 'semantic:' || p_body)))
  ON CONFLICT DO NOTHING
  RETURNING id INTO d;
  IF d IS NULL THEN
    RETURN false;
  END IF;
  INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id, webhook_delivery_id)
  VALUES (tenant, j, dbtest.u(p_tenant * 1000 + 1), dbtest.u(p_tenant * 1000 + 2), 'production', 'L1', ARRAY['INTAKE'], gen_random_uuid(), d);
  UPDATE jobs SET status = 'ACTIVE', version = version + 1 WHERE tenant_id = tenant AND id = j;
  INSERT INTO outbox (tenant_id, event_id, event_type, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id,
                      correlation_id, occurred_at, producer, payload)
  VALUES (tenant, gen_random_uuid(), 'job.admitted', j, 'job', j, 2, 'J01', gen_random_uuid(), now(), 'workflow.engine',
          jsonb_build_object('delivery_id', p_delivery));
  RETURN true;
END
$$;

CREATE FUNCTION dbtest.totals() RETURNS text LANGUAGE sql AS $$
  SELECT format('deliveries=%s jobs=%s outbox=%s',
    (SELECT count(*) FROM webhook_deliveries), (SELECT count(*) FROM jobs), (SELECT count(*) FROM outbox))
$$;

-- ---------------------------------------------------------------------------------------------
-- 1. The first delivery creates one delivery row, one job and one outbox row.

DO $$
BEGIN
  PERFORM dbtest.expect_true('the first delivery is accepted', dbtest.receive_delivery(1, 'delivery-0001', 'body one'));
  PERFORM dbtest.expect_eq('it created exactly one delivery, one job and one outbox row', dbtest.totals(), 'deliveries=1 jobs=1 outbox=1');
  PERFORM dbtest.expect_true('the job points back at its delivery',
    (SELECT j.webhook_delivery_id = d.id FROM jobs j JOIN webhook_deliveries d ON d.tenant_id = j.tenant_id AND d.id = j.webhook_delivery_id));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. A second delivery with the same delivery id violates the unique constraint.

DO $$
BEGIN
  PERFORM dbtest.expect_error('a raw INSERT of the same delivery id violates the unique constraint',
    format($q$INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256)
              VALUES (%L, gen_random_uuid(), 'delivery-0001', 'issues', 9001, %L)$q$, dbtest.u(1), dbtest.sha('a different body')),
    '23505', 'factory_app', 'webhook_deliveries_tenant_id_delivery_id_key');
  PERFORM dbtest.expect_true('the receiver reports the repeat as not new (acknowledge and ignore)',
    NOT dbtest.receive_delivery(1, 'delivery-0001', 'body one'));
  PERFORM dbtest.expect_true('the same delivery id with another body is also a repeat',
    NOT dbtest.receive_delivery(1, 'delivery-0001', 'body two'));
  PERFORM dbtest.expect_eq('no second delivery, job or outbox row was created', dbtest.totals(), 'deliveries=1 jobs=1 outbox=1');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. The signature covers the body and not the headers, so a captured body replayed under a fresh
-- delivery id arrives with a new id and the same body hash. The body hash catches it.

DO $$
BEGIN
  PERFORM dbtest.expect_error('a replayed body under a fresh delivery id violates the body hash constraint',
    format($q$INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256)
              VALUES (%L, gen_random_uuid(), 'delivery-0002', 'issues', 9001, %L)$q$, dbtest.u(1), dbtest.sha('body one')),
    '23505', 'factory_app', 'webhook_deliveries_tenant_id_body_sha256_key');
  PERFORM dbtest.expect_true('the receiver treats the replayed body as a repeat', NOT dbtest.receive_delivery(1, 'delivery-0002', 'body one'));
  PERFORM dbtest.expect_eq('still one delivery, one job, one outbox row', dbtest.totals(), 'deliveries=1 jobs=1 outbox=1');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. The same event under a new delivery id and a different body is a semantic duplicate
-- (policies/security.yaml, webhook.semantic_idempotency). A legitimate relabel has a new key.

DO $$
BEGIN
  PERFORM dbtest.expect_true('a first event for an issue is accepted', dbtest.receive_delivery(1, 'delivery-0010', 'label event body A', 'issue-7-labeled-t1'));
  PERFORM dbtest.expect_true('the same event under a new delivery id and body is a semantic duplicate', NOT dbtest.receive_delivery(1, 'delivery-0011', 'label event body B', 'issue-7-labeled-t1'));
  PERFORM dbtest.expect_error('a raw INSERT of the semantic duplicate violates the semantic key constraint',
    format($q$INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256, semantic_key)
              VALUES (%L, gen_random_uuid(), 'delivery-0012', 'issues', 9001, %L, %L)$q$, dbtest.u(1), dbtest.sha('body C'), dbtest.sha('issue-7-labeled-t1')),
    '23505', 'factory_app', 'webhook_deliveries_tenant_id_semantic_key_key');
  PERFORM dbtest.expect_true('a legitimate relabel (a new updated_at, so a new semantic key) is processed', dbtest.receive_delivery(1, 'delivery-0013', 'label event body D', 'issue-7-labeled-t2'));
  PERFORM dbtest.expect_eq('two more jobs exist, one for each distinct event', dbtest.totals(), 'deliveries=3 jobs=3 outbox=3');
  PERFORM dbtest.expect_error('a semantic key that is not a SHA-256 is rejected',
    format($q$INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, github_installation_id, body_sha256, semantic_key)
              VALUES (%L, gen_random_uuid(), 'delivery-0014', 'issues', 9001, %L, 'not-a-hash')$q$, dbtest.u(1), dbtest.sha('body E')),
    '23514', 'factory_app');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 5. The backstop under the receiver code: even a receiver that forgot ON CONFLICT cannot make a
-- second job, a second outbox event for the same aggregate version, or a second admission.

DO $$
DECLARE
  d uuid := (SELECT id FROM webhook_deliveries WHERE delivery_id = 'delivery-0001');
  j uuid := (SELECT id FROM jobs WHERE webhook_delivery_id = (SELECT id FROM webhook_deliveries WHERE delivery_id = 'delivery-0001'));
BEGIN
  PERFORM dbtest.expect_error('a second job from the same delivery violates a unique constraint',
    format($q$INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id, webhook_delivery_id)
              VALUES (%L, gen_random_uuid(), %L, %L, 'production', 'L1', ARRAY['INTAKE'], gen_random_uuid(), %L)$q$, dbtest.u(1), dbtest.u(1001), dbtest.u(1002), d),
    '23505', 'factory_app', 'jobs_tenant_id_webhook_delivery_id_key');
  PERFORM dbtest.expect_error('a second admission event for the same job version violates a unique constraint',
    format($q$INSERT INTO outbox (tenant_id, event_id, event_type, job_id, aggregate_type, aggregate_id, aggregate_version, transition_id, correlation_id, occurred_at, producer, payload)
              VALUES (%L, gen_random_uuid(), 'job.admitted', %L, 'job', %L, 2, 'J01', gen_random_uuid(), now(), 'workflow.engine', '{}')$q$, dbtest.u(1), j, j),
    '23505', 'factory_app', 'outbox_one_event_per_aggregate_version');
  PERFORM dbtest.expect_eq('the totals never changed', dbtest.totals(), 'deliveries=3 jobs=3 outbox=3');
END
$$;

-- Delivery rows are records of fact: the application role cannot rewrite or remove them.
DO $$
BEGIN
  PERFORM dbtest.expect_error('the application role cannot UPDATE a delivery', 'UPDATE webhook_deliveries SET delivery_id = ''x''', '42501', 'factory_app');
  PERFORM dbtest.expect_error('the application role cannot DELETE a delivery', 'DELETE FROM webhook_deliveries', '42501', 'factory_app');
END
$$;
