-- scripts/db-perf/scenarios.sql - helpers for the concurrency runs, applied by perf.py to the write clone only.
--
-- perf.append_next appends the next ledger entry of a job in one call, the way the Store does in three statements:
-- lock the job row (FOR NO KEY UPDATE), read the head, insert the entry (the trigger checks the hash again), move the
-- head. It is SECURITY INVOKER, so it runs with the caller's rights under row-level security, as the Store does. pgbench
-- cannot build a hash chain on the client, which is why the document and the hash are made here.

CREATE FUNCTION perf.append_next(p_tenant uuid, p_job uuid, p_run uuid) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE
  h record;
  seq bigint;
  entry uuid := gen_random_uuid();
  at timestamptz := timestamptz '2026-10-28 12:00:00+00';
  doc text;
  hash text;
BEGIN
  SELECT ledger_head_sequence AS s, ledger_head_hash AS hh INTO h FROM jobs WHERE tenant_id = p_tenant AND id = p_job FOR NO KEY UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'no such job for this tenant';
  END IF;
  seq := h.s + 1;
  doc := perf.ledger_doc(p_job, p_run, NULL, seq, h.hh, entry, at, seq);
  hash := 'sha256:' || encode(sha256(convert_to(coalesce(h.hh, '') || E'\n' || doc, 'UTF8')), 'hex');
  INSERT INTO ledger_entries (tenant_id, job_id, sequence, entry_id, stage_run_id, attempt_id, recorded_at, execution_mode, recorded_component,
                              recorded_fidelity, claim_kind, assurance_level, confidence_level, invalidates, prev_entry_hash, entry_hash, canonical_json)
  VALUES (p_tenant, p_job, seq, entry, p_run, NULL, at, 'production', 'workflow.gate-evaluator', 'real', 'measured_fact', 'VERIFIED_IN_SANDBOX',
          'high', '{}', h.hh, hash, doc);
  UPDATE jobs SET ledger_head_sequence = seq, ledger_head_hash = hash WHERE tenant_id = p_tenant AND id = p_job;
  RETURN seq;
END
$$;
