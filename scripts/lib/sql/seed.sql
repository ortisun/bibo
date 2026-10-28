-- Rows for the restore drill (work package s1-local-deployment).
--
-- Run as the database superuser, after docs/database/tests/00_helpers.sql has been loaded into the same
-- session (the script feeds both files, in that order). The helpers are the DBA's fixture builders: they make
-- tenants, repositories, jobs and stage runs, append ledger entries with the hash the database expects, and
-- write audit events. Using them means the drill's data is shaped exactly like the data the database tests use.
--
-- What it makes:
--   two tenants; three jobs (two for tenant 1, one for tenant 2) with a stage run each;
--   a ledger chain of 4, 3 and 3 entries; an audit chain of 5 events for each tenant.
-- The artifact index rows are added by the script after it has written the blobs.
-- At the end the helper schema and its database setting are removed, so the dump holds only product objects.

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_tenant(2);
  PERFORM dbtest.mk_job(1, 1);
  PERFORM dbtest.mk_job(1, 2);
  PERFORM dbtest.mk_job(2, 1);
  PERFORM dbtest.mk_stage_run(1, 1, 1);
  PERFORM dbtest.mk_stage_run(1, 2, 2);
  PERFORM dbtest.mk_stage_run(2, 1, 1);
  FOR n IN 1..4 LOOP PERFORM dbtest.append_entry(1, dbtest.u(1101), dbtest.u(1201), n); END LOOP;
  FOR n IN 1..3 LOOP PERFORM dbtest.append_entry(1, dbtest.u(1102), dbtest.u(1202), n); END LOOP;
  FOR n IN 1..3 LOOP PERFORM dbtest.append_entry(2, dbtest.u(2101), dbtest.u(2201), n); END LOOP;
  FOR n IN 1..5 LOOP PERFORM dbtest.audit(1, n); END LOOP;
  FOR n IN 1..5 LOOP PERFORM dbtest.audit(2, n); END LOOP;
END
$$;

-- The engine moves each job's ledger head with every append (docs/database/ledger-and-audit.md, "The job head").
-- The builders do not, and a head left behind is a problem the chain verifier reports, so move it here.
UPDATE jobs j SET ledger_head_sequence = h.s, ledger_head_hash = e.entry_hash, version = j.version + 1
  FROM (SELECT tenant_id, job_id, max(sequence) AS s FROM ledger_entries GROUP BY tenant_id, job_id) h
  JOIN ledger_entries e ON e.tenant_id = h.tenant_id AND e.job_id = h.job_id AND e.sequence = h.s
 WHERE j.tenant_id = h.tenant_id AND j.id = h.job_id;

-- The artifact index. Tenant 1 holds blobs 1 to 4, tenant 2 holds blobs 4 and 5 (blob 4 is shared by hash, as
-- ADR 0008 allows). The hashes come from the script, which wrote the files.
\set ON_ERROR_STOP on
INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend)
SELECT dbtest.u(CASE WHEN n <= 4 THEN 1 ELSE 2 END), 'sha256:' || h, sz, 'text/plain', 'local-fs'
  FROM unnest(string_to_array(:'blob_hashes', ',')) WITH ORDINALITY AS t(h, n)
  JOIN unnest(string_to_array(:'blob_sizes', ',')::bigint[]) WITH ORDINALITY AS s(sz, m) ON m = n
UNION ALL
SELECT dbtest.u(2), 'sha256:' || h, sz, 'text/plain', 'local-fs'
  FROM unnest(string_to_array(:'blob_hashes', ',')) WITH ORDINALITY AS t(h, n)
  JOIN unnest(string_to_array(:'blob_sizes', ',')::bigint[]) WITH ORDINALITY AS s(sz, m) ON m = n
 WHERE n = 4;

DROP SCHEMA dbtest CASCADE;
ALTER DATABASE factory RESET dbtest.tenant;
