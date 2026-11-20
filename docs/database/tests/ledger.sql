-- Suite: ledger
-- Proves the evidence ledger is append-only at the database level (UPDATE, DELETE and TRUNCATE fail
-- for the application role, and for the owner through the trigger), that a gapped, forked or forged
-- insert fails, that fake evidence cannot enter a production job, and that tampering is detectable.

-- ---------------------------------------------------------------------------------------------
-- Fixtures: tenant 1 with a production job (1101, stage run 1201), a test job (1102, stage run 1202)
-- and a scratch job (1103, stage run 1203) for single-purpose cases.

DO $$
BEGIN
  PERFORM dbtest.mk_tenant(1);
  PERFORM dbtest.mk_tenant(2);
  PERFORM dbtest.mk_job(1, 1);
  PERFORM dbtest.mk_job(1, 2, 'test');
  PERFORM dbtest.mk_job(1, 3);
  PERFORM dbtest.mk_stage_run(1, 1, 1);
  PERFORM dbtest.mk_stage_run(1, 2, 2);
  PERFORM dbtest.mk_stage_run(1, 3, 3);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 1. The application role can append a valid chain.

DO $$
DECLARE
  j uuid := dbtest.u(1101);
  sr uuid := dbtest.u(1201);
BEGIN
  PERFORM dbtest.exec(format('SELECT dbtest.append_entry(1, %L, %L, 1)', j, sr), 'factory_app');
  PERFORM dbtest.exec(format('SELECT dbtest.append_entry(1, %L, %L, 2, ''measured_fact'', ''production'', ''real'', ''IMPLEMENTED'')', j, sr), 'factory_app');
  PERFORM dbtest.exec(format('SELECT dbtest.append_entry(1, %L, %L, 3)', j, sr), 'factory_app');
  PERFORM dbtest.expect_eq('the application role appended three entries to the chain of job 1101',
    (SELECT count(*) FROM ledger_entries WHERE job_id = j), 3::bigint);
  PERFORM dbtest.expect_eq('the database derived prev_sequence for entries 2 and 3',
    (SELECT array_agg(prev_sequence ORDER BY sequence) FROM ledger_entries WHERE job_id = j), ARRAY[NULL, 1, 2]::bigint[]);
  PERFORM dbtest.expect_true('sequence 1 has no predecessor hash', (SELECT prev_entry_hash IS NULL FROM ledger_entries WHERE job_id = j AND sequence = 1));
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 2. UPDATE, DELETE and TRUNCATE fail for the application role (grant layer) and for the owner
-- (trigger layer). The row count never changes.

DO $$
DECLARE
  j uuid := dbtest.u(1101);
  before bigint := (SELECT count(*) FROM ledger_entries);
BEGIN
  PERFORM dbtest.expect_error('application role: UPDATE on the ledger is denied',
    format('UPDATE ledger_entries SET confidence_level = ''low'' WHERE job_id = %L', j), '42501', 'factory_app', NULL, 'permission denied for table ledger_entries');
  PERFORM dbtest.expect_error('application role: DELETE on the ledger is denied',
    format('DELETE FROM ledger_entries WHERE job_id = %L', j), '42501', 'factory_app', NULL, 'permission denied for table ledger_entries');
  PERFORM dbtest.expect_error('application role: TRUNCATE on the ledger is denied',
    'TRUNCATE ledger_entries', '42501', 'factory_app', NULL, 'permission denied for table ledger_entries');
  PERFORM dbtest.expect_error('application role: DROP TABLE on the ledger is denied',
    'DROP TABLE ledger_entries', '42501', 'factory_app', NULL, 'must be owner of table ledger_entries');
  PERFORM dbtest.expect_error('application role: DISABLE TRIGGER on the ledger is denied',
    'ALTER TABLE ledger_entries DISABLE TRIGGER ledger_entries_no_change', '42501', 'factory_app', NULL, 'must be owner of table ledger_entries');
  PERFORM dbtest.expect_error('application role: INSERT with an updated row through ON CONFLICT DO UPDATE is denied',
    format($q$INSERT INTO ledger_entries (tenant_id, job_id, sequence, entry_id, stage_run_id, recorded_at, execution_mode, recorded_component,
              recorded_fidelity, claim_kind, confidence_level, entry_hash, canonical_json)
              VALUES (%L, %L, 1, %L, %L, now(), 'production', 'x', 'real', 'assumption', 'high', %L, '{}')
              ON CONFLICT (tenant_id, job_id, sequence) DO UPDATE SET confidence_level = 'low'$q$,
           dbtest.u(1), j, dbtest.u(99), dbtest.u(1201), dbtest.sha('x')), '42501', 'factory_app');

  -- The owner (the superuser running this test) is stopped by the trigger.
  PERFORM dbtest.expect_error('owner: UPDATE on the ledger is stopped by the append-only trigger',
    format('UPDATE ledger_entries SET confidence_level = ''low'' WHERE job_id = %L', j), '42501', NULL, NULL, 'ledger_entries is append-only: UPDATE%');
  PERFORM dbtest.expect_error('owner: DELETE on the ledger is stopped by the append-only trigger',
    format('DELETE FROM ledger_entries WHERE job_id = %L', j), '42501', NULL, NULL, 'ledger_entries is append-only: DELETE%');
  PERFORM dbtest.expect_error('owner: a plain TRUNCATE is refused by PostgreSQL itself, because foreign keys reference the ledger',
    'TRUNCATE ledger_entries', '0A000');
  PERFORM dbtest.expect_error('owner: TRUNCATE ... CASCADE on the ledger is stopped by the append-only trigger',
    'TRUNCATE ledger_entries CASCADE', '42501', NULL, NULL, '% is append-only: TRUNCATE%');
  PERFORM dbtest.expect_error('owner: TRUNCATE ... CASCADE through the job table is stopped as well',
    'TRUNCATE jobs CASCADE', '42501', NULL, NULL, '% is append-only: TRUNCATE%');
  PERFORM dbtest.expect_eq('the ledger still holds the same rows after all those attempts', (SELECT count(*) FROM ledger_entries), before);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 3. A gapped, forked or forged insert fails. Job 1101 holds entries 1 to 3.

DO $$
DECLARE
  j uuid := dbtest.u(1101);
  sr uuid := dbtest.u(1201);
  h2 text := (SELECT entry_hash FROM ledger_entries WHERE job_id = j AND sequence = 2);
  h3 text := (SELECT entry_hash FROM ledger_entries WHERE job_id = j AND sequence = 3);
BEGIN
  PERFORM dbtest.expect_error('a gapped insert fails: entry 5 after entry 3, naming entry 3 as its predecessor',
    format('SELECT dbtest.insert_entry(1, %L, %L, 5, %L)', j, sr, h3), '23503', 'factory_app');
  PERFORM dbtest.expect_error('a gapped insert fails: entry 5 with no predecessor hash',
    format('SELECT dbtest.insert_entry(1, %L, %L, 5, NULL)', j, sr), '23514', 'factory_app', 'ledger_entries_first_has_no_predecessor');
  PERFORM dbtest.expect_error('a fork fails: a second entry 3 on top of entry 2',
    format('SELECT dbtest.insert_entry(1, %L, %L, 3, %L, ''hypothesis'', p_entry_id => %L)', j, sr, h2, dbtest.u(7777)), '23505', 'factory_app', 'ledger_entries_pkey');
  PERFORM dbtest.expect_error('a forged link fails: entry 4 names a predecessor hash that does not exist',
    format('SELECT dbtest.insert_entry(1, %L, %L, 4, %L)', j, sr, dbtest.sha('forged')), '23503', 'factory_app');
  PERFORM dbtest.expect_error('a link to the wrong predecessor fails: entry 4 names entry 2, not entry 3',
    format('SELECT dbtest.insert_entry(1, %L, %L, 4, %L)', j, sr, h2), '23503', 'factory_app');
  PERFORM dbtest.expect_error('a wrong entry_hash fails',
    format('SELECT dbtest.insert_entry(1, %L, %L, 4, %L, p_hash => %L)', j, sr, h3, dbtest.sha('not the hash')),
    '23514', 'factory_app', 'ledger_entries_hash_matches_document');
  PERFORM dbtest.expect_error('a document that disagrees with a column fails (claim kind)',
    format('SELECT dbtest.insert_entry(1, %L, %L, 4, %L, p_col_kind => ''measured_fact'')', j, sr, h3),
    '23514', 'factory_app', 'ledger_entries_document_matches_columns');
  PERFORM dbtest.expect_error('a document that is not JSON fails',
    format('SELECT dbtest.insert_entry(1, %L, %L, 4, %L, p_doc => ''not json'', p_hash => %L)', j, sr, h3, dbtest.ledger_hash(h3, 'not json')),
    '23514', 'factory_app', 'ledger_entries_document_matches_columns');
  PERFORM dbtest.expect_error('a document that carries its own entry_hash fails',
    format('SELECT dbtest.insert_entry(1, %L, %L, 4, %L, p_doc => (dbtest.ledger_doc(%L, %L, 4, %L, md5(%L)::uuid)::jsonb || ''{"entry_hash":"x"}'')::text)',
           j, sr, h3, j, sr, h3, j::text || ':4'), '23514', 'factory_app');
  PERFORM dbtest.expect_error('entry 1 cannot carry a predecessor hash (job 1103)',
    format('SELECT dbtest.insert_entry(1, %L, %L, 1, %L)', dbtest.u(1103), dbtest.u(1203), h3), '23514', 'factory_app', 'ledger_entries_first_has_no_predecessor');
  PERFORM dbtest.exec(format('SELECT dbtest.append_entry(1, %L, %L, 1)', dbtest.u(1103), dbtest.u(1203)), 'factory_app');
  PERFORM dbtest.expect_error('entry 2 must carry a predecessor hash (job 1103)',
    format('SELECT dbtest.insert_entry(1, %L, %L, 2, NULL)', dbtest.u(1103), dbtest.u(1203)), '23514', 'factory_app', 'ledger_entries_first_has_no_predecessor');
  PERFORM dbtest.expect_error('sequence 0 and negative sequences fail',
    format('SELECT dbtest.insert_entry(1, %L, %L, 0, NULL)', dbtest.u(1103), dbtest.u(1203)), '23514', 'factory_app');
  PERFORM dbtest.expect_eq('after all the failed inserts job 1101 still has exactly three entries', (SELECT count(*) FROM ledger_entries WHERE job_id = j), 3::bigint);
  PERFORM dbtest.exec(format('SELECT dbtest.append_entry(1, %L, %L, 4)', j, sr), 'factory_app');
  PERFORM dbtest.expect_eq('and the next valid entry (4) is still accepted', (SELECT count(*) FROM ledger_entries WHERE job_id = j), 4::bigint);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 4. Fake evidence cannot enter a production job (invariant INV-08). Job 1102 is a test job.

DO $$
DECLARE
  pj uuid := dbtest.u(1101);
  psr uuid := dbtest.u(1201);
  tj uuid := dbtest.u(1102);
  tsr uuid := dbtest.u(1202);
BEGIN
  PERFORM dbtest.expect_error('a fake recorder in a production entry is rejected',
    format('SELECT dbtest.append_entry(1, %L, %L, 5, ''assumption'', ''production'', ''fake'')', pj, psr),
    '23514', 'factory_app', 'ledger_entries_fake_only_in_test');
  PERFORM dbtest.expect_error('an entry marked test cannot join a production job (execution modes must agree)',
    format('SELECT dbtest.append_entry(1, %L, %L, 5, ''assumption'', ''test'', ''fake'')', pj, psr),
    '23503', 'factory_app');
  PERFORM dbtest.exec(format('SELECT dbtest.append_entry(1, %L, %L, 1, ''assumption'', ''test'', ''fake'')', tj, tsr), 'factory_app');
  PERFORM dbtest.expect_eq('a fake entry is accepted in a test job', (SELECT count(*) FROM ledger_entries WHERE job_id = tj), 1::bigint);
  PERFORM dbtest.expect_error('a fake entry can never support an assurance level, even in a test job',
    format('SELECT dbtest.append_entry(1, %L, %L, 2, ''measured_fact'', ''test'', ''fake'', ''IMPLEMENTED'')', tj, tsr),
    '23514', 'factory_app', 'ledger_entries_assurance_needs_real');
  PERFORM dbtest.expect_error('a simulated recorder cannot support an assurance level',
    format('SELECT dbtest.append_entry(1, %L, %L, 2, ''simulation_result'', ''test'', ''simulated'', ''VERIFIED_IN_SIMULATOR'')', tj, tsr),
    '23514', 'factory_app', 'ledger_entries_assurance_needs_real');
  PERFORM dbtest.expect_error('an assumption cannot carry an assurance level',
    format('SELECT dbtest.append_entry(1, %L, %L, 5, ''assumption'', ''production'', ''real'', ''IMPLEMENTED'')', pj, psr),
    '23514', 'factory_app', 'ledger_entries_assumption_has_no_assurance');
  PERFORM dbtest.expect_error('an unknown assurance level is rejected',
    format('SELECT dbtest.append_entry(1, %L, %L, 5, ''measured_fact'', ''production'', ''real'', ''SHIPPED'')', pj, psr),
    '23514', 'factory_app', 'ledger_entries_assurance_level_check');
  PERFORM dbtest.expect_error('an unknown claim kind is rejected',
    format('SELECT dbtest.append_entry(1, %L, %L, 5, ''rumour'')', pj, psr), '23514', 'factory_app', 'ledger_entries_claim_kind_check');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 5. Withdrawing a claim appends an entry that names the old ones. Job 1101 holds entries 1 to 4.

DO $$
DECLARE
  j uuid := dbtest.u(1101);
  sr uuid := dbtest.u(1201);
  e2 uuid := (SELECT entry_id FROM ledger_entries WHERE job_id = j AND sequence = 2);
  e3 uuid := (SELECT entry_id FROM ledger_entries WHERE job_id = j AND sequence = 3);
BEGIN
  PERFORM dbtest.expect_eq('before any withdrawal the assurance view lists IMPLEMENTED from entry 2',
    (SELECT array_agg(assurance_level) FROM ledger_assurance_levels WHERE job_id = j), ARRAY['IMPLEMENTED']);
  PERFORM dbtest.expect_error('withdrawing an entry that does not exist is rejected',
    format('SELECT dbtest.append_entry(1, %L, %L, 5, ''assumption'', ''production'', ''real'', NULL, ARRAY[%L]::uuid[])', j, sr, dbtest.u(424242)),
    '23514', 'factory_app', 'ledger_entries_invalidates_earlier_entries');
  PERFORM dbtest.expect_error('withdrawing the same entry twice in one entry is rejected',
    format('SELECT dbtest.append_entry(1, %L, %L, 5, ''assumption'', ''production'', ''real'', NULL, ARRAY[%L, %L]::uuid[])', j, sr, e2, e2),
    '23514', 'factory_app', 'ledger_entries_invalidates_earlier_entries');
  PERFORM dbtest.exec(format('SELECT dbtest.append_entry(1, %L, %L, 5, ''assumption'', ''production'', ''real'', NULL, ARRAY[%L, %L]::uuid[])', j, sr, e2, e3), 'factory_app');
  PERFORM dbtest.expect_eq('after withdrawal entries 2 and 3 are no longer current claims',
    (SELECT array_agg(sequence ORDER BY sequence) FROM ledger_current_claims WHERE job_id = j), ARRAY[1, 4, 5]::bigint[]);
  PERFORM dbtest.expect_eq('after withdrawal the assurance view no longer lists IMPLEMENTED',
    (SELECT count(*) FROM ledger_assurance_levels WHERE job_id = j), 0::bigint);
  PERFORM dbtest.expect_eq('the withdrawn entries are still in the ledger',
    (SELECT count(*) FROM ledger_entries WHERE job_id = j AND sequence IN (2, 3)), 2::bigint);
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 6. The chain formula is fixed by a vector computed outside PostgreSQL (Python hashlib):
--    sha256(prev_hash_text + "\n" + document_text) over the UTF-8 bytes.

DO $$
DECLARE
  doc text := '{"claim":{"kind":"assumption","statement":"Café ü ß gate"},"schema_version":1}';
BEGIN
  PERFORM dbtest.expect_eq('the chain formula matches an independent SHA-256 (with a previous hash)',
    public.ledger_entry_hash('sha256:' || repeat('a', 64), doc),
    'sha256:0f5f57aa591430b785ee073cdf1ac6e09932ee15965755ae728714f00e2bc7c3');
  PERFORM dbtest.expect_eq('the chain formula matches an independent SHA-256 (first entry, empty previous hash)',
    public.ledger_entry_hash(NULL, doc),
    'sha256:9f563e281c5bf7065d0ead6194d1e3140cee4610b140dc82263618a4d2302520');
END
$$;

-- ---------------------------------------------------------------------------------------------
-- 7. The verifier finds tampering. A superuser can bypass the triggers (session_replication_role),
-- which is the threat the chain is for. Each case is rolled back.

DO $$
DECLARE
  j uuid := dbtest.u(1101);
  t uuid := dbtest.u(1);
  off text := 'SET LOCAL session_replication_role = replica; ';
  head text := (SELECT entry_hash FROM ledger_entries WHERE job_id = j AND sequence = 5);
BEGIN
  PERFORM dbtest.exec(format('UPDATE jobs SET ledger_head_sequence = 5, ledger_head_hash = %L, version = version + 1 WHERE id = %L', head, j), 'factory_app');
  PERFORM dbtest.expect_true('an intact chain verifies: ledger_verify_chain returns NULL', public.ledger_verify_chain(t, j) IS NULL);

  -- A verify call inside the rolled-back subtransaction reports through RAISE, so the answer is read
  -- back with a message and compared here.
  PERFORM dbtest.expect_error('editing a stored document is found at that entry (entry 2)',
    off || format($q$UPDATE ledger_entries SET canonical_json = replace(canonical_json, 'passed', 'FAILED') WHERE job_id = %L AND sequence = 2;
                     DO $d$ BEGIN RAISE EXCEPTION 'verify=%%', public.ledger_verify_chain(%L, %L); END $d$ $q$, j, t, j),
    'P0001', NULL, NULL, 'verify=2');
  PERFORM dbtest.expect_error('editing a column so it disagrees with the document is found at that entry (entry 3)',
    off || format($q$UPDATE ledger_entries SET claim_kind = 'hypothesis' WHERE job_id = %L AND sequence = 3;
                     DO $d$ BEGIN RAISE EXCEPTION 'verify=%%', public.ledger_verify_chain(%L, %L); END $d$ $q$, j, t, j),
    'P0001', NULL, NULL, 'verify=3');
  PERFORM dbtest.expect_error('deleting a middle entry is found at the entry after the gap (entry 4)',
    off || format($q$DELETE FROM ledger_entries WHERE job_id = %L AND sequence = 3;
                     DO $d$ BEGIN RAISE EXCEPTION 'verify=%%', public.ledger_verify_chain(%L, %L); END $d$ $q$, j, t, j),
    'P0001', NULL, NULL, 'verify=4');
  PERFORM dbtest.expect_error('replacing an entry hash is found at that entry (entry 4)',
    off || format($q$UPDATE ledger_entries SET entry_hash = %L WHERE job_id = %L AND sequence = 4;
                     DO $d$ BEGIN RAISE EXCEPTION 'verify=%%', public.ledger_verify_chain(%L, %L); END $d$ $q$, dbtest.sha('replaced'), j, t, j),
    'P0001', NULL, NULL, 'verify=4');
  PERFORM dbtest.expect_error('deleting the tail makes the job head point past the chain (the head sequence is reported)',
    off || format($q$DELETE FROM ledger_entries WHERE job_id = %L AND sequence = 5;
                     DO $d$ BEGIN RAISE EXCEPTION 'verify=%%', public.ledger_verify_chain(%L, %L); END $d$ $q$, j, t, j),
    'P0001', NULL, NULL, 'verify=5');
  PERFORM dbtest.expect_true('and the intact chain still verifies afterwards (nothing was kept)', public.ledger_verify_chain(t, j) IS NULL);
END
$$;

-- The job head is a real foreign key, checked at commit.
DO $$
BEGIN
  PERFORM dbtest.expect_error('a job head that names no entry is rejected when the constraint is checked',
    format($q$SET CONSTRAINTS jobs_ledger_head_fk IMMEDIATE;
              UPDATE jobs SET ledger_head_sequence = 5, ledger_head_hash = %L, version = version + 1 WHERE id = %L$q$, dbtest.sha('no such entry'), dbtest.u(1101)),
    '23503', 'factory_app', 'jobs_ledger_head_fk');
  PERFORM dbtest.expect_error('a job head of sequence 0 with a hash is rejected',
    format($q$UPDATE jobs SET ledger_head_sequence = 0, ledger_head_hash = %L, version = version + 1 WHERE id = %L$q$, dbtest.sha('x'), dbtest.u(1103)),
    '23514', 'factory_app', 'jobs_ledger_head_check');
END
$$;
