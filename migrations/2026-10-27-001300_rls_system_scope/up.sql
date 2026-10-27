-- Row-level security, part 3 of 4: the system scope (ADR 0012, section 3).
--
-- The engine's loops look for work across tenants: the claim finds READY stage runs of ACTIVE jobs, the
-- sweep finds attempts whose lease or deadline has passed, the outbox relay finds unpublished events.
-- They use their own login, a member of factory_system, and their own connection pool
-- (Store::begin_system, callable from the workflow crate only).
--
-- factory_system is not a bypass. It has no BYPASSRLS, and what it gets is written out below:
--
--   * Read access to the COLUMNS the finding queries use, on stage_runs, jobs and attempts, and all
--     columns of the outbox, because the relay publishes whole events. Not the stage contract, the
--     gate report, the lease owner, the request hash or anything else.
--   * The right to LOCK stage runs and attempts. FOR NO KEY UPDATE SKIP LOCKED needs an UPDATE privilege
--     on one column and a policy that lets an UPDATE see the row. The privilege is on updated_at, the
--     policy says USING (true) WITH CHECK (false): the lock is granted and no row can ever be written, as
--     a third layer behind the missing column privileges and the version trigger.
--   * On the outbox, the relay's two bookkeeping columns (published_at, publish_attempts). The trigger
--     outbox_guard already limits what they may become.
--   * SELECT on the Diesel version table, for the start-up check that the schema is not behind.
--
-- A system transaction FINDS work and returns identifiers. The transition itself (the compare and swap on
-- the stage run, the attempt, the ledger entry, the event) is made in a tenant transaction for the tenant
-- that was found, so it happens under the tenant policy. Two claimers can both find one READY run
-- once the first system transaction has ended: the compare and swap on version, and the unique index of
-- one live attempt per stage run, decide the winner (the `lease` suite and the shell races prove it).
-- Adding a loop later (a timer for paused jobs, say) is a new migration with a new policy and a new line
-- in the `rls` suite; this one is the complete list for Slice 1.

-- Stage runs: the claim.
GRANT SELECT (tenant_id, id, job_id, status, version, not_before) ON stage_runs TO factory_system;
GRANT UPDATE (updated_at) ON stage_runs TO factory_system;
CREATE POLICY system_find ON stage_runs AS PERMISSIVE FOR SELECT TO factory_system USING (true);
CREATE POLICY system_lock ON stage_runs AS PERMISSIVE FOR UPDATE TO factory_system USING (true) WITH CHECK (false);

-- Jobs: the claim only claims stage runs of ACTIVE jobs.
GRANT SELECT (tenant_id, id, status) ON jobs TO factory_system;
CREATE POLICY system_find ON jobs AS PERMISSIVE FOR SELECT TO factory_system USING (true);

-- Attempts: the sweep.
GRANT SELECT (tenant_id, id, job_id, stage_run_id, status, version, lease_epoch, lease_expires_at, deadline_at, teardown_deadline_at)
  ON attempts TO factory_system;
GRANT UPDATE (updated_at) ON attempts TO factory_system;
CREATE POLICY system_find ON attempts AS PERMISSIVE FOR SELECT TO factory_system USING (true);
CREATE POLICY system_lock ON attempts AS PERMISSIVE FOR UPDATE TO factory_system USING (true) WITH CHECK (false);

-- Outbox: the relay publishes events of every tenant and marks them.
GRANT SELECT ON outbox TO factory_system;
GRANT UPDATE (published_at, publish_attempts) ON outbox TO factory_system;
CREATE POLICY system_find ON outbox AS PERMISSIVE FOR SELECT TO factory_system USING (true);
CREATE POLICY system_relay ON outbox AS PERMISSIVE FOR UPDATE TO factory_system USING (true) WITH CHECK (true);

-- The start-up check of the schema version (ADR 0007, rule 1). Diesel creates the table before the first
-- migration runs; a psql-only run may not have it.
DO $$
BEGIN
  IF to_regclass('public.__diesel_schema_migrations') IS NOT NULL THEN
    GRANT SELECT ON public.__diesel_schema_migrations TO factory_system;
  END IF;
END
$$;
