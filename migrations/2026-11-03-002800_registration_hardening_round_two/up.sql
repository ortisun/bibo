-- Second round of the hardening of the repository registration path (findings RH-5, RH-8 and RH-9 of
-- docs/reviews/registration-hardening-security-review.md; the project owner delegated the decisions on 2026-11-03).
--
-- What this migration does:
--
--   1. RH-5. The API login (factory_api_app) could write an audit record `repository.disabled` for any actor, the
--      system included, with any words, and an unsigned `repository.change_requested` record that the status route
--      believed. The trigger audit_events_api_actions now also judges the actor and the words of the two repository
--      actions the login may still write: the actor must be a person (actor type `human`), the record must belong to
--      no job and no stage run, the decision must be `record`, and the subject must be exactly the words the API writes:
--      `repository <id> disabled` for a disable, and the canonical words of a request with its time and its word for
--      a request. SQL cannot check the keyed word (the key is not in the database), so the status route and the
--      worker verify it; what this guard stops is a row in the name of the system or in the shape of an act that the
--      API does not write. The worker writes its own effect record (a switch-off that an attestation of another map
--      caused) under a new action, `repository.disabled_by_attestation`, which the API login may not write at all, so
--      `repository.disabled` means "a person disabled it" and nothing else. The list of actions the login may write is
--      unchanged.
--   2. RH-8. A repository that is enabled under the strict rule must say who enabled it. The trigger
--      repositories_strict_enabler_guard refuses, for a login of the factory (a member of factory_app or factory_api_app
--      that is not a superuser), a row that is enabled, not single-maintainer, and has no enabler. Before this migration
--      the pair (enabler, attestor) was judged only when both were named, so one INSERT by the group of the worker could
--      enable a strict repository with no enabler. The guard is a trigger and not a CHECK on purpose: the table owner
--      and a superuser are administrators and not logins of the factory, as for the flag single_maintainer (migration
--      2026-11-03-002600), and a CHECK would bind them too and change many fixtures that enable a repository by hand.
--      It fires after repositories_project_map_guard (its name sorts later), so it sees the row as that guard leaves it.
--      Repositories that violate the rule now are switched off (their version rises, the record of the enabling is
--      emptied by the table), with a NOTICE and with one audit record each, written here as a component of the system
--      under `repository.disabled_by_migration`, so that no later update of such a row is refused by the guard. The table
--      has none today unless a privileged writer made one: the Store always names the enabler.
--
-- What this migration does NOT do, and says so (RH-9).
--
--   * It does not write an audit record for the repositories that migrations 2026-11-02-002400, 2026-11-02-002500 and
--     2026-11-03-002600 switched off. Those three wrote a NOTICE and no record; nothing in the database marks which rows
--     they switched off, and the NOTICE went to the output of the program that ran the migration. A record written now
--     could not say which repositories, and a worker that wrote one on its first start would also write it on an
--     installation that those migrations never touched. A migration also cannot write such a record without changing rows
--     that the upgrade checks (scripts/db-test.sh, `compat`) compare byte for byte. So the record is a documented
--     procedure: docs/database/migration-safety.md, "What the migrations of November 2026 switched off", has the query
--     that lists the disabled repositories with an attested map and no record of a disable, for an operator to read and
--     to write down. The NOTICE at the end of this file prints the number of such repositories on the database being
--     migrated, so that the deployment note the three earlier headers ask for has a number to carry.
--   * It does not edit migration 2026-11-03-002700 or migration 2026-11-02-002400, because a migration that was applied
--     anywhere is never edited. Their comments are stated here instead:
--       - The header of 2026-11-02-002400 says that the login of the API "may register a repository", that "the audit rows
--         are signed by nobody" and that "the same limit holds for the decision requests of people". That is the state of
--         that migration. 2026-11-03-002700 took register, attest and enable away from the login, and the review of
--         2026-11-02 (REG-2) said the comparison with the decision requests was out of date the day it was written. The
--         comparison is SUPERSEDED, and so is the residual risk stated in that header. The comments of that file were
--         edited twice after it was first committed (on 2026-11-02, to correct the residual-risk text and to say that the
--         switch-off writes no audit record, and on 2026-11-03, for a supersession note). Both edits were reverted, so
--         the file is byte for byte what the first commit made it, and this paragraph replaces them: the corrections
--         it carried are the ones in the list above ("What this migration does NOT do"). The file
--         docs/database/applied-migrations.sha256 now holds the bytes of every migration, and the migrations suite of
--         scripts/db-test.sh fails when the bytes of one change.
--       - The header of 2026-11-03-002700 says that the repository requests are on "the same path" as the decisions of
--         people. That was true except for the expiry: the worker applied a request of any age, and a disable did not
--         cancel one that was waiting (RH-1). The worker now refuses a request older than fifteen minutes and a request
--         whose repository was disabled after it was made, and records the refusal. That header also says "run the new
--         worker before the new API". The order is: this migration (and 2026-11-03-002700 before it), then the new worker,
--         then the new API. Between the migration and the new API the old API cannot register, attest or enable (its
--         grants are gone), and between the migration and the new worker the new API's requests wait, unapplied. Plan the
--         three steps as one window.
--
-- Residual risk, stated plainly: a holder of the API database credentials can still switch every repository of every
-- tenant off (it names the tenant by hand, ADR 0012), which is safe for integrity and not for availability (RH-10, accepted
-- by the project owner on 2026-11-03: narrowing is safe by design). Such a switch-off leaves no audit record. The owner of
-- the table and a superuser can do anything. The guards here stop the credentials of the API login from saying something
-- false in the audit log in the name of the system; they do not stop a compromise of the API process, which holds the key.
--
-- Contract only: the audit trigger becomes stricter and one trigger is added after the repair. No column is added or
-- dropped, and no constraint is validated.

SET LOCAL lock_timeout = '5s';

-- 1. The audit trigger. The list of actions is the one of migration 2026-11-03-002700, unchanged. The new part is the
--    second test: a repository record must be a person's, and in the words the API writes.
CREATE OR REPLACE FUNCTION audit_events_api_actions() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE
  uuid_text CONSTANT text := '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
  at_text   CONSTANT text := '[0-9TZ:.-]{1,40}';
  words_ok  boolean;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
              WHERE r.rolname IN (session_user, current_user) AND NOT r.rolsuper
                AND pg_catalog.pg_has_role(r.oid, 'factory_api_app'::pg_catalog.regrole::pg_catalog.oid, 'MEMBER')) THEN
    IF NEW.action <> ALL (ARRAY[
            'decision.requested', 'decision.dependency_requested', 'decision.stage_requested', 'decision.denied',
            'decision.denied_summary', 'decision.denied_suppressed', 'job.submitted', 'job.received_from_webhook',
            'webhook.accepted', 'webhook.duplicate_delivery', 'webhook.rejected', 'webhook.unbound',
            'webhook.audit_dropped', 'webhook_accepted_or_rejected.granted',
            'webhook_accepted_or_rejected.denied',
            'repository.change_requested', 'repository.disabled']) THEN
      RAISE EXCEPTION 'the API login may not write an audit record with this action or this actor'
        USING ERRCODE = '42501', TABLE = 'audit_events';
    END IF;
    -- RH-5. The two repository actions are a person's, in the API's words. Any other repository.* action is
    -- refused above, so the pattern here is a belt for an action added to the list later.
    IF NEW.action LIKE 'repository.%' THEN
      words_ok := CASE NEW.action
        WHEN 'repository.disabled' THEN
          NEW.subject ~ ('^repository ' || uuid_text || ' disabled$')
        WHEN 'repository.change_requested' THEN
          NEW.subject ~ ('^change kind=(register repository=' || uuid_text
                         || ' installation=[0-9]+ github_repository=[0-9]+ single_maintainer=(true|false)'
                         || '|(attest|enable) repository=' || uuid_text || ' commit=[0-9a-f]{40})'
                         || ' payload=sha256:[0-9a-f]{64} at=' || at_text || ' mac=[0-9a-f]{64}$')
        ELSE false
      END;
      IF NEW.actor_type <> 'human' OR NEW.job_id IS NOT NULL OR NEW.stage_run_id IS NOT NULL
         OR NEW.decision <> 'record' OR words_ok IS NOT TRUE THEN
        RAISE EXCEPTION 'the API login may write a repository audit record only as a person and in the words the API writes'
          USING ERRCODE = '42501', TABLE = 'audit_events';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END
$$;

-- 2. A strict repository that is enabled names its enabler. First the repair: the table forces row-level security,
--    which binds its owner too, so the setting is lifted for the one statement and put back (the same step as migrations
--    2026-11-02-002500 and 2026-11-03-002600). The audit table forces it as well and is not lifted: the tenant is named
--    for each record, as the Store names it.
ALTER TABLE repositories NO FORCE ROW LEVEL SECURITY;
DO $$
DECLARE
  repaired record;
  switched_off bigint := 0;
BEGIN
  FOR repaired IN
    SELECT r.tenant_id, r.id FROM repositories r
     WHERE r.enabled AND NOT r.single_maintainer AND r.enabled_by_principal_id IS NULL
     ORDER BY r.tenant_id, r.id
  LOOP
    UPDATE repositories SET enabled = false, version = version + 1
     WHERE tenant_id = repaired.tenant_id AND id = repaired.id;
    PERFORM pg_catalog.set_config('factory.tenant_id', repaired.tenant_id::text, true);
    INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash,
                              correlation_id)
    VALUES (repaired.tenant_id, gen_random_uuid(), 'system', 'migration.2026-11-03-002800',
            'repository.disabled_by_migration', 'repository ' || repaired.id::text || ' disabled', 'record',
            'The repository was enabled under the strict rule with no record of who enabled it. The table now refuses that, so the migration switched the repository off. Another person enables it again after reading the project map.',
            'sha256:' || repeat('0', 64), gen_random_uuid());
    switched_off := switched_off + 1;
  END LOOP;
  PERFORM pg_catalog.set_config('factory.tenant_id', '', true);
  IF switched_off > 0 THEN
    RAISE NOTICE '% repositories were enabled under the strict rule with no recorded enabler and are now disabled; each has an audit record repository.disabled_by_migration', switched_off;
  END IF;
END
$$;
ALTER TABLE repositories FORCE ROW LEVEL SECURITY;

-- The guard. 23514 is the code of a check violation, the code the neighbouring guards of this table use, and the
-- constraint name is the one a reader of an error would look for.
CREATE FUNCTION repositories_strict_enabler_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  -- A row with no map commit is refused by the CHECK repositories_enabled_needs_project_map, which names the cause.
  IF NEW.enabled AND NOT NEW.single_maintainer AND NEW.enabled_by_principal_id IS NULL AND NEW.project_map_commit IS NOT NULL
     AND EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                  WHERE r.rolname IN (session_user, current_user) AND NOT r.rolsuper
                    AND (pg_catalog.pg_has_role(r.oid, 'factory_api_app'::pg_catalog.regrole::pg_catalog.oid, 'MEMBER')
                         OR pg_catalog.pg_has_role(r.oid, 'factory_app'::pg_catalog.regrole::pg_catalog.oid, 'MEMBER'))) THEN
    RAISE EXCEPTION 'a repository that is enabled under the strict rule must say who enabled it'
      USING ERRCODE = '23514', CONSTRAINT = 'repositories_strict_enabled_has_an_enabler', TABLE = 'repositories';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER repositories_strict_enabler_guard BEFORE INSERT OR UPDATE ON repositories
  FOR EACH ROW EXECUTE FUNCTION repositories_strict_enabler_guard();

-- 3. RH-9. The deployment note the headers of migrations 2026-11-02-002400, 2026-11-02-002500 and 2026-11-03-002600 ask
--    for: how many repositories are disabled, have an attested project map and have no audit record of a disable. Some of
--    them were switched off by those migrations, which wrote no record; some are repositories that were attested and
--    never enabled; some were switched off by a raw UPDATE (RH-10). The number is a count of candidates to read, not of
--    switch-offs. The table forces row-level security, so the count is made for each tenant in turn.
DO $$
DECLARE
  one_tenant record;
  candidates bigint;
  total bigint := 0;
BEGIN
  FOR one_tenant IN SELECT t.id FROM tenants t ORDER BY t.id LOOP
    PERFORM pg_catalog.set_config('factory.tenant_id', one_tenant.id::text, true);
    SELECT count(*) INTO candidates
      FROM repositories r
     WHERE NOT r.enabled AND r.project_map_commit IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM audit_events a
                        WHERE a.tenant_id = r.tenant_id
                          AND a.action IN ('repository.disabled', 'repository.disabled_by_migration', 'repository.disabled_by_attestation')
                          AND position(r.id::text IN a.subject) > 0);
    total := total + candidates;
  END LOOP;
  PERFORM pg_catalog.set_config('factory.tenant_id', '', true);
  IF total > 0 THEN
    RAISE NOTICE '% disabled repositories have an attested project map and no audit record of a disable; some may have been switched off without a record by migrations 2026-11-02-002400, 2026-11-02-002500 or 2026-11-03-002600. See docs/database/migration-safety.md, "What the migrations of November 2026 switched off"', total;
  END IF;
END
$$;
