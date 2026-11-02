-- A repository takes tickets only after a person has attested its project map (ADR 0016, "What is not built",
-- item 1).
--
-- The project map is the set of contract files that `/egm:egm-bootstrap` writes into a project, reviewed and
-- merged by pull request. A person who has read it records the commit of the default branch that holds it. This
-- is an ATTESTATION BY A PERSON. The engine holds no GitHub credential, so it cannot look at the repository, and
-- it does not check that the commit exists or that the map is good. The database records who said so and when.
--
-- What this migration does:
--
--   1. Three nullable columns on repositories: the commit of the map (40 lowercase hexadecimal characters), the
--      principal who attested it and the time. All three are set together or all three are empty.
--   2. The invariant that holds in the database for every role, owner and superuser included: a repository
--      cannot be enabled without a map commit (repositories_enabled_needs_project_map). It is a CHECK and not a
--      rule of the Rust code.
--   3. A trigger that stamps the time from the database clock and refuses an attestor who is not an active human
--      principal of the tenant, as repositories_attestation_guard does for the bypass attestation.
--   4. `enabled` now defaults to false. A row that is written without saying so starts switched off.
--   5. Rows that were enabled before this migration are switched off, because none of them has a map. A person
--      attests the map and enables each one again. The version of each such row rises by one. NO AUDIT RECORD is
--      written for this switch-off: the audit chain does not say who or what switched them off, only this file and
--      the NOTICE do. A deployment note should carry the count of repositories that were switched off.
--   6. The login of the HTTP API (factory_api_app) may register a repository and change four columns of it. It
--      could write nothing to this table before (finding API-3 of docs/reviews/api-security-review.md). The grants
--      are column grants, so the login still cannot set the autonomy ceiling, the protection preflight result or
--      the bypass attestation, and a new row always starts disabled at level L0. The suite api_privileges lists
--      them both ways.
--   7. The API may write four more audit actions (repository.registered, repository.map_attested,
--      repository.enabled and repository.disabled), in the list of the trigger audit_events_api_actions.
--
-- Residual risk, stated plainly: whoever holds the credentials of the API database login can now, in one session
-- that names a tenant, register any installation, GitHub repository id and name; write a map commit under the
-- name of any active human principal of that tenant; enable a repository that has a map commit; switch off every
-- repository; switch back on one that an operator switched off as an incident response; and write the matching
-- audit rows with any actor. Before this migration that login could write none of it. The audit rows are signed
-- by nobody. This is WEAKER than the decision requests of people. Since AUT-12 those carry a keyed word that the
-- worker verifies before it applies them, and a change of a repository does not. An earlier text of this comment
-- said "the same limit holds for the decision requests"; that was out of date, because AUT-12 is fixed
-- (docs/reviews/authority-and-evidence-security-review.md, section 10) and the review of this change says so
-- (docs/reviews/engine-registration-and-status-security-review.md, REG-2). The choice between a signed request
-- for the acts that widen the factory's reach, a function owned by another role, or accepting the risk with an
-- owner and a date is open and belongs to the product owner.
--
-- Expand only: nullable columns, and constraints that are added and then validated. The constraints are added
-- NOT VALID and then validated in the same transaction. That two-step form lets reads and writes go on only when
-- the steps run in separate transactions. Inside this migration the lock of ADD CONSTRAINT is held to the commit,
-- so it gives no benefit here. The table is small, and the validation is a scan under that lock.

SET LOCAL lock_timeout = '5s';

-- 5. Switch off what was enabled before a map could exist. The table forces row-level security, which binds its
--    owner too, so the owner would see no row. The setting is lifted for this one statement and put back.
ALTER TABLE repositories NO FORCE ROW LEVEL SECURITY;
DO $$
DECLARE
  switched_off bigint;
BEGIN
  UPDATE repositories SET enabled = false, version = version + 1 WHERE enabled;
  GET DIAGNOSTICS switched_off = ROW_COUNT;
  IF switched_off > 0 THEN
    RAISE NOTICE '% repositories were enabled without a project map and are now disabled; attest the map and enable each one again', switched_off;
  END IF;
END
$$;
ALTER TABLE repositories FORCE ROW LEVEL SECURITY;

-- 1 and 4.
ALTER TABLE repositories
  ADD COLUMN project_map_commit text,
  ADD COLUMN project_map_attested_by_principal_id uuid,
  ADD COLUMN project_map_attested_at timestamptz;
ALTER TABLE repositories ALTER COLUMN enabled SET DEFAULT false;

-- 1 and 2. IS NOT NULL is spelled out where a CHECK would accept NULL by accident.
ALTER TABLE repositories ADD CONSTRAINT repositories_project_map_commit_check
  CHECK (project_map_commit IS NULL OR project_map_commit ~ '^[0-9a-f]{40}$') NOT VALID;
ALTER TABLE repositories ADD CONSTRAINT repositories_project_map_attestation_complete
  CHECK ((project_map_commit IS NULL) = (project_map_attested_by_principal_id IS NULL)
     AND (project_map_commit IS NULL) = (project_map_attested_at IS NULL)) NOT VALID;
ALTER TABLE repositories ADD CONSTRAINT repositories_project_map_attested_by_fkey
  FOREIGN KEY (tenant_id, project_map_attested_by_principal_id) REFERENCES principals (tenant_id, id) NOT VALID;
ALTER TABLE repositories ADD CONSTRAINT repositories_enabled_needs_project_map
  CHECK (NOT enabled OR project_map_commit IS NOT NULL) NOT VALID;
ALTER TABLE repositories VALIDATE CONSTRAINT repositories_project_map_commit_check;
ALTER TABLE repositories VALIDATE CONSTRAINT repositories_project_map_attestation_complete;
ALTER TABLE repositories VALIDATE CONSTRAINT repositories_project_map_attested_by_fkey;
ALTER TABLE repositories VALIDATE CONSTRAINT repositories_enabled_needs_project_map;

-- 3. The time is the database's: whatever the caller writes is replaced. The attestor is an active human
--    principal of the same tenant. The time moves when the attestor or the commit changes, and not otherwise.
CREATE FUNCTION repositories_project_map_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.project_map_attested_by_principal_id IS NULL THEN
    NEW.project_map_attested_at := NULL;
  ELSIF TG_OP = 'INSERT'
     OR NEW.project_map_attested_by_principal_id IS DISTINCT FROM OLD.project_map_attested_by_principal_id
     OR NEW.project_map_commit IS DISTINCT FROM OLD.project_map_commit THEN
    IF NOT EXISTS (SELECT 1 FROM public.principals p
                    WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.project_map_attested_by_principal_id
                      AND p.kind = 'human' AND p.disabled_at IS NULL) THEN
      RAISE EXCEPTION 'the project map must be attested by an active human principal of the tenant'
        USING ERRCODE = '23514', CONSTRAINT = 'repositories_map_attestor_is_an_active_human', TABLE = 'repositories';
    END IF;
    NEW.project_map_attested_at := now();
  ELSE
    NEW.project_map_attested_at := OLD.project_map_attested_at;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER repositories_project_map_guard BEFORE INSERT OR UPDATE ON repositories
  FOR EACH ROW EXECUTE FUNCTION repositories_project_map_guard();

-- The worker's group changes the same two columns of the map, as it changes the bypass attestation (migration
-- 2026-10-27-001700) and the enabled flag. The Store port is one trait for both logins, and its contract suite
-- runs as the worker's group. The time is never granted: the database stamps it.
GRANT UPDATE (project_map_commit, project_map_attested_by_principal_id) ON repositories TO factory_app;

-- 6. The API login: register a repository, and change four columns of it. Nothing else.
GRANT INSERT (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch)
  ON repositories TO factory_api_app;
GRANT UPDATE (enabled, project_map_commit, project_map_attested_by_principal_id, version)
  ON repositories TO factory_api_app;

-- 7. The audit actions of the API, now with the four of the repository.
CREATE OR REPLACE FUNCTION audit_events_api_actions() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
              WHERE r.rolname IN (session_user, current_user) AND NOT r.rolsuper
                AND pg_catalog.pg_has_role(r.oid, 'factory_api_app'::pg_catalog.regrole::pg_catalog.oid, 'MEMBER'))
     AND NEW.action <> ALL (ARRAY[
            'decision.requested', 'decision.dependency_requested', 'decision.stage_requested', 'decision.denied',
            'decision.denied_summary', 'decision.denied_suppressed', 'job.submitted', 'job.received_from_webhook',
            'webhook.accepted', 'webhook.duplicate_delivery', 'webhook.rejected', 'webhook.unbound',
            'webhook.audit_dropped', 'webhook_accepted_or_rejected.granted',
            'webhook_accepted_or_rejected.denied',
            'repository.registered', 'repository.map_attested', 'repository.enabled', 'repository.disabled']) THEN
    RAISE EXCEPTION 'the API login may not write an audit record with this action or this actor'
      USING ERRCODE = '42501', TABLE = 'audit_events';
  END IF;
  RETURN NEW;
END
$$;
