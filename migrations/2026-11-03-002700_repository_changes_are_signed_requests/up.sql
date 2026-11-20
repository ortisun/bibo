-- Register, attest and enable become signed requests that the worker applies (finding REG-2 of
-- docs/reviews/engine-registration-and-status-security-review.md; the product owner decided on 2026-11-03).
--
-- Before this migration the login of the HTTP API (factory_api_app) could register a repository, write a map
-- commit under the name of any active human of the tenant, enable a repository and write the matching audit
-- rows, all with plain column grants and an audit row that nobody signed. Since AUT-12 the decisions of people
-- are different: the API appends a request that carries a keyed word, and the worker verifies the word before it
-- applies anything. The comparison that migration 2026-11-02-002400 made ("the same limit holds for the decision
-- requests") was out of date the day it was written, and the review (REG-2) said so. This migration makes the
-- statement true by moving the acts that WIDEN the factory's reach, register, attest and enable, onto the same
-- path. Disabling stays a direct write, because narrowing is safe.
--
-- What this migration does:
--
--   1. The audit action `repository.change_requested` is added to the actions the API login may write
--      (audit_events_api_actions). The three actions it wrote before for these acts, `repository.registered`,
--      `repository.map_attested` and `repository.enabled`, are taken out of the list: from now on the worker writes
--      those, as a component of the system, when it has applied a request. `repository.disabled` stays, because
--      the API still disables directly.
--   2. The API login loses its column grants for the three acts: INSERT on the seven columns of a registration and
--      UPDATE on the map commit, its attestor, and the commit and the person of the enabling. It keeps UPDATE on
--      `enabled` and `version`, which a disable writes.
--   3. The worker's group (factory_app) already holds what it needs to apply a request: INSERT on repositories and
--      UPDATE on the map columns and on the record of the enabling (migrations 2026-11-02-002400 and
--      2026-11-02-002500 gave them "because the Store port is one trait"). Nothing is added, and in this design
--      those grants are in the right place. The suites `privileges` and `api_privileges` list both sides.
--   4. A BEFORE UPDATE trigger on repositories, in the style of audit_events_api_actions, that refuses, for a member
--      of factory_api_app, any change of a repository except one that sets `enabled` to false. It compares the
--      whole row, so a column added later is refused too. The column grants are the first guard and this is the
--      second: the grant of `enabled` alone would let the API login switch a repository ON, and the trigger does
--      not. The version, which every update raises, and the time of the update are the only other things that may
--      differ. The trigger fires before the guard of the project map (its name sorts first), so it sees the
--      statement as the caller wrote it and not as the guard rewrote it.
--
-- Residual risk, stated plainly. A signed request protects against a holder of the API database credentials who
-- does not hold the signing key. It does NOT protect against the compromise of the API process, because the process
-- holds the key (decisions.key_file): such an attacker signs any request, and the worker applies what the
-- designation of the person it names allows. The worker re-checks that designation by the numeric GitHub id against
-- the protected allowlist when it applies a request (the R-4 rule the decisions follow), so the attacker is limited
-- to what an existing, named, active person of the tenant may do. This risk is accepted. The owner of the risk is the
-- project owner. Review date: 2026-11-03, when it was written down; it is reviewed again when a second tenant is
-- onboarded or the key is moved out of the API process. The symmetric key stays shared between the API and the worker
-- (AUT-12): a compromised worker can forge a request too.
--
-- Contract only for the API login (grants are taken away). Nothing is dropped from the table, no row changes, and the
-- worker is changed in the same release, so run the new worker before the new API: a new API writes requests that an
-- old worker leaves alone, and an old API cannot write the three acts any more.

SET LOCAL lock_timeout = '5s';

-- 1. The audit actions of the API.
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
            'repository.change_requested', 'repository.disabled']) THEN
    RAISE EXCEPTION 'the API login may not write an audit record with this action or this actor'
      USING ERRCODE = '42501', TABLE = 'audit_events';
  END IF;
  RETURN NEW;
END
$$;

-- 2. The API login no longer registers, attests or enables.
REVOKE INSERT (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, single_maintainer)
  ON repositories FROM factory_api_app;
REVOKE UPDATE (project_map_commit, project_map_attested_by_principal_id, enabled_project_map_commit, enabled_by_principal_id)
  ON repositories FROM factory_api_app;

-- 4. The second guard. 42501 is the code of a privilege refusal, as in audit_events_api_actions.
CREATE FUNCTION repositories_api_may_only_disable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
              WHERE r.rolname IN (session_user, current_user) AND NOT r.rolsuper
                AND pg_catalog.pg_has_role(r.oid, 'factory_api_app'::pg_catalog.regrole::pg_catalog.oid, 'MEMBER'))
     AND NOT (NOT NEW.enabled
              AND pg_catalog.to_jsonb(NEW) - 'enabled' - 'version' - 'updated_at'
                  = pg_catalog.to_jsonb(OLD) - 'enabled' - 'version' - 'updated_at') THEN
    RAISE EXCEPTION 'the API login may only switch a repository off'
      USING ERRCODE = '42501', TABLE = 'repositories';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER repositories_api_may_only_disable BEFORE UPDATE ON repositories
  FOR EACH ROW EXECUTE FUNCTION repositories_api_may_only_disable();
