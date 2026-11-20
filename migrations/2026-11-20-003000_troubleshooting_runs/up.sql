-- The troubleshooter's own rows (ADR 0021, decisions 1, 2 and 7): its runs, the state of each probe, the map
-- from a finding's fingerprint to its triage issue, and the counters of one UTC day.
--
-- A troubleshooting run is not a job. It has its own table and its own identifier (the pattern of
-- troubleshooter-input.v1 `run_id`), never enters `jobs`, the pipeline or a job's budget, and its spend is
-- counted against the day ceiling of the `troubleshooter` role of policies/model_routing.yaml.
--
-- Tenancy (ADR 0012, docs/database/tenancy.md). Every table carries `tenant_id` in its primary key and a
-- foreign key to `tenants`; row-level security is enabled and forced; the one `tenant_isolation` policy of
-- every tenant table lets `factory_app` see and write the rows of the tenant its transaction names. The
-- troubleshooter writes as a worker-shaped login (a member of `factory_app` only) for the tenant its
-- configuration names. `factory_system` gets nothing: no engine loop reads these tables, and the existing
-- tables give it a policy only where a loop of the engine needs one.
--
-- What `factory_app` may do: SELECT and INSERT, and UPDATE of the columns that change after the insert. No
-- DELETE: history is kept. What `factory_observer` may read: every column, through one `observer_read`
-- policy per table, so the troubleshooter's agent can see its own history through `pg_query`. Every column
-- is an identifier, a state, a time, a count, a code or a digest computed by code
-- (docs/database/observer-columns.txt).
--
-- Times come from the troubleshooter's clock, which reads UTC (ADR 0011); a "day" is a UTC calendar date.

CREATE TABLE troubleshooting_runs (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  id text NOT NULL CHECK (id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
  trigger text NOT NULL CHECK (trigger IN ('probe', 'sweep')),
  state text NOT NULL DEFAULT 'running' CHECK (state IN ('running', 'finished')),
  started_at timestamptz NOT NULL,
  ended_at timestamptz,
  spend_micro_usd bigint NOT NULL DEFAULT 0 CHECK (spend_micro_usd >= 0),
  report_sha256 text CHECK (report_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  gateway_record_sha256 text CHECK (gateway_record_sha256 ~ '^sha256:[0-9a-f]{64}$'),
  outcome text CHECK (outcome IN (
    'healthy', 'findings', 'needs_human', 'blocked', 'source_unavailable', 'evidence_mismatch',
    'report_invalid', 'agent_failed', 'spend_ceiling', 'failed')),
  agent_ran boolean NOT NULL DEFAULT false,
  dry_run boolean NOT NULL DEFAULT false,
  datadog_enabled boolean NOT NULL,
  issues_opened integer NOT NULL DEFAULT 0 CHECK (issues_opened >= 0),
  comments_posted integer NOT NULL DEFAULT 0 CHECK (comments_posted >= 0),
  deferred_fingerprints text[] NOT NULL DEFAULT '{}'
    CHECK (cardinality(deferred_fingerprints) <= 20),
  PRIMARY KEY (tenant_id, id),
  CHECK ((state = 'finished') = (ended_at IS NOT NULL AND outcome IS NOT NULL)),
  CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE INDEX troubleshooting_runs_by_start ON troubleshooting_runs (tenant_id, started_at);

CREATE TABLE troubleshooting_probe_state (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  probe_id text NOT NULL CHECK (probe_id ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
  last_outcome text NOT NULL
    CHECK (last_outcome IN ('ok', 'tripped', 'no_data', 'source_unavailable', 'disabled')),
  -- The observed value as the exact decimal text it was compared in, or NULL when there was none.
  last_value text CHECK (length(last_value) <= 64),
  last_call_id text CHECK (last_call_id ~ '^call-[1-9][0-9]{0,3}$'),
  last_run_id text CHECK (last_run_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'),
  last_checked_at timestamptz NOT NULL,
  last_tripped_at timestamptz,
  cooldown_until timestamptz,
  PRIMARY KEY (tenant_id, probe_id)
);

CREATE TABLE troubleshooting_issues (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  fingerprint text NOT NULL CHECK (fingerprint ~ '^sha256:[0-9a-f]{64}$'),
  repository text NOT NULL CHECK (repository ~ '^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$'),
  issue_number bigint NOT NULL CHECK (issue_number > 0),
  opened_at timestamptz NOT NULL,
  last_comment_day date,
  comments_on_last_day integer NOT NULL DEFAULT 0 CHECK (comments_on_last_day >= 0),
  PRIMARY KEY (tenant_id, fingerprint)
);

CREATE TABLE troubleshooting_daily_counters (
  tenant_id uuid NOT NULL REFERENCES tenants (id),
  day date NOT NULL,
  agent_runs integer NOT NULL DEFAULT 0 CHECK (agent_runs >= 0),
  new_issues integer NOT NULL DEFAULT 0 CHECK (new_issues >= 0),
  comments integer NOT NULL DEFAULT 0 CHECK (comments >= 0),
  spend_micro_usd bigint NOT NULL DEFAULT 0 CHECK (spend_micro_usd >= 0),
  PRIMARY KEY (tenant_id, day)
);

GRANT SELECT, INSERT ON troubleshooting_runs, troubleshooting_probe_state, troubleshooting_issues,
                        troubleshooting_daily_counters
  TO factory_app;
GRANT UPDATE (state, ended_at, spend_micro_usd, report_sha256, gateway_record_sha256, outcome, agent_ran,
              issues_opened, comments_posted, deferred_fingerprints)
  ON troubleshooting_runs TO factory_app;
GRANT UPDATE (last_outcome, last_value, last_call_id, last_run_id, last_checked_at, last_tripped_at,
              cooldown_until)
  ON troubleshooting_probe_state TO factory_app;
GRANT UPDATE (repository, issue_number, opened_at, last_comment_day, comments_on_last_day)
  ON troubleshooting_issues TO factory_app;
GRANT UPDATE (agent_runs, new_issues, comments, spend_micro_usd)
  ON troubleshooting_daily_counters TO factory_app;

-- Column grants, never a table grant: a table grant would cover a column added later that nobody classified.
GRANT SELECT (tenant_id, id, trigger, state, started_at, ended_at, spend_micro_usd, report_sha256,
              gateway_record_sha256, outcome, agent_ran, dry_run, datadog_enabled, issues_opened, comments_posted,
              deferred_fingerprints)
  ON troubleshooting_runs TO factory_observer;
GRANT SELECT (tenant_id, probe_id, last_outcome, last_value, last_call_id, last_run_id, last_checked_at,
              last_tripped_at, cooldown_until)
  ON troubleshooting_probe_state TO factory_observer;
GRANT SELECT (tenant_id, fingerprint, repository, issue_number, opened_at, last_comment_day, comments_on_last_day)
  ON troubleshooting_issues TO factory_observer;
GRANT SELECT (tenant_id, day, agent_runs, new_issues, comments, spend_micro_usd)
  ON troubleshooting_daily_counters TO factory_observer;

DO $$
DECLARE
  tenant_table text;
BEGIN
  FOREACH tenant_table IN ARRAY ARRAY[
    'troubleshooting_runs', 'troubleshooting_probe_state', 'troubleshooting_issues',
    'troubleshooting_daily_counters'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', tenant_table);
    EXECUTE format($policy$
      CREATE POLICY tenant_isolation ON public.%I
        AS PERMISSIVE FOR ALL TO factory_app
        USING (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid)
        WITH CHECK (tenant_id = NULLIF(current_setting('factory.tenant_id', true), '')::uuid)
    $policy$, tenant_table);
    EXECUTE format(
      'CREATE POLICY observer_read ON public.%I AS PERMISSIVE FOR SELECT TO factory_observer USING (true)',
      tenant_table);
  END LOOP;
END
$$;
