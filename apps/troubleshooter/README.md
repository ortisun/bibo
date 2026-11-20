# factory-troubleshooter

The troubleshooter watches the factory itself (its API, worker, database and telemetry) and files issues for a person to triage. It never changes anything. The design is [ADR 0021](../../docs/adr/0021-troubleshooter-agent-and-mcp-sources.md); the rules it runs by are [`policies/troubleshooting.yaml`](../../policies/troubleshooting.yaml).

## What it does

Every `schedule.probe_period_s` (5 minutes by default) it runs one pass:

1. **Probes.** Each probe of the policy runs once, through the troubleshooter's own MCP gateway on the control-plane path (`vm_query` for `promql_threshold`, `pg_factory_health` for `sql_check`, `datadog_search_monitors` for `datadog_monitors_alerting`), or as a direct GET of `api_health_url` + the route for `http_health`. Each result is stored with its gateway call id. Values are compared with the threshold as exact decimals (`0.30000000000000004 > 0.3` holds, `0.300 > 0.3` does not). An empty answer is `no_data` and does not trip. A source that does not answer is `source_unavailable`.
2. **Agent run**, only when a probe tripped and is past its cool-down (`probe_cooldown_s`, 6 hours), or the sweep is due (`sweep_period_s`, a day after the last sweep, or after the start), and only while the UTC day is under `max_agent_runs_per_day` and the role's `per_day` spend ceiling of `policies/model_routing.yaml`. One run at a time. The agent runs in the `troubleshooter` sandbox with Claude Code, the gateway tools and a broker token holding the role's `per_run` ceiling.
3. **The report is checked.** It must pass `health-findings` v1, and every observation must cite a call that the gateway recorded for this run, that ended `ok`, and that was a call of the tool the observation names. Otherwise the report is refused (`report_invalid` or `evidence_mismatch`) and nothing is filed from it.
4. **Issues.** Each accepted finding, and each `source_unavailable` finding (raised by code, without the model), is redacted, rendered from the closed template of `factory_domain::troubleshooting::issue` and identified by a fingerprint computed from code-known inputs only (the probes of the run that tripped and that the finding names, else its category and component). If its issue is open: one "seen again" comment a UTC day. If not: a new issue while the day is under `issues.max_new_per_day`, else the finding is deferred and named in the run record. The run's GitHub tokens are revoked at the end.

Everything is recorded in the `troubleshooting_runs`, `troubleshooting_probe_state`, `troubleshooting_issues` and `troubleshooting_daily_counters` tables (migration `2026-11-20-003000`).

Only one troubleshooter acts at a time: it holds a PostgreSQL advisory lock on a connection of its own. A second instance says `another troubleshooter is active; this one idles` and takes over when the first one stops.

## Run it

```text
factory-troubleshooter --config /etc/factory/troubleshooter/troubleshooter.yaml [--once] [--sweep-now] [--dry-run]
```

| Flag | What it does |
|---|---|
| `--config PATH` | The configuration file. Required. |
| `--once` | One pass, then exit. Exit code 4 when another troubleshooter is active (this one did nothing). |
| `--sweep-now` | Start the sweep in the first pass, whatever the schedule says. |
| `--dry-run` | Everything except writing to GitHub: probes run, the agent runs (and spends), the run is recorded, and each issue decision is printed as a `DRY RUN:` line on standard output instead of being sent. |

Exit codes: 0 a clean stop, 1 a start-up check or a `--once` pass failed, 2 bad usage or configuration, 4 `--once` while another instance is active.

## It refuses to start when

- the gateway's `listen` address is not loopback;
- a secret file (the store URL, the observer password, the VictoriaMetrics token, the Datadog keys, the provider key, the GitHub App key) is a link, not a regular file, or readable by group or others;
- the observer login is a superuser, bypasses row-level security, is not a member of `factory_observer`, or is a member of a group that can write (the check of `crates/mcp_postgres`);
- the store login is not a member of `factory_app` only, or the database lacks a migration;
- `sandbox.gateway_upstream` is missing (the sidecar of the troubleshooter sandbox relays the agent to the gateway there);
- a policy, the `troubleshooter` agent, its prompt or its schemas do not load.

## Configuration

Every value below is a placeholder. Secrets are files of mode 0600; none is written in the configuration.

```yaml
profile: local
protected_checkout: /etc/factory/troubleshooter/checkout
tenant: 00000000-0000-4000-8000-000000000001
issue_repository: example-org/factory
api_health_url: http://127.0.0.1:8080
api_health_timeout_s: 5
store:
  url_file: /etc/factory/troubleshooter/store-url
  login: factory_troubleshooter_rw
  max_connections: 4
observer:
  host: 127.0.0.1
  port: 5432
  database: factory
  user: factory_troubleshooter
  password_file: /etc/factory/troubleshooter/observer-password
gateway:
  listen: 127.0.0.1:8445
  allowed_hosts: [host.docker.internal]
  victoriametrics:
    url: http://127.0.0.1:8081/mcp
    token_file: /etc/factory/troubleshooter/victoriametrics-token
broker:
  listen: 127.0.0.1:8446
  upstreams:
    - provider: anthropic
      base_url: https://api.anthropic.com
      key_file: /etc/factory/troubleshooter/anthropic-key
sandbox:
  images_catalog: /etc/factory/troubleshooter/images.json
  token_root: /etc/factory/troubleshooter/tokens
  workspace_root: /etc/factory/troubleshooter/workspaces
  owner: factory-troubleshooter
  sidecar_command: [/usr/local/bin/factory-egress-sidecar, --mode, broker, --listen, 0.0.0.0:8443]
  gateway_upstream: 127.0.0.1:8445
artifacts:
  root: /etc/factory/troubleshooter/artifacts
github:
  app_id: 1
  key_file: /etc/factory/troubleshooter/github-app-key.pem
  installations:
    - tenant: 00000000-0000-4000-8000-000000000001
      repository: example-org/factory
      installation_id: 1
```

| Section | Meaning |
|---|---|
| `tenant` | The tenant whose rows the troubleshooter writes and whose GitHub installation covers `issue_repository`. |
| `store` | The troubleshooter's own rows: a login that is a member of `factory_app` and nothing else (the worker's shape), URL in a file. The same login holds the advisory lock. |
| `observer` | The read-only login of the PostgreSQL MCP server (`docs/database/observer-login.sql`), password in a file. |
| `gateway` | `mcp_gateway`'s `GatewayConfig`. `datadog` (`site`, `api_key_file`, `application_key_file`) is optional: absent, the Datadog probes are `disabled`, its tools are not offered, and each run row says `datadog_enabled = false`. `victoriametrics` is optional the same way. |
| `broker`, `sandbox`, `artifacts`, `github`, `runtimes`, `telemetry` | The worker's sections (`factory_composition::config`). The troubleshooter hosts its own broker: its agent runs outside any job, so it cannot use the worker's job tokens. |

## Installer step: the labels

The issue writer applies the labels `troubleshooter` and `troubleshooter: triage` and expects them to exist in `issue_repository` (the port has no call that creates labels). Create them once:

```text
gh label create troubleshooter --repo OWNER/NAME --color 5319e7 --description "Found by the troubleshooter" --force
gh label create "troubleshooter: triage" --repo OWNER/NAME --color fbca04 --description "Waits for a person to triage" --force
```

## What has not been run

The probes, the gateway, the store, the evidence check and the issue decisions are tested end to end offline (`tests/end_to_end.rs`) against a fake VictoriaMetrics, the real database and the in-memory issue writer, with a scripted agent. Not run: the agent in a real Docker sandbox, a live Datadog or VictoriaMetrics server, and live GitHub.
