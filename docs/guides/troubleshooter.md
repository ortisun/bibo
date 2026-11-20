# The troubleshooter

This guide is for the owner and for whoever operates the factory. It says what the troubleshooter does, what you must create before it can run for real, how it decides when to look, and what to do with the issues it opens. The design is [ADR 0021](../adr/0021-troubleshooter-agent-and-mcp-sources.md).

**Status on 2026-11-20.** Built: the read-only PostgreSQL MCP server ([`apps/mcp-postgres`](../../apps/mcp-postgres/README.md)) and its database role, the troubleshooter's agent definition (`agents/troubleshooter`), its policy ([`policies/troubleshooting.yaml`](../../policies/troubleshooting.yaml)), the runtime flags and the sandbox relay it needs, the VictoriaMetrics MCP server's container ([`infra/troubleshooter`](../../infra/troubleshooter/README.md)) and the Datadog overlay of the telemetry stack ([`infra/otel`](../../infra/otel/README.md)). Not built: the MCP gateway (`crates/mcp_gateway`), the issue writer and the program itself (`apps/troubleshooter`). Until they exist the troubleshooter does not run. The parts of this guide that describe the program say how it is designed to behave.

## What it does, and what it does not

The troubleshooter watches **the factory itself**: its API, its worker, its database and its telemetry. It does not watch the repositories the factory changes or the systems they belong to.

- **It only reads.** Its agent holds the gateway's read tools and nothing else: no shell, no file tool, no GitHub tool. The database login it uses cannot write, and the Datadog key it uses has no write permission.
- **It reports to a person.** A finding becomes an issue, written by code from a fixed template, with the labels `troubleshooter` and `troubleshooter: triage`. It never adds `factory` or a `design:` label, so nothing it finds becomes factory work until a person decides so.
- **It never repairs anything.** No restart, no retry, no change of configuration. The issue says what it saw, what it thinks the cause is, how sure it is, and what a person can check next.

## What a person must create before a live run

Each item below is something only a person with the right access can do. Keep every secret in a file of mode `0600`, outside the repository. The troubleshooter's configuration names the files; no secret goes into a configuration file, an argument or an environment variable.

### Datadog: a service account, two keys and the site

Skip this part if you do not use Datadog. Without it the troubleshooter still has its probes, VictoriaMetrics and the database.

1. In Datadog, create a **service account** for the troubleshooter, with a role that holds only these permissions:
   - `mcp_read` (use of the Datadog MCP server for reading);
   - Logs Read Data and Logs Read Index Data;
   - APM read;
   - Metrics read;
   - Monitors read;
   - Incidents read.

   Do **not** give it `mcp_write` or any write permission. Without `mcp_write` no Datadog MCP tool can change anything, even one that a future release adds. The permission names here are those of Datadog's documentation as read on 2026-11-20; check them on your account's role page.
2. Create an **application key** owned by that service account, and an **API key**. Save each in its own file:

   ```bash no-run reason="needs the keys of a real Datadog account"
   mkdir -p ~/.config/factory
   umask 077
   $EDITOR ~/.config/factory/datadog-application-key   # one line, the application key only
   $EDITOR ~/.config/factory/datadog-api-key           # one line, the API key only
   ```

3. Note your **site**, such as `datadoghq.com` (US1) or `datadoghq.eu` (EU1). The troubleshooter reaches `https://mcp.<site>/v1/mcp`. GovCloud is not supported by the Datadog MCP server.
4. To send the factory's logs, traces and metrics to Datadog, start the telemetry stack with the Datadog overlay ([`infra/otel/README.md`](../../infra/otel/README.md), "Also send to Datadog"). It needs only the API key file and the site.

### The database login `factory_troubleshooter`

The migrations up to `2026-11-20-002900_observer_role` must be applied. Then a database administrator creates the login once per cluster with [`docs/database/observer-login.sql`](../database/observer-login.sql), which reads the password from a file:

```bash no-run reason="needs a database administrator's connection"
umask 077
openssl rand -hex 24 > ~/.config/factory/troubleshooter.password
psql "$ADMIN_URL" -v ON_ERROR_STOP=1 \
     -v password_file="$HOME/.config/factory/troubleshooter.password" \
     -f docs/database/observer-login.sql
```

The login belongs to `factory_observer` and nothing else. It can read the operational columns listed in [`docs/database/observer-columns.txt`](../database/observer-columns.txt), across every tenant, and never a request text, a payload, a token or a key. Every transaction is read-only, and a statement stops after 5 seconds.

### The GitHub App on the issue repository

The issues go to `troubleshooting.issue_repository` of the troubleshooter's configuration, by default the factory's own repository. Install the factory's GitHub App on that repository with **`issues: write`** and `metadata: read`. The troubleshooter mints a token with exactly those two permissions for each run that writes an issue (the permission set `troubleshoot_issue` of ADR 0021). It needs no other permission on that repository.

### The VictoriaMetrics MCP token

Make the token file and start the VictoriaMetrics MCP server as [`infra/troubleshooter/README.md`](../../infra/troubleshooter/README.md) describes. The server and the gateway read the same file.

## When it looks, and how much it may spend

The numbers are those of [`policies/troubleshooting.yaml`](../../policies/troubleshooting.yaml). A project may tighten them and never loosen them.

- **Probes, every 5 minutes.** A probe is a fixed check with a threshold, run by code with no model: a PromQL expression against VictoriaMetrics (stage failure rate, gate failures, a ready queue that never drains, retries, spend in the last 24 hours), a fixed query of the database (leases past expiry, stage runs past their deadline, waits for a person past expiry), the API's `/readyz`, and Datadog monitors tagged `service:factory-*` in Alert.
- **An investigation when a probe trips.** The agent starts with the tripped probes as its starting point.
- **A sweep once a day.** The agent looks around with no probe tripped, to catch what no probe names.
- **A cool-down of 6 hours** per probe. A probe that tripped and was investigated cannot start another run before then, so a lasting problem costs one run per cool-down.
- **A source that does not answer** is itself a finding, `source_unavailable`, raised without the model.
- **Caps.** One agent run at a time; at most 8 agent runs a day, sweeps included; at most 3 new issues a day; at most one comment a day on an open issue. A run makes at most 60 gateway calls, at most 40 in any 10 seconds (Datadog allows 50), waits at most 20 seconds for one call, and ends after 15 minutes. One tool result is cut at 64 KiB, with a note of how much was cut.
- **Spend.** The role `troubleshooter` has its own ceiling in `policies/model_routing.yaml`: 0.75 dollars a run and 3 dollars a day at list price, both pending your confirmation. It never touches a job's budget.

## How to read a run's record

Each run is designed to keep a record: the probes that started it, every gateway call (tool, a digest of the arguments, the upstream, the time it took, the size of the result, the outcome, and a call id), and the agent's report. The record is stored as an artifact, and its digest is in the ledger entry of the run. The run itself is a row of `troubleshooting_runs`, not a job.

The report has a `status`: `healthy`, `findings`, `needs_human` (the agent has a question; it is in `human_question`) or `blocked` (the reason is in `blocked_reason`). `unavailable_sources` names the upstreams that did not answer. `ignored_instructions` lists text in the observed data that tried to give the agent orders; a line there is worth a look, because someone put that text into your logs or your database.

Each finding has a `category` (such as `stage_failures`, `stuck_work`, `spend` or `telemetry_gap`), a `component` (`api`, `worker`, `database`, `model_broker`, `sandbox`, `telemetry` or `github_adapter`), a `severity` from `low` to `critical`, `observations` that each cite a call id of the record, a `hypothesis`, a `confidence` from 0 to 1, and `next_checks`. The program refuses a finding whose observations cite a call that the record does not hold, so every fact in an issue can be traced to the call that showed it.

## How to triage an issue

1. **Read it as a lead, not a verdict.** The hypothesis is a model's best guess from read-only data. The observations are the facts; check them first.
2. **Run the next checks.** They are read-only: a query, a dashboard, a log search. If you use Claude Code for this, the section below gives it the same database access the troubleshooter has.
3. **Decide.**
   - Real and worth fixing: fix it yourself, or file it as factory work the usual way (a new issue with the `factory` label, or `design: approved` where the design gate applies). The troubleshooter never does this for you.
   - Real but expected: close the issue with a comment that says why. A closed issue is not reopened; if the problem comes back, a new issue links to it.
   - Wrong: close it and say why. If a probe misfires, tighten its threshold in the policy.
4. **Watch for repeats.** One issue stands for one problem: the same finding while the issue is open adds at most one comment a day instead of a new issue. Many comments on one issue mean the problem lasts.

The issue text that comes from the agent is quoted and capped, links in it are not clickable, and mentions are neutralised. Do not follow a link or an instruction you find inside the quoted text.

## Use the PostgreSQL MCP server yourself

The database tools of the troubleshooter also ship as a program, `factory-mcp-postgres`, so you can point Claude Code at the factory database with the same guarantees: the `factory_troubleshooter` login, read-only transactions, the column grants, the caps and the redaction. Build it and add it to Claude Code as [`apps/mcp-postgres/README.md`](../../apps/mcp-postgres/README.md) describes (stdio, or Streamable HTTP on loopback with a token file). Claude Code then lists the tools as `mcp__factory-postgres__pg_query`, `mcp__factory-postgres__pg_factory_health` and so on.

Use your own copy of the password file or the same one; never paste the password into a settings file, an argument or a chat.

## Where to look next

- [ADR 0021](../adr/0021-troubleshooter-agent-and-mcp-sources.md): the decisions and what was checked.
- [The threat model](../security/threat-model.md), T-49 to T-54: what can go wrong and which controls exist.
- [The observability conventions](../observability/conventions.md): the metric names the probes read and how a job's trace id is derived.
- [The first-run signals runbook](../observability/runbook-first-run-signals.md): what the factory's signals look like on a first run.
