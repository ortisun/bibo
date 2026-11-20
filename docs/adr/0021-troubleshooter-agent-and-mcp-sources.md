# 0021: A troubleshooter watches the factory itself through an MCP gateway, and a person triages what it finds

- Status: **Accepted by the owner on 2026-11-20.** The owner chose the scope, approved the new direct dependency `rmcp` 3.11.0 and approved the second fixed relay of the troubleshooter sidecar (section "Owner decisions this record needs"). The rest of the design is the engineer's. No independent review has covered it yet.
- Date: 2026-11-20
- Deciders: the owner chose what is watched and what happens to a finding; the engineer wrote the rest.
- Related: [ADR 0003](0003-sandbox-strategy.md), [ADR 0005](0005-agent-runtime-adapter-boundary.md), [ADR 0010](0010-failure-escalation-routing-and-invalidation.md), [ADR 0012](0012-row-level-security-in-slice-1.md), [ADR 0013](0013-telemetry-wiring.md), [ADR 0017](0017-ports-v1-2-issue-status-writer.md), [ADR 0020](0020-subscription-mode-by-default.md), [threat model](../security/threat-model.md) T-49 to T-54

## Context and problem statement

The owner asked (in Portuguese, 2026-11-20) for a new agent, a troubleshooter, that looks at logs and traces from time to time, reaches Datadog and VictoriaMetrics through MCP servers, and reads the database through a new read-only MCP server for PostgreSQL. Asked two questions, the owner answered:

1. **What is watched:** the factory itself only (its API, worker, database and telemetry). Not the systems of the repositories the factory changes.
2. **What happens to a finding:** an issue for a person to triage. Nothing becomes factory work until a person says so.

Nothing in the factory today fits such an agent:

- Every agent runs inside a job, and every job belongs to one GitHub issue. The API refuses a job without one (FR-001), and intake would refuse a request that is not an issue.
- Every agent runs Claude Code with `--strict-mcp-config` and no `--mcp-config`. `Flag` and `ClaudeTool` in `crates/runtime/src/claude/argv.rs` are closed enums, and a negative test asserts that the tool starts with no MCP server.
- The agent sandbox reaches one address: the model broker, through the egress sidecar in `broker` mode. The broker knows two body shapes (Anthropic, OpenAI) and refuses a body that names `mcp_servers`.
- Nothing opens an issue. The GitHub adapter comments, writes `factory: <state>` labels and opens draft pull requests. Every token is minted for a job.
- No read-only database role exists. Every tenant table has FORCE ROW LEVEL SECURITY.
- Logs are JSON on stderr and are exported nowhere. Traces go to Jaeger, metrics to VictoriaMetrics (`infra/otel`). Datadog is not mentioned anywhere.

## What was checked

On 2026-11-20.

- **Datadog MCP Server** (docs.datadoghq.com/bits_ai/mcp_server, its setup and tools pages, read through a fetch agent): remote, Streamable HTTP, `https://mcp.<site>/v1/mcp` (US1 `mcp.datadoghq.com`, EU1 `mcp.datadoghq.eu`, others listed; GovCloud not supported). A non-interactive client sends `DD_API_KEY` and `DD_APPLICATION_KEY` headers, or a service access token as `Authorization: Bearer`. Read use needs the `mcp_read` permission plus the read permission of each product; without `mcp_write` no write tool works. `toolsets` (default `core`) selects tools and `omit_tools` removes some. Fair use: 50 tool calls per 10 seconds. The pages call the server "under significant development". The core toolset holds notebook tools that write. **Verified from the pages, not by a call.**
- **VictoriaMetrics MCP server**: `github.com/VictoriaMetrics/mcp-victoriametrics`, latest release v1.21.0 (2026-11-12), image `ghcr.io/victoriametrics/mcp-victoriametrics`. `MCP_SERVER_MODE=http` serves Streamable HTTP on `/mcp`; `MCP_AUTH_TOKEN` guards it; `MCP_DISABLED_TOOLS` removes tools; `MCP_MAX_RESPONSE_SIZE` caps a response (16 MiB by default). Tools include `query`, `query_range`, `labels`, `label_values`, `metrics`, `metrics_metadata`, `alerts`, `active_queries`, `explain_query`; `export` and the debug tools are off by default. Siblings exist for VictoriaLogs (`mcp-victorialogs` v1.10.0) and VictoriaTraces (`mcp-victoriatraces` v1.5.0). **Verified from the README and the GitHub release API, not run.**
- **`rmcp`**, the official Rust SDK of the Model Context Protocol (`modelcontextprotocol/rust-sdk`): 3.11.0, Apache-2.0, Rust 1.88. With the features `server`, `macros`, `transport-streamable-http-server` and `transport-io` it adds `schemars` 1.2, `chrono`, `rand` 0.10, `darling` and a few small crates to the tree; `axum`, `hyper`, `tower`, `tokio` and `reqwest` are already in `Cargo.lock`. **Verified with `cargo tree` in a probe crate; not compiled into the workspace.**
- **This repository**: the facts in "Context" were read from the code with file and line references (engine attempt path, `argv.rs`, `relay/mod.rs`, `broker/provider.rs`, `apps/worker/src/run.rs`, `BeforeClaim` in `crates/composition/src/hooks.rs`, `permissions.rs`, the migrations up to 002800).

Not verified: whether Claude Code 2.1.3xx keeps honoring `--mcp-config` together with `--strict-mcp-config` (ADR 0005 recorded it for 2.1.311); how Datadog bills or limits a service account's MCP use; whether `rmcp` 3.11's Streamable HTTP client works against Datadog's server.

## Decision 1: the troubleshooter is its own program, not a job of the pipeline

### Considered options

1. **A new job kind with one stage.** It reuses claims, leases, budgets and the ledger. But a job is for one issue, intake refuses anything else, and a new `StageKind` touches about twelve files, two database CHECK constraints and the state machine. Worse, a watchdog that runs inside the worker it watches cannot report that the worker is stuck.
2. **A `BeforeClaim` hook in the worker**, like the token sweep. Small, but the same flaw: it stops when the worker loop stops.
3. **A separate binary, `apps/troubleshooter`**, built on the composition library (ADR 0015) like the API and the worker. It schedules its own runs, keeps its own rows, and uses the same sandbox, runtime, broker, redactor and ledger code.

### Outcome

Chosen: **option 3.** The program that watches is a different process from the ones it watches. It still runs the agent the way the worker does: in the agent sandbox, with a job-like run token, through the broker, under the model routing policy.

A run is not a job. It has its own table (`troubleshooting_runs`) and its own identifier, and it never enters `jobs`, the pipeline or the job budget. Its spend is charged to its own day ceiling in `policies/model_routing.yaml` (role `troubleshooter`).

Cost of this choice: a fourth binary to deploy and configure, and a scheduler of its own instead of the worker's claim protocol.

## Decision 2: cheap deterministic probes on a short period; the model only when a probe trips, and on a slow sweep

### Considered options

1. **Run the agent every few minutes.** Simple. With the Sonnet route at the measured 0.12 to 0.25 US dollars a run, every 15 minutes is 11 to 24 dollars a day of plan use for a factory that is idle most of the time, and the agent sees the same healthy signals again and again.
2. **Probes first.** A probe is a typed, deterministic check with a threshold: a PromQL expression against VictoriaMetrics, a fixed query against a read-only database view, or "a Datadog monitor is alerting". Probes cost nothing but a few HTTP calls. The agent runs when a probe trips, with the tripped probes as its starting point, and on a slow sweep (once a day by default) to catch what no probe names.

### Outcome

Chosen: **option 2**, the way on-call work is done: alerts are cheap and mechanical, and the investigation is expensive and targeted.

- Probes, the period (5 minutes by default), the sweep (24 hours by default), the cool-down per probe (6 hours) and the daily caps live in a new policy file, `policies/troubleshooting.yaml`, with the same parser contract as the other policies (`deny_unknown_fields`, `schema_version`, tighten-only overrides, a policy hash).
- The first probes come from the factory's own signals (`docs/observability/conventions.md`): a stage failure rate, the gate failure rate, queue depth over a limit, retries, a lease past its deadline, a job waiting for a person past its expiry, the day spend near its ceiling, the API health route, and any Datadog monitor tagged `service:factory-*` in Alert.
- A probe that cannot run (its source is down) is itself a finding with the reason `source_unavailable`, raised without the model. The troubleshooter does not need the thing that broke in order to say it broke.
- At most one agent run at a time, at most `max_agent_runs_per_day` (8 by default), and a probe that tripped and was investigated waits for its cool-down before it can start another run.

## Decision 3: one MCP gateway in the control plane; the agent never holds a credential

### Considered options

1. **Run the MCP servers inside the agent sandbox** (stdio). The sandbox would need the Datadog keys, the VictoriaMetrics token and a database password, and a route to the internet. This breaks the rule that a sandbox holds only its run token (ADR 0020) and widens egress to arbitrary hosts.
2. **Let the sandbox reach each MCP server directly** over the job network. Three addresses, three credentials somewhere reachable, no single place that can see or limit what the agent asks.
3. **A gateway.** One MCP server, in the troubleshooter process, that the agent reaches as its only MCP server. The gateway holds the upstream credentials, connects to the upstream MCP servers as a client, and offers the agent a fixed list of tools, each mapped to one upstream tool.

### Outcome

Chosen: **option 3.** The gateway (`crates/mcp_gateway`) is the only place that:

- **holds credentials.** Datadog keys, the VictoriaMetrics token and the database login are files with mode `0600` named in the troubleshooter configuration, read at start, registered with the redactor by exact value, and never written to a sandbox, an argument, an environment variable of a container, or a log;
- **decides which tools exist.** A closed allowlist in `policies/troubleshooting.yaml`. Tools not on it are not listed to the agent and a call to one is refused. The upstream servers are also started or addressed with their own narrowing (Datadog `toolsets=core` and `omit_tools=` every notebook tool; VictoriaMetrics `MCP_DISABLED_TOOLS` with `export` and every debug tool; the Datadog application key holds no `mcp_write`). Two independent layers, because Datadog says its tools change;
- **checks a run token.** Each agent run gets a random bearer token valid for that run only, with a call budget and a wall-clock end. The gateway listens on loopback; the egress sidecar relays to it (Decision 5);
- **limits.** Calls per run, calls per 10 seconds (under Datadog's 50), bytes per tool result (64 KiB by default, the rest replaced by a truncation marker that says how much was cut), and a deadline per call;
- **redacts** every tool result with the factory's redactor before the agent sees it;
- **records** every call: run, tool, argument digest, upstream, duration, result bytes, outcome. The record of a run is stored as an artifact and its digest goes in the ledger entry of the run.

The upstreams in the first version:

| Gateway tool prefix | Upstream | How reached |
|---|---|---|
| `datadog_*` | Datadog MCP Server, `https://mcp.<site>/v1/mcp?toolsets=core&omit_tools=...` | Streamable HTTP client, `DD_API_KEY` and `DD_APPLICATION_KEY` headers from files |
| `vm_*` | `mcp-victoriametrics` v1.21.0, pinned by digest, `MCP_SERVER_MODE=http`, on the operations network | Streamable HTTP client, `MCP_AUTH_TOKEN` from a file |
| `pg_*` | The factory's read-only PostgreSQL MCP server (Decision 4) | In process, through an in-memory transport; the same code also ships as a binary |

VictoriaLogs and VictoriaTraces have official MCP servers of the same shape. Adding one is an upstream entry and an allowlist, not a design change. They are not in the first version because the owner named Datadog and VictoriaMetrics.

Cost of this choice: the gateway is new code on a security boundary and needs its own review. The agent sees renamed tools (`vm_query` instead of `query`), so a model's knowledge of the upstream names helps less.

## Decision 4: the PostgreSQL MCP server is read-only by the database, not by parsing SQL

### Considered options

1. **Parse the SQL and allow only `SELECT`.** Needs a parser dependency, and a parser that differs from PostgreSQL's in one corner is a hole. A `SELECT` can still call a function that writes or signals.
2. **Only curated tools, no free SQL.** Safest, but the agent cannot follow a lead the tool author did not foresee.
3. **Least privilege in the database, with free SQL boxed in by PostgreSQL itself, plus curated tools for the common questions.**

### Outcome

Chosen: **option 3.** The controls, in the order PostgreSQL applies them:

1. **A role that can only read what it should.** Migration `002900` adds the group role `factory_observer` (NOLOGIN, no BYPASSRLS, no CREATE anywhere). It gets `SELECT` on named columns of the operational tables only: identifiers, states, kinds, timestamps, counters, codes and reasons. It gets no column that holds a request text, a specification, an issue body, a token or token digest, a key, or a signature. Each such table gets one row-level policy `FOR SELECT TO factory_observer USING (true)`: the factory's troubleshooter looks across tenants, read-only, and FORCE ROW LEVEL SECURITY otherwise shows it nothing. It is a member of `pg_read_all_stats` (for `pg_stat_activity` and `pg_stat_statements`) and of nothing else. The login role that a deployment creates (`factory_troubleshooter`) is a member of `factory_observer` and has `default_transaction_read_only = on`, `statement_timeout = 5s`, `lock_timeout = 1s`, `idle_in_transaction_session_timeout = 10s` and a connection limit of 4. The migration refuses to run if a role of that name already has more powers, as migrations 0001 and 0011 do.
2. **Every query runs in `BEGIN READ ONLY`, then `ROLLBACK`.** A write, `nextval`, `NOTIFY` or a data-modifying CTE fails.
3. **Free SQL is wrapped as a subquery and sent with the extended protocol**: `SELECT to_jsonb(q) FROM (<sql>) AS q LIMIT <max_rows + 1>`. The extended protocol accepts one statement only. A subquery can only be a query: `INSERT`, `UPDATE`, `DELETE`, `MERGE`, DDL and a data-modifying `WITH` do not parse there. Rows come back as JSON whatever their column types.
4. **Caps** on rows (200), result bytes (64 KiB), statement time (5 s) and calls per run, enforced by the server whether or not the gateway enforces them too.
5. **Redaction** of every value with the factory's redactor, and of `query` texts from `pg_stat_activity` and `pg_stat_statements`, which can hold literals.

The tools: `pg_list_relations`, `pg_describe_relation`, `pg_query` (the boxed free SQL), `pg_explain` (`EXPLAIN (FORMAT JSON)` without `ANALYZE`), `pg_activity` (sessions, waits, oldest transaction), `pg_locks` (blocked and blocking sessions), `pg_table_health` (dead tuples, last vacuum and analyze, sequential scans), and `pg_factory_health` (fixed queries over the observer columns: jobs by state, stage runs past their deadline, leases past expiry, waits for a person past expiry, failures by reason in a window).

The library is `crates/mcp_postgres`. It is served by the gateway in process and also ships as `apps/mcp-postgres` (stdio and Streamable HTTP), so an engineer can point Claude Code at the factory database with the same guarantees.

It connects with `tokio-postgres` directly. Diesel is the factory's storage layer, but it maps rows to known types; this server returns arbitrary result sets, and `tokio-postgres` is already in the tree under `diesel-async`.

Cost of this choice: the column grants must be kept in step with the schema. A test lists every column of every table the role can read and fails when a new column appears that nobody classified, so a new sensitive column is denied until a person allows it.

## Decision 5: the agent reaches the gateway through a second, fixed relay of the sidecar

### Considered options

1. **Put the gateway on the job network.** The agent could then reach a host program directly, which no agent can today.
2. **Teach the broker MCP.** The broker is a model proxy with closed body shapes and pricing; MCP JSON-RPC would be a second protocol inside it.
3. **A second relay in the sidecar.** In `broker` mode the sidecar relays every connection to one upstream. A second listener relays to one more fixed upstream, the gateway. No host list, no CONNECT, no DNS.

### Outcome

Chosen: **option 3**, only for the `troubleshooter` sandbox profile. The agent's MCP configuration (written by the troubleshooter, never by the agent) names `http://<sidecar alias>:<mcp port>/mcp` and the run token. The policy's agent egress profile gains one entry, `mcp_gateway`, for this profile only. The policy says egress widening needs a person and a security review, so this waits for the owner.

## Decision 6: Claude Code gets `--mcp-config` for this profile only, and only gateway tools

- `FlagSet` gains `Troubleshooting`. `Flag` gains `McpConfig(path)` and `AllowedTools(list)`; `ClaudeTool` gains `Mcp { server: "factory", tool }` whose rendered name is `mcp__factory__<tool>`. Every other flag set stays as today, and the negative test that asserts no MCP server at start keeps holding for them.
- `--strict-mcp-config` stays. With it, the only MCP server is the one in the factory's file. The repository's `.mcp.json` is never read (there is no repository in the sandbox of this profile anyway).
- The troubleshooter's tools are the gateway tools and nothing else: no `Read`, `Write`, `Edit`, `Bash`, `Glob`, `Grep` or `Skill`. The sandbox has an empty workspace.

## Decision 7: a finding becomes an issue that a person triages, written by code from a closed template

- The agent returns a report, `health-findings` v1: `status` (`healthy`, `findings`, `needs_human`, `blocked`), and for each finding a `category` from a closed list, a `severity`, the `component`, a short `title`, `observations` (each tied to a gateway call id), a `hypothesis`, `confidence`, and `next_checks` for a person. The schema is closed, like every other agent's.
- **The engine checks the evidence.** Every observation must cite a call id that the gateway recorded for this run. A finding with no recorded call is refused.
- **Code writes the issue, the agent never does.** The troubleshooter renders a fixed template in which every agent-written field is quoted and length-capped, links are not made clickable, and mentions and cross-references are neutralised. The agent holds no GitHub tool (`github.write` stays `never_grantable`).
- **One issue per problem.** A finding's fingerprint is the SHA-256 of its category, component and the names of the probes or tools behind it, computed by code. The issue body carries it in a hidden marker. A second finding with the same fingerprint while the issue is open adds one capped comment (at most one a day) instead of a new issue. A closed issue is not reopened; a new one links to it.
- **Labels:** `troubleshooter` and `troubleshooter: triage`. Never `factory` or `design:`: an issue only becomes factory work when a person adds `design: approved` or files it again as factory work (ADR 0016's design gate is unchanged).
- **Caps:** at most `max_issues_per_day` (3 by default) new issues; past the cap, findings are kept in the run record and named in the next issue.
- **Where:** `troubleshooting.issue_repository` in the configuration, by default the factory's own repository. The GitHub App gets a new permission set, `troubleshoot_issue` (`issues: write`, `metadata: read`), minted for a troubleshooting run, not a job. `GitScope` gains a run scope. That is an additive port change and needs the review ADR 0016 asks for.

## Decision 8: logs and traces reach Datadog through the collector, as an option

The troubleshooter can only read logs and traces that some backend holds. Today logs go nowhere and traces go to Jaeger.

- An optional overlay, `infra/otel/compose.datadog.yaml`, switches the collector image to the contrib distribution, adds the `datadog` exporter to the traces and metrics pipelines, and adds a `filelog` receiver over the factory containers' JSON logs with a `logs` pipeline to Datadog. The Datadog API key is a Docker secret file.
- The factory's processes are not changed: they still write JSON on stderr. `opentelemetry-appender-tracing` stays off the dependency list.
- The default local stack stays as it is (VictoriaMetrics and Jaeger, no account needed). Without the overlay the troubleshooter still has the probes, VictoriaMetrics and the database.

## Owner decisions this record needs

Both answered by the owner on 2026-11-20 ("Aprovar rmcp", "Aprovar relay fixo").

1. **New direct dependency `rmcp` 3.11.0** (Apache-2.0, official SDK) with the features named above. Alternative: write the MCP protocol by hand over the HTTP stack the factory already has. Chosen: `rmcp`. MCP is a moving specification (the Streamable HTTP transport replaced SSE in 2025-03-26) and the official SDK follows it. **Approved.**
2. **Egress widening for the troubleshooter profile only**: one relay from its sidecar to the gateway (Decision 5). **Approved.** The security review the policy also asks for is still owed.

Items only a person can do, which block a live run but not the build: a Datadog service account with an application key that holds `mcp_read` and the product read permissions and no `mcp_write`, plus an API key; the GitHub App installed on the issue repository with `issues: write`; a database login role for `factory_troubleshooter`.

## Consequences

- A fourth binary and two library crates (`mcp_postgres`, `mcp_gateway`, both ring 2 adapters, no edge between them). `apps/troubleshooter` composes them.
- New migration `002900_observer_role`; the applied-migrations hash list gains a line.
- New policy `policies/troubleshooting.yaml`; new role `troubleshooter` in `security.yaml` and `model_routing.yaml`; a new agent in `agents/troubleshooter`.
- New threats, mitigations and negative tests (threat model):
  - **T-49** a log line, span attribute, metric label or database value carries instructions to the troubleshooter (prompt injection through observed data). Mitigation: every tool result is untrusted data inside the delimiters of the prompt; the agent has no tool that writes; the issue is written by code from a closed template; a person triages.
  - **T-50** the troubleshooter reads more of the database than it should. Mitigation: column grants, a column classification test, read-only transactions, redaction.
  - **T-51** an upstream MCP server adds a write tool. Mitigation: gateway allowlist plus upstream narrowing plus credentials without write permission.
  - **T-52** a run token or upstream credential leaks through a tool result or the issue. Mitigation: exact-value redaction of every result and of the issue body; run tokens expire with the run.
  - **T-53** the troubleshooter floods the issue tracker or the plan. Mitigation: fingerprints, one comment a day, issue and run caps, the role's day ceiling.
  - **T-54** a stuck or slow upstream holds the run. Mitigation: per-call deadline, run wall clock, `source_unavailable` findings raised without the model.
- Not built here: watching the repositories the factory changes (the owner chose the factory only); remediation of any kind; VictoriaLogs and VictoriaTraces upstreams; Codex as the troubleshooter's runtime (unavailable in subscription mode, ADR 0020).
