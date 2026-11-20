# Security review of the troubleshooter's MCP sources (ADR 0021, `feat/troubleshooter-agent`)

- Reviewer: an independent security reviewer (Claude Opus 5.5), working alone from the repository. I wrote none of the code under review and changed none of it. My only addition is this document. Every experiment ran in a scratch database (`factory_t_review_tr01`) and scratch logins (`dbtest_review_*`) that I made and dropped again on the test server. No test, source or policy file was changed, not even for a while.
- Date: 2026-11-20. Reviewed range: `git diff 02b8ec9..HEAD` on `feat/troubleshooter-agent` (HEAD `a412150`, "Disable the VictoriaMetrics documentation tool and shrink its server").
- Question: can the read-only PostgreSQL server, the MCP gateway, the troubleshooter's flag set and sandbox, the issue writer, the findings schema or the infrastructure overlays be used to write, signal, leak a secret or another tenant's data, reach anything other than the broker and the gateway, fake evidence, or exhaust a resource. `apps/troubleshooter` is not built yet and is out of scope. Where a defect only shows once that program composes these parts, I say so.
- Environment. **(run)** means I ran it against PostgreSQL 18.7 at `127.0.0.1:54329`, with every migration applied by a superuser the way the test support applies them, as real `LOGIN` roles, or that I ran it with `cargo nextest`. **(read)** means I read the code and did not run it. Nothing ran against Datadog, a real VictoriaMetrics MCP server, GitHub or Claude Code.

## 1. Verdict

**PASS WITH CONDITIONS.** I found no BLOCKER and no HIGH.

What holds up (section 5 has the detail). The read-only boundary of the database server held against everything I tried. Writes, `nextval`, `NOTIFY`, `SELECT ... FOR UPDATE`, data-modifying CTEs and a second statement all fail or are rolled back. Session state does not outlive a call, because every call ends with `ROLLBACK` and `DISCARD ALL`. Sensitive columns are refused to a correctly made observer login (run). The gateway's allowlist is an exact byte match on a name taken from the policy, and the upstream tool name never comes from the agent. Run tokens are 256 bits from the OS, compared in constant time, and end at `close_run` or at the wall clock. Credential files are checked for mode on the open handle. Redaction runs on the whole upstream text before the cut, so a cut cannot leave half a secret. The runtime and the argv builder each refuse MCP for any flag set other than `Troubleshooting` and refuse every built-in tool for it. The launcher line is a fixed constant and takes its arguments as positional parameters. The token is a variable reference in the inline JSON, and the URL is checked for `$`, user info and query. The issue template defangs every agent field and puts it in a code span, and only issues the App opened, with a marker in the body, count for deduplication.

**Why not PASS.** Five MEDIUM findings, each with a concrete scenario and, for four of them, a run that shows it:

1. **TR-1.** The login check is a denylist that misses `pg_read_all_data`, ownership and the owning role. Because the observer policies are `USING (true)` on every tenant, a login made wrongly in one of those ways reads every sensitive column of every tenant, and the check accepts it (run).
2. **TR-2.** An agent-written query can stream gigabytes into the troubleshooter's memory before any cap applies: 3.6 GB in the 5-second statement timeout (run).
3. **TR-3.** Free SQL reads the raw query texts of other sessions. Literal scrubbing only applies to a column named `query`, and SQL can change any text past the exact-value redactor (run).
4. **TR-4.** From the observer login, inside `BEGIN READ ONLY`, the agent can hold the per-tenant advisory lock of the audit chain, and so stall every audit write of every tenant 5 seconds per call (run).
5. **TR-5.** A refused call gets a citable call id, and the record does not tie an id to a result. The "evidence check" can be satisfied by fabricated observations at no cost (read).

**Conditions.** Close TR-1 to TR-5 before the troubleshooter or `apps/mcp-postgres` is pointed at a database that holds a real tenant's data. TR-5 must be closed in the record API before `apps/troubleshooter` writes its evidence check on top of it. TR-6 (shared call budget) must be settled when `apps/troubleshooter` is composed, or the PostgreSQL tools stop working within hours. TR-7 to TR-11 can follow.

**What the verdict does not cover.** Section 7.

## 2. Severity scale

BLOCKER: do not run against real data until closed. HIGH: a promised control does not hold for a realistic attacker, with serious impact. MEDIUM: a promised control is weaker than promised, or a prompt-injected agent can reach further than its design allows, and the fix is cheap. LOW: defence in depth, a misclassification, a contract that will break when composed, an inaccurate claim.

## 3. Findings

| ID | Severity | Area | Finding |
|---|---|---|---|
| TR-1 | MEDIUM | `mcp_postgres` login check | The refusal list misses `pg_read_all_data`, table ownership and membership in the owning role; such a login reads every sensitive column of every tenant and is accepted |
| TR-2 | MEDIUM | `mcp_postgres` caps | Rows are fully buffered before the row and byte caps apply; one query streams 3.6 GB in 5 s into the troubleshooter process |
| TR-3 | MEDIUM | `mcp_postgres`, `pg_read_all_stats` | Free SQL returns other sessions' query texts unscrubbed and can transform them past the redactor |
| TR-4 | MEDIUM | `mcp_postgres`, database availability | The observer can take the factory's advisory locks (the audit chain lock of every tenant) inside a read-only transaction |
| TR-5 | MEDIUM | `mcp_gateway` call record, evidence | Refused calls receive call ids, and refusals past the run limits cost nothing; the record has no result digest and does not tie the cited tool; fabricated observations pass an existence check |
| TR-6 | LOW | `mcp_postgres` with `mcp_gateway` | The PostgreSQL call budget (300) is per `Inspector`, shared by every clone and so by every run of a long-lived gateway; the probes alone spend it in hours |
| TR-7 | LOW | `mcp_gateway`, T-49 | Upstream tool descriptions and input schemas reach the model as tool definitions, outside the prompt's data delimiters; schemas are uncapped and changes are not detected |
| TR-8 | LOW | domain fingerprint | The fingerprint is built from agent-chosen tool names and probe ids; the agent can split one problem into many issues or collide with another |
| TR-9 | LOW | `apps/mcp-postgres` | A password or bearer token shorter than the redactor's minimum is silently not registered for redaction |
| TR-10 | LOW | `observer-login.sql` | The password travels in the SQL text of `CREATE ROLE`, where server logs and `pg_stat_statements` (readable by the observer itself) keep it |
| TR-11 | LOW | column classification | GitHub repository and installation ids are granted while the repository name is withheld; the id resolves to the name through GitHub's public API |

Counts: 11 findings: 0 BLOCKER, 0 HIGH, 5 MEDIUM (TR-1 to TR-5), 6 LOW (TR-6 to TR-11).

## 4. The findings in detail

### TR-1. The login check is a denylist with gaps (MEDIUM)

**Where.** `crates/mcp_postgres/src/inspector.rs:22` (`FORBIDDEN_GROUPS`) and `:112-153` (`check_login`). `migrations/2026-11-20-002900_observer_role/up.sql:150-163` (the `observer_read` policies, `USING (true)`).

**Scenario.** The migration's control rests on column grants: the observer gets no sensitive column. The row filter is deliberately open, because the policies are `FOR SELECT TO factory_observer USING (true)` on all fifteen tables. So any extra **table** privilege that a login also holds becomes a cross-tenant read of that column. `check_login` is meant to refuse such a login, but it only refuses a superuser, `BYPASSRLS` and a fixed list of ten groups. Three ways a deployer gets this wrong pass the check:

- the login is also in `pg_read_all_data`, which is common for "read-only monitoring" logins;
- the login owns the factory's tables, or is a member of the role that owns them (the migration role in a deployment that does not migrate as superuser);
- the login is in `pg_monitor` (which adds `pg_read_all_settings` and `pg_stat_scan_tables`). This one is less serious.

**Evidence (run).** In a migrated database I made `dbtest_review_rad LOGIN IN ROLE factory_observer, pg_read_all_data`, ran the exact `check_login` query as that role, and got `superuser=f, bypassrls=f, observer=t, too_much=f`, so the check accepts it. In `BEGIN READ ONLY`, the wrapped free SQL `select tenant_id, idempotency_key, normalized_request_sha256 from jobs` then returned both tenants' rows with the two sensitive columns. A login made as `observer-login.sql` makes it got `permission denied for table jobs` for the same query. `pg_read_all_data` does not bypass row-level security. The observer's own `USING (true)` policy is what opens every tenant's rows to it.

**Fix (described).** Make the check an allowlist of what the login *is*, not a denylist of what it must not be. The login's transitive memberships (`pg_auth_members`, recursively) must be exactly `{factory_observer, pg_read_all_stats}`. It must own no relation, schema or function in the database. It must have no `rolcreaterole`, `rolcreatedb` or `rolreplication`. And `has_table_privilege(c.oid, 'SELECT')` must be false for every table that has sensitive columns. That last check is the property itself, whatever role grants it. Add a test per case: `pg_read_all_data`, owner role, `pg_monitor`, CREATEROLE.

### TR-2. Results are buffered before they are capped (MEDIUM)

**Where.** `crates/mcp_postgres/src/inspector.rs:509` (`client.query(...)`, which collects every row in memory), `:511-526` (each row parsed into a `serde_json::Value`), and `crates/mcp_postgres/src/sql.rs:43-49` and `:189-240` (the row limit is in SQL, but the byte cap applies only after everything has arrived).

**Scenario.** A prompt-injected agent (T-49), or an engineer's mistake through `apps/mcp-postgres`, sends `select repeat('x', 200000000) from generate_series(1, 200)`. The `LIMIT 201` lets every row through. PostgreSQL streams each row as fast as it can until the statement timeout. `tokio-postgres` keeps all of them, then the code parses each into a `Value` (a second copy), then `render_rows` serialises each again (a third). The troubleshooter process holds the gateway, the scheduler and the probes, and it dies of memory. The watchdog is down, and it cannot report that it is down. If the rows finish before the timeout the call even succeeds, and the three copies are all live at once.

**Evidence (run).** As a correct observer login, in `BEGIN READ ONLY` with `statement_timeout = 5000`, the wrapped query above streamed **3,600,000,202 bytes** to the client before `canceling statement due to statement timeout` (`psql` with `FETCH_COUNT 1`, piped to `wc -c`, 5.38 s wall). The server also allocates each 200 MB value, and the login may hold four connections.

**Fix (described).** Bound the bytes in SQL and on the wire, not after. Wrap as `SELECT left(to_jsonb(q)::text, <max_result_bytes + 1>) FROM (...) q LIMIT n`, so that no row larger than the cap is ever sent. Read with `query_raw` as a stream, keep a running byte count, and stop and cancel the query (`cancel_token`) the moment the count passes `max_result_bytes`. Add a test with a 100 MB row and a test with 200 rows of 1 MB that asserts the process's peak growth stays near the cap.

### TR-3. Free SQL reads other sessions' query texts unscrubbed (MEDIUM)

**Where.** `crates/mcp_postgres/src/inspector.rs:15-18` (`QUERY_TEXT_KEYS`) and `:426-438` (`clean`). `migrations/2026-11-20-002900_observer_role/up.sql:23-25` and `:64` (`pg_read_all_stats`).

**Scenario.** ADR 0021, decision 4, item 5, promises redaction of query texts from `pg_stat_activity` and `pg_stat_statements`, "which can hold literals". The scrubbing applies to a JSON key named `query`, `blocked_query` or `blocking_query`. Through `pg_query` the agent writes the SQL, so `select query as t from pg_stat_activity` comes back raw. The exact-value redactor is also bypassed by `reverse(query)`, `encode(convert_to(query,'UTF8'),'base64')`, or `substr` in pieces, because the SQL can change the text before redaction sees it. These texts are not only the factory's own bind-parameter statements. They include an operator's `psql` session, a migration, `CREATE ROLE ... PASSWORD '...'` (TR-10), and any client of the cluster: `pg_read_all_stats` is cluster-wide, so other databases' sessions are visible too. They then reach the model and, quoted, a GitHub issue.

**Evidence (run).** A superuser session ran `SELECT 'customer-literal-31337' AS v, pg_sleep(3)`. The observer's wrapped `select pid, query as text_of_session from pg_stat_activity where ...` returned `{"pid": 53800, "text_of_session": "SELECT 'customer-literal-31337' AS v, pg_sleep(3)"}`. The existing test `activity_shows_other_sessions_without_their_literals` passes, but it covers only the curated tool.

**Fix (described).** Do not give the free-SQL login the raw texts. Revoke `pg_read_all_stats` from `factory_observer`. Expose the texts through a `SECURITY DEFINER` view or function, owned by a role that has `pg_read_all_stats`, that returns the activity and statement columns with `query` already scrubbed in SQL (or no `query` column at all), and filtered to the factory's database (`datid = (SELECT oid FROM pg_database WHERE datname = current_database())`). Grant only that view to the observer and point `pg_activity` and `pg_locks` at it. If raw texts are kept for the curated tools, give those tools a separate login that cannot run free SQL.

### TR-4. The observer can hold the factory's advisory locks (MEDIUM)

**Where.** `migrations/2026-11-20-002900_observer_role/up.sql:26-27` ("The functions PUBLIC may execute stay as they are"). `migrations/2026-10-27-000700_audit_events/up.sql:96` (`pg_advisory_xact_lock(hashtextextended('factory.audit_events:' || tenant_id, 0))`). `crates/mcp_postgres/src/inspector.rs:490-499`.

**Scenario.** Advisory lock functions are executable by `PUBLIC` and work in a read-only transaction. The tenant ids are on the observer's grant (`tenants.id`), and the lock key formula is in a public migration. One `pg_query` call does the whole thing: `select pg_advisory_xact_lock(hashtextextended('factory.audit_events:' || id::text, 0)), pg_sleep(4.9) from tenants`. That takes the audit chain lock of every tenant and holds it for the statement timeout. Every audit insert of every tenant waits behind it, and with them the transactions that write audit events last (jobs, approvals, the API's records). With 60 calls a run, about five minutes of stall per run are possible, and up to eight runs a day. Integrity is not touched, but a log line that injects instructions turns the troubleshooter into a stall of the thing it watches. `DISCARD ALL` releases a session-level lock at the end of the call, but that does not shorten the hold.

**Evidence (run).** As the observer, in `BEGIN READ ONLY` with `statement_timeout = 5000`, the wrapped `select pg_advisory_xact_lock(hashtextextended('factory.audit_events:' || t.id::text, 0)), pg_sleep(4) from tenants t where t.id = '...0001'` ran. Meanwhile a superuser's `pg_try_advisory_xact_lock` on the same key returned `f`.

**Fix (described).** In order of strength: point the observer login at a physical read replica (advisory locks, row locks and load then stay off the primary, which is also the best answer to TR-2's server-side cost); or `REVOKE EXECUTE` on the `pg_advisory_*` and `pg_try_advisory_*` functions from `PUBLIC` and grant them to the factory's own roles; at the least, set `lock_timeout` and a short `statement_timeout` on the audit writers so a stall becomes a fast failure. Add a negative test that the observer cannot take `factory.audit_events:<tenant>`.

### TR-5. Call ids can be minted for nothing, and the record cannot verify an observation (MEDIUM)

**Where.** `crates/mcp_gateway/src/gateway.rs:715-731` (a call id is assigned and the record pushed for every refusal) and `:806-856` (`admit`: `ToolNotAllowed`, `MaxCallsPerRun` and `MaxCallsPer10s` refusals do not count against any limit). `crates/mcp_gateway/src/record.rs:264-271` (`RunRecord::call` returns any recorded call, whatever its outcome) and `:199-222` (no result digest). `agents/schemas/health-findings.v1.schema.json` (`observation.call_id` and `observation.tool` are independent). `crates/domain/src/troubleshooting/issue.rs` (the issue tells the reader "each line is one gateway call of the run").

**Scenario.** Decision 7 says that a finding with no recorded call is refused, and the issue presents each observation as backed by a call. But the record gives an id to every refused call. After its 60 allowed calls, or past 40 in ten seconds, each extra call the agent makes is refused, recorded with a fresh id, and charged to nothing, up to `MAX_RECORDED_CALLS` (1000). An injected agent can therefore cite `call-61` ... `call-70` for fabricated observations, and `RunRecord::call` finds each one. Even a successful call proves only that a call happened. Nothing ties the `observed` text to what that call returned, and nothing ties the cited `tool` to the call's `gateway_tool`. A second effect: filling the record to 1000 with free refusals makes every later `call_for_run` of the control plane fail `RecordFull`, so the probes go blind for the rest of that run.

**Evidence (read).** I traced the paths above. A `ToolNotAllowed` refusal can only come from a name that Claude Code's `--allowedTools` lets through, so in practice the free ids come from the two rate refusals. The evidence check itself is in `apps/troubleshooter`, which is not built, so this finding concerns what the record API makes possible.

**Fix (described).** Give refusals no citable id: record them under a separate counter, or mark them `citable: false`. Add `RunRecord::evidence(call_id, tool)`, which returns a call only when its outcome is `ok` or `tool_error`, its `gateway_tool` equals the cited tool, and it was made by the agent or a probe of this run. Store a SHA-256 of the returned text in each `CallRecord`, so a person (or a later check) can match a quote to a result. Count refusals against `max_calls_per_run` past a small grace, and reserve record slots for control-plane calls.

### TR-6. The PostgreSQL call budget is per process, not per run (LOW)

**Where.** `crates/mcp_postgres/src/limits.rs:16-18,32` ("One server serves one troubleshooting run in the gateway"; 300). `crates/mcp_postgres/src/tools.rs:108` (every clone shares one `Inspector`). `crates/mcp_gateway/src/upstream.rs:145-167` (`InProcessUpstream` serves a clone on each connect). `crates/mcp_gateway/src/lib.rs:44-56` (one gateway, many `open_run`).

**Scenario.** The gateway is built once with its upstreams and serves run after run. The in-process PostgreSQL upstream is one `PostgresMcp` whose clones share one `Inspector` and one 300-call budget. The SQL probes (three, every 5 minutes, through `call_for_run`) plus the agents' `pg_*` calls spend it within hours. After that every `pg_*` call fails `call_budget_spent` for the rest of the process's life. Depending on how the app maps that failure, it either raises false `source_unavailable` findings or silently loses the database view.

**Fix (described).** Make the budget a per-run value: `Inspector::with_budget` per run, or a budget keyed by run id passed through the call. Or build a fresh `PostgresMcp` for each run and have the gateway swap the upstream at `open_run`. Keep a process-wide rate limit for the database's sake.

### TR-7. Upstream tool descriptions and schemas reach the model as tool definitions (LOW)

**Where.** `crates/mcp_gateway/src/gateway.rs:488-505` (`exposed_tool`: description redacted and cut to 4096 bytes; the input schema redacted but not capped) and `:51-57` of `server.rs` (`list_tools`).

**Scenario.** The prompt treats tool results and the `gateway_tools` input block as untrusted data inside delimiters. The same upstream text also reaches Claude Code as MCP tool definitions, which the model reads as part of its tool set, outside any delimiter. Datadog calls its server "under significant development" and changes its tools. A description change, whether a mistake or a compromise upstream, is passed through on the next `connect`/`refresh` without notice, at a higher trust level than a log line. The input schema has no size cap, and its property descriptions are a second free-text channel.

**Fix (described).** Write each gateway tool's description in the policy (one sentence, as `security.yaml` already has) and send that, not the upstream's. Pin a SHA-256 of each upstream tool's name, description and input schema in `policies/troubleshooting.yaml`. On a mismatch, leave the tool out and raise the `upstream_tool_not_allowed` finding as for a new tool. Cap the schema's bytes.

### TR-8. The fingerprint rests on what the agent chose to cite (LOW)

**Where.** `crates/domain/src/troubleshooting/mod.rs:189-226` (`FindingFingerprint::of` uses the observations' `tool` and the finding's `probe_ids`).

**Scenario.** One problem cited once with `vm_query` and once with `vm_query, pg_activity` gets two fingerprints, so two issues. An agent can also cite a tripped probe it did not investigate, which steers a finding onto another problem's issue as a "seen again" comment. The caps (3 new issues and one comment per issue a day) bound the damage. Dedup is still steered by the agent, which ADR 0021 says code decides.

**Fix (described).** Take the probe ids only from the probes that tripped for this run (refuse others). Take the tool names from the call record of the cited ids (TR-5), not from the agent's `tool` field. Consider fingerprinting on category, component and probe ids only, with tools as a tie-breaker for sweep findings.

### TR-9. A short password or token is silently left unredacted (LOW)

**Where.** `apps/mcp-postgres/src/main.rs:111-120`. `Redactor::register` returns `Ok(Registered::TooShort)` (`crates/domain/src/redaction/registry.rs:142-143`), and only `Err` is mapped to a refusal.

**Scenario.** A database password shorter than the redactor's minimum is accepted and never redacted from error messages or results. `mcp_gateway` treats `TooShort` as an error and refuses (`redact.rs`, `RegisterFailed::TooShort`); the app does not.

**Fix (described).** Treat `Registered::TooShort` as a usage error in the app, as the gateway does, with a message that names the minimum.

### TR-10. The login script puts the password in the SQL text (LOW)

**Where.** `docs/database/observer-login.sql:11-13` (`CREATE ROLE ... PASSWORD :'password'`).

**Scenario.** The text of `CREATE ROLE` includes the cleartext password. With `log_statement = ddl` (or `all`) it lands in the server log. If an operator enables `pg_stat_statements` as `docs/database/operating-settings.md` §3 describes (`track_utility` is on by default), the utility statement is kept. As far as I can read PostgreSQL's grammar, the password is a plain string option that normalisation does not replace. Members of `pg_read_all_stats`, the observer itself among them, can read it, and through TR-3 so can the agent. The script is the template operators will copy for other logins. I did **not** run the `pg_stat_statements` part, because the test server does not preload it.

**Fix (described).** Set the password as a SCRAM verifier computed on the client (`psql`'s `\password factory_troubleshooter`, or `PASSWORD 'SCRAM-SHA-256$...'` built by a script), never as cleartext SQL. Note in `operating-settings.md` that `pg_stat_statements` texts are readable by the observer.

### TR-11. GitHub ids are granted while the repository name is withheld (LOW)

**Where.** `migrations/2026-11-20-002900_observer_role/up.sql:80-84` and `:98-101`. `docs/database/observer-columns.txt:167-168,243-244`.

**Scenario.** The migration withholds `repositories.full_name` because it "names a customer", but grants `github_repository_id` and `github_installation_id`. For a public repository, `GET /repositories/{id}` returns the name, and an installation id identifies the customer's account to anyone with the App's credentials. The classification is inconsistent with its own reason. The agent can quote the ids in an issue, which may be public.

**Fix (described).** Classify both ids as sensitive, or replace them for the observer with the factory's own `repositories.id`, which is already granted and is opaque outside the factory.

## 5. What I checked and found sound

- **The read-only box (run, the crate's own suite).** The 81 tests of `factory-mcp_postgres` and `factory-mcp_gateway` pass. They include writes, a second statement after a closed subquery, `nextval`, ending another role's session, settings and advisory locks not outliving a call, the timeout, row and byte caps, sensitive columns, redaction of results and error messages, the call budget, and a login with write groups being refused. **(read)** `SELECT ... FOR UPDATE/SHARE` needs `UPDATE` privilege and is refused in a read-only transaction. `set_config('transaction_read_only','off', ...)` fails after the first query. `pg_notify` is discarded by `ROLLBACK`. `EXPLAIN` without `ANALYZE` checks privileges and does not run the query. A data-modifying `WITH` is refused inside a subquery. The prefix `SELECT to_jsonb(q)::text FROM (` fixes the top-level statement kind.
- **SECURITY DEFINER functions (read).** The only two (`resolve_token`, `resolve_installation`) have `EXECUTE` revoked from `PUBLIC` (`2026-10-27-001400/up.sql:107-110`), so the observer cannot reach token digests through them.
- **Errors (read).** Connection errors become a fixed sentence. Database messages go through the redactor. `Password` and `SecretValue` hide their values in `Debug`.
- **Gateway tokens and allowlist (read, gateway tests run).** 256-bit OS random tokens, base64url. The comparison is constant time over the expected length, and every open run is scanned with no early exit. The token stops at `close_run` (marked closing at once) and at the wall clock. The allowlist is an exact byte match on the policy's `gateway_name`, and the upstream tool name comes from the policy, never the caller, so no case, Unicode or prefix trick changes the target. Redaction runs before truncation, and truncation keeps UTF-8 boundaries. The upstream HTTP client follows no redirects and uses no proxy from the environment. Datadog sites are a closed list. The VictoriaMetrics URL refuses user info and query. SSE events and JSON bodies are bounded by `rmcp` (`max_json_response_size`, a default SSE event limit).
- **Runtime (read).** `ClaudeCodeRuntime` refuses a request where `flag_set == Troubleshooting` and the presence of `mcp_gateway` disagree, and Codex refuses both. `argv::build` refuses built-in tools for the troubleshooter, gateway tools for every other flag set, and a URL that is not plain `http://host:port/path` without `$`. It writes no `--dangerously-skip-permissions` for the troubleshooter and keeps `--strict-mcp-config`. The JSON is built with `serde_json`, so there is no injection. The launcher lines are constants run as `sh -c <line> <tool> <args...>`, with the tool and its arguments as positional parameters.
- **Sandbox and egress (read).** The MCP token mount is all or nothing against the spec. Only the `Troubleshooter` profile gets the second relay, and a base sidecar command that names `--second-*` is refused. The second listener relays to one fixed `SocketAddr` and reads no byte. The token file is created new at 0400 in a 0700 directory.
- **Issue writer (read).** Every agent field is cut, flattened to one line, stripped of bidirectional, zero-width and tag characters, defanged (`<>@#`, `://`, `www.`, the marker word), and put in a code span with a long enough fence. Only issues the App opened, labelled `troubleshooter`, with the marker on a body line of its own count for deduplication. A listing cut short is `Unavailable`, not absence. Labels are checked again before sending. The run's token class cannot be minted for a job, and a job's classes cannot be minted for a run. The secret guard runs on the rendered text and on the raw agent words.
- **Collector overlay (read).** Agent sandboxes and sidecars run with `--log-driver none` (`crates/sandbox/src/container/args.rs`), so their output is not in the files the `filelog` receiver reads. The Datadog API key is a Docker secret read with `${file:...}`. Images are pinned by digest.

## 6. What was run

- `FACTORY_DB_ADMIN_URL=postgres://factory_admin@127.0.0.1:54329/postgres cargo nextest run -p factory-mcp_postgres -p factory-mcp_gateway -p factory-mcp-postgres`: 81 passed, 0 failed.
- A scratch database `factory_t_review_tr01` with every migration and the two-tenant fixtures of `docs/database/tests/00_helpers.sql`, and two logins: `dbtest_review_obs` (observer only) and `dbtest_review_rad` (observer plus `pg_read_all_data`). In it:
  - the `check_login` query as `dbtest_review_rad` (TR-1);
  - a wrapped read of `jobs.idempotency_key` and `jobs.normalized_request_sha256` as each login (TR-1);
  - a wrapped `repeat('x', 200000000) ... generate_series(1, 200)` under a 5-second timeout, measured with `wc -c` and `/usr/bin/time -l` (TR-2);
  - a wrapped `pg_stat_activity` read with an aliased `query` column against a concurrent literal-bearing session (TR-3);
  - the audit-chain advisory lock taken by the observer and probed with `pg_try_advisory_xact_lock` from another session (TR-4).
- The scratch database and both logins were dropped afterwards. `factory_observer` is cluster-wide and was left as the test suites leave it.

## 7. What I did not review

- `apps/troubleshooter` (not built): the scheduler, the evidence check, the probe engine, how a run id, run scope and tenant are chosen, and how upstream failures map to findings.
- Behaviour against the real Datadog MCP Server, VictoriaMetrics MCP server, GitHub and Claude Code (including whether `dontAsk` with `--allowedTools` holds in the agent image's Claude Code version).
- Whether the egress sidecar can reach a gateway that `check_listen` restricts to loopback, given `--second-upstream 172.17.0.1:9444` in the examples. This is a deployment-topology question that I did not resolve.
- `crates/contracts` policy loaders and their tests, `policies/model_routing.yaml` and its schema, `crates/ports` beyond `triage_issue.rs`, the `crates/testkit` fakes and contracts beyond a skim, and the threat-model and guide text beyond T-49 to T-54.
- The prompt (`agents/troubleshooter/prompt.md`) beyond its injection-handling sections.
- Statistical or timing measurement of the constant-time comparisons.

## 8. Fix status

| ID | Status | Commit | The test that holds it | What was done |
|---|---|---|---|---|
| TR-1 | open | | | |
| TR-2 | open | | | |
| TR-3 | open | | | |
| TR-4 | open | | | |
| TR-5 | open | | | |
| TR-6 | open | | | |
| TR-7 | open | | | |
| TR-8 | open | | | |
| TR-9 | open | | | |
| TR-10 | open | | | |
| TR-11 | open | | | |
