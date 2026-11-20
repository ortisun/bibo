# API security review: authentication, webhook, authorization, tenancy and hardening

- Scope: the HTTP API (`apps/api`), its webhook path (`crates/composition/src/webhook.rs`, `crates/github/src/webhook.rs`), the store operations behind tokens, idempotency and webhook de-duplication (`crates/storage`, migrations 2 to 4 and 9 to 14), the command line client (`apps/cli`), and the redactor pattern changed in commit `8215375`. Spec: `apps/api/README.md`, `apps/api/openapi.json`, `docs/security/` (threat model and negative-test catalog), ADR 0012 and 0014, `policies/approval.yaml`.
- Date: 2026-10-28. Reviewed commit: `8215375` (`feat/slice-0-foundation`). Reviewer: the security specialist, working independently. I did not build any of this and I changed none of it.
- Environment: one macOS laptop, PostgreSQL 18.6 (a private Homebrew cluster started by the storage crate's test support), the real server on loopback, no TLS terminator, no real GitHub, no model calls, no Docker.
- Evidence: the test target `apps/api/tests/security_review/` holds 26 tests, all `#[ignore]` so CI is unchanged. **13 are confirmed defects and fail today. 13 are probes that held and pass today.** No `[[test]]` line was needed: cargo finds the directory target by itself, and no existing file was edited. The package's own suite (86 tests) passes in the same environment.

## 1. Verdicts

| Scope | Verdict |
|---|---|
| A. The HTTP API and its authentication | **PASS WITH CONDITIONS** |
| B. The worker hook (requirements only) | Not a review. The requirements are in section 8. |

**Why not PASS.** Nothing I found lets an unauthenticated client read another tenant, forge a signature, or approve anything. The token design, the webhook verification and the tenant isolation held against everything I tried (section 4). But four findings make the service weaker than its own documents say, and each can be closed with a small change:

1. **API-1.** The allowlist's `repositories` narrowing is read and then ignored. A person limited to one repository can act on every repository of the tenant.
2. **API-3.** The internet-facing database login can insert tokens, approvals, ledger entries and outbox rows. With its own credentials I minted a working token for another tenant's approver.
3. **API-4.** Nothing recognises an API token (`sfat_`) as a secret: not the redactor, not gitleaks, not the check that refuses secrets in a job request.
4. **API-6.** One source address can occupy every connection slot of the server.

**Conditions.** Close API-1, API-3 and API-4 before any person other than the builders gets a token. Close API-6 (or compensate at the proxy, D-3) before the port is reachable from a network you do not control. The Low findings can wait for the next slice. If API-3 is accepted as a Slice 1 risk it must be recorded as one with an owner and a date, because section 8 shows it also decides how far the worker hook can trust the audit log.

**What the verdict does not cover.** A real GitHub delivery, a TLS terminator, a deployment, load above the rate limits, statistical timing measurements, and the worker hook, which does not exist yet. See section 6.

## 2. Severity scale

High: an unauthenticated or low-privilege party reads across tenants, forges an approval, or runs code. Medium: a boundary is weaker than the documents say, or one unauthenticated source can deny service. Low: defence in depth, evidence quality, or a mistake that a caller can trigger on demand. Info: worth knowing, no action needed now. There is no High finding.

## 3. Findings

All commands start from the worktree root and need `CARGO_INCREMENTAL=0` if you share a target directory. Run one defect with
`cargo test -p factory-api --locked --test security_review -- --ignored <path> --exact`; all of them with `-- --ignored api_ --test-threads=1`; all probes with `-- --ignored held_ --test-threads=1`.

| ID | Severity | Status | Finding | Owner |
|---|---|---|---|---|
| API-1 | Medium | Confirmed | The allowlist `repositories` narrowing grants nothing less than the whole tenant | `workflow` (Authority port), `composition`, `apps/api` |
| API-2 | Low | Confirmed | An idempotency key belongs to the tenant, not the caller: a second user is answered with the first user's job | `apps/api`, `storage` |
| API-3 | Medium | Confirmed | The API login holds INSERT on 13 tables it never writes; it can mint a token for any principal of any tenant | `dba`, `storage` |
| API-4 | Medium | Confirmed | No rule recognises an API token (`sfat_`); a pasted token is accepted into a job request | `security` (policy, gitleaks), `apps/api` |
| API-5 | Low | Confirmed | `url_with_credentials` misses 11 shapes; 3 of them are a regression of commit `8215375` | `security`, `observability` |
| API-6 | Medium | Confirmed | No per-peer connection cap: one source holds every slot with silent connections | `apps/api`, `sre` |
| API-7 | Low | Confirmed | Forged deliveries use up the shared platform-audit budget, so a genuine unbound delivery is not audited | `apps/api` |
| API-8 | Low | Confirmed | Every refused decision writes an audit row; no bound per principal | `apps/api` |
| API-9 | Low | Confirmed (unit level) | The per-source rate limit is per IPv6 address, not per prefix | `apps/api` |
| API-10 | Low | Confirmed | The CLI prints control characters sent by the server | `apps/cli` |
| API-11 | Low | Confirmed | A repeated `X-Correlation-Id` and a malformed pagination cursor are answered 503 and logged as store faults | `apps/api`, `storage` |
| H-1 to H-8 | Low or Info | Hypothesis | See section 5; no test | various |

### API-1. A narrowed designation reaches every repository (Medium, confirmed)

- **Evidence.** `policies/approval.yaml:122` says an allowlist entry "may be narrowed to listed repositories". `crates/composition/src/seams.rs:206` parses `repositories`. `StoreAuthority::designations` (`crates/composition/src/authority.rs:88-111`) filters by tenant, numeric id and expiry and never reads it. `Authority::roles(tenant, principal)` has no repository argument, so no caller could apply it.
- **Shown by.** `defects::api_1_a_designation_narrowed_to_one_repository_does_not_reach_another`. A requester narrowed to `org/repo-0` submitted a job to `org/other-repo`: `201`. An approver narrowed the same way approved a job on the other repository: `202`.
- **Impact.** The one control that limits a person to some repositories does nothing in the API. Inside a tenant, a narrowed requester can start work and a narrowed approver can record approvals anywhere. The worker hook will inherit the same blindness unless it is told (R-4).
- **Smallest fix.** Give `roles` and `admission` the repository, filter entries by `repositories` (and by the job's repository on a decision). Until then, fail closed: refuse to load an allowlist entry that sets `repositories`, so nobody believes a narrowing is in force.

### API-2. An idempotency key is shared by the whole tenant (Low, confirmed)

- **Evidence.** `migrations/2026-10-27-000400_jobs_and_requests/up.sql:39` has `UNIQUE (tenant_id, idempotency_key)`. `jobs::submit` (`apps/api/src/jobs.rs:172-181`) compares the repository and the text hash on a repeat and never the requester.
- **Shown by.** `defects::api_2_an_idempotency_key_of_one_caller_does_not_find_the_job_of_another`. Two requesters of one tenant sent the same key and text; the second got `200`, `created: false`, and the first user's job id and correlation id. That job's requester stays the first user.
- **Impact.** The second user believes the job is theirs. It runs under the first user's authority and autonomy. Keys are random UUIDs by default (the CLI), so this needs a chosen or predictable key. Different content under a taken key is `409`, which lets one user block another's key, and the pair `200` or `409` tells a caller who knows a key whether a guess of the first caller's text is exact (an equality oracle on another person's request).
- **Smallest fix.** Store `principal id + ":" + key` as the key, and compare the requester on a repeat. No migration is needed. Decisions are already safe: the second approver with the same key and body gets `409` because the actor is part of the compared content (seen in a scratch run).

### API-3. The API login can write what it should not (Medium, confirmed)

- **Evidence.** `migrations/2026-10-27-000900_application_privileges/up.sql:33-71` grants `factory_app` INSERT on 17 tables, including `api_tokens` (line 37), `principals` (33), `ledger_entries` and `audit_events` (63), `outbox` (67) and `approvals` (71). The API login is a member of `factory_app`. The API writes only `jobs`, `original_requests`, `audit_events` and `webhook_deliveries`. ADR 0012 says the tenant setting can be named by any session, so a session that names a tenant by hand is that tenant.
- **Shown by.** `defects::api_3a_the_api_login_holds_only_the_insert_privileges_the_api_uses` lists the 13 tables. `defects::api_3b_the_api_login_cannot_mint_a_token` is the end-to-end proof: a raw connection with the API login's credentials set tenant B, inserted a token for B's approver, and `GET /v1/jobs` with it answered `200`.
- **Impact.** Anyone who gets the API login's credentials or an SQL primitive in the API process can impersonate any principal of any tenant (including approvers), and can write approvals, ledger rows and outbox events directly. The README's claim that the API "cannot do what the engine login does" is true of the claim loop and false of the evidence tables. I did not try to get a forged ledger row past the hash-chain triggers; the privilege is enough to be a finding.
- **Smallest fix.** A fourth group role for the API (`factory_api_app`) with INSERT on the four tables above, SELECT on what the handlers read, and nothing else. Keep `factory_resolver` for the two lookups. Add the privilege list to `tests/database_logins.rs`. Token issue and revocation then belong to an operator role.

### API-4. Nothing recognises an API token as a secret (Medium, confirmed)

- **Evidence.** `apps/api/src/tokens.rs:22` and `apps/api/README.md:65` say the `sfat_` prefix makes a token recognisable to a secret scanner. The job token has a rule in `policies/security.yaml:950` and `.gitleaks.toml:178`; the API token has none in either.
- **Shown by.** `defects::api_4a_the_redactor_recognises_an_api_token`: the real policy redactor reports no secret in a bare token, in a log line, in JSON, or after "Bearer". `defects::api_4b_a_job_request_that_contains_an_api_token_is_refused`: `POST /v1/jobs` with a token in `text` answers `201` and the token is stored in `original_requests`; `jobs::submit` (`apps/api/src/jobs.rs:139`) only refuses what the redactor knows. Gitleaks 8.30.1 with `.gitleaks.toml` found nothing in a prose sample and a JSON sample containing a token built at run time. It found the third sample only because that line was a `curl -H 'Authorization: Bearer …'` command.
- **Impact.** A token that lands in an issue, a job request, a log line, a pull request body or a prompt passes every filter. A token approves jobs.
- **Smallest fix.** Add `api_token` (`\bsfat_[A-Za-z0-9_-]{43}\b`, block) to `policies/security.yaml` and to `.gitleaks.toml`, next to `factory_job_token`, with the same test.

### API-5. URL credentials the policy pattern misses (Low, confirmed; three are a regression)

- **Evidence.** `policies/security.yaml:949`, changed in `8215375`. `crates/composition/src/redaction.rs:135` runs the redactor with `FlagHandling::ReportOnly`, so only `block` patterns change text.
- **Shown by.** `defects::api_5_url_credentials_the_policy_pattern_misses` runs 11 shapes through the real policy and through the pattern as it was before `8215375`:
  - **Regression (caught before, missed now):** a double quote, a single quote, or a leading quote inside the password. The commit added quotes to the excluded classes so that a second URL on a JSON line is not swallowed; a password that contains a quote now never matches.
  - **Never caught:** a `/` inside or at the start of the password (base64 passwords have them); no user name (`redis://:pw@host`); a token as the user name with no password (`https://TOKEN@github.com/…`); an upper-case or capitalised scheme (`HTTPS://`, `Postgres://`); slashes escaped for JSON (`https:\/\/…`); the whole URL percent-encoded.
- **What a 70-line table also showed (not committed as a test).** `password=…`, `DB_PASSWORD=…`, `"password":"…"`, `Cookie: session=…`, `?access_token=…` and `Bearer <x>` in prose are not redacted. That is the policy as written (`generic_assignment` and the entropy rule are flag-only), not a bug in the code. The JSON-key form is not matched even by the flag pattern.
- **What did redact.** A plain password; `@`, `:`, `#`, `?`, `;`, `)`, `<`, `,`, a backslash or a percent escape inside the password; IPv6 hosts; IPv4 with a port; a host list; the URL inside a sentence, logfmt with either quote, parentheses, angle brackets, a markdown link, a query value, a Rust `Debug` dump, several lines; two URLs in one JSON line (the OBS-1 case). The registry of exact values (the database URL, the webhook secrets) is the first line of defence and was not in scope.
- **Impact.** The pattern is the second line, for secrets the registry has never seen: a clone URL printed by a tool, a connection string pasted into an issue. The misses are the common shapes of real connection strings.
- **Smallest fix.** Make the scheme case-insensitive; allow an empty user; allow the password class to contain `/` and quotes but stop at whitespace and at `@` followed by a host; match `\/\/` and `%3A%2F%2F`; add a second pattern for `scheme://TOKEN@`. Add every shape above to the pattern's own tests. The pattern needs a property test (a generated URL with a marker password must never survive redaction) so the next change cannot trade one miss for another.

### API-6. One source can hold every connection slot (Medium, confirmed)

- **Evidence.** `apps/api/src/server.rs:52-66`: one semaphore for the whole server; a connection over the limit is closed unread. The rate limiter counts requests (`apps/api/src/routes.rs:260-269`), and a silent connection never becomes one. A silent connection is closed only at the header timeout, 10 s by default (shown by `held_silent_trickling_and_slow_clients_are_cut_off`), so an attacker needs about 26 new connections per second to hold 256 slots for ever.
- **Shown by.** `defects::api_6_one_peer_cannot_take_every_connection_slot`. A dual-stack listener with 16 slots; the attacker is `127.0.0.1`, the victim is `::1` (two different sources). With the attacker holding 16 silent connections the victim got no answer at all.
- **Impact.** One unauthenticated host takes the API, and the webhook, down. Behind a proxy every connection is the proxy's, so an API-side cap would count the proxy as one peer; the cap has to exist at the proxy too (D-3).
- **Smallest fix.** A per-peer cap in `serve` (for example 16 connections per address, per /64 for IPv6) and a shorter timeout before the first byte (2 s). Keep the global cap.

### API-7. Forged deliveries spend the audit budget of a real one (Low, confirmed)

- **Evidence.** `apps/api/src/boot.rs:48` (60 events a minute) and `apps/api/src/limits.rs:110-158`: one budget for every kind of event and every source. A rejected delivery (`webhook.rs:114-119`) and an unbound one (`webhook.rs:144-148`) draw from it.
- **Shown by.** `defects::api_7_forged_deliveries_do_not_use_up_the_audit_of_a_real_one`: 70 forged deliveries give exactly 60 `webhook.rejected` rows; a correctly signed delivery for an unregistered installation then leaves no `webhook.unbound` row.
- **Impact.** NT-AUTHZ-08 says an unknown binding is "dropped, audited, acknowledged". An attacker with no credentials can make the audit half of that false, and can hide a real forgery attempt among 60 noise rows a minute.
- **Smallest fix.** Separate budgets per action; when events are dropped, write one summary row with the count (the task already counts them) instead of a log line only.

### API-8. Refused decisions are an unbounded audit write (Low, confirmed)

- **Evidence.** `apps/api/src/decisions.rs:203-216, 230-251`: a refused caller gets a `decision.denied` row with a fresh id each time, and the idempotency key does not de-duplicate it.
- **Shown by.** `defects::api_8_refused_decisions_of_one_principal_are_bounded`: 60 requests from an unlisted principal wrote 60 rows. The limit is the per-address rate (600 a minute).
- **Impact.** Any holder of a token, listed or not, can grow the tenant's hash-chained audit log at about 36,000 rows an hour, and the chain serialises writers.
- **Smallest fix.** Count refusals per principal and job per minute and write one row with a counter after the first few.

### API-9. The rate limit is per IPv6 address (Low, confirmed at unit level)

- **Evidence.** `apps/api/src/limits.rs:57-74` keys on `IpAddr`; the map is pruned only when it exceeds 50,000 entries and only of expired windows.
- **Shown by.** `defects::api_9_the_rate_limit_holds_for_a_client_with_a_whole_ipv6_prefix`: 2,000 requests from 2,000 addresses of one /64 are all inside a limit of 600 a minute. A `::ffff:a.b.c.d` peer is also a different key from `a.b.c.d` on a dual-stack listener.
- **Impact.** Only if the API is reachable over IPv6. Then the per-source limit, which is the only protection of the unauthenticated `resolve_token` lookup and `/readyz`, does not apply to a client with a /64, and the map grows by one entry per address.
- **Smallest fix.** Mask IPv6 to /64, unmap v4-mapped addresses, and cap the map.

### API-10. The CLI prints control characters from the server (Low, confirmed)

- **Evidence.** `apps/cli/src/render.rs` prints `job_id`, `status`, `kind`, `event`, `reason`, `action` and, in `refusal`, `field`, exactly as received.
- **Shown by.** `cli::api_10_the_cli_does_not_print_terminal_escapes_sent_by_the_server`: a fake server on loopback answered `status` with clear-screen, title-change and colour sequences; all five escape bytes reached standard output.
- **Impact.** Today every value the real API sends is typed on its side, so a tenant cannot reach a terminal this way. A wrong, replaced or compromised server can. This is the terminal-escape item of the brief, kept at Low for that reason.
- **Smallest fix.** One function in `render` that replaces control characters, used by `text` and `refusal`.

### API-11. Caller mistakes answered as service faults (Low, confirmed)

- **Evidence.** `apps/api/src/routes.rs:190-199` takes `X-Correlation-Id` from the client and `jobs::submit` gives it to the job; `jobs` is unique on `(tenant_id, correlation_id)`. `list_query` (`apps/api/src/jobs.rs:273-303`) checks only the characters of `after`; `parse_cursor` (`crates/storage/src/pg/jobs.rs:276`) fails in the store. `From<StoreError> for ApiError` (`apps/api/src/answers.rs:109-121`) turns both into `503 unavailable` and a `warn!`.
- **Shown by.** `defects::api_11_a_repeated_correlation_id_is_the_callers_error_not_the_services`: both give `503`.
- **Impact.** A token holder can raise the 5xx rate and the warning rate at will. Behind a proxy that ejects a host after consecutive 5xx, that takes the host out.
- **Smallest fix.** Parse the cursor in the API and answer `400 after`; map the correlation-id clash to `409`, or stop taking the correlation id from the client for a job.

## 4. What I tried that held

Each line says what I tried; the test that re-runs it is named in brackets. "Scratch" means I saw it in an exploration run whose code I did not keep.

**Webhook.**
- Signature on the raw bytes: a byte-order mark, UTF-16, a trailing NUL, a duplicate key, a duplicate key spelled with an escape (`action`), a duplicate key in a nested object, each with a valid signature: `202`, nothing recorded, no job [`held_webhook_valid_signature_hostile_encodings_are_ignored`]. The same body in two chunks verifies and records once [same test].
- A `Content-Encoding: gzip` claim changes nothing: there is no decompression, so there is nothing to expand [same test]. Body size is capped at 1 MiB while reading, for a declared and an undeclared length; a stalled body is `408` after the body deadline [`held_silent_trickling_and_slow_clients_are_cut_off`, and `tests/webhook.rs`].
- Constant-time comparison: the only secret comparison in the request path is `ct_eq` over every secret in the rotation window (`crates/github/src/webhook.rs`, `matches`). Tokens are never compared by the application: equality is the unique index on the SHA-256, over a value the caller cannot steer. I listed every `==`, `!=`, `.eq`, `eq_ignore_ascii_case`, `starts_with` and `contains` in `apps/api/src`, `crates/github/src/webhook.rs` and `crates/composition/src/webhook.rs` with grep (about 40 sites). The only secret comparison is the `ct_eq` above. The rest compare labels, enumerations, lengths, ids and one non-secret hash (the equality oracle of API-2). I did not measure timing.
- Tenant selection: the installation and the repository are resolved as a pair; a payload that mixes tenant B's installation with tenant A's repository, or the reverse, is unbound and audited; a sender who is tenant B's requester is not a principal of tenant A; a bot sender, a wrong-case label and a label with a trailing newline make no job [`held_webhook_cannot_select_another_tenant_or_borrow_its_people`].
- Replay: the same delivery id with another body, the same body under a new id, and 30 concurrent copies give one delivery and one job [`held_webhook_replays_make_one_delivery`]. Unknown events (`ping`, an upper-case `Issues`), an id of 7 or 129 characters, an id with a space or a non-ASCII character (scratch).
- Header handling: every header value used is matched against a fixed list or a fixed shape; `X-Correlation-Id` is replaced when it is not a UUID, never echoed [`held_a_hostile_correlation_id_is_replaced`]. Nothing from the payload becomes a path, a branch name or a prompt in this code: the job has no text.
- Secret missing: the production profile refuses to start without a webhook secret (`apps/api/src/config.rs`, `validate`); outside it, a missing verifier makes the route answer as an unknown route.

**Tokens.**
- Revoked, expired and wrong-audience tokens give the same `401` bytes, and a revocation takes effect on the very next request (no cache) [`held_tokens_are_revoked_at_once_and_never_logged`].
- A token placed in the path, the query, `X-Api-Key`, `X-Correlation-Id`, a doubled `Authorization` header, the JSON body or the idempotency key is never echoed in a body or header, and appears in no captured log event or span [same test]. A token in the query string alone is `401` [`held_no_cors_no_query_token_no_override`].
- Generation: 32 random bytes, 43 characters, prefix `sfat_`; the API does not generate tokens (`tokens::format_token` is for an operator). SHA-256 without salt or pepper is right for a 256-bit random value: there is nothing to guess or precompute, and a salt would only force a lookup by principal. The lookup is a unique-index equality on a hash the caller cannot choose, so there is no useful timing signal. A grep of the workspace for `Debug` on types that hold secrets found hand-written redacting implementations for `WebhookSecret`, `SecretText`, `DatabaseUrl` and `ApiClient`, and none derived on `TokenHash`.

**Authorization.**
- Role by route by tenant, including objects that do not exist: five principals, eleven requests each [`held_authorization_matrix`]. An unlisted principal gets `403` everywhere; a listed principal of another tenant gets `404` for the first tenant's job and timeline; an approver gets `404` for another tenant's job, and an operator gets `404` for a missing job it may act on; a decision with another job's or another tenant's stage run is `404`.
- Decisions follow the numeric id: renaming a login to an approver's changes nothing (`tests/http_api.rs`); an allowlist edit takes effect on the next request (I saw an expiry and a narrowing take effect between two requests in a scratch run); unknown fields, a repeated key and a `tenant_id` in a decision body are `400` [`held_authorization_matrix`].
- A decision's `head`, `evidence` and `target` are parsed into typed values and the stored subject is built from the typed values, so a `head` with a smuggled `evidence=` is `400` and one with surrounding spaces is stored trimmed (scratch).

**Tenancy and the database.**
- The API login cannot become the engine, disable row-level security, bypass it, create a policy, alter or delete an audit row, truncate, drop, create tables or roles, read files, run programs, or execute any non-trigger function other than the lookups and the chain verifiers [`held_the_service_database_login_is_neither_the_engine_nor_a_bypass`, with a control that a row for the named tenant works and one for another tenant is refused inside the same transaction].
- Pool reuse: with a pool of one connection, 300 rounds of a transaction for tenant A dropped at a random microsecond followed by a committed transaction for tenant B. All 300 of B's writes were durable and no row landed under the wrong tenant [`held_a_cancelled_transaction_does_not_leak_into_the_next_borrower`]. The design explains why: the setting is made with `set_config(..., true)` as the first statement of every transaction (`crates/storage/src/pg/tx.rs:88`), the pool runs `RESET factory.tenant_id` on every checkout (`pool.rs:25`), and the calls outside a transaction (`resolve_token`, `resolve_installation`, the schema probe behind `/readyz`) read no tenant data. I tried to produce the classic leak and could not.
- Dynamic SQL: values are bound. Every `format!` that builds a statement in `crates/storage/src/pg` interpolates only a `const` column list (`COLUMNS`, `JOB_COLUMNS`, `REQUEST_COLUMNS`, `STAGE_RUN_COLUMNS`; checked with grep, no lower-case name is interpolated into SQL). The only value built into text is the pagination cursor, which is parsed back and bound.

**HTTP hardening.**
- Two different `Content-Length` values, `Transfer-Encoding: xchunked`, `chunked, identity`, a space before the colon of `Transfer-Encoding` or `Content-Length`, a plus sign, hex or an overflowing length, a NUL in a header, obsolete line folding, a chunk-size overflow: all `400` [`held_hostile_framing_is_refused_and_nothing_is_smuggled`]. `Content-Length` together with `Transfer-Encoding` gives one response and closes the connection, so a request hidden behind the body is never run [same test]. 200 headers give `431`. The HTTP/2 preface is not served; the feature flags enable `http1` only (`apps/api/Cargo.toml`).
- No CORS: `OPTIONS` is `405`, no `Access-Control-*`, no cookie, no `Server` header [`held_no_cors_no_query_token_no_override`]. `X-Forwarded-For` and a method-override header are ignored (also `tests/http_api.rs`). Absolute-form targets are routed by path only (scratch), which is harmless here because the `Host` header is never used.
- A panic in a handler ends that connection only: six panics with a limit of two connections, then `/healthz` is `200` [`held_a_panic_in_a_handler_costs_one_connection`]. The default panic hook writes to standard error, outside the redactor (D-8).
- Silent, trickling and idle keep-alive connections are closed at the header timeout; a stalled webhook body is `408` [`held_silent_trickling_and_slow_clients_are_cut_off`]. Graceful shutdown has its own test in `tests/http_api.rs`.
- Readiness and liveness: `/healthz` and `/readyz` answer check names and a pass or fail, with no version, path, schema number or error text. `/readyz` makes one database round trip per call without authentication (H-5).

**The CLI.** The token comes only from a file, not an argument or the environment. The file must be a regular file, not a link, with no group or other permission. A link is refused before anything is sent. A redirect is not followed and the second host receives no connection [`cli::held_cli_does_not_follow_a_redirect_and_refuses_a_linked_token_file`]. Plain HTTP is refused except to a literal loopback address; TLS verification is the `ureq` default with no override (read, not exercised).

## 5. Hypotheses and observations without a test

| ID | Severity | Observation | Why no test |
|---|---|---|---|
| H-1 | Low | `SecretFile::read` (`crates/composition/src/config.rs:99-119`) checks `symlink_metadata` and then opens the path again: a race between the check and the read, no owner check, no check of the parent directory. Someone who can write the directory can swap the file. | Needs a second writer in the directory; if they have it they have the secret already. Fix: open once with `O_NOFOLLOW`, then `fstat` the descriptor and check mode and owner. |
| H-2 | Info | The dedupe policy says 30 days of retention, and nothing prunes `webhook_deliveries`. When a pruning job is written, a captured delivery becomes replayable after it runs: GitHub signs no timestamp. | The job does not exist. See R-12. |
| H-3 | Info | hyper accepts a bare line feed as a line end. A front end that does not could be desynchronised from the API. | Needs a proxy. D-2. |
| H-4 | Info | `MAX_HEAD_BYTES` is documented as a 32 KiB limit answered with `431`. A 40 KiB header is served; 64 KiB gets `431`. The limit is a read-buffer size, not a head size. | Correct the comment and the README, or enforce it. |
| H-5 | Low | `/readyz` makes a pool checkout and a query per call, unauthenticated, 600 a minute per address (and unlimited per /64, API-9). | Load. Cache the result for a second. |
| H-6 | Info | A delivery with a valid signature and `sender.id` of 0 or above `i64::MAX` is `503` (a check constraint fails). Only GitHub can sign one. | Not reachable by an attacker. |
| H-7 | Info | The webhook `401` carries `WWW-Authenticate: Bearer` (`apps/api/src/answers.rs:187`). It advertises a scheme the route does not use. | No impact. |
| H-8 | Info | `apps/cli/src/commands.rs:87-94`: if the random source fails the CLI uses the fixed idempotency key `no-random-source`, so every command after the first is a conflict or, with API-2, a collision. | Needs a failing random source. Make it an error. |

Also noted, not findings: the API writes no `last_used_at` and does not audit a successful authentication, so a stolen token leaves no trace until it is used for a write; every listed designation sees every job and requester id of its tenant (the README says "any designation"); a session that names a tenant by hand is that tenant (ADR 0012); `listen` is not restricted in the production profile, and the server has no TLS (D-1); the allowlist is read and parsed with blocking file calls on a worker thread for every authenticated request.

## 6. What I could not verify, and why

- **A real GitHub delivery.** No network and no GitHub. The payload shape is the documented one, as the adapter's own tests assume. `issue.pull_request` presence is still unverified, as the adapter says.
- **A TLS terminator or any deployment.** None exists. Everything about the proxy is a requirement (section 9), not a result. The CLI's TLS path was not run against a TLS server.
- **Timing.** I read the comparison code and relied on `subtle`; I did not measure. The unknown-object versus foreign-object timing parity rests on the existing 100 ms test.
- **Load.** No test above the rate limits and no long run. API-6 and API-9 are shown at small scale.
- **The hyper parser.** About 50 hand-written hostile requests, not a fuzzer.
- **The redactor.** About 70 hand-chosen lines, plus a product of 301,644 generated lines (9 schemes, 7 user names, 19 password forms, 6 hosts, 3 paths, 14 contexts) whose per-factor miss rates were too tangled to quote, because several factors miss on their own. The 11 shapes in API-5 are the clean result. This was a structured sweep, not a random fuzz; absence of a miss elsewhere is not proof.
- **Ledger and approval forgery under API-3.** I showed the privilege and the token. I did not try to build a ledger row that passes the chain triggers.
- **The worker hook.** It does not exist. Section 8 is a list of requirements.
- **Docker and the container image.** Not used, not reviewed.

## 7. How this review was run

I read the API, the webhook verifier, the store operations behind tokens, deliveries and idempotency, the lookup functions and privilege migrations, the CLI client, and the redaction module's description. I then wrote hostile input against the real server and a real PostgreSQL, as raw bytes on a socket where the question was framing. Anything I report as confirmed has a test that fails today. Anything I report as held has a test that passes today. The numbers in section 4 come from those runs on 2026-10-28; the existing suite of the package also passed in the same environment.

`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo xtask check-architecture` and the `secret-scan` step of `scripts/ci.sh` pass with the new target present. No test writes a secret-shaped literal: tokens, passwords and the sample credentials are built at run time.

## 8. Requirements on the worker hook (Scope B)

The hook reads `decision.requested` audit rows and applies them, and admits `RECEIVED` jobs. I have not seen it. These are the requirements it has to meet, each one testable.

**The record is untrusted input.**
- **R-1. The audit log is not an authenticated command channel.** Any process with the `factory_app` role can insert an `audit_events` row with any action and any actor, in any tenant it names (API-3). Until API-3 is closed and the record is bound to the API (an HMAC with a key held by the API and the worker and by no database role, or a table only the API's narrowed role can write), the hook must treat the row as a request to be proven, not as proof that a person asked.
- **R-2. Parse strictly, and only the structured fields.** Accept a row only if `action` is exactly `decision.requested`, `actor_type` is `human`, `actor_id` is a principal UUID of the row's tenant, the subject matches `verb=<verb> job=<uuid> run=<uuid|none> head=<sha|none> evidence=<digest|none> target=<kind|none>` byte for byte (re-render and compare), the `job_id` and `stage_run_id` columns equal the subject's values, and `tenant_id` is the row's column, never text. Never parse `reason`: it is free text, may hold line breaks, and starts with `requested: `.
- **R-3. Tenant binding.** The system scope may list candidate rows across tenants; applying one must open a tenant transaction for the row's `tenant_id` (`TenantScope`), and the job and stage run must be found inside it. A row whose job is not in its own tenant is rejected, not skipped silently.

**Authority is checked again, at apply time.**
- **R-4. Re-read the authority now.** Resolve `actor_id` to the principal, require a human principal that is not disabled, take its numeric GitHub id, and check the designation the action table of the protected `policies/approval.yaml` names for the verb (`approver` for approve, reject and rework; `operator` for pause, resume and cancel) against the allowlist as it is at that moment, with expiry. The record's `policy_hash` and the allowlist read at accept time prove nothing about now. Apply the repository narrowing of the entry (API-1) against the job's repository.
- **R-5. Separation of duties.** Compare the actor's numeric id with the job's requester (and the pull request author when known). Refuse where `approval.yaml` says the approver must differ: risk tier high or critical, protected path, sensitive file, new dependency, and always for `security_approver`. The API does not make this check (README, "The decision pre-check is by designation only"), so the hook is the only place it happens.
- **R-6. Cancel.** Only an `operator` (per the table) may cancel, pause or resume. The job's own requester may not cancel unless the policy is changed; if that is a product gap, change the policy, not the hook. Re-check that the job is in a state the verb applies to (a cancel of a terminal job is a no-op with an audit row, not an error loop).
- **R-7. Bind approvals to current facts.** An approval is applied only if its `head`, `evidence` digest and stage run equal the current ones, and it is inside the 72-hour window of `approval_binding`. Use `ApprovalService::judge` for this; do not copy its rules. Record the allowlist version hash and the policy hash in force now in the approval row.

**Exactly once, and what happens around it.**
- **R-8. One request, one effect.** Use the request's `event_id` as the causation id of the engine command so that a replay is a no-op in the engine itself, and write the marker (`decision.applied` or `decision.rejected`, naming the request's `event_id`) in the same transaction as the transition. A marker written after the transition, in another transaction, is not enough.
- **R-9. Crash between apply and marker.** On restart the hook finds the request without a marker and applies it again. This is safe only if R-8 holds. Test it with a fault injected between the two steps, and with two hooks racing for the same row (claim with a lease or `FOR NO KEY UPDATE SKIP LOCKED`, and the marker's unique key as the last guard).
- **R-10. Replay and duplicates.** The API makes one row per tenant, job and key, so a retried request is one row; the hook must still treat two rows with the same verb, job and run as two requests, and apply the second as a no-op or reject it as stale. Never apply by position in a list that a new row can reorder: order by the audit `sequence` of the tenant.
- **R-11. Stale decisions.** The job may have moved on: a terminal state, a different current stage run, a new head, new evidence, an invalidated approval, a pause. A stale decision is rejected with a reason code and an audit row, never applied "as far as possible". The decision's age is limited by the 72-hour window; older rows are rejected as expired.
- **R-12. Bounded work and poison rows.** Process a bounded number of rows per tick. A row that cannot be parsed or applied must get a `decision.rejected` marker and stop being a candidate, so one bad row cannot block the queue. Do not delete or edit audit rows; the marker is a new row.
- **R-13. Audit of every outcome.** Applied, rejected, stale, expired and unauthorised-at-apply are each an audit event with the request's `event_id`, a fixed reason code, the numeric id and the allowlist version, and no text from the request. The audit volume of rejections is bounded (API-8 shows what happens when it is not). Rejections must not be visible to the requester as detail: a caller who lost the designation learns "not applied" and nothing more.

**Admission of `RECEIVED` jobs (same hook).**
- **R-14. Admit by current facts.** Re-check that the requester is a human principal, not disabled, holding `requester` for this repository (API-1), that the repository is enabled, and the quota. Do not trust `autonomy_level` stored on the job beyond the repository's ceiling now.
- **R-15. A job from a webhook has no text.** Intake must fetch the live issue, take the repository from the registered row (not from `full_name` in the payload, which can be stale after a rename), check that the label is still on the issue and that the issue has not been edited since the label, record it as revision 1 with its hash, and treat the author's text as untrusted: the person who labelled is not necessarily the person who wrote the issue.
- **R-16. Retention must not reopen replay.** If `webhook_deliveries` is pruned at 30 days (H-2), a captured delivery is accepted again afterwards. Either keep the delivery id rows for longer than any delivery can be replayed, or make admission depend on the live label so a replay creates nothing.
- **R-17. Logs and metrics.** No request text, reason or token in a log line. Count outcomes by reason code. The hook's panics go through the same redacting pipeline (D-8).

## 9. Requirements on the deployment

- **D-1. TLS in front, loopback or private behind.** The API speaks plain HTTP/1.1 and carries bearer tokens. It must be reachable only through a TLS terminator. The production profile does not restrict `listen`; the container example binds `0.0.0.0:8080`, which is correct inside a private network and wrong anywhere else. Add a setting that states which of the two this is, and refuse a non-loopback `listen` in production without it.
- **D-2. The proxy must normalise HTTP.** Reject bare line feeds, obsolete folding, duplicate `Content-Length`, and `Content-Length` with `Transfer-Encoding`; speak HTTP/1.1 to the API (it has no HTTP/2); strip hop-by-hop headers it does not mean to forward.
- **D-3. Limits at the proxy that the API cannot enforce.** A per-client connection cap and a pre-first-byte timeout (API-6); a request rate per client address, since the API sees only the proxy's address and ignores `X-Forwarded-For` by design; a per-/64 key for IPv6 (API-9); a header size cap (H-4); a 1 MiB body cap on the webhook path.
- **D-4. The webhook path.** Allow only GitHub's published hook address ranges to reach `/v1/webhooks/github`; everything else gets `404` from the proxy. Everyone else needs a token, and tokens are for people and the CLI.
- **D-5. Keep `/readyz` and `/openapi.json` internal** unless there is a reason not to; cache `/readyz` for a second (H-5).
- **D-6. Secret files.** Mode `0400` or `0600`, owned by the service user, in a directory only that user can write, delivered on a memory filesystem or by a secret manager; never in the environment or the command line. The webhook secret is 32 random bytes or more (the verifier already refuses less). Rotation is two files for an overlap, then one; test the old one is refused afterwards (`both_secrets_are_accepted_during_a_rotation…` does).
- **D-7. The database login.** The narrowed API role of API-3 before production; its own password; connections from the API host only; SCRAM; no superuser anywhere in the API's reach. Token issue and revocation as an operator procedure: 32 bytes from the operating system, shown once, expiry of 90 days or less, one token per person and purpose, a revocation drill, and `last_used_at` updated so a stolen token can be seen.
- **D-8. Process.** Run as a non-root user on a read-only filesystem. Send standard error through the same redacting pipeline as the logs: the default panic hook and the start-up `eprintln!` calls bypass it. Do not set `panic = "abort"`: a handler panic now costs one connection and would cost the process.
- **D-9. The allowlist file.** Mounted read-only for the API; replaced atomically (write a temporary file and rename it). A half-written file makes every authenticated request `503`, which is the correct fail-closed behaviour and a bad surprise during an edit.
- **D-10. Alerting.** Alert on `webhook.rejected` above a small baseline, on any `decision.denied` from a principal that was never listed, on 5xx rates (and fix API-11 first so callers cannot raise them), and on the drop counter of the platform audit writer (API-7).
- **D-11. Order of work.** Close API-3, API-1 and API-4, then API-6 or its proxy compensation, before issuing tokens to anyone but the builders. The worker hook is built against R-1 to R-17; its authority check (R-4) is the control that makes API-3 survivable.

## 10. Status after fixes

- Written by: the software engineer, on branch `worktree-agent-a9e16db405c6464fa`, from `d9d478f` (the merge of this review). The text above is the reviewer's and is unchanged. **This section is the engineer's account, not a re-review.** Every "fixed" below means "the reviewer's test, un-ignored, passes, with the other tests named"; whether the fix is right is for the re-review to say.
- The 13 `held_` probes still pass when run with `--ignored` (13 passed, 0 failed, run last). Two edits to the reviewer's test code were needed. Before anything could run, `held.rs` implemented the `Authority` trait without the `repository` argument that `admission` gained after `8215375`, so the whole target did not compile (`PanickingAuthority`, one parameter added). And `held_webhook_replays_make_one_delivery` sends thirty copies at once from one address, which is now more than one source may hold by default (API-6); the probe sets the share to the table, as the setting is for.

### 10.1 The eleven findings

| ID | Status | What was done | Tests (all run without `--ignored`, except where marked) |
|---|---|---|---|
| API-1 | Fixed | `AllowlistEntry::covers_repository` in the domain (whole names, any case, an empty list covers nothing); the policy engine's own check uses it; `FileAllowlist::{designations_on, covers}`; asked at engine admission, `POST /v1/jobs`, a decision (a narrowed approver or operator is refused like one without the designation: audited, no reason, no job named), a factory label (recorded, no job), and in the worker hook at apply time. The roles stay the tenant-wide answer, so a narrowed person can still read. | `defects::api_1_…`; `webhook::a_label_from_a_requester_narrowed_to_another_repository_makes_no_job`; `authority_admission::a_requester_narrowed_to_one_repository_is_not_admitted_on_another`; `claim_work::an_operator_narrowed_to_another_repository_since_the_request_is_refused_at_apply_time`, `…an_approver_narrowed_to_another_repository_never_reaches_the_service`; domain `an_entry_covers_the_repositories_it_lists_and_no_others` |
| API-2 | Fixed | A job is stored under the principal and the SHA-256 of the caller's key (32 + 1 + 64 characters, inside the store's 128); a repeat must also be the same requester. The id of a decision is derived from the caller as well. No migration. | `api_2_…`, `api_2b_a_key_is_found_again_by_its_own_caller_and_by_nobody_else`, `api_2c_two_approvers_with_the_same_key_write_two_records`, unit `the_same_tenant_caller_job_and_key_…` |
| API-3 | Fixed, with a deployment step and a residual (R-1) | Migration `2026-10-28-002000_api_login_narrow_group` adds `factory_api_app`: SELECT on nine tables and the three reference tables, INSERT on `jobs`, `original_requests`, `audit_events`, `webhook_deliveries`, no UPDATE, no DELETE, no column grant, a place in the eight tenant policies it needs (not in the `api_tokens`, `approvals` or `ledger_entries` policy, so a regained grant on those would still be refused by row-level security). The API login is a member of `factory_api_app` and `factory_resolver` and **not** of `factory_app`; the role query of the storage crate has a column for the group and refuses to start on any other shape. An existing API login must be moved (`scripts/lib/ops.sh` does it; `docs/database/tenancy.md` says how). Nothing was revoked from `PUBLIC`: it held nothing, and the suite now says so. | New database suite `api_privileges` (44 checks, exact list both ways, the token mint as a real session); `rls` suite (membership rules, policy list, the API session cannot read or insert a token); `defects::api_3a`, `api_3b`; storage `refuses_a_role_that_bypasses_rls` |
| API-4 | Fixed | `api_token` (`\bsfat_[A-Za-z0-9_-]{43}`, block) in `policies/security.yaml` and `.gitleaks.toml`, no trailing `\b` (a token ending in a hyphen would escape it); domain fixture regenerated. A scan of tokens built at run time (prose, JSON, ending in a hyphen) found all three. | `defects::api_4a`, `api_4b`; domain `patterns_the_samples_cover_every_pattern…`; contracts `the_domain_fixtures_equal_the_loaded_policy_files` |
| API-5 | Fixed, one stated limit | Pattern rebuilt from named pieces (scheme in any case, `://` or `:\/\/`, userinfo in three forms where the first that fits wins, host characters only, a whole URL percent-encoded as a fourth alternative); see the commit message for the grammar. A seeded generator of URLs in JSON, key=value and plain lines (4,000 lines in the suite; the final pattern also passed 150,000 lines under another seed) checks that no password survives, whole or in a piece of six characters, and that nothing outside the URL changed. The OBS-1 test is unchanged and passes. **The limit:** in plain text, a bare double quote followed by a character that could end a string or a sentence, after an at sign inside the same password, cannot be told from the end of a string. In JSON and key=value lines the quote is escaped and every combination held. The pattern also redacts a user name of 12 characters or more that stands alone (`scheme://user@host`), and a path that holds an at sign after a port, as over-redaction. | `defects::api_5`; domain `urls_with_a_password_are_redacted_in_every_shape_the_review_found`, `a_user_name_alone_is_not_a_secret_and_a_url_without_userinfo_is_left_alone`, `urls_stuck_together_are_each_redacted_and_the_text_between_them_is_kept`, `generated_urls_in_generated_lines_lose_every_password_and_nothing_else`, `the_same_url_twice_on_one_json_line_…`; observability `a_url_with_a_password_twice_on_one_log_line_is_redacted` |
| API-6 | Fixed (a pre-first-byte timeout shorter than the header timeout was not added) | `serve` counts open connections per source before reading a byte (`Sources`/`Slot`); the share is `limits.max_connections_per_source` or a sixteenth of `max_connections`, at least 1, validated against the total. Behind a proxy it must be set to the total and the proxy must cap clients (D-3). | `defects::api_6`; unit `a_source_holds_no_more_than_its_share_…`, `the_count_forgets_a_source_that_holds_nothing`, `the_addresses_of_one_ipv6_prefix_…`, config `one_source_may_hold_a_sixteenth_…` |
| API-7 | Fixed | A budget per kind of platform audit event; the events a window leaves out are counted and one `webhook.audit_dropped` row per kind says how many, written at the end of the window even if nothing arrives. | `defects::api_7`; unit `each_kind_of_audit_event_has_its_own_budget_…` |
| API-8 | Fixed | Five `decision.denied` rows per person per minute, then one `decision.denied_suppressed` row, then a count, written as a `decision.denied_summary` row when the next minute opens. The refusal is still `403` with no reason. | `defects::api_8`; unit `a_person_gets_a_few_refusal_rows_then_one_note_then_a_count` |
| API-9 | Fixed | `source_of`: IPv4 as is, IPv4-mapped IPv6 as the IPv4 address, other IPv6 as its /64; the limiter keys on it and has a bound (100,000 live sources, then one shared overflow count). | `defects::api_9`; unit `an_ipv6_source_is_its_64_bit_prefix_…`, `a_full_table_does_not_grow_…` |
| API-10 | Fixed | `printable()` for every field of every answer (controls, and characters that hide or reorder text, become U+FFFD); the two places the CLI writes repeat it on the finished block. | `cli::api_10` (builds the binary, about 90 s the first time); render unit tests |
| API-11 | Fixed | A taken `X-Correlation-Id` is `400` on `x-correlation-id`; a cursor that is not one is `400` on `after`; neither is logged as a store fault. | `defects::api_11` |

### 10.2 The worker hook against R-1 to R-17

The hook is `crates/composition/src/decisions.rs` (`ClaimWork`). "On PostgreSQL" means the real store, the real engine, the real allowlist file and the real policy files; the approval service is the stand-in the older tests name (`RecordingSubmitter`), and the complete run uses the real one.

| Req | Verdict | Evidence |
|---|---|---|
| R-1 | **Not met. Proposal below.** API-3 closes the mint of tokens and approvals by the API login, but the API login still writes `audit_events` for any tenant it names, so a holder of its credentials can write a `decision.requested` row for any person. | R-4 limits a forged row to what that person may do now; every forged row is an audit row of its own. |
| R-2 | **Fixed here.** The hook accepted a subject in any order and spacing, a repeated key, and let the stage run column override the text. Now: human principal, canonical subject byte for byte, job and stage run columns equal to the subject's. | `r2_a_subject_that_is_not_the_canonical_text_is_rejected_and_nothing_moves`, `r2_the_columns_and_the_actor_must_agree_with_the_subject` (both fail with the check removed) |
| R-3 | Met. Every read and write of a pass is in a transaction for the row's tenant; a job that is not in it is `NoJob`. | `r3_a_request_for_a_job_of_another_tenant_is_rejected_and_that_job_does_not_move` |
| R-4 | Met, and extended by API-1: the principal is resolved now, must be human and not disabled, the designation comes from the action table by numeric id with expiry and the repository narrowing, all read at apply time. | `a_person_who_left_the_allowlist_since_the_api_checked_…`, `a_person_who_never_held_the_designation_is_refused`, `r4_a_principal_disabled_since_the_request_is_not_a_current_user`, `r4_an_entry_that_expired_since_the_request_is_refused`, the two narrowing tests above |
| R-5 | Met by delegation, not re-tested at hook level: the approval service's `judge` compares the approver with the stored requester. | `crates/workflow/tests/delivery/judging.rs`, engine scenario `nobody_approves_their_own_request` |
| R-6 | Met. The verb-to-designation table is the policy's; the requester asking for a pause is refused; a pause of an ended job is rejected with a marker. | `a_person_who_never_held_the_designation_is_refused`, `a_request_for_a_job_that_has_ended_is_refused_with_a_plain_reason`, `a_rejection_by_someone_who_is_not_an_approver_never_reaches_the_service` |
| R-7 | Met by delegation: `ApprovalService::submit` judges the binding and the 72 hours and records the allowlist version and the policy hash in the approval row (`service.rs`). Not re-tested here. | `crates/workflow/tests/delivery/judging.rs`; `apps/api/tests/complete_run.rs` runs the real service |
| R-8 | **Met by a different mechanism than written.** The marker is *not* in the transaction of the transition. The effect is made exactly once by the command id (the request's `event_id` is the engine's causation id and the approval id), and a request without a marker is recognised as applied by asking the engine. The review said that is "not enough"; the tests show the property it was after. Putting both in one transaction needs the engine to take a hook for it (`crates/workflow`, not in this brief). | `a_stop_between_the_engine_commit_and_the_marker_neither_applies_twice_nor_loses_it`, `a_stop_after_a_cancel_that_ended_the_job_still_ends_with_an_applied_marker` |
| R-9 | Met. The crash between the two steps is the first test above. Two hooks racing for one row, eight rounds: one effect, one marker, and it says applied. The extra "ask the engine again" in the hook is defence in depth: the test also passes without it, so it is not shown necessary. | `r9_two_hooks_racing_for_one_request_apply_it_once` |
| R-10 | Met. Pending requests are keyed by the tenant's audit sequence; a second pause is rejected with a marker. | `r10_two_requests_for_the_same_pause_are_two_requests_in_order` |
| R-11 | **Fixed here** (age). Terminal job and a stage run that moved were already rejected; a request older than the approval window (`approval_binding.expires_after_hours`) is now rejected as `expired`, after the check for "already applied". | `r11_an_old_request_is_rejected_as_expired_but_an_applied_one_stays_applied` (fails with the check removed) |
| R-12 | **Fixed here.** A record that is not a request used to be ignored forever with no marker, and a pass dealt with every pending request. Now it gets a `decision.rejected` marker naming only its id; a pass deals with at most 50 records and reads at most 20 pages. | `r12_a_pass_deals_with_a_bounded_number_and_the_rest_wait` (fails with the bound removed), `r2_…` |
| R-13 | **Fixed here.** Each marker names the request, a fixed code (`Reason`), the numeric id and the first 16 characters of the allowlist version hash, and nothing from the request; the words for the person are the same whatever failed. | `r13_a_marker_has_a_code_the_numeric_id_and_the_allowlist_version_and_no_request_text` |
| R-14 | **Partly met.** Requester, repository enabled, quota and now the narrowing are read from current facts at admission. **Not met:** the job's stored `autonomy_level` is not clamped to the repository's ceiling as it is now (`crates/workflow/src/engine/admission.rs`; outside this brief). | `a_requester_narrowed_to_one_repository_is_not_admitted_on_another`, `the_facts_about_the_repository_are_read_from_the_repository`, `a_requester_who_left_the_allowlist_is_not_admitted_and_the_job_is_rejected` |
| R-15 | **Partly met.** Fixed here: the repository of a webhook job is the registered row, not the payload's `full_name`. Already there: intake reads the live label and its actor. **Not met:** "the issue has not been edited since the label" (the payload's `updated_at` is not kept; `crates/workflow` intake). | `a_webhook_job_names_the_registered_repository_and_not_the_one_in_the_payload` |
| R-16 | Met by absence, and it must be re-checked the day a pruning job is written. Nothing prunes `webhook_deliveries`, and no application role holds DELETE on it, so a captured delivery stays a duplicate. | database suites `privileges` and `api_privileges` (no DELETE, no TRUNCATE for either group) |
| R-17 | Met for log lines: the hook logs the code of each outcome and nothing from a request. **Not met:** no metric instrument counts outcomes yet; the `code` field of the line `a decision was dealt with` is what a counter would read. | `r17_no_log_line_of_the_hook_holds_the_text_of_a_request` |

**R-1, the smallest proposal.** Sign the request with a key no database role holds. Add a seventh word, `mac=<64 hex>`, to the canonical subject (`DecisionFields` is the one grammar the API writes and the hook reads, so it changes in one place); `mac` is HMAC-SHA256 over the tenant, the event id, the principal and the six other words, keyed by 32 random bytes in a file that only the API user and the worker user can read (D-6), named by one setting in each configuration; the hook verifies in constant time and treats a missing or wrong `mac` as malformed, which already gets a marker. It needs `hmac`, `sha2` and `subtle` as direct dependencies of `factory-composition` (all three are in the lock file through `factory-github`) and a secret provisioned to two processes. That is why it was not done here: the brief ruled out both. Until it exists, record API-3's residual risk with an owner and a date, as the verdict asked.

### 10.3 Deliberate breaks, each shown caught

| Break | Caught by |
|---|---|
| The revoked grants put back (`INSERT` on five tables) | `api_privileges` suite (names the five tables) and `defects::api_3a`. `api_3b` still passed: the group has no place in the `api_tokens` policy, so row-level security refused the insert on its own. |
| Allowlist narrowing ignored (`covers_repository` always true) | six tests: the domain method, admission, the hook for an operator and for an approver, the webhook, `defects::api_1` |
| The `api_token` pattern removed | `api_4a`, `api_4b`, the pattern-coverage test and the domain fixture test |
| The URL pattern put back to the one of `8215375` | the shapes table, the generator, the stuck-together test, `api_5` and the domain fixture test. The OBS-1 test passes with it, as it did before. |
| No per-source connection cap | `api_6` and two unit tests |
| Idempotency key shared between callers | `api_2b`. The reviewer's `api_2` alone still passed, because the repeat now also compares the requester and answers `409`: `409` against `201` is the oracle `api_2b` looks for. |
| The hook applying without the authority re-check | the existing `break_applying_a_decision_without_rechecking_authority_is_caught` (both walls removed; the removed person pauses the job; the check fails) |
| The new guards of the hook removed (canonical subject and columns, age, bound) | the four tests named in R-2, R-11 and R-12 |

### 10.4 What remains, and the commands that were run

Open: R-1 (above); R-8's single transaction; R-14's autonomy ceiling and R-15's "edited since the label" (both in `crates/workflow`); a metric for R-17; the sandbox image audit tool `infra/sandbox-images/tools/fsaudit.py` lists `sfjt_` among its high-signal literals and does not list `sfat_` (`infra/` was out of scope); the gitleaks rule for URLs was left on its older shape because the broader one flags a made-up URL with a long user name in `scripts/lib/ops.sh` and the brief allowed no allowlist entry; D-1 to D-10 are untouched.

Things changed outside the list in the brief, because the fix needed them: `crates/storage/src/pg/readiness.rs` (the role query and the check), `crates/storage/tests/**` and `apps/worker/tests/engine_scenarios_all_on_postgres.rs` (a worker store and an API store joined by a test-only `SplitStore`, because no single login may now do both), `scripts/db-test.sh`, `scripts/lib/ops.sh`, `scripts/db-perf/perf.py`, `docs/database/**` (the group, the suite, the counts), `apps/api/README.md`, `apps/worker/tests/claim_work.rs`. One thing found on the way: a `REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC` in the new migration made the timing-sensitive `lease` suite fail three runs out of three, for a reason that was not chased; it was left out of the migration (PUBLIC holds nothing on sequences, and the suites check that).

The results of the verification commands are in the engineer's final report, not here, because they change with every run.

## 11. Status after the final wiring

Added by the software engineer. A claim for the re-reviewer, not a verdict.

- The decisions endpoint takes two more verbs, `approve-dependency` and `approve-build-code`, with `package`, `version`, an optional `checksum` prefix and a `reason` of 10 to 500 characters. The words go through the one reader of the dependency commands. A request is recorded under its own audit action (`decision.dependency_requested`), so the hook of the six verbs never reads it, and carries the same kind of word as the others (HMAC-SHA256 over the tenant, the person, the event id, the time and the other words) with a **different context line**, so a word made for one kind of request is never the word of the other (AUT-12 holds for both). `http_api::a_decision_on_a_dependency_*` (four tests) show the record and its word, the designations (`approver` for the dependency, a security approver for build code, nobody else), the grammar, retries and conflicts; `openapi_contract` stays green.
- The worker's step for these requests meets the same requirements as the hook of the six verbs, with these differences: it checks the word first, asks the engine whether the command was applied, rejects a request older than the approval window, resolves the person by numeric id, and asks the policy engine for the proof with the allowlist read at that moment. `apps/api/tests/dependency_run.rs` shows an unsigned request rejected with the fixed code `not_signed`.
- A refusal of the new verbs is the same `403` with no reason, audited and rate limited like the others (API-8), and writes no word.
