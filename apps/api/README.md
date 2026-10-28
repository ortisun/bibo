# factory-api

The HTTP API of the factory: a composition root in ring 3 ([ADR 0002](../../docs/adr/0002-workspace-layout-and-dependency-rule.md)).
It receives GitHub webhooks, accepts jobs and decisions from people, and answers status and timeline
queries. It chooses its adapters through the composition library
([`factory-composition`](../../crates/composition/README.md), [ADR 0015](../../docs/adr/0015-composition-library.md)),
depends on the `WebhookVerifier` port and not on the `github` crate ([ADR 0014](../../docs/adr/0014-ports-v1-1-claim-protocol-and-port-revision.md)),
and connects to PostgreSQL as the **API login only** ([ADR 0012](../../docs/adr/0012-row-level-security-in-slice-1.md)):
a member of `factory_app` and `factory_resolver`, with no system pool. It cannot find work across tenants and
it cannot do what the engine login does. `tests/database_logins.rs` shows both directions.

The package is a library (`src/lib.rs`, crate `factory_api`) and a thin binary (`src/main.rs`).

## Running it

```text
FACTORY_CONFIG=/etc/factory/api.yaml factory-api
```

Exit codes: `0` a clean stop (SIGTERM or SIGINT; open requests get `limits.drain_s` to finish), `1` a start-up
check failed or the listener could not bind, `2` the configuration was refused. Start-up runs, in order: the
policy from the protected checkout (hashed), the redactor built from it and the registry of secret values the
process holds, telemetry with that redactor in front of every log line, the webhook verifier from its secret
files, the database pool (role and schema checked by the store), the profile's rule over each of the API's six
ports, and the kinds of secret the policy requires. The production profile refuses a fake for each of the six
(`tests/profile.rs`, `production_profile_refuses_fakes`).

## Endpoints

The contract is [`openapi.json`](openapi.json), written first and served on `GET /openapi.json`.
[`routes::ROUTES`](src/routes.rs) is the table the router is built from, and
`cargo nextest run -p factory-api --test openapi_contract` fails when the two differ.

| Method and path | Auth | Role (allowlist designation) | Idempotency |
|---|---|---|---|
| `GET /healthz` | none | none | read |
| `GET /readyz` | none | none | read |
| `GET /openapi.json` | none | none | read |
| `POST /v1/jobs` | bearer token | `requester` | `Idempotency-Key` required: the same key and request finds the first job (`200`), the same key and another request is `409` |
| `GET /v1/jobs` | bearer token | any designation | read |
| `GET /v1/jobs/{job_id}` | bearer token | any designation | read |
| `GET /v1/jobs/{job_id}/timeline` | bearer token | any designation | read |
| `POST /v1/jobs/{job_id}/decisions` | bearer token | `approver` for approve, reject and rework; `operator` for pause, resume and cancel (read from the `actions` table of `policies/approval.yaml`) | `Idempotency-Key` required: the record id is derived from the tenant, the job and the key |
| `POST /v1/webhooks/github` | HMAC-SHA256 of the raw body | none (GitHub) | the delivery id, the body hash and the event on the same subject revision, in the store |

There is no route that merges or deploys, and a test keeps the words out of the table (ST-05).

`/readyz` answers `503` when any check fails or could not run. A database that is behind the code is a failed
check, not a passed one (`readiness_checks_schema_version`). Its body names the checks and their status and
nothing else.

### What a decision does, and does not

The API records the decision and does not apply it. Moving a stage run needs `Engine::decide` or `Engine::control`
and, for a pull request approval, the change host and the binding checks of `ApprovalService::judge` (the head,
tree, base and evidence as they are now). The engine runs in the worker, which holds the sandbox, the agent
runtime and the GitHub App; the API holds none of them and cannot build an engine without a fake. So the answer
is `202` with `"applied": false`, and the record is an audit event `decision.requested` in the caller's tenant
whose subject carries the verb, the job, the stage run, the head, the evidence digest and the target (the grammar
is `factory_composition::decisions::DecisionFields`, shared with the worker). A caller who does not hold the
designation gets `403` with no reason and a `decision.denied` audit record, whether or not the job exists.

`"applied": false` is true of the moment of the answer and says nothing about what comes after. The worker
(`factory_composition::decisions::ClaimWork`, a step before each claim) reads the record, checks the allowlist again by
numeric id, applies the decision once and writes `decision.applied` or `decision.rejected` for the same job. Both
show in `GET /v1/jobs/{id}/timeline`, and a person polls it to learn the outcome. `apps/api/tests/complete_run.rs`
shows the whole path against the real server.

## Authentication and authority

* **Tokens are opaque.** `sfat_` and 43 URL-safe characters (256 random bits). Nothing in one can be decoded, so
  `alg: none`, a swapped key and a stretched expiry have nothing to work on. The database keeps only the
  SHA-256, an audience, an expiry and a revocation time. `Store::resolve_token` is the only lookup, and an
  unknown, expired, revoked, wrong-audience or disabled-owner token is the same `401` with the same bytes.
  The application compares no token with anything: equality is the unique index on the hash. There is no
  cache, so a revocation takes effect on the next request.
* **A token proves who is calling and grants no role.** The roles come from the protected allowlist
  (`allowlist/allowlist.yaml`, read on every request) by the **numeric GitHub id** of the principal behind the
  token. A login string is never read for a decision, and a person removed from the file loses the right on the
  next request.
* **Issuing and revoking a token** is an operator action on the database today: the store port has no operation
  for either (the application role can insert a row and set `revoked_at`, and no port method does). Make a
  token with `tokens::format_token` on 32 bytes from the operating system, show it once, store
  `tokens::hash_token` of it. Rotation is two tokens that overlap and a revocation of the old one.
* **The source address is the TCP peer.** `X-Forwarded-For`, `Forwarded` and `X-Real-IP` are never read, so a client
  cannot choose the key it is rate limited under (`a_forged_forwarding_header_changes_nothing`). Behind a reverse
  proxy every client is counted as the proxy until a trusted-proxy setting exists; the limit is then too coarse,
  not too loose.

## Webhooks

The order is the point (module `webhook`): size and time before the body is read; verification of the raw bytes
by the `WebhookVerifier` port, with no database access, the same `401` for every failure and one event put in a
bounded queue; binding of the installation and repository to a tenant; deduplication in the store; then a hint,
never a claim. After a valid signature every outcome is `202 {"status": "accepted"}`: a new delivery, a
repeat, an unknown installation and an event the factory does not act on look the same.

A labeled issue makes a `RECEIVED` job only if the label is the factory label, the sender is a registered
principal of the tenant, and the allowlist lists that numeric id as a requester. The job has no original request:
the text of the issue is not in the payload the verifier reads and the API holds no GitHub credential.

## Configuration

One YAML file, read with the restricted reader, `deny_unknown_fields`, secrets as paths to files that only
their owner may read.

```yaml
profile: production                     # production | local | test; no default
protected_checkout: /srv/factory/protected   # policies/ and allowlist/allowlist.yaml; no default
database:
  api: { url_file: /run/secrets/db_api, login: factory_api, max_connections: 8 }
listen: 127.0.0.1:8080
github:
  webhook_secret_files: [/run/secrets/webhook_secret]   # one file per secret in the rotation window; required in production
  factory_label: factory
tokens: { audience: factory-api }
limits:                                 # all optional
  max_body_bytes: 262144
  header_timeout_ms: 10000
  body_timeout_ms: 10000
  request_timeout_ms: 30000
  max_connections: 256
  drain_s: 15
  per_ip_per_minute: 600
  webhook_per_installation_per_minute: 120
artifacts: { root: /var/lib/factory/artifacts }   # accepted, not read by this part
```

### The local stack's example

`infra/compose/config/api.local.example.yaml` is **parsed as written except for one missing setting**: the
API reads the policy and the allowlist, so it needs `protected_checkout`. `infra/**` is not edited here.
The corrected file is the existing one plus this line, and the container must mount that directory read-only:

```yaml
protected_checkout: /etc/factory/protected
```

`tests/profile.rs` (`the_api_example_of_the_local_stack_parses_once_it_names_the_protected_checkout`) parses the
file as it is, shows the refusal naming `protected_checkout`, and parses the corrected text. The names the
placeholder chose (`database.api`, `listen`, `artifacts`) are the names the API uses.

## Limits and hostile input

A body is read only after the token is checked, with a hard cap and a deadline; a declared length over the cap
is refused without reading a byte. hyper's header read timeout closes a slow-loris connection; a stalled body is
`408`. Open connections are bounded and the ones over the limit are closed unread. Every string is checked: no
NUL or other control character (line breaks and tabs allowed in request text only), an idempotency key from a
small alphabet, ids parsed as UUIDs, an unknown JSON field or a repeated key is `400`. Request text is stored
as received and never interpreted. `tests/http_api.rs`, `malformed_and_hostile_input_is_a_400_and_never_a_500`.

## Tests

```text
cargo nextest run -p factory-api
```

The tests start the real server on a loopback port and a real PostgreSQL (the storage crate's test server,
`docs/database/running.md`; a test that cannot get one panics with `BLOCKED:`).

| File | What it proves |
|---|---|
| `tests/http_api.rs` | health and readiness; submit, status, listing, timeline; idempotency; NT-WEB-05; NT-TEN-05 with row-level security alone and the application scope alone shown separately; roles and decisions by numeric id; the grammar; hostile input; one shape for every error; correlation id; body size, slow clients, connection limit; a forged forwarding header |
| `tests/webhook.rs` | NT-WH-01 to 04, 07, 08, 10 and NT-AUTHZ-08 |
| `tests/openapi_contract.rs` | the document is valid; the router matches it; a drift is caught |
| `tests/profile.rs` | the production profile refuses a fake for each API port; the local stack's example |
| `tests/database_logins.rs` | the three-logins rule from the API login and from the engine login |
| `tests/telemetry.rs` | work on a job runs in a `factory.job` span; the real redactor reaches telemetry |
| `tests/breaks.rs` | the deliberate breaks |

### Deliberate breaks

Each safeguard is one check that passes on the real wiring, and a second test runs the same check on a wiring with
the safeguard broken and expects it to fail.

| Break | Caught by |
|---|---|
| Skip signature verification | `break_skipping_signature_verification_is_caught` (the forged delivery is answered `202`) |
| Compare a token or signature with `==` | `break_comparing_a_token_with_equals_is_caught` (a scan of `src/`; the real source has no hit) |
| Log a token | `break_logging_a_token_is_caught` (a capture of every event; a field and a whole header map) |
| Accept a decision authenticated by login | `break_deciding_by_login_is_caught` (an authority that reads the login string) |
| Serve tenant B's job to tenant A | `break_serving_tenant_b_to_tenant_a_is_caught` (a store that opens B's scope for everyone) |
| Report readiness OK while the schema is behind | `break_readiness_that_ignores_the_schema_is_caught` |
| Route a webhook through the engine login | `database_logins.rs`: the store refuses to start on the engine login, the worker login and a superuser |
| A fake in the production profile | `profile.rs`, for each of the six ports |
| Drift between the document and the routes | `openapi_contract.rs`, five edits and an undocumented route |

## Dependencies

Direct dependencies added by this package, **pending confirmation by a person**
(`policies/security.yaml`, `supply_chain.new_direct_dependency`). `cargo deny --locked check` passes with the
unchanged `deny.toml`. The first five are used behind two modules (`server` and `routes`).

| Crate | Version | Licence | Why | New to `Cargo.lock` |
|---|---|---|---|---|
| `axum` | 0.8.9 | MIT | routing by method and path; the stack the master prompt names. Features `http1` and `tokio` only | yes (with `axum-core` 0.5.6 MIT, `matchit` 0.8.4 MIT and BSD-3-Clause, `mime` 0.3.17 MIT or Apache-2.0) |
| `hyper` | 1.12.0 | MIT | the connection loop, so the header timeout, the connection limit and the peer address are the API's | no |
| `hyper-util` | 0.1.21 | MIT | `TokioIo`, `TokioTimer` | no |
| `http-body-util` | 0.1.5 | MIT | the body reader with a size limit | no |
| `tower` | 0.5.3 | MIT | `ServiceExt::oneshot` between the router and the connection | no |

The rest (`serde`, `serde_json`, `thiserror`, `tracing`, `tokio`, `uuid`) were already direct dependencies of other
packages. `tokio` here also enables `rt-multi-thread` and `net`, both already in the allowed list of
`source_scans.dep_05.resolved_features`. The entry for `apps/api` in
`docs/architecture/crate-dependency-rules.json` lists them with the same reasons.

## Additions to `crates/composition`

Pure additions, no change to an existing item, all of them the kind of thing the worker could use too:
`config::read_document` (the reader of the worker's configuration, for any type), `database::api_store_config`
and `database::connect_api` (the API login on one pool, `TenantLogin::Api`, no system pool), and the `webhook`
module (`verifier_from_files`: the real verifier from secret files, registering each secret with the
redactor).

## What is not done, and what is not verified

* **Applying a recorded decision: done.** The worker applies it (see "What a decision does, and does not").
* **Admitting a received job: done.** `ClaimWork` lists the `RECEIVED` jobs of the tenants the worker serves and
  admits them.
* **A job from a webhook has no original request: done.** The intake stage fetches the issue with `IssueSource` and
  records revision 1 when it runs. The issue is found in the audit record `job.received_from_webhook`, which is why
  that record's subject (`issue <owner>/<name>#<number>`) is now part of the contract between the API and the
  worker.
* **Still open:** a person cannot answer the specification stage's human gate through this endpoint, an approval
  with an open translation warning is refused because no endpoint records a decision about a warning, and a job
  submitted without a `source_ref` cannot pass intake (worker README, mismatches 19 to 21).
* **The outbox criterion of the package** ("one job, one outbox row and 49 duplicate-delivery audit events") is met
  for the job and the audit events and not for the outbox: `state-machine.json` has no event for a received job
  (the first event of a job is `job.admitted`, written by the engine), and the API invents no event type. The
  test asserts the outbox is empty.
* **Token issue and revocation have no port operation.** *Smallest change, owner `ports` and `storage`:* a
  `TokenOps` with `issue_token` and `revoke_token` on `Tx`.
* **The decision pre-check is by designation only.** Whether the autonomy level, separation of duties (the
  requester may not approve their own job) and the risk tier allow it is `ApprovalService::judge`, which has the
  facts. The API does not copy those rules.
* **Verified against a real PostgreSQL 18 and the real server on loopback only.** Not verified: a real GitHub
  delivery (the shape of the payload is the documented one, as the adapter's tests assume); a deployment behind a
  proxy or TLS terminator; the container image; a run of the whole stack; behaviour above the rate limits under
  real load; the timing equality of a foreign and a missing object beyond a 100 ms bound on one machine.
* **No dashboard origin, CSRF token or step-up authentication.** The API is for tokens, not for browsers: it sets no
  cookie and answers no `OPTIONS`. NT-WEB-02 belongs to the dashboard package.
* **Telemetry export** is the composition library's helper; the API passes it the real scrubber. The trace context
  derived from the job (ADR 0013) is the `factory.job` span's correlation id and job id; a remote parent is not set,
  as in the worker, because the observability helper for it has not landed.
