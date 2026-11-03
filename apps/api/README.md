# factory-api

The HTTP API of the factory: a composition root in ring 3 ([ADR 0002](../../docs/adr/0002-workspace-layout-and-dependency-rule.md)).
It receives GitHub webhooks, accepts jobs and decisions from people, and answers status and timeline
queries. It chooses its adapters through the composition library
([`factory-composition`](../../crates/composition/README.md), [ADR 0015](../../docs/adr/0015-composition-library.md)),
depends on the `WebhookVerifier` port and not on the `github` crate ([ADR 0014](../../docs/adr/0014-ports-v1-1-claim-protocol-and-port-revision.md)),
and connects to PostgreSQL as the **API login only** ([ADR 0012](../../docs/adr/0012-row-level-security-in-slice-1.md)):
a member of `factory_api_app` and `factory_resolver` and not of `factory_app`, with no system pool. It cannot find
work across tenants, it cannot do what the engine login does, and it can write only the four tables the API writes
(`jobs`, `original_requests`, `audit_events`, `webhook_deliveries`): it cannot insert a token, a principal, an
approval, a ledger entry or an outbox row (finding API-3). It reads three more tables since the endpoints that serve
evidence exist (migration `2026-10-29-002300`): the index of the stored documents, the links from a stage run to them and
the ledger entries. Those grants are SELECT and nothing else, under row-level security. `tests/database_logins.rs` shows both directions.

The package is a library (`src/lib.rs`, crate `factory_api`) and a thin binary (`src/main.rs`).

## Running it

```text
FACTORY_CONFIG=/etc/factory/api.yaml factory-api
```

Exit codes: `0` a clean stop (SIGTERM or SIGINT; open requests get `limits.drain_s` to finish), `1` a start-up
check failed or the listener could not bind, `2` the configuration was refused. Start-up runs, in order: the
policy from the protected checkout (hashed), the redactor built from it and the registry of secret values the
process holds, telemetry with that redactor in front of every log line, the webhook verifier from its secret
files, the database pool (role and schema checked by the store), the artifact store when the configuration names an
artifact root, the profile's rule over each of the API's ports (six, and a seventh when there is an artifact root),
and the kinds of secret the policy requires. The production profile refuses a fake for each of them
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
| `POST /v1/jobs` | bearer token | `requester` | `Idempotency-Key` required: the same key and request finds the first job (`200`), the same key and another request is `409`. `source_ref` is required and must be `owner/name#number` of an issue of the repository the job is for, or the answer is `400` naming the field: a job is for one issue (FR-001), intake reads it from the pointer and delivery links the pull request to it. The `text` must be the title, a blank line and the body of that issue as the code host shows them when intake runs; the API cannot check it, and intake refuses a job whose text is not the issue's (DG-3) |
| `GET /v1/jobs` | bearer token | any designation | read |
| `GET /v1/jobs/{job_id}` | bearer token | any designation | read |
| `GET /v1/jobs/{job_id}/timeline` | bearer token | any designation | read |
| `GET /v1/jobs/{job_id}/specification-draft` | bearer token | any designation | read: the commit of the draft, the head of the ledger and the approval window (`reads.rs`) |
| `GET /v1/jobs/{job_id}/gate-reports` | bearer token | any designation | read: the gate reports of the ledger of the job |
| `GET /v1/jobs/{job_id}/artifacts/{sha256}` | bearer token | any designation | read: one stored document, as an attachment, at most 4 MiB, under a content type the API fixes |
| `POST /v1/jobs/{job_id}/decisions` | bearer token | `approver` for approve, reject and rework; `operator` for pause, resume, cancel and `unblock`; `approver` for `approve-dependency` and a security approver for `approve-build-code` and `approve-project-build-code` (read from the `actions` table of `policies/approval.yaml`). The two dependency verbs take `package`, `version`, an optional `checksum` prefix and a `reason` of 10 to 500 characters, are read by the same reader as the other channels, and are recorded as `decision.dependency_requested` with their own signed word | `Idempotency-Key` required: the record id is derived from the tenant, the job and the key |
| `POST /v1/repositories` | bearer token | `operator` (the action `register_repository`) | `Idempotency-Key` required. Asks to register a repository of the tenant, as a signed request that the worker applies: it will be disabled, at level `L0`, no project map, whatever the body says (unknown fields are `400`). The optional `single_maintainer` (boolean, default false) is written here and never after. `202` with a `request_id`, and with `"changed": false` for the request the same key made; `409` for another request under a taken key. A GitHub repository that is already registered, here or by another tenant, is refused by the worker with the code `conflict` (the state of the request does not say whose) |
| `GET /v1/repositories/{repository_id}` | bearer token | any designation | read: the repository, the rule about the enabler, whether its people still stand (`standing`), the attestation of its project map and what it was enabled for. Another tenant's repository, and one outside the repositories the caller's allowlist entry is narrowed to, have the answer of a missing one |
| `POST /v1/repositories/{repository_id}/project-map` | bearer token | `operator` (`confirm_project_map`) | `Idempotency-Key` required. Takes `commit` (40 lowercase hexadecimal characters) and a `reason` of 10 to 500 characters. A signed request that the worker applies: `202`. An attestation by a person, not a verification (see below) |
| `POST /v1/repositories/{repository_id}/enable` | bearer token | `approver` (`enable_repository`) | `Idempotency-Key` required. Takes the `commit` of the map the approver read and an optional `reason`. A signed request that the worker applies: `202`. `409` at once with the code `project_map_not_attested` until a map was attested, with `project_map_changed` when the commit is not the one attested now, and with `enabler_is_attestor` when the caller attested the map of a strict repository. A repository that is enabled for the commit attested now is answered `200` with `changed: false`, records nothing and names no second approver (finding RH-7) |
| `POST /v1/repositories/{repository_id}/disable` | bearer token | `operator` (`disable_repository`) | `Idempotency-Key` required. An optional `reason`. The one change the API makes itself, because it only narrows: `200`. Webhooks and job submissions for the repository are dropped from then on |
| `GET /v1/repository-changes/{request_id}` | bearer token | any designation | where a request to register, attest or enable stands: `requested`, `applied` (with the code `already_enabled` when the repository was enabled already), or `refused` with a fixed `code` (`not_permitted`, `not_an_active_person`, `not_found`, `conflict`, `project_map_not_attested`, `project_map_changed`, `enabler_is_attestor`, `single_maintainer_not_allowed`, `expired`, `clock_skew`, `disabled_since_request`, `malformed`, `not_settled`). A request lives fifteen minutes, and a disable made after it cancels it. A record without the API's keyed word is not a request and the route answers as for a missing one. The answer holds no text of the request. A request of another tenant has the answer of a missing one |
| `POST /v1/webhooks/github` | HMAC-SHA256 of the raw body | none (GitHub) | the delivery id, the body hash and the event on the same subject revision, in the store |

There is no route that merges or deploys, and a test keeps the words out of the table (ST-05).

`/readyz` answers `503` when any check fails or could not run. A database that is behind the code is a failed
check, not a passed one (`readiness_checks_schema_version`). Its body names the checks and their status and
nothing else.

### Registering a repository and attesting its project map

`repositories.rs` is the front door of the path in [ADR 0016](../../docs/adr/0016-design-phase-onboarding-and-issue-workflow.md):
register, attest the map, enable, disable. Register, attest and enable are the acts that **widen** the factory's reach, so
they are signed requests, as a decision is (finding REG-2): the API checks the designation and the narrowing, appends one
`repository.change_requested` record that carries a keyed word, and answers `202`. The worker verifies the word, asks the
allowlist again by the numeric GitHub id, applies the change through the Store and writes the result as the system
(`repository.registered`, `repository.map_attested`, `repository.enabled`, or `repository.change_refused` with a fixed
code). `GET /v1/repository-changes/{request_id}` says where a request stands: `requested`, `applied` or `refused`.
**Disable** only narrows, so the API does it itself, in the caller's transaction with its record (`repository.disabled`),
and the table lets the API login do nothing else to a repository (a trigger refuses any other change).

**An attestation is not a verification.** The API holds no GitHub credential and cannot read a repository. It records that
a person said commit `C` of the default branch holds the project map, with the reason they gave and the time from the
database clock. Every answer carries `"verified_by_engine": false`, and the audit text says the same. If the engine ever
checks the repository, that is a new check with its own name.

What keeps the path honest:

* The designation each action needs comes from the `actions` table of `policies/approval.yaml`, by the numeric GitHub id,
  and an entry narrowed to other repositories holds nothing here (API-1). A refusal is `403` with no reason, audited within
  the bound of API-8, and changes nothing.
* The person who enables a repository is not the person who attested its map, unless the repository was registered with
  `"single_maintainer": true` (finding REG-6). The answer is `409` with the code `enabler_is_attestor`, and the table
  refuses the same pair for every role. `GET /v1/repositories/{id}` says which rule applies and, in `standing`, whether the
  attestor and the enabler are still active humans of the tenant; a repository whose either is not drops webhooks and job
  submissions like a disabled one.
* The database refuses an enabled repository without a map commit for every role (`repositories_enabled_needs_project_map`).
  The API answers the case first, with a typed code, and the table is the guard behind it.
* The login of the API holds two column grants on `repositories` and nothing else: `enabled` and `version`, which a disable
  writes (migration `2026-11-03-002700`). It cannot insert a repository, write a map commit or an enabler, or set the autonomy
  ceiling or the protection result, and a trigger refuses any change of a repository by it except one that sets `enabled`
  to false. The suite `api_privileges` lists the grants both ways. The residual risk is written in the ADR note and in
  threat T-38: the API process holds the decision key, so a compromise of the process (not a leak of the database
  credential) can sign a request, and the worker still applies it only as far as the designation of the active person it
  names allows.
* The record id is derived from the tenant, the caller, the repository and the `Idempotency-Key`, so a retry finds its
  record and changes nothing, and the same key with another request is `409`. A registration derives its repository id
  from the caller and the key.

### Letting a blocked stage run go again

`unblock` (`apps/api/src/stage_decisions.rs`) is the operator's verb for transition `S17`. It takes `stage_run_id` and a
`reason` of 10 to 500 characters, and nothing else: a word that means nothing to it is a `400` naming the field. The
request is recorded as the audit action `decision.stage_requested`, under an id derived from the tenant, the caller, the
job and the `Idempotency-Key`, signed with the key that signs the other requests under a context line of its own. The
action is on the list of the database trigger (migration `2026-10-29-002200_api_stage_decision_action`). The worker's step
(`factory_composition::stage_decisions`) asks the policy engine for the row `unblock_blocked_stage_run`, then calls
`Engine::decide` with `UnblockRerun`. The verb asserts no fact. The engine reads from what it stored whether a decision was
recorded after the attempt that blocked the run, and the worker has no capability probe adapter, so the re-probe never
passes today. A request for a run that is not blocked ends with the marker code `wrong_state`; one the engine does not
clear ends with `not_cleared`.

### What a person reads before they decide

Three read endpoints (`apps/api/src/reads.rs`) give a person the evidence an approval rests on. They need the artifact
root (`artifacts.root`) and the three reads of migration `2026-10-29-002300`.

* `specification-draft` gives the commit that holds the draft and the head of the ledger, which are what `head=` and
  `evidence=` of an `approve` must say, and whether the stage run waits for a person. The commit is read through the
  seam the worker's hook reads (`StoreSpecDrafts`), so it is the value the hook compares with.
* `gate-reports` lists the reports the engine cited in the ledger, with the gate, the outcome, the block code and the
  hash. A report the store cannot read is listed as such, with its hash.
* `artifacts/{sha256}` downloads one document. It is served as an attachment under `text/plain; charset=utf-8` when
  the stages stored it as text or JSON, and under `application/octet-stream` otherwise, with `nosniff`, whatever type the
  document claims. The document must be in the tenant's index (the database's row-level rule, applied again by the
  artifact store) and must belong to the job in the path: the index says its stage run is the job's, or a stage run of
  the job is linked to it (the application's scope). `tests/artifact_download.rs` shows each layer on its own and
  the tenant-crossing break caught.

The text of a document is untrusted. The command line prints it through the sanitizer (`factory-cli artifact`).

### Translation warnings

The approval request counts the open warnings of the documentation reviewer's rule `translation-unfaithful`
(`open_translation_warnings`), and an approval is refused while one has no decision of the person who approves
(`G_APPROVER_AUTHORIZED`, ADR 0009 item 17). `ack-translation-warning` takes the approval `stage_run_id`, the `warning`
(its number, from 1, in the order the gate reports list them) and a `reason`, and needs the approver designation. The
worker applies it through `Engine::record_warning_decision`, which reads the warnings and the manifest of the request from
what the stage run stored, refuses a number the request does not count, and writes one ledger entry for each decision.
The `approve` that follows reads those entries back for the person who approves, for that request and that stage run
(`stages::approval::warnings::all_decided`); a decision of another person, of an earlier request (another manifest) or of
a person who left the allowlist counts for nothing.

### The project's own build code

A change that adds a `build.rs`, a procedural macro or build dependencies to the project itself blocks the gate `build`
with the code `policy_unresolvable`, before any command builds it (`gates::scope::build_code`). The evidence of the
blocked validation stage run lists each such file with the SHA-256 of its content (`project_build_code.awaiting`).
`approve-project-build-code` takes `path`, `digest` (the start of that hash) and a `reason`. The worker selects the one
awaited file the two words name, asks the policy engine for the action `approve_build_code` (a security approver, never
the requester), and calls `Engine::record_project_build_code_decision`. The decision is stored in the ledger bound to the
path and the hash. The gate passes only for a file with a decision on exactly that content, taken for this tenant, this
job and this policy bundle by a person who still holds the designation: a script that is edited afterwards waits for a
new decision. `build-code-policy-unresolvable` is on `gate_integrity.non_overridable_blocks`, so no override replaces it.

### What a decision does, and does not

The API records the decision and does not apply it. Moving a stage run needs `Engine::decide` or `Engine::control`
and, for a pull request approval, the change host and the binding checks of `ApprovalService::judge` (the head,
tree, base and evidence as they are now). The engine runs in the worker, which holds the sandbox, the agent
runtime and the GitHub App; the API holds none of them and cannot build an engine without a fake. So the answer
is `202` with `"applied": false`, and the record is an audit event `decision.requested` in the caller's tenant
whose subject carries the verb, the job, the stage run, the head, the evidence digest and the target (the grammar
is `factory_composition::decisions::DecisionFields`, shared with the worker). A caller who does not hold the
designation gets `403` with no reason and a `decision.denied` audit record, whether or not the job exists.

**The record carries the API's word (AUT-12, R-1 of the API review).** A row in the audit log proves nothing
about who wrote it: any login of the API's database group can write one. So the subject ends with
`at=<the time of the request> mac=<64 hex digits>`, and the word is HMAC-SHA256 over the tenant, the person,
the event id, that time and the six other words (`factory_composition::decision_signing`). The key is a file
named by `decisions.key_file`, readable by its owner only, and the worker's hook verifies with the same file,
in constant time, before it reads anything else in the row. A row with no word, or the wrong one, is rejected
with the fixed code `not_signed`. A retry of a request that was recorded (same `Idempotency-Key`) has a later
time and so another word; the API finds the record it wrote, checks that it is the same request, and answers as
the first did. A refusal (`decision.denied`) is not a request and carries no word.

**Rotation.** Put the new key in `decisions.key_file` and the old one in `decisions.previous_key_file`, on the
API and the worker. The API signs with the current key; the worker accepts a word made with either. Set
`decisions.previous_key_valid_until` to the time 72 hours after the rotation (the approval window): after it
the previous key is ignored, and the `production` profile ignores the previous key when no such time is
set, so a replaced key stops verifying on its own. Remove the file once the requests signed with it have been
dealt with. In `production` every directory above a key file must be closed to group and others (a sticky
directory is allowed) and the file must belong to the owner of its directory or the directory to root.
A key must be random: 32 bytes at least once decoded (64 hex digits), not one byte or one short word written
again and again. The `production` profile does not start without `decisions.key_file`. The `local` and `test` profiles make
the file (mode `0600`) when it is missing, so the API and the worker that name the same path share it; with no
`decisions` section a process keeps a key in memory, which no other process shares.

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

The same label from anyone else (a person the tenant does not know, a person who is not a requester, a requester
narrowed to other repositories) makes no job (FR-002, SC-002). Because the API holds no GitHub credential, it leaves
one signed request in the audit log, in the transaction that records the delivery, under the action
`webhook_accepted_or_rejected.denied`, which its database trigger allows. The worker's hook answers it: one fixed
reply on the issue and the record `intake.rejected`
(`factory_composition::intake_rejections`). A repeated delivery leaves no second request, and a bot is never answered.
The worker answers one sender at most once in ten minutes and three times in 24 hours (SF-16); a request it does not
answer is still recorded, with `reply=suppressed` and the bound that held it (`withheld=spacing` or `withheld=cap`).

A repository that is switched off (registered, not enabled) answers nobody and starts nothing, whoever the sender is.
The lookup that binds a delivery to a tenant answers only for a repository that is registered and enabled, so such a
label is dropped there like one for a repository that was never registered: no delivery row, no job, no request for a
reply, and the platform record `webhook.unbound`. For the factory label (SF-19) that record's reason says that the
repository is not registered or that the factory is switched off for it, and that the label starts nothing and nobody
is answered; any other delivery that does not resolve keeps the plain reason. The record carries the delivery id and
nothing from the payload. A record in the tenant's own stream that names the repository would need the lookup to
return a disabled repository too, which is open. The answer to the sender of the webhook is the same `202` in every
case.

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
decisions:
  key_file: /run/secrets/decision_signing_key           # required in production; at least 32 bytes, mode 0600
  # previous_key_file: /run/secrets/decision_signing_key_previous   # during a rotation only
  # previous_key_valid_until: 2026-11-02T12:00:00Z                  # 72 hours after the rotation
tokens: { audience: factory-api }
limits:                                 # all optional
  max_body_bytes: 262144
  header_timeout_ms: 10000
  body_timeout_ms: 10000
  request_timeout_ms: 30000
  max_connections: 256
  max_connections_per_source: 16          # absent: a sixteenth of max_connections
  drain_s: 15
  per_ip_per_minute: 600
  webhook_per_installation_per_minute: 120
artifacts: { root: /var/lib/factory/artifacts }   # accepted, not read by this part
```

### The local stack's example

`infra/compose/config/api.local.example.yaml` is parsed as written by `tests/profile.rs`. It names
`protected_checkout` (the container mounts that directory read-only) and the same `decisions.key_file` as the
worker's example, so the two processes share one signing key. The names the placeholder chose
(`database.api`, `listen`, `artifacts`) are the names the API uses.

## Limits and hostile input

A body is read only after the token is checked, with a hard cap and a deadline; a declared length over the cap
is refused without reading a byte. hyper's header read timeout closes a slow-loris connection; a stalled body is
`408`. Open connections are bounded, in all and per source (an address, or an IPv6 /48; an IPv4 client of a
dual-stack listener is its IPv4 address), and the ones over either limit are closed unread, so one source cannot
hold the table with silent connections. The per-source request rate counts under the same grouping. Behind a proxy
every connection comes from the proxy: set `max_connections_per_source` to `max_connections` and cap clients there. Every string is checked: no
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
| `tests/repositories.rs` | the path register, attest, enable, disable and its effect on a webhook and a job; each role refused and accepted; another tenant; enabling without a map refused by the database; replayed keys; malformed input |
| `tests/openapi_contract.rs` | the document is valid; the router matches it; a drift is caught |
| `tests/profile.rs` | the production profile refuses a fake for each API port; the local stack's example |
| `tests/database_logins.rs` | the three-logins rule from the API login and from the engine login |
| `tests/telemetry.rs` | work on a job runs in a `factory.job` span; the real redactor reaches telemetry |
| `tests/breaks.rs` | the deliberate breaks |
| `tests/complete_run.rs` | one job from a signed webhook to `COMPLETED` with the engine suite's stand-in handlers after the first three stages, and the decision path on its own |
| `tests/full_run.rs` | one job through the real handler of every stage, the person's two approvals through this API, the assertions that matter, two runs compared, and seven deliberate breaks (the worker README, "The full run") |
| `tests/playbook_outputs.rs` | the scripted agent playbook on its own: every answer valid against its agent's schema, an answer it does not have fails loudly |

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
* **Done by the full run** (`tests/full_run.rs`, worker README "The full run"): a person approves the specification
  draft through this endpoint (`verb: approve` on the specification stage run, `head` the commit of the draft the
  person read, `evidence` the ledger head they saw; the worker's `ClaimWork::with_specification` applies it), and a job
  submitted without a `source_ref` is refused with a `400` at the door.
* **Still open:** an approval with an open translation warning is refused because no endpoint records a decision
  about a warning (worker README, mismatch 19), and no endpoint lets a person read the specification draft or the ledger
  head that a decision must name (mismatch 26).
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
