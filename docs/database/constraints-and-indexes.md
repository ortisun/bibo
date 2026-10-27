# Constraints and indexes

- Status: baseline for Slice 0. Every constraint named here exists in [`migrations/`](../../migrations/) and has at least one test in [`tests/`](tests/). The test that proves it is named in the last column of the tables.
- Form: reference, with the reason beside each rule.
- Related: [data-model.md](data-model.md) for what the tables hold, [tenancy.md](tenancy.md) for the tenant rules, [ledger-and-audit.md](ledger-and-audit.md) for the two chains.

## Patterns used everywhere

These apply to many tables. The per-table sections below only mention what is specific to a table.

| Pattern | Mechanism | Why |
|---|---|---|
| Tenant on every row | `tenant_id uuid NOT NULL`, first column of the primary key, and a foreign key to `tenants`. | ADR 0007, rule 4. A lookup by key cannot omit the tenant, and a missing tenant is a null violation. |
| Foreign keys name the tenant on both sides | `FOREIGN KEY (tenant_id, x_id) REFERENCES x (tenant_id, id)`. | A child cannot point at another tenant's parent. The `tenancy` suite reads all 31 such keys from the catalog and fails if one lacks the pair. |
| Foreign keys also name the job | Children of a stage run name `(tenant_id, job_id, stage_run_id)`. | A stage run's attempt, ledger entry or approval cannot be filed under a different job of the same tenant. This needs the extra unique key `(tenant_id, job_id, id)` on `stage_runs`. |
| Unique keys include the tenant | Every unique constraint and unique index starts with or contains `tenant_id`. | Two tenants may use the same delivery id, artifact hash or idempotency key without colliding or learning of each other. Two exceptions are listed in the next section. |
| Status columns | `CHECK (status IN (...))` with the list from `state-machine.json`, named `<table>_status_check`. | ADR 0007, rule 3. The `statuses` suite compares each list with the JSON. |
| Legal moves | Trigger `enforce_status_transition('<machine>')` on `jobs`, `stage_runs`, `attempts`, `task_nodes`. A new row must start in the initial state. A status change must follow an edge in `state_machine_edges`. | A second line behind the domain's transition functions (invariant INV-02). The suite tries all 308 ordered pairs of states. |
| Terminal state and its timestamp | `CHECK ((status IN (terminal states)) = (finished_at IS NOT NULL))`, named `<table>_terminal_check`. | A row cannot be terminal without saying when, or carry a finish time while live. |
| Compare and swap | `version bigint`, trigger `bump_guard`: an update must set `version = old + 1`. The trigger also stamps `updated_at` from the database clock. | ADR 0007, rule 6. A writer that forgets to bump would silently switch off the check for everyone after it. |
| Hash columns | `CHECK (col ~ '^sha256:[0-9a-f]{64}$')`. | The artifact store addresses by this form. A malformed value could never match a blob. |
| Slugs | `CHECK (col ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$')`. | The same pattern as the `slug` type in the contract schemas. |
| Append-only | No `UPDATE` or `DELETE` grant to the application role, plus a trigger that raises for every role on `UPDATE`, `DELETE` and `TRUNCATE`. | Two layers, so a mistake in one grant does not open the table. |
| NULL in a CHECK | Conditions that must fail on NULL say `IS NOT NULL AND ...`. | A CHECK accepts NULL. The `terminal_rows` suite found `status <> 'PASSED' OR gate_outcome IN (...)` letting a PASSED run through without an outcome. |

### The two unique keys without a tenant

| Constraint | Why it cannot start with the tenant |
|---|---|
| `repositories_github_repository_id_key` on `github_repository_id` | The webhook receiver finds the tenant from the repository, so the lookup comes first. The key also makes it impossible for two tenants to claim one GitHub repository, which would make the tenant binding of a webhook ambiguous (threat T-24, control C-04). |
| `api_tokens_token_hash_key` on `token_hash` | The API authenticates a request by hashing the presented token, before it knows the tenant. A SHA-256 of 256 random bits will not collide in practice, and the key turns the unlikely case into an insert error. |

The `tenancy` suite asserts that these two are the only unique indexes on tenant-owned tables without a tenant.

## Tables

### `repositories`

| Rule | Why | Test |
|---|---|---|
| `autonomy_ceiling` in `L0`..`L3`, default `L0`; `protection_preflight_passed` default false | A repository without branch protection runs at L0 only (ADR 0009, default 3). The safe state is the default. | `tenancy`, `privileges` |
| Index on `github_installation_id` | Installation events list the repositories of one installation. | |

### `principals`

| Rule | Why | Test |
|---|---|---|
| `(kind = 'human') = (github_user_id IS NOT NULL)` | The numeric GitHub id is the identity of a person. A service has none. | `tokens` |
| `UNIQUE (tenant_id, github_user_id)` | One principal per person per tenant. | `tokens` |
| `UNIQUE (tenant_id, id, kind, github_user_id)` | The target of the approvals key, so an approver is a human of this tenant whose GitHub id is the recorded one. | `approvals` |
| No role or permission column | Authority comes from the allowlist in protected configuration (`policies/approval.yaml`, `authority`), which names `dashboard_database` among the places it must not be read from. | `tokens` |

### `api_tokens` and `active_api_tokens`

| Rule | Why | Test |
|---|---|---|
| `token_hash bytea`, exactly 32 bytes | Only a SHA-256 hash is stored. A readable token does not fit in the column. | `tokens` |
| `audience` slug, `expires_at NOT NULL`, `expires_at > created_at` | A token is for one audience and always expires. | `tokens` |
| Trigger `api_tokens_guard`: once `revoked_at` is set it cannot change | Revocation is final. | `tokens` |
| Column grants: the application role may update only `revoked_at` and `last_used_at` | It cannot extend, retarget or swap a token. | `tokens`, `privileges` |
| View `active_api_tokens` (not revoked, not expired, owner not disabled, tenant not disabled) | One place says what a usable token is. `security_invoker` means the row-level security policies of the caller apply through it. `resolve_token` reads it. | `tokens`, `rls` |
| No column named like a secret | Catalog scan in `tokens`: nothing matches `secret`, `password`, `credential`, `private`, `api_key` or `token` except `token_hash`. | `tokens` |

### `webhook_deliveries`

| Rule | Why | Test |
|---|---|---|
| `UNIQUE (tenant_id, delivery_id)` | The `X-GitHub-Delivery` id; a repeat is acknowledged and ignored (control C-02). | `webhook_delivery` |
| `UNIQUE (tenant_id, body_sha256)` | The signature covers the body and not the headers, so a captured body replayed with a fresh delivery header has a new id and the same body. **A decision for review**, see the end of this page. | `webhook_delivery` |
| `UNIQUE (tenant_id, semantic_key)` | The policy's semantic idempotency key (event, action, installation, repository, subject, subject update time, sender). NULLs do not collide. | `webhook_delivery` |
| Index on `received_at` | The 30-day retention scan. | |

### `artifacts` and `stage_run_artifacts`

| Rule | Why | Test |
|---|---|---|
| Primary key `(tenant_id, content_sha256)` | One metadata row per tenant and hash (ADR 0008). A tenant reaches a blob only through its own row. | `tenancy` |
| `backend IN ('local-fs', 's3-compatible')` | The label says which store holds the bytes, so the local adapter is never mistaken for S3. | |
| Foreign key to the creating stage run, added after `stage_runs` exists | The creating run belongs to the same tenant and job. | `tenancy` |
| `stage_run_artifacts`: primary key `(tenant_id, stage_run_id, direction, role)`, index `(tenant_id, content_sha256, direction)` | Answers "which runs consumed this hash", which supersession needs (`invalidation_rules`). | `plans` |
| Both are INSERT and SELECT only for the application role | Records of fact. | `privileges` |

### `jobs`

| Rule | Why | Test |
|---|---|---|
| `UNIQUE (tenant_id, webhook_delivery_id)` and `UNIQUE (tenant_id, idempotency_key)` | One delivery or one API retry makes at most one job. This holds even if the receiver forgets to deduplicate. | `webhook_delivery` |
| `UNIQUE (tenant_id, id, execution_mode)` | The target of the ledger's key on `(job, execution_mode)`. A production job can never receive an entry from a fake recorder (INV-08). | `ledger` |
| `UNIQUE (tenant_id, correlation_id)` | The correlation id is one per job. | |
| `pipeline_scope` is a non-empty subset of the 14 stage kinds | The list is checked against the pipeline in `state-machine.json`. | `statuses` |
| `ledger_head_sequence = 0` exactly when `ledger_head_hash IS NULL` | The head is either empty or a pair. | `ledger` |
| Deferred foreign key `jobs_ledger_head_fk` to `ledger_entries (tenant_id, job_id, sequence, entry_hash)` | The head pointer must name a real entry of this job. Deferred, so the entry and the job update can be written in either order. | `ledger` |
| Index `jobs_open_idx (tenant_id, id) WHERE status NOT IN (terminal)` | The job quota at admission and the engine's search for open work. The claim plan uses it for the join to `jobs`. | `plans` |
| Index `jobs_listing_idx (tenant_id, created_at DESC, id DESC)` | Dashboard listing with keyset pagination. | |
| The second unique index on `(tenant_id, id, execution_mode)` also serves key lookups | The planner picks it for `(tenant_id, id)` lookups. The primary key stays because other tables reference `(tenant_id, id)` exactly. The cost is one extra index to maintain per job write. | `plans` |

### `original_requests`

| Rule | Why | Test |
|---|---|---|
| `CHECK (content_sha256 = 'sha256:' || encode(sha256(convert_to(request_text, 'UTF8')), 'hex'))` | The hash cannot drift from the text it names (control C-05). | `tenancy` |
| `UNIQUE (tenant_id, job_id, revision)` and no `UPDATE` | An edited source creates a new revision. The earlier text stays as the record of what was authorized. | `privileges` |
| `octet_length(request_text) BETWEEN 1 AND 1048576` | Matches `webhook.max_body_bytes`. | |

### `stage_runs`

| Rule | Why | Test |
|---|---|---|
| `UNIQUE (tenant_id, job_id, stage_kind, run_number)` | Rework adds a run with the next number and never reopens an old one. The index also serves "stage runs of one job". | `plans` |
| Trigger `stage_runs_guard`: a terminal run cannot change, except that a run in a state with a supersede edge (`PASSED` and, since ADR 0010, `SKIPPED`) can become `SUPERSEDED` with only `status`, `version`, `updated_at` and `superseded_at` different. It reads the edges from `state_machine_edges`, so it follows `state-machine.json` | Invariant INV-04. A skipped run satisfies the stages that require it, so when an input changes the decision is made again in a new run and the old one must give way. | `terminal_rows` (all 66 moves out of a terminal state, against the JSON) |
| The same trigger: `lease_epoch` changes only with `READY` to `RUNNING`, by exactly one, and that move must change it | A claim and nothing else raises the fencing counter. | `terminal_rows` |
| `passed_has_outcome`, `skipped_has_outcome`, `superseded_check` | `PASSED` needs a gate outcome (`PASSED`, or `BLOCKED` after an override), `SKIPPED` needs `NOT_APPLICABLE`, `superseded_at` is set exactly for `SUPERSEDED`. | `terminal_rows` |
| `max_attempts BETWEEN 1 AND 20` | A sanity bound; the policy value sits below it. | |
| Partial index `stage_runs_claim_idx (not_before) WHERE status = 'READY'` | The claim query. It holds only runs that can be claimed (about 1.6 percent of the generated rows). It has no tenant column on purpose: the engine claims across tenants in the system scope. | `plans` |

### `attempts`

| Rule | Why | Test |
|---|---|---|
| Partial unique index `attempts_one_active_per_stage_run (tenant_id, stage_run_id) WHERE status IN (STARTING, RUNNING, CANCELLING)` | The database's answer to "two workers claimed the same run". | `lease` |
| `UNIQUE (tenant_id, stage_run_id, attempt_number)`, trigger `attempts_insert_guard` | Attempts are numbered 1, 2, 3 in order and cannot pass the run's `max_attempts` (INV-10). | `lease` |
| Deferred constraint trigger `attempts_epoch_check` | A live attempt holds the stage run's current epoch. | `lease` |
| Trigger `attempts_update_guard` | A finished attempt keeps its result. Only `sandbox_id` and `sandbox_leaked` may still change. The epoch of an attempt never changes (INV-05). | `terminal_rows` |
| Trigger `attempts_lease_bound`: `lease_expires_at <= now() + 1 hour` | A skewed or hostile worker cannot hold a lease far ahead of the database clock. | `lease` |
| `attempts_active_has_lease`, `attempts_failed_has_class`, `attempts_succeeded_has_output`, `attempts_cancelling_has_teardown` | A live attempt has an owner and an expiry. Only a failure has a failure class, and every failure has one. A success names its output artifact. A cancelling attempt has a teardown deadline. | `terminal_rows`, `lease` |
| Partial indexes `attempts_lease_expiry_idx`, `attempts_deadline_idx` (live attempts), `attempts_teardown_idx` (cancelling) | The three sweeper scans. Not tenant scoped, by design. They stay small because most attempts are finished. | `plans` |

### `task_nodes` and `task_node_dependencies`

| Rule | Why | Test |
|---|---|---|
| `UNIQUE (tenant_id, stage_run_id, task_key)` | A task key is unique inside its run. | |
| Dependencies carry `stage_run_id` on both ends | An edge cannot leave its stage run. | `tenancy` |
| Trigger `task_node_dependencies_acyclic` | The planner validator checks for cycles; this is the backstop. | |
| `FAILED` is not terminal for a task | The state machine allows a retry (`T06`). | `statuses` |

### `ledger_entries`

Covered in [ledger-and-audit.md](ledger-and-audit.md). In short: primary key `(tenant_id, job_id, sequence)`, a foreign key from each entry to its predecessor `(job, sequence - 1, entry_hash)`, a trigger that recomputes the hash from `canonical_json` and checks the document against the columns, three CHECKs that copy the fake-versus-real rules of the schema, a foreign key on `(job, execution_mode)`, and the append-only pair of layers. Index `ledger_entries_stage_run_idx (tenant_id, job_id, stage_run_id, sequence)` serves "every claim made in this stage run", which the gate needs.

### `audit_events`

Covered in [ledger-and-audit.md](ledger-and-audit.md). Primary key `(tenant_id, sequence)`, assigned by a trigger, with a foreign key to the previous row. Index `audit_events_job_idx` is partial on `job_id IS NOT NULL`.

### `outbox`

| Rule | Why | Test |
|---|---|---|
| Foreign key `(aggregate_type, transition_id, event_type)` to `state_machine_transitions (machine, transition_id, emits)` | An event names a real transition of its machine and carries the event type that transition emits. | `outbox` |
| `outbox_one_event_per_aggregate_version` | Replaying a transition after a crash cannot emit it twice, and consumers can use the version to find gaps. | `outbox`, `webhook_delivery` |
| Deferred trigger `outbox_aggregate_check` | `aggregate_id` points at one of four tables, so no foreign key can check it. The trigger checks that the aggregate exists in the tenant, belongs to the event's job and has reached the announced version. | `outbox` |
| `event_type <> 'attempt.heartbeat'`, event type starts with the aggregate type | Heartbeats are not domain events (ADR 0004). | `outbox` |
| `payload` is a JSON object of at most 16 KiB | Events carry identifiers and hashes. Large content belongs in the artifact store. | `outbox` |
| Trigger `outbox_guard` and column grants | Only `published_at` (once) and `publish_attempts` (upwards) change. | `outbox` |
| `seq` identity column; partial index `outbox_unpublished_idx (seq) WHERE published_at IS NULL`; index `outbox_job_timeline_idx (tenant_id, job_id, seq)` | `seq` orders the relay and has gaps by design. The first index holds only the backlog (1 percent of the generated rows). The second serves the job timeline. | `plans` |

### `inbox`

Primary key `(tenant_id, consumer, event_id)`. A consumer inserts its row in the same transaction as its effects inside PostgreSQL, so a repeated delivery hits the key and is dropped (ADR 0004). There is no foreign key to `outbox`, so the outbox can be trimmed on its own schedule.

### `approvals`

| Rule | Why | Test |
|---|---|---|
| `approvals_approve_is_bound`: an `approve` decision needs `pr_head_sha`, `tree_hash`, `base_sha`, `evidence_manifest_hash` and `spec_version` | `policies/approval.yaml`, `approval_binding`. The approval says what it approved. | `approvals` |
| Foreign key `(tenant_id, approver_principal_id, approver_kind, approver_github_user_id)` to `principals`, with `approver_kind = 'human'` | The approver is a human of this tenant and the GitHub id recorded is the principal's own. A service principal cannot approve. | `approvals` |
| Unique index on `(tenant_id, stage_run_id, approver_principal_id, decision, pr_head_sha)` where the head is set | One person records one decision per head commit once. | `approvals` |
| Trigger `approvals_guard` and column grants | Only `invalidated_at` and `invalidation_reason`, once, together. | `approvals` |
| `expires_at > created_at` | The 72-hour limit is policy and is set by the caller. The database only requires a window. | `approvals` |

## Invariants from `state-machine.json` and where the database stands on each

| Invariant | In the database | Proven by |
|---|---|---|
| INV-01 only the engine writes a status | Not enforceable by a database that cannot tell the engine from a worker. Column grants and the version guard limit what the application role can do. | `privileges`, `terminal_rows` |
| INV-02 an unlisted transition is rejected | Transition trigger on the four machines. | `statuses` |
| INV-03 evidence and status change commit together | One transaction; foreign keys and deferred checks that make the pieces consistent. | `outbox` |
| INV-04 a terminal stage run is never edited | `stage_runs_guard`. | `terminal_rows` |
| INV-05 an old lease epoch is rejected | One live attempt per run, the epoch rule, the terminal-attempt guard, the lease bound. The fenced `WHERE` of the write is the engine's. | `lease` |
| INV-06 a mandatory gate that did not run is BLOCKED | Not in the database. | |
| INV-07, INV-08 overrides and fake evidence | Ledger CHECKs and the execution mode key. | `ledger` |
| INV-09 the ledger is append-only | Grants and triggers. | `ledger` |
| INV-10 bounded attempts | `attempts_insert_guard`. Rework rounds are counted by the engine. | `lease` |
| INV-11 documentation stages come after review | Not in the database. | |

## Decisions that need a person

1. **`UNIQUE (tenant_id, body_sha256)` on `webhook_deliveries`.** It closes a replay hole that the delivery id alone leaves open, and it assumes two different legitimate deliveries never have byte-identical bodies. GitHub payloads carry ids and timestamps, so this should hold, but it is an assumption. The alternative is to rely on the semantic key alone.
2. **The platform tenant** (`00000000-0000-0000-0000-000000000001`) that owns audit events with no tenant. The other choice is to let `audit_events.tenant_id` be null, which would break the per-tenant chain.
3. **The one-hour bound on a lease** and the **16 KiB limit on an outbox payload.** Both are generous sanity limits, set here because the policy gives no figure. Change them by migration.
