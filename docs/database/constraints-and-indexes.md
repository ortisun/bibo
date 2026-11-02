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
| Partial index `stage_runs_claim_order_idx (not_before, id) WHERE status = 'READY'` (migration 16; it replaced `stage_runs_claim_idx (not_before)`) | The claim query. It holds only runs that can be claimed (about 1.6 percent of the generated rows). It has no tenant column on purpose: the engine claims across tenants in the system scope. | `plans` |

### `attempts`

| Rule | Why | Test |
|---|---|---|
| Partial unique index `attempts_one_active_per_stage_run (tenant_id, stage_run_id) WHERE status IN (STARTING, RUNNING, CANCELLING)` | The database's answer to "two workers claimed the same run". | `lease` |
| `UNIQUE (tenant_id, stage_run_id, attempt_number)`, trigger `attempts_insert_guard` | Attempts are numbered 1, 2, 3 in order and cannot pass the run's `max_attempts` (INV-10). | `lease` |
| Deferred constraint trigger `attempts_epoch_check` | A live attempt holds the stage run's current epoch. Judged on the row as it stands at commit (migration 16). | `lease` |
| Trigger `attempts_update_guard` | A finished attempt keeps its result. Only `sandbox_id` and `sandbox_leaked` may still change. The epoch of an attempt never changes (INV-05). | `terminal_rows` |
| Trigger `attempts_lease_bound`: `lease_expires_at <= now() + 1 hour` | A skewed or hostile worker cannot hold a lease far ahead of the database clock. | `lease` |
| `attempts_active_has_lease`, `attempts_failed_has_class`, `attempts_succeeded_has_output`, `attempts_cancelling_has_teardown` | A live attempt has an owner and an expiry. Only a failure has a failure class, and every failure has one. A success names its output artifact. A cancelling attempt has a teardown deadline. | `terminal_rows`, `lease` |
| Partial indexes `attempts_deadline_idx` (live attempts) and `attempts_teardown_idx` (cancelling) | Two of the three sweeper scans. Not tenant scoped, by design. They stay small because most attempts are finished. The third scan, for an expired lease, has had no index of its own since migration 19: a lease renewal changes `lease_expires_at`, and an index keyed on it made every renewal a full index write (none heap-only against 99.84 percent without it, [performance.md](performance.md)). The query reads the live attempts through `attempts_deadline_idx` or `attempts_one_active_per_stage_run` and sorts the few that are left, so its cost follows the number of live attempts. | `plans`, `lease` section 14 |

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

## Added for ports v1.1 (migrations 15 to 18)

Each row is a rule the revised Store ([ports-v1.1](../architecture/ports-v1.1.md), [ADR 0014](../adr/0014-ports-v1-1-claim-protocol-and-port-revision.md)) states or relies on, and why the database holds it as well as the code. The test column names the suite; the deliberate break that shows each check can fail is in [running.md](running.md). Nothing is removed: the migrations only add, replace a function by a stricter one, or replace an index by a superset (see [migration-safety.md](migration-safety.md)).

### State machine (migration 15)

| Rule | Why | Test |
|---|---|---|
| Rows `S21` (`RUNNING` to `BLOCKED`, `attempt_blocked`, emits `stage_run.blocked`) and `S22` (`READY` to `WAITING_FOR_HUMAN`, `require_reauthorization`, emits `stage_run.waiting_for_human`), with their edges | The reference tables are generated from `state-machine.json`. The status trigger reads the edges, so the two moves are legal only from here on, and the outbox foreign key accepts the two events only for these transitions. | `statuses`, `outbox` |

### Claim protocol (migration 16)

| Rule | Why | Test |
|---|---|---|
| Deferred constraint triggers `stage_runs_live_attempt_check` (on `stage_runs`) and `attempts_live_attempt_check` (on `attempts`): a run that is not `RUNNING` or `SUPERSEDED` has no live attempt, checked at commit | ADR 0014, R1 to R3: the lease lives on the attempt, a retry (S05) waits for no lease because the failed attempt is terminal in the same transaction. Without this, a run could go back to `READY` with a live attempt; the unique index would then block the next start and the epoch check would fail the one after. `SUPERSEDED` is exempt: superseding asks its attempts to cancel, and they take their grace period. A function that reads the live state at commit, so a transaction may create, end and restart in any order. | `lease` section 9, 14 |
| `stage_runs_guard`: `not_before` changes only while the run is `READY` after the move | A back-off or a postponement belongs to a run that can be claimed. | `lease` section 10 |
| `stage_runs_guard`: an update that keeps the status changes only `not_before`, `max_attempts` and the bookkeeping columns | `postpone_stage_run` is "the only update of a stage run that is not a transition" (ports-v1.1). A raised budget stays allowed: the application role has that column grant, and the existing `terminal_rows` check shows it is deliberate. | `lease` section 10, `terminal_rows` |
| `stage_runs.attempts_before_last_answer integer NOT NULL DEFAULT 0 CHECK (>= 0)`, set by `stage_runs_guard` when a run moves `WAITING_FOR_HUMAN` to `READY` (S13) and by nothing else | INV-10 and `G_RETRY_ALLOWED` count the attempts since the last human answer. The old trigger counted all of them and would have refused the first attempt after an answer. The numbers of attempts keep rising; only the limit subtracts the window. No role has a column grant on it; a write by anyone else is refused. | `lease` section 8 |
| `attempts_insert_guard`: `attempt_number - attempts_before_last_answer <= max_attempts` (the constraint keeps its name `attempts_within_stage_run_limit`) | The same rule, at the row. | `lease` sections 2, 8 |
| `attempts_update_guard`: `sandbox_leaked` never goes from true to false, and `sandbox_id` never changes once set | `record_sandbox` (ports-v1.1): "`leaked` only rises". An attempt has one sandbox. The masked columns of the terminal guard still let both be written after the attempt ended. | `lease` section 13 |
| `attempts_epoch_check` reads the attempt as it stands at commit | The old function judged the row as it was when the event was queued; a transaction that created, ended and restarted would fail for an attempt that is no longer live. The rule is the same. | `lease` sections 8, 9 |
| Index `stage_runs_claim_order_idx (not_before, id) WHERE status = 'READY'`, replacing `stage_runs_claim_idx (not_before)` | `find_claim_candidates` promises `not_before` then `id`. Rows made in one transaction share `not_before`; the tie-break makes the order total and avoids an incremental sort. A superset of the old index, so code that ordered by `not_before` alone still uses it. | `plans` |

### Store model (migration 17)

| Rule | Why | Test |
|---|---|---|
| `stage_runs.failing_set_sha256 text`, `CHECK` hash form, `CHECK` only with the `FAILED` outcome (IS NOT NULL spelled out) | `GateRecord::failing_set_sha256` for the stagnation detector, a digest and not an artifact so that it is read without an artifact inside a transaction. A terminal run is frozen with it. | `store_model` section 1 |
| `stage_runs_blocked_has_outcome`: `BLOCKED` records the `BLOCKED` outcome | S11 and S21 both record it (`stage_run_effects_rule`). With `passed_has_outcome` and `skipped_has_outcome`, every status that the port ties to an outcome is tied in the data. The report hash is not forced by the database: the port types it optional because `NOT_APPLICABLE` has none. The adapter and the Store contract suite do force it for every other outcome (ADR 0014, amendment 1). | `store_model` section 1 |
| `repositories.bypass_attested_by_principal_id`, `bypass_attested_at` (nullable); `CHECK` both or neither; composite foreign key `(tenant_id, bypass_attested_by_principal_id)` to `principals`; trigger `repositories_attestation_guard` | ADR 0014, decision 7: the attestation that the App is on no bypass list, by an organization admin. The trigger requires an active human principal of the tenant, stamps `bypass_attested_at` from the database clock (the port's rule that times come from the database), clears it with the attestor, and keeps it when something else changes. | `store_model` section 2 |
| `repositories.project_map_commit`, `project_map_attested_by_principal_id`, `project_map_attested_at` (nullable); `CHECK repositories_project_map_commit_check` (40 lowercase hexadecimal characters); `CHECK repositories_project_map_attestation_complete` (all three or none); composite foreign key to `principals`; `CHECK repositories_enabled_needs_project_map` (`NOT enabled OR project_map_commit IS NOT NULL`); trigger `repositories_project_map_guard`; `enabled` defaults to `false` | ADR 0016, item 1: a repository takes tickets only after a person attested the commit that holds its project map. The invariant is in the table, so it holds for the owner and a superuser too. The trigger requires an active human principal of the tenant as the attestor and stamps the time from the database clock. The map is a statement by a person: nothing in the database or in the engine looks at the repository. Migration `2026-11-02-002400` switches off every repository that was enabled before, because none has a map; it writes no audit record. | `repository_map` |
| `repositories.enabled_project_map_commit`, `enabled_by_principal_id`, `enabled_at` (nullable); `CHECK repositories_enabled_project_map_commit_matches` (a recorded commit exists only while enabled and equals `project_map_commit`); `CHECK repositories_enabled_record_is_complete` (commit and time together, the person only with a commit, a record for every enabled row); composite foreign key `repositories_enabled_by_fkey` to `principals`; the same trigger `repositories_project_map_guard`, which also sets `enabled` to false when an enabled repository's map commit or attestor changes, fills the record when `enabled` turns true, requires an active human principal of the tenant as the enabler, stamps `enabled_at` from the database clock, and empties the record when `enabled` turns false | REG-1 of the [security review](../reviews/engine-registration-and-status-security-review.md): attesting another map must not leave a repository enabled for a map nobody enabled it for. The rule is in the table so a writer that skips the API cannot skip it, and the two CHECK constraints are the second guard behind the trigger. The enabler may state the commit it means, and the table then holds it to the commit on file. Migration `2026-11-02-002500` switches off every repository that was enabled, because none has a record of what it was enabled for; it writes no audit record. | `repository_map` section 10 |
| `task_nodes_running_has_attempt`, `task_nodes_idle_has_no_attempt` (`PENDING`, `READY`, `FAILED`), `task_nodes_commit_iff_succeeded` | `TaskNodeEffects`: the attempt is set on T02 and cleared on T04 and T05, the commit is required on T03. | `store_model` section 3 |
| Trigger `jobs_bump_guard` replaces `bump_guard` on `jobs`: moving only `ledger_head_sequence` and `ledger_head_hash` may leave the version where it is (a raise by one is still accepted); the head never moves back | `append_ledger_entry` returns the chain head and no version; `transition_job` takes the version the caller read. If an append raised the version, every transition after an append in the same transaction would be a `Conflict`. The fake store has always behaved as this does. A decision for a person: ADR 0008 says the head moves "with the same compare-and-swap as any other state". The chain stays linear without it: the primary key and the key to the predecessor of `ledger_entries` allow one entry at each position. | `store_model` section 4, `ledger` |
| Grants: the tenant role may `UPDATE` `failing_set_sha256` and the two attestation columns. The system role holds nothing new | The tenant role writes these through `transition_stage_run` and the repository operations. The system role finds work and writes nothing; the `rls` suite lists its grants column by column. | `privileges`, `rls`, `store_model` |

### Listings (migration 18)

| Rule | Why | Test |
|---|---|---|
| Index `jobs_repository_listing_idx (tenant_id, repository_id, created_at DESC, id DESC)` | `list_jobs` with a repository filter. Measured without it: a bitmap scan of every job of the tenant and a sort (400 of 2,000 rows read to return one page of one repository); the cost followed the tenant's history. Also the index behind the foreign key to `repositories`. | `plans` |
| No other new index | The other listings and probes were measured and already use an index (`query-plans.md`, "Listings and the other operations of ports v1.1"). The edges of a task graph are read through their nodes, so an index on `task_node_dependencies (tenant_id, stage_run_id)` would be written for every edge and read by no plan. | `plans` |

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
| INV-10 bounded attempts | `attempts_insert_guard`, counted since the last human answer through `stage_runs.attempts_before_last_answer`. Rework rounds are counted by the engine. | `lease` |
| INV-11 documentation stages come after review | Not in the database. | |

## Decisions that need a person

1. **`UNIQUE (tenant_id, body_sha256)` on `webhook_deliveries`.** It closes a replay hole that the delivery id alone leaves open, and it assumes two different legitimate deliveries never have byte-identical bodies. GitHub payloads carry ids and timestamps, so this should hold, but it is an assumption. The alternative is to rely on the semantic key alone.
2. **The platform tenant** (`00000000-0000-0000-0000-000000000001`) that owns audit events with no tenant. The other choice is to let `audit_events.tenant_id` be null, which would break the per-tenant chain.
3. **The one-hour bound on a lease** and the **16 KiB limit on an outbox payload.** Both are generous sanity limits, set here because the policy gives no figure. Change them by migration.
4. **A ledger append does not raise the job's version** (migration 17). It differs from the wording of ADR 0008 and is needed because `append_ledger_entry` returns no version while `transition_job` compares one. The alternative is a port that returns the version from an append; this one was chosen because it matches the fake store and keeps the chain's safety in the keys of `ledger_entries`.
5. **The attempt limit counts since the last human answer** (migration 16), as INV-10 says, through a column the database derives when a person answers (S13). The alternative is to count the `human-answer-<n>` inputs of `stage_run_artifacts`; the column is cheaper to read and cannot be edited by the application.
6. **A run that is not `RUNNING` has no live attempt** (migration 16). `SUPERSEDED` is the one exception. If the engine ever needs a state that keeps an attempt alive (a graceful cancel of a run in `CANCELLED`), the check names the states in one place.
