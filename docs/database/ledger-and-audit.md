# The evidence ledger and the audit log

- Status: baseline for Slice 0. Both tables, both verifiers and the tests named below exist. The external anchor (a copy of the chain head outside the database) does not.
- Form: explanation, with the exact hash formulas as reference.
- Source: [ADR 0008](../adr/0008-artifact-store-and-evidence-ledger.md), `policies/security.yaml` section `audit`, [threat model](../security/threat-model.md) T-31 and control C-37, negative tests NT-AUD-01 to NT-AUD-04.

## Two records with different jobs

| | Evidence ledger (`ledger_entries`) | Audit log (`audit_events`) |
|---|---|---|
| Records | Claims about the work: "the build gate passed on this commit", each bound to evidence. | Who did what and what the policy decided: a webhook accepted, a tool call denied, an approval granted. |
| Chain scope | One chain per job. | One chain per tenant. |
| Who computes the hash | The domain code, over RFC 8785 canonical JSON. The database recomputes it and refuses a mismatch. | The database, in a trigger. The caller cannot supply it. |
| Who sets the time | The caller (`recorded_at` is inside the hashed document). The database adds its own `inserted_at`. | The database clock only. |
| Used for | Assurance levels, gates, the evidence manifest in the pull request. | Accountability and incident review. |

## Why the database refuses to edit them

A record that its own writers can change proves little. Four layers apply to both tables:

1. **No grant.** The application role has `SELECT` and `INSERT` on both tables and nothing else, at table and column level, and sees only its own tenant's rows (row-level security). The system role has no access to either table. The `privileges` suite compares the full grant list with the expected one in both directions.
2. **A trigger.** `BEFORE UPDATE OR DELETE` and `BEFORE TRUNCATE` triggers raise SQLSTATE 42501 for every role, the owner included. This is the second layer behind the grant. The suites run `UPDATE`, `DELETE` and `TRUNCATE` as the application role (permission denied) and as the owner (the trigger).
3. **No change to the table.** The application role cannot `DROP`, `ALTER`, `DISABLE TRIGGER`, create a trigger, or create objects in the schema. It owns nothing.
4. **A chain.** Each row names its predecessor, so an edit, a deletion or a reordering by someone who got past the first three layers can be found afterwards.

PostgreSQL itself adds one more: a plain `TRUNCATE ledger_entries` fails with SQLSTATE 0A000 because foreign keys reference the table, before any trigger runs. `TRUNCATE ... CASCADE` reaches the trigger.

## The evidence ledger

### What the database checks on every insert

- **No gap, no fork, no forged link.** The primary key is `(tenant_id, job_id, sequence)`. A foreign key from `(tenant_id, job_id, prev_sequence, prev_entry_hash)` to the predecessor's `(tenant_id, job_id, sequence, entry_hash)` means an entry can only follow an entry that exists, with that exact hash. `prev_sequence` is set by the trigger to `sequence - 1`, so the caller cannot disagree with its own sequence. Sequence 1 has no predecessor, and every later entry must have one (`ledger_entries_first_has_no_predecessor`).
- **The hash is the hash of the document.** A trigger recomputes the hash from the stored `canonical_json` and the previous hash, and refuses the insert if `entry_hash` differs.
- **The columns say what the document says.** The function `ledger_document_matches` compares the queryable columns (entry id, job, stage run, attempt, sequence, time, execution mode, recorder component and fidelity, claim kind, assurance level, confidence, the invalidated entries and the previous hash) with the JSON. A column that disagrees with the hashed text is refused. The chain verifier uses the same function.
- **Fake evidence stays out of production** (invariant INV-08). Three CHECKs copy the rules of `evidence-ledger-entry.schema.json`: a fake or simulated recorder needs `execution_mode = 'test'`, an assurance level needs a real recorder, and an assumption or hypothesis carries no assurance level. A foreign key on `(tenant_id, job_id, execution_mode)` to the job means an entry marked `test` cannot join a `production` job at all.
- **Withdrawal names earlier entries.** `invalidates` must list distinct entries of the same job with a lower sequence.

### The hash formula

```text
entry_hash = "sha256:" + lowercase_hex( SHA-256( UTF-8( prev_entry_hash + "\n" + canonical_json ) ) )
```

- `prev_entry_hash` is the previous entry's whole `entry_hash` text, including the `sha256:` prefix. For entry 1 it is the empty string.
- `canonical_json` is the entry as RFC 8785 canonical JSON, without the `entry_hash` key and with the `prev_entry_hash` key (null for entry 1), as ADR 0008 describes.

ADR 0008 says "the previous entry's hash text". I read that as the full string with its prefix. If the domain code means the bare hex, one of the two has to change, and the first insert will fail loudly rather than quietly produce a different chain.

Two vectors computed outside PostgreSQL with Python's `hashlib`, which the `ledger` suite checks against the database function:

| `prev_entry_hash` | `canonical_json` | `entry_hash` |
|---|---|---|
| `sha256:` followed by 64 letters `a` | `{"claim":{"kind":"assumption","statement":"Café ü ß gate"},"schema_version":1}` | `sha256:0f5f57aa591430b785ee073cdf1ac6e09932ee15965755ae728714f00e2bc7c3` |
| empty | the same text | `sha256:9f563e281c5bf7065d0ead6194d1e3140cee4610b140dc82263618a4d2302520` |

### What the database does not check

It hashes the text it is given. It does not check that the text is RFC 8785 canonical, or that the entry satisfies the JSON Schema (for example that a `measured_fact` has test evidence). The domain code does both before it calls the store. The Rust verifier in `s1-storage-postgres` should recompute canonical form and check the schema, which the database verifier cannot.

### The job head

`jobs.ledger_head_sequence` and `jobs.ledger_head_hash` hold the head, as ADR 0008 asks. A deferred foreign key makes the pair point at a real entry of that job. The engine moves the head with the append. Since migration 17 a move of the head alone may leave the job's version where it is (a move together with any other change still raises the version by one), because `append_ledger_entry` returns no version and a later `transition_job` compares the one it read; the head never moves back. ADR 0008 says the head moves "with the same compare-and-swap as any other state"; the chain is linear without it, because the primary key of `ledger_entries` and the key to the predecessor allow one entry at each position. This is a decision for a person. A writer that appends without moving the head leaves the head behind, which the verifier reports.

### Appending concurrently

Two writers that both compute entry `n + 1` race on the primary key. The second waits for the first, then fails with a unique violation (SQLSTATE 23505). The `ledger` suite runs eight sessions on one position and gets one winner, seven refusals and a chain that verifies. The storage layer can either retry on the violation or take `SELECT ... FOR NO KEY UPDATE` on the job row first, to serialize writers. Use `FOR NO KEY UPDATE` and not `FOR UPDATE`: the foreign keys of every ledger, audit and outbox insert take a `KEY SHARE` lock on the job and the stage run, and `FOR UPDATE` blocks them. The `lease` suite measures this, see [for-the-storage-crate.md](for-the-storage-crate.md).

### Withdrawing a claim and deriving assurance

A withdrawal appends an entry whose `invalidates` names the old ones. `ledger_current_claims` lists the entries no later entry withdraws. `ledger_assurance_levels` lists, per job, the assurance levels supported by current claims from a recorder with fidelity `real`. The levels are a set, not a ladder, as `state-machine.json` says.

### Verifying a chain

`SELECT ledger_verify_chain(tenant, job)` returns the sequence of the first bad entry, or NULL when the chain is sound. It finds a gap, a broken link, a hash that does not match its stored document, columns that disagree with the document, and a job head that does not match the last entry. When the head is 0 and entries exist, it returns 0: the chain is intact and nobody has set the head. The `ledger` suite tampers as a superuser (with triggers off) and checks that each of these is found at the right entry.

## The audit log

### What the database assigns

The application inserts the event id, actor type and id, action, subject, decision, reason, policy hash, job and stage run if any, and correlation id. A `BEFORE INSERT` trigger then overwrites the rest, whatever the caller supplied (NT-AUD-04):

- `sequence`: the next number in the tenant's chain, starting at 1;
- `created_at`: `clock_timestamp()`, the database clock;
- `prev_sequence`, `prev_hash`: the last row of the tenant;
- `canonical_json`: the text that is hashed;
- `hash`: `sha256:` plus the hex of SHA-256 over `prev_hash`, a newline and `canonical_json`, using the same rule as the ledger.

The required fields of the policy (actor, policy hash, correlation id) are `NOT NULL`, and the policy hash must be a `sha256:` value. An event written when no policy could be loaded has no real hash to record. The all-zero hash passes the format check, and I suggest using it for that case so readers can recognise it as "no policy loaded". That convention is not written down anywhere else yet.

### The canonical text

One JSON object, fifteen keys in alphabetical order, no whitespace, strings escaped as JSON requires, `created_at` as UTC with microseconds and a `Z`, `sequence` as an integer, absent values as `null`:

```text
{"action":...,"actor_id":...,"actor_type":...,"correlation_id":...,"created_at":...,"decision":...,"event_id":...,"job_id":...,"policy_hash":...,"prev_hash":...,"reason":...,"sequence":...,"stage_run_id":...,"subject":...,"tenant_id":...}
```

Every value is a string, `null` or an integer, so PostgreSQL's JSON string escaping and a standard library's agree. This is the form the policy's `hash_chain` calls "canonical_event_json". It is not claimed to be RFC 8785 for arbitrary input. The `audit` suite checks it from outside: it writes an event full of quotes, a backslash, control characters, a bell, a delete character, accented text, a snowman, an astral-plane character and U+2028, then [`tools/verify_audit_chain.py`](tools/verify_audit_chain.py) rebuilds the canonical text from the columns with Python's `json` module and recomputes every hash. They agree on 41 events.

### One writer at a time per tenant

The trigger takes `pg_advisory_xact_lock` on the tenant before it reads the last row. That keeps the chain gapless and unforked. The cost is that two transactions that both write audit events for one tenant take turns, and the lock lasts until the writer's transaction ends. So a transaction should write its audit events last, just before it commits, and should not hold a long transaction open after writing one. The suite runs eight concurrent writers with five events each and gets 40 rows numbered 1 to 40.

The tests use the default `READ COMMITTED` isolation, as ADR 0007 sets. I did not test stricter levels. By reasoning, under `REPEATABLE READ` the trigger could read a stale last row, and the primary key would then refuse the duplicate sequence, so the chain would stay sound and the writer would get an error.

### Verifying a chain

`SELECT audit_verify_chain(tenant)` returns the first sequence with a gap, a broken link, a stored text that differs from its columns, or a hash that differs from its text, and NULL when sound. `tools/verify_audit_chain.py` does the same from a JSON export, with no PostgreSQL function involved. The hourly verification job in the policy should use the Python or Rust form against an export, so it does not trust the function that lives in the database being checked.

## What the chains do not give

- **A superuser, or anyone who can disable triggers, can rewrite a whole chain.** Setting `session_replication_role = replica` turns the triggers and the foreign keys off. The `ledger` and `audit` suites do exactly this to prove the verifiers notice partial tampering. Rewriting every row from the point of the edit forward, with fresh hashes, makes a consistent chain that passes both verifiers. Only a copy of the head outside the database exposes it.
- **Deleting rows from the end is not found by `audit_verify_chain`.** The remaining prefix is a sound chain. The `audit` suite has a test that states this limit. The external anchor (an hourly copy of the head hash to an object store with a retention lock, `audit.external_anchor` in the policy) is what catches it. It is not built.
- **The verifiers read under the caller's row-level security policy.** `audit_verify_chain(tenant)` and `ledger_verify_chain(tenant, job)` run with the rights of the caller. A session set to tenant 1 that asks about tenant 2 reads no row, and the audit verifier answers NULL, which is also the answer for a sound chain (the `rls` suite shows it). The verification job must run in a transaction that made the setting for the tenant it checks, or as a role with a policy of its own, and must treat a NULL from a session set to another tenant as no answer. Under `FORCE ROW LEVEL SECURITY` the owner role sees no row either, so a check run as the owner reads nothing.
- **The owner can `DROP TABLE`.** An event trigger could prevent that, but creating one needs superuser rights, and it would interfere with migrations. The mitigation is operational: nobody uses the owner role at run time, and migrations run from a deploy step.
- **Nothing here stops the application from recording false claims.** The ledger makes a claim durable and checkable. Whether the claim is true is for the gates and the reviewers.

## Requests for the people who build on this

1. Make the domain's hash function reproduce the two vectors above, and write the test first.
2. Decide whether `prev_entry_hash` in the formula is the prefixed string (what is implemented) or the bare hex.
3. Build the external anchor and the hourly verifier before the second tenant, and keep the anchor in a different account from the database.
