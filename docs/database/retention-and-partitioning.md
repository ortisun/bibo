# Retention and partitioning: a proposal for the outbox, the ledger and the artifact metadata

- Status: proposal of the work package `s1-database-review`, written 2026-10-28. **Nothing in this page is built.** It rests on a growth estimate (assumptions listed below), on measured sizes of the synthetic data, and on prototypes that ran on a scratch cluster (`scripts/db-perf.sh --prototype partitions`, the lines starting `proto |` are quoted in the tables). It needs the software architect and, for the ledger and the audit log, the security specialist.
- Form: explanation and decision record in the making.
- Decides nothing alone. Section 6 lists the decisions that belong to a person.

## 1. Short version

| | Slice 1 | Later, and only when a trigger in section 5 is met |
|---|---|---|
| **Outbox** | Keep everything. Add the size and age to the monitoring. | Prune published events older than a retention period with a maintenance role, in batches of 5,000. Not by partitioning: the table's keys forbid it (C1). First settle a contradiction between two documents: ADR 0004 calls the outbox "the long-term record". |
| **Ledger** | Keep everything, online, unpartitioned. Write the archive format and the checkpoint rule down now, so the first archive is not invented under pressure. | Partition by range of `job_id`, which is time ordered, so a whole chain stays in one partition; export, verify, detach and drop closed ranges. This needs three changes to the schema first, each proved by a prototype (A1, A15 to A22). |
| **Audit log** | Keep everything. | A per-tenant chain cannot be cut by time. It can be cut by sequence range per tenant (B5), with a checkpoint row at each cut. Same prerequisite as the ledger: the link to the predecessor must stop being a foreign key. |
| **Artifact metadata** | Keep everything. It is 5 percent of the bytes. | Do not partition. Mark `retention_class` and collect blobs by hash with a grace period. |
| **`webhook_deliveries`** | Add the 30 day trim that `policies/security.yaml` already requires. | The same maintenance role. |

What the repository's own rules forbid, and the proposal respects: no role may update or delete a ledger or audit row, the owner included (trigger); each row names its predecessor by hash; a job's head points at a real entry.

## 2. How much data, per job

The repository does not state volumes. These are estimates from the state machine (`docs/architecture/state-machine.json`), for a **completed job with the full pipeline of 14 stages and the rework the policy allows** (a factor of 1.3 on stage runs). The bytes per row are measured: heap, indexes and TOAST of the synthetic data at 100,000 rows ([performance.md](performance.md)). The synthetic ledger entry holds about 1.2 KB of canonical JSON; the schema allows 256 KiB, so a ledger that stores evidence inline would be several times larger.

| Table | Rows per job | Why | Bytes per row (measured) | KB per job | Share |
|---|---:|---|---:|---:|---:|
| `outbox` | 134 | 2 job events; 4 per stage run (ready, started, gating, passed) times 18 runs; 2 per attempt (running and a result) times 21; 3 per task node times 6 | 1,148 | 150 | 37% |
| `ledger_entries` | 40 | between 2 and 3 per stage: the gate result and the evidence it names | 2,624 | 103 | 26% |
| `audit_events` | 50 | about 3 per stage: start, result, decision; plus intake and approval | 1,677 | 82 | 20% |
| `artifacts` | 58 | one output per attempt (21), a gate report and a stage contract per run (36), a few documents | 353 | 20 | 5% |
| `stage_run_artifacts` | 45 | 2.5 links per run | 401 | 18 | 4% |
| `attempts`, `stage_runs`, `jobs`, task nodes, approvals, requests, deliveries | 59 | | 300 to 1,543 | 30 | 8% |
| **Total** | **386** | | | **403** | |

Projection (a job is counted once, when it finishes; an active job holds a fraction):

| Jobs | All tables | Outbox | Ledger | Audit log | Artifact metadata |
|---:|---:|---:|---:|---:|---:|
| 1,000 | 0.41 GB | 134,000 rows, 0.15 GB | 40,000 rows, 0.10 GB | 50,000 rows, 0.08 GB | 58,000 rows, 0.02 GB |
| 10,000 | 4.1 GB | 1.34 million rows, 1.5 GB | 400,000 rows, 1.1 GB | 500,000 rows, 0.8 GB | 580,000 rows, 0.2 GB |
| 100,000 | 41 GB | 13.4 million rows, 15 GB | 4 million rows, 10.5 GB | 5 million rows, 8.4 GB | 5.8 million rows, 2 GB |

What this says. Three tables hold 83 percent of the bytes. At 10,000 jobs the whole database fits in memory on a small server and a dump takes seconds (the 20,000 row test database, 170 MB, dumped in 1 to 2 s and restored in 3 to 4 s). Nothing needs partitioning for performance in Slice 1 or Slice 2: the measured queries are far inside their budgets at 100,000 rows of every table ([performance.md](performance.md)), and an index lookup grows with the logarithm of the table. The first real pressure is operational and arrives with the 100,000 job column: backup and restore time (about 16 minutes to restore at the measured rate, a guess from a straight line), the size of a point-in-time archive, and the time of `VACUUM` on the outbox.

## 3. What each table's rules allow

| Table | Delete? | What stands in the way | Who could do it |
|---|---|---|---|
| `ledger_entries` | Never in place | `BEFORE UPDATE OR DELETE` trigger for every role (A19). Foreign keys that point in: the next entry names this one by `(tenant, job, sequence, hash)`; the job's head names the last one (deferred). | Nobody. An archive moves whole chains out by detaching a partition. |
| `audit_events` | Never in place | The same trigger. The next event names this one. The chain is per tenant. | Nobody. |
| `outbox` | Yes, once published | The application role has no `DELETE`. The system role may update `published_at` and `publish_attempts` only. Nothing references an outbox row. ADR 0004 line 48 says "The `outbox` table, not JetStream, is the long-term record." | A new maintenance role (C3 to C5). |
| `artifacts` | Only a row nothing points at | Six foreign keys from jobs, stage runs, attempts, task nodes and links, all without `ON DELETE`. A row is deletable only after every row that names it is gone, which in practice means with its job. | The same role, later. |
| `webhook_deliveries` | The unreferenced ones, after 30 days | `jobs.webhook_delivery_id` names the delivery that created a job. Three unique keys give the replay protection, and `policies/security.yaml` fixes 30 days for the first and the third. | The same role. |
| Blobs of the artifact store | Yes | Shared by hash across tenants. A blob is written **before** its index row (ADR 0008), so a blob without a row may be a write in progress. | A collector (section 4.4). |

## 4. The proposals

### 4.1 Outbox

**Slice 1: nothing.** 134 rows per job is 13,400 rows per 100 jobs. The relay query is a partial index of the unpublished rows, so its cost follows the backlog, not the history: p50 0.15 ms at 100,000 rows. A relay drained a backlog of 22,000 rows in 5.3 s with one client and 0.8 s with sixteen, with no event published twice (the table in performance.md).

**Retention when needed.** Published events older than N days are deleted by a role that can do nothing else.

```sql
CREATE ROLE factory_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT SELECT (seq, tenant_id, published_at), DELETE ON outbox TO factory_maintenance;
CREATE POLICY maintenance_find  ON outbox FOR SELECT TO factory_maintenance USING (published_at IS NOT NULL AND published_at < now() - interval '30 days');
CREATE POLICY maintenance_prune ON outbox FOR DELETE TO factory_maintenance USING (published_at IS NOT NULL AND published_at < now() - interval '30 days');
-- and a login in that group, on its own pool, that no process of the factory shares
```

Tried (`proto | C3` to `C5`): the role sees only the rows it may prune, a delete of unpublished events removes none, and 32,373 rows went in batches of 5,000 in 0.5 s. `FORCE ROW LEVEL SECURITY` binds the owner too, so the policy has to be written; a role without one deletes nothing.

**Why not partition the outbox.** `proto | C1`: `PARTITION BY RANGE (created_at)` with the primary key `(tenant_id, event_id)` is refused ("unique constraint on partitioned table must include all partitioning columns"). The idempotent enqueue (`ON CONFLICT` on that key) and the unique key `(tenant, aggregate, version)` both need to be global. Adding `created_at` to them would make an event id unique only within a day, which is a different guarantee. A queue with a 30 day life and a fast `DELETE` has no need of `DROP PARTITION`.

**The open contradiction.** ADR 0004 says the outbox is the long-term record. If that stays true, pruning must **archive first**: export the batch as lines of JSON with a checksum to the artifact store, record the range `(first seq, last seq, sha256)` in a manifest row, then delete. If the architect decides that the ledger and the audit log are the long-term record and the outbox is a stream, the archive step goes. This is decision D1 in section 6.

### 4.2 Ledger

**Slice 1: nothing.** What to prepare now costs only text.

**The chain per job makes the job the unit.** A chain never crosses a job, and `jobs.ledger_head_sequence` and `ledger_head_hash` already hold the head of every chain. That row is a **checkpoint that exists today**: when a job's entries are archived, the head on the job row is what the archive is verified against. No new checkpoint table is needed for the ledger, as long as the `jobs` row stays.

**Partition by range of `job_id`.** Job ids are time ordered (version 7), so ranges of `job_id` are ranges of creation time, and every entry of a job lands in the same partition because they share `job_id`. The primary key `(tenant_id, job_id, sequence)` already holds the partition key (A2). A tenant and job lookup prunes to one partition (A12); a query without the job scans them all (A13), which no query of the Store makes.

What the prototype found, in the order it matters:

| Finding | Evidence | What it requires |
|---|---|---|
| `UNIQUE (tenant_id, entry_id)` cannot exist on the partitioned table | A1: "unique constraint on partitioned table must include all partitioning columns" | Make it `UNIQUE (tenant_id, job_id, entry_id)`. `invalidates` only names entries of the same job (the trigger checks it), so the guarantee that matters is kept. |
| The guard trigger does not run on a partitioned copy as written | A15: `function public.ledger_document_matches(proto_ledger_p0) does not exist`. The function is declared on the row type of `ledger_entries`. | Rewrite `ledger_document_matches` and the verifier to take the columns, or pass `jsonb_populate_record(NULL::ledger_entries, to_jsonb(NEW))`. Tried (A16): a good append is accepted, a wrong hash is refused. Small, and it touches the function that defines what a valid entry is, so it needs the security specialist. |
| Row-level security on the parent covers every query through the parent | A6, A7, A8: tenant 1 sees its 17,705 rows, a tenant 2 session asking for tenant 1's job sees none, no setting sees none. A9: the application role cannot read a partition directly because it holds no grant. | Nothing. |
| **A grant on a partition bypasses the parent's policy** | A10: with `SELECT` granted on one partition and no policy there, a tenant 2 session read 7,294 rows of other tenants. A11: with `ENABLE`, `FORCE` and its own policy on the partition the same read returns 0. | Every partition gets `ENABLE ROW LEVEL SECURITY`, `FORCE` and the policy, in the same statement that creates it; the `rls` suite already finds tables with a tenant column from the catalog and would flag a partition without them. A later `GRANT ... ON ALL TABLES` must not reach partitions. |
| **Neither archive nor drop is possible while the two foreign keys that point into the ledger exist** | A17: `DETACH PARTITION` is refused, "violates foreign key constraint ...prev_sequence_prev_entry_has_fk". A18: `DROP TABLE` refused, other objects depend on it. A19: `DELETE` is stopped by the trigger. A20: still refused after the job head key is removed; the **self reference** (each entry names the one before) is what blocks it. A21 and A22: with both keys gone, the detach is accepted and 7,649 entries stand alone. A23: they verify among themselves. | Replace the two keys by checks that need no foreign key: the link to the predecessor by a `BEFORE INSERT` check that the entry before exists with that hash (the guard trigger already looks the neighbours up for `invalidates`); the job head by a check made when the head moves. The cost is that PostgreSQL stops guaranteeing the link for rows that are already stored; the verifier and the archive checks take over. |
| Adding the first partitioned table moves a lot | `rls`, `tenancy`, `privileges` and the catalog fingerprint suites all list tables by name | They need updating in the same pull request. |

**The archive, when needed.** For each closed range of `job_id` (every job in it terminal for more than N months):

1. Verify every chain in the range with `ledger_verify_chain`, and compare each last hash with `jobs.ledger_head_hash`.
2. Export the range to the artifact store as lines of JSON (`canonical_json` and the columns), with a manifest: tenant, job, count, first and last sequence, last hash, and the SHA-256 of the file. Store the manifest hash in an anchored copy outside the database (the external anchor of `policies/security.yaml` is not built yet; the archive should wait for it, or for an agreed substitute).
3. Verify the export with the external tool (`docs/database/tools/` has the audit counterpart; a ledger one is to be written).
4. `DETACH PARTITION`, then drop it. Dropping a table is not stopped by the append-only triggers (they stop row changes), and the owner can do it: it stays an owner action, as the weak points list in [not-covered.md](not-covered.md) already says.
5. Keep `jobs`, `stage_runs`, `attempts` and the head of each chain. A reader who needs the entries asks the archive.

### 4.3 Audit log

The chain is per tenant, hashed under a tenant lock, with the primary key `(tenant_id, sequence)`.

| Try | Evidence | Result |
|---|---|---|
| By time, `RANGE (created_at)` | B1 | Refused: the key lacks the column. A time cut is impossible without changing the key to include `created_at`, which would make `(tenant, sequence)` no longer unique by itself. |
| By tenant, `HASH (tenant_id)` | B2 to B4 | Works. Plans prune to one partition, the trigger and the policy work through the parent, every chain verifies. It spreads tenants; it does not help retention. |
| By sequence range per tenant, `RANGE (tenant_id, sequence)` | B5 to B8 | Works. The big tenant's chain can be cut at sequence numbers, every other tenant sits in a default partition. The tail query of a cut tenant becomes a `Merge Append` over its partitions. |

Archiving a prefix of one tenant's chain has the same two obstacles as the ledger (the self reference), plus one more: the next event after the cut names the last archived event by hash. A **checkpoint** is needed that says "events 1 to N are gone, the hash of event N is H, the archive file has this SHA-256", and the verifier has to accept a chain that starts at a checkpoint. Today `audit_verify_chain` starts at sequence 1 and would report the first remaining row as a gap. So the audit archive needs: a table `audit_checkpoints (tenant_id, up_to_sequence, up_to_hash, archive_sha256, archived_at)` written by a role that can write only that; a verifier that starts from the newest checkpoint; and the external anchor. **Not for Slice 1 or 2.** At 500,000 events (10,000 jobs, 0.8 GB) there is nothing to gain.

### 4.4 Artifact metadata and blobs

The metadata is 353 bytes per row, 58 rows per job: 20 KB per job. Partitioning by `HASH (tenant_id)` works and the composite foreign keys into it are accepted (D1, D3), but it buys nothing at 5.8 million rows. **Do not partition.**

`artifacts.retention_class` exists, default `'standard'`, and nothing reads it. Proposed meaning (for the architect to confirm): `evidence` is kept as long as the ledger entries that cite it; `working` (raw model transcripts, intermediate diffs) may go a set number of days after its job ends.

Blob collection, by hash, across tenants:

1. A collector with a read-only policy on `artifacts (content_sha256)` for all tenants (it learns hashes, never content) lists the hashes that still have at least one row.
2. A blob is deleted when no row names its hash **and** it is older than a grace period longer than the longest time between writing a blob and committing its index row (ADR 0008 writes the blob first). A day is ample today; the number should come from the artifact store's own timeouts.
3. A tenant's metadata row is removed only with its job. Until jobs can be archived (section 4.2), no metadata row is ever removed, and the collector only frees blobs of failed or abandoned writes.

### 4.5 `webhook_deliveries`

Policy: 30 days for the delivery id and the semantic key. After 30 days a delivery that created no job can go (a duplicate or a rejected one). One that created a job is named by the job and stays, or the job's column is cleared by the same role. Same maintenance role, same batch size.

## 5. When to act

Start from measurement, not from a calendar. Each trigger has a number that the harness can produce again (`scripts/db-perf.sh`):

| Trigger | Action |
|---|---|
| The database exceeds 20 GB, or a full restore exceeds the recovery time the operator accepts | Start the outbox pruning (and the archive of the outbox if D1 says so), then the ledger archive design. |
| A tail or timeline query of the ledger passes its 5 ms budget at the real table size (harness, `ledger_tail`, `ledger_timeline`) | Check the plan first (bloat, statistics); partition only if the index no longer fits in memory. |
| `VACUUM` of `outbox` takes longer than its interval | Pruning, then partition-free: more frequent small deletes. |
| The first tenant asks to leave and take or delete its data | The per-tenant partition of the audit log and the ledger (hash or range by tenant) becomes the way to hand over or drop one tenant. This needs a decision about deleting an append-only record, which the repository has not made. |

## 6. Decisions for a person

| # | Decision | Who | Why it cannot wait forever |
|---|---|---|---|
| D1 | Is the outbox the long-term record (ADR 0004) or a stream whose record is the ledger and the audit log? | software_architect | It decides whether pruning needs an archive. |
| D2 | May an append-only record ever be removed from the live database, once it is archived and anchored? How long must it stay online? | software_architect, security | It decides whether sections 4.2 and 4.3 are ever built. |
| D3 | The retention period of the outbox, of deliveries (30 days is set) and of working artifacts | product_owner | A number the policy does not give. |
| D4 | Who owns the external anchor and when it is built | security | The archive of the ledger and the audit log needs it first. |
| D5 | The guarantee that replaces the two foreign keys of the ledger, and who reviews the rewritten guard function | security | Section 4.2, rows 2 and 5. |

## 7. What not to do in Slice 1

- Do not partition anything. No table is near a size where it helps, and the first partitioned table costs a rewrite of the guard function, a new unique key and an update of five suites.
- Do not delete a ledger or audit row, and do not add a `DELETE` grant, a policy or a role for it. `TRUNCATE ... CASCADE` reaches the trigger, but only because the trigger exists; do not rely on it.
- Do not drop a foreign key of the ledger or the audit log to make room for an archive. Replace it with a tested check first.
- Do not give a maintenance role `BYPASSRLS`. Write its policies, as the system role's are written.
- Do not run a collector over the blob store before the grace period is a number someone chose.
- Do not install `pg_partman` or any extension for this.

## 8. What was not tried

The prototypes ran on 30,000 rows per table, one machine. Not tried: partition pruning at hundreds of partitions; the cost of `DETACH` and `DROP` on a partition of several gigabytes; replication or backup of a partitioned table; a partition boundary crossed by an in-flight transaction; the planner's behaviour for the system role (which has policies of its own) on a partitioned table; and the hash chain across an archive and a restore. The ledger prototype copied the rows with the triggers off; the append path was exercised through the parent (A15, A16).
