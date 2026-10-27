# 0008: Store artifacts by content hash and record claims in a hash-chained, append-only evidence ledger

- Status: Accepted
- Date: 2026-10-27
- Deciders: software_architect (database enforcement belongs to the DBA, integrity review to security)
- Related: [ADR 0007](0007-persistence-access-and-tenancy.md), [`evidence-ledger-entry` schema](../../schemas/evidence-ledger-entry.schema.json), [state machines](../architecture/state-machine.md)

## Context and problem statement

The V6 standard says a stage cannot succeed because an agent says so, and that every important claim is bound to a test, trace, artifact, source, benchmark, experiment, code location or named expert judgment. It also asks for immutable artifact snapshots with content hashes, invalidation of downstream work when upstream changes, and a clear line between measured facts, simulation results, assumptions and hypotheses. The master prompt (section 1) wants large artifacts in S3-compatible storage addressed by hash, with metadata in PostgreSQL and immutable audit events.

Two decisions follow. Where do artifact bytes live, and what makes the record of claims trustworthy?

## What we checked

- `serde_jcs` 0.2.0 (crates.io, updated 2026-03-25, MIT or Apache-2.0) describes itself as a JSON Canonicalization Scheme implementation for Serde. JCS is RFC 8785. We have not tested it, in particular on number handling.
- Nothing else: this ADR is a design with no experiment behind it. Hash chains and content-addressed stores are well-known patterns, but the specific database constraints below have not been run.

## Considered options

For artifact bytes:

1. **Content-addressed blobs behind an `ArtifactStore` port**, local filesystem in Slice 1, S3-compatible (MinIO) in Slice 2.
2. **Blobs in PostgreSQL** (`bytea` or large objects). One system and transactional with the rest. Bloats the database, and logs and diffs can be large.

For the record of claims:

1. **Mutable status rows with an audit trigger.** Simple to query. The record can be edited, and the audit trigger is only as trustworthy as the database role.
2. **An append-only ledger with a per-job hash chain.** Edits and removals are detectable, and withdrawing a claim is itself a recorded fact.
3. **Event-source the whole system on the ledger.** A larger change than the problem needs.

## Decision outcome

Chosen: blobs behind a port (option 1), and an append-only hash-chained ledger (option 2).

### Artifacts

- A blob is addressed by `sha256:<64 hex>`. `put` is idempotent and never overwrites. `get` re-hashes and fails on mismatch.
- The Slice 1 adapter is `LocalFsArtifactStore` under a configured directory, laid out as `sha256/ab/cd/<hash>`, written to a temporary file in the same directory, flushed, then renamed, and made read-only. It is labelled as the `local-fs` backend in the metadata. It is not S3, and no document may call it that. The S3-compatible adapter is a Slice 2 work item. Both implement the same port.
- Metadata is a PostgreSQL row per tenant and hash (size, media type, creating stage run, retention class). Blobs are shared by hash, but access always goes through the tenant's metadata row, so one tenant cannot learn that another holds a given blob.
- Logs and transcripts pass through a redactor before `put`. The redaction rules are `security`'s.

### The ledger

- One entry per claim, validated by the `evidence-ledger-entry` schema. Entries for a job form a chain: `entry_hash` is the SHA-256 of the previous entry's hash text (empty for the first entry), a newline, and the RFC 8785 canonical JSON of the entry without its `entry_hash`. Entries hold no floating-point numbers by design, which sidesteps canonicalization pitfalls with numbers.
- **Append only.** The application role has no `UPDATE` or `DELETE` on the table, and a trigger raises on both as a second layer (invariant INV-09).
- **Continuity.** The primary key is `(job_id, sequence)` and a foreign key from each entry's predecessor makes gaps impossible. The job row holds the head `(sequence, hash)` and is updated with the same compare-and-swap as any other state, so two concurrent appends cannot both claim the next position.
- **Withdrawing a claim** appends a new entry whose `invalidates` names the old ones. A claim is current if no later entry invalidates it. Assurance levels are derived from current claims whose recording component had fidelity `real` (invariants INV-07 and INV-08). A view over current claims is the DBA's deliverable.
- **Verification.** `storage` checks the previous hash on every append. A verifier recomputes the whole chain, and the engine runs it before taking `J13` (complete the job). The delivery stage also writes the chain head into the evidence manifest placed in the pull request body.

### What the chain does and does not give

It makes silent edits, deletions and reordering detectable by anyone who holds an earlier head hash. It does not stop someone with write access to the whole table from recomputing the chain from the start. The mitigations are the separate writer role, the head hash copied into the pull request and later into signed attestations, and a periodic export of the head. Signing is out of scope for Slice 1 and listed as a gap.

### Consequences

- Good: claims are checkable years later, withdrawal is explicit, and the fake-versus-real label is part of the record.
- Good: the artifact port hides the filesystem-to-S3 move.
- Bad: ledger writes serialize per job through the job row. That is fine at our concurrency and would need revisiting only if a single job produced entries at a high rate.
- Bad: tamper evidence is not tamper prevention, as above.
- Bad: local filesystem storage is a single-host store. Losing the disk loses the blobs, while the ledger would still show which hashes are missing. Backups of the artifact directory are an `sre` item for Slice 1.
- Neutral: canonical JSON hashing ties entries to one canonicalization library. A change of library must prove byte-identical output on a fixture set.

## Pros and cons of the options

**Blobs by hash behind a port**: deduplication, cheap integrity checks, a clean path to S3. Needs garbage collection later.

**Blobs in PostgreSQL**: simplest operations. Heavy for large logs, and backup size follows.

**Mutable rows with audit**: easy queries, weak evidence.

**Hash-chained ledger**: stronger evidence, slightly more write logic.

## Confirmation

- Slice 0: the DBA's tests that `UPDATE`, `DELETE` and a gapped insert fail on the ledger.
- Slice 1: a storage test that appends concurrently to one job and ends with a continuous, verifiable chain; a test that flips one byte in a stored entry and sees the verifier fail; an artifact test that corrupts a blob and sees `get` fail.
- Slice 1 end-to-end: the ledger of the fixture run verifies, and the head hash in the pull request body equals the stored head.
