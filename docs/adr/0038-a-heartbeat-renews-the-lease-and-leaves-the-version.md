# 0038: A heartbeat renews the lease and leaves the attempt's version alone

- Status: **Decided by the owner on 2026-11-26**; the engineer found the cause and wrote the options. No independent review has covered it.
- Date: 2026-11-26
- Deciders: the owner chose among four options after the evidence of the failing test.
- Related: [for the storage crate](../database/for-the-storage-crate.md) ("Renew a lease"), [performance](../database/performance.md) (section 6), PR #18 and #20 (the failing liveness test).

## Context and problem statement

The worker test `a_cancel_recorded_while_an_attempt_runs_ends_that_attempt_as_cancelled` failed in 3 of 6 GitHub CI runs of PR #18. Each time the job was still active after 8 seconds. The evidence the test now prints (PR #20) showed the cancel watch called the decision hook 4 times, the longest call took 2.4 seconds, and the audit log held the request and no marker. A request with no marker is one the hook left for later.

The cause is a race between two writers of the same row:

1. Cancelling a job (`Engine::control`, then `settle` and `cancellation_round`) reads the running attempt and moves it to `CANCELLING` with a compare and swap on its `version` (`transition_attempt`, `WHERE ... version = $3`).
2. The attempt's heartbeat ran `UPDATE attempts SET lease_expires_at = ..., last_heartbeat_at = now(), version = version + 1` (`crates/storage/src/pg/attempts.rs`).
3. A heartbeat that committed while the cancel's transaction was open made the cancel fail with `Conflict`. The hook turned every engine error other than a refusal into `Verdict::Later`, with no log, and tried again at its next pass with a new transaction.

The test's heartbeat runs every 500 ms. Under the CI's load one cancel took up to 2.4 s, so almost every try met a heartbeat and the cancel never got through. In production the heartbeat runs every 15 s, so the same race delays a cancel instead of stopping it, unless the database is slow.

The bump had a stated reason: "a heartbeat raises `version`, so a stale move by the sweeper fails its compare and swap and reads again". But the sweeper's move of a lapsed lease (A07) already checks `lease_expires_at < now()` by the database clock in the same `UPDATE`, and a heartbeat can never renew a lapsed lease. The in-memory store of `factory-testkit` never bumped the version on a heartbeat.

## Considered options

1. **The heartbeat leaves `version` alone** (chosen). `version` counts changes of state. The lease is fenced by its owner and epoch, and the sweeper's lapse by the database clock.
2. **The cancel locks the attempt row before it reads it** (`SELECT ... FOR UPDATE`). No conflict, but a new store method, and a slow cancel would hold the heartbeat up to the lock timeout of 5 s.
3. **The engine retries `control` at once on `Conflict`.** The smallest change, but under load the race stays, only less often.
4. **Wait longer in the test.** It hides a real defect.

## Decision

- `heartbeat` runs `UPDATE attempts SET lease_expires_at = ..., last_heartbeat_at = now()` and no longer changes `version`. The `WHERE` clause and the answers (`Conflict` for an ended attempt, `LeaseFenced` otherwise) are unchanged.
- `version` of an attempt changes only with its state: a transition, a sandbox record, the start.
- The database enforced the bump: `bump_guard` refuses any update that does not raise `version` by exactly one. Migration 33 (`2026-11-26-003300_lease_renewal_keeps_the_version`) puts `attempts_bump_guard` on `attempts` in its place, as migration 17 did for the ledger head of `jobs`: an update that changes only `lease_expires_at` and `last_heartbeat_at` may keep the version, a raise by one is still accepted (the earlier code's renewal), and every other update must still raise it by exactly one.
- The sweeper keeps its own guard: its moves of a lapsed lease, a passed deadline and a passed teardown deadline are allowed only when the database clock says that time has passed (`$13`, `$14`, `$15` of `transition_attempt`).
- The decision hook logs, at `warn`, why it leaves a request for a later pass (a store error, an unreadable source, an engine conflict). Before, that was silent.

## Consequences

- Good: a cancel, or any other versioned move of a running attempt, no longer races its heartbeat.
- Good: the real store and the in-memory store of the tests agree.
- Good: a request left for later says why in the worker's log.
- Neutral: a heartbeat changes two columns, not three. Section 6 of [performance](../database/performance.md) measured the statement with the bump; the numbers are not measured again.
- Bad: nothing that reads `version` sees a heartbeat any more. The search for such a reader found none: the engine reads an attempt again before it moves it, and the sweeper is guarded by the clock.

## What was checked

- The storage tests of leases and claims (`crates/storage/tests/claims_and_leases.rs`), the store contract and tenant isolation.
- The worker suite, including the liveness test with its evidence, and the engine and composition tests.
- A new storage test: a heartbeat between a read and a move of the attempt leaves the move's compare and swap valid.
- The SQL suites of `scripts/db-test.sh`, with a new `lease` section: a renewal keeps the version, a renewal that also changes another column must raise it, and the earlier code's renewal is still accepted.
- Not measured: the heartbeat's throughput without the bump.
