-- s1-database-review: make a lease renewal a heap-only update by dropping the one index that a renewal changes.
--
-- A heartbeat (AttemptOps::heartbeat) is the most frequent write of the factory: every live attempt renews its lease
-- every few seconds. It changes lease_expires_at, last_heartbeat_at and version. The partial index
-- attempts_lease_expiry_idx is keyed on lease_expires_at, so no renewal could be a heap-only (HOT) update: each one wrote
-- a new entry to every index of attempts that covers a live row (six of them) and left a dead tuple in the heap and in
-- each index for vacuum to remove.
--
-- Measured with scripts/db-perf.sh on 600 live attempts renewed by four clients for 20 seconds, then the same with the
-- index dropped (docs/database/performance.md, "Churn"):
--
--                                 with the index    without it
--   renewals that were heap-only        0.01 %         99.9 %
--   dead tuples left behind            325,278          1,063
--   index bytes after the run       20,209,664      6,881,280    (8,019,968 before)
--   sweeper, lease expired, p95          0.14 ms        0.18 ms   (alone, one client, 20,000 rows)
--
-- What the sweeper does instead. The query of find_due_attempts for an expired lease keeps its text:
--   WHERE status IN ('STARTING', 'RUNNING') AND lease_expires_at < now() ORDER BY lease_expires_at, id LIMIT n
--   FOR NO KEY UPDATE SKIP LOCKED
-- It now reads the live attempts through attempts_one_active_per_stage_run (the partial unique index on the live
-- statuses, which the query's predicate implies), filters on the lease and sorts the few that remain. The cost grows with
-- the number of LIVE attempts, which is bounded by the number of sandboxes running at once, and not with the history.
-- attempts_deadline_idx and attempts_teardown_idx stay: the columns they are keyed on do not change on a renewal.
--
-- Compatible with the earlier code (it changes a plan, not a statement). The down script puts the index back.

SET LOCAL lock_timeout = '5s';

DROP INDEX attempts_lease_expiry_idx;
