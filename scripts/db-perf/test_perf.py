#!/usr/bin/env python3
"""Unit tests for the pure parts of the database performance harness. Standard library only; no database.

    python3 -I scripts/db-perf/test_perf.py

The harness itself is tested by its deliberate breaks (scripts/db-perf.sh --break ...), which need a PostgreSQL server;
see docs/database/performance.md.
"""

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("perf", HERE / "perf.py")
assert spec is not None and spec.loader is not None
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)


class IdentifierMirror(unittest.TestCase):
    # The two values were produced by the SQL functions perf.uid and perf.sha on PostgreSQL 18.6.
    def test_uid_equals_the_sql_function(self):
        self.assertEqual(perf.uid("job", 123), "00000000-007b-7e3f-8194-e9e16befc602")

    def test_sha_equals_the_sql_function(self):
        self.assertEqual(perf.sha("out", 7), "sha256:89f1911731b9b613f7b9b6a190ad947706ffd82ba5f7241af3dbd3b8357c0bb5")

    def test_uids_sort_in_creation_order(self):
        ids = [perf.uid("job", n) for n in (1, 2, 255, 256, 70000)]
        self.assertEqual(ids, sorted(ids))


class Statistics(unittest.TestCase):
    def test_percentiles_interpolate(self):
        values = [float(v) for v in range(1, 101)]
        self.assertAlmostEqual(perf.pct(values, 50), 50.5)
        self.assertAlmostEqual(perf.pct(values, 95), 95.05)

    def test_summary_of_nothing_is_empty(self):
        self.assertEqual(perf.summarize([]), {"n": 0})

    def test_summary_orders_p50_p95_max(self):
        s = perf.summarize([1.0, 2.0, 3.0, 4.0, 100.0])
        self.assertLessEqual(s["p50"], s["p95"])
        self.assertLessEqual(s["p95"], s["max"])
        self.assertEqual(s["n"], 5)


class Statements(unittest.TestCase):
    def test_literals_replace_the_longer_placeholder_first(self):
        text = perf.literal_sql("SELECT $1, $10, $2", ["a"] + ["x"] * 8 + ["z"])
        self.assertEqual(text, "SELECT 'a', 'z', 'x'")

    def test_integers_stay_integers_and_quotes_are_doubled(self):
        self.assertEqual(perf.literal_sql("LIMIT $1", ["10"]), "LIMIT 10")
        self.assertEqual(perf.literal_sql("WHERE a = $1", ["it's"]), "WHERE a = 'it''s'")

    def test_psql_parameters_keep_backslashes_literal(self):
        self.assertEqual(perf.psql_param("\\xdeadbeef"), "'\\\\xdeadbeef'")

    def test_every_series_has_a_budget_and_a_source(self):
        for s in perf.series_catalogue():
            self.assertGreater(s.budget_ms, 0, s.id)
            self.assertTrue(s.rust, s.id)
            self.assertTrue(s.steps, s.id)

    def test_series_ids_are_unique(self):
        ids = [s.id for s in perf.series_catalogue()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_a_script_has_one_set_of_commands_per_iteration(self):
        series = next(s for s in perf.series_catalogue() if s.id == "ledger_tail@big")
        pool = [{"tenant_id": "t", "job_id": "j"}]
        script, prelude, per = perf.build_script(series, pool, 3, "perfdb_worker", "separate")
        self.assertEqual(script.count("BEGIN;"), 3)
        self.assertEqual(script.count("COMMIT;"), 3)
        self.assertEqual(prelude, 2 + len(series.steps))
        self.assertEqual(per, 2 + 2 + len(series.steps))  # BEGIN, set tenant, set limits, the steps, COMMIT
        self.assertIn("1 / (NOT r.rolsuper", script, "the guard must come first")

    def test_the_guard_comes_before_any_timed_command(self):
        series = next(s for s in perf.series_catalogue() if s.id == "claim_candidates")
        script, _, _ = perf.build_script(series, [{}], 1, "perfdb_engine", "separate")
        self.assertLess(script.index("rolsuper"), script.index("\\timing on"))

    def test_the_harness_statements_still_appear_in_the_rust_source(self):
        self.assertEqual(perf.source_drift(), [])

    def test_a_statement_that_left_the_source_is_reported(self):
        perf.DRIFT["crates/storage/src/pg/ledger.rs"].append("A STATEMENT THAT IS NOT THERE")
        try:
            self.assertEqual(len(perf.source_drift()), 1)
        finally:
            perf.DRIFT["crates/storage/src/pg/ledger.rs"].pop()


class Arguments(unittest.TestCase):
    def test_unknown_break_is_refused(self):
        with self.assertRaises(SystemExit):
            perf.parse_args(["--break", "nonsense"])

    def test_known_breaks_are_accepted(self):
        for b in ("superuser", "chain", "drop-index=stage_runs_claim_order_idx"):
            self.assertEqual(perf.parse_args(["--break", b]).break_, b)


if __name__ == "__main__":
    unittest.main()
