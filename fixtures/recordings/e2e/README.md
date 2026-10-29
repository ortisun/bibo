# Recordings of the end-to-end scenarios in test mode

These directories are what the composed pipeline left when `scripts/e2e.sh --scenario E3` (and E4 to E9) drove a scenario through the real engine, the real API server, the worker's hook and a real PostgreSQL, with the labelled fakes that each `mode.json` lists. No model was called and nothing cost anything.

Nobody edits these files by hand. The command writes them again, and the harness judges them: the assertions read `evidence.json`, and a manifest of hashes catches a file that changed after the run. The acceptance report ([`docs/reports/slice-1-acceptance.md`](../../../docs/reports/slice-1-acceptance.md)) cites the digest of each manifest, so a report and a recording that disagree fail `scripts/e2e.sh --check-report`.

The files in a recording, and the checks the harness makes before it trusts one, are described in [`tests/end_to_end/README.md`](../../../tests/end_to_end/README.md) under "Recordings of the composed pipeline".

A recording is not a real run. A scenario that is defined for real adapters (E1 and E2) has no recording here, because it has not run.
