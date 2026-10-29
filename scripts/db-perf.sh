#!/usr/bin/env bash
# scripts/db-perf.sh - measure the hot queries at realistic volume, as the real login roles, with row-level security on.
#
#   scripts/db-perf.sh                                 100,000 rows per hot table; prints a table, exit 0 when every verdict passes
#   scripts/db-perf.sh --rows 20000 --quick            a smoke run in about a minute
#   scripts/db-perf.sh --report out.json --markdown out.md
#   scripts/db-perf.sh --break superuser               the harness must refuse (exit 4): it will not report numbers from a superuser
#   scripts/db-perf.sh --break chain                   a ledger entry is damaged after the load; the verification must refuse (exit 4)
#   scripts/db-perf.sh --break drop-index=NAME         drops an index the series depend on; the report must show the regression (exit 1)
#   scripts/db-perf.sh --help                          every option
#
# It starts a scratch PostgreSQL cluster of its own (127.0.0.1, a high random port, no unix socket, passwords made at run
# time, never written to the repository), loads deterministic synthetic data, measures, and removes the cluster. It does
# not touch any other database or any other PostgreSQL process. The method, the numbers and what they do not show are in
# docs/database/performance.md.
#
# Exit codes: 0 pass, 1 a verdict failed, 2 bad usage, 3 BLOCKED (PostgreSQL binaries or Python missing), 4 REFUSED.

set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v python3 >/dev/null 2>&1 || { echo "BLOCKED: python3 is not installed" >&2; exit 3; }
exec python3 -I "$ROOT/scripts/db-perf/perf.py" "$@"
