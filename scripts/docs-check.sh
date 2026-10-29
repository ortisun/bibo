#!/usr/bin/env bash
# scripts/docs-check.sh - check the factory's own documentation the way the factory checks the
# documents of others.
#
# The documents are README.md, docs/guides, docs/runbooks, docs/reference and docs/walkthroughs.
# The checks are written in Python (docs/reference/tools/docs_check.py). This file finds a Python
# and passes the arguments on.
#
# USAGE
#   scripts/docs-check.sh                    Every check below except --quickstart.
#   scripts/docs-check.sh --links            Relative links resolve (cargo xtask check-links).
#   scripts/docs-check.sh --snippets         Every shell block is marked run, quickstart or no-run
#                                            with a reason. Each run block executes and prints what
#                                            the page says.
#   scripts/docs-check.sh --commands         Every command, option, endpoint, verb and path that the
#                                            documents name exists in the real help output.
#   scripts/docs-check.sh --config-keys      Every configuration key and environment variable in the
#                                            code is documented and every documented one exists.
#   scripts/docs-check.sh --walkthrough      Every step of the walkthrough cites a recorded file or
#                                            ledger entry that holds what the step says.
#   scripts/docs-check.sh --readability      The readability gate reports nothing on these documents.
#   scripts/docs-check.sh --self-test        Each check fails on an input that is broken on purpose.
#   scripts/docs-check.sh --quickstart       Clone the repository into a scratch directory and run
#                                            the commands of docs/guides/quickstart.md. A step that
#                                            needs Docker or PostgreSQL is BLOCKED when it is not there.
#   scripts/docs-check.sh --refresh-walkthrough
#                                            Rewrite the ids and hashes of the ledger citations after
#                                            scripts/e2e.sh has written the recordings again.
#   scripts/docs-check.sh --help             Show this text.
#
# ENVIRONMENT
#   DOCS_CHECK_TARGET_DIR   The Cargo target directory that --quickstart uses. Without it the
#                           quickstart builds from nothing in its scratch directory.
#   DOCS_CHECK_KEEP         Keep the scratch clone of --quickstart, for a look at what went wrong.
#   CARGO_TARGET_DIR        Where the binaries for the other checks are built (Cargo's own variable).
#
# EXIT CODES
#   0  Every check that ran passed, and none was BLOCKED.
#   1  At least one check failed.
#   2  The script was used wrongly.
#   3  Nothing failed, and at least one check is BLOCKED: a tool is missing or does not answer, so
#      there is no evidence either way. BLOCKED is never counted as a pass.

set -uo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SELF_DIR/.." && pwd -P)
TOOL="$ROOT/docs/reference/tools/docs_check.py"

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
  exit 0
fi

if ! type -P python3 >/dev/null 2>&1; then
  printf 'BLOCKED: python3 is not installed, so no documentation check can run.\n' >&2
  exit 3
fi
if [ ! -f "$TOOL" ]; then
  printf 'docs-check.sh: %s is missing.\n' "$TOOL" >&2
  exit 2
fi

cd "$ROOT" || exit 2
DOCS_CHECK_ROOT="$ROOT" exec python3 -I "$TOOL" "$@"
