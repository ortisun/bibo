#!/usr/bin/env bash
# scripts/e2e-composed.sh - the composed wiring program of the end-to-end harness.
#
# scripts/e2e.sh runs it for the real scenarios E1 and E2 (it is the program FACTORY_E2E_COMPOSED
# names, and the default when that variable is not set). It honours the contract of
# tests/end_to_end/README.md, "Wirings":
#
#   scripts/e2e-composed.sh protection     Print the protection of the fixture's default branch,
#                                          read through the factory's GitHub App, as one JSON object.
#   scripts/e2e-composed.sh run E1         Drive the scenario against GitHub and the owner's Claude
#                                          subscription and print the evidence as one JSON object.
#   scripts/e2e-composed.sh --help         Show this text.
#
# Both commands run an ignored test of apps/api/tests/real_e2e.rs, which holds the real run
# (apps/api/tests/real/mod.rs says what in it is real). When something the run needs is missing,
# it prints one line "BLOCKED: <reason>" for each item on standard error and exits with code 3.
#
# What it reads (the owner provides the first four; docs/guides/first-real-run.md says how):
#   FACTORY_E2E_GITHUB_APP_ID, FACTORY_E2E_GITHUB_APP_KEY_FILE, FACTORY_E2E_FIXTURE_REPO,
#   FACTORY_E2E_REQUESTER_ALLOWLIST
#   FACTORY_E2E_SUBSCRIPTION_TOKEN_FILE   default ~/claud-oauth-token.txt
#   FACTORY_E2E_JOB_BUDGET_USD            optional; lowers the job budget of the routing policy
#   FACTORY_E2E_HUMAN_WAIT_MINUTES        optional; how long one decision may wait (default 240)
#   FACTORY_DB_ADMIN_URL                  optional; the PostgreSQL server the run's private database
#                                         is made on (otherwise a private cluster is started)
#
# What it writes: everything under target/e2e-real/<command>-<time>/ (and target/e2e-real/latest):
#   answer.json      what the command printed
#   blocked.txt      the reasons it could not run, one per line
#   next-step.txt    what the run asked the owner to do, with the exact factory-cli commands
#   owner-api-token  the owner's token for the run's own API (mode 600; that database is thrown away)
#   recording/E1/    the evidence, ledger, timeline, gate reports and their hashes (run only)
#   run.log          the output of the test
#
# Exit codes: 0 done, 1 failed, 2 wrong usage, 3 BLOCKED.

set -uo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SELF_DIR/.." && pwd -P)

usage() {
  sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

blocked() {
  printf 'BLOCKED: %s\n' "$@" >&2
  exit 3
}

command=${1:-}
case $command in
  --help | -h)
    usage
    exit 0
    ;;
  protection)
    test_name=the_protection_of_the_fixture_repository
    label=protection
    ;;
  run)
    scenario=${2:-}
    case $scenario in
      E1 | E2) ;;
      *)
        printf 'e2e-composed.sh: run takes E1 or E2, not "%s"\n' "$scenario" >&2
        exit 2
        ;;
    esac
    test_name=the_real_scenario
    label=$scenario
    ;;
  *)
    printf 'e2e-composed.sh: give protection or run E1|E2 (see --help)\n' >&2
    exit 2
    ;;
esac

# The owner's four items, named before anything is built.
missing=()
for name in FACTORY_E2E_GITHUB_APP_ID FACTORY_E2E_GITHUB_APP_KEY_FILE FACTORY_E2E_FIXTURE_REPO; do
  [ -n "${!name:-}" ] || missing+=("$name is not set (docs/guides/first-real-run.md)")
done
if [ "$command" = run ] && [ -z "${FACTORY_E2E_REQUESTER_ALLOWLIST:-}" ]; then
  missing+=("FACTORY_E2E_REQUESTER_ALLOWLIST is not set (docs/guides/first-real-run.md)")
fi
[ "${#missing[@]}" -eq 0 ] || blocked "${missing[@]}"
type -P cargo >/dev/null 2>&1 || blocked "cargo is not installed"

stamp=$(date -u +%Y%m%dT%H%M%SZ)
base="$ROOT/target/e2e-real"
out="$base/$label-$stamp"
mkdir -p "$out" || exit 1
ln -sfn "$out" "$base/latest"
log="$out/run.log"

# The owner takes each decision with factory-cli; the run prints the commands with its path.
cli="$ROOT/target/debug/factory-cli"
if [ "$command" = run ]; then
  (cd "$ROOT" && cargo build --locked -p factory-cli) >>"$log" 2>&1 || {
    printf 'e2e-composed.sh: factory-cli does not build; see %s\n' "$log" >&2
    exit 1
  }
fi

rc=0
(
  cd "$ROOT" || exit 1
  FACTORY_E2E_OUT="$out" \
    FACTORY_E2E_SCENARIO="${scenario:-}" \
    FACTORY_E2E_CLI="$cli" \
    cargo test --locked -p factory-api --test real_e2e -- \
    --ignored --exact "$test_name" --nocapture --test-threads=1
) >>"$log" 2>&1 || rc=$?

if [ -s "$out/blocked.txt" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] || printf 'BLOCKED: %s\n' "$line" >&2
  done <"$out/blocked.txt"
  exit 3
fi
if [ "$rc" -eq 0 ] && [ -s "$out/answer.json" ]; then
  cat "$out/answer.json"
  exit 0
fi
# A test that stopped with a BLOCKED panic of the rig (no PostgreSQL, a missing image).
if grep -q 'BLOCKED:' "$log"; then
  grep -o 'BLOCKED: [^"]*' "$log" | sort -u >&2
  exit 3
fi
printf 'e2e-composed.sh: the %s command failed (cargo exit code %s); the end of %s follows\n' "$label" "$rc" "$log" >&2
tail -n 30 "$log" >&2
exit 1
