#!/usr/bin/env bash
# scripts/e2e.sh - the end-to-end acceptance harness of the Slice 1 proof.
#
# It builds and runs the harness in tests/end_to_end (scenarios E1 to E13 and the assertions A1 to
# A14) and the contract checks of the fixture repository in tests/contract. The harness never
# passes a scenario it could not run: a missing prerequisite is BLOCKED, with exit code 3.
#
# USAGE
#   scripts/e2e.sh --list                       List the scenarios.
#   scripts/e2e.sh --scenario ID [--scenario ID ...] [--test-mode] [--wiring W] [--evidence-dir D]
#                  [--judge-only]
#                                               Run scenarios. E1 and E2 need real adapters: they
#                                               run through the composed wiring program
#                                               (FACTORY_E2E_COMPOSED, by default
#                                               scripts/e2e-composed.sh) in subscription mode, and
#                                               are BLOCKED until what the owner provides is there;
#                                               each missing item is looked for and named
#                                               (docs/guides/first-real-run.md). --test-mode runs
#                                               them on the scripted wiring, labelled as test mode
#                                               with fakes.
#                                               E3 to E9 are driven through the real composed
#                                               pipeline in test mode (the test
#                                               apps/api/tests/e2e_scenarios.rs, which needs a
#                                               PostgreSQL server), which writes a recording under
#                                               fixtures/recordings/e2e/ID, and the harness then
#                                               judges the recording. --judge-only skips the first
#                                               step and judges the recordings that are there.
#                                               W is auto (default), scripted, composed or recorded.
#   scripts/e2e.sh --self-test                  Prove the assertions: the canned passing evidence
#                                               passes, and each corrupted copy fails the
#                                               assertion that guards it.
#   scripts/e2e.sh --self-test-blocked          Prove that a missing prerequisite is BLOCKED (3).
#   scripts/e2e.sh --self-test-preflight        Prove that a remote that fails the protection
#                                               preflight is BLOCKED and that nothing runs on it.
#   scripts/e2e.sh --self-test-report           Prove that the report check fails on a report
#                                               that claims PASSED with no recording, with a
#                                               recording that changed, or with BLOCKED naming
#                                               nothing, and accepts an honest one.
#   scripts/e2e.sh --self-test-all              The four self tests above.
#   scripts/e2e.sh --check-fixture              Build and test the fixture on the host and in the
#                                               pinned verify image, and check that its gap is open.
#   scripts/e2e.sh --check-fixture-host         The same, on the host only.
#   scripts/e2e.sh --check-report [PATH]        Check the acceptance report against its recordings.
#   scripts/e2e.sh --check-readability PATH...  Run the readability gate of the factory over
#                                               Markdown documents. Exit 1 when a rule that blocks
#                                               is broken.
#   scripts/e2e.sh --help                       Show this text.
#
# EXIT CODES
#   0  Everything that was asked passed.
#   1  Something failed.
#   2  The script was used wrongly.
#   3  BLOCKED: something could not run, so there is no evidence either way. It is never a pass
#      and never skipped.
#
# The build output goes to target/e2e in the repository (git ignores target). Set CARGO_TARGET_DIR
# to use another place.

set -uo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SELF_DIR/.." && pwd -P)
TARGET=${CARGO_TARGET_DIR:-$ROOT/target/e2e}
export CARGO_TARGET_DIR=$TARGET

EXIT_FAILED=1
EXIT_USAGE=2
EXIT_BLOCKED=3

err() { printf 'e2e.sh: %s\n' "$*" >&2; }

usage_error() {
  err "$*"
  err "Run scripts/e2e.sh --help for the usage text."
  exit "$EXIT_USAGE"
}

show_help() {
  sed -n '2,/^set -uo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

blocked() {
  printf 'BLOCKED: %s\n' "$*"
  exit "$EXIT_BLOCKED"
}

need_cargo() {
  type -P cargo >/dev/null 2>&1 ||
    blocked "cargo is not installed. Install Rust with rustup (https://rustup.rs); rust-toolchain.toml selects the pinned version."
}

# Builds one standalone cargo project under tests/ and its binary.
build() { # build DIRECTORY BINARY
  local dir=$1 bin=$2
  need_cargo
  if ! (cd "$ROOT/tests/$dir" && cargo build --locked --bin "$bin" 2>&1 | tail -n 5 >&2; exit "${PIPESTATUS[0]}"); then
    err "tests/$dir does not build"
    exit "$EXIT_FAILED"
  fi
}

e2e_bin() { printf '%s/debug/e2e' "$TARGET"; }
fixture_bin() { printf '%s/debug/check-fixture' "$TARGET"; }

run_e2e() {
  build end_to_end e2e
  "$(e2e_bin)" "$@"
}

# The variables a real run reads. They are cleared for the test that shows BLOCKED.
REAL_VARIABLES=(
  FACTORY_E2E_COMPOSED
  FACTORY_E2E_SUBSCRIPTION_TOKEN_FILE
  FACTORY_E2E_JOB_BUDGET_USD
  FACTORY_E2E_GITHUB_APP_ID
  FACTORY_E2E_GITHUB_APP_KEY_FILE
  FACTORY_E2E_FIXTURE_REPO
  FACTORY_E2E_REQUESTER_ALLOWLIST
)

self_test_blocked() {
  build end_to_end e2e
  local rc=0 output
  "$(e2e_bin)" blocked-self-test || rc=$?
  [ "$rc" -eq 0 ] || return "$rc"
  # The command line itself: with nothing in the environment, E1 exits with 3 and says BLOCKED.
  local -a clear=()
  local name
  for name in "${REAL_VARIABLES[@]}"; do clear+=(-u "$name"); done
  output=$(env "${clear[@]}" "$(e2e_bin)" run --scenario E1 2>&1)
  rc=$?
  printf '%s\n' "$output"
  if [ "$rc" -ne "$EXIT_BLOCKED" ]; then
    err "E1 with no prerequisite exited with $rc, and it must exit with 3"
    return "$EXIT_FAILED"
  fi
  case $output in
    *BLOCKED*) ;;
    *)
      err "E1 exited with 3 but printed no BLOCKED line"
      return "$EXIT_FAILED"
      ;;
  esac
  printf 'PASS the command line exits with 3 and prints BLOCKED when nothing is set up\n'
  return 0
}

# The scenarios whose recording the composed pipeline makes in test mode.
COMPOSED_TEST_SCENARIOS=(E3 E4 E5 E6 E7 E8 E9)

# Drives the scenarios of E3 to E9 that were asked for through the real composed pipeline and
# writes their recordings. Exit 3 (BLOCKED) when no PostgreSQL server can be had, 1 when a
# scenario could not be driven to the end.
record_scenarios() { # record_scenarios ID...
  local -a filters=()
  local id lower
  for id in "$@"; do
    lower=$(printf '%s' "$id" | tr '[:upper:]' '[:lower:]')
    filters+=("scenario_${lower}_")
  done
  need_cargo
  printf '== recording %s through the composed pipeline (real engine, API, worker hook and PostgreSQL; labelled fakes)\n' "$*"
  local log
  log=$(mktemp "${TMPDIR:-/tmp}/e2e-record.XXXXXX")
  local rc=0
  (
    cd "$ROOT" || exit 1
    FACTORY_E2E_RECORD_DIR="$ROOT/fixtures/recordings/e2e" \
      CARGO_TARGET_DIR="${FACTORY_E2E_WORKSPACE_TARGET:-$ROOT/target}" \
      cargo test -p factory-api --locked --test e2e_scenarios -- "${filters[@]}" --test-threads=1 --nocapture 2>&1
  ) >"$log" 2>&1 || rc=$?
  grep -E '^(RECORDED|test |test result)' "$log" | sed 's/^/  /'
  if [ "$rc" -ne 0 ]; then
    if grep -q 'BLOCKED: no PostgreSQL' "$log"; then
      printf 'BLOCKED: %s\n' "no PostgreSQL server could be had for the recording of $* (set FACTORY_DB_ADMIN_URL, install PostgreSQL 16 or later, or start Docker); nothing was recorded and nothing was judged"
      rm -f "$log"
      exit "$EXIT_BLOCKED"
    fi
    err "the recording of $* failed (cargo exit code $rc); the end of its output follows"
    tail -n 40 "$log" >&2
    rm -f "$log"
    exit "$EXIT_FAILED"
  fi
  rm -f "$log"
}

# Picks the scenarios of E3 to E9 out of the arguments of a run, unless the run is something other
# than the composed pipeline (a test-mode run of E1, an explicit scripted or composed wiring).
composed_ids_of() { # composed_ids_of ARGS...
  local -a ids=()
  local wiring=auto test_mode=0
  while [ "$#" -gt 0 ]; do
    case $1 in
      --scenario) ids+=("$2"); shift ;;
      --wiring) wiring=$2; shift ;;
      --test-mode) test_mode=1 ;;
    esac
    shift
  done
  [ "$test_mode" -eq 0 ] || return 0
  case $wiring in auto | recorded) ;; *) return 0 ;; esac
  local id known
  for id in ${ids[@]+"${ids[@]}"}; do
    for known in "${COMPOSED_TEST_SCENARIOS[@]}"; do
      [ "$id" = "$known" ] && printf '%s\n' "$id"
    done
  done
}

check_fixture() { # check_fixture MODE...
  build contract check-fixture
  "$(fixture_bin)" "$@"
}

main() {
  [ "$#" -gt 0 ] || usage_error "give one of the modes; see --help"
  local -a run_args=()
  local mode=""
  local judge_only=0
  while [ "$#" -gt 0 ]; do
    case $1 in
      --help | -h)
        show_help
        exit 0
        ;;
      --list | --self-test | --self-test-blocked | --self-test-preflight | --self-test-report | --self-test-all | --check-fixture | --check-fixture-host)
        [ -z "$mode" ] || [ "$mode" = "$1" ] || usage_error "give one mode, not $mode and $1"
        mode=$1
        ;;
      --check-report | --check-readability)
        mode=$1
        shift
        run_args+=("$@")
        break
        ;;
      --scenario | --wiring | --evidence-dir)
        [ "$#" -ge 2 ] || usage_error "$1 needs a value"
        [ -z "$mode" ] || [ "$mode" = "--run" ] || usage_error "give one mode, not $mode and $1"
        mode=--run
        run_args+=("$1" "$2")
        shift
        ;;
      --test-mode)
        [ -z "$mode" ] || [ "$mode" = "--run" ] || usage_error "give one mode, not $mode and $1"
        mode=--run
        run_args+=("$1")
        ;;
      --judge-only)
        [ -z "$mode" ] || [ "$mode" = "--run" ] || usage_error "give one mode, not $mode and $1"
        mode=--run
        judge_only=1
        ;;
      *) usage_error "unknown argument '$1'" ;;
    esac
    shift
  done

  case $mode in
    --list) run_e2e list ;;
    --self-test) run_e2e self-test ;;
    --self-test-blocked) self_test_blocked ;;
    --self-test-preflight) run_e2e preflight-self-test ;;
    --self-test-report) run_e2e report-self-test ;;
    --self-test-all)
      local rc=0 step
      for step in --self-test --self-test-blocked --self-test-preflight --self-test-report; do
        printf '== %s\n' "$step"
        "$0" "$step" || rc=$?
        [ "$rc" -eq 0 ] || exit "$rc"
      done
      ;;
    --check-fixture) check_fixture --host --image ;;
    --check-fixture-host) check_fixture --host ;;
    --check-report) run_e2e check-report ${run_args[@]+"${run_args[@]}"} ;;
    --check-readability) run_e2e readability ${run_args[@]+"${run_args[@]}"} ;;
    --run)
      if [ "$judge_only" -eq 0 ]; then
        local -a composed=()
        local composed_id
        while IFS= read -r composed_id; do
          [ -z "$composed_id" ] || composed+=("$composed_id")
        done < <(composed_ids_of ${run_args[@]+"${run_args[@]}"})
        if [ "${#composed[@]}" -gt 0 ]; then
          record_scenarios "${composed[@]}"
        fi
      fi
      run_e2e run ${run_args[@]+"${run_args[@]}"}
      ;;
    *) usage_error "give one of the modes; see --help" ;;
  esac
}

main "$@"
