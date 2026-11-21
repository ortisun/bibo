#!/usr/bin/env bash
# scripts/ci.sh - the one script that runs every check in this repository.
#
# Developers run it on their laptops and the CI workflow runs the same file, so a result on
# a laptop and a result in CI cannot drift apart. The workflow (.github/workflows/ci.yml)
# installs tools and then calls this script. It holds no check logic of its own.
#
# USAGE
#   scripts/ci.sh                     Run every step. Print a summary table. The last line of
#                                     output is one line of JSON with the outcome of each step.
#   scripts/ci.sh --list              List the steps and the tools each one needs.
#   scripts/ci.sh --only ID[,ID...]   Run only these steps. The result is marked PARTIAL and
#                                     must not be used as evidence that CI passed.
#   scripts/ci.sh --json-file PATH    Also write the JSON summary to PATH.
#   scripts/ci.sh --self-test         Prove that this script itself behaves as described here.
#                                     The parts: --self-test-blocked, --self-test-failed,
#                                     --self-test-dropin, --self-test-no-secrets,
#                                     --self-test-pinning and --self-test-compose.
#   scripts/ci.sh --help              Show this text.
#
# WHAT EACH STEP CAN REPORT
#   PASSED          The check ran and succeeded.
#   FAILED          The check ran and found a problem. The build is broken.
#   BLOCKED         The check could not run, so there is no evidence either way. A tool is
#                   missing or does not start, a file the check needs is missing, or the network
#                   needed to fetch data was unreachable. BLOCKED is never counted as a pass.
#   NOT_APPLICABLE  The check does not apply, and the reason is printed. For example, there are
#                   no Mermaid diagrams to check. A missing tool is never NOT_APPLICABLE.
#
# EXIT CODES
#   0  Every step PASSED or was NOT_APPLICABLE.
#   1  At least one step FAILED. (FAILED wins over BLOCKED, because a defect we saw is more
#      useful to report than a gap. The JSON line still counts both.)
#   2  The script was used wrongly, or a step definition is broken. Nothing was run.
#   3  No step FAILED, but at least one is BLOCKED. This code is the same one that
#      fixtures/readability/check_corpus.py uses for "could not run".
#
# A step that needs a tool you do not have is reported as BLOCKED with a plain-English reason
# and an install hint. It is never skipped and never passed. There is no switch to skip a step.
# scripts/setup-tools.sh installs the pinned tools into .tools/bin in the repository, and this
# script puts that folder first on the PATH when it exists (FACTORY_TOOLS_PREFIX names another
# folder; its bin/ is used then).
#
# HOW A LATER WORK PACKAGE ADDS A STEP WITHOUT EDITING THIS FILE
#   Put a file named scripts/ci/steps.d/NN-name.step in the repository. Each line is
#   "key = value". Blank lines and lines that start with # are ignored.
#
#     id              Short name: lower-case letters, digits and hyphens. Must be unique.
#     title           One line that says what the step checks.
#     requires        Space-separated tools that must be on PATH. Missing means BLOCKED.
#     blocked_codes   Extra exit codes that mean BLOCKED. Exit code 3 always does.
#     applies_if_path A glob, relative to the repository root. If nothing matches, the step is
#                     NOT_APPLICABLE and the reason says so.
#     run             The command. It is split on spaces and run directly, with no shell, so
#                     quotes, pipes and "$(...)" have no special meaning. Use a script for
#                     anything more complex.
#
#   Example, scripts/ci/steps.d/40-docs-check.step:
#     id       = docs-check
#     title    = Documentation checks pass
#     requires = python3
#     run      = scripts/docs-check.sh
#
#   A malformed file stops the whole run with exit code 2. It is never ignored. A step file runs
#   repository code with the permissions of whoever runs this script, so scripts/ci/ is a
#   protected path (policies/security.yaml, gate_and_toolchain_config) and has code owners.
#
# A step has no time limit of its own. CI sets a limit on the whole job. Locally, press Ctrl-C.
#
# This script works with the bash that ships with macOS (3.2) and with bash 4 and 5.

set -uo pipefail

SELF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SELF="$SELF_DIR/$(basename "${BASH_SOURCE[0]}")"
ROOT=$(cd "$SELF_DIR/.." && pwd -P)
DEFAULT_STEPS_DIR="$ROOT/scripts/ci/steps.d"
SUMMARY_SCHEMA="factory-ci-summary/1"

EXIT_FAILED=1
EXIT_USAGE=2
EXIT_BLOCKED=3

# ---------------------------------------------------------------------------------------------
# Tool versions that CI installs. They live in scripts/lib/tool-pins.sh, which
# scripts/setup-tools.sh reads too, so the checks and the installer name the same versions. The
# workflow pins the same numbers (the tool-pins step compares them). A person who installs a
# different version gets a different result at their own risk, and the version actually used is
# recorded in the output and in the JSON line.
# ---------------------------------------------------------------------------------------------
TOOL_PINS_FILE="$SELF_DIR/lib/tool-pins.sh"
if [ ! -f "$TOOL_PINS_FILE" ]; then
  printf 'ci.sh: %s is missing; it names the versions of the tools.\n' "$TOOL_PINS_FILE" >&2
  exit "$EXIT_USAGE"
fi
# shellcheck source=lib/tool-pins.sh
. "$TOOL_PINS_FILE"

# The tools that scripts/setup-tools.sh installs land in this folder's bin/ (by default .tools/ in
# the repository). It goes first on the PATH, so the checks use the factory's own pinned tools
# before any other copy on the machine. FACTORY_TOOLS_PREFIX names another folder.
TOOLS_BIN="${FACTORY_TOOLS_PREFIX:-$ROOT/.tools}/bin"
if [ -d "$TOOLS_BIN" ]; then
  case ":$PATH:" in
    *":$TOOLS_BIN:"*) ;;
    *) PATH="$TOOLS_BIN:$PATH" ;;
  esac
  export PATH
fi

# ---------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------
err() { printf 'ci.sh: %s\n' "$*" >&2; }
usage_error() {
  err "$*"
  err "Run scripts/ci.sh --help for the usage text."
  exit "$EXIT_USAGE"
}

# One line of plain ASCII, at most $2 characters (default 300). Anything outside printable ASCII,
# including newlines and tabs, becomes "?". This keeps the JSON line valid whatever a tool prints.
clean_text() {
  local text max=${2:-300}
  text=$(printf '%s' "$1" | LC_ALL=C tr -c ' -~' '?')
  printf '%s' "${text:0:$max}"
}

# A JSON string, with quotes. Control characters are already gone after clean_text.
json_str() {
  local s
  s=$(clean_text "$1" "${2:-300}")
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  printf '"%s"' "$s"
}

# SHA-256 of a file, or the word "unavailable" if this machine has no tool for it.
file_sha256() {
  if type -P shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif type -P sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    printf 'unavailable'
  fi
}

# How to get a tool. Shown when a step is BLOCKED because the tool is missing.
tool_hint() {
  case $1 in
    cargo | rustc | rustup) printf 'Install Rust with rustup (https://rustup.rs). rust-toolchain.toml selects the pinned version.' ;;
    cargo-nextest) printf 'Run scripts/setup-tools.sh, which installs cargo-nextest %s' "$PIN_NEXTEST" ;;
    cargo-deny) printf 'Run scripts/setup-tools.sh, which installs cargo-deny %s' "$PIN_DENY" ;;
    cargo-audit) printf 'Run scripts/setup-tools.sh, which installs cargo-audit %s' "$PIN_AUDIT" ;;
    gitleaks) printf 'Run scripts/setup-tools.sh, which installs gitleaks %s from its release, checked against a recorded SHA-256' "$PIN_GITLEAKS" ;;
    actionlint) printf 'Run scripts/setup-tools.sh, which installs actionlint %s from its release, checked against a recorded SHA-256' "$PIN_ACTIONLINT" ;;
    pyright) printf 'Run scripts/setup-tools.sh, which installs pyright %s from .github/tools/pyright/package-lock.json' "$PIN_PYRIGHT" ;;
    shellcheck) printf 'Run scripts/setup-tools.sh (it uses Homebrew when present), or install shellcheck %s with apt install shellcheck' "$PIN_SHELLCHECK" ;;
    docker) printf 'Install Docker with the Compose plugin (https://docs.docker.com/get-docker/)' ;;
    node | npm) printf 'Install Node.js and npm (https://nodejs.org)' ;;
    uv | uvx) printf 'Install uv (https://docs.astral.sh/uv/)' ;;
    python3) printf 'Install Python 3' ;;
    git) printf 'Install git' ;;
    *) printf 'Install %s and make sure it is on PATH' "$1" ;;
  esac
}

# Version cache: each tool is asked once per run.
TV_COUNT=0
TV_NAMES=()
TV_VALUES=()

# Ask tool $1 for its version and put a one-line answer in PROBE_TEXT. Return 1 if the tool is on
# PATH but does not run, for example a rustup shim whose toolchain is not installed. In that case
# PROBE_TEXT holds what the tool said. This is not called inside $(...) so the cache survives.
PROBE_TEXT=""
probe_tool() {
  local tool=$1 i flag out line
  i=0
  while [ "$i" -lt "$TV_COUNT" ]; do
    if [ "${TV_NAMES[$i]}" = "$tool" ]; then
      PROBE_TEXT=${TV_VALUES[$i]}
      return 0
    fi
    i=$((i + 1))
  done
  out=""
  for flag in --version version -version; do
    out=$("$tool" "$flag" 2>&1 </dev/null) || continue
    line=$(printf '%s\n' "$out" | grep -m1 '[0-9]') || continue
    line=$(clean_text "$line" 120)
    TV_NAMES[TV_COUNT]=$tool
    TV_VALUES[TV_COUNT]=$line
    TV_COUNT=$((TV_COUNT + 1))
    PROBE_TEXT=$line
    return 0
  done
  PROBE_TEXT=$(clean_text "$out" 200)
  return 1
}

# ---------------------------------------------------------------------------------------------
# The step registry. A step is: id, title, required tools, extra BLOCKED exit codes, an optional
# "applies if" path, where it came from, the command (as separate words), and how to show it.
# Words are stored joined by the ASCII unit separator (0x1f) because bash 3.2 has no nested arrays.
# ---------------------------------------------------------------------------------------------
US=$'\037'
S_COUNT=0
S_ID=()
S_TITLE=()
S_REQ=()
S_BLK=()
S_NAPATH=()
S_SRC=()
S_ARGV=()
S_SHOW=()

ID_PATTERN='^[a-z0-9][a-z0-9-]{0,39}$'
TOOL_PATTERN='^[A-Za-z0-9._+-]+$'
CODES_PATTERN='^([0-9]{1,3}( [0-9]{1,3})*)?$'

step_index() { # print the index of step id $1, or return 1
  local i=0
  while [ "$i" -lt "$S_COUNT" ]; do
    if [ "${S_ID[$i]}" = "$1" ]; then
      printf '%s' "$i"
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

# add_step ID TITLE REQUIRES BLOCKED_CODES APPLIES_IF_PATH SOURCE SHOW -- WORD...
add_step() {
  local id=$1 title=$2 req=$3 blk=$4 napath=$5 src=$6 show=$7 joined="" word tool code
  shift 8
  [[ $id =~ $ID_PATTERN ]] || usage_error "$src: step id '$id' must be lower-case letters, digits and hyphens (1 to 40 characters)"
  if step_index "$id" >/dev/null; then usage_error "$src: step id '$id' is already used"; fi
  [ -n "$title" ] || usage_error "$src: step '$id' has no title"
  for tool in $req; do
    [[ $tool =~ $TOOL_PATTERN ]] || usage_error "$src: step '$id' lists a tool name with unusual characters: $tool"
  done
  [[ $blk =~ $CODES_PATTERN ]] || usage_error "$src: step '$id': blocked_codes must be numbers separated by spaces"
  for code in $blk; do
    if [ "$code" -lt 1 ] || [ "$code" -gt 255 ]; then usage_error "$src: step '$id': blocked code $code is outside 1 to 255"; fi
  done
  case $napath in
    /* | *..*) usage_error "$src: step '$id': applies_if_path must be relative and must not contain .." ;;
  esac
  [ "$#" -ge 1 ] || usage_error "$src: step '$id' has no command"
  for word in "$@"; do
    case $word in
      *$'\n'* | *"$US"*) usage_error "$src: step '$id': the command contains a control character" ;;
    esac
    joined="$joined$word$US"
  done
  S_ID[S_COUNT]=$id
  S_TITLE[S_COUNT]=$(clean_text "$title" 160)
  S_REQ[S_COUNT]=$req
  S_BLK[S_COUNT]=$blk
  S_NAPATH[S_COUNT]=$napath
  S_SRC[S_COUNT]=$src
  S_ARGV[S_COUNT]=$joined
  S_SHOW[S_COUNT]=$show
  S_COUNT=$((S_COUNT + 1))
}

# A built-in step whose command is a plain program with arguments.
#   step ID TITLE REQUIRES EXTRA_BLOCKED_CODES -- PROGRAM ARGUMENT...
step() {
  local id=$1 title=$2 req=$3 blk=$4
  shift 5
  add_step "$id" "$title" "$req" "$blk" "" builtin "$*" -- "$@"
}

# A built-in step implemented by a function in this file. The runner starts a fresh copy of this
# script with "--internal NAME", so each such step runs in its own process and prints its own
# commands. The step table therefore only ever runs programs.
#   internal_step ID TITLE REQUIRES
internal_step() {
  add_step "$1" "$2" "$3" "" "" builtin "scripts/ci.sh --internal $1" -- "$BASH" "$SELF" --internal "$1"
}

# ---------------------------------------------------------------------------------------------
# THE STEP TABLE. The order is "cheap and quick first" so that a developer sees the common
# mistakes quickly. Each line is one check. Add built-in checks here; other work packages add
# theirs as .step files (see the header).
# ---------------------------------------------------------------------------------------------
register_builtin_steps() {
  internal_step no-secrets-in-config "Example env file and Compose files hold no secret-looking values" "python3"
  internal_step workflow-policy "Workflows: actions pinned to commit SHAs, no pull_request_target, least privilege (ST-10)" "python3"
  internal_step tool-pins "Tool versions and archive hashes agree between scripts/lib/tool-pins.sh, the workflow and the pyright lockfile" "python3"
  internal_step policy-yaml "policies/*.yaml follow the parser contract and name only real threats (ST-06)" "uv python3"
  step design-tokens "Design tokens: generated CSS is current and every contrast pair meets WCAG 2.2 AA (ADR 0031)" "python3" "" -- \
    python3 -I design-system/tools/build_tokens.py --check
  step design-tokens-tests "Design token generator: unit tests (references, cycles, contrast formula)" "python3" "" -- \
    python3 -I design-system/tools/test_build_tokens.py
  step readability-corpus "Readability corpus is well formed and matches the master prompt" "python3" "" -- \
    python3 -I fixtures/readability/check_corpus.py --prompt-examples
  step readability-corpus-selftest "Readability corpus validator rejects malformed input" "python3" "" -- \
    python3 -I fixtures/readability/check_corpus.py --self-test
  step state-machine-doc "State machine JSON is valid and its document is in sync" "python3" "" -- \
    python3 -I docs/architecture/tools/render_state_machine.py --check
  step crate-rules-doc "Crate dependency rules are valid and overview.md is in sync" "python3" "" -- \
    python3 -I docs/architecture/tools/check_crate_rules.py --check
  step work-packages-doc "Work packages are valid and slice-plan.md is in sync" "python3" "" -- \
    python3 -I docs/architecture/tools/check_work_packages.py --check
  internal_step schemas "JSON Schemas and their examples validate (schemas/validate.sh)" "uvx python3"
  internal_step pyright "Pyright finds no type errors in the repository's Python scripts" "pyright"
  internal_step shellcheck "Shell scripts pass shellcheck (warnings and errors)" "shellcheck"
  step actionlint "Workflow files pass actionlint" "actionlint" "" -- actionlint
  internal_step compose-config "Compose files are valid, loopback-only, digest-pinned and match .env.example" "docker python3"
  step architecture-check "Crate dependency rules and source scans hold (cargo xtask check-architecture)" "cargo" "2" -- \
    cargo xtask check-architecture
  step rust-fmt "Rust formatting is canonical" "cargo" "" -- cargo fmt --all -- --check
  step rust-clippy "Clippy reports nothing; every warning is an error" "cargo" "" -- \
    cargo clippy --workspace --all-targets --locked -- -D warnings
  step rust-test "Workspace tests pass, and at least one test runs" "cargo cargo-nextest" "" -- \
    cargo nextest run --workspace --locked --no-tests=fail
  step rust-doctest "Documentation examples compile and pass" "cargo" "" -- \
    cargo test --workspace --doc --locked
  internal_step rust-deny "cargo deny: licenses, bans, advisories and sources" "cargo-deny"
  internal_step rust-audit "cargo audit: no known vulnerable or unmaintained dependency" "cargo-audit"
  internal_step mermaid "Mermaid diagrams in the documents parse" "node npm"
  internal_step secret-scan "No secret in the full git history (ST-08)" "gitleaks git"
  internal_step ci-self-test "This script's own tests pass (BLOCKED, FAILED, drop-ins, secrets, pinning, Compose)" "python3"
}

# ---------------------------------------------------------------------------------------------
# Drop-in step files
# ---------------------------------------------------------------------------------------------
DROPIN_LINE='^[[:space:]]*([a-z_]+)[[:space:]]*=[[:space:]]*(.*)$'
DROPIN_SKIP='^[[:space:]]*(#.*)?$'
DROPIN_FILES=()
DROPIN_COUNT=0

parse_dropin() {
  local file=$1 name id="" title="" req="" blk="" napath="" run="" seen=" " n=0 line key value
  local -a words
  name="dropin:${file##*/}"
  [ ! -L "$file" ] || usage_error "$file: symbolic links are not allowed for step files"
  [ -f "$file" ] || usage_error "$file: not a regular file"
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    [ "$n" -le 100 ] || usage_error "$file: more than 100 lines"
    line=${line%$'\r'}
    if [[ $line =~ $DROPIN_SKIP ]]; then continue; fi
    [[ $line =~ $DROPIN_LINE ]] || usage_error "$file:$n: expected 'key = value', found: $(clean_text "$line" 80)"
    key=${BASH_REMATCH[1]}
    value=${BASH_REMATCH[2]}
    value=${value%"${value##*[![:space:]]}"}
    case $seen in *" $key "*) usage_error "$file:$n: '$key' appears twice" ;; esac
    seen="$seen$key "
    case $key in
      id) id=$value ;;
      title) title=$value ;;
      requires) req=$value ;;
      blocked_codes) blk=$value ;;
      applies_if_path) napath=$value ;;
      run) run=$value ;;
      *) usage_error "$file:$n: unknown key '$key' (allowed: id, title, requires, blocked_codes, applies_if_path, run)" ;;
    esac
  done <"$file"
  [ -n "$id" ] || usage_error "$file: missing 'id'"
  [ -n "$title" ] || usage_error "$file: missing 'title'"
  [ -n "$run" ] || usage_error "$file: missing 'run'"
  IFS=' ' read -r -a words <<<"$run"
  add_step "$id" "$title" "$req" "$blk" "$napath" "$name" "$run" -- "${words[@]}"
  DROPIN_FILES[DROPIN_COUNT]=$file
  DROPIN_COUNT=$((DROPIN_COUNT + 1))
}

load_dropins() {
  local dir=$1 file
  [ -d "$dir" ] || return 0
  for file in "$dir"/*.step; do
    [ -e "$file" ] || [ -L "$file" ] || continue
    parse_dropin "$file"
  done
}

# ---------------------------------------------------------------------------------------------
# The runner
# ---------------------------------------------------------------------------------------------
R_STATUS=()
R_CODE=()
R_DUR=()
R_REASON=()
R_TOOLS=()
N_PASSED=0
N_FAILED=0
N_BLOCKED=0
N_NA=0
LOGDIR=""

last_output_line() { # the last line of file $1 that holds a letter or digit, without colour codes
  local esc=$'\033'
  tail -n 30 "$1" 2>/dev/null | sed "s/${esc}\\[[0-9;]*[A-Za-z]//g; s/${esc}([A-Za-z]//g" | grep '[A-Za-z0-9]' | tail -n 1
}

# Run step number $1 (an index) as number $2 of $3 in this run.
run_step() {
  local i=$1 pos=$2 total=$3
  local id=${S_ID[$i]} req=${S_REQ[$i]} blk=${S_BLK[$i]} napath=${S_NAPATH[$i]}
  local status="" code=0 reason="" started=$SECONDS missing="" tool tools_json="" first_tool=1
  local notef logf argv0 note_status note_reason hint
  local -a argv
  printf '\n==> [%s/%s] %s: %s\n' "$pos" "$total" "$id" "${S_TITLE[$i]}"
  printf '    source   : %s\n' "${S_SRC[$i]}"
  printf '    command  : %s\n' "${S_SHOW[$i]}"

  # 1. Does the step apply at all?
  if [ -n "$napath" ] && ! compgen -G "$ROOT/$napath" >/dev/null 2>&1; then
    status=NOT_APPLICABLE
    reason="nothing matches $napath, so there is nothing to check"
  fi

  # 2. Is every required tool present, and does it run?
  if [ -z "$status" ]; then
    for tool in $req; do
      if ! type -P "$tool" >/dev/null 2>&1; then
        missing="$missing $tool"
        hint=$(tool_hint "$tool")
        printf '    tool     : %s = NOT FOUND on PATH. %s\n' "$tool" "$hint"
        continue
      fi
      if probe_tool "$tool"; then
        printf '    tool     : %s = %s\n' "$tool" "$PROBE_TEXT"
        [ "$first_tool" -eq 1 ] || tools_json="$tools_json,"
        tools_json="$tools_json$(json_str "$tool"):$(json_str "$PROBE_TEXT")"
        first_tool=0
      else
        missing="$missing $tool"
        printf '    tool     : %s = found, but it does not run. It said: %s\n' "$tool" "$PROBE_TEXT"
      fi
    done
    if [ -n "$missing" ]; then
      status=BLOCKED
      code=$EXIT_BLOCKED
      reason="required tool not available:$missing. Nothing was checked."
    fi
  fi

  # 3. Is the program itself there? A missing script is missing evidence, not a failure.
  IFS=$US read -r -a argv <<<"${S_ARGV[$i]}"
  argv0=${argv[0]}
  if [ -z "$status" ]; then
    case $argv0 in
      */*)
        if [ ! -f "$ROOT/$argv0" ] && [ ! -f "$argv0" ]; then
          status=BLOCKED
          code=$EXIT_BLOCKED
          reason="the command $argv0 does not exist. Nothing was checked."
        fi
        ;;
      *)
        if ! type -P "$argv0" >/dev/null 2>&1; then
          status=BLOCKED
          code=$EXIT_BLOCKED
          reason="the program $argv0 was not found on PATH. Nothing was checked."
        fi
        ;;
    esac
  fi

  # 4. Run it. The output is shown live and also kept, to name the reason for a bad result.
  if [ -z "$status" ]; then
    logf="$LOGDIR/$id.log"
    notef="$LOGDIR/$id.note"
    : >"$logf"
    : >"$notef"
    if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::group::%s output\n' "$id"; fi
    (
      cd "$ROOT" || exit 1
      # shellcheck disable=SC2030  # set on purpose for the child process only
      export CI_STEP_NOTE_FILE=$notef
      exec "${argv[@]}"
    ) </dev/null 2>&1 | tee "$logf"
    code=${PIPESTATUS[0]}
    if [ -n "${GITHUB_ACTIONS:-}" ]; then printf '::endgroup::\n'; fi
    note_status=""
    note_reason=""
    if [ -s "$notef" ]; then
      IFS=$'\t' read -r note_status note_reason <"$notef"
    fi
    if [ "$code" -eq 0 ]; then
      if [ "$note_status" = NOT_APPLICABLE ]; then
        status=NOT_APPLICABLE
        reason=$note_reason
      else
        status=PASSED
      fi
    elif [ "$code" -eq "$EXIT_BLOCKED" ] || { [ -n "$blk" ] && [[ " $blk " == *" $code "* ]]; }; then
      status=BLOCKED
      reason=${note_reason:-"the check could not run (exit code $code): $(last_output_line "$logf")"}
    else
      status=FAILED
      reason=${note_reason:-"exit code $code: $(last_output_line "$logf")"}
    fi
  fi

  local duration=$((SECONDS - started))
  R_STATUS[i]=$status
  R_CODE[i]=$code
  R_DUR[i]=$duration
  R_REASON[i]=$(clean_text "$reason" 300)
  R_TOOLS[i]=$tools_json
  case $status in
    PASSED) N_PASSED=$((N_PASSED + 1)) ;;
    FAILED) N_FAILED=$((N_FAILED + 1)) ;;
    BLOCKED) N_BLOCKED=$((N_BLOCKED + 1)) ;;
    NOT_APPLICABLE) N_NA=$((N_NA + 1)) ;;
  esac
  printf '    <== %s  (exit %s, %ss)' "$status" "$code" "$duration"
  if [ -n "$reason" ]; then printf '  %s' "$(clean_text "$reason" 300)"; fi
  printf '\n'
}

# ---------------------------------------------------------------------------------------------
# The summary
# ---------------------------------------------------------------------------------------------
repo_head() {
  local head
  head=$(cd "$ROOT" && git rev-parse HEAD 2>/dev/null) || head=""
  printf '%s' "${head:-unknown}"
}

print_summary() { # arguments: list of selected indexes
  local i outcome exit_code started_at=$1 started_secs=$2 scope=$3 json first=1 finished_at
  shift 3
  finished_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if [ "$N_FAILED" -gt 0 ]; then
    outcome=FAILED
    exit_code=$EXIT_FAILED
  elif [ "$N_BLOCKED" -gt 0 ]; then
    outcome=BLOCKED
    exit_code=$EXIT_BLOCKED
  else
    outcome=PASSED
    exit_code=0
  fi

  printf '\n==================== CI SUMMARY ====================\n'
  if [ "$scope" = partial ]; then
    printf 'PARTIAL RUN: only %s of %s steps were selected. This is NOT evidence that CI passes.\n' "$#" "$S_COUNT"
  fi
  for i in "$@"; do
    printf '%-15s %-28s %4ss  %s\n' "${R_STATUS[$i]}" "${S_ID[$i]}" "${R_DUR[$i]}" "$(clean_text "${R_REASON[$i]}" 110)"
  done
  printf -- '----------------------------------------------------\n'
  printf 'PASSED %s   FAILED %s   BLOCKED %s   NOT_APPLICABLE %s   ->  %s (exit %s)\n' \
    "$N_PASSED" "$N_FAILED" "$N_BLOCKED" "$N_NA" "$outcome" "$exit_code"

  # The JSON line is built by hand so that it works even when python3 is not installed.
  json="{\"schema\":$(json_str "$SUMMARY_SCHEMA")"
  json="$json,\"outcome\":$(json_str "$outcome"),\"exit_code\":$exit_code,\"scope\":$(json_str "$scope")"
  json="$json,\"started_at\":$(json_str "$started_at"),\"finished_at\":$(json_str "$finished_at")"
  json="$json,\"duration_s\":$((SECONDS - started_secs)),\"repo_head\":$(json_str "$(repo_head)")"
  json="$json,\"host\":$(json_str "$(uname -sm 2>/dev/null || echo unknown)")"
  json="$json,\"gate_definition\":{\"ci_sh_sha256\":$(json_str "$(file_sha256 "$SELF")"),\"step_files\":["
  i=0
  while [ "$i" -lt "$DROPIN_COUNT" ]; do
    [ "$i" -eq 0 ] || json="$json,"
    json="$json{\"file\":$(json_str "${DROPIN_FILES[$i]#"$ROOT"/}"),\"sha256\":$(json_str "$(file_sha256 "${DROPIN_FILES[$i]}")")}"
    i=$((i + 1))
  done
  json="$json]}"
  json="$json,\"counts\":{\"PASSED\":$N_PASSED,\"FAILED\":$N_FAILED,\"BLOCKED\":$N_BLOCKED,\"NOT_APPLICABLE\":$N_NA}"
  json="$json,\"steps\":["
  for i in "$@"; do
    [ "$first" -eq 1 ] || json="$json,"
    first=0
    json="$json{\"id\":$(json_str "${S_ID[$i]}"),\"title\":$(json_str "${S_TITLE[$i]}" 160)"
    json="$json,\"status\":$(json_str "${R_STATUS[$i]}"),\"exit_code\":${R_CODE[$i]},\"duration_s\":${R_DUR[$i]}"
    json="$json,\"command\":$(json_str "${S_SHOW[$i]}" 400),\"source\":$(json_str "${S_SRC[$i]}")"
    json="$json,\"tools\":{${R_TOOLS[$i]}},\"reason\":$(json_str "${R_REASON[$i]}")}"
  done
  json="$json]}"
  SUMMARY_JSON=$json
  SUMMARY_EXIT=$exit_code
}

# ---------------------------------------------------------------------------------------------
# Internal steps. The runner starts "scripts/ci.sh --internal NAME" for each of these. A step
# prints each command it runs on a line that starts with "+", then ends with exit code 0
# (PASSED), 1 (FAILED) or 3 (BLOCKED). It can leave a one-line reason for the summary.
# ---------------------------------------------------------------------------------------------

# note STATUS REASON: leave a reason for the runner. Ignored when run outside the runner.
note() {
  # shellcheck disable=SC2031  # the runner exported it to this child process
  if [ -n "${CI_STEP_NOTE_FILE:-}" ]; then printf '%s\t%s\n' "$1" "$2" >"$CI_STEP_NOTE_FILE"; fi
}
int_blocked() {
  printf 'BLOCKED: %s\n' "$*"
  note BLOCKED "$*"
  exit "$EXIT_BLOCKED"
}
int_failed() {
  printf 'FAILED: %s\n' "$*"
  note FAILED "$*"
  exit "$EXIT_FAILED"
}
int_not_applicable() {
  printf 'NOT_APPLICABLE: %s\n' "$*"
  note NOT_APPLICABLE "$*"
  exit 0
}
show_cmd() { # print a command line the way a person would type it
  printf '+'
  printf ' %s' "$@"
  printf '\n'
}

# Run a command, show it, show its output, and keep the output in file $1. The exit code is in RC.
RC=0
capture_run() {
  local log=$1
  shift
  show_cmd "$@"
  "$@" 2>&1 | tee "$log"
  RC=${PIPESTATUS[0]}
}

need_tool() { # need_tool TOOL...: BLOCKED unless every tool is on PATH
  local tool
  for tool in "$@"; do
    type -P "$tool" >/dev/null 2>&1 || int_blocked "$tool is not installed. $(tool_hint "$tool")"
  done
}

# ----- shellcheck -----------------------------------------------------------------------------
# Scope: scripts written for this repository's workflow. Generated Spec Kit scripts under .specify
# and scripts owned by other packages in their own folders are not in scope until they are clean.
int_shellcheck() {
  need_tool shellcheck
  local -a files=()
  local f
  while IFS= read -r f; do files+=("$f"); done < <(find scripts docs/architecture/tools -maxdepth 2 -type f -name '*.sh' 2>/dev/null | LC_ALL=C sort)
  [ "${#files[@]}" -gt 0 ] || int_not_applicable "there are no shell scripts under scripts/ or docs/architecture/tools/"
  show_cmd shellcheck --severity=warning "${files[@]}"
  shellcheck --severity=warning "${files[@]}"
  RC=$?
  case $RC in
    0) printf 'shellcheck: %s scripts, no warnings or errors\n' "${#files[@]}" ;;
    1) int_failed "shellcheck reported problems in the scripts above" ;;
    *) int_blocked "shellcheck could not finish (exit code $RC)" ;;
  esac
}

# ----- pyright --------------------------------------------------------------------------------
int_pyright() {
  need_tool pyright
  local -a files=()
  local f
  while IFS= read -r f; do files+=("${f#./}"); done < <(
    find . \( -name target -o -name node_modules -o -name .git -o -name .specify -o -name .claude -o -name .venv \) -prune \
      -o -type f -name '*.py' -print | LC_ALL=C sort
  )
  [ "${#files[@]}" -gt 0 ] || int_not_applicable "the repository has no Python files"
  show_cmd pyright "${files[@]}"
  pyright "${files[@]}"
  RC=$?
  case $RC in
    0) ;;
    1) int_failed "pyright reported type errors" ;;
    *) int_blocked "pyright could not finish (exit code $RC)" ;;
  esac
}

# ----- JSON Schemas ---------------------------------------------------------------------------
# schemas/validate.sh starts check-jsonschema through uvx, which needs the network the first time.
# Prove that it can start before running it, so "no network" is BLOCKED and not a pile of failures.
int_schemas() {
  need_tool uvx python3
  [ -f schemas/validate.sh ] || int_blocked "schemas/validate.sh does not exist"
  if [ -z "${CHECK_JSONSCHEMA:-}" ]; then
    local version library
    version=$(sed -n 's/^CJ_VERSION="\(.*\)"$/\1/p' schemas/validate.sh | head -n 1)
    library=$(sed -n 's/^JSONSCHEMA_VERSION="\(.*\)"$/\1/p' schemas/validate.sh | head -n 1)
    [ -n "$version" ] || int_blocked "could not read CJ_VERSION from schemas/validate.sh"
    [ -n "$library" ] || int_blocked "could not read JSONSCHEMA_VERSION from schemas/validate.sh"
    show_cmd uvx --from "check-jsonschema==$version" --with "jsonschema==$library" check-jsonschema --version
    uvx --from "check-jsonschema==$version" --with "jsonschema==$library" check-jsonschema --version >/dev/null 2>&1 \
      || int_blocked "check-jsonschema $version could not be started through uvx (is the network reachable, or is it cached?)"
  fi
  show_cmd schemas/validate.sh
  schemas/validate.sh
  RC=$?
  [ "$RC" -eq 0 ] || int_failed "schemas/validate.sh reported failures (exit code $RC)"
}

# ----- cargo deny -----------------------------------------------------------------------------
# deny.toml belongs to work package s0-security-baseline. Without it cargo-deny falls back to
# defaults that reject every license, which says nothing about this project's real policy, so the
# honest answer is BLOCKED.
int_rust_deny() {
  need_tool cargo cargo-deny
  [ -f deny.toml ] || int_blocked "deny.toml does not exist yet. It is owned by work package s0-security-baseline. Without it cargo-deny uses defaults that say nothing about this project's policy."
  local log="$LOGDIR_INT/deny.log"
  capture_run "$log" cargo deny --locked check
  if [ "$RC" -eq 0 ]; then return 0; fi
  if grep -Eq '(advisories|bans|licenses|sources) FAILED' "$log"; then
    int_failed "cargo deny found a policy violation (exit code $RC)"
  fi
  int_blocked "cargo deny could not finish (exit code $RC). Most likely it could not fetch the advisory database."
}

# ----- cargo audit ----------------------------------------------------------------------------
# cargo audit downloads the advisory database and exits 1 both for "found a problem" and for
# "could not download". The report format tells them apart: a finding always names an advisory
# or says how many warnings were denied. Anything else is "could not finish", so BLOCKED.
int_rust_audit() {
  need_tool cargo cargo-audit
  local log="$LOGDIR_INT/audit.log"
  capture_run "$log" cargo audit --deny warnings
  if [ "$RC" -eq 0 ]; then return 0; fi
  if grep -Eq 'RUSTSEC-[0-9]{4}-[0-9]{4}|vulnerabilit(y|ies) found|denied warnings? found' "$log"; then
    int_failed "cargo audit reported a vulnerable, unmaintained or yanked dependency"
  fi
  int_blocked "cargo audit could not finish (exit code $RC). Most likely it could not fetch the advisory database."
}

# ----- Mermaid --------------------------------------------------------------------------------
int_mermaid() {
  need_tool node npm
  local -a files=()
  local f
  while IFS= read -r f; do files+=("$f"); done < <(grep -rlF '```mermaid' --include='*.md' docs specs README.md 2>/dev/null | LC_ALL=C sort)
  [ "${#files[@]}" -gt 0 ] || int_not_applicable "no Markdown file contains a Mermaid diagram"
  local log="$LOGDIR_INT/mermaid.log"
  capture_run "$log" docs/architecture/tools/check-mermaid.sh "${files[@]}"
  if [ "$RC" -eq 0 ]; then
    # A run that checked zero diagrams proves nothing.
    grep -Eq '^[1-9][0-9]*/[1-9][0-9]* mermaid blocks parse' "$log" || int_blocked "the Mermaid checker finished without checking any diagram"
    return 0
  fi
  if grep -q '^FAIL ' "$log"; then
    int_failed "at least one Mermaid diagram does not parse"
  fi
  int_blocked "the Mermaid checker could not run (exit code $RC). Most likely npm could not install the pinned packages."
}

# ----- secret scan of the whole history (ST-08) -------------------------------------------------
# Scans every commit on every ref, not only the current files, so a secret that was committed and
# later deleted is still found. A shallow clone has no full history, so it is BLOCKED rather than
# passing on a partial scan. Inline "gitleaks:allow" comments are ignored, so a pull request cannot
# hide a finding. Allowed exceptions live in .gitleaksignore, which has code owners.
int_secret_scan() {
  local repo=${1:-$ROOT} v
  need_tool git gitleaks
  git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || int_blocked "$repo is not a git checkout, so there is no history to scan"
  if [ "$(git -C "$repo" rev-parse --is-shallow-repository 2>/dev/null)" = true ]; then
    int_blocked "this is a shallow clone, so the full history is not available. Fetch everything (in GitHub Actions: fetch-depth: 0)."
  fi
  # GITLEAKS_* variables can change any gitleaks setting. Start from a clean slate so that only
  # the repository's own .gitleaks.toml and .gitleaksignore (both protected) apply.
  local -a clear=()
  for v in $(compgen -e); do
    case $v in GITLEAKS_*) clear+=(-u "$v") ;; esac
  done
  show_cmd gitleaks git --no-banner --no-color --redact --ignore-gitleaks-allow --exit-code 2 --verbose --log-opts="--all --full-history" "$repo"
  env ${clear[@]+"${clear[@]}"} gitleaks git --no-banner --no-color --redact --ignore-gitleaks-allow \
    --exit-code 2 --verbose --log-opts="--all --full-history" "$repo"
  RC=$?
  case $RC in
    0) ;;
    2) int_failed "gitleaks found a secret in the git history (values are redacted above)" ;;
    *) int_blocked "gitleaks could not finish (exit code $RC)" ;;
  esac
}

# ----- policy YAML (ST-06) ----------------------------------------------------------------------
py_policy_yaml() {
  # PyYAML is not part of the standard library. uv installs the pinned version into a throwaway
  # environment, so nothing is installed on the machine or in the repository.
  uv run --no-project --with "pyyaml==$PIN_PYYAML" python -I - "$@" <<'PY'
import pathlib
import re
import sys

import yaml
from yaml.events import (AliasEvent, DocumentStartEvent, MappingEndEvent, MappingStartEvent,
                         ScalarEvent, SequenceEndEvent, SequenceStartEvent)

threat_model = pathlib.Path(sys.argv[1])
policy_files = [pathlib.Path(p) for p in sys.argv[2:]]
known_threats = set(re.findall(r"^\|\s*(T-\d+)\s*\|", threat_model.read_text(encoding="utf-8"), re.M))
if len(known_threats) < 10:
    print(f"BLOCKED: {threat_model} lists only {len(known_threats)} threats, so it cannot be used to check references")
    sys.exit(3)


def structure_problems(text):
    """Rules from the parser contract at the top of policies/security.yaml, read from the event stream."""
    problems, documents, stack = [], 0, []

    def node_done():
        if stack and stack[-1][0] == "map":
            stack[-1][1] ^= 1  # next node in this mapping is a key, then a value, then a key

    for ev in yaml.parse(text, Loader=yaml.SafeLoader):
        if isinstance(ev, DocumentStartEvent):
            documents += 1
            continue
        line = getattr(getattr(ev, "start_mark", None), "line", -1) + 1
        if isinstance(ev, AliasEvent):
            problems.append(f"line {line}: alias '*{ev.anchor}' is not allowed")
        elif getattr(ev, "anchor", None):
            problems.append(f"line {line}: anchor '&{ev.anchor}' is not allowed")
        if not isinstance(ev, AliasEvent) and getattr(ev, "tag", None):
            problems.append(f"line {line}: explicit tag '{ev.tag}' is not allowed")
        if isinstance(ev, (MappingStartEvent, SequenceStartEvent)):
            if stack and stack[-1][0] == "map" and stack[-1][1] == 0:
                problems.append(f"line {line}: a mapping key must be a plain scalar")
            stack.append(["map" if isinstance(ev, MappingStartEvent) else "seq", 0, set()])
        elif isinstance(ev, (MappingEndEvent, SequenceEndEvent)):
            stack.pop()
            node_done()
        elif isinstance(ev, (ScalarEvent, AliasEvent)):
            if stack and stack[-1][0] == "map" and stack[-1][1] == 0:
                key = ev.value if isinstance(ev, ScalarEvent) else None
                if key == "<<":
                    problems.append(f"line {line}: merge key '<<' is not allowed")
                elif key in stack[-1][2]:
                    problems.append(f"line {line}: key '{key}' appears twice in the same mapping")
                stack[-1][2].add(key)
            node_done()
    if documents != 1:
        problems.append(f"the file holds {documents} YAML documents; exactly one is allowed")
    return problems


def threat_references(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "threats" and isinstance(value, list):
                found.update(str(item) for item in value)
            threat_references(value, found)
    elif isinstance(node, list):
        for item in node:
            threat_references(item, found)


failed = 0
for path in policy_files:
    problems = []
    try:
        text = path.read_text(encoding="utf-8")
        problems = structure_problems(text)
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            problems.append("the top level is not a mapping")
        else:
            refs = set()
            threat_references(data, refs)
            for ref in sorted(refs - known_threats):
                problems.append(f"threat {ref} is not defined in {threat_model}")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"BLOCKED: cannot read {path}: {exc}")
        sys.exit(3)
    except yaml.YAMLError as exc:
        problems.append(f"does not parse: {str(exc).splitlines()[0] if str(exc) else exc}")
    if problems:
        failed += 1
        for problem in problems:
            print(f"FAIL  {path}: {problem}")
    else:
        print(f"ok    {path} (one document, no anchors, aliases, merge keys, tags or duplicate keys; {len(refs)} threat references, all defined)")
print(f"{len(policy_files) - failed}/{len(policy_files)} policy files satisfy the parser contract (PyYAML {yaml.__version__}, YAML 1.1 rules for scalars)")
sys.exit(1 if failed else 0)
PY
}

int_policy_yaml() {
  need_tool uv python3
  local -a files=()
  local f
  for f in policies/*.yaml policies/*.yml; do
    [ -f "$f" ] && files+=("$f")
  done
  [ "${#files[@]}" -gt 0 ] || int_blocked "there is no policies/*.yaml file to check"
  [ -f docs/security/threat-model.md ] || int_blocked "docs/security/threat-model.md is missing, so threat references cannot be checked"
  show_cmd uv run --no-project --with "pyyaml==$PIN_PYYAML" python -I - docs/security/threat-model.md "${files[@]}"
  uv run --no-project --with "pyyaml==$PIN_PYYAML" python -I -c 'import yaml' >/dev/null 2>&1 \
    || int_blocked "PyYAML $PIN_PYYAML could not be installed through uv (is the network reachable, or is it cached?)"
  py_policy_yaml docs/security/threat-model.md "${files[@]}"
  RC=$?
  case $RC in
    0) ;;
    3) int_blocked "the policy check could not read its inputs (see above)" ;;
    *) int_failed "a policy file breaks the parser contract (see above)" ;;
  esac
}

# ----- workflow rules (ST-10 and the least-privilege rules) -------------------------------------
py_workflow_policy() {
  python3 -I - "$@" <<'PY'
import pathlib
import re
import sys

PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$")
DOCKER_PINNED = re.compile(r"^docker://[^\s@]+@sha256:[0-9a-f]{64}$")
USES = re.compile(r"(?:^|[\s\-{,\[])uses\s*:\s*(.*)$")


def scalar(value):
    value = value.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        return value[1:end] if end != -1 else None
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


def check(path, text):
    problems = []
    lines = text.splitlines()
    is_workflow = "workflows" in path.parts
    for index, raw in enumerate(lines):
        number = index + 1
        if raw.lstrip().startswith("#"):
            continue
        code = re.split(r"\s+#", raw, maxsplit=1)[0]
        match = USES.search(code)
        if match:
            value = scalar(match.group(1))
            if not value:
                problems.append(f"{path}:{number}: 'uses' has no value on the same line, so it cannot be checked")
            elif value.startswith("./"):
                pass  # an action stored in this repository is reviewed with the repository
            elif "${{" in value:
                problems.append(f"{path}:{number}: 'uses: {value}' is built from an expression and cannot be pinned")
            elif value.startswith("docker://"):
                if not DOCKER_PINNED.match(value):
                    problems.append(f"{path}:{number}: '{value}' is not pinned to an image digest (@sha256:...)")
            elif not PINNED.match(value):
                problems.append(f"{path}:{number}: '{value}' is not pinned to a full 40-character commit SHA (a tag or branch can be moved)")
            if value and value.startswith("actions/checkout@"):
                found = False
                for follower in lines[index + 1:index + 13]:
                    if re.match(r"^\s*-\s+\w", follower):
                        break
                    if re.search(r"persist-credentials\s*:\s*false\b", follower):
                        found = True
                if not found:
                    problems.append(f"{path}:{number}: actions/checkout must set 'persist-credentials: false' so later steps cannot reuse the token")
        if not is_workflow:
            continue
        if re.search(r"\b(pull_request_target|workflow_run)\b", code):
            problems.append(f"{path}:{number}: the trigger 'pull_request_target' or 'workflow_run' runs with secrets for code from a pull request and is not allowed")
        if re.search(r":\s*write\b|\bwrite-all\b", code):
            problems.append(f"{path}:{number}: this workflow may not request write permission")
        for secret in re.finditer(r"\bsecrets\.([A-Za-z0-9_]+)", code):
            if secret.group(1) != "GITHUB_TOKEN":
                problems.append(f"{path}:{number}: the workflow reads secret {secret.group(1)}; CI for pull requests must hold no secrets")
        if re.search(r"\bsecrets\s*:\s*inherit\b", code):
            problems.append(f"{path}:{number}: 'secrets: inherit' passes every secret on")
        if re.search(r"github\.event\.|github\.head_ref", code):
            problems.append(f"{path}:{number}: text from the event (title, branch name, body) is attacker-controlled and must not be used in a workflow")
    if is_workflow and not re.search(r"^permissions\s*:", text, re.M):
        problems.append(f"{path}: no top-level 'permissions:' block, so the token gets the repository default instead of least privilege")
    return problems


root = pathlib.Path(sys.argv[1])
files = sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in (".yml", ".yaml"))
if not any("workflows" in p.parts for p in files):
    print(f"BLOCKED: no workflow file found under {root}, so the workflow rules cannot be checked")
    sys.exit(3)
failed = 0
for path in files:
    try:
        problems = check(path, path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        print(f"BLOCKED: cannot read {path}: {exc}")
        sys.exit(3)
    for problem in problems:
        print(f"FAIL  {problem}")
    failed += 1 if problems else 0
    if not problems:
        print(f"ok    {path}")
print(f"{len(files) - failed}/{len(files)} workflow files follow the rules")
sys.exit(1 if failed else 0)
PY
}

int_workflow_policy() {
  need_tool python3
  local dir=${1:-.github}
  show_cmd python3 -I - "$dir"
  py_workflow_policy "$dir"
  RC=$?
  case $RC in
    0) ;;
    3) int_blocked "no workflow file was found to check" ;;
    *) int_failed "a workflow breaks the rules above" ;;
  esac
}

# ----- tool versions agree everywhere they are written -------------------------------------------
# Tool versions are written in three places: PIN_* in scripts/lib/tool-pins.sh (read by this
# script for its install hints and by scripts/setup-tools.sh to install), the workflow (what CI
# installs) and the pyright lockfile. A version changed in one place only would leave people and
# CI testing with different tools, which is exactly the drift this script exists to stop. The
# SHA-256 of the linux amd64 archives of gitleaks and actionlint is written in the pins file and in
# the workflow; those must agree too. And no other script may keep a PIN_ line of its own, since a
# second copy is how two places come to disagree.
py_tool_pins() {
  python3 -I - "$@" <<'PY'
import json
import pathlib
import re
import sys

pins_path, workflow_path, package_path, lock_path = (pathlib.Path(arg) for arg in sys.argv[1:5])
other_scripts = [pathlib.Path(arg) for arg in sys.argv[5:]]
try:
    pins_text = pins_path.read_text(encoding="utf-8")
    workflow = workflow_path.read_text(encoding="utf-8")
    package = json.loads(package_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    others = {path: path.read_text(encoding="utf-8") for path in other_scripts}
except (OSError, ValueError) as exc:
    print(f"BLOCKED: cannot read one of the files that name tool versions: {exc}")
    sys.exit(3)

pins = dict(re.findall(r'^PIN_([A-Z]+)="([^"]+)"$', pins_text, re.M))
hashes = dict(re.findall(r'^SHA256_([A-Z0-9_]+)="([^"]*)"$', pins_text, re.M))
problems = []


def expect(label, pin, actual):
    want = pins.get(pin)
    if want is None:
        problems.append(f"{pins_path} has no PIN_{pin} line")
    elif actual != want:
        problems.append(f"{label}: the workflow or lockfile says {actual!r}, but PIN_{pin} in {pins_path} says {want!r}")
    else:
        print(f"ok    {label} {want}")


for path, text in others.items():
    for line in re.findall(r'^\s*PIN_[A-Z]+=.*$', text, re.M):
        problems.append(f"{path} sets its own {line.strip()!r}; versions belong in {pins_path} only")
for tool in ("GITLEAKS", "ACTIONLINT"):
    for platform in ("DARWIN_ARM64", "DARWIN_AMD64", "LINUX_AMD64", "LINUX_ARM64"):
        value = hashes.get(f"{tool}_{platform}")
        if value is None or not re.fullmatch(r"[0-9a-f]{64}", value):
            problems.append(f"{pins_path}: SHA256_{tool}_{platform} is missing or is not 64 lower-case hex digits")
for tool, archive in (("gitleaks", "linux_x64"), ("actionlint", "linux_amd64")):
    match = re.search(rf"/{tool}_[0-9.]+_{archive}\.tar\.gz\"\s*\\\s*\n\s*([0-9a-f]{{64}})", workflow)
    want = hashes.get(f"{tool.upper()}_LINUX_AMD64")
    if match is None:
        problems.append(f"{workflow_path}: no SHA-256 found after the {tool} {archive} download")
    elif match.group(1) != want:
        problems.append(f"{tool} linux amd64: the workflow checks {match.group(1)}, but {pins_path} records {want}")
    else:
        print(f"ok    {tool} linux amd64 SHA-256 {want[:12]}...")


tool_line = re.search(r"^\s*tool:\s*(\S+)\s*$", workflow, re.M)
action_tools = dict(item.split("@", 1) for item in tool_line.group(1).split(",") if "@" in item) if tool_line else {}
for tool, pin in (("cargo-nextest", "NEXTEST"), ("cargo-deny", "DENY"), ("cargo-audit", "AUDIT"), ("shellcheck", "SHELLCHECK")):
    expect(tool, pin, action_tools.get(tool))
for tool, pin in (("gitleaks", "GITLEAKS"), ("actionlint", "ACTIONLINT")):
    found = {v for pair in re.findall(rf"/{tool}/releases/download/v([0-9.]+)/{tool}_([0-9.]+)_", workflow) for v in pair}
    expect(tool, pin, next(iter(found)) if len(found) == 1 else f"{sorted(found)} (the release tag and the file name must agree)")
expect("pyright (package.json)", "PYRIGHT", (package.get("devDependencies") or {}).get("pyright"))
expect("pyright (lockfile)", "PYRIGHT", ((lock.get("packages") or {}).get("node_modules/pyright") or {}).get("version"))
for problem in problems:
    print(f"FAIL  {problem}")
sys.exit(1 if problems else 0)
PY
}

# int_tool_pins [PINS WORKFLOW PACKAGE LOCK [SCRIPT...]]: the self-test passes copies to change.
# SCRIPT are the scripts that must not keep a PIN_ line of their own.
int_tool_pins() {
  need_tool python3
  local pins=${1:-scripts/lib/tool-pins.sh} workflow=${2:-.github/workflows/ci.yml}
  local package=${3:-.github/tools/pyright/package.json} lock=${4:-.github/tools/pyright/package-lock.json}
  local -a scripts=(scripts/ci.sh scripts/setup-tools.sh scripts/install.sh)
  if [ "$#" -gt 4 ]; then
    shift 4
    scripts=("$@")
  fi
  show_cmd python3 -I - "$pins" "$workflow" "$package" "$lock" "${scripts[@]}"
  py_tool_pins "$pins" "$workflow" "$package" "$lock" "${scripts[@]}"
  RC=$?
  case $RC in
    0) ;;
    3) int_blocked "a file that names tool versions could not be read (see above)" ;;
    *) int_failed "a tool version or archive hash differs between scripts/lib/tool-pins.sh, the workflow and the pyright lockfile" ;;
  esac
}

# ----- secret-looking values in example and Compose files ---------------------------------------
py_no_secrets() {
  python3 -I - "$@" <<'PY'
import math
import pathlib
import re
import sys

POLICY = pathlib.Path("policies/security.yaml")
SECRET_SUFFIX = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIALS?|PAT)$", re.I)
ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
COMPOSE_LITERAL = re.compile(
    r"^\s*(?:-\s*)?([A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|KEY|CREDENTIALS?)[A-Za-z0-9_]*)\s*[:=]\s*(\S.*?)\s*$", re.I)


class Blocked(Exception):
    pass


def load_rules(policy):
    """The secret patterns of policies/security.yaml (section 9), read as text.

    The file's regexes are in Rust syntax. The ones used here also work in Python. If the layout
    changes so that this reader finds fewer patterns than the file lists, it stops (BLOCKED)
    instead of checking against a partial list."""
    try:
        text = policy.read_text(encoding="utf-8")
        start = text.index("\nsecrets:\n")
        first = text.index("\n  patterns:\n", start)
        last = text.index("\n  entropy_heuristic:", first)
    except (OSError, ValueError) as exc:
        raise Blocked(f"cannot read the secret patterns from {policy}: {exc}")
    block = text[first:last]
    entry = re.compile(r"\{\s*id:\s*([a-z0-9_]+),\s*regex:\s*'((?:[^']|'')*)'\s*,\s*action:\s*([a-z]+)")
    patterns = []
    for match in entry.finditer(block):
        try:
            patterns.append((match.group(1), re.compile(match.group(2).replace("''", "'")), match.group(3)))
        except re.error as exc:
            raise Blocked(f"secret pattern '{match.group(1)}' does not compile in Python: {exc}")
    listed = sum(1 for line in block.splitlines() if line.lstrip().startswith("- {"))
    if len(patterns) < 10 or len(patterns) != listed:
        raise Blocked(f"read {len(patterns)} secret patterns but the policy lists {listed}; the file layout changed")
    tail = text[last:last + 400]
    length, bits = re.search(r"min_length:\s*(\d+)", tail), re.search(r"min_shannon_bits_per_char:\s*([0-9.]+)", tail)
    if not (length and bits):
        raise Blocked("cannot read the entropy settings from policies/security.yaml")
    return patterns, int(length.group(1)), float(bits.group(1))


def entropy(text):
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values()) if text else 0.0


def env_value(raw):
    value = raw.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        return value[1:end] if end != -1 else value[1:]
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()


def pattern_problems(label, text, rules):
    patterns, _, _ = rules
    return [f"{label}:{n}: matches the secret pattern '{pid}' (policy action: {action})"
            for n, line in enumerate(text.splitlines(), 1) for pid, rx, action in patterns if rx.search(line)]


def check_dotenv(label, text, rules):
    _, min_length, min_bits = rules
    problems = pattern_problems(label, text, rules)
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.strip().startswith("#"):
            continue
        match = ASSIGN.match(line)
        if not match:
            problems.append(f"{label}:{n}: not a comment and not NAME=value")
            continue
        name, value = match.group(1), env_value(match.group(2))
        if SECRET_SUFFIX.search(name) and value != "":
            problems.append(f"{label}:{n}: {name} ends in a secret-like word, so it must be empty in an example file")
        if len(value) >= min_length and entropy(value) >= min_bits:
            problems.append(f"{label}:{n}: the value of {name} looks like random key material")
    return problems


def check_compose(label, text, rules):
    problems = pattern_problems(label, text, rules)
    for n, line in enumerate(text.splitlines(), 1):
        match = COMPOSE_LITERAL.match(re.split(r"\s+#", line, maxsplit=1)[0])
        if match:
            value = match.group(2).strip().strip("'\"")
            if value and not value.startswith("${"):
                problems.append(f"{label}:{n}: {match.group(1)} has a literal value; Compose must read credentials from .env with ${{NAME}}")
    return problems


def check_path(path, rules):
    text = path.read_text(encoding="utf-8")
    return (check_compose if path.suffix in (".yml", ".yaml") else check_dotenv)(str(path), text, rules)


def selftest(rules):
    # Fake secrets are assembled here from pieces, so no complete one is stored in the repository.
    token = "ghp_" + "Ab1Cd2Ef3Gh4" * 3
    aws = "AKIA" + "QWERTYUIOPASDFGH"
    key_header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    anthropic = "sk-ant-" + "a1B2c3D4e5" * 3
    url = "postgres://factory:" + "s3cr3tpw" + "@localhost:5432/factory"
    random_blob = "q8Zx3Lm9Vt2Kd7Rb5Ns4Hp6Jy1Wc0Fg8Xa3UeZ"
    assert entropy(random_blob) >= rules[2] and len(random_blob) >= rules[1], "self-test value is not random enough"
    must_fail = [
        ("a GitHub token under a secret-like name", check_dotenv, f"GITHUB_TOKEN={token}\n"),
        ("a GitHub token under a harmless name", check_dotenv, f"NOTE={token}\n"),
        ("an AWS key id under a harmless name", check_dotenv, f"REGION_HINT={aws}\n"),
        ("a private key header inside a comment", check_dotenv, f"# {key_header}\n"),
        ("an Anthropic key", check_dotenv, f"MODEL_ACCESS={anthropic}\n"),
        ("a password with a value", check_dotenv, "POSTGRES_PASSWORD=hunter2\n"),
        ("a placeholder in a secret-like name", check_dotenv, "API_TOKEN=CHANGE_ME\n"),
        ("a URL with a password in it", check_dotenv, f"DATABASE_URL={url}\n"),
        ("random key material under a harmless name", check_dotenv, f"SESSION_SALT={random_blob}\n"),
        ("a line that is not NAME=value", check_dotenv, "this is not an assignment\n"),
        ("a literal password in a Compose file", check_compose, "    environment:\n      POSTGRES_PASSWORD: hunter2\n"),
        ("a literal API key in a Compose list", check_compose, "    environment:\n      - API_KEY=abc123\n"),
    ]
    must_pass = [
        ("a blank password and ordinary settings", check_dotenv,
         "# comment\nPOSTGRES_USER=factory\nPOSTGRES_PASSWORD=\nPOSTGRES_HOST_PORT=5432\n"),
        ("a Compose password read from .env", check_compose,
         "    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?Set it in .env}\n"),
    ]
    failures = 0
    for label, check, text in must_fail:
        found = check("selftest", text, rules)
        print(("  PASS  rejects " if found else "  FAIL  ACCEPTED ") + label)
        failures += 0 if found else 1
    for label, check, text in must_pass:
        found = check("selftest", text, rules)
        print(("  PASS  accepts " if not found else "  FAIL  REJECTED ") + label + ("" if not found else f": {found[0]}"))
        failures += 1 if found else 0
    print(f"no-secrets detector: {len(must_fail)} bad inputs and {len(must_pass)} good inputs, {failures} wrong answers")
    return 1 if failures else 0


try:
    rules = load_rules(POLICY)
    if sys.argv[1:2] == ["selftest"]:
        sys.exit(selftest(rules))
    paths = [pathlib.Path(arg) for arg in sys.argv[1:]]
    if not paths:
        raise Blocked("no file was given to check")
    problems = []
    for path in paths:
        try:
            problems += check_path(path, rules)
        except (OSError, UnicodeDecodeError) as exc:
            raise Blocked(f"cannot read {path}: {exc}")
except Blocked as exc:
    print(f"BLOCKED: {exc}")
    sys.exit(3)
for problem in problems:
    print(f"FAIL  {problem}")
if problems:
    sys.exit(1)
print(f"ok    {len(paths)} files hold no secret-looking value ({len(rules[0])} patterns from {POLICY}, entropy limit {rules[2]} bits over {rules[1]} characters)")
PY
}

int_no_secrets_in_config() {
  need_tool python3
  local -a files=()
  local f
  if [ "$#" -gt 0 ]; then
    files=("$@")
  else
    [ -f .env.example ] || int_blocked ".env.example does not exist"
    files=(.env.example)
    for f in infra/compose/*.yml infra/compose/*.yaml; do
      [ -f "$f" ] && files+=("$f")
    done
  fi
  [ -f policies/security.yaml ] || int_blocked "policies/security.yaml is missing, so the secret patterns cannot be read"
  show_cmd python3 -I - "${files[@]}"
  py_no_secrets "${files[@]}"
  RC=$?
  case $RC in
    0) ;;
    3) int_blocked "the detector could not read its inputs (see above)" ;;
    *) int_failed "a file holds a secret-looking value (see above)" ;;
  esac
}

# ----- Compose files ----------------------------------------------------------------------------
py_compose_config() {
  python3 -I - "$@" <<'PY'
import json
import pathlib
import re
import sys

rendered_path, example_path, compose_dir = (pathlib.Path(arg) for arg in sys.argv[1:4])
try:
    rendered = json.loads(rendered_path.read_text(encoding="utf-8"))
    example = example_path.read_text(encoding="utf-8")
except (OSError, ValueError) as exc:
    print(f"BLOCKED: cannot read the rendered Compose file or .env.example: {exc}")
    sys.exit(3)

DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_RAW"}
problems = []
services = rendered.get("services") or {}
if not services:
    problems.append("the Compose project has no services")
for name, service in sorted(services.items()):
    for port in service.get("ports") or []:
        if port.get("host_ip") not in ("127.0.0.1", "::1"):
            problems.append(f"{name}: port {port.get('published')} is published on '{port.get('host_ip') or 'every interface'}'; it must be bound to 127.0.0.1")
    if service.get("privileged"):
        problems.append(f"{name}: privileged mode is not allowed")
    for key in ("network_mode", "pid", "ipc", "uts", "userns_mode"):
        if service.get(key) == "host":
            problems.append(f"{name}: {key}: host is not allowed")
    if not re.search(r"@sha256:[0-9a-f]{64}$", service.get("image", "")):
        problems.append(f"{name}: image '{service.get('image')}' is not pinned by digest (@sha256:...)")
    for cap in service.get("cap_add") or []:
        if cap.upper().replace("CAP_", "") in DANGEROUS_CAPS:
            problems.append(f"{name}: capability {cap} is not allowed")
    if service.get("devices"):
        problems.append(f"{name}: device mappings are not allowed")
    for volume in service.get("volumes") or []:
        source = str(volume.get("source", ""))
        if "docker.sock" in source or source in ("/", "/etc", "/var", "/root", "/home", "/proc", "/sys"):
            problems.append(f"{name}: it mounts {source}, which is forbidden")

# Every variable a Compose file reads must be documented in .env.example.
documented = set(re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)=", example, re.M))
for file in sorted(list(compose_dir.glob("*.yml")) + list(compose_dir.glob("*.yaml"))):
    # Comments may mention ${NAME} as an example. Only real configuration lines count.
    code = "\n".join(re.split(r"\s#", line, maxsplit=1)[0] for line in file.read_text(encoding="utf-8").splitlines()
                     if not line.lstrip().startswith("#"))
    for variable in sorted(set(re.findall(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", code))):
        if variable not in documented:
            problems.append(f"{file.name}: reads ${{{variable}}}, which .env.example does not list")

for problem in problems:
    print(f"FAIL  {problem}")
if problems:
    sys.exit(1)
print(f"ok    {len(services)} service(s): ports on loopback only, images pinned by digest, no privileged mode, "
      "no host namespaces, no docker socket, every variable documented in .env.example")
PY
}

int_compose_config() {
  need_tool docker python3
  local dir=${1:-infra/compose} example=${2:-.env.example}
  if ! { [ -d "$dir" ] && compgen -G "$dir/*.yml" >/dev/null; }; then
    int_not_applicable "there is no Compose file under $dir"
  fi
  docker compose version >/dev/null 2>&1 || int_blocked "the 'docker compose' plugin is not available. $(tool_hint docker)"
  [ -f "$example" ] || int_blocked "$example does not exist, so the Compose variables cannot be checked"
  local work line
  work=$(mktemp -d "${TMPDIR:-/tmp}/factory-compose.XXXXXX") || int_blocked "cannot create a temporary directory"
  # The Compose file reads ../../.env. Rebuild that layout in a temporary folder, with every
  # blank value in .env.example filled by a dummy, so the real .env is never read or needed.
  mkdir -p "$work/infra"
  cp -R "$dir" "$work/infra/compose"
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ $line =~ ^([A-Za-z_][A-Za-z0-9_]*)=[[:space:]]*$ ]]; then
      printf '%s=ci-validation-only\n' "${BASH_REMATCH[1]}"
    else
      printf '%s\n' "$line"
    fi
  done <"$example" >"$work/.env"
  # Start from an empty environment so that COMPOSE_* or POSTGRES_* variables in the caller's shell
  # cannot change what is validated.
  local -a clean=("PATH=$PATH" "HOME=${HOME:-/nonexistent}")
  [ -z "${DOCKER_CONFIG:-}" ] || clean+=("DOCKER_CONFIG=$DOCKER_CONFIG")
  show_cmd docker compose -f "$dir/docker-compose.yml" config --format json
  if ! env -i "${clean[@]}" docker compose -f "$work/infra/compose/docker-compose.yml" config --format json >"$work/rendered.json" 2>"$work/stderr.txt"; then
    cat "$work/stderr.txt"
    rm -rf "$work"
    int_failed "Docker Compose rejects the files in $dir"
  fi
  show_cmd python3 -I - rendered.json "$example" "$dir"
  py_compose_config "$work/rendered.json" "$example" "$dir"
  RC=$?
  rm -rf "$work"
  case $RC in
    0) ;;
    3) int_blocked "the Compose check could not read its inputs (see above)" ;;
    *) int_failed "the Compose files break a rule above" ;;
  esac
}

# ----- the script's own tests -------------------------------------------------------------------
int_ci_self_test() {
  need_tool python3
  run_self_tests all
}

# Dispatch for "--internal NAME [ARGUMENT...]". Only the names below are accepted.
LOGDIR_INT=""
run_internal() {
  local name=${1:-}
  [ "$#" -gt 0 ] && shift
  LOGDIR_INT=$(mktemp -d "${TMPDIR:-/tmp}/factory-ci-int.XXXXXX") || int_blocked "cannot create a temporary directory"
  trap 'rm -rf "$LOGDIR_INT"' EXIT
  case $name in
    no-secrets-in-config) int_no_secrets_in_config "$@" ;;
    no-secrets-selftest)
      need_tool python3
      py_no_secrets selftest
      ;;
    workflow-policy) int_workflow_policy "$@" ;;
    tool-pins) int_tool_pins "$@" ;;
    policy-yaml) int_policy_yaml "$@" ;;
    schemas) int_schemas "$@" ;;
    pyright) int_pyright "$@" ;;
    shellcheck) int_shellcheck "$@" ;;
    compose-config) int_compose_config "$@" ;;
    rust-deny) int_rust_deny "$@" ;;
    rust-audit) int_rust_audit "$@" ;;
    mermaid) int_mermaid "$@" ;;
    secret-scan) int_secret_scan "$@" ;;
    ci-self-test) int_ci_self_test "$@" ;;
    *) usage_error "unknown internal step '$name'" ;;
  esac
  # An internal step that returns without calling int_blocked, int_failed or int_not_applicable passed.
  exit 0
}

# ---------------------------------------------------------------------------------------------
# Self-tests. They run this script again as a child process, against small fixtures and against a
# PATH from which a tool has been removed. They check the exit code and the JSON line, so they test
# the same code path that a real run uses. Most also run a "control" that must come out the other
# way, to show that the failure was caused by the thing under test and by nothing else.
# ---------------------------------------------------------------------------------------------
ST_PASS=0
ST_FAIL=0
ST_BLOCKED=0
ST_TMP=""
ST_PATH=""
SUB_OUT=""
SUB_CODE=0
# Basic tools a child run needs. Notably absent: cargo, gitleaks, python3, docker.
ST_ESSENTIAL="cat cut date find grep head ls mkdir mktemp rm sed sort tail tee tr uname wc basename dirname env sh sleep chmod cp mv ln od uniq expr true false shasum sha256sum"

st_ok() {
  printf '  PASS  %s\n' "$1"
  ST_PASS=$((ST_PASS + 1))
}
st_bad() {
  printf '  FAIL  %s\n' "$1"
  ST_FAIL=$((ST_FAIL + 1))
}
st_equal() { # label actual expected
  if [ "$2" = "$3" ]; then st_ok "$1"; else st_bad "$1 (expected '$3', got '$2')"; fi
}
st_contains() { # label text needle
  case $2 in *"$3"*) st_ok "$1" ;; *) st_bad "$1 (the output does not contain: $3)" ;; esac
}
st_lacks() { # label text needle
  case $2 in *"$3"*) st_bad "$1 (the output contains: $3)" ;; *) st_ok "$1" ;; esac
}

st_workdir() {
  ST_TMP=$(mktemp -d "${TMPDIR:-/tmp}/factory-ci-selftest.XXXXXX") || int_blocked "cannot create a temporary directory"
}
st_cleanup() {
  if [ -n "$ST_TMP" ]; then rm -rf "$ST_TMP"; fi
  ST_TMP=""
  ST_PATH=""
}

# Run this script as a child process. Output goes to SUB_OUT, the exit code to SUB_CODE.
# If ST_PATH is set it replaces PATH for the child. GITHUB_ACTIONS is cleared so that the child
# does not print workflow commands.
sub_ci() {
  # The child must see exactly ST_PATH, so the factory's own tool folder is pointed at nothing.
  SUB_OUT=$(GITHUB_ACTIONS="" FACTORY_TOOLS_PREFIX=/nonexistent-factory-tools PATH="${ST_PATH:-$PATH}" "$BASH" "$SELF" "$@" 2>&1)
  SUB_CODE=$?
}
sub_json() { printf '%s\n' "$SUB_OUT" | tail -n 1; }

# json_get JSON PATH: print one value. PATH is dotted keys and list positions, for example
# "counts.FAILED", "steps.0.id", or "step:ID.status" to find a step by its id.
json_get() {
  python3 -I -c '
import json, sys
data, path = json.loads(sys.argv[1]), sys.argv[2]
if path.startswith("step:"):
    step_id, field = path[5:].split(".", 1)
    data = next(step for step in data["steps"] if step["id"] == step_id)
    path = field
for part in path.split("."):
    data = data[int(part)] if isinstance(data, list) else data[part]
print(data)
' "$1" "$2" 2>/dev/null
}

# A PATH directory that holds only the basic tools, for tests that hide a tool.
make_scrubbed_bin() {
  local dir=$1 tool src
  mkdir -p "$dir"
  for tool in $ST_ESSENTIAL; do
    src=$(type -P "$tool" 2>/dev/null) || continue
    ln -s "$src" "$dir/$tool"
  done
}

write_step() { # write_step DIR FILE ID TITLE REQUIRES RUN [EXTRA_LINE]
  {
    printf 'id = %s\ntitle = %s\nrequires = %s\nrun = %s\n' "$3" "$4" "$5" "$6"
    if [ -n "${7:-}" ]; then printf '%s\n' "$7"; fi
  } >"$1/$2"
}
write_script() { # write_script PATH EXIT_CODE MESSAGE
  printf '#!/bin/sh\necho "%s"\nexit %s\n' "$3" "$2" >"$1"
  chmod +x "$1"
}

# ----- BLOCKED ----------------------------------------------------------------------------------
st_blocked() {
  printf '\nself-test blocked: a step that cannot run is BLOCKED, with its own exit code, and is never a pass\n'
  st_workdir
  local d="$ST_TMP/fx" bin="$ST_TMP/bin" json
  mkdir -p "$d"

  write_step "$d" 10-missing.step needs-missing-tool "Fixture that needs an absent tool" no-such-tool-for-ci-selftest true
  sub_ci --no-builtin --steps-dir "$d"
  json=$(sub_json)
  st_equal "an absent tool makes the run exit 3" "$SUB_CODE" 3
  st_contains "the output says BLOCKED" "$SUB_OUT" "BLOCKED"
  st_contains "the reason names the absent tool" "$SUB_OUT" "no-such-tool-for-ci-selftest"
  st_equal "the JSON outcome is BLOCKED" "$(json_get "$json" outcome)" BLOCKED
  st_equal "the step status is BLOCKED and not NOT_APPLICABLE" "$(json_get "$json" step:needs-missing-tool.status)" BLOCKED

  # A real step of this script, with its real tool hidden from PATH, then the same step with a
  # stand-in for the tool. Only the presence of the tool differs between the two runs.
  make_scrubbed_bin "$bin"
  ST_PATH=$bin
  sub_ci --only rust-fmt
  json=$(sub_json)
  st_equal "hiding cargo makes the real step rust-fmt exit 3" "$SUB_CODE" 3
  st_equal "rust-fmt is BLOCKED" "$(json_get "$json" step:rust-fmt.status)" BLOCKED
  st_contains "the output tells the user how to install cargo" "$SUB_OUT" "rustup"
  # shellcheck disable=SC2016  # the text is meant to reach the file unexpanded
  printf '#!/bin/sh\ncase "$1" in --version) echo "cargo 0.0.0 (self-test stand-in)" ;; esac\nexit 0\n' >"$bin/cargo"
  chmod +x "$bin/cargo"
  sub_ci --only rust-fmt
  st_equal "control: with a cargo on PATH the same step is PASSED" "$(json_get "$(sub_json)" step:rust-fmt.status)" PASSED
  st_equal "control: and the run exits 0" "$SUB_CODE" 0
  ST_PATH=""

  # A tool that exists but cannot run (for example a rustup shim without its toolchain).
  mkdir -p "$ST_TMP/broken"
  write_script "$ST_TMP/broken/brokentool" 1 "I am broken"
  write_step "$d" 11-broken.step uses-broken-tool "Fixture with a tool that does not start" brokentool true
  ST_PATH="$ST_TMP/broken:$PATH"
  sub_ci --no-builtin --steps-dir "$d" --only uses-broken-tool
  ST_PATH=""
  st_equal "a tool that is on PATH but does not run is BLOCKED" "$(json_get "$(sub_json)" step:uses-broken-tool.status)" BLOCKED

  # A command that is not there is missing evidence, not a test failure.
  rm -f "$d"/*.step
  write_step "$d" 20-nocmd.step no-such-program "Fixture whose program does not exist" "" no-such-program-for-ci-selftest
  write_step "$d" 21-noscript.step no-such-script "Fixture whose script does not exist" "" scripts/no-such-script-for-ci-selftest.sh
  sub_ci --no-builtin --steps-dir "$d"
  json=$(sub_json)
  st_equal "a missing program is BLOCKED" "$(json_get "$json" step:no-such-program.status)" BLOCKED
  st_equal "a missing script is BLOCKED" "$(json_get "$json" step:no-such-script.status)" BLOCKED

  # Exit code 3 from a command means BLOCKED. Another code means BLOCKED only when declared.
  rm -f "$d"/*.step
  write_script "$ST_TMP/exit3.sh" 3 "fixture: I could not run"
  write_script "$ST_TMP/exit2.sh" 2 "fixture: exit two"
  write_step "$d" 30-exit3.step exit-three "Fixture that exits 3" "" "$ST_TMP/exit3.sh"
  write_step "$d" 31-exit2-undeclared.step exit-two-undeclared "Fixture that exits 2, not declared" "" "$ST_TMP/exit2.sh"
  write_step "$d" 32-exit2-declared.step exit-two-declared "Fixture that exits 2, declared as BLOCKED" "" "$ST_TMP/exit2.sh" "blocked_codes = 2"
  sub_ci --no-builtin --steps-dir "$d"
  json=$(sub_json)
  st_equal "exit code 3 from a command is BLOCKED" "$(json_get "$json" step:exit-three.status)" BLOCKED
  st_equal "exit code 2 is FAILED when it is not declared as BLOCKED" "$(json_get "$json" step:exit-two-undeclared.status)" FAILED
  st_equal "exit code 2 is BLOCKED when the step declares it" "$(json_get "$json" step:exit-two-declared.status)" BLOCKED
  st_cleanup
}

# ----- FAILED and the overall exit code ---------------------------------------------------------
st_failed() {
  printf '\nself-test failed: one failing step fails the whole script, and BLOCKED never hides it\n'
  st_workdir
  local d="$ST_TMP/fx" json
  mkdir -p "$d"
  write_script "$ST_TMP/ok.sh" 0 "fixture: all good"
  write_script "$ST_TMP/bad.sh" 1 "boom-marker-for-ci-selftest"
  write_step "$d" 10-ok.step fine "Fixture that passes" "" "$ST_TMP/ok.sh"

  sub_ci --no-builtin --steps-dir "$d"
  st_equal "all steps pass: exit 0" "$SUB_CODE" 0
  st_equal "all steps pass: outcome PASSED" "$(json_get "$(sub_json)" outcome)" PASSED

  write_step "$d" 20-bad.step broken "Fixture that fails" "" "$ST_TMP/bad.sh"
  sub_ci --no-builtin --steps-dir "$d"
  json=$(sub_json)
  st_equal "one failing step: the script exits 1" "$SUB_CODE" 1
  st_equal "one failing step: outcome FAILED" "$(json_get "$json" outcome)" FAILED
  st_equal "the failing step is FAILED" "$(json_get "$json" step:broken.status)" FAILED
  st_equal "the passing step is still PASSED" "$(json_get "$json" step:fine.status)" PASSED
  st_contains "the reason repeats the last line the step printed" "$(json_get "$json" step:broken.reason)" "boom-marker-for-ci-selftest"

  write_step "$d" 30-blocked.step gap "Fixture that is BLOCKED" no-such-tool-for-ci-selftest true
  sub_ci --no-builtin --steps-dir "$d"
  json=$(sub_json)
  st_equal "FAILED and BLOCKED together: the script exits 1, not 3" "$SUB_CODE" 1
  st_equal "FAILED and BLOCKED together: both are counted" "$(json_get "$json" counts.FAILED)/$(json_get "$json" counts.BLOCKED)" "1/1"

  rm -f "$d"/*.step
  write_step "$d" 40-na.step not-here "Fixture that does not apply" "" "$ST_TMP/ok.sh" "applies_if_path = no-such-folder-for-ci-selftest/*"
  sub_ci --no-builtin --steps-dir "$d"
  json=$(sub_json)
  st_equal "NOT_APPLICABLE exits 0" "$SUB_CODE" 0
  st_equal "the step is NOT_APPLICABLE" "$(json_get "$json" step:not-here.status)" NOT_APPLICABLE
  st_contains "the reason says why" "$(json_get "$json" step:not-here.reason)" "no-such-folder-for-ci-selftest"

  rm -f "$d"/*.step
  sub_ci --no-builtin --steps-dir "$d"
  st_equal "no steps at all: exit 2, never a vacuous pass" "$SUB_CODE" 2
  sub_ci --only no-such-step-id
  st_equal "an unknown step id in --only: exit 2" "$SUB_CODE" 2
  sub_ci --no-such-flag
  st_equal "an unknown flag: exit 2" "$SUB_CODE" 2

  write_step "$d" 10-ok.step fine "Fixture that passes" "" "$ST_TMP/ok.sh"
  sub_ci --no-builtin --steps-dir "$d"
  st_equal "a run that is not the full default set is marked partial in the JSON" "$(json_get "$(sub_json)" scope)" partial
  st_cleanup
}

# ----- drop-in step files -----------------------------------------------------------------------
dropin_rejected() { # dropin_rejected LABEL EXPECTED_TEXT  (the bad file is $ST_TMP/fx/10-bad.step)
  sub_ci --no-builtin --steps-dir "$ST_TMP/fx"
  if [ "$SUB_CODE" -eq 2 ] && [[ $SUB_OUT == *"$2"* ]]; then
    st_ok "rejected with exit 2: $1"
  else
    st_bad "$1 (expected exit 2 and '$2'; got exit $SUB_CODE)"
  fi
}

st_dropin() {
  printf '\nself-test dropin: a later package can add a step by adding a file, and a bad file stops the run\n'
  st_workdir
  local d="$ST_TMP/fx" json marker="$ST_TMP/pwned" i
  mkdir -p "$d"
  write_script "$ST_TMP/ok.sh" 0 "fixture: all good"

  # Added in the wrong order on purpose: files are read in name order.
  write_step "$d" 20-second.step second-step "Second by file name" "" "$ST_TMP/ok.sh"
  write_step "$d" 10-first.step first-step "First by file name" "" "$ST_TMP/ok.sh"
  sub_ci --no-builtin --steps-dir "$d"
  json=$(sub_json)
  st_equal "two step files are both run, with no change to ci.sh" "$(json_get "$json" counts.PASSED)" 2
  st_equal "they run in file-name order" "$(json_get "$json" steps.0.id),$(json_get "$json" steps.1.id)" "first-step,second-step"
  st_contains "the JSON records the hash of each step file" "$json" '"step_files":[{"file"'

  # The command is split on spaces and run directly. Shell syntax has no meaning.
  rm -f "$d"/*.step
  write_step "$d" 10-hostile.step hostile "Fixture with shell syntax in run" "" "echo hello; touch $marker \$(touch $marker) \`touch $marker\`"
  sub_ci --no-builtin --steps-dir "$d"
  st_equal "shell syntax in 'run' is passed as plain text to the program" "$(json_get "$(sub_json)" step:hostile.status)" PASSED
  if [ -e "$marker" ]; then st_bad "a command in a step file ran through a shell and created $marker"; else st_ok "no command hidden in a step file was executed"; fi

  # Odd text in a title must not break the JSON line.
  rm -f "$d"/*.step
  write_step "$d" 10-odd.step odd-title "Quote \" backslash \\ tab	and caf$(printf '\303\251')" "" "$ST_TMP/ok.sh"
  sub_ci --no-builtin --steps-dir "$d"
  json=$(sub_json)
  if [ "$(json_get "$json" outcome)" = PASSED ]; then st_ok "quotes, backslashes, tabs and non-ASCII bytes in a title keep the JSON valid"; else st_bad "the JSON line could not be parsed: $json"; fi

  # Broken files stop the run before anything executes.
  rm -f "$d"/*.step
  printf 'id = x\ntitle = t\nrun = true\ncolour = red\n' >"$d/10-bad.step"
  dropin_rejected "an unknown key" "unknown key"
  printf 'id = x\ntitle = t\nrun = true\nrun = false\n' >"$d/10-bad.step"
  dropin_rejected "a key that appears twice" "appears twice"
  printf 'id = x\ntitle = t\n' >"$d/10-bad.step"
  dropin_rejected "a file without run" "missing 'run'"
  printf 'id = Bad_Id\ntitle = t\nrun = true\n' >"$d/10-bad.step"
  dropin_rejected "an id with capitals and an underscore" "must be lower-case"
  printf 'id = x\ntitle = t\nrun = true\napplies_if_path = ../outside/*\n' >"$d/10-bad.step"
  dropin_rejected "applies_if_path that climbs out of the repository" "must be relative"
  printf 'id = x\ntitle = t\nrun = true\nblocked_codes = abc\n' >"$d/10-bad.step"
  dropin_rejected "blocked_codes that are not numbers" "blocked_codes"
  printf 'id = x\ntitle = t\nrun = true\nthis line has no equals sign\n' >"$d/10-bad.step"
  dropin_rejected "a line that is not key = value" "expected 'key = value'"
  : >"$d/10-bad.step"
  i=0
  while [ "$i" -lt 101 ]; do
    printf '# padding\n' >>"$d/10-bad.step"
    i=$((i + 1))
  done
  dropin_rejected "a file longer than 100 lines" "more than 100 lines"
  rm -f "$d"/*.step
  printf 'id = same\ntitle = t\nrun = true\n' >"$d/10-a.step"
  printf 'id = same\ntitle = t\nrun = true\n' >"$d/20-b.step"
  dropin_rejected "two files with the same id" "already used"
  rm -f "$d"/*.step
  printf 'id = x\ntitle = t\nrun = true\n' >"$ST_TMP/real.step"
  ln -s "$ST_TMP/real.step" "$d/10-link.step"
  dropin_rejected "a symbolic link used as a step file" "symbolic links"
  st_cleanup
}

# ----- secret-looking values --------------------------------------------------------------------
st_no_secrets() {
  printf '\nself-test no-secrets: example and Compose files hold no secret-looking value, and the detector works\n'
  st_workdir
  local rc copy="$ST_TMP/.env.example"

  "$BASH" "$SELF" --internal no-secrets-selftest
  rc=$?
  st_equal "the detector rejects every bad input and accepts every good input" "$rc" 0

  sub_ci --internal no-secrets-in-config
  printf '%s\n' "$SUB_OUT" | sed 's/^/        | /'
  st_equal "the real .env.example and Compose files hold no secret-looking value" "$SUB_CODE" 0

  cp .env.example "$copy"
  sub_ci --internal no-secrets-in-config "$copy"
  st_equal "control: an unchanged copy of .env.example passes" "$SUB_CODE" 0
  sed 's/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=hunter2/' .env.example >"$copy"
  sub_ci --internal no-secrets-in-config "$copy"
  st_equal "a password filled into .env.example is rejected" "$SUB_CODE" 1
  st_contains "and the message says why" "$SUB_OUT" "must be empty"
  # The fake token is assembled from two pieces so that no complete one is stored in this file.
  { cat .env.example; printf 'NOTE=ghp_%s\n' "Zq8Xw3Lm9Vt2Kd7Rb5Ns4Hp6Jy1Wc0Fg8Xa3"; } >"$copy"
  sub_ci --internal no-secrets-in-config "$copy"
  st_equal "a GitHub-token-shaped value under a harmless name is rejected" "$SUB_CODE" 1

  sed 's/POSTGRES_PASSWORD: \${[^}]*}/POSTGRES_PASSWORD: hunter2/' infra/compose/postgres.yml >"$ST_TMP/postgres.yml"
  sub_ci --internal no-secrets-in-config "$ST_TMP/postgres.yml"
  st_equal "a literal password written into a Compose file is rejected" "$SUB_CODE" 1
  st_cleanup
}

# ----- pinning (ST-10) and the history scan (ST-08) ---------------------------------------------
# Write a workflow file into $1/workflows/ci.yml. $2 is the line that holds the "uses" under test.
pin_fixture() {
  mkdir -p "$1/workflows"
  cat >"$1/workflows/ci.yml" <<EOF
name: fixture
on: pull_request
permissions:
  contents: read
jobs:
  ci:
    runs-on: ubuntu-24.04
    steps:
      $2
        with:
          persist-credentials: false
EOF
}
pin_rejected() { # pin_rejected LABEL USES_LINE
  rm -rf "$ST_TMP/pin"
  pin_fixture "$ST_TMP/pin" "$2"
  sub_ci --internal workflow-policy "$ST_TMP/pin"
  if [ "$SUB_CODE" -eq 1 ]; then st_ok "rejected: $1"; else st_bad "ACCEPTED (exit $SUB_CODE): $1"; fi
}

make_repo() { # make_repo DIR: an empty repository that ignores every user and system git setting
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git init -q --template= "$1" >/dev/null
}
commit_all() { # commit_all DIR MESSAGE
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C "$1" add -A
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C "$1" -c user.name=selftest -c user.email=selftest@example.invalid \
    -c commit.gpgsign=false commit -q -m "$2"
}

st_pinning() {
  printf '\nself-test pinning: actions are pinned to commit SHAs (ST-10), and the history scan is BLOCKED without its scanner (ST-08)\n'
  st_workdir
  local sha=3d3c42e5aac5ba805825da76410c181273ba90b1 bin="$ST_TMP/bin" origin="$ST_TMP/origin" clone="$ST_TMP/clone" git_path

  sub_ci --internal workflow-policy
  printf '%s\n' "$SUB_OUT" | sed 's/^/        | /'
  st_equal "the real workflow files follow every rule" "$SUB_CODE" 0

  rm -rf "$ST_TMP/pin"
  pin_fixture "$ST_TMP/pin" "- uses: actions/checkout@$sha # v7.0.1"
  sub_ci --internal workflow-policy "$ST_TMP/pin"
  st_equal "control: a fixture pinned to a full commit SHA passes" "$SUB_CODE" 0

  pin_rejected "a version tag" "- uses: actions/checkout@v4"
  pin_rejected "a branch name" "- uses: actions/checkout@main"
  pin_rejected "a short SHA" "- uses: actions/checkout@3d3c42e"
  pin_rejected "a 41-character SHA" "- uses: actions/checkout@${sha}a"
  pin_rejected "an upper-case SHA" "- uses: actions/checkout@3D3C42E5AAC5BA805825DA76410C181273BA90B1"
  pin_rejected "a tag inside quotes" "- uses: \"actions/checkout@v4\""
  pin_rejected "a tag in flow style" "- {uses: actions/checkout@v4}"
  pin_rejected "a Docker image by tag" "- uses: docker://alpine:3.20"
  pin_rejected "a reusable workflow by tag" "- uses: octo/repo/.github/workflows/x.yml@v1"
  pin_rejected "a value that is not on the same line" "- uses:"
  pin_rejected "a value built from an expression" "- uses: actions/checkout@\${{ matrix.ref }}"
  rm -rf "$ST_TMP/pin"
  pin_fixture "$ST_TMP/pin" "- uses: docker://alpine@sha256:$(printf '%064d' 7)"
  sub_ci --internal workflow-policy "$ST_TMP/pin"
  st_equal "control: a Docker image pinned by digest passes" "$SUB_CODE" 0

  # The other workflow rules.
  rm -rf "$ST_TMP/pin"
  pin_fixture "$ST_TMP/pin" "- uses: actions/checkout@$sha"
  sed -i.bak 's/^on: pull_request$/on: pull_request_target/' "$ST_TMP/pin/workflows/ci.yml"
  sub_ci --internal workflow-policy "$ST_TMP/pin"
  st_equal "the trigger pull_request_target is rejected" "$SUB_CODE" 1
  rm -rf "$ST_TMP/pin"
  pin_fixture "$ST_TMP/pin" "- uses: actions/checkout@$sha"
  sed -i.bak 's/contents: read/contents: write/' "$ST_TMP/pin/workflows/ci.yml"
  sub_ci --internal workflow-policy "$ST_TMP/pin"
  st_equal "a write permission is rejected" "$SUB_CODE" 1
  rm -rf "$ST_TMP/pin"
  pin_fixture "$ST_TMP/pin" "- uses: actions/checkout@$sha"
  sed -i.bak '/^permissions:/,/contents: read/d' "$ST_TMP/pin/workflows/ci.yml"
  sub_ci --internal workflow-policy "$ST_TMP/pin"
  st_equal "a workflow with no permissions block is rejected" "$SUB_CODE" 1
  rm -rf "$ST_TMP/pin"
  pin_fixture "$ST_TMP/pin" "- uses: actions/checkout@$sha"
  # shellcheck disable=SC2016  # the text is meant to reach the file unexpanded
  printf '      - run: echo "${{ secrets.DEPLOY_KEY }}"\n' >>"$ST_TMP/pin/workflows/ci.yml"
  sub_ci --internal workflow-policy "$ST_TMP/pin"
  st_equal "reading a secret in a workflow is rejected" "$SUB_CODE" 1
  rm -rf "$ST_TMP/pin"
  pin_fixture "$ST_TMP/pin" "- uses: actions/checkout@$sha"
  # shellcheck disable=SC2016  # the text is meant to reach the file unexpanded
  printf '      - run: echo "${{ github.event.pull_request.title }}"\n' >>"$ST_TMP/pin/workflows/ci.yml"
  sub_ci --internal workflow-policy "$ST_TMP/pin"
  st_equal "using the pull request title in a workflow is rejected" "$SUB_CODE" 1
  rm -rf "$ST_TMP/pin"
  pin_fixture "$ST_TMP/pin" "- uses: actions/checkout@$sha"
  sed -i.bak '/persist-credentials/d;/with:/d' "$ST_TMP/pin/workflows/ci.yml"
  sub_ci --internal workflow-policy "$ST_TMP/pin"
  st_equal "checkout without persist-credentials: false is rejected" "$SUB_CODE" 1

  # Tool versions must agree between this script, the workflow and the pyright lockfile.
  sub_ci --internal tool-pins
  printf '%s\n' "$SUB_OUT" | sed 's/^/        | /'
  st_equal "the real tool versions agree everywhere" "$SUB_CODE" 0
  mkdir -p "$ST_TMP/pins"
  cp .github/workflows/ci.yml "$ST_TMP/pins/ci.yml"
  cp .github/tools/pyright/package.json "$ST_TMP/pins/package.json"
  cp .github/tools/pyright/package-lock.json "$ST_TMP/pins/package-lock.json"
  sub_ci --internal tool-pins scripts/lib/tool-pins.sh "$ST_TMP/pins/ci.yml" "$ST_TMP/pins/package.json" "$ST_TMP/pins/package-lock.json"
  st_equal "control: an unchanged copy of the three files agrees" "$SUB_CODE" 0
  sed 's/cargo-deny@0\.19\.9/cargo-deny@0.19.8/' .github/workflows/ci.yml >"$ST_TMP/pins/ci.yml"
  sub_ci --internal tool-pins scripts/lib/tool-pins.sh "$ST_TMP/pins/ci.yml" "$ST_TMP/pins/package.json" "$ST_TMP/pins/package-lock.json"
  st_equal "a cargo-deny version changed only in the workflow is rejected" "$SUB_CODE" 1
  sed 's|/download/v8\.30\.1/|/download/v8.30.2/|' .github/workflows/ci.yml >"$ST_TMP/pins/ci.yml"
  sub_ci --internal tool-pins scripts/lib/tool-pins.sh "$ST_TMP/pins/ci.yml" "$ST_TMP/pins/package.json" "$ST_TMP/pins/package-lock.json"
  st_equal "a gitleaks release tag that disagrees with its file name is rejected" "$SUB_CODE" 1
  cp .github/workflows/ci.yml "$ST_TMP/pins/ci.yml"
  sed 's/"pyright": "1\.1\.413"/"pyright": "1.1.412"/' .github/tools/pyright/package.json >"$ST_TMP/pins/package.json"
  sub_ci --internal tool-pins scripts/lib/tool-pins.sh "$ST_TMP/pins/ci.yml" "$ST_TMP/pins/package.json" "$ST_TMP/pins/package-lock.json"
  st_equal "a pyright version changed only in package.json is rejected" "$SUB_CODE" 1
  cp .github/tools/pyright/package.json "$ST_TMP/pins/package.json"
  sed 's/551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb/551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470ec/' \
    .github/workflows/ci.yml >"$ST_TMP/pins/ci.yml"
  sub_ci --internal tool-pins scripts/lib/tool-pins.sh "$ST_TMP/pins/ci.yml" "$ST_TMP/pins/package.json" "$ST_TMP/pins/package-lock.json"
  st_equal "a gitleaks archive hash changed only in the workflow is rejected" "$SUB_CODE" 1
  cp .github/workflows/ci.yml "$ST_TMP/pins/ci.yml"
  grep -v '^SHA256_ACTIONLINT_DARWIN_AMD64=' scripts/lib/tool-pins.sh >"$ST_TMP/pins/tool-pins.sh"
  sub_ci --internal tool-pins "$ST_TMP/pins/tool-pins.sh" "$ST_TMP/pins/ci.yml" "$ST_TMP/pins/package.json" "$ST_TMP/pins/package-lock.json"
  st_equal "a pins file without the hash for one platform is rejected" "$SUB_CODE" 1
  { cat scripts/setup-tools.sh; printf 'PIN_GITLEAKS="8.30.1"\n'; } >"$ST_TMP/pins/setup-tools.sh"
  sub_ci --internal tool-pins scripts/lib/tool-pins.sh "$ST_TMP/pins/ci.yml" "$ST_TMP/pins/package.json" "$ST_TMP/pins/package-lock.json" scripts/ci.sh "$ST_TMP/pins/setup-tools.sh"
  st_equal "a second PIN_ line in another script is rejected, even with the same value" "$SUB_CODE" 1
  sub_ci --internal tool-pins scripts/lib/tool-pins.sh "$ST_TMP/pins/ci.yml" "$ST_TMP/pins/package.json" "$ST_TMP/pins/package-lock.json" scripts/ci.sh scripts/setup-tools.sh
  st_equal "control: the real scripts keep no PIN_ line of their own" "$SUB_CODE" 0

  # The history scan. First: the scanner is hidden, so the result must be BLOCKED.
  git_path=$(type -P git 2>/dev/null || true)
  if [ -z "$git_path" ]; then
    st_bad "git is not installed, so the history-scan tests cannot run"
    st_cleanup
    return
  fi
  make_scrubbed_bin "$bin"
  ln -s "$git_path" "$bin/git"
  ST_PATH=$bin
  sub_ci --internal secret-scan
  ST_PATH=""
  st_equal "with gitleaks hidden the history scan exits 3" "$SUB_CODE" 3
  st_contains "and says BLOCKED" "$SUB_OUT" "BLOCKED"
  st_contains "and names gitleaks" "$SUB_OUT" "gitleaks"
  ST_PATH=$bin
  sub_ci --only secret-scan
  ST_PATH=""
  st_equal "the secret-scan STEP is BLOCKED in the same situation" "$(json_get "$(sub_json)" step:secret-scan.status)" BLOCKED

  # A shallow clone has no full history. Tested with a stand-in scanner that always says "clean".
  make_repo "$origin"
  printf 'one\n' >"$origin/a.txt"
  commit_all "$origin" "first"
  printf 'two\n' >"$origin/a.txt"
  commit_all "$origin" "second"
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git clone -q --depth 1 --no-local "file://$origin" "$clone" 2>/dev/null
  # shellcheck disable=SC2016  # the text is meant to reach the file unexpanded
  printf '#!/bin/sh\ncase "$1" in --version) echo "gitleaks version 0.0.0-selftest" ;; esac\nexit 0\n' >"$bin/gitleaks"
  chmod +x "$bin/gitleaks"
  ST_PATH=$bin
  sub_ci --internal secret-scan "$clone"
  st_equal "a shallow clone is BLOCKED, not scanned partially" "$SUB_CODE" 3
  st_contains "and the message says how to fix it" "$SUB_OUT" "fetch-depth: 0"
  sub_ci --internal secret-scan "$origin"
  ST_PATH=""
  st_equal "control: a full history reaches the scanner (stand-in says clean)" "$SUB_CODE" 0

  # With the real scanner: a secret that was committed and then deleted must still be found.
  if type -P gitleaks >/dev/null 2>&1; then
    local leaky="$ST_TMP/leaky" tidy="$ST_TMP/tidy"
    make_repo "$leaky"
    printf 'token=ghp_%s\n' "Zq8Xw3Lm9Vt2Kd7Rb5Ns4Hp6Jy1Wc0Fg8Xa3" >"$leaky/config.txt"
    commit_all "$leaky" "add a config"
    rm "$leaky/config.txt"
    printf 'clean\n' >"$leaky/readme.txt"
    commit_all "$leaky" "remove the config again"
    sub_ci --internal secret-scan "$leaky"
    st_equal "real gitleaks: a secret that is only in OLD history is found (FAILED)" "$SUB_CODE" 1
    st_lacks "and the secret value is redacted in the output" "$SUB_OUT" "Zq8Xw3Lm9Vt2Kd7Rb5Ns4Hp6Jy1Wc0Fg8Xa3"
    make_repo "$tidy"
    printf 'nothing secret here\n' >"$tidy/readme.txt"
    commit_all "$tidy" "clean"
    sub_ci --internal secret-scan "$tidy"
    st_equal "real gitleaks: control, a clean history passes" "$SUB_CODE" 0
  else
    printf '  NOTE  gitleaks is not installed on this machine, so the detection path was NOT exercised here.\n'
    printf '        The BLOCKED path above was. CI installs gitleaks, so CI exercises the detection path.\n'
  fi
  st_cleanup
}

# ----- Compose safety rules ---------------------------------------------------------------------
# Copy the real Compose files and .env.example into $ST_TMP/m, then break one thing at a time.
compose_fixture() {
  rm -rf "$ST_TMP/m"
  mkdir -p "$ST_TMP/m"
  cp -R infra/compose "$ST_TMP/m/compose"
  cp .env.example "$ST_TMP/m/env.example"
}
# compose_mutate_rejected LABEL EXPECTED_TEXT: run the check on the broken copy
compose_mutate_rejected() {
  sub_ci --internal compose-config "$ST_TMP/m/compose" "$ST_TMP/m/env.example"
  if [ "$SUB_CODE" -eq 1 ] && [[ $SUB_OUT == *"$2"* ]]; then
    st_ok "rejected: $1"
  else
    st_bad "$1 (expected exit 1 and '$2'; got exit $SUB_CODE)"
  fi
}
st_compose() {
  printf '\nself-test compose: the Compose check refuses unsafe settings and accepts the real files\n'
  if ! type -P docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    printf '  BLOCKED  docker with the Compose plugin is not available, so these tests could not run\n'
    ST_BLOCKED=$((ST_BLOCKED + 1))
    return
  fi
  st_workdir
  local f="$ST_TMP/m/compose/postgres.yml"
  sub_ci --internal compose-config
  st_equal "the real Compose files pass" "$SUB_CODE" 0
  compose_fixture
  sub_ci --internal compose-config "$ST_TMP/m/compose" "$ST_TMP/m/env.example"
  st_equal "control: an unchanged copy of the Compose files passes" "$SUB_CODE" 0

  compose_fixture
  sed 's|"127\.0\.0\.1:|"|' "$f" >"$f.new" && mv "$f.new" "$f"
  compose_mutate_rejected "a port published on every interface" "127.0.0.1"
  compose_fixture
  sed 's|"127\.0\.0\.1:|"0.0.0.0:|' "$f" >"$f.new" && mv "$f.new" "$f"
  compose_mutate_rejected "a port published on 0.0.0.0" "127.0.0.1"
  compose_fixture
  sed 's|@sha256:[0-9a-f]\{64\}||' "$f" >"$f.new" && mv "$f.new" "$f"
  compose_mutate_rejected "an image given by tag only" "not pinned by digest"
  compose_fixture
  awk '{print} /^    restart:/{print "    privileged: true"}' "$f" >"$f.new" && mv "$f.new" "$f"
  compose_mutate_rejected "privileged mode" "privileged"
  compose_fixture
  awk '{print} /^    restart:/{print "    pid: host"}' "$f" >"$f.new" && mv "$f.new" "$f"
  compose_mutate_rejected "the host process namespace" "pid: host"
  compose_fixture
  awk '{print} /^    volumes:$/{print "      - /var/run/docker.sock:/var/run/docker.sock"}' "$f" >"$f.new" && mv "$f.new" "$f"
  compose_mutate_rejected "the Docker socket mounted into a container" "forbidden"
  compose_fixture
  sed 's/- CHOWN/- SYS_ADMIN/' "$f" >"$f.new" && mv "$f.new" "$f"
  compose_mutate_rejected "the SYS_ADMIN capability" "SYS_ADMIN"
  compose_fixture
  # Compose can render this (it has a default), so only the "documented in .env.example" rule can reject it.
  # shellcheck disable=SC2016  # the ${...} is meant to reach the Compose file unexpanded
  awk '{print} /^    environment:$/{print "      EXTRA_SETTING: ${UNDOCUMENTED_SETTING:-x}"}' "$f" >"$f.new" && mv "$f.new" "$f"
  compose_mutate_rejected "a variable that .env.example does not document" "UNDOCUMENTED_SETTING"
  st_cleanup
}

run_self_tests() {
  local which=$1 part parts
  type -P python3 >/dev/null 2>&1 || int_blocked "python3 is needed to read the JSON lines in the self-tests. $(tool_hint python3)"
  unset CI_STEP_NOTE_FILE
  case $which in
    all) parts="blocked failed dropin no-secrets pinning compose" ;;
    blocked | failed | dropin | no-secrets | pinning | compose) parts=$which ;;
    *) usage_error "unknown self-test part: $which" ;;
  esac
  for part in $parts; do
    case $part in
      blocked) st_blocked ;;
      failed) st_failed ;;
      dropin) st_dropin ;;
      no-secrets) st_no_secrets ;;
      pinning) st_pinning ;;
      compose) st_compose ;;
    esac
  done
  printf '\nself-test result: %s passed, %s failed, %s blocked\n' "$ST_PASS" "$ST_FAIL" "$ST_BLOCKED"
  if [ "$ST_FAIL" -gt 0 ]; then exit "$EXIT_FAILED"; fi
  if [ "$ST_BLOCKED" -gt 0 ]; then exit "$EXIT_BLOCKED"; fi
  exit 0
}

# ---------------------------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------------------------
usage() {
  # The comment block at the top of this file, up to its first blank line.
  sed -n '2,/^$/p' "$SELF" | sed 's/^# \{0,1\}//'
}

absolute_path() { # a path given on the command line is relative to where the user ran the script
  case $1 in
    /*) printf '%s' "$1" ;;
    *) printf '%s/%s' "$ORIG_PWD" "$1" ;;
  esac
}

main() {
  local mode=run only="" json_file="" steps_dir=$DEFAULT_STEPS_DIR builtin=yes part=all
  ORIG_PWD=$PWD
  while [ "$#" -gt 0 ]; do
    case $1 in
      -h | --help) mode=help ;;
      --list) mode=list ;;
      --only)
        [ "$#" -ge 2 ] || usage_error "--only needs a comma-separated list of step ids"
        only=$2
        shift
        ;;
      --json-file)
        [ "$#" -ge 2 ] || usage_error "--json-file needs a path"
        json_file=$(absolute_path "$2")
        shift
        ;;
      --steps-dir)
        [ "$#" -ge 2 ] || usage_error "--steps-dir needs a folder"
        steps_dir=$(absolute_path "$2")
        shift
        ;;
      --no-builtin) builtin=no ;;
      --self-test)
        mode=selftest
        part=all
        ;;
      --self-test-blocked | --self-test-failed | --self-test-dropin | --self-test-no-secrets | --self-test-pinning | --self-test-compose)
        mode=selftest
        part=${1#--self-test-}
        ;;
      --internal)
        shift
        mode=internal
        break
        ;;
      *) usage_error "unknown argument: $1" ;;
    esac
    shift
  done

  cd "$ROOT" || usage_error "cannot enter the repository root $ROOT"
  case $mode in
    help)
      usage
      exit 0
      ;;
    internal) run_internal "$@" ;;
    selftest) run_self_tests "$part" ;;
  esac

  LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}/factory-ci.XXXXXX") || usage_error "cannot create a temporary folder"
  trap 'rm -rf "$LOGDIR"' EXIT
  trap 'exit 130' INT TERM
  [ "$builtin" = no ] || register_builtin_steps
  load_dropins "$steps_dir"
  [ "$S_COUNT" -gt 0 ] || usage_error "no steps are defined, so there is nothing to run (a run that checks nothing is never a pass)"

  local i=0
  if [ "$mode" = list ]; then
    printf '%-28s %-22s %s\n' STEP REQUIRES TITLE
    while [ "$i" -lt "$S_COUNT" ]; do
      printf '%-28s %-22s %s\n' "${S_ID[$i]}" "${S_REQ[$i]:--}" "${S_TITLE[$i]}"
      i=$((i + 1))
    done
    exit 0
  fi

  # Choose the steps to run, in table order.
  local -a want=() selected=()
  local id found scope=full
  if [ -n "$only" ]; then
    IFS=, read -r -a want <<<"$only"
    for id in "${want[@]}"; do
      step_index "$id" >/dev/null || usage_error "--only: there is no step called '$id' (see --list)"
    done
    scope=partial
  fi
  [ "$builtin" = yes ] || scope=partial
  [ "$steps_dir" = "$DEFAULT_STEPS_DIR" ] || scope=partial
  i=0
  while [ "$i" -lt "$S_COUNT" ]; do
    found=yes
    if [ -n "$only" ]; then
      found=no
      for id in "${want[@]}"; do
        if [ "$id" = "${S_ID[$i]}" ]; then found=yes; fi
      done
    fi
    if [ "$found" = yes ]; then selected+=("$i"); fi
    i=$((i + 1))
  done

  local started_at started_secs=$SECONDS pos=0 total=${#selected[@]}
  started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  printf 'Factory CI: %s steps\n' "$total"
  printf '  repository : %s\n' "$ROOT"
  printf '  head       : %s\n' "$(repo_head)"
  printf '  shell      : bash %s on %s\n' "$BASH_VERSION" "$(uname -sm 2>/dev/null || echo unknown)"
  if [ "$DROPIN_COUNT" -gt 0 ]; then
    printf '  step files : %s in %s\n' "$DROPIN_COUNT" "$steps_dir"
  else
    printf '  step files : none (no .step files in %s)\n' "$steps_dir"
  fi
  if [ "$scope" = partial ]; then
    printf '  PARTIAL RUN: %s of %s steps. This is not evidence that CI passes.\n' "$total" "$S_COUNT"
  fi
  for i in "${selected[@]}"; do
    pos=$((pos + 1))
    run_step "$i" "$pos" "$total"
  done

  print_summary "$started_at" "$started_secs" "$scope" "${selected[@]}"
  if [ -n "$json_file" ]; then
    printf '%s\n' "$SUMMARY_JSON" >"$json_file" || err "could not write $json_file"
  fi
  printf '%s\n' "$SUMMARY_JSON"
  exit "$SUMMARY_EXIT"
}

main "$@"
