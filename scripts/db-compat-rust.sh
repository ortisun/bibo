#!/usr/bin/env bash
# scripts/db-compat-rust.sh - run the storage crate as it was written for an EARLIER schema against LATER schemas.
#
#   scripts/db-compat-rust.sh                          the default: code of revision $FACTORY_COMPAT_CODE_REV, schemas 14 to the newest
#   scripts/db-compat-rust.sh --code-rev REV           another revision of the storage crate
#   scripts/db-compat-rust.sh --schemas "14 16 18"     only these schema levels (a level is the number of migrations applied)
#   scripts/db-compat-rust.sh --suite store_contract   only this test binary (repeatable); the default is every integration test
#   scripts/db-compat-rust.sh --target-dir DIR         where cargo builds the old crate (default: inside the scratch folder)
#   scripts/db-compat-rust.sh --keep                   keep the scratch folder (the exported old source and its build)
#
# What it does, and why it is a fair "version N-1 code on version N schema" check:
#   1. Exports the repository at REV with `git archive` into a scratch folder. REV is the last commit of the storage crate that was
#      written for the schema after migration 14 (ports v1, before the claim protocol of ports v1.1 became a rule of the data).
#      Nothing in the working tree is touched.
#   2. Builds that crate's integration tests there, with its own sources, its own Cargo.lock and its own embedded list of 14
#      migrations. This is the binary the earlier release shipped.
#   3. For each schema level S, replaces the scratch folder's migrations/ by the first S migrations of THIS checkout and runs the
#      test binaries. The tests build their database from that folder at run time (tests/support/server.rs), as a superuser, the
#      way a deploy step does, and then connect as the three real logins. So the old code runs against the new schema.
#   4. Prints a matrix: one row per test binary, one column per schema level, with the failing test names under it.
#
# Level 14 is the control: the old code on the schema it was written for must pass, or the other columns mean nothing.
#
# Needs: git, tar, python3, cargo, and a local PostgreSQL install (initdb, pg_ctl, postgres: FACTORY_PG_BIN, PATH or Homebrew).
# No Docker, no network (cargo runs --offline), no database but the private cluster each test binary starts and removes.
# Exit codes: 0 the control passed and the matrix was printed (cells may be red: that is the answer), 1 the control failed,
# 2 bad usage, 3 BLOCKED (a tool is missing or the old crate does not build).

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODE_REV="${FACTORY_COMPAT_CODE_REV:-53c0938}"
SCHEMAS=""
SUITES=()
TARGET_DIR=""
KEEP=0

say() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }
blocked() { err "BLOCKED: $*"; exit 3; }
usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h | --help) usage; exit 0 ;;
    --code-rev) CODE_REV="${2:?--code-rev needs a revision}"; shift ;;
    --schemas) SCHEMAS="${2:?--schemas needs a list}"; shift ;;
    --suite) SUITES+=("${2:?--suite needs a name}"); shift ;;
    --target-dir) TARGET_DIR="${2:?--target-dir needs a folder}"; shift ;;
    --keep) KEEP=1 ;;
    *) err "unknown option: $1"; usage >&2; exit 2 ;;
  esac
  shift
done

for tool in git tar python3 cargo; do
  command -v "$tool" >/dev/null 2>&1 || blocked "$tool is not installed"
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/factory-compat.XXXXXX")"
cleanup() {
  local rc=$?
  set +e
  if [ "$KEEP" = 1 ]; then
    err "--keep: the scratch folder is $WORK"
  else
    rm -rf "$WORK"
  fi
  exit "$rc"
}
trap cleanup EXIT

CODE="$WORK/code"
mkdir -p "$CODE"
git -C "$ROOT" cat-file -e "$CODE_REV^{commit}" 2>/dev/null || blocked "revision $CODE_REV is not in this repository"
git -C "$ROOT" archive "$CODE_REV" | tar -x -C "$CODE"
[ -d "$CODE/crates/storage/tests" ] || blocked "revision $CODE_REV has no crates/storage/tests"
OLD_MIGRATIONS="$(find "$CODE/migrations" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
say "old code: $CODE_REV ($(git -C "$ROOT" log -1 --format=%s "$CODE_REV"))"
say "old code was written for $OLD_MIGRATIONS migrations; this checkout has $(find "$ROOT/migrations" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"

[ -n "$TARGET_DIR" ] || TARGET_DIR="$WORK/target"
export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_INCREMENTAL=0

say "building the old crate's integration tests (offline)..."
BUILD_JSON="$WORK/build.json"
if ! (cd "$CODE" && cargo test -p factory-storage --tests --no-run --locked --offline --message-format=json >"$BUILD_JSON" 2>"$WORK/build.err"); then
  tail -n 25 "$WORK/build.err" >&2
  blocked "the old crate did not build offline (see above)"
fi

# name<TAB>path of every integration test binary
python3 -I - "$BUILD_JSON" >"$WORK/bins.tsv" <<'PY'
import json, sys
seen = {}
for line in open(sys.argv[1]):
    try:
        m = json.loads(line)
    except json.JSONDecodeError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("executable") and m["target"]["kind"] == ["test"] and m["package_id"].find("factory-storage") >= 0:
        seen[m["target"]["name"]] = m["executable"]
for name in sorted(seen):
    print(f"{name}\t{seen[name]}")
PY
[ -s "$WORK/bins.tsv" ] || blocked "no integration test binaries were produced"

if [ "${#SUITES[@]}" -gt 0 ]; then
  : >"$WORK/bins.sel"
  for s in "${SUITES[@]}"; do
    awk -F'\t' -v n="$s" '$1 == n' "$WORK/bins.tsv" >>"$WORK/bins.sel"
    awk -F'\t' -v n="$s" '$1 == n { found = 1 } END { exit !found }' "$WORK/bins.tsv" || blocked "no test binary named $s"
  done
  mv "$WORK/bins.sel" "$WORK/bins.tsv"
fi

NEW_TOTAL="$(find "$ROOT/migrations" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
[ -n "$SCHEMAS" ] || SCHEMAS="$(seq "$OLD_MIGRATIONS" "$NEW_TOTAL" | tr '\n' ' ')"

list_migrations() { find "$ROOT/migrations" -mindepth 1 -maxdepth 1 -type d | sort; }

RESULTS="$WORK/results.tsv"
: >"$RESULTS"
for level in $SCHEMAS; do
  rm -rf "$CODE/migrations"
  mkdir -p "$CODE/migrations"
  n=0
  while IFS= read -r d; do
    n=$((n + 1))
    [ "$n" -le "$level" ] || break
    cp -R "$d" "$CODE/migrations/"
  done < <(list_migrations)
  last="$(find "$CODE/migrations" -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1 | xargs basename)"
  say "== schema level $level (last migration $last)"
  while IFS=$'\t' read -r name bin; do
    out="$WORK/run-$level-$name.out"
    rc=0
    # Run from the old crate's folder so any relative path the tests use resolves there.
    (cd "$CODE/crates/storage" && FACTORY_DB_PROVISION=local "$bin" --test-threads=4 >"$out" 2>&1) || rc=$?
    passed="$(grep -E '^test result:' "$out" | sed -E 's/.* ([0-9]+) passed.*/\1/' | tail -n 1)"
    failed="$(grep -E '^test result:' "$out" | sed -E 's/.* ([0-9]+) failed.*/\1/' | tail -n 1)"
    [ -n "$passed" ] || passed=0
    [ -n "$failed" ] || failed="?"
    names="$(grep -E '^test .* \.\.\. FAILED$' "$out" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/' | tr '\n' ',' | sed 's/,$//')"
    blocked_msg="$(grep -m1 'BLOCKED:' "$out" || true)"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$level" "$name" "$rc" "$passed" "$failed" "$names" "$blocked_msg" >>"$RESULTS"
    say "   $name: exit $rc, $passed passed, $failed failed${names:+ ($names)}${blocked_msg:+ $blocked_msg}"
  done <"$WORK/bins.tsv"
done

python3 -I - "$RESULTS" "$OLD_MIGRATIONS" <<'PY'
import sys
rows = [line.rstrip("\n").split("\t") for line in open(sys.argv[1])]
control = sys.argv[2]
levels = sorted({r[0] for r in rows}, key=int)
suites = sorted({r[1] for r in rows})
cell = {(r[0], r[1]): r for r in rows}
print()
print("| Test binary | " + " | ".join(f"schema {lv}" for lv in levels) + " |")
print("|---|" + "---|" * len(levels))
for s in suites:
    cells = []
    for lv in levels:
        r = cell.get((lv, s))
        if r is None:
            cells.append("-")
        elif r[6]:
            cells.append("BLOCKED")
        elif r[2] == "0":
            cells.append(f"pass ({r[3]})")
        else:
            cells.append(f"FAIL {r[4]}/{int(r[3]) + (int(r[4]) if r[4].isdigit() else 0)}")
    print(f"| `{s}` | " + " | ".join(cells) + " |")
failing = [r for r in rows if r[2] != "0"]
if failing:
    print()
    print("Failing tests by level:")
    for lv in levels:
        names = sorted({n for r in failing if r[0] == lv for n in (r[5].split(",") if r[5] else [f"{r[1]} (no test names: exit {r[2]})"])})
        if names:
            print(f"- schema {lv}: " + "; ".join(names))
control_bad = [r for r in rows if r[0] == control and r[2] != "0"]
sys.exit(1 if control_bad else 0)
PY
