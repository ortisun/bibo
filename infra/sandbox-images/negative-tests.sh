#!/usr/bin/env bash
# negative-tests.sh - prove that test.sh fails when an image breaks a rule.
#
#   infra/sandbox-images/negative-tests.sh [--only MUTATION]...
#
# A test that has never failed proves nothing. For each mutation below this script builds a copy
# of a real image with one deliberate defect, points test.sh at the copy and requires test.sh to
# exit 1 with a FAIL line for the rule the defect breaks. The real images are never changed: the
# copies get their own names, are labelled factory.sandbox-images.test=1 and are removed at the
# end, and images.json is not touched (the copies are recorded in a scratch file).
#
# Mutations:
#   add-git               a program named git in the verify image             -> NO-FORBIDDEN
#   setuid-bit            a setuid file in the verify image                   -> NO-SETID
#   run-as-root           the agent image's user set to root                  -> IMAGE-USER
#   secret-in-env         an API-key-shaped environment value in the agent image -> IMAGE-CONFIG
#   secret-in-file        an API-key-shaped string in a file of the verify image -> NO-SECRET-CONTENT
#   agent-tool-in-verify  a program named codex in the verify image           -> TOOLS-ONLY-IN-AGENT
#   shell-in-verify       a shell named sh in the verify image                -> SHELLS
#
# The secret-shaped strings are made at run time and never written to the repository.
#
# Exit codes: 0 every mutation was caught, 1 a mutation was NOT caught, 2 misuse, 3 BLOCKED.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
# shellcheck source=tools/common.sh
. "$here/tools/common.sh"

ONLY=""
while [ "$#" -gt 0 ]; do
  case $1 in
    --only)
      [ "$#" -ge 2 ] || sbx_usage_error "--only needs a mutation name"
      ONLY="$ONLY $2"
      shift 2
      ;;
    -h | --help)
      sed -n '2,25p' "$0"
      exit 0
      ;;
    *) sbx_usage_error "unknown argument '$1'" ;;
  esac
done

sbx_require_docker
sbx_load_pins
PLATFORM=$(sbx_daemon_platform)
REAL_JSON=$(sbx_images_json)
[ -f "$REAL_JSON" ] || sbx_blocked "$REAL_JSON does not exist. Run infra/sandbox-images/build.sh first."
AGENT_REF=$(sbx_json_get "$REAL_JSON" "$PLATFORM" agent reference 2>/dev/null) || sbx_blocked "no agent image for $PLATFORM in $REAL_JSON"
VERIFY_REF=$(sbx_json_get "$REAL_JSON" "$PLATFORM" verify reference 2>/dev/null) || sbx_blocked "no verify image for $PLATFORM in $REAL_JSON"
docker image inspect "$AGENT_REF" >/dev/null 2>&1 || sbx_blocked "$AGENT_REF is not in the local store"
docker image inspect "$VERIFY_REF" >/dev/null 2>&1 || sbx_blocked "$VERIFY_REF is not in the local store"
# BuildKit looks a digest reference up in the registry. The copies start from the local tag of the
# same image instead, which resolves in the local store.
AGENT_TAGGED="$(sbx_json_get "$REAL_JSON" "$PLATFORM" agent name):$(sbx_json_get "$REAL_JSON" "$PLATFORM" agent tag)"
VERIFY_TAGGED="$(sbx_json_get "$REAL_JSON" "$PLATFORM" verify name):$(sbx_json_get "$REAL_JSON" "$PLATFORM" verify tag)"
[ "$(docker image inspect "$AGENT_TAGGED" --format '{{.Descriptor.digest}}')" = "$(sbx_json_get "$REAL_JSON" "$PLATFORM" agent digest)" ] ||
  sbx_blocked "the tag $AGENT_TAGGED no longer points at the digest in images.json"
[ "$(docker image inspect "$VERIFY_TAGGED" --format '{{.Descriptor.digest}}')" = "$(sbx_json_get "$REAL_JSON" "$PLATFORM" verify digest)" ] ||
  sbx_blocked "the tag $VERIFY_TAGGED no longer points at the digest in images.json"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/sbx-neg.XXXXXX")
MUTANTS=""
cleanup() {
  local m
  for m in $MUTANTS; do docker image rm -f "$m" >/dev/null 2>&1; done
  rm -rf "$WORK"
}
trap cleanup EXIT

fake_secret() { $SBX_PY -c 'import secrets,sys;print(sys.argv[1]+secrets.token_hex(24))' "$1"; }

# build_mutant NAME DOCKERFILE_TEXT   (context: $WORK/NAME, which may hold extra files)
build_mutant() {
  local name=$1 text=$2 ctx="$WORK/$1"
  mkdir -p "$ctx"
  printf '%s\n' "$text" >"$ctx/Dockerfile"
  docker buildx build --pull=false --provenance=false --sbom=false --platform "$PLATFORM" \
    --label "$SBX_TEST_LABEL" --output "type=docker,name=factory-sandbox-test/mutant:$name" \
    -f "$ctx/Dockerfile" "$ctx" >"$ctx/build.log" 2>&1 || { tail -n 15 "$ctx/build.log"; return 1; }
  MUTANTS="$MUTANTS factory-sandbox-test/mutant:$name"
}

# record_mutant NAME ROLE   -> $WORK/NAME/images.json with the mutant standing in for ROLE
record_mutant() {
  local name=$1 role=$2 ctx="$WORK/$1"
  cp "$REAL_JSON" "$ctx/images.json"
  docker image inspect "factory-sandbox-test/mutant:$name" >"$ctx/inspect.json"
  $SBX_PY "$here/tools/images_json.py" record --file "$ctx/images.json" --platform "$PLATFORM" --role "$role" \
    --name factory-sandbox-test/mutant --tag "$name" --pins "$SBX_PINS" --inspect "$ctx/inspect.json" \
    --field status=ready >/dev/null
}

CAUGHT=0
MISSED=0
selected() { [ -z "$ONLY" ] || case " $ONLY " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# expect_failure NAME ROLE RULE
expect_failure() {
  local name=$1 role=$2 rule=$3 out rc
  record_mutant "$name" "$role" || { echo "ERROR $name: could not record the copy"; MISSED=$((MISSED + 1)); return; }
  out=$("$here/test.sh" --images-json "$WORK/$name/images.json" --platform "$PLATFORM" --only "$role" --rule "$rule" 2>&1)
  rc=$?
  if [ "$rc" -eq 1 ] && printf '%s\n' "$out" | grep -q "^FAIL  $rule "; then
    echo "CAUGHT  $name: test.sh exited 1 and reported: $(printf '%s\n' "$out" | grep "^FAIL  $rule " | head -n 1 | cut -c1-220)"
    CAUGHT=$((CAUGHT + 1))
  else
    echo "MISSED  $name: expected exit 1 with a FAIL $rule line; got exit $rc"
    printf '%s\n' "$out" | tail -n 8
    MISSED=$((MISSED + 1))
  fi
}

mutation() {
  local name=$1 role=$2 rule=$3 text=$4
  selected "$name" || return 0
  echo "--- $name (breaks $rule in the $role image)"
  build_mutant "$name" "$text" || { echo "ERROR $name: the copy did not build"; MISSED=$((MISSED + 1)); return; }
  expect_failure "$name" "$role" "$rule"
}

mutation add-git verify NO-FORBIDDEN "FROM $VERIFY_TAGGED AS src
FROM $VERIFY_TAGGED
COPY --from=src /usr/bin/true /usr/bin/git"

mutation setuid-bit verify NO-SETID "FROM $VERIFY_TAGGED AS src
FROM $VERIFY_TAGGED
COPY --chmod=4755 --from=src /usr/bin/true /usr/bin/suid-probe"

mutation run-as-root agent IMAGE-USER "FROM $AGENT_TAGGED
USER 0:0"

mutation secret-in-env agent IMAGE-CONFIG "FROM $AGENT_TAGGED
ENV ANTHROPIC_API_KEY=$(fake_secret sk-ant-api03-)"

if selected secret-in-file; then
  mkdir -p "$WORK/secret-in-file"
  printf 'token=%s\n' "$(fake_secret ghp_ | cut -c1-40)" >"$WORK/secret-in-file/leftover.conf"
fi
mutation secret-in-file verify NO-SECRET-CONTENT "FROM $VERIFY_TAGGED
COPY leftover.conf /etc/leftover.conf"

mutation agent-tool-in-verify verify TOOLS-ONLY-IN-AGENT "FROM $VERIFY_TAGGED AS src
FROM $VERIFY_TAGGED
COPY --from=src /usr/bin/true /usr/local/bin/codex"

mutation shell-in-verify verify SHELLS "FROM $AGENT_TAGGED AS agent
FROM $VERIFY_TAGGED
COPY --from=agent /usr/bin/dash /usr/bin/sh"

echo
echo "mutations caught: $CAUGHT, missed: $MISSED"
if [ "$MISSED" -gt 0 ] || [ "$CAUGHT" -eq 0 ]; then
  echo "RESULT: FAILED"
  exit "$EXIT_FAILED"
fi
echo "RESULT: PASSED (every deliberate defect was caught)"
