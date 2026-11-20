#!/usr/bin/env bash
# selftest-execute-only.sh - prove that the TOOLS-EXECUTE-ONLY judgement fails when it should, with no
# Docker and no network.
#
#   infra/sandbox-images/tools/selftest-execute-only.sh
#
# test.sh rule TOOLS-EXECUTE-ONLY runs `stat` in the built agent image and hands its output to
# sbx_execute_only_problems (tools/common.sh), which judges it against lib/execute-only.txt. The
# image the repository has built so far predates the rule, so the rule cannot be shown to fail on a
# deliberate defect by building copies of that image (negative-tests.sh calls such a copy UNPROVEN
# while the real image is red for the same reason). The judgement itself is a pure function of its
# input, so the cases are made here: the right modes pass, and each defect below is named.
#
#   * a readable program anywhere in the command chain, `/usr/bin/env` first of all (finding RR-14)
#   * a program that is missing, owned by someone else, a link, or setuid
#   * a program added to execute-only.txt that the image does not have
#
# Exit codes: 0 every case behaved, 1 one did not.
set -uo pipefail

here=$(cd "$(dirname "$0")/.." && pwd -P)
# shellcheck source=/dev/null
. "$here/tools/common.sh"

failed=0
not() { ! "$@"; }
expect() {
  # expect LABEL COMMAND [ARGUMENT]...   the case behaved when the command succeeds
  local label=$1
  shift
  if "$@"; then
    printf 'ok    %s\n' "$label"
  else
    printf 'FAIL  %s\n' "$label"
    failed=1
  fi
}

list="$here/lib/execute-only.txt"
paths=$(sbx_execute_only_paths "$list")

# The right image: every listed path, regular file, 711, root.
right=$(printf '%s\n' "$paths" | while IFS= read -r p; do printf '%s|711|0:0|regular file\n' "$p"; done)

out=$(printf '%s\n' "$right" | sbx_execute_only_problems "$list")
expect "an image whose chain programs are all 0711 and owned by root is accepted" [ -z "$out" ]

# The list itself covers the chain. These are the programs crates/runtime/src/command.rs puts in a
# vector (crates/runtime/tests/execute_only_chain.rs checks the same from the Rust side).
for needed in /usr/bin/env /usr/bin/timeout /usr/local/bin/claude /opt/codex/bin/codex; do
  expect "execute-only.txt names $needed" grep -q -x -F -e "$needed" "$list"
done

# One readable program, in turn. The first case is the one RR-14 is about.
for victim in $paths; do
  mutated=$(printf '%s\n' "$right" | sed "s#^$victim|711|#$victim|755|#")
  out=$(printf '%s\n' "$mutated" | sbx_execute_only_problems "$list")
  expect "$victim left readable (0755) is named and nothing else is" [ "$out" = "$victim mode 0755" ]
done

victim=$(printf '%s\n' "$paths" | head -n 1)
out=$(printf '%s\n' "$right" | grep -v -F -e "$victim|" | sbx_execute_only_problems "$list")
expect "a missing program is named" [ "$out" = "$victim missing" ]

mutated=$(printf '%s\n' "$right" | sed "s#^$victim|711|0:0|#$victim|711|10001:10001|#")
out=$(printf '%s\n' "$mutated" | sbx_execute_only_problems "$list")
expect "a program owned by the sandbox user is named" [ "$out" = "$victim owner 10001:10001" ]

mutated=$(printf '%s\n' "$right" | sed "s#^$victim|711|0:0|regular file#$victim|777|0:0|symbolic link#")
out=$(printf '%s\n' "$mutated" | sbx_execute_only_problems "$list")
expect "a link is named, whatever its own mode says" [ "$out" = "$victim is a symbolic link, not a regular file" ]

mutated=$(printf '%s\n' "$right" | sed "s#^$victim|711|#$victim|4711|#")
out=$(printf '%s\n' "$mutated" | sbx_execute_only_problems "$list")
expect "a setuid program is named" [ "$out" = "$victim mode 4711" ]

# A list that names a program the image does not have.
extra="$(mktemp "${TMPDIR:-/tmp}/sbx-exec-only.XXXXXX")"
trap 'rm -f "$extra"' EXIT
{
  cat "$list"
  echo /usr/bin/a-program-the-image-does-not-have
} >"$extra"
out=$(printf '%s\n' "$right" | sbx_execute_only_problems "$extra")
expect "a program added to the list is required of the image" [ "$out" = "/usr/bin/a-program-the-image-does-not-have missing" ]

# An empty answer from stat is every program missing, never a pass.
out=$(printf '' | sbx_execute_only_problems "$list")
expect "no answer at all is every program missing" [ "$(printf '%s\n' "$out" | grep -c ' missing$')" -eq "$(printf '%s\n' "$paths" | wc -l | tr -d ' ')" ]

# harden.sh reads the same list and keeps no list of its own.
expect "harden.sh reads execute-only.txt" grep -q 'execute-only.txt' "$here/lib/harden.sh"
expect "harden.sh keeps no list of its own" not grep -q 'for tool in' "$here/lib/harden.sh"

if [ "$failed" -eq 0 ]; then
  echo "RESULT: PASSED"
  exit 0
fi
echo "RESULT: FAILED"
exit 1
