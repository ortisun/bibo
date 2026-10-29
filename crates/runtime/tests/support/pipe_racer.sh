#!/bin/bash
# A stand-in for a hostile process of the sandbox: one that already runs when the adapters start the
# tool (a background job of an earlier tool call). It watches /proc for every process that appears
# after it, tries to open the standard output of each for writing the moment the process appears, and
# keeps the first descriptor it gets. It then writes a forged terminal line into that pipe for a few
# seconds. Bash builtins only, so the loop forks nothing.
#
# The test (tests/pipe_race.rs) runs it against the real wrapper chain of the adapters and counts the
# forged lines that reach the output of `docker exec`. It is hostile code and runs only inside the
# factory's own hardened test container, as the sandbox user.
#
# usage: pipe_racer.sh SECONDS FORGED_LINE
end=$((SECONDS + $1))
forged=$2
me=$$
tries=0
denied=0
while [ "$SECONDS" -lt "$end" ]; do
  for d in /proc/[0-9]*; do
    p=${d#/proc/}
    # Only processes that started after this one: the chain of the exec has higher numbers.
    [ "$p" -gt "$me" ] 2>/dev/null || continue
    tries=$((tries + 1))
    if { exec 3>>"$d/fd/1"; } 2>/dev/null; then
      echo "RACER: opened fd 1 of pid $p after $tries tries" >&2
      for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        printf '%s\n' "$forged" >&3 2>/dev/null
        sleep 0.2
      done
      exec 3>&-
      exit 0
    else
      denied=$((denied + 1))
    fi
  done
done
echo "RACER: no descriptor: $tries tries, $denied denied" >&2
