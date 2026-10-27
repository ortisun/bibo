#!/bin/sh
# Footprint wrapper for the agent runtime spike. It runs inside the hardened container, mounted read-only.
#
# usage: wrap.sh COMMAND [ARGS...]
#
# It runs the command, then writes /out/footprint.txt: the exit code, every file the command left in
# the writable tmpfs mounts (home and /tmp) with its size, and the cgroup peak counters. The command's own
# output stays on stdout and stderr untouched. The wrapper is only used for runs that do not test
# signals, because a shell parent would swallow a SIGTERM that the test wants the tool to receive.
"$@"
code=$?
{
  echo "exit_code=$code"
  echo "--- files under /home/agent (bytes path)"
  find /home/agent -type f 2>/dev/null | while read -r f; do
    printf '%s %s\n' "$(wc -c <"$f" 2>/dev/null | tr -d ' ')" "$f"
  done | sort -k2
  echo "--- files under /tmp (bytes path)"
  find /tmp -type f 2>/dev/null | while read -r f; do
    printf '%s %s\n' "$(wc -c <"$f" 2>/dev/null | tr -d ' ')" "$f"
  done | sort -k2
  echo "--- sockets and fifos under /tmp and /home/agent"
  find /tmp /home/agent \( -type s -o -type p \) 2>/dev/null | sort
  echo "--- cgroup counters"
  for counter in memory.peak pids.peak memory.max pids.max; do
    printf '%s=' "$counter"
    cat "/sys/fs/cgroup/$counter" 2>/dev/null || echo unavailable
  done
} >/out/footprint.txt 2>&1
exit "$code"
