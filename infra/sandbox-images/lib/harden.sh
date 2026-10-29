#!/bin/sh
# harden.sh - build-time clean-up for the agent and verify images.
#
# Runs once, as root, inside the build stage of agent/Dockerfile and verify/Dockerfile (mounted
# from the build context, never copied into an image layer). It starts from the official Rust
# image's Debian userland and removes what a sandbox does not need:
#
#   1. every program named in forbidden-binaries.txt (git, package managers, network clients,
#      account tools, interpreters nothing needs),
#   2. the package manager's state that is only useful for installing,
#   3. the setuid and setgid bits on every file that still has one,
#   4. every shell that the image's role does not allow,
#   5. (agent) the read permission on the agent tools and on timeout,
#
# and it adds the numeric sandbox user. The test in test.sh then proves the result from outside.
#
# usage: harden.sh ROLE UID GID LOGIN_SHELL
#   ROLE         agent (keeps bash, sh and dash) or verify (keeps no shell at all)
#   UID, GID     numeric id of the sandbox user, 10000 or higher
#   LOGIN_SHELL  the shell field of the user's /etc/passwd line
#
# It is POSIX sh because it must run before, and while, the shells are being removed.
set -eu

if [ "$#" -ne 4 ]; then
    echo "usage: harden.sh ROLE UID GID LOGIN_SHELL" >&2
    exit 2
fi
role=$1
uid=$2
gid=$3
login_shell=$4
here=$(cd "$(dirname "$0")" && pwd)

case $role in
    agent | verify) ;;
    *)
        echo "harden.sh: unknown role '$role'" >&2
        exit 2
        ;;
esac
case $uid$gid in
    *[!0-9]*)
        echo "harden.sh: uid and gid must be numbers" >&2
        exit 2
        ;;
esac
if [ "$uid" -lt 10000 ] || [ "$gid" -lt 10000 ]; then
    echo "harden.sh: uid and gid must be 10000 or higher" >&2
    exit 2
fi

# --- 1. Programs that may not exist --------------------------------------------------------------
# Only executables and symbolic links are removed, so data files such as /etc/passwd are never hit
# by a program name. The names come from one file that the audit also reads.
set --
while IFS= read -r name; do
    case $name in
        '' | '#'*) continue ;;
    esac
    if [ "$#" -gt 0 ]; then
        set -- "$@" -o
    fi
    set -- "$@" -name "$name"
done <"$here/forbidden-binaries.txt"
find / -xdev \( -type l -o \( -type f -perm /111 \) \) \( "$@" \) -delete

# --- 2. Package manager state --------------------------------------------------------------------
# dpkg's own database (/var/lib/dpkg) stays, so image scanners can still list what is installed.
rm -rf /etc/apt /usr/lib/apt /usr/lib/dpkg /usr/share/dpkg /var/lib/apt /var/cache /var/log \
    /usr/local/cargo/registry /usr/local/cargo/git
mkdir -p /var/cache /var/log

# --- 3. setuid and setgid bits -------------------------------------------------------------------
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -exec chmod ug-s {} +

# --- 4. The sandbox user and its mount points ----------------------------------------------------
printf 'agent:x:%s:\n' "$gid" >>/etc/group
printf 'agent:x:%s:%s:sandbox user:/home/agent:%s\n' "$uid" "$gid" "$login_shell" >>/etc/passwd
# The supervisor mounts over these; they exist so that the read-only root needs no new directory.
mkdir -p /workspace /out /cache /home/agent
chown "$uid:$gid" /home/agent
chmod 0700 /home/agent
chmod 1777 /tmp

# --- 5. Execute-only tools (agent) ---------------------------------------------------------------
# The adapters run `env -i ... timeout ... claude|codex ...`, and the stream the adapters trust is
# the standard output of that process chain. Any process of the sandbox user can open
# /proc/<pid>/fd/1 of another process of the same user and write into that pipe, unless the other
# process is not dumpable. The kernel makes a process non-dumpable when it is started from a file
# that nobody can read, and then /proc/<pid>/fd and /proc/<pid>/mem belong to root. So the tools and
# `timeout`, the processes that hold the pipe, are execute-only: mode 0711, owned by root. They run
# the same (verified for claude 2.1.311 and codex 0.163.0, including a full turn with the Bash tool
# through the broker) and cannot be read by the sandbox user. test.sh rule TOOLS-EXECUTE-ONLY checks
# the modes (finding SBX-4 of docs/reviews/isolation-core-security-review.md).
if [ "$role" = agent ]; then
    for tool in /usr/local/bin/claude /opt/codex/bin/codex /opt/codex/bin/codex-code-mode-host /usr/bin/timeout; do
        test -f "$tool" || {
            echo "harden.sh: $tool is missing" >&2
            exit 1
        }
        chown 0:0 "$tool"
        chmod 0711 "$tool"
    done
fi

# --- 6. Shells -----------------------------------------------------------------------------------
# This is the last step, because after it nothing in this script can run a shell.
shell_names=$(grep -v -e '^#' -e '^$' "$here/shells.txt")
set --
for name in $shell_names; do
    if [ "$role" = agent ]; then
        case $name in
            sh | bash | dash) continue ;;
        esac
    fi
    if [ "$#" -gt 0 ]; then
        set -- "$@" -o
    fi
    set -- "$@" -name "$name"
done
if [ "$#" -gt 0 ]; then
    find / -xdev \( -type l -o \( -type f -perm /111 \) \) \( "$@" \) -delete
fi
