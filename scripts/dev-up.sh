#!/usr/bin/env bash
# scripts/dev-up.sh - start, stop or remove the local development stack.
#
# The stack is described in infra/compose/. Today it holds PostgreSQL and nothing else.
#
#   scripts/dev-up.sh                   Create .env on first use, start the stack and wait
#                                       until PostgreSQL reports healthy.
#   scripts/dev-up.sh --status          Show what is running.
#   scripts/dev-up.sh --down            Stop and remove the containers. The data is kept.
#   scripts/dev-up.sh --destroy --yes   Also delete the data volume. All local data is lost.
#   scripts/dev-up.sh --help            Show this text.
#
# What the first run does with credentials:
#   It copies .env.example to .env and writes a random 48-character password into .env.
#   The password is never printed and never written to any other file. Git ignores .env.
#   If .env already exists, the script leaves your values alone. It fills in the password
#   only when POSTGRES_PASSWORD is missing or empty.
#
# Exit codes:
#   0  done
#   1  something failed (the reason is printed)
#   2  wrong arguments
#   3  BLOCKED: Docker, or the Docker Compose plugin, is missing, too old or not running.
#      This is the same meaning that exit code 3 has in scripts/ci.sh: the work could not
#      be done, and that is never reported as success.
#
# Works with the bash that ships with macOS (3.2) and with bash 4 and 5.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
COMPOSE_FILE="$ROOT/infra/compose/docker-compose.yml"
ENV_FILE="$ROOT/.env"
ENV_EXAMPLE="$ROOT/.env.example"

# The "include: env_file:" form in docker-compose.yml needs Compose 2.24 or newer.
MIN_COMPOSE_VERSION="2.24.0"
# Seconds to wait for the health check to turn healthy before giving up.
WAIT_TIMEOUT_SECONDS=120

say() { printf '%s\n' "$*"; }
warn() { printf 'dev-up: warning: %s\n' "$*" >&2; }
die() { printf 'dev-up: error: %s\n' "$*" >&2; exit 1; }
blocked() { printf 'dev-up: BLOCKED: %s\n' "$*" >&2; exit 3; }

usage() {
  # Print the leading comment block (everything up to the first blank line after it).
  sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# True when version $1 is at least version $2. Both look like 1.2.3 (a leading "v" and any
# suffix such as "-desktop.1" are ignored).
version_at_least() {
  local have=$1 want=$2 i h w
  local -a hp wp
  have=${have#v}; have=${have%%[!0-9.]*}
  want=${want#v}; want=${want%%[!0-9.]*}
  IFS=. read -r -a hp <<<"$have"
  IFS=. read -r -a wp <<<"$want"
  for i in 0 1 2; do
    h=${hp[$i]:-0}
    w=${wp[$i]:-0}
    if [ "$h" -gt "$w" ]; then return 0; fi
    if [ "$h" -lt "$w" ]; then return 1; fi
  done
  return 0
}

require_docker() {
  command -v docker >/dev/null 2>&1 \
    || blocked "docker is not installed or not on PATH. Install Docker Desktop, or Docker Engine with the Compose plugin."
  local compose_version
  compose_version=$(docker compose version --short 2>/dev/null) \
    || blocked "the 'docker compose' plugin is not available. Install Docker Compose $MIN_COMPOSE_VERSION or newer."
  version_at_least "$compose_version" "$MIN_COMPOSE_VERSION" \
    || blocked "Docker Compose $compose_version is too old. This stack needs $MIN_COMPOSE_VERSION or newer."
  docker info >/dev/null 2>&1 \
    || blocked "the Docker daemon is not running, or this user cannot reach it. Start Docker and run this script again."
}

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

# 48 hexadecimal characters from 24 random bytes of the operating system's random source.
generate_password() {
  local password
  password=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
  [ "${#password}" -eq 48 ] || die "could not read random bytes to build a password"
  printf '%s' "$password"
}

# Print the value of one setting from .env (the last assignment wins, as in Compose).
# Used only to show non-secret settings. The file is read as text and never run as shell code.
env_value() {
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1
}

# Write a copy of $1 to $2 in which POSTGRES_PASSWORD holds a new random value.
# An empty "POSTGRES_PASSWORD=" line is replaced. If the line is absent, one is appended.
# A non-empty password is never replaced: the caller only calls this when it is blank.
# The copy is made with bash built-ins only. The password is never given to another program
# as an argument, because the arguments of a running program can be seen by other users of
# the machine in the process list.
write_with_password() {
  local source=$1 target=$2 password line replaced=no
  password=$(generate_password)
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ $line =~ ^POSTGRES_PASSWORD=[[:space:]]*$ ]]; then
      printf 'POSTGRES_PASSWORD=%s\n' "$password"
      replaced=yes
    else
      printf '%s\n' "$line"
    fi
  done <"$source" >"$target"
  if [ "$replaced" = no ]; then printf 'POSTGRES_PASSWORD=%s\n' "$password" >>"$target"; fi
}

ensure_env_file() {
  [ -f "$ENV_EXAMPLE" ] || die ".env.example is missing from $ROOT"
  local tmp
  if [ ! -e "$ENV_FILE" ]; then
    # umask 077 and mktemp both give the new file owner-only permissions.
    umask 077
    tmp=$(mktemp "$ROOT/.env.XXXXXX")
    write_with_password "$ENV_EXAMPLE" "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$ENV_FILE"
    say "Created .env from .env.example with a generated database password (not shown)."
  elif ! grep -Eq '^POSTGRES_PASSWORD=[^[:space:]]' "$ENV_FILE"; then
    umask 077
    tmp=$(mktemp "$ROOT/.env.XXXXXX")
    write_with_password "$ENV_FILE" "$tmp"
    chmod 600 "$tmp"
    mv "$tmp" "$ENV_FILE"
    say "Filled in the empty POSTGRES_PASSWORD in .env with a generated value (not shown)."
  fi
  # Warn, but do not change, if any group or other permission bit is set on the file.
  # Each -perm test below means "this bit is set", which works the same with GNU and BSD find.
  if [ -n "$(find "$ENV_FILE" -maxdepth 0 \( -perm -040 -o -perm -020 -o -perm -010 \
    -o -perm -004 -o -perm -002 -o -perm -001 \) -print)" ]; then
    warn ".env can be used by other users on this machine. Run: chmod 600 .env"
  fi
}

cmd_up() {
  require_docker
  ensure_env_file
  compose config --quiet \
    || die "the Compose files in infra/compose/ are not valid (see the message above)"
  if ! compose up --detach --wait --wait-timeout "$WAIT_TIMEOUT_SECONDS"; then
    printf '\n--- last log lines from PostgreSQL ---\n' >&2
    compose logs --tail 25 postgres >&2 || true
    die "PostgreSQL did not become healthy within ${WAIT_TIMEOUT_SECONDS}s"
  fi
  # Ask Docker which address it really published. A variable set in your shell wins over
  # .env, so the file alone can be wrong. Fall back to the file if Docker gives no answer.
  local published
  published=$(compose port postgres 5432 2>/dev/null | head -n 1) || published=""
  [ -n "$published" ] || published="127.0.0.1:$(env_value POSTGRES_HOST_PORT)"
  say ""
  say "PostgreSQL is healthy."
  say "  address   $published (reachable from this machine only)"
  say "  database  $(env_value POSTGRES_DB)"
  say "  user      $(env_value POSTGRES_USER)"
  say "  password  stored in .env as POSTGRES_PASSWORD (only you can read the file)"
  say ""
  say "Stop it, keeping the data:   scripts/dev-up.sh --down"
  say "Delete the data as well:     scripts/dev-up.sh --destroy --yes"
}

# Stop commands need .env too, because Compose reads it while loading the files.
require_env_file_for_stop() {
  if [ ! -f "$ENV_FILE" ]; then
    say "There is no .env file, so this script has not started a stack from this checkout. Nothing to do."
    exit 0
  fi
}

cmd_status() {
  require_docker
  require_env_file_for_stop
  compose ps
}

cmd_down() {
  require_docker
  require_env_file_for_stop
  compose down
  say "Stopped. The data volume was kept. Start again with scripts/dev-up.sh."
}

cmd_destroy() {
  require_docker
  require_env_file_for_stop
  compose down --volumes
  say "Stopped and deleted the data volume. All local database data is gone."
}

action=up
confirmed=no
while [ "$#" -gt 0 ]; do
  case $1 in
    --status) action=status ;;
    --down) action=down ;;
    --destroy) action=destroy ;;
    --yes) confirmed=yes ;;
    -h | --help) usage; exit 0 ;;
    *) printf 'dev-up: unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [ "$action" = destroy ] && [ "$confirmed" != yes ]; then
  printf 'dev-up: --destroy deletes all local database data. Add --yes to confirm.\n' >&2
  exit 2
fi
if [ "$confirmed" = yes ] && [ "$action" != destroy ]; then
  printf 'dev-up: --yes only makes sense together with --destroy.\n' >&2
  exit 2
fi

case $action in
  up) cmd_up ;;
  status) cmd_status ;;
  down) cmd_down ;;
  destroy) cmd_destroy ;;
esac
