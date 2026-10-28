# shellcheck shell=bash
# scripts/lib/ops.sh - helpers shared by local-up.sh, backup.sh, restore.sh, restore-drill.sh and smoke.sh
# (work package s1-local-deployment). Source it; do not run it.
#
#   OPS_TOOL=backup . "$(dirname "$0")/lib/ops.sh"
#
# What it gives the scripts:
#   * the exit-code convention of scripts/ci.sh: 0 done, 1 failed, 2 misuse, 3 BLOCKED (a prerequisite is
#     missing, so nothing was verified; never a pass),
#   * the machine-wide Docker lock that the sandbox tests use, so two runs never create networks at the
#     same moment from the small address pool Docker shares among all the stacks on this machine,
#   * a cleanup list that runs on exit, Ctrl-C and a kill, and a check that nothing labelled with this run
#     is left,
#   * the compose project, the PostgreSQL container, the artifact volume and the secret files,
#   * the checks file that becomes the JSON report.
#
# Works with the bash that ships with macOS (3.2): no associative arrays, no mapfile.

OPS_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
OPS_ROOT=$(cd "$OPS_LIB_DIR/../.." && pwd -P)
OPS_COMPOSE_FILE="$OPS_ROOT/infra/compose/local.yml"
OPS_TOOL=${OPS_TOOL:-ops}
OPS_MIN_COMPOSE_VERSION="2.24.0"
OPS_PINNED_DIESEL="2.3.11"

ops_say() { printf '%s\n' "$*"; }
ops_warn() { printf '%s: warning: %s\n' "$OPS_TOOL" "$*" >&2; }
ops_die() { printf '%s: error: %s\n' "$OPS_TOOL" "$*" >&2; exit 1; }
ops_blocked() { printf '%s: BLOCKED: %s\n' "$OPS_TOOL" "$*" >&2; exit 3; }
ops_usage_error() { printf '%s: %s\n' "$OPS_TOOL" "$*" >&2; exit 2; }

ops_py() { python3 -I "$OPS_LIB_DIR/factory_ops.py" "$@"; }

# ---- cleanup ------------------------------------------------------------------------------------

OPS_CLEANUPS=()
OPS_CLEANING=0

# Register a command to run when the script ends, last registered first.
ops_on_exit() { OPS_CLEANUPS+=("$1"); }

ops_run_cleanups() {
  local ops_i
  [ "$OPS_CLEANING" = 1 ] && return 0
  OPS_CLEANING=1
  set +e
  ops_i=${#OPS_CLEANUPS[@]}
  while [ "$ops_i" -gt 0 ]; do
    ops_i=$((ops_i - 1))
    eval "${OPS_CLEANUPS[$ops_i]}" || ops_warn "cleanup step failed: ${OPS_CLEANUPS[$ops_i]}"
  done
  return 0
}

ops_install_traps() {
  # A cleanup step may set OPS_EXIT_CODE to turn a clean exit into a failure (for example, objects left over).
  # The status gets its own name: a script function that has a local "rc" would otherwise be written to by this
  # trap (bash scoping is dynamic), and the exit code would be lost.
  trap 'ops_exit_status=$?; ops_run_cleanups; exit "${OPS_EXIT_CODE:-$ops_exit_status}"' EXIT
  trap 'exit 130' INT
  trap 'ops_warn "terminated (also what the Docker lock watchdog does to a run that holds the lock too long)"; exit 143' TERM
}

# ---- prerequisites ------------------------------------------------------------------------------

# True when version $1 is at least version $2 (a leading "v" and a suffix such as "-desktop.1" are ignored).
ops_version_at_least() {
  local have=$1 want=$2 i h w
  local -a hp wp
  have=${have#v}; have=${have%%[!0-9.]*}
  want=${want#v}; want=${want%%[!0-9.]*}
  IFS=. read -r -a hp <<<"$have"
  IFS=. read -r -a wp <<<"$want"
  for i in 0 1 2; do
    h=${hp[$i]:-0}; w=${wp[$i]:-0}
    if [ "$h" -gt "$w" ]; then return 0; fi
    if [ "$h" -lt "$w" ]; then return 1; fi
  done
  return 0
}

ops_require_python() {
  command -v python3 >/dev/null 2>&1 || ops_blocked "python3 is not installed. The scripts use it for hashing, JSON and the lock."
}

ops_require_docker() {
  local v
  command -v docker >/dev/null 2>&1 || ops_blocked "docker is not installed or not on PATH."
  v=$(docker compose version --short 2>/dev/null) || ops_blocked "the 'docker compose' plugin is not available. Install Docker Compose $OPS_MIN_COMPOSE_VERSION or newer."
  ops_version_at_least "$v" "$OPS_MIN_COMPOSE_VERSION" || ops_blocked "Docker Compose $v is too old. This stack needs $OPS_MIN_COMPOSE_VERSION or newer."
  docker info >/dev/null 2>&1 || ops_blocked "the Docker daemon is not running, or this user cannot reach it."
}

ops_require_psql() {
  command -v psql >/dev/null 2>&1 || ops_blocked "psql is not installed (version 16 or newer). The login checks connect from the host."
}

ops_require_diesel() {
  local v
  command -v diesel >/dev/null 2>&1 || ops_blocked "the diesel CLI is not installed. cargo install diesel_cli --version $OPS_PINNED_DIESEL --locked --no-default-features --features postgres"
  v=$(diesel --version 2>/dev/null | sed -n 's/^ *Version: *//p' | head -n1)
  [ "$v" = "$OPS_PINNED_DIESEL" ] || ops_warn "diesel CLI is $v but the pinned version is $OPS_PINNED_DIESEL."
}

# ---- the machine-wide Docker lock -----------------------------------------------------------------
#
# The same file and the same kind of lock as crates/sandbox/tests/support/docker_lock.rs: an exclusive
# flock(2) on <temp dir>/factory-docker-network.lock. The Rust code and this code exclude each other.
# Python's fcntl.flock is used because macOS has no flock(1). The lock belongs to the open file, so it
# stays held after the short Python process ends, for as long as this shell keeps descriptor 9 open.
# It is released when the script ends.

ops_lock_path() { printf '%s/factory-docker-network.lock' "${FACTORY_DOCKER_LOCK_DIR:-${TMPDIR:-/tmp}}" | sed 's#//*#/#g'; }

# Wait for the lock for at most $1 seconds (default 900, as the Rust tests do), then hold it. A script that
# holds it for more than FACTORY_DOCKER_HOLD_SECONDS (default 300) is ended, so one stuck run cannot keep
# the machine's lock for ever. Exits BLOCKED when the lock is not free in time.
ops_lock_acquire() {
  local wait=${1:-${FACTORY_DOCKER_LOCK_WAIT_SECONDS:-900}} hold=${FACTORY_DOCKER_HOLD_SECONDS:-300}
  local path waited=0 holder
  path=$(ops_lock_path)
  exec 9>>"$path" || ops_blocked "cannot open the Docker lock file $path"
  while ! python3 -I -c 'import fcntl, sys
try:
    fcntl.flock(9, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    sys.exit(1)' 2>/dev/null; do
    if [ "$waited" -ge "$wait" ]; then
      holder=$(tr -d '\n' <"$path" 2>/dev/null || true)
      ops_blocked "waited ${waited}s for the Docker lock $path and did not get it. Another run is using the Docker network pool (${holder:-holder unknown}). Wait for it, or remove the file when no run is alive."
    fi
    [ "$waited" = 0 ] && ops_say "$OPS_TOOL: waiting for the Docker lock (held by: $(tr -d '\n' <"$path" 2>/dev/null || true))"
    sleep 1
    waited=$((waited + 1))
  done
  python3 -I -c 'import os, sys, time
os.ftruncate(9, 0)
os.write(9, ("pid %d thread %s since %d" % (int(sys.argv[1]), sys.argv[2], time.time())).encode())' "$$" "$OPS_TOOL" 2>/dev/null || true
  OPS_LOCK_HELD=1
  # The watchdog closes descriptor 9 so that it never holds the lock itself, and has no output of its own, so a
  # caller that reads this script's output through a pipe is not kept waiting for it. The TERM trap of
  # ops_install_traps reports that the run was ended.
  (
    exec 9>&- >/dev/null 2>&1
    n=0
    # Stop at once if the script is gone (it may have been killed without running its traps), so a recycled
    # process id is never sent a signal.
    while [ "$n" -lt "$hold" ]; do kill -0 $$ 2>/dev/null || exit 0; sleep 1; n=$((n + 1)); done
    kill -TERM $$
  ) &
  OPS_WATCHDOG=$!
  ops_on_exit 'kill "$OPS_WATCHDOG" 2>/dev/null; true'
}

# Hand the lock on early. A script whose stack outlives it (scripts/local-up.sh) holds the lock only while
# it creates the network.
ops_lock_release() {
  [ "${OPS_LOCK_HELD:-0}" = 1 ] || return 0
  kill "$OPS_WATCHDOG" 2>/dev/null || true
  exec 9>&-
  OPS_LOCK_HELD=0
}

# ---- run identity and temporary files -------------------------------------------------------------

# Names one run. Used in the project name and in the factory.run label, so cleanup can find exactly what
# this run created.
ops_new_run() {
  OPS_RUN_ID="${FACTORY_RUN_ID:-${OPS_RUN_ID:-$(date +%H%M%S)-$$}}"
  OPS_RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/factory-ops.XXXXXX") || ops_die "cannot make a temporary folder"
  chmod 0700 "$OPS_RUN_DIR"
  OPS_CHECKS="$OPS_RUN_DIR/checks.tsv"
  : >"$OPS_CHECKS"
  OPS_FAILED=0
  ops_on_exit 'rm -rf "$OPS_RUN_DIR"'
}

# ---- compose, secrets and the database -------------------------------------------------------------

ops_compose() { docker compose --progress quiet -p "$OPS_PROJECT" -f "$OPS_COMPOSE_FILE" --profile "$OPS_PROFILE" "$@"; }

# Create the secret files that do not exist yet. Existing ones are never changed: a changed password
# would no longer match the one stored inside the database volume.
ops_make_secrets() {
  local dir=$1 name
  mkdir -p "$dir" && chmod 0700 "$dir"
  for name in pg_superuser_password pg_password_api pg_password_worker pg_password_engine; do
    if [ ! -s "$dir/$name" ]; then
      (umask 077 && python3 -I -c 'import secrets; print(secrets.token_hex(24))' >"$dir/$name")
    fi
    chmod 0600 "$dir/$name"
  done
}

ops_secret() { tr -d '\n' <"$OPS_SECRETS_DIR/$1"; }

ops_free_port() {
  python3 -I -c 'import socket
s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

# Find the running PostgreSQL container of the project and its published loopback port.
ops_find_postgres() {
  OPS_PG=$(docker ps -q --filter "label=com.docker.compose.project=$OPS_PROJECT" \
                        --filter "label=com.docker.compose.service=postgres" | head -n1)
  [ -n "$OPS_PG" ] || ops_die "no running PostgreSQL container in the compose project '$OPS_PROJECT'. Start the stack first (scripts/local-up.sh)."
  OPS_PG_PORT=$(docker port "$OPS_PG" 5432/tcp 2>/dev/null | head -n1 | sed 's/.*://')
  OPS_PG_IMAGE_REF=$(docker inspect --format '{{.Config.Image}}' "$OPS_PG")
  OPS_ARTIFACT_VOLUME="${OPS_PROJECT}_artifacts"
}

# psql as the database superuser, inside the container, over its Unix socket (no password on any command
# line). The script is read from standard input unless arguments say otherwise.
ops_sql() { docker exec -i "$OPS_PG" psql -X -q -At -v ON_ERROR_STOP=1 -U factory_admin -d "${OPS_DB:-factory}" "$@"; }

# A password file for libpq (mode 0600): host:port:database:user:password, one line per login.
ops_write_pgpass() {
  OPS_PGPASS="$OPS_RUN_DIR/pgpass"
  (umask 077
   : >"$OPS_PGPASS"
   printf '127.0.0.1:%s:*:factory_admin:%s\n' "$OPS_PG_PORT" "$(ops_secret pg_superuser_password)" >>"$OPS_PGPASS"
   printf '127.0.0.1:%s:*:factory_api:%s\n' "$OPS_PG_PORT" "$(ops_secret pg_password_api)" >>"$OPS_PGPASS"
   printf '127.0.0.1:%s:*:factory_worker:%s\n' "$OPS_PG_PORT" "$(ops_secret pg_password_worker)" >>"$OPS_PGPASS"
   printf '127.0.0.1:%s:*:factory_engine:%s\n' "$OPS_PG_PORT" "$(ops_secret pg_password_engine)" >>"$OPS_PGPASS")
}

# psql from the host as one of the logins, over TCP on the loopback port, with the password from the pgpass
# file. The first argument is the user name.
ops_psql_as() {
  local user=$1; shift
  PGPASSFILE="$OPS_PGPASS" PGCONNECT_TIMEOUT=5 psql -X -q -At -v ON_ERROR_STOP=1 \
    -h 127.0.0.1 -p "$OPS_PG_PORT" -U "$user" -d "${OPS_DB:-factory}" "$@"
}

# Apply the migrations with the pinned Diesel CLI, as the owner role. Never from the application (ADR 0007).
ops_migrate() {
  local cfg="$OPS_RUN_DIR/diesel.toml"
  printf '[migrations_directory]\ndir = "%s"\n' "$OPS_ROOT/migrations" >"$cfg"
  DATABASE_URL="postgres://factory_admin@127.0.0.1:$OPS_PG_PORT/factory" PGPASSFILE="$OPS_PGPASS" \
    diesel --config-file "$cfg" migration run >"$OPS_RUN_DIR/migrate.log" 2>&1 \
    || { sed -n '1,20p' "$OPS_RUN_DIR/migrate.log" >&2; ops_die "diesel migration run failed"; }
}

# Create the three logins when they are missing, and set all three passwords from the secret files. The
# passwords reach psql on standard input, never on a command line or in the environment. The logins are
# the ones docs/database/for-the-storage-crate.md names.
ops_ensure_logins() {
  {
    printf "\\\\set pw_api '%s'\n" "$(ops_secret pg_password_api)"
    printf "\\\\set pw_worker '%s'\n" "$(ops_secret pg_password_worker)"
    printf "\\\\set pw_engine '%s'\n" "$(ops_secret pg_password_engine)"
    cat <<'SQL'
SELECT format('CREATE ROLE factory_api LOGIN PASSWORD %L IN ROLE factory_app, factory_resolver', :'pw_api')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'factory_api') \gexec
SELECT format('CREATE ROLE factory_worker LOGIN PASSWORD %L IN ROLE factory_app', :'pw_worker')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'factory_worker') \gexec
SELECT format('CREATE ROLE factory_engine LOGIN PASSWORD %L IN ROLE factory_system', :'pw_engine')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'factory_engine') \gexec
SELECT format('ALTER ROLE factory_api PASSWORD %L', :'pw_api') \gexec
SELECT format('ALTER ROLE factory_worker PASSWORD %L', :'pw_worker') \gexec
SELECT format('ALTER ROLE factory_engine PASSWORD %L', :'pw_engine') \gexec
SQL
  } | ops_sql -f - >/dev/null
}

# The start-up check of a pool (docs/database/tests/role_readiness.sql), run as the pool's own login.
ops_role_readiness() {
  ops_psql_as "$1" -f "$OPS_ROOT/docs/database/tests/role_readiness.sql"
}

# ---- the artifact volume ----------------------------------------------------------------------------

# Run a shell script in a throwaway container with the artifact volume at /v. The container has no network,
# a read-only root, no capabilities except the three that root needs to read and write other users' files,
# and the same image as the database (already on this machine). $1 is the volume, $2 is ro or rw, $3 the
# script. Standard input and output pass through.
ops_volume_run() {
  local volume=$1 mode=$2 script=$3
  docker run --rm -i --pull never --network none --user 0:0 \
    --cap-drop ALL --cap-add DAC_OVERRIDE --cap-add CHOWN --cap-add FOWNER \
    --security-opt no-new-privileges:true --read-only --tmpfs /tmp --memory 256m --pids-limit 64 \
    --label factory.managed=true --label "factory.test=${OPS_TEST:-false}" --label "factory.run=${OPS_RUN_ID:-local}" \
    -v "$volume:/v:$mode" --entrypoint /bin/sh "$OPS_PG_IMAGE_REF" -c "$script"
}

# One line per blob: "<sha256> <size> <path>", sorted by path. The hash is computed from the bytes on disk.
OPS_LIST_SCRIPT='cd /v || exit 1
find sha256 -type f -exec sha256sum {} + 2>/dev/null | sed "s/  / /" | LC_ALL=C sort -k2 >/tmp/h
find sha256 -type f -printf "%s %p\n" 2>/dev/null | LC_ALL=C sort -k2 >/tmp/s
awk '"'"'NR==FNR{h[$2]=$1;next}{print h[$2], $1, $2}'"'"' /tmp/h /tmp/s'

# Permissions the storage crate sets (crates/storage/src/artifact_fs): blobs 0400, folders 0700, owned by the
# factory user, nothing but files and folders, nothing outside sha256/.
OPS_STATE_SCRIPT='cd /v || exit 1
a=$(find sha256 -type f ! -perm 0400 2>/dev/null | wc -l)
b=$(find . -type d ! -perm 0700 | wc -l)
c=$(find . \( ! -user 10010 -o ! -group 10010 \) | wc -l)
d=$(find . -mindepth 1 ! -type f ! -type d | wc -l)
e=$(find . -mindepth 1 -type f ! -path "./sha256/*" | wc -l)
printf "{\"files_not_0400\":%s,\"folders_not_0700\":%s,\"not_owned_by_10010\":%s,\"links_or_special_files\":%s,\"files_outside_sha256\":%s}\n" $a $b $c $d $e'

# ---- checks and the report --------------------------------------------------------------------------

# ops_check NAME PASS|FAIL|SKIP DETAIL
ops_check() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3" >>"$OPS_CHECKS"
  printf '  %-4s  %-46s %s\n' "$2" "$1" "$3"
  [ "$2" = FAIL ] && OPS_FAILED=1
  return 0
}

# Run a factory_ops.py command that prints check lines; record them and remember a failure.
ops_py_checks() {
  local out="$OPS_RUN_DIR/py-checks.$$" rc=0
  ops_py "$@" >"$out" || rc=$?
  local name status detail
  while IFS="$(printf '\t')" read -r name status detail; do
    [ -n "$name" ] && ops_check "$name" "$status" "$detail"
  done <"$out"
  rm -f "$out"
  if [ "$rc" -ne 0 ]; then OPS_FAILED=1; fi
  return 0
}

# Write the JSON report ($1 = file or empty for none) and set the exit status from the checks.
ops_finish() {
  local out=$1 rc=0
  shift
  if [ -n "$out" ]; then
    ops_py report --checks "$OPS_CHECKS" --tool "$OPS_TOOL" --out "$out" "$@" || rc=$?
    ops_say "$OPS_TOOL: report written to $out"
  else
    ops_py report --checks "$OPS_CHECKS" --tool "$OPS_TOOL" --out "$OPS_RUN_DIR/report.json" "$@" >/dev/null || rc=$?
  fi
  [ "$OPS_FAILED" = 0 ] || rc=1
  return "$rc"
}

# ---- leftovers --------------------------------------------------------------------------------------

# After the cleanup: nothing labelled with this run may remain. Prints what is left and returns 1 if any.
ops_leftovers() {
  local c n v
  c=$(docker ps -aq --filter "label=factory.run=$OPS_RUN_ID" | wc -l | tr -d ' ')
  n=$(docker network ls -q --filter "label=factory.run=$OPS_RUN_ID" | wc -l | tr -d ' ')
  v=$(docker volume ls -q --filter "label=factory.run=$OPS_RUN_ID" | wc -l | tr -d ' ')
  ops_say "$OPS_TOOL: left over from run $OPS_RUN_ID: containers=$c networks=$n volumes=$v"
  [ "$c$n$v" = "000" ]
}

# Start the stack in the order that works with `--wait`. Compose treats a one-shot container that has
# finished (the artifact volume job) as a failure while it waits, so the job runs first, on its own, and
# the long-running services are started and waited for by name. With --no-deps Compose does not start the
# one-shot job again as a dependency. Arguments: the long-running services to start.
ops_stack_up() {
  ops_compose run --rm --no-deps -T artifacts-init >/dev/null \
    || ops_die "the artifact volume could not be prepared (docker compose run artifacts-init)"
  ops_compose up --detach --no-deps --wait --wait-timeout 180 "$@" \
    || ops_die "the stack did not become healthy. See: docker compose -p $OPS_PROJECT logs"
}

# Remove the compose project's containers, network and volumes. Only this project, only what it created.
ops_stack_down() {
  [ -n "${OPS_PROJECT:-}" ] || return 0
  ops_compose down --volumes --remove-orphans --timeout 10 >/dev/null 2>&1 || true
}
