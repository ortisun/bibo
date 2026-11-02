#!/usr/bin/env bash
# Build a throwaway PostgreSQL database, run the Diesel migrations on it, and prove the schema rules.
#
#   scripts/db-test.sh                 run every suite
#   scripts/db-test.sh SUITE [SUITE..] run the named suites (see --list)
#   scripts/db-test.sh --list          print the suite names and what each one proves
#   scripts/db-test.sh write-schema    regenerate crates/storage/src/schema.rs with diesel print-schema
#   scripts/db-test.sh plans --rows N  the plans suite at N rows in each large table (a multiple of 10,000; 100000 is the
#                                      done criterion of s1-database-review). The same as FACTORY_DB_PLANS_SCALE=N/10000.
#
# Exit codes: 0 every suite passed, 1 a check failed, 2 bad usage, 3 BLOCKED.
# BLOCKED means a tool or a database that the run needs is missing. It is never a pass.
#
# Where the database comes from, first match wins:
#   1. FACTORY_DB_ADMIN_URL  a superuser URL of a server you provide (postgres://user@host:port/postgres).
#                            The script only creates and drops databases named factory_t_* and factory_tpl_*.
#   2. a local PostgreSQL install (initdb, pg_ctl and postgres found in FACTORY_PG_BIN, on PATH, or in the
#      usual Homebrew and Debian places). A private cluster is started on a unix socket and removed at the end.
#   3. Docker, image FACTORY_DB_IMAGE (default postgres:18), on a random loopback port.
# FACTORY_DB_PROVISION=local|docker|none forces one of the last two or turns provisioning off.
# FACTORY_DB_LEASE_ROUNDS (default 25) sets how many contested claims the lease suite makes.
# FACTORY_DB_PLANS_SCALE (default 1) sets the size of the plans suite: 1 is 10,000 rows in each large table, 10 is 100,000.
#
# Needs: psql, python3, and the pinned diesel CLI (see PINNED_DIESEL) for the migrations suite.

set -Eeuo pipefail

EXIT_FAIL=1
EXIT_USAGE=2
EXIT_BLOCKED=3

PINNED_DIESEL="2.3.11"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS="$ROOT/docs/database/tests"
TOOLS="$ROOT/docs/database/tools"
MIGRATIONS="$ROOT/migrations"
DIESEL_CONFIG="$ROOT/crates/storage/diesel.toml"
SCHEMA_RS="$ROOT/crates/storage/src/schema.rs"
STATE_MACHINE="$ROOT/docs/architecture/state-machine.json"

SUITES="migrations statuses ledger tenancy rls terminal_rows plans audit webhook_delivery lease outbox approvals tokens privileges api_privileges repository_map contracts store_model compat"

RUN_ID="$$_$(date +%s)"
WORK=""
SOCK=""
CONTAINER=""
PG_BIN_DIR=""
URL_PREFIX=""
URL_QUERY=""
PROVISIONED=""
KEEP=0
TEMPLATE_DB=""
RLS_LOGINS=()
RLS_PASS=""
SERVER_VERSION=""
CLONE=""
TOTAL_OK=0

export PGCLIENTENCODING=UTF8

say() { printf '%s\n' "$*"; }
err() { printf '%s\n' "$*" >&2; }

blocked() {
  err "BLOCKED: $*"
  err "BLOCKED is not a pass. Nothing was verified."
  exit "$EXIT_BLOCKED"
}

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
}

list_suites() {
  cat <<'EOF'
migrations       up, revert all, up again, redo on an empty database; the catalog (tables, policies, grants,
                 function owners) is identical afterwards, also after reverting only the newest j migrations,
                 for every j; the committed schema.rs equals diesel print-schema
statuses         every status column rejects an unknown value; allowed values, terminal flags, transitions
                 and event names equal state-machine.json
ledger           the evidence ledger refuses UPDATE, DELETE, TRUNCATE and gapped, forked or forged inserts;
                 concurrent appends to one job leave one winner and a sound chain
tenancy          a foreign key into another tenant is rejected, also for a session under row-level security;
                 unique keys carry the tenant
rls              every tenant-owned table, found from the catalog, is isolated by row-level security: another
                 tenant's rows cannot be read, added, changed or deleted, and no tenant setting sees nothing;
                 the roles, the system scope and the two lookup functions; real logins and a reused connection
terminal_rows    terminal stage runs cannot be edited except to become SUPERSEDED from PASSED or SKIPPED;
                 every other move out of a terminal state fails
plans            claim, sweep, timeline and ledger-tail queries use index scans on 10,000 generated rows (100,000
                 with FACTORY_DB_PLANS_SCALE=10), run as the roles that run them, with row-level security on
audit            the application role can only INSERT and SELECT audit events; the chain is built by the
                 server, survives concurrent writers and verifies outside PostgreSQL
webhook_delivery a duplicate delivery id cannot create a second job or outbox row, also under 50 concurrent replays
lease            concurrent claims (system role finds, tenant role swaps) give exactly one winner; stale epochs
                 and forged renewals are refused; a claimer does not block the ledger
outbox           the outbox is atomic with the state change, immutable, and consumer idempotent; the relay
                 runs as the system role
approvals        approvals bind a head SHA and only a human principal can approve
tokens           API tokens are stored hashed, expire, are audience bound and cannot be un-revoked; resolve_token
                 agrees with the view on every case
privileges       the application role has exactly the grants the design lists
api_privileges   the group of the API login (factory_api_app) holds only what the API uses: it cannot insert a token,
                 a principal, an approval, a ledger or outbox row, and it works only on the tenant it names
repository_map  a repository cannot be enabled without a project map commit, for any role; the commit is 40 lowercase hex
                 characters; the attestor is an active human of the tenant and the database stamps the time; the API login
                 may register a repository and change four columns of it, in its own tenant only
contracts        the rows can carry the fields the domain-event and evidence-ledger-entry schemas require
store_model      the tables carry what the Store port of ports v1.1 needs and the rules it states are rules of the data:
                 gate record, attestation, task nodes and graph, ledger head; the recipes of the operations that
                 need only the existing tables
compat           the statements of the code written for the schema of migration 14 keep working, and every row keeps its
                 content, after EACH later migration in turn (15, 16, 17, 18): version N-1 code on version N schema
EOF
}

# ---------------------------------------------------------------------------------------------
# cleanup

cleanup() {
  local rc=$?
  set +e
  if [ "$KEEP" = 1 ] && [ -n "$PROVISIONED" ]; then
    err "--keep: leaving the $PROVISIONED server running. Maintenance database: $(db_url postgres)"
    exit "$rc"
  fi
  if [ -n "$URL_PREFIX" ]; then
    [ -n "$CLONE" ] && drop_db "$CLONE"
    [ -n "$TEMPLATE_DB" ] && drop_db "$TEMPLATE_DB"
    # Login roles are cluster wide. The rls suite makes a few; drop them whatever happened.
    local login
    for login in ${RLS_LOGINS[@]+"${RLS_LOGINS[@]}"}; do
      psql "$(db_url postgres)" -X -q -At -c "DROP ROLE IF EXISTS \"$login\"" >/dev/null 2>&1
    done
  fi
  case "$PROVISIONED" in
    local)
      if [ -n "$PG_BIN_DIR" ] && [ -d "$WORK/data" ]; then
        "$PG_BIN_DIR/pg_ctl" -D "$WORK/data" -m immediate -w stop >/dev/null 2>&1
      fi
      ;;
    docker)
      [ -n "$CONTAINER" ] && docker rm -f "$CONTAINER" >/dev/null 2>&1
      ;;
  esac
  [ -n "$WORK" ] && rm -rf "$WORK"
  [ -n "$SOCK" ] && rm -rf "$SOCK"
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# ---------------------------------------------------------------------------------------------
# connection helpers

db_url() { printf '%s/%s%s' "$URL_PREFIX" "$1" "$URL_QUERY"; }

psql_db() {
  local db=$1
  shift
  psql "$(db_url "$db")" -X -q -v ON_ERROR_STOP=1 -P pager=off "$@"
}

psql_scalar() {
  local db=$1
  shift
  psql_db "$db" -At "$@"
}

create_db() { psql_scalar postgres -c "CREATE DATABASE \"$1\" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'" >/dev/null; }

create_db_from_template() { psql_scalar postgres -c "CREATE DATABASE \"$1\" TEMPLATE \"$TEMPLATE_DB\"" >/dev/null; }

drop_db() { psql "$(db_url postgres)" -X -q -At -c "DROP DATABASE IF EXISTS \"$1\" WITH (FORCE)" >/dev/null 2>&1 || true; }

# ---------------------------------------------------------------------------------------------
# provisioning

find_pg_bin() {
  local d found=""
  found="$(command -v initdb 2>/dev/null || true)"
  [ -n "$found" ] && found="$(dirname "$found")"
  for d in "${FACTORY_PG_BIN:-}" "$found" \
    /opt/homebrew/opt/postgresql@18/bin /opt/homebrew/opt/postgresql@17/bin \
    /usr/local/opt/postgresql@18/bin /usr/local/opt/postgresql@17/bin \
    /usr/lib/postgresql/18/bin /usr/lib/postgresql/17/bin; do
    # initdb alone is not enough: the libpq client package ships one with no server beside it.
    if [ -n "$d" ] && [ -x "$d/initdb" ] && [ -x "$d/pg_ctl" ] && [ -x "$d/postgres" ]; then
      PG_BIN_DIR="$d"
      return 0
    fi
  done
  return 1
}

provision_external() {
  local url=$FACTORY_DB_ADMIN_URL base
  base="${url%%\?*}"
  URL_QUERY=""
  case "$url" in *\?*) URL_QUERY="?${url#*\?}" ;; esac
  case "${base#*://}" in
    */*) URL_PREFIX="${base%/*}" ;;
    *) URL_PREFIX="$base" ;;
  esac
  PROVISIONED="external"
}

provision_local() {
  find_pg_bin || return 1
  SOCK="$(mktemp -d /tmp/fdb.XXXXXX)"
  local port=$((20000 + RANDOM % 30000))
  "$PG_BIN_DIR/initdb" -D "$WORK/data" -U postgres --auth=trust -E UTF8 --no-locale >"$WORK/initdb.log" 2>&1 || {
    err "initdb failed:"
    cat "$WORK/initdb.log" >&2
    return 1
  }
  # TCP is off: only this user can reach the private socket directory. fsync is off because the
  # cluster is thrown away; durability settings are not what these tests prove.
  "$PG_BIN_DIR/pg_ctl" -D "$WORK/data" -l "$WORK/server.log" -w \
    -o "-c listen_addresses= -c unix_socket_directories=$SOCK -c port=$port -c fsync=off -c max_connections=120" \
    start >"$WORK/pg_ctl.log" 2>&1 || {
    err "pg_ctl start failed:"
    cat "$WORK/pg_ctl.log" "$WORK/server.log" >&2
    return 1
  }
  URL_PREFIX="postgresql://postgres@"
  URL_QUERY="?host=$SOCK&port=$port"
  PROVISIONED="local"
}

provision_docker() {
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1 || return 1
  local image="${FACTORY_DB_IMAGE:-postgres:18}"
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    err "pulling $image"
    docker pull -q "$image" >/dev/null || return 1
  fi
  CONTAINER="factory-db-test-$RUN_ID"
  local password
  password="$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 24)"
  docker run -d --rm --name "$CONTAINER" -e "POSTGRES_PASSWORD=$password" \
    -p 127.0.0.1::5432 "$image" -c fsync=off -c max_connections=120 >/dev/null || return 1
  local port="" i
  for i in $(seq 1 60); do
    port="$(docker port "$CONTAINER" 5432/tcp 2>/dev/null | head -n1 | sed 's/.*://')"
    if [ -n "$port" ] && PGPASSWORD="$password" psql "postgresql://postgres@127.0.0.1:$port/postgres" -X -q -At -c 'select 1' >/dev/null 2>&1; then
      break
    fi
    port=""
    sleep 1
  done
  [ -n "$port" ] || return 1
  export PGPASSWORD="$password"
  URL_PREFIX="postgresql://postgres@127.0.0.1:$port"
  URL_QUERY=""
  PROVISIONED="docker"
}

provision() {
  local mode="${FACTORY_DB_PROVISION:-auto}"
  command -v psql >/dev/null 2>&1 || blocked "psql is not on PATH"
  command -v python3 >/dev/null 2>&1 || blocked "python3 is not on PATH"
  if [ -n "${FACTORY_DB_ADMIN_URL:-}" ]; then
    provision_external
  elif [ "$mode" = none ]; then
    blocked "FACTORY_DB_PROVISION=none and FACTORY_DB_ADMIN_URL is not set, so there is no database"
  elif [ "$mode" = docker ]; then
    provision_docker || blocked "Docker is not available or could not start the PostgreSQL image"
  elif [ "$mode" = local ]; then
    provision_local || blocked "no local PostgreSQL server binaries (initdb, pg_ctl, postgres) were found, or the server did not start"
  else
    provision_local || provision_docker || blocked "no PostgreSQL server: set FACTORY_DB_ADMIN_URL, install PostgreSQL 16 or later, or start Docker"
  fi
  if ! SERVER_VERSION="$(psql_scalar postgres -c 'SHOW server_version' 2>/dev/null)"; then
    blocked "the $PROVISIONED database server is not reachable"
  fi
  if [ "$(psql_scalar postgres -c "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")" != "t" ]; then
    blocked "the database user must be a superuser (the tests create roles and switch session settings)"
  fi
  say "database: $PROVISIONED, PostgreSQL $SERVER_VERSION"
}

# ---------------------------------------------------------------------------------------------
# diesel

# `diesel --version` prints "diesel <newline> Version: X.Y.Z <newline> Supported Backends: ...".
diesel_version() { diesel --version 2>/dev/null | sed -n 's/^ *Version: *//p' | head -n1; }

install_hint="cargo install diesel_cli --version $PINNED_DIESEL --locked --no-default-features --features postgres"

require_diesel() {
  command -v diesel >/dev/null 2>&1 || blocked "the diesel CLI is not installed. Install the pinned one: $install_hint"
  local v
  v="$(diesel_version)"
  if [ "$v" != "$PINNED_DIESEL" ]; then
    err "WARNING: diesel CLI is $v but the pinned version is $PINNED_DIESEL. schema.rs may format differently."
  fi
}

# A diesel config with no print_schema section, so that running migrations never rewrites schema.rs.
plain_diesel_config() {
  local cfg="$WORK/diesel-plain.toml"
  printf '[migrations_directory]\ndir = "%s"\n' "$MIGRATIONS" >"$cfg"
  printf '%s' "$cfg"
}

diesel_run() { # db, then diesel arguments
  local db=$1
  shift
  DATABASE_URL="$(db_url "$db")" diesel "$@"
}

# ---------------------------------------------------------------------------------------------
# databases for the suites

ensure_template() {
  [ -n "$TEMPLATE_DB" ] && return 0
  require_diesel
  TEMPLATE_DB="factory_tpl_${RUN_ID}"
  create_db "$TEMPLATE_DB"
  local cfg out="$WORK/template-migrate.out"
  cfg="$(plain_diesel_config)"
  if ! diesel_run "$TEMPLATE_DB" --config-file "$cfg" migration run >"$out" 2>&1; then
    err "diesel migration run failed on the template database:"
    cat "$out" >&2
    return 1
  fi
}

# A migrated clone with the test helpers loaded.
clone_begin() {
  ensure_template || return 1
  CLONE="factory_t_${RUN_ID}_$1"
  create_db_from_template "$CLONE"
  local out="$WORK/helpers.out"
  psql_db "$CLONE" -f "$TESTS/00_helpers.sql" >/dev/null 2>"$out" || {
    err "loading the test helpers failed:"
    cat "$out" >&2
    return 1
  }
}

clone_end() {
  [ -n "$CLONE" ] && drop_db "$CLONE"
  CLONE=""
}

show_checks() {
  local out=$1 n
  sed -E 's/^psql:[^ ]+:[0-9]+: (NOTICE|INFO):  //' "$out" | sed -E 's/^psql:[^ ]+:[0-9]+: //' | grep -v '^truncate cascades to table' || true
  n="$(grep -c 'NOTICE:  ok - ' "$out" || true)"
  TOTAL_OK=$((TOTAL_OK + n))
}

# Run SQL files (names in docs/database/tests, or absolute paths) in the clone and print the checks.
sql_in_clone() { # label, files...
  local label=$1
  shift
  local out="$WORK/$label.out" rc=0 args=() f
  for f in "$@"; do
    case "$f" in
      /*) args+=(-f "$f") ;;
      *) args+=(-f "$TESTS/$f") ;;
    esac
  done
  # Results go nowhere; the checks report through NOTICE and ERROR messages on stderr.
  psql_db "$CLONE" "${args[@]}" >/dev/null 2>"$out" || rc=$?
  show_checks "$out"
  return "$rc"
}

# One suite that is a single SQL file run on a fresh clone.
simple_suite() { # suite name, files...
  local name=$1 rc=0
  shift
  clone_begin "$name" || return 1
  sql_in_clone "$name" "$@" || rc=$?
  clone_end
  return "$rc"
}

ok() {
  say "ok - $1"
  TOTAL_OK=$((TOTAL_OK + 1))
}
not_ok() { err "NOT OK - $1"; }

expect_count() { # label, actual, expected
  if [ "$2" = "$3" ]; then
    ok "$1 ($2)"
  else
    not_ok "$1: expected $3, got $2"
    return 1
  fi
}

# ---------------------------------------------------------------------------------------------
# concurrency: release WORKERS real sessions at the same moment.
#
# A holder session takes an exclusive advisory lock. Every worker connects and asks for the same
# lock in shared mode, so all of them queue behind it. When the holder has seen WORKERS requests
# waiting it ends, the lock goes, and PostgreSQL grants every request together. Each worker then
# runs its statement. Output and exit status per worker land in $WORK/race.N.out, .err and .rc.
race() { # workers, sql (with __N__ for the worker number)
  local workers=$1 sql=$2 i p pids=() holder holder_rc=0
  rm -f "$WORK"/race.*
  psql_db "$CLONE" -At >/dev/null 2>"$WORK/race.holder.err" <<EOF &
SELECT pg_advisory_lock(424242);
DO \$\$
DECLARE
  n int := 0;
BEGIN
  FOR i IN 1..1500 LOOP
    SELECT count(*) INTO n FROM pg_locks WHERE locktype = 'advisory' AND classid = 0 AND objid = 424242 AND NOT granted;
    EXIT WHEN n >= $workers;
    PERFORM pg_sleep(0.01);
  END LOOP;
  IF n < $workers THEN
    RAISE EXCEPTION 'only % of $workers workers reached the barrier', n;
  END IF;
END
\$\$;
EOF
  holder=$!
  # Wait for the holder to own the lock before the workers start.
  for i in $(seq 1 200); do
    [ "$(psql_scalar "$CLONE" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND classid = 0 AND objid = 424242 AND granted")" = 1 ] && break
    sleep 0.02
  done
  for i in $(seq 1 "$workers"); do
    (
      rc=0
      psql_db "$CLONE" -At -c "SELECT pg_advisory_lock_shared(424242)" -c "${sql//__N__/$i}" >"$WORK/race.$i.out" 2>"$WORK/race.$i.err" || rc=$?
      echo "$rc" >"$WORK/race.$i.rc"
    ) &
    pids+=("$!")
  done
  wait "$holder" || holder_rc=$?
  for p in "${pids[@]}"; do wait "$p" || true; done
  if [ "$holder_rc" -ne 0 ]; then
    not_ok "the race barrier failed, so the workers did not start together: $(cat "$WORK/race.holder.err")"
    return 1
  fi
}

# How many workers printed exactly this line.
race_count_output() { (grep -lx -- "$1" "$WORK"/race.*.out 2>/dev/null || true) | wc -l | tr -d ' '; }
# How many workers exited with an error.
race_count_failed() { (grep -L '^0$' "$WORK"/race.*.rc 2>/dev/null || true) | wc -l | tr -d ' '; }
# How many error lines mention this text.
race_errors_mention() { (cat "$WORK"/race.*.err 2>/dev/null || true) | grep -c -- "$1" || true; }

# ---------------------------------------------------------------------------------------------
# suites

suite_migrations() {
  require_diesel
  local db="factory_t_${RUN_ID}_migrations" out="$WORK/migrations.out" cfg
  cfg="$(plain_diesel_config)"
  create_db "$db"
  local expected
  expected="$(find "$MIGRATIONS" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
  [ "$expected" -gt 0 ] || { not_ok "there are no migration directories in $MIGRATIONS"; drop_db "$db"; return 1; }

  step() { # label, command...
    local label=$1
    shift
    if "$@" >"$out" 2>&1; then
      ok "$label"
    else
      not_ok "$label"
      cat "$out" >&2
      drop_db "$db"
      return 1
    fi
  }

  # The first run uses the committed config with --locked-schema: Diesel regenerates the schema after
  # the run and fails instead of overwriting crates/storage/src/schema.rs when it differs.
  step "diesel migration run --locked-schema on an empty database ($expected migrations)" \
    diesel_run "$db" --config-file "$DIESEL_CONFIG" migration run --locked-schema || return 1
  local applied
  applied="$(psql_scalar "$db" -c 'SELECT count(*) FROM __diesel_schema_migrations')"
  if [ "$applied" != "$expected" ]; then
    not_ok "applied $applied migrations but $expected directories exist"
    drop_db "$db"
    return 1
  fi
  ok "__diesel_schema_migrations lists all $applied migrations"
  local fp_first fp_second fp_third
  fp_first="$(psql_scalar "$db" -f "$TESTS/catalog_fingerprint.sql")"

  step "diesel migration revert --all (every down.sql runs)" diesel_run "$db" --config-file "$cfg" migration revert --all || return 1
  local leftovers
  leftovers="$(psql_scalar "$db" -f "$TESTS/catalog_leftovers.sql")"
  if [ -n "$leftovers" ]; then
    not_ok "objects remain after reverting every migration:"
    err "$leftovers"
    drop_db "$db"
    return 1
  fi
  ok "nothing of ours is left after reverting everything (roles are cluster wide and stay)"

  step "diesel migration run again after a full revert" diesel_run "$db" --config-file "$cfg" migration run || return 1
  fp_second="$(psql_scalar "$db" -f "$TESTS/catalog_fingerprint.sql")"
  step "diesel migration redo --all (revert then run every migration)" diesel_run "$db" --config-file "$cfg" migration redo --all || return 1
  fp_third="$(psql_scalar "$db" -f "$TESTS/catalog_fingerprint.sql")"
  if [ "$fp_first" != "$fp_second" ] || [ "$fp_first" != "$fp_third" ]; then
    not_ok "the catalog differs between the first run, the run after revert, and the redo"
    err "  first=$fp_first second=$fp_second third=$fp_third"
    drop_db "$db"
    return 1
  fi
  ok "the catalog fingerprint is identical after up, down-up and redo (${fp_first:0:16}...)"

  # A full revert hides a down script that leaves something behind when a later down drops the table anyway (a
  # policy on a table, for example). So revert only the newest j migrations, run them again, and compare, for
  # every j. A leftover then makes the run fail ("already exists") or changes the fingerprint.
  local j
  for j in $(seq 1 "$expected"); do
    for _ in $(seq 1 "$j"); do
      if ! diesel_run "$db" --config-file "$cfg" migration revert >"$out" 2>&1; then
        not_ok "reverting the newest migration failed while reverting the $j newest"
        cat "$out" >&2
        drop_db "$db"
        return 1
      fi
    done
    if ! diesel_run "$db" --config-file "$cfg" migration run >"$out" 2>&1; then
      not_ok "running the $j newest migrations again after reverting them failed (a down script left something behind?)"
      cat "$out" >&2
      drop_db "$db"
      return 1
    fi
    if [ "$(psql_scalar "$db" -f "$TESTS/catalog_fingerprint.sql")" != "$fp_first" ]; then
      not_ok "reverting the $j newest migrations and running them again changed the catalog"
      drop_db "$db"
      return 1
    fi
  done
  ok "reverting the j newest migrations and running them again leaves the catalog unchanged, for every j from 1 to $expected"

  local printed="$WORK/print-schema.rs"
  if ! diesel_run "$db" --config-file "$DIESEL_CONFIG" print-schema >"$printed" 2>"$out"; then
    not_ok "diesel print-schema failed"
    cat "$out" >&2
    drop_db "$db"
    return 1
  fi
  if ! diff -u "$SCHEMA_RS" "$printed" >"$out" 2>&1; then
    not_ok "crates/storage/src/schema.rs differs from diesel print-schema (run: scripts/db-test.sh write-schema)"
    head -n 40 "$out" >&2
    drop_db "$db"
    return 1
  fi
  ok "the committed schema.rs equals diesel print-schema"
  drop_db "$db"
  upgrade_check
}

# The last migration of the schema before ports v1.1. The upgrade test migrates to here, loads rows, runs the rest.
UPGRADE_FROM="2026-10-27-001400"

# A data-preserving upgrade (docs/database/migration-safety.md, rule 7): build the schema as it was before ports v1.1,
# write rows into every tenant-owned table with the statements of that time, run the newer migrations, and check that
# every row is byte for byte what it was (a hash per table over the columns the table had), that the new columns hold
# their defaults, and that the statements of the earlier code still work on the new schema.
upgrade_check() {
  local db="factory_t_${RUN_ID}_upgrade" out="$WORK/upgrade.out" prev="$WORK/migrations-prev" cfg_prev cfg_all d before after kept=0
  create_db "$db"
  mkdir -p "$prev"
  for d in "$MIGRATIONS"/*/; do
    d="${d%/}"
    if [[ "$(basename "$d")" < "${UPGRADE_FROM}~" ]]; then
      cp -R "$d" "$prev/"
      kept=$((kept + 1))
    fi
  done
  cfg_prev="$WORK/diesel-prev.toml"
  printf '[migrations_directory]\ndir = "%s"\n' "$prev" >"$cfg_prev"
  cfg_all="$(plain_diesel_config)"
  if ! diesel_run "$db" --config-file "$cfg_prev" migration run >"$out" 2>&1; then
    not_ok "the migrations up to $UPGRADE_FROM did not run"
    cat "$out" >&2
    drop_db "$db"
    return 1
  fi
  ok "upgrade: the schema of the earlier version is built ($kept migrations)"
  if ! psql_db "$db" -f "$TESTS/00_helpers.sql" -f "$TESTS/upgrade_fixture.sql" >/dev/null 2>"$out"; then
    not_ok "upgrade: loading the rows of the earlier version failed"
    cat "$out" >&2
    drop_db "$db"
    return 1
  fi
  before="$(psql_scalar "$db" -f "$TESTS/upgrade_fingerprint.sql")"
  if ! diesel_run "$db" --config-file "$cfg_all" migration run >"$out" 2>&1; then
    not_ok "upgrade: the newer migrations did not run on a database with rows"
    cat "$out" >&2
    drop_db "$db"
    return 1
  fi
  after="$(psql_scalar "$db" -f "$TESTS/upgrade_fingerprint.sql")"
  if [ "$before" != "$after" ]; then
    not_ok "upgrade: rows changed while the newer migrations ran"
    diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2 || true
    drop_db "$db"
    return 1
  fi
  ok "upgrade: $(printf '%s\n' "$after" | wc -l | tr -d ' ') tables kept every row, byte for byte, over the columns they had before ($(printf '%s\n' "$after" | awk -F'|' '{ n += $2 } END { print n }') rows)"
  local rc=0
  psql_db "$db" -f "$TESTS/upgrade_check.sql" >/dev/null 2>"$out" || rc=$?
  show_checks "$out"
  drop_db "$db"
  return "$rc"
}

# Version N-1 code on version N schema, for every migration after UPGRADE_FROM, one at a time (docs/database/migration-safety.md,
# "The rule for every later migration"). The schema as it was after UPGRADE_FROM gets a row in every tenant-owned table. Then the
# later migrations are applied ONE BY ONE. After each: every table still holds its rows byte for byte over the columns it had,
# and the statements of the code that was written for UPGRADE_FROM (compat_earlier_code.sql) still run, inside a transaction that
# is rolled back, so the next step starts from the same rows. The first line is the control: the same statements on the schema they
# were written for.
suite_compat() {
  require_diesel
  local db="factory_t_${RUN_ID}_compat" out="$WORK/compat.out" step_dir="$WORK/compat-steps" cfg d name before after rc=0 kept=0 steps=()
  create_db "$db"
  mkdir -p "$step_dir"
  cfg="$WORK/diesel-compat.toml"
  printf '[migrations_directory]\ndir = "%s"\n' "$step_dir" >"$cfg"
  for d in "$MIGRATIONS"/*/; do
    d="${d%/}"
    name="$(basename "$d")"
    if [[ "$name" < "${UPGRADE_FROM}~" ]]; then
      cp -R "$d" "$step_dir/"
      kept=$((kept + 1))
    else
      steps+=("$name")
    fi
  done
  if [ "${#steps[@]}" -eq 0 ]; then
    not_ok "compat: there is no migration after $UPGRADE_FROM, so there is nothing to compare"
    drop_db "$db"
    return 1
  fi
  if ! diesel_run "$db" --config-file "$cfg" migration run >"$out" 2>&1; then
    not_ok "compat: the migrations up to $UPGRADE_FROM did not run"
    cat "$out" >&2
    drop_db "$db"
    return 1
  fi
  if ! psql_db "$db" -f "$TESTS/00_helpers.sql" -f "$TESTS/upgrade_fixture.sql" >/dev/null 2>"$out"; then
    not_ok "compat: loading the rows of the earlier version failed"
    cat "$out" >&2
    drop_db "$db"
    return 1
  fi
  before="$(psql_scalar "$db" -f "$TESTS/upgrade_fingerprint.sql")"
  # The control: the earlier code on the schema it was written for.
  psql_db "$db" -c "BEGIN" -f "$TESTS/compat_earlier_code.sql" -c "ROLLBACK" >/dev/null 2>"$out" || rc=$?
  show_checks "$out"
  if [ "$rc" -ne 0 ]; then
    not_ok "compat: the control failed: the earlier code does not run on the schema after $UPGRADE_FROM, so the comparison below means nothing"
    drop_db "$db"
    return 1
  fi
  ok "compat: code written for $UPGRADE_FROM on schema $UPGRADE_FROM (the control): its statements run"
  for name in "${steps[@]}"; do
    cp -R "$MIGRATIONS/$name" "$step_dir/"
    if ! diesel_run "$db" --config-file "$cfg" migration run >"$out" 2>&1; then
      not_ok "compat: migration $name did not run on a database with rows"
      cat "$out" >&2
      rc=1
      continue
    fi
    after="$(psql_scalar "$db" -f "$TESTS/upgrade_fingerprint.sql")"
    if [ "$before" != "$after" ]; then
      not_ok "compat: migration $name changed rows over the columns they had before"
      diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2 || true
      rc=1
    else
      ok "compat: migration $name kept every row, byte for byte, over the columns the tables had"
    fi
    if psql_db "$db" -c "BEGIN" -f "$TESTS/compat_earlier_code.sql" -c "ROLLBACK" >/dev/null 2>"$out"; then
      show_checks "$out"
      ok "compat: code written for $UPGRADE_FROM on the schema after $name: its statements run"
    else
      show_checks "$out"
      not_ok "compat: code written for $UPGRADE_FROM does NOT run on the schema after $name (this migration needs two steps: see docs/database/migration-safety.md)"
      rc=1
    fi
  done
  drop_db "$db"
  return "$rc"
}

suite_statuses() {
  ensure_template || return 1
  local expected="$WORK/expected_from_json.sql" rc=0
  python3 -I "$TOOLS/state_machine_sql.py" expected "$STATE_MACHINE" >"$expected" || return 1
  clone_begin statuses || return 1
  sql_in_clone statuses "$expected" statuses.sql || rc=$?
  clone_end
  return "$rc"
}

suite_ledger() {
  clone_begin ledger || return 1
  local rc=0
  sql_in_clone ledger ledger.sql || rc=$?
  if [ "$rc" -eq 0 ]; then ledger_race || rc=$?; fi
  clone_end
  return "$rc"
}

# Eight sessions try to append the next entry of one job at the same moment.
ledger_race() {
  local rc=0
  psql_db "$CLONE" >/dev/null 2>"$WORK/ledger-race.err" <<'EOF' || { cat "$WORK/ledger-race.err" >&2; return 1; }
SELECT dbtest.mk_tenant(5);
SELECT dbtest.mk_job(5, 1);
SELECT dbtest.mk_stage_run(5, 1, 1);
SELECT dbtest.append_entry(5, dbtest.u(5101), dbtest.u(5201), 1);
SELECT dbtest.append_entry(5, dbtest.u(5101), dbtest.u(5201), 2);
EOF
  race 8 "SET LOCAL ROLE factory_app; SELECT set_config('factory.tenant_id', dbtest.u(5)::text, true); SELECT 'appended-' || length(dbtest.append_entry(5, dbtest.u(5101), dbtest.u(5201), 3))" || rc=1
  expect_count "ledger race: eight concurrent appends of entry 3 give exactly one winner" "$(race_count_output 'appended-71')" 1 || rc=1
  expect_count "ledger race: the seven losers were refused by a unique constraint on the position" "$(race_errors_mention 'duplicate key value violates unique constraint')" 7 || rc=1
  expect_count "ledger race: the job holds entries 1 to 3" "$(psql_scalar "$CLONE" -c "SELECT count(*) FROM ledger_entries WHERE job_id = dbtest.u(5101)")" 3 || rc=1
  # The winner's transaction also moves the job's head pointer; do the same here, then verify.
  psql_db "$CLONE" -c "UPDATE jobs SET ledger_head_sequence = 3, version = version + 1, ledger_head_hash = (SELECT entry_hash FROM ledger_entries WHERE tenant_id = dbtest.u(5) AND job_id = dbtest.u(5101) AND sequence = 3) WHERE tenant_id = dbtest.u(5) AND id = dbtest.u(5101)" >/dev/null 2>&1 || rc=1
  expect_count "ledger race: the chain verifies (ledger_verify_chain is NULL)" "$(psql_scalar "$CLONE" -c "SELECT coalesce(ledger_verify_chain(dbtest.u(5), dbtest.u(5101))::text, 'ok')")" ok || rc=1
  return "$rc"
}

suite_tenancy() { simple_suite tenancy tenancy.sql; }

suite_rls() {
  # The session checks send the tenant as a bound parameter with \bind, which psql has from version 16.
  local psql_major
  psql_major="$(psql --version | sed -n 's/^psql (PostgreSQL) \([0-9][0-9]*\).*/\1/p')"
  [ -n "$psql_major" ] && [ "$psql_major" -ge 16 ] || blocked "the rls suite needs psql 16 or later (it uses \\bind); found: $(psql --version)"
  clone_begin rls || return 1
  local rc=0
  sql_in_clone rls rls.sql || rc=$?
  if [ "$rc" -eq 0 ]; then rls_sessions || rc=$?; fi
  if [ "$rc" -eq 0 ]; then rls_claim_race || rc=$?; fi
  clone_end
  return "$rc"
}

# The same server as another user. A password goes in PGPASSWORD so that a server that asks for one (the
# Docker image does) is satisfied; the private cluster trusts its socket and ignores it.
login_url() { # login, database
  local prefix
  case "$URL_PREFIX" in
    *@*) prefix="$(printf '%s' "$URL_PREFIX" | sed -E "s#^([A-Za-z0-9+.-]+://)[^@/]*@#\\1$1@#")" ;;
    *) prefix="$(printf '%s' "$URL_PREFIX" | sed -E "s#^([A-Za-z0-9+.-]+://)#\\1$1@#")" ;;
  esac
  printf '%s/%s%s' "$prefix" "$2" "$URL_QUERY"
}

# A session as a real login to the clone, with psql arguments after the login name. A script can go in on
# standard input.
psql_as() {
  local login=$1
  shift
  PGPASSWORD="$RLS_PASS" psql "$(login_url "$login" "$CLONE")" -X -q -v ON_ERROR_STOP=1 -P pager=off "$@"
}

# A login role that is a member of the groups named. Roles are cluster wide, so cleanup drops them.
make_login() { # name, groups (comma separated)
  psql_scalar postgres -c "CREATE ROLE \"$1\" LOGIN PASSWORD '$RLS_PASS' IN ROLE $2" >/dev/null || return 1
  RLS_LOGINS+=("$1")
}

# The output of a script run as a login, errors included, one string. The script is the second argument.
session_output() { # login, script
  psql_as "$1" -At 2>&1 <<<"$2" || true
}

# True when the script, run as the login, fails and the error text contains the pattern.
session_refused() { # login, script, pattern
  local out
  if out="$(psql_as "$1" -At 2>&1 <<<"$2")"; then
    return 1
  fi
  printf '%s' "$out" | grep -q -- "$3"
}

# What the sessions of real logins prove, which a SET ROLE inside one superuser session cannot: a reused
# connection, a poisoned one, the login's own limits, the extended protocol with a bound parameter.
rls_sessions() {
  local rc=0 app sys api t1 t2 out expected
  RLS_PASS="$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 24)"
  app="dbtest_app_${RUN_ID}"
  sys="dbtest_system_${RUN_ID}"
  api="dbtest_api_${RUN_ID}"
  make_login "$app" factory_app || return 1
  make_login "$sys" factory_system || return 1
  make_login "$api" "factory_api_app, factory_resolver" || return 1
  t1="$(psql_scalar "$CLONE" -c "SELECT dbtest.u(1)")"
  t2="$(psql_scalar "$CLONE" -c "SELECT dbtest.u(2)")"

  expect_count "logins: the three logins are members of the groups they were given and the membership check finds no conflict" \
    "$(psql_scalar "$CLONE" -c "SELECT count(*) || ':' || dbtest.membership_conflicts() FROM dbtest.group_members() WHERE member LIKE 'dbtest_%_${RUN_ID}'")" "4:" || rc=1

  # The start-up check a pool runs on its own role (docs/database/tests/role_readiness.sql, quoted in the storage notes).
  expect_count "readiness query as the tenant login: not a superuser, no bypass, owns nothing, in factory_app only" \
    "$(psql_as "$app" -At -f "$TESTS/role_readiness.sql")" "f|f|f|t|f|f|f|f" || rc=1
  expect_count "readiness query as the system login: in factory_system only" \
    "$(psql_as "$sys" -At -f "$TESTS/role_readiness.sql")" "f|f|f|f|t|f|f|f" || rc=1
  expect_count "readiness query as the API login: in factory_api_app and factory_resolver, not in factory_app" \
    "$(psql_as "$api" -At -f "$TESTS/role_readiness.sql")" "f|f|f|f|f|t|f|t" || rc=1
  expect_count "control: the readiness query as a superuser starts with true, so a pool that connects as one refuses to start" \
    "$(psql_db "$CLONE" -At -f "$TESTS/role_readiness.sql" | cut -c1-2)" "t|" || rc=1

  # --- A tenant login (the application role) --------------------------------------------------------
  out="$(session_output "$app" "SELECT count(*) FROM jobs;
SELECT current_setting('factory.tenant_id', true) IS NULL;")"
  expect_count "a session that never made the setting sees zero rows and gets no error, and the setting is NULL" "$out" "$(printf '0\nt')" || rc=1

  # The ADR 0012 probe: after a transaction that made the setting has ended, the NEXT transaction on the
  # same connection reads an empty string, not NULL. The policy has NULLIF, so it sees nothing and raises nothing.
  out="$(session_output "$app" "BEGIN;
SELECT set_config('factory.tenant_id', '$t1', true) AS x \\gset
SELECT 'first:' || count(*) FROM jobs;
COMMIT;
SELECT 'second:' || count(*) FROM jobs;
SELECT 'setting:' || CASE WHEN current_setting('factory.tenant_id', true) = '' THEN 'empty' WHEN current_setting('factory.tenant_id', true) IS NULL THEN 'null' ELSE 'other' END;")"
  expect_count "a second transaction on the reused connection sees zero rows with no error, and the setting reads as an empty string, not NULL" \
    "$out" "$(printf 'first:1\nsecond:0\nsetting:empty')" || rc=1

  out="$(session_output "$app" "BEGIN;
SELECT set_config('factory.tenant_id', '$t1', true) AS x \\gset
RESET factory.tenant_id;
SELECT 'after_reset:' || count(*) FROM jobs;
COMMIT;")"
  expect_count "RESET of the setting inside a transaction leaves the session with no tenant: zero rows, no error" "$out" "after_reset:0" || rc=1

  out="$(session_output "$app" "BEGIN;
SELECT set_config('factory.tenant_id', '$t1', true) AS x \\gset
SAVEPOINT inner_point;
SELECT set_config('factory.tenant_id', '$t2', true) AS x \\gset
SELECT 'in_savepoint:' || string_agg(DISTINCT tenant_id::text, ',') FROM jobs;
ROLLBACK TO inner_point;
SELECT 'after_rollback_to:' || string_agg(DISTINCT tenant_id::text, ',') FROM jobs;
COMMIT;")"
  expect_count "inside a savepoint the setting can be changed, and rolling the savepoint back restores the tenant of the outer transaction" \
    "$out" "$(printf 'in_savepoint:%s\nafter_rollback_to:%s' "$t2" "$t1")" || rc=1

  # A prepared statement is planned once and run for many tenants on a pooled connection (diesel-async keeps a
  # statement cache per connection). The policy reads the setting when the statement runs, not when it is
  # planned, so a generic plan made under one tenant must give the next tenant its own rows.
  out="$(session_output "$app" "SET plan_cache_mode = force_generic_plan;
PREPARE who AS SELECT coalesce(string_agg(DISTINCT tenant_id::text, ','), 'nobody') FROM jobs;
BEGIN;
SELECT set_config('factory.tenant_id', '$t1', true) AS x \\gset
EXECUTE who;
COMMIT;
BEGIN;
SELECT set_config('factory.tenant_id', '$t2', true) AS x \\gset
EXECUTE who;
COMMIT;
EXECUTE who;")"
  expect_count "a prepared statement with a generic plan, reused on one connection for tenant 1, tenant 2 and no tenant, gives each its own rows" \
    "$out" "$(printf '%s\n%s\nnobody' "$t1" "$t2")" || rc=1

  # COPY ... FROM is not supported on a table with row-level security. COPY ... TO obeys the policy.
  session_refused "$app" "COPY jobs FROM STDIN" 'COPY FROM not supported with row-level security' && ok "COPY FROM into a tenant table is refused: bulk loads must use INSERT" || { not_ok "COPY FROM into a tenant table was not refused"; rc=1; }
  out="$(session_output "$app" "BEGIN;
SELECT set_config('factory.tenant_id', '$t1', true) AS x \\gset
COPY jobs (tenant_id) TO STDOUT;
COMMIT;")"
  expect_count "COPY TO from a tenant table returns the rows of the session's tenant only" "$out" "$t1" || rc=1

  # The extended protocol with a typed, bound parameter, which is how Store::begin sends it. psql 16 and
  # later have \bind. diesel-async itself was not run (there is no Rust here).
  out="$(session_output "$app" "BEGIN;
SELECT set_config('factory.tenant_id', \$1, true) \\bind '$t1' \\g
SELECT 'rows:' || count(*) FROM jobs;
COMMIT;")"
  expect_count "set_config with the tenant as a bound parameter of the extended protocol works as the first statement of a transaction" \
    "$out" "$(printf '%s\nrows:1' "$t1")" || rc=1

  # A pool that returns a connection that someone SET at session level hands the next borrower another
  # tenant. The local setting of Store::begin hides it inside a transaction and gives it back at the end.
  out="$(session_output "$app" "SELECT set_config('factory.tenant_id', '$t2', false) AS x \\gset
BEGIN;
SELECT set_config('factory.tenant_id', '$t1', true) AS x \\gset
SELECT 'inside:' || string_agg(DISTINCT tenant_id::text, ',') FROM jobs;
COMMIT;
SELECT 'poisoned:' || string_agg(DISTINCT tenant_id::text, ',') FROM jobs;
RESET factory.tenant_id;
SELECT 'reset:' || count(*) FROM jobs;
SELECT set_config('factory.tenant_id', '$t2', false) AS x \\gset
DISCARD ALL;
SELECT 'discarded:' || count(*) FROM jobs;")"
  expect_count "KNOWN LIMIT: a session-level SET survives the transaction and shows its tenant to the next borrower; RESET of the setting, or DISCARD ALL, ends it" \
    "$out" "$(printf 'inside:%s\npoisoned:%s\nreset:0\ndiscarded:0' "$t1" "$t2")" || rc=1

  # What the login cannot do to the rules themselves.
  session_refused "$app" "SET ROLE factory_system" 'permission denied to set role "factory_system"' && ok "the tenant login cannot become the system role (SET ROLE)" || { not_ok "the tenant login could become the system role"; rc=1; }
  session_refused "$app" "SET ROLE factory_lookup" 'permission denied to set role "factory_lookup"' && ok "the tenant login cannot become the lookup owner" || { not_ok "the tenant login could become the lookup owner"; rc=1; }
  session_refused "$app" "SET SESSION AUTHORIZATION postgres" 'permission denied to set session authorization' && ok "the tenant login cannot switch session authorization" || { not_ok "the tenant login could switch session authorization"; rc=1; }
  session_refused "$app" "SET row_security = off; SELECT count(*) FROM jobs" 'query would be affected by row-level security policy' && ok "SET row_security = off does not bypass the policies: the query fails instead of returning every row" || { not_ok "row_security = off did not make the query fail"; rc=1; }
  session_refused "$app" "ALTER TABLE jobs DISABLE ROW LEVEL SECURITY" 'must be owner of table jobs' && ok "the tenant login cannot disable row-level security" || { not_ok "the tenant login could disable row-level security"; rc=1; }
  session_refused "$app" "ALTER TABLE jobs NO FORCE ROW LEVEL SECURITY" 'must be owner of table jobs' && ok "the tenant login cannot remove FORCE" || { not_ok "the tenant login could remove FORCE"; rc=1; }
  session_refused "$app" "DROP POLICY tenant_isolation ON jobs" 'must be owner of' && ok "the tenant login cannot drop a policy" || { not_ok "the tenant login could drop a policy"; rc=1; }
  session_refused "$app" "CREATE POLICY open ON jobs USING (true)" 'must be owner of table jobs' && ok "the tenant login cannot add a policy" || { not_ok "the tenant login could add a policy"; rc=1; }
  session_refused "$app" "SELECT * FROM resolve_token('\\x00'::bytea, 'factory-api')" 'permission denied for function resolve_token' && ok "the tenant login cannot run resolve_token" || { not_ok "the tenant login could run resolve_token"; rc=1; }

  # --- A system login ----------------------------------------------------------------------------------
  expected="$(psql_scalar "$CLONE" -c "SELECT count(*) FROM stage_runs")"
  out="$(session_output "$sys" "SELECT count(*) FROM (SELECT tenant_id, id FROM stage_runs) x;")"
  expect_count "the system login sees the stage runs of every tenant, with no tenant setting" "$out" "$expected" || rc=1
  expected="$(psql_scalar "$CLONE" -c "SELECT count(*) FROM stage_runs WHERE status = 'READY'")"
  out="$(session_output "$sys" "BEGIN;
SELECT count(*) FROM (SELECT s.tenant_id, s.id, s.version FROM stage_runs s JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE'
  WHERE s.status = 'READY' AND s.not_before <= now() ORDER BY s.not_before FOR NO KEY UPDATE OF s SKIP LOCKED) x;
COMMIT;")"
  expect_count "the claim query (FOR NO KEY UPDATE SKIP LOCKED) runs for the system login and finds the READY runs of every tenant" "$out" "$expected" || rc=1
  session_refused "$sys" "SELECT * FROM stage_runs" 'permission denied for table stage_runs' && ok "the system login cannot read whole stage run rows" || { not_ok "the system login read whole stage run rows"; rc=1; }
  session_refused "$sys" "SELECT 1 FROM ledger_entries" 'permission denied for table ledger_entries' && ok "the system login cannot read the evidence ledger" || { not_ok "the system login read the ledger"; rc=1; }
  session_refused "$sys" "UPDATE stage_runs SET updated_at = now()" 'version must rise by exactly one' && ok "the system login can lock stage runs but an update of one fails" || { not_ok "the system login updated a stage run"; rc=1; }
  session_refused "$sys" "UPDATE stage_runs SET status = 'RUNNING'" 'permission denied for table stage_runs' && ok "the system login cannot change a status" || { not_ok "the system login changed a status"; rc=1; }
  session_refused "$sys" "SET ROLE factory_app" 'permission denied to set role "factory_app"' && ok "the system login cannot become the tenant role" || { not_ok "the system login could become the tenant role"; rc=1; }
  session_refused "$sys" "SELECT * FROM resolve_token('\\x00'::bytea, 'factory-api')" 'permission denied for function resolve_token' && ok "the system login cannot run resolve_token" || { not_ok "the system login could run resolve_token"; rc=1; }
  # Even with a tenant setting chosen by the caller, a system login sees the same rows: the setting means nothing to it.
  out="$(session_output "$sys" "SELECT set_config('factory.tenant_id', '$t1', false) AS x \\gset
SELECT count(*) FROM (SELECT tenant_id, id FROM stage_runs) x;")"
  expect_count "a tenant setting made by the system login changes nothing it sees" "$out" "$(psql_scalar "$CLONE" -c "SELECT count(*) FROM stage_runs")" || rc=1

  # --- The login of the API: tenant role and resolver ---------------------------------------------------
  out="$(session_output "$api" "SELECT tenant_id, principal_id FROM resolve_token(sha256(convert_to('token-1', 'UTF8')), 'factory-api');")"
  expect_count "the API login resolves a token to its tenant and principal before any tenant is known" "$out" "$(psql_scalar "$CLONE" -c "SELECT dbtest.u(1) || '|' || dbtest.u(1002)")" || rc=1
  out="$(session_output "$api" "SELECT count(*) FROM resolve_installation(9002, 8002);")"
  expect_count "the API login resolves an installation and repository to a tenant" "$out" "1" || rc=1
  session_refused "$api" "SELECT count(*) FROM api_tokens;" 'permission denied for table api_tokens' \
    && ok "the API login cannot read the token table directly, with or without a tenant setting" \
    || { not_ok "the API login could read the token table"; rc=1; }
  # Finding API-3 as a real session: name another tenant by hand and mint a token for its principal.
  session_refused "$api" "BEGIN;
SELECT set_config('factory.tenant_id', '$t2', true);
INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, expires_at)
  VALUES ('$t2', dbtest.u(2999), dbtest.u(2002), sha256(convert_to('minted', 'UTF8')), 'factory-api', now() + interval '1 day');
COMMIT;" 'permission denied for table api_tokens' \
    && ok "the API login cannot mint a token for a tenant it names by hand (API-3b)" \
    || { not_ok "the API login minted a token"; rc=1; }
  out="$(session_output "$api" "BEGIN;
SELECT set_config('factory.tenant_id', '$t1', true) AS x \\gset
SELECT count(*) FROM jobs;
ROLLBACK;")"
  expect_count "the API login reads the jobs of the tenant it names, through its own group" "$out" "1" || rc=1
  session_refused "$api" "SET ROLE factory_system" 'permission denied to set role "factory_system"' && ok "the API login cannot become the system role" || { not_ok "the API login could become the system role"; rc=1; }

  # --- Control: a login that belongs to both groups is a finding, and the policies would combine -------
  local both="dbtest_both_${RUN_ID}"
  make_login "$both" "factory_app, factory_system" || return 1
  expect_count "control: a login in both factory_app and factory_system is reported by the membership check" \
    "$(psql_scalar "$CLONE" -c "SELECT dbtest.membership_conflicts() LIKE '%${both} is a member of both factory_app and factory_system%'")" "t" || rc=1
  out="$(session_output "$both" "SELECT count(*) FROM jobs;")"
  expect_count "control: such a login reads every tenant's jobs, whole rows, with no tenant setting: permissive policies are combined with OR, which is why the membership check exists" \
    "$out" "$(psql_scalar "$CLONE" -c "SELECT count(*) FROM jobs")" || rc=1
  psql_scalar postgres -c "DROP ROLE \"$both\"" >/dev/null 2>&1 || true
  return "$rc"
}

# The claim as the engine makes it (ADR 0012, ADR 0014): two transactions with two logins. Several workers find
# the same READY run through the system login at the same moment (find_claim_candidates); each then runs the
# start_attempt statement sequence through the tenant login, in its own transaction: share-lock the job, lock the
# stage run, decide, move READY to RUNNING with the epoch raised, insert the attempt. The lock on the run makes the
# later workers wait, and the version check and the unique index of one live attempt per stage run must leave
# exactly one winner. Every worker's find holds FOR NO KEY UPDATE SKIP LOCKED only until its transaction ends,
# which is before the swap, so more than one worker can hold the same candidate: that is the case being tried.
rls_claim_race() {
  local rounds="${FACTORY_DB_LEASE_ROUNDS:-25}" workers=4 r i rc=0 wins=0 bad=0 multi=0 candidates winners live line tid sid ver
  local app="dbtest_app_${RUN_ID}" pids
  [ "$rounds" -gt 12 ] && rounds=12
  psql_db "$CLONE" -c "SELECT dbtest.mk_tenant(8)" -c "SELECT dbtest.mk_job(8, 1)" -c "SELECT dbtest.set_status('jobs', 8, dbtest.u(8101), 'ACTIVE')" >/dev/null 2>"$WORK/claim-race.err" || { cat "$WORK/claim-race.err" >&2; return 1; }
  for r in $(seq 1 "$rounds"); do
    psql_db "$CLONE" -c "SELECT dbtest.mk_stage_run(8, 1, $r, 'INTAKE', $r)" -c "SELECT dbtest.set_status('stage_runs', 8, dbtest.u($((8200 + r))), 'READY')" >/dev/null 2>"$WORK/claim-race.err" || { cat "$WORK/claim-race.err" >&2; return 1; }
    # Step 1, released together: the system role finds the candidate (tenant 8 only, so the READY runs of the
    # other tenants in this database do not get in the way).
    race "$workers" "SET LOCAL ROLE factory_system; SELECT s.tenant_id || ' ' || s.id || ' ' || s.version FROM stage_runs s JOIN jobs j ON j.tenant_id = s.tenant_id AND j.id = s.job_id AND j.status = 'ACTIVE' WHERE s.tenant_id = dbtest.u(8) AND s.status = 'READY' AND s.not_before <= now() ORDER BY s.not_before, s.id LIMIT 10 FOR NO KEY UPDATE OF s SKIP LOCKED" || bad=$((bad + 1))
    candidates=0
    pids=()
    rm -f "$WORK"/cas.*
    for i in $(seq 1 "$workers"); do
      line="$(grep -E '^[0-9a-f-]{36} [0-9a-f-]{36} [0-9]+$' "$WORK/race.$i.out" 2>/dev/null | head -n1 || true)"
      [ -n "$line" ] || continue
      candidates=$((candidates + 1))
      read -r tid sid ver <<<"$line"
      # Step 2, in its own transaction as the tenant login: swap on version, raise the epoch, write the attempt.
      (
        psql_as "$app" -At >"$WORK/cas.$i.out" 2>&1 <<EOF || true
BEGIN;
SELECT set_config('factory.tenant_id', '$tid', true) AS x \\gset
SELECT job_id AS job FROM stage_runs WHERE tenant_id = '$tid' AND id = '$sid' \\gset
SELECT status = 'ACTIVE' AS job_active FROM jobs WHERE tenant_id = '$tid' AND id = :'job' FOR SHARE \\gset
SELECT (s.status = 'READY' AND s.version = $ver AND s.not_before <= now()) AS startable,
       (SELECT coalesce(max(a.attempt_number), 0) + 1 FROM attempts a WHERE a.tenant_id = s.tenant_id AND a.stage_run_id = s.id) AS next_number
  FROM stage_runs s WHERE s.tenant_id = '$tid' AND s.id = '$sid' FOR NO KEY UPDATE \\gset
\\if :job_active
\\if :startable
UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1
 WHERE tenant_id = '$tid' AND id = '$sid' AND version = $ver AND status = 'READY' RETURNING lease_epoch AS granted \\gset
INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at)
VALUES ('$tid', gen_random_uuid(), :'job', '$sid', :next_number, 'worker-$i', :granted, now() + interval '30 seconds', now() + interval '1 hour')
RETURNING 'won';
\\endif
\\endif
COMMIT;
EOF
      ) &
      pids+=("$!")
    done
    for i in ${pids[@]+"${pids[@]}"}; do wait "$i" || true; done
    winners="$( (grep -lx 'won' "$WORK"/cas.*.out 2>/dev/null || true) | wc -l | tr -d ' ')"
    live="$(psql_scalar "$CLONE" -c "SELECT count(*) || ':' || coalesce(max(a.lease_epoch), 0) FROM attempts a WHERE a.stage_run_id = dbtest.u($((8200 + r))) AND a.status IN ('STARTING','RUNNING')")"
    [ "$winners" = 1 ] && wins=$((wins + 1)) || bad=$((bad + 1))
    [ "$live" = "1:1" ] || { not_ok "claim race round $r: expected one live attempt at epoch 1, found $live"; bad=$((bad + 1)); }
    [ "$candidates" -gt 1 ] && multi=$((multi + 1))
  done
  expect_count "claim race through two logins: $rounds rounds of $workers workers each ended with exactly one winner and one live attempt" "$wins:$bad" "$rounds:0" || rc=1
  say "info - in $multi of $rounds rounds more than one worker had found the same candidate before the swap"
  return "$rc"
}

suite_terminal_rows() {
  ensure_template || return 1
  local expected="$WORK/expected_from_json.sql" rc=0
  python3 -I "$TOOLS/state_machine_sql.py" expected "$STATE_MACHINE" >"$expected" || return 1
  clone_begin terminal_rows || return 1
  sql_in_clone terminal_rows "$expected" terminal_rows.sql || rc=$?
  clone_end
  return "$rc"
}

suite_audit() {
  clone_begin audit || return 1
  local rc=0
  sql_in_clone audit audit.sql || rc=$?
  if [ "$rc" -eq 0 ]; then audit_concurrent_and_external || rc=$?; fi
  clone_end
  return "$rc"
}

# Eight writers append five events each to one tenant's chain at once; then Python rebuilds the chain.
audit_concurrent_and_external() {
  local rc=0 events
  psql_db "$CLONE" -c "SELECT dbtest.mk_tenant(3)" >/dev/null 2>&1 || return 1
  race 8 "SET LOCAL ROLE factory_app; SELECT set_config('factory.tenant_id', dbtest.u(3)::text, true); SELECT dbtest.audit(3, __N__ * 100 + 1); SELECT dbtest.audit(3, __N__ * 100 + 2); SELECT dbtest.audit(3, __N__ * 100 + 3); SELECT dbtest.audit(3, __N__ * 100 + 4); SELECT dbtest.audit(3, __N__ * 100 + 5)" || rc=1
  expect_count "audit race: no writer failed" "$(race_count_failed)" 0 || rc=1
  expect_count "audit race: 40 events from 8 concurrent writers" "$(psql_scalar "$CLONE" -c "SELECT count(*) FROM audit_events WHERE tenant_id = dbtest.u(3)")" 40 || rc=1
  expect_count "audit race: the sequence is 1 to 40 with no gap and no duplicate" \
    "$(psql_scalar "$CLONE" -c "SELECT (count(DISTINCT sequence) = 40 AND min(sequence) = 1 AND max(sequence) = 40)::text FROM audit_events WHERE tenant_id = dbtest.u(3)")" true || rc=1
  expect_count "audit race: audit_verify_chain finds nothing wrong" "$(psql_scalar "$CLONE" -c "SELECT coalesce(audit_verify_chain(dbtest.u(3))::text, 'ok')")" ok || rc=1

  # An event full of awkward text, so the outside check covers escaping.
  psql_db "$CLONE" -c "
    INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id)
    VALUES (dbtest.u(3), dbtest.u(98), 'human', 'user \"quoted\" back\\slash', 'tool.denied',
            'line one' || chr(10) || 'tab' || chr(9) || 'bell' || chr(7) || 'unit' || chr(1) || 'del' || chr(127),
            'deny', 'caf' || chr(233) || ' ' || chr(9731) || ' ' || chr(128512) || ' line' || chr(8232) || 'separator',
            dbtest.sha('policy'), dbtest.u(98))" >/dev/null 2>"$WORK/audit-awkward.err" || { cat "$WORK/audit-awkward.err" >&2; return 1; }
  events="$(psql_scalar "$CLONE" -c "SELECT json_agg(row_to_json(a) ORDER BY sequence) FROM audit_events a WHERE tenant_id = dbtest.u(3)")"
  if printf '%s' "$events" | python3 -I "$TOOLS/verify_audit_chain.py" >"$WORK/audit-python.out" 2>"$WORK/audit-python.err"; then
    ok "audit chain of 41 events (quotes, control characters, non-ASCII text) verified by verify_audit_chain.py outside PostgreSQL"
  else
    not_ok "the external verifier rejected the chain"
    cat "$WORK/audit-python.err" >&2
    rc=1
  fi
  return "$rc"
}

suite_webhook_delivery() {
  clone_begin webhook_delivery || return 1
  local rc=0
  sql_in_clone webhook_delivery webhook_delivery.sql || rc=$?
  if [ "$rc" -eq 0 ]; then webhook_race || rc=$?; fi
  clone_end
  return "$rc"
}

# NT-WH-04: the same delivery sent 50 times at once, and a captured body replayed under 50 fresh ids.
webhook_race() {
  local rc=0
  local as_tenant_1="SET LOCAL ROLE factory_app; SELECT set_config('factory.tenant_id', dbtest.u(1)::text, true); "
  race 50 "${as_tenant_1}SELECT dbtest.receive_delivery(1, 'concurrent-delivery-1', 'concurrent body one')" || rc=1
  expect_count "webhook race: 50 concurrent copies of one delivery id give exactly one new delivery" "$(race_count_output t)" 1 || rc=1
  expect_count "webhook race: the other 49 are acknowledged as repeats" "$(race_count_output f)" 49 || rc=1
  expect_count "webhook race: no copy failed with an error (the unique violation is absorbed)" "$(race_count_failed)" 0 || rc=1
  expect_count "webhook race: exactly one delivery, one job and one outbox row were added" \
    "$(psql_scalar "$CLONE" -c "SELECT dbtest.totals()")" "deliveries=4 jobs=4 outbox=4" || rc=1

  race 50 "${as_tenant_1}SELECT dbtest.receive_delivery(1, 'replay-under-fresh-id-__N__', 'concurrent body two')" || rc=1
  expect_count "webhook race: a body replayed under 50 fresh delivery ids is accepted once" "$(race_count_output t)" 1 || rc=1
  expect_count "webhook race: after the replay there is one more delivery, job and outbox row" \
    "$(psql_scalar "$CLONE" -c "SELECT dbtest.totals()")" "deliveries=5 jobs=5 outbox=5" || rc=1
  return "$rc"
}

suite_lease() {
  clone_begin lease || return 1
  local rc=0
  sql_in_clone lease lease.sql || rc=$?
  if [ "$rc" -eq 0 ]; then lease_races || rc=$?; fi
  if [ "$rc" -eq 0 ]; then lease_lock_modes || rc=$?; fi
  clone_end
  return "$rc"
}

# Why the claim locks with FOR NO KEY UPDATE. Appending a ledger entry takes a KEY SHARE lock on the
# stage run it names (the foreign key). FOR UPDATE conflicts with that lock, FOR NO KEY UPDATE does not.
# Two claimers hold a lock on a run each for two seconds; a writer then appends a ledger entry for each
# run with a 500 ms lock timeout.
lease_lock_modes() {
  local rc=0 i
  psql_db "$CLONE" >/dev/null 2>"$WORK/lock-modes.err" <<'EOF' || { cat "$WORK/lock-modes.err" >&2; return 1; }
SELECT dbtest.mk_tenant(7);
SELECT dbtest.mk_job(7, 1);
SELECT dbtest.mk_job(7, 2);
SELECT dbtest.mk_stage_run(7, 1, 1);
SELECT dbtest.mk_stage_run(7, 2, 2);
SELECT dbtest.mk_job(7, 3);
SELECT dbtest.mk_stage_run(7, 3, 3);
EOF
  # The claimers are the system role; the writer is the tenant role for tenant 7 (ADR 0012).
  psql_db "$CLONE" -At -c "BEGIN; SET LOCAL ROLE factory_system; SELECT 1 FROM stage_runs WHERE id = dbtest.u(7201) FOR NO KEY UPDATE; SELECT pg_sleep(2); COMMIT" >/dev/null 2>&1 &
  local holder_a=$!
  psql_db "$CLONE" -At -c "BEGIN; SET LOCAL ROLE factory_system; SELECT 1 FROM stage_runs WHERE id = dbtest.u(7202) FOR UPDATE; SELECT pg_sleep(2); COMMIT" >/dev/null 2>&1 &
  local holder_b=$!
  # start_attempt share-locks the job (FOR SHARE) and holds the lock to the end of its transaction.
  psql_db "$CLONE" -At -c "BEGIN; SET LOCAL ROLE factory_app; SELECT set_config('factory.tenant_id', dbtest.u(7)::text, true); SELECT 1 FROM jobs WHERE tenant_id = dbtest.u(7) AND id = dbtest.u(7103) FOR SHARE; SELECT pg_sleep(2); COMMIT" >/dev/null 2>&1 &
  local holder_c=$!
  for i in $(seq 1 100); do
    [ "$(psql_scalar "$CLONE" -c "SELECT count(*) FROM pg_stat_activity WHERE wait_event = 'PgSleep' AND datname = current_database()")" = 3 ] && break
    sleep 0.05
  done
  local as_tenant_7="SET ROLE factory_app; SELECT set_config('factory.tenant_id', dbtest.u(7)::text, false)"
  if psql_db "$CLONE" -At -c "SET lock_timeout = '500ms'" -c "$as_tenant_7" -c "SELECT dbtest.append_entry(7, dbtest.u(7101), dbtest.u(7201), 1)" >/dev/null 2>"$WORK/lock-a.err"; then
    ok "lock modes: a ledger append by the tenant role is not blocked while the system role holds the stage run FOR NO KEY UPDATE"
  else
    not_ok "lock modes: a ledger append was blocked by FOR NO KEY UPDATE: $(cat "$WORK/lock-a.err")"
    rc=1
  fi
  if psql_db "$CLONE" -At -c "SET lock_timeout = '500ms'" -c "$as_tenant_7" -c "SELECT dbtest.append_entry(7, dbtest.u(7102), dbtest.u(7202), 1)" >/dev/null 2>"$WORK/lock-b.err"; then
    not_ok "lock modes: FOR UPDATE was expected to block the ledger append, so the reason for FOR NO KEY UPDATE is gone"
    rc=1
  elif grep -q 'lock timeout' "$WORK/lock-b.err"; then
    ok "lock modes: the same append IS blocked while the stage run is held FOR UPDATE by the system role (lock timeout), which is why claims use FOR NO KEY UPDATE"
  else
    not_ok "lock modes: the append failed for another reason: $(cat "$WORK/lock-b.err")"
    rc=1
  fi
  # The job share lock of start_attempt: an insert that only needs KEY SHARE on the job (a ledger entry) goes
  # through, and a change of the job's status (a pause, a cancel) waits for the decision that holds the lock.
  if psql_db "$CLONE" -At -c "SET lock_timeout = '500ms'" -c "$as_tenant_7" -c "SELECT dbtest.append_entry(7, dbtest.u(7103), dbtest.u(7203), 1)" >/dev/null 2>"$WORK/lock-c.err"; then
    ok "lock modes: a ledger append is not blocked while start_attempt share-locks the job (FOR SHARE)"
  else
    not_ok "lock modes: a ledger append was blocked by the job share lock: $(cat "$WORK/lock-c.err")"
    rc=1
  fi
  if psql_db "$CLONE" -At -c "SET lock_timeout = '500ms'" -c "UPDATE jobs SET policy_hash = NULL, version = version + 1 WHERE tenant_id = dbtest.u(7) AND id = dbtest.u(7103)" >/dev/null 2>"$WORK/lock-d.err"; then
    not_ok "lock modes: a change of the job did not wait for the share lock, so a pause could slip between the check and the start"
    rc=1
  elif grep -q 'lock timeout' "$WORK/lock-d.err"; then
    ok "lock modes: a change of the job waits while start_attempt holds it FOR SHARE (lock timeout), so a pause and a start are serialized"
  else
    not_ok "lock modes: the job change failed for another reason: $(cat "$WORK/lock-d.err")"
    rc=1
  fi
  wait "$holder_a" || true
  wait "$holder_b" || true
  wait "$holder_c" || true
  return "$rc"
}

# Contested claims (NT-LSE-02 at the database level), three ways, several rounds each.
lease_races() {
  local rounds="${FACTORY_DB_LEASE_ROUNDS:-25}" workers=4 r rc=0 bad=0 live
  local claim_wins=0 cas_wins=0 insert_wins=0
  for r in $(seq 1 "$rounds"); do
    # 1. The claim query itself: only the winner gets an attempt back.
    psql_db "$CLONE" -c "SELECT dbtest.mk_ready_run($((100 + r)))" >/dev/null 2>&1 || return 1
    race "$workers" "SELECT 'claimed' WHERE dbtest.claim('worker-__N__') IS NOT NULL" || bad=$((bad + 1))
    if [ "$(race_count_output claimed)" = 1 ]; then claim_wins=$((claim_wins + 1)); else bad=$((bad + 1)); fi
    live="$(psql_scalar "$CLONE" -c "SELECT count(*) || ':' || max(a.lease_epoch) FROM attempts a WHERE a.stage_run_id = dbtest.u($((1800 + r))) AND a.status IN ('STARTING','RUNNING')")"
    [ "$live" = "1:1" ] || { not_ok "round $r: expected one live attempt at epoch 1, found $live"; bad=$((bad + 1)); }

    # 2. A bare compare-and-swap on the stage run, with no SKIP LOCKED: one UPDATE matches.
    psql_db "$CLONE" -c "SELECT dbtest.mk_ready_run($((200 + r)))" >/dev/null 2>&1 || return 1
    race "$workers" "SET LOCAL ROLE factory_app; SELECT set_config('factory.tenant_id', dbtest.u(1)::text, true); UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1 WHERE tenant_id = dbtest.u(1) AND id = dbtest.u($((1900 + r))) AND version = 2 AND status = 'READY' RETURNING 'swapped'" || bad=$((bad + 1))
    if [ "$(race_count_output swapped)" = 1 ]; then cas_wins=$((cas_wins + 1)); else bad=$((bad + 1)); fi

    # 3. No claim code at all: several sessions insert a live attempt for the same running run.
    psql_db "$CLONE" -c "SELECT dbtest.mk_ready_run($((300 + r)))" -c "SELECT dbtest.set_status('stage_runs', 1, dbtest.u($((2000 + r))), 'RUNNING', ', lease_epoch = lease_epoch + 1')" >/dev/null 2>&1 || return 1
    race "$workers" "SET LOCAL ROLE factory_app; SELECT set_config('factory.tenant_id', dbtest.u(1)::text, true); INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at) VALUES (dbtest.u(1), gen_random_uuid(), dbtest.u(1101), dbtest.u($((2000 + r))), 1, 'worker-__N__', 1, now() + interval '30 seconds', now() + interval '1 hour') RETURNING 'inserted'" || bad=$((bad + 1))
    if [ "$(race_count_output inserted)" = 1 ]; then insert_wins=$((insert_wins + 1)); else bad=$((bad + 1)); fi
  done
  expect_count "lease race: $rounds contested claims by $workers workers each had exactly one winner" "$claim_wins" "$rounds" || rc=1
  expect_count "lease race: $rounds bare compare-and-swap races on the stage run each had exactly one winner" "$cas_wins" "$rounds" || rc=1
  expect_count "lease race: $rounds races to insert a live attempt each had exactly one winner (unique index)" "$insert_wins" "$rounds" || rc=1
  expect_count "lease race: across all $((rounds * 3)) rounds no round gave zero winners or two" "$bad" 0 || rc=1
  expect_count "lease race: no stage run ended with two live attempts" \
    "$(psql_scalar "$CLONE" -c "SELECT count(*) FROM (SELECT stage_run_id FROM attempts WHERE status IN ('STARTING','RUNNING','CANCELLING') GROUP BY 1 HAVING count(*) > 1) x")" 0 || rc=1
  return "$rc"
}

suite_plans() {
  local scale="${FACTORY_DB_PLANS_SCALE:-1}" rc=0
  case "$scale" in
    '' | *[!0-9]*) err "FACTORY_DB_PLANS_SCALE must be a whole number, not '$scale'"; return 1 ;;
  esac
  clone_begin plans || return 1
  # 1 gives 10,000 rows in each large table, 10 gives 100,000. The setting is read by dbtest.scale().
  psql_db postgres -c "ALTER DATABASE \"$CLONE\" SET dbtest.plans_scale = '$scale'" >/dev/null || { clone_end; return 1; }
  sql_in_clone plans plans.sql || rc=$?
  clone_end
  return "$rc"
}

suite_outbox() { simple_suite outbox outbox.sql; }

suite_tokens() { simple_suite tokens tokens.sql; }

suite_privileges() { simple_suite privileges privileges.sql; }

suite_api_privileges() { simple_suite api_privileges api_privileges.sql; }

suite_repository_map() { simple_suite repository_map repository_map.sql; }

suite_approvals() { simple_suite approvals approvals.sql; }

suite_store_model() { simple_suite store_model store_model.sql; }

suite_contracts() {
  ensure_template || return 1
  local expected="$WORK/expected_from_json.sql" rc=0
  python3 -I "$TOOLS/state_machine_sql.py" expected "$STATE_MACHINE" >"$expected" || return 1
  clone_begin contracts || return 1
  sql_in_clone contracts "$expected" contracts.sql || rc=$?
  clone_end
  return "$rc"
}

write_schema() {
  require_diesel
  ensure_template || return 1
  local db="factory_t_${RUN_ID}_schema"
  create_db_from_template "$db"
  if ! diesel_run "$db" --config-file "$DIESEL_CONFIG" print-schema >"$WORK/schema.rs" 2>"$WORK/schema.err"; then
    cat "$WORK/schema.err" >&2
    drop_db "$db"
    return 1
  fi
  drop_db "$db"
  cp "$WORK/schema.rs" "$SCHEMA_RS"
  say "wrote $SCHEMA_RS ($(wc -l <"$SCHEMA_RS" | tr -d ' ') lines) from diesel print-schema on a freshly migrated database"
}

# ---------------------------------------------------------------------------------------------

main() {
  local selected=() arg do_write=0 rows=""
  while [ "$#" -gt 0 ]; do
    arg="$1"
    shift
    case "$arg" in
      -h | --help) usage; exit 0 ;;
      --list) list_suites; exit 0 ;;
      --keep) KEEP=1 ;;
      --rows)
        [ "$#" -gt 0 ] || { err "--rows needs a number"; exit "$EXIT_USAGE"; }
        rows="$1"
        shift
        case "$rows" in
          '' | *[!0-9]* | 0*) err "--rows must be a positive whole number, not '$rows'"; exit "$EXIT_USAGE" ;;
        esac
        if [ $((rows % 10000)) -ne 0 ]; then err "--rows must be a multiple of 10,000 (the plans suite grows in steps of 10,000), not $rows"; exit "$EXIT_USAGE"; fi
        export FACTORY_DB_PLANS_SCALE=$((rows / 10000))
        ;;
      write-schema) do_write=1 ;;
      all) read -r -a selected <<< "$SUITES" ;;
      *)
        case " $SUITES " in
          *" $arg "*) selected+=("$arg") ;;
          *) err "unknown suite or option: $arg"; usage >&2; exit "$EXIT_USAGE" ;;
        esac
        ;;
    esac
  done
  if [ "$do_write" = 0 ] && [ "${#selected[@]}" -eq 0 ]; then read -r -a selected <<< "$SUITES"; fi

  WORK="$(mktemp -d "${TMPDIR:-/tmp}/factory-db-work.XXXXXX")"
  provision

  if [ "$do_write" = 1 ]; then
    write_schema
    exit $?
  fi

  local failed=() s rc
  for s in "${selected[@]}"; do
    if ! declare -F "suite_$s" >/dev/null; then
      err "suite $s is listed but not implemented"
      failed+=("$s")
      continue
    fi
    say "== suite: $s"
    rc=0
    "suite_$s" || rc=$?
    if [ "$rc" -ne 0 ]; then
      failed+=("$s")
      err "== suite $s: FAIL"
    else
      say "== suite $s: pass"
    fi
  done
  if [ "${#failed[@]}" -gt 0 ]; then
    err "FAIL: ${failed[*]}"
    exit "$EXIT_FAIL"
  fi
  say "PASS: ${selected[*]} ($TOTAL_OK checks, PostgreSQL $SERVER_VERSION, $PROVISIONED)"
}

main "$@"
