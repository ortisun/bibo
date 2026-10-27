#!/usr/bin/env bash
# Build a throwaway PostgreSQL database, run the Diesel migrations on it, and prove the schema rules.
#
#   scripts/db-test.sh                 run every suite
#   scripts/db-test.sh SUITE [SUITE..] run the named suites (see --list)
#   scripts/db-test.sh --list          print the suite names and what each one proves
#   scripts/db-test.sh write-schema    regenerate crates/storage/src/schema.rs with diesel print-schema
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

SUITES="migrations statuses ledger tenancy terminal_rows plans audit webhook_delivery lease outbox approvals tokens privileges contracts"

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
  sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
}

list_suites() {
  cat <<'EOF'
migrations       up, revert all, up again, redo on an empty database; the catalog is identical afterwards;
                 the committed schema.rs equals diesel print-schema
statuses         every status column rejects an unknown value; allowed values, terminal flags, transitions
                 and event names equal state-machine.json
ledger           the evidence ledger refuses UPDATE, DELETE, TRUNCATE and gapped, forked or forged inserts;
                 concurrent appends to one job leave one winner and a sound chain
tenancy          a foreign key into another tenant is rejected; unique keys carry the tenant; the
                 row-level security candidate is tried and rolled back
terminal_rows    terminal stage runs cannot be edited except PASSED to SUPERSEDED; illegal transitions fail
plans            claim, sweep, timeline and ledger-tail queries use index scans on 10,000 generated rows
audit            the application role can only INSERT and SELECT audit events; the chain is built by the
                 server, survives concurrent writers and verifies outside PostgreSQL
webhook_delivery a duplicate delivery id cannot create a second job or outbox row, also under 50 concurrent replays
lease            concurrent claims give exactly one winner; stale epochs and forged renewals are refused
outbox           the outbox is atomic with the state change, immutable, and consumer idempotent
approvals        approvals bind a head SHA and only a human principal can approve
tokens           API tokens are stored hashed, expire, are audience bound and cannot be un-revoked
privileges       the application role has exactly the grants the design lists
contracts        the rows can carry the fields the domain-event and evidence-ledger-entry schemas require
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
  race 8 "SELECT 'appended-' || length(dbtest.append_entry(5, dbtest.u(5101), dbtest.u(5201), 3))" || rc=1
  expect_count "ledger race: eight concurrent appends of entry 3 give exactly one winner" "$(race_count_output 'appended-71')" 1 || rc=1
  expect_count "ledger race: the seven losers were refused by a unique constraint on the position" "$(race_errors_mention 'duplicate key value violates unique constraint')" 7 || rc=1
  expect_count "ledger race: the job holds entries 1 to 3" "$(psql_scalar "$CLONE" -c "SELECT count(*) FROM ledger_entries WHERE job_id = dbtest.u(5101)")" 3 || rc=1
  # The winner's transaction also moves the job's head pointer; do the same here, then verify.
  psql_db "$CLONE" -c "UPDATE jobs SET ledger_head_sequence = 3, version = version + 1, ledger_head_hash = (SELECT entry_hash FROM ledger_entries WHERE tenant_id = dbtest.u(5) AND job_id = dbtest.u(5101) AND sequence = 3) WHERE tenant_id = dbtest.u(5) AND id = dbtest.u(5101)" >/dev/null 2>&1 || rc=1
  expect_count "ledger race: the chain verifies (ledger_verify_chain is NULL)" "$(psql_scalar "$CLONE" -c "SELECT coalesce(ledger_verify_chain(dbtest.u(5), dbtest.u(5101))::text, 'ok')")" ok || rc=1
  return "$rc"
}

suite_tenancy() { simple_suite tenancy tenancy.sql; }

suite_terminal_rows() { simple_suite terminal_rows terminal_rows.sql; }

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
  race 8 "SELECT dbtest.audit(3, __N__ * 100 + 1); SELECT dbtest.audit(3, __N__ * 100 + 2); SELECT dbtest.audit(3, __N__ * 100 + 3); SELECT dbtest.audit(3, __N__ * 100 + 4); SELECT dbtest.audit(3, __N__ * 100 + 5)" || rc=1
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
  race 50 "SELECT dbtest.receive_delivery(1, 'concurrent-delivery-1', 'concurrent body one')" || rc=1
  expect_count "webhook race: 50 concurrent copies of one delivery id give exactly one new delivery" "$(race_count_output t)" 1 || rc=1
  expect_count "webhook race: the other 49 are acknowledged as repeats" "$(race_count_output f)" 49 || rc=1
  expect_count "webhook race: no copy failed with an error (the unique violation is absorbed)" "$(race_count_failed)" 0 || rc=1
  expect_count "webhook race: exactly one delivery, one job and one outbox row were added" \
    "$(psql_scalar "$CLONE" -c "SELECT dbtest.totals()")" "deliveries=4 jobs=4 outbox=4" || rc=1

  race 50 "SELECT dbtest.receive_delivery(1, 'replay-under-fresh-id-__N__', 'concurrent body two')" || rc=1
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
EOF
  psql_db "$CLONE" -At -c "BEGIN; SELECT 1 FROM stage_runs WHERE id = dbtest.u(7201) FOR NO KEY UPDATE; SELECT pg_sleep(2); COMMIT" >/dev/null 2>&1 &
  local holder_a=$!
  psql_db "$CLONE" -At -c "BEGIN; SELECT 1 FROM stage_runs WHERE id = dbtest.u(7202) FOR UPDATE; SELECT pg_sleep(2); COMMIT" >/dev/null 2>&1 &
  local holder_b=$!
  for i in $(seq 1 100); do
    [ "$(psql_scalar "$CLONE" -c "SELECT count(*) FROM pg_stat_activity WHERE wait_event = 'PgSleep' AND datname = current_database()")" = 2 ] && break
    sleep 0.05
  done
  if psql_db "$CLONE" -At -c "SET lock_timeout = '500ms'" -c "SELECT dbtest.append_entry(7, dbtest.u(7101), dbtest.u(7201), 1)" >/dev/null 2>"$WORK/lock-a.err"; then
    ok "lock modes: a ledger append is not blocked while a claimer holds the stage run FOR NO KEY UPDATE"
  else
    not_ok "lock modes: a ledger append was blocked by FOR NO KEY UPDATE: $(cat "$WORK/lock-a.err")"
    rc=1
  fi
  if psql_db "$CLONE" -At -c "SET lock_timeout = '500ms'" -c "SELECT dbtest.append_entry(7, dbtest.u(7102), dbtest.u(7202), 1)" >/dev/null 2>"$WORK/lock-b.err"; then
    not_ok "lock modes: FOR UPDATE was expected to block the ledger append, so the reason for FOR NO KEY UPDATE is gone"
    rc=1
  elif grep -q 'lock timeout' "$WORK/lock-b.err"; then
    ok "lock modes: the same append IS blocked while the stage run is held FOR UPDATE (lock timeout), which is why claims use FOR NO KEY UPDATE"
  else
    not_ok "lock modes: the append failed for another reason: $(cat "$WORK/lock-b.err")"
    rc=1
  fi
  wait "$holder_a" || true
  wait "$holder_b" || true
  return "$rc"
}

# Contested claims (NT-LSE-02 at the database level), three ways, several rounds each.
lease_races() {
  local rounds="${FACTORY_DB_LEASE_ROUNDS:-25}" workers=4 r rc=0 bad=0 live
  local claim_wins=0 cas_wins=0 insert_wins=0
  for r in $(seq 1 "$rounds"); do
    # 1. The claim query itself: only the winner gets an attempt back.
    psql_db "$CLONE" -c "SELECT dbtest.mk_ready_run($((100 + r)))" >/dev/null 2>&1 || return 1
    race "$workers" "SELECT 'claimed' WHERE dbtest.claim_as_app('worker-__N__') IS NOT NULL" || bad=$((bad + 1))
    if [ "$(race_count_output claimed)" = 1 ]; then claim_wins=$((claim_wins + 1)); else bad=$((bad + 1)); fi
    live="$(psql_scalar "$CLONE" -c "SELECT count(*) || ':' || max(a.lease_epoch) FROM attempts a WHERE a.stage_run_id = dbtest.u($((1800 + r))) AND a.status IN ('STARTING','RUNNING')")"
    [ "$live" = "1:1" ] || { not_ok "round $r: expected one live attempt at epoch 1, found $live"; bad=$((bad + 1)); }

    # 2. A bare compare-and-swap on the stage run, with no SKIP LOCKED: one UPDATE matches.
    psql_db "$CLONE" -c "SELECT dbtest.mk_ready_run($((200 + r)))" >/dev/null 2>&1 || return 1
    race "$workers" "UPDATE stage_runs SET status = 'RUNNING', lease_epoch = lease_epoch + 1, version = version + 1 WHERE tenant_id = dbtest.u(1) AND id = dbtest.u($((1900 + r))) AND version = 2 AND status = 'READY' RETURNING 'swapped'" || bad=$((bad + 1))
    if [ "$(race_count_output swapped)" = 1 ]; then cas_wins=$((cas_wins + 1)); else bad=$((bad + 1)); fi

    # 3. No claim code at all: several sessions insert a live attempt for the same running run.
    psql_db "$CLONE" -c "SELECT dbtest.mk_ready_run($((300 + r)))" -c "SELECT dbtest.set_status('stage_runs', 1, dbtest.u($((2000 + r))), 'RUNNING', ', lease_epoch = lease_epoch + 1')" >/dev/null 2>&1 || return 1
    race "$workers" "INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, lease_epoch, lease_expires_at, deadline_at) VALUES (dbtest.u(1), gen_random_uuid(), dbtest.u(1101), dbtest.u($((2000 + r))), 1, 'worker-__N__', 1, now() + interval '30 seconds', now() + interval '1 hour') RETURNING 'inserted'" || bad=$((bad + 1))
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

suite_plans() { simple_suite plans plans.sql; }

suite_outbox() { simple_suite outbox outbox.sql; }

suite_tokens() { simple_suite tokens tokens.sql; }

suite_privileges() { simple_suite privileges privileges.sql; }

suite_approvals() { simple_suite approvals approvals.sql; }

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
  local selected=() arg do_write=0
  for arg in "$@"; do
    case "$arg" in
      -h | --help) usage; exit 0 ;;
      --list) list_suites; exit 0 ;;
      --keep) KEEP=1 ;;
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
