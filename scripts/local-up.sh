#!/usr/bin/env bash
# scripts/local-up.sh - start, stop or remove the full local stack (infra/compose/local.yml).
#
#   scripts/local-up.sh                  Create the secret files on first use, start PostgreSQL 18 and the artifact
#                                        volume (profile "local"), apply the migrations, create the three logins.
#   scripts/local-up.sh --factory        Also start the factory services (profile "factory"). Needs their images:
#                                        see docs/operations/local-deployment.md. Today they do not exist.
#   scripts/local-up.sh --bare           Start PostgreSQL and the artifact volume only: no migrations, no logins. This is
#                                        the empty target that scripts/restore.sh needs.
#   scripts/local-up.sh --status         Show what is running.
#   scripts/local-up.sh --down           Stop and remove the containers. The data volumes stay.
#   scripts/local-up.sh --destroy --yes  Also delete the data volumes (the database and the artifacts).
#   scripts/local-up.sh --help           Show this text.
#
# This stack is separate from scripts/dev-up.sh (PostgreSQL only, project factory-dev). They never share data.
#
# Settings (environment): FACTORY_PG_PORT (default 55432), FACTORY_API_PORT (8080), FACTORY_SECRETS_DIR
# (default infra/compose/secrets, created with mode 0700 and random passwords, never committed).
# FACTORY_PROJECT, FACTORY_TEST and FACTORY_RUN_ID name a throwaway copy and label its objects; the smoke and
# drill scripts set them. A person leaves them alone.
#
# Exit codes: 0 done, 1 failed, 2 wrong arguments, 3 BLOCKED (Docker, psql or diesel is missing or not running).

# The OPS_* variables set below are read by scripts/lib/ops.sh, which this script sources.
# shellcheck disable=SC2034
set -euo pipefail
OPS_TOOL=local-up
# shellcheck source=lib/ops.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/lib/ops.sh"

action=up
profile=local
yes=0
bare=0
while [ $# -gt 0 ]; do
  case "$1" in
    --status) action=status ;;
    --down) action=down ;;
    --destroy) action=destroy ;;
    --yes) yes=1 ;;
    --factory) profile=factory ;;
    --bare) bare=1 ;;
    -h | --help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) ops_usage_error "unknown argument '$1' (try --help)" ;;
  esac
  shift
done

ops_require_python
ops_require_docker

OPS_PROJECT=${FACTORY_PROJECT:-factory-local}
OPS_SECRETS_DIR=${FACTORY_SECRETS_DIR:-$OPS_ROOT/infra/compose/secrets}
export FACTORY_SECRETS_DIR=$OPS_SECRETS_DIR
export FACTORY_PG_PORT=${FACTORY_PG_PORT:-55432}
export FACTORY_TEST=${FACTORY_TEST:-false}
export FACTORY_RUN_ID=${FACTORY_RUN_ID:-local}
OPS_RUN_ID=$FACTORY_RUN_ID
# The "factory" profile adds to "local".
OPS_PROFILE=local
if [ "$profile" = factory ]; then OPS_EXTRA_PROFILE=factory; fi

case "$action" in
  status)
    ops_compose ps
    exit 0
    ;;
  down)
    # Both profiles are named, whatever was started: a network belongs to the services of a profile, and `down`
    # leaves behind the networks of a profile it was not told about.
    OPS_EXTRA_PROFILE=factory
    ops_compose down --remove-orphans
    ops_say "local-up: stopped. The data volumes are kept. Start again with scripts/local-up.sh"
    exit 0
    ;;
  destroy)
    [ "$yes" = 1 ] || ops_usage_error "--destroy deletes the database and the artifacts. Add --yes to confirm."
    OPS_EXTRA_PROFILE=factory
    ops_compose down --volumes --remove-orphans
    ops_say "local-up: removed the containers, the network and the data volumes."
    exit 0
    ;;
esac

ops_require_psql
ops_require_diesel
ops_install_traps
ops_new_run
OPS_TEST=$FACTORY_TEST
OPS_PG_IMAGE_REF=$(ops_compose config --images 2>/dev/null | grep '^postgres' | head -n1) || true
[ -n "$OPS_PG_IMAGE_REF" ] || ops_die "cannot read the PostgreSQL image from $OPS_COMPOSE_FILE"
ops_make_secrets "$OPS_SECRETS_DIR"
ops_pgdata_guard

# Only the creation of the networks needs the lock. The stack outlives this script, so the lock is handed on
# as soon as the stack is up.
ops_lock_acquire
ops_say "local-up: starting the '$profile' profile on 127.0.0.1:$FACTORY_PG_PORT"
ops_stack_up postgres

ops_find_postgres
ops_write_pgpass

# The secret file for the superuser must match the password stored in the volume. The image reads it only when it
# first creates the database, so a regenerated or restored secrets folder goes unnoticed until something logs in.
if ! ops_psql_as factory_admin -c 'SELECT 1' >/dev/null 2>"$OPS_RUN_DIR/admin.err"; then
  ops_die "cannot log in as factory_admin with $OPS_SECRETS_DIR/pg_superuser_password ($(head -n 1 "$OPS_RUN_DIR/admin.err")). The password is stored inside the database volume when it is first created. Restore the secrets folder you started this volume with, or start again with scripts/local-up.sh --destroy --yes."
fi

if [ "$bare" = 1 ]; then
  ops_lock_release
  ops_say "local-up: PostgreSQL and the artifact volume are up and empty on 127.0.0.1:$FACTORY_PG_PORT (no migrations, no logins)."
  ops_say "  next: scripts/restore.sh --backup <folder>"
  exit 0
fi

applied=$(ops_sql -c 'SELECT count(*) FROM __diesel_schema_migrations' 2>/dev/null || echo none)
expected=$(find "$OPS_ROOT/migrations" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
if [ "$applied" = "$expected" ]; then
  ops_say "local-up: the schema is current ($applied migrations)"
else
  ops_say "local-up: applying migrations ($applied of $expected are applied)"
  ops_migrate
fi
ops_ensure_logins

for pair in "factory_worker:f|f|f|t|f|f|f" "factory_api:f|f|f|t|f|t|f" "factory_engine:f|f|f|f|t|f|f"; do
  login=${pair%%:*}; want=${pair#*:}
  got=$(ops_role_readiness "$login") || ops_die "cannot log in as $login"
  [ "$got" = "$want" ] || ops_die "$login failed the start-up role check: got '$got', expected '$want'"
done

# The factory services start last, so the database they check at start-up is ready for them.
if [ "$profile" = factory ]; then ops_stack_up api worker; fi
ops_lock_release

ops_say "local-up: ready."
ops_say "  database :postgres://factory_api@127.0.0.1:$FACTORY_PG_PORT/factory (passwords in $OPS_SECRETS_DIR)"
ops_say "  stop     : scripts/local-up.sh --down      remove data too: scripts/local-up.sh --destroy --yes"
