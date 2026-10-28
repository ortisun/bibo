#!/usr/bin/env bash
# scripts/restore.sh - restore a backup (scripts/backup.sh) into a FRESH local stack, then verify the result.
#
#   scripts/restore.sh --backup DIR [--project NAME] [--secrets-dir DIR] [--report FILE]
#
#   --backup DIR      A folder made by scripts/backup.sh.
#   --project NAME    The Compose project of the target stack. Default factory-local. The stack must be running
#                     and EMPTY: a new database volume and a new artifact volume, with the migrations not applied
#                     and no factory login. Start one with: scripts/local-up.sh --destroy --yes, then start
#                     PostgreSQL only (see docs/operations/backup-and-restore.md). The script refuses a target that
#                     holds data, because restoring over data would hide exactly the damage this exists to find.
#   --secrets-dir DIR The folder of the secret files (default infra/compose/secrets, or FACTORY_SECRETS_DIR).
#                     The restore sets the three login passwords from them; the backup holds no password.
#   --report FILE     Write the machine-readable report here (JSON, mode 0600).
#
# What it does, in order. Each step stops the restore at the first failure and nothing later is attempted.
#   1. Checks SHA256SUMS and that the manifest names the same hashes. A damaged backup is refused before the
#      target is touched.
#   2. Refuses a target that is not fresh, or whose PostgreSQL major version differs from the backup's.
#   3. Applies globals.sql (the roles), then pg_restore --exit-on-error --single-transaction, then sets the login
#      passwords, then unpacks artifacts.tar into the artifact volume.
#   4. Verifies, and prints one line per check: the schema version, the roles and their memberships, the grants
#      and row-level security policies (as fingerprints), the row count and content hash of every table, the heads
#      of every hash chain, the ledger chain rebuilt outside PostgreSQL and checked by the database's own
#      function, the three logins and the isolation between tenants through a real login, every artifact file
#      against its recorded hash, the modes, and every artifact index row against a blob.
#
# Exit codes: 0 restored and every check passed, 1 a check failed or the restore failed, 2 wrong arguments,
# 3 BLOCKED (Docker or psql is missing or not running).

set -euo pipefail
OPS_TOOL=restore
# shellcheck source=lib/ops.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/lib/ops.sh"

OPS_PROJECT=${FACTORY_PROJECT:-factory-local}
backup=""
OPS_SECRETS_DIR=${FACTORY_SECRETS_DIR:-$OPS_ROOT/infra/compose/secrets}
report=""
while [ $# -gt 0 ]; do
  case "$1" in
    --backup) backup=${2:?--backup needs a folder}; shift ;;
    --project) OPS_PROJECT=${2:?--project needs a name}; shift ;;
    --secrets-dir) OPS_SECRETS_DIR=${2:?--secrets-dir needs a folder}; shift ;;
    --report) report=${2:?--report needs a file}; shift ;;
    -h | --help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) ops_usage_error "unknown argument '$1' (try --help)" ;;
  esac
  shift
done
[ -n "$backup" ] || ops_usage_error "--backup is required (try --help)"
[ -d "$backup" ] || ops_usage_error "$backup is not a folder"
backup=$(cd "$backup" && pwd -P)
for f in pg_password_api pg_password_worker pg_password_engine pg_superuser_password; do
  [ -s "$OPS_SECRETS_DIR/$f" ] || ops_usage_error "the secret file $OPS_SECRETS_DIR/$f is missing"
done

ops_require_python
ops_require_docker
ops_require_psql
ops_install_traps
ops_new_run
OPS_TEST=${FACTORY_TEST:-false}

finish() { # the last line of every path: write the report, print the verdict, exit
  local rc=0
  ops_finish "$report" --meta "backup=$backup" --meta "project=$OPS_PROJECT" || rc=$?
  if [ "$rc" = 0 ]; then ops_say "restore: PASS"; else ops_say "restore: FAIL"; fi
  exit "$rc"
}

ops_say "restore: backup $backup into project $OPS_PROJECT"

# 1. The backup itself.
ops_py_checks check-sums --dir "$backup"
[ "$OPS_FAILED" = 0 ] || { ops_say "restore: the backup is damaged; the target was not touched"; finish; }

ops_find_postgres
ops_write_pgpass
manifest="$backup/manifest.json"
want_major=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["database"]["server_major"])' "$manifest")

# 2. The target must be fresh and the same major version.
have_major=$(ops_sql -c "SELECT current_setting('server_version_num')::int / 10000")
if [ "$have_major" != "$want_major" ]; then
  ops_check target-major-version FAIL "the backup is from PostgreSQL $want_major, the target is PostgreSQL $have_major. A dump moves between major versions only through a restore into the matching major; see docs/operations/troubleshooting.md"
  finish
fi
tables=$(ops_sql -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m','S')")
roles=$(ops_sql -c "SELECT count(*) FROM pg_roles WHERE rolname LIKE 'factory\_%' AND rolname <> 'factory_admin'")
blobs=$(ops_volume_run "$OPS_ARTIFACT_VOLUME" ro 'find /v -mindepth 1 | wc -l' | tr -d ' ')
if [ "$tables" != 0 ] || [ "$roles" != 0 ] || [ "$blobs" != 0 ]; then
  ops_check target-is-fresh FAIL "the target is not empty: $tables relations in public, $roles factory roles, $blobs entries in the artifact volume. Restore into a new database volume and a new artifact volume"
  finish
fi
ops_check target-is-fresh PASS "no tables, no factory roles, empty artifact volume; PostgreSQL $have_major"

# 3. Restore: the roles, the database, the passwords, the artifacts.
grep -v -E '^(CREATE|ALTER) ROLE factory_admin( |;)' "$backup/globals.sql" >"$OPS_RUN_DIR/globals.filtered.sql"
if ! ops_sql -f - <"$OPS_RUN_DIR/globals.filtered.sql" >/dev/null 2>"$OPS_RUN_DIR/globals.err"; then
  ops_check roles-applied FAIL "$(head -n 3 "$OPS_RUN_DIR/globals.err" | tr '\n' ' ')"
  finish
fi
ops_check roles-applied PASS "globals.sql applied (the bootstrap superuser is the target's own)"

if ! docker exec -i "$OPS_PG" pg_restore -U factory_admin -d factory --exit-on-error --single-transaction \
      <"$backup/database.dump" >/dev/null 2>"$OPS_RUN_DIR/restore.err"; then
  ops_check database-restored FAIL "pg_restore stopped and rolled back: $(grep -m2 -E 'error|ERROR' "$OPS_RUN_DIR/restore.err" | tr '\n' ' ' | cut -c1-400)"
  finish
fi
ops_check database-restored PASS "pg_restore finished in one transaction"

ops_ensure_logins || { ops_check login-passwords FAIL "could not set the passwords"; finish; }
if ! ops_volume_run "$OPS_ARTIFACT_VOLUME" rw 'tar --numeric-owner -C /v -xpf -' <"$backup/artifacts.tar" 2>"$OPS_RUN_DIR/untar.err"; then
  ops_check artifacts-unpacked FAIL "tar failed: $(head -n 2 "$OPS_RUN_DIR/untar.err" | tr '\n' ' ')"
  finish
fi
ops_check artifacts-unpacked PASS "artifacts.tar extracted with owners and modes"

# 4. Verify.
ops_sql -f - <"$OPS_LIB_DIR/sql/facts.sql" >"$OPS_RUN_DIR/facts.json"
ops_sql -f - <"$OPS_LIB_DIR/sql/tables.sql" >"$OPS_RUN_DIR/tables.json"
ops_py_checks compare-db --manifest "$manifest" --facts "$OPS_RUN_DIR/facts.json" --tables "$OPS_RUN_DIR/tables.json"

# The ledger chain rebuilt outside PostgreSQL, from an export of the rows. This does not call the verifier
# function that lives in the database being checked.
ops_sql -c "SELECT coalesce(json_agg(row_to_json(e) ORDER BY e.tenant_id, e.job_id, e.sequence), '[]'::json) FROM ledger_entries e" \
  >"$OPS_RUN_DIR/ledger.json"
ops_py_checks verify-ledger --manifest "$manifest" <"$OPS_RUN_DIR/ledger.json"

# The audit chain of every tenant, rebuilt by the DBA's reference verifier (docs/database/tools).
audit_tenants=$(ops_sql -c "SELECT DISTINCT tenant_id FROM audit_events ORDER BY 1")
audit_bad=""
audit_n=0
for tenant in $audit_tenants; do
  ops_sql -c "SELECT json_agg(row_to_json(a) ORDER BY a.sequence) FROM audit_events a WHERE a.tenant_id = '$tenant'" \
    >"$OPS_RUN_DIR/audit.json"
  if ! python3 -I "$OPS_ROOT/docs/database/tools/verify_audit_chain.py" <"$OPS_RUN_DIR/audit.json" \
        >"$OPS_RUN_DIR/audit.out" 2>&1; then
    audit_bad="$audit_bad $tenant: $(head -n 1 "$OPS_RUN_DIR/audit.out")"
  fi
  audit_n=$((audit_n + 1))
done
if [ -z "$audit_bad" ] && [ "$audit_n" -gt 0 ]; then
  ops_check audit-chain-rebuilt-outside-postgresql PASS "$audit_n tenant chains verified by verify_audit_chain.py"
else
  ops_check audit-chain-rebuilt-outside-postgresql FAIL "${audit_bad:-no audit chain found}"
fi

# The three logins, as real logins over TCP, with the start-up check of the storage crate
# (docs/database/tests/role_readiness.sql).
for pair in "factory_worker:f|f|f|t|f|f|f" "factory_api:f|f|f|t|f|t|f" "factory_engine:f|f|f|f|t|f|f"; do
  login=${pair%%:*}; want=${pair#*:}
  if got=$(ops_role_readiness "$login" 2>&1); then
    if [ "$got" = "$want" ]; then ops_check "login-$login" PASS "logs in; role check $got"
    else ops_check "login-$login" FAIL "role check returned '$got', expected '$want'"; fi
  else
    ops_check "login-$login" FAIL "cannot log in: $(echo "$got" | head -n 1)"
  fi
done

# Forced row-level security, through the tenant login. For every tenant: the rows the login sees with that
# tenant's setting are exactly that tenant's rows (counted by the superuser), none of another tenant's, and with
# no setting there are none. This is the isolation of NT-TEN-01 on the restored database; the full rls suite of
# scripts/db-test.sh builds its own database and is not run here.
rls_bad=""
rls_n=0
for tenant in $(ops_sql -c "SELECT id FROM tenants ORDER BY id"); do
  for table in jobs ledger_entries audit_events; do
    want_n=$(ops_sql -c "SELECT count(*) FROM $table WHERE tenant_id = '$tenant'")
    printf "BEGIN;\nSELECT set_config('factory.tenant_id', '%s', true);\nSELECT count(*) || '/' || count(*) FILTER (WHERE tenant_id <> '%s') FROM %s;\nROLLBACK;\n" \
      "$tenant" "$tenant" "$table" >"$OPS_RUN_DIR/rls.sql"
    got=$(ops_psql_as factory_worker -f "$OPS_RUN_DIR/rls.sql" 2>&1 || true)
    # The last line of the answer is "<visible>/<foreign>".
    last=$(printf '%s\n' "$got" | tail -n 1)
    if [ "$last" != "$want_n/0" ]; then rls_bad="$rls_bad $table@${tenant:0:8}(saw '$last', expected '$want_n/0')"; fi
    rls_n=$((rls_n + 1))
  done
done
none=$(ops_psql_as factory_worker -c "SELECT (SELECT count(*) FROM jobs) + (SELECT count(*) FROM ledger_entries) + (SELECT count(*) FROM audit_events)" 2>&1 || true)
[ "$none" = 0 ] || rls_bad="$rls_bad no-setting(saw '$none' rows)"
sys_read=$(ops_psql_as factory_engine -c "SELECT count(*) FROM ledger_entries" 2>&1 || true)
case "$sys_read" in *"permission denied"*) ;; *) rls_bad="$rls_bad system-role-reads-ledger('$sys_read')" ;; esac
if [ -z "$rls_bad" ]; then
  ops_check forced-rls-isolates-tenants PASS "$rls_n tenant-and-table checks; no setting sees no rows; the system login cannot read the ledger"
else
  ops_check forced-rls-isolates-tenants FAIL "$rls_bad"
fi

# The artifacts: found on disk, compared with the recorded list, the modes, and the index rows.
ops_volume_run "$OPS_ARTIFACT_VOLUME" ro "$OPS_LIST_SCRIPT" >"$OPS_RUN_DIR/found.list"
ops_volume_run "$OPS_ARTIFACT_VOLUME" ro "$OPS_STATE_SCRIPT" >"$OPS_RUN_DIR/state.json"
ops_py_checks compare-artifacts --manifest "$manifest" --recorded "$backup/artifacts.list" --found "$OPS_RUN_DIR/found.list" \
  --state "$OPS_RUN_DIR/state.json" --database-facts "$OPS_RUN_DIR/facts.json"

finish
