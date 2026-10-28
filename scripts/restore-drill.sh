#!/usr/bin/env bash
# scripts/restore-drill.sh - prove that a backup restores, on a throwaway stack that this script creates and removes.
#
#   scripts/restore-drill.sh                 DB and artifacts: seed, back up, destroy, restore into fresh volumes, verify.
#   scripts/restore-drill.sh --artifacts     The artifact directory only. Needs no database and no network.
#   scripts/restore-drill.sh --breaks        Also damage the backup or the target on purpose, one thing at a time, and
#                                            require every damage to be caught. (With --artifacts: the artifact breaks.)
#   scripts/restore-drill.sh --report FILE   Write the machine-readable report (JSON, mode 0600) to FILE.
#
# What it makes: one Compose project named factory-drill-<run>, with one network and two volumes, every object
# labelled factory.test=true and factory.run=<run>. It holds the machine-wide Docker lock while it runs (the pool of
# network addresses is shared with every other stack on this machine) and removes only what it made. It never
# prunes. If the address pool is exhausted it stops and says so; it does not delete anyone else's network.
#
# The happy path, in order:
#   1. start PostgreSQL 18 (profile test, random loopback port), apply the migrations, create the three logins;
#   2. seed two tenants, three jobs, three ledger chains, two audit chains, five artifact blobs and their index rows
#      (with the fixture builders of docs/database/tests/00_helpers.sql);
#   3. scripts/backup.sh;
#   4. destroy the database container and BOTH volumes, and start a fresh container on fresh volumes;
#   5. scripts/restore.sh with verification: schema version, roles, grants and policies, row counts and content hash,
#      chain heads, the ledger chain rebuilt outside PostgreSQL, the three logins, isolation between tenants through
#      a real login, every artifact file against its recorded hash;
#   6. checks on the backup folder itself: modes 0600/0700, no secret value in any file.
#
# The deliberate breaks (--breaks). Each is made in a copy of the backup, or in the target, and must make the restore
# or the backup exit non-zero with the check that names the damage:
#   corrupt-dump-byte           one byte of database.dump flipped; checksums untouched
#   corrupt-dump-byte-rehashed  the same, with SHA256SUMS and the manifest fixed to match
#   delete-artifact             one blob removed from artifacts.tar, checksums fixed to match
#   restore-without-roles       globals.sql emptied, checksums fixed to match
#   restore-into-stale-target   a second restore into the target that already holds the first
#   major-version-mismatch      the manifest says PostgreSQL 17
#   tamper-ledger-row           one ledger row edited with triggers off: backup.sh refuses; with --allow-inconsistent the
#                               restore verification fails on the ledger checks
#
# Exit codes: 0 every check passed (and every break was caught), 1 a check failed, 2 wrong arguments, 3 BLOCKED (Docker,
# psql, diesel or python3 is missing, or the lock was not free in time).

set -euo pipefail
OPS_TOOL=restore-drill
# shellcheck source=lib/ops.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/lib/ops.sh"

mode=full
breaks=0
report=""
while [ $# -gt 0 ]; do
  case "$1" in
    --artifacts) mode=artifacts ;;
    --breaks) breaks=1 ;;
    --report) report=${2:?--report needs a file}; shift ;;
    -h | --help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) ops_usage_error "unknown argument '$1' (try --help)" ;;
  esac
  shift
done

ops_require_python
ops_require_docker
if [ "$mode" = full ]; then ops_require_psql; ops_require_diesel; fi
ops_install_traps
ops_new_run
started=$SECONDS

OPS_TEST=true
OPS_PROFILE=test
OPS_PROJECT="factory-drill-$OPS_RUN_ID"
OPS_SECRETS_DIR="$OPS_RUN_DIR/secrets"
BACKUPS="$OPS_RUN_DIR/backups"
mkdir -m 0700 "$BACKUPS"
ops_make_secrets "$OPS_SECRETS_DIR"
export FACTORY_SECRETS_DIR=$OPS_SECRETS_DIR FACTORY_TEST=true FACTORY_RUN_ID=$OPS_RUN_ID FACTORY_RESTART=no
export FACTORY_PROJECT=$OPS_PROJECT COMPOSE_PROFILES=test
OPS_PG_IMAGE_REF=$(ops_compose config --images 2>/dev/null | grep '^postgres:' | head -n1)
[ -n "$OPS_PG_IMAGE_REF" ] || ops_die "cannot read the PostgreSQL image from $OPS_COMPOSE_FILE"
OPS_ARTIFACT_VOLUME="${OPS_PROJECT}_artifacts"

# Last cleanup to run first: remove the project (containers, the network, both volumes), then count what is left. A
# leftover turns the exit code into a failure, so the drill cannot pass while leaving objects behind.
drill_cleanup() {
  ops_stack_down
  ops_lock_release
  if ! ops_leftovers; then
    ops_warn "objects of this run are still there: remove them with their labels (docker ... --filter label=factory.run=$OPS_RUN_ID)"
    OPS_EXIT_CODE=1
  fi
}
ops_on_exit drill_cleanup

ops_lock_acquire
ops_say "restore-drill: project $OPS_PROJECT, mode $mode$([ "$breaks" = 1 ] && echo ' with breaks')"

# ---- helpers ------------------------------------------------------------------------------------------------------

# Five blobs, written the way the storage crate writes them: sha256/ab/cd/<hash>, mode 0400, folders 0700, owner 10010.
# Prints "<hash> <size>" for each. One of them is about 200 KB so that the archive is not trivially small.
SEED_BLOBS_SCRIPT='cd /v && umask 077
put() { h=$(sha256sum "$1" | cut -d" " -f1); d="sha256/$(echo "$h" | cut -c1-2)/$(echo "$h" | cut -c3-4)"
  mkdir -p "$d"; cp "$1" "$d/$h"; chmod 0400 "$d/$h"; echo "$h $(wc -c <"$1" | tr -d " ")"; }
i=1; while [ $i -le 4 ]; do printf "factory drill artifact number %s\n" "$i" >/tmp/b; put /tmp/b; i=$((i+1)); done
yes "a large drill block that repeats" | head -n 6000 >/tmp/b; put /tmp/b
chown -R 10010:10010 /v/sha256; chown 10010:10010 /v; find /v -type d -exec chmod 0700 {} +'

drill_prepare_volume() { ops_compose run --rm --no-deps -T artifacts-init >/dev/null || ops_die "cannot prepare the artifact volume"; }

drill_seed_blobs() { ops_volume_run "$OPS_ARTIFACT_VOLUME" rw "$SEED_BLOBS_SCRIPT" >"$OPS_RUN_DIR/blobs.txt"; }

drill_seed_db() {
  local hashes sizes
  hashes=$(cut -d' ' -f1 "$OPS_RUN_DIR/blobs.txt" | paste -sd, -)
  sizes=$(cut -d' ' -f2 "$OPS_RUN_DIR/blobs.txt" | paste -sd, -)
  {
    printf 'SET client_min_messages = warning;\n'
    cat "$OPS_ROOT/docs/database/tests/00_helpers.sql"
    printf "\\\\set blob_hashes '%s'\n\\\\set blob_sizes '%s'\n" "$hashes" "$sizes"
    cat "$OPS_LIB_DIR/sql/seed.sql"
  } | ops_sql -f - >/dev/null
}

# Delete the database and every factory role except the bootstrap superuser, and empty the artifact volume. The
# target is then as fresh as the one a real restore needs (a new cluster would also do; this is quicker).
drill_reset_target() {
  ops_sql -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'factory' AND pid <> pg_backend_pid()" >/dev/null
  ops_sql -d postgres -c "DROP DATABASE IF EXISTS factory" >/dev/null
  ops_sql -d postgres -c "CREATE DATABASE factory OWNER factory_admin" >/dev/null
  local r
  for r in $(ops_sql -d postgres -c "SELECT rolname FROM pg_roles WHERE rolname LIKE 'factory\_%' AND rolname <> 'factory_admin' ORDER BY rolname"); do
    ops_sql -d postgres -c "DROP ROLE $r" >/dev/null
  done
  ops_volume_run "$OPS_ARTIFACT_VOLUME" rw 'find /v -mindepth 1 -delete' >/dev/null
}

# A real second cluster on new volumes: the target the happy path needs.
drill_fresh_stack() {
  ops_compose rm --stop --force postgres >/dev/null 2>&1
  docker volume rm "${OPS_PROJECT}_pgdata" "${OPS_PROJECT}_artifacts" >/dev/null
  ops_stack_up postgres
  ops_find_postgres
  ops_write_pgpass
}

restore_run() { # backup-dir report-file  (the exit status is the restore's)
  FACTORY_PROJECT=$OPS_PROJECT bash "$OPS_ROOT/scripts/restore.sh" --backup "$1" --secrets-dir "$OPS_SECRETS_DIR" --report "$2" \
    >"$OPS_RUN_DIR/last-restore.log" 2>&1
}

# A break passes when the restore exits non-zero AND the check that names this damage is among the failures.
expect_caught() { # name report-file exit-status expected-check
  local failed
  failed=$(ops_py lines --report "$2" --failed-only 2>/dev/null || true)
  if [ "$3" != 0 ] && printf '%s\n' "$failed" | tr ' ' '\n' | grep -qx "$4"; then
    ops_check "break-$1" PASS "caught: exit $3, failed checks: $failed"
  else
    ops_check "break-$1" FAIL "NOT caught as expected (wanted '$4' to fail): exit $3, failed checks: ${failed:-none}"
  fi
}

copy_backup() { # source-dir name -> prints the copy's path
  local to="$OPS_RUN_DIR/break-$2"
  cp -R "$1" "$to"
  printf '%s' "$to"
}

# ---- the artifacts-only drill ---------------------------------------------------------------------------------------

drill_artifacts_only() {
  local bad
  drill_prepare_volume
  drill_seed_blobs
  ops_volume_run "$OPS_ARTIFACT_VOLUME" ro "$OPS_LIST_SCRIPT" >"$OPS_RUN_DIR/recorded.list"
  ops_volume_run "$OPS_ARTIFACT_VOLUME" ro 'tar --numeric-owner --sort=name -C /v -cf - .' >"$OPS_RUN_DIR/artifacts.tar"
  ops_check artifacts-source-seeded PASS "$(wc -l <"$OPS_RUN_DIR/recorded.list" | tr -d ' ') blobs, $(wc -c <"$OPS_RUN_DIR/artifacts.tar" | tr -d ' ') bytes archived"

  # Destroy the volume and make a new one, then unpack.
  docker volume rm "$OPS_ARTIFACT_VOLUME" >/dev/null
  drill_prepare_volume
  ops_volume_run "$OPS_ARTIFACT_VOLUME" rw 'tar --numeric-owner -C /v -xpf -' <"$OPS_RUN_DIR/artifacts.tar"
  ops_volume_run "$OPS_ARTIFACT_VOLUME" ro "$OPS_LIST_SCRIPT" >"$OPS_RUN_DIR/found.list"
  ops_volume_run "$OPS_ARTIFACT_VOLUME" ro "$OPS_STATE_SCRIPT" >"$OPS_RUN_DIR/state.json"
  ops_py_checks compare-artifacts --recorded "$OPS_RUN_DIR/recorded.list" --found "$OPS_RUN_DIR/found.list" --state "$OPS_RUN_DIR/state.json"

  [ "$breaks" = 1 ] || return 0
  # Break 1: a blob is missing from the archive.
  local victim
  victim=$(awk 'NR==2 {print $3}' "$OPS_RUN_DIR/recorded.list")
  cp "$OPS_RUN_DIR/artifacts.tar" "$OPS_RUN_DIR/lost.tar"
  ops_py tar-drop --tar "$OPS_RUN_DIR/lost.tar" --member "$victim"
  ops_volume_run "$OPS_ARTIFACT_VOLUME" rw 'find /v -mindepth 1 -delete'
  ops_volume_run "$OPS_ARTIFACT_VOLUME" rw 'tar --numeric-owner -C /v -xpf -' <"$OPS_RUN_DIR/lost.tar"
  ops_volume_run "$OPS_ARTIFACT_VOLUME" ro "$OPS_LIST_SCRIPT" >"$OPS_RUN_DIR/found.list"
  if ops_py compare-artifacts --recorded "$OPS_RUN_DIR/recorded.list" --found "$OPS_RUN_DIR/found.list" \
        >"$OPS_RUN_DIR/break.out"; then
    ops_check break-delete-artifact FAIL "a missing blob was not noticed"
  else
    ops_check break-delete-artifact PASS "caught: $(grep FAIL "$OPS_RUN_DIR/break.out" | cut -f1,3 | head -n 2 | tr '\t\n' ': ')"
  fi
  # Break 2: one byte of one blob changes on disk (the file is read-only; root can still write it).
  ops_volume_run "$OPS_ARTIFACT_VOLUME" rw 'find /v -mindepth 1 -delete'
  ops_volume_run "$OPS_ARTIFACT_VOLUME" rw 'tar --numeric-owner -C /v -xpf -' <"$OPS_RUN_DIR/artifacts.tar"
  ops_volume_run "$OPS_ARTIFACT_VOLUME" rw "f=\$(find /v/sha256 -type f | sort | sed -n 3p); chmod 0600 \$f; printf X | dd of=\$f bs=1 seek=0 conv=notrunc 2>/dev/null; chmod 0400 \$f"
  ops_volume_run "$OPS_ARTIFACT_VOLUME" ro "$OPS_LIST_SCRIPT" >"$OPS_RUN_DIR/found.list"
  if ops_py compare-artifacts --recorded "$OPS_RUN_DIR/recorded.list" --found "$OPS_RUN_DIR/found.list" \
        >"$OPS_RUN_DIR/break.out"; then
    ops_check break-corrupt-blob FAIL "a changed blob was not noticed"
  else
    ops_check break-corrupt-blob PASS "caught: $(grep FAIL "$OPS_RUN_DIR/break.out" | cut -f1 | head -n 3 | tr '\n' ' ')"
  fi
}

# ---- the full drill ---------------------------------------------------------------------------------------------------

drill_full() {
  export FACTORY_PG_PORT
  FACTORY_PG_PORT=$(ops_free_port)
  ops_stack_up postgres
  ops_find_postgres
  ops_write_pgpass
  ops_migrate
  ops_ensure_logins
  ops_check source-stack-started PASS "PostgreSQL $(ops_sql -c 'SHOW server_version') on 127.0.0.1:$OPS_PG_PORT, project $OPS_PROJECT"
  drill_seed_blobs
  drill_seed_db
  ops_check source-seeded PASS "$(ops_sql -c 'SELECT count(*) FROM ledger_entries') ledger entries, $(ops_sql -c 'SELECT count(*) FROM audit_events') audit events, $(ops_sql -c 'SELECT count(*) FROM artifacts') artifact rows, 5 blobs"

  # Back up.
  local bdir
  FACTORY_PROJECT=$OPS_PROJECT bash "$OPS_ROOT/scripts/backup.sh" --out "$BACKUPS" --keep 5 --label "restore drill" >"$OPS_RUN_DIR/backup.log" 2>&1 \
    || { cat "$OPS_RUN_DIR/backup.log" >&2; ops_die "backup.sh failed"; }
  bdir=$(sed -n 's/^BACKUP_DIR=//p' "$OPS_RUN_DIR/backup.log" | tail -n 1)
  [ -d "$bdir" ] || ops_die "backup.sh did not report a folder"
  ops_check backup-made PASS "$(basename "$bdir"), $(wc -c <"$bdir/database.dump" | tr -d ' ') bytes of database, $(wc -l <"$bdir/artifacts.list" | tr -d ' ') blobs"
  drill_check_backup_folder "$bdir"

  # The deliberate break that needs the source: a tampered ledger row is refused at backup time.
  # (It is done on the restored copy below, where the data is the same; the source is about to be destroyed.)

  # Destroy the source, start fresh, restore.
  drill_fresh_stack
  local rc=0
  restore_run "$bdir" "$OPS_RUN_DIR/restore-happy.json" || rc=$?
  ops_py_checks lines --report "$OPS_RUN_DIR/restore-happy.json" --prefix "restore: "
  if [ "$rc" = 0 ]; then ops_check restore-into-fresh-stack PASS "scripts/restore.sh exited 0"; else
    ops_check restore-into-fresh-stack FAIL "scripts/restore.sh exited $rc"; sed -n '1,40p' "$OPS_RUN_DIR/last-restore.log" >&2; fi

  [ "$breaks" = 1 ] || return 0

  # Breaks that damage a copy of the backup.
  local d off size rc2
  d=$(copy_backup "$bdir" corrupt-dump-byte)
  size=$(wc -c <"$d/database.dump" | tr -d ' ')
  ops_py corrupt --file "$d/database.dump" --offset $((size / 2))
  drill_reset_target; rc2=0; restore_run "$d" "$OPS_RUN_DIR/b1.json" || rc2=$?
  expect_caught corrupt-dump-byte "$OPS_RUN_DIR/b1.json" "$rc2" backup-checksums
  drill_check_untouched corrupt-dump-byte

  d=$(copy_backup "$bdir" corrupt-dump-byte-rehashed)
  ops_py corrupt --file "$d/database.dump" --offset $((size / 2))
  ops_py rehash --dir "$d"
  drill_reset_target; rc2=0; restore_run "$d" "$OPS_RUN_DIR/b2.json" || rc2=$?
  failed=$(ops_py lines --report "$OPS_RUN_DIR/b2.json" --failed-only)
  if [ "$rc2" != 0 ] && [ -n "$failed" ]; then ops_check break-corrupt-dump-byte-rehashed PASS "caught: exit $rc2, failed checks: $failed"
  else ops_check break-corrupt-dump-byte-rehashed FAIL "NOT caught: exit $rc2, failed: ${failed:-none}"; fi

  d=$(copy_backup "$bdir" delete-artifact)
  ops_py tar-drop --tar "$d/artifacts.tar" --member "$(awk 'NR==2 {print $3}' "$d/artifacts.list")"
  ops_py rehash --dir "$d"
  drill_reset_target; rc2=0; restore_run "$d" "$OPS_RUN_DIR/b3.json" || rc2=$?
  expect_caught delete-artifact "$OPS_RUN_DIR/b3.json" "$rc2" artifacts-same-files

  d=$(copy_backup "$bdir" restore-without-roles)
  printf -- '-- roles removed on purpose\nSET client_encoding = '"'"'UTF8'"'"';\n' >"$d/globals.sql"
  ops_py rehash --dir "$d"
  drill_reset_target; rc2=0; restore_run "$d" "$OPS_RUN_DIR/b4.json" || rc2=$?
  expect_caught restore-without-roles "$OPS_RUN_DIR/b4.json" "$rc2" database-restored

  d=$(copy_backup "$bdir" major-version-mismatch)
  ops_py manifest-set --dir "$d" --key database.server_major --value 17
  drill_reset_target; rc2=0; restore_run "$d" "$OPS_RUN_DIR/b5.json" || rc2=$?
  expect_caught major-version-mismatch "$OPS_RUN_DIR/b5.json" "$rc2" target-major-version

  # A good restore, then a second one into the same target: it must be refused.
  drill_reset_target
  rc2=0; restore_run "$bdir" "$OPS_RUN_DIR/b6a.json" || rc2=$?
  if [ "$rc2" != 0 ]; then ops_check break-restore-into-stale-target FAIL "the setup restore failed (exit $rc2)"; else
    rc2=0; restore_run "$bdir" "$OPS_RUN_DIR/b6.json" || rc2=$?
    expect_caught restore-into-stale-target "$OPS_RUN_DIR/b6.json" "$rc2" target-is-fresh
  fi

  # Tamper with a ledger row in the live (restored) database, with the triggers off as only a superuser can.
  ops_sql -c "SET session_replication_role = replica; UPDATE ledger_entries SET canonical_json = replace(canonical_json, 'passed', 'FAILED') WHERE sequence = 2 AND job_id = (SELECT job_id FROM ledger_entries ORDER BY tenant_id, job_id LIMIT 1)" >/dev/null
  rc2=0; FACTORY_PROJECT=$OPS_PROJECT bash "$OPS_ROOT/scripts/backup.sh" --out "$BACKUPS" >"$OPS_RUN_DIR/tamper-backup.log" 2>&1 || rc2=$?
  if [ "$rc2" = 1 ] && grep -q 'does not verify' "$OPS_RUN_DIR/tamper-backup.log"; then
    ops_check break-tamper-ledger-row-refused-at-backup PASS "backup.sh exited 1: $(grep -m1 'does not verify' "$OPS_RUN_DIR/tamper-backup.log" | cut -c1-160)"
  else ops_check break-tamper-ledger-row-refused-at-backup FAIL "backup.sh exited $rc2"; fi
  rc2=0; FACTORY_PROJECT=$OPS_PROJECT bash "$OPS_ROOT/scripts/backup.sh" --out "$BACKUPS" --allow-inconsistent >"$OPS_RUN_DIR/tamper-backup2.log" 2>&1 || rc2=$?
  d=$(sed -n 's/^BACKUP_DIR=//p' "$OPS_RUN_DIR/tamper-backup2.log" | tail -n 1)
  if [ "$rc2" = 0 ] && [ -d "$d" ]; then
    drill_reset_target; rc2=0; restore_run "$d" "$OPS_RUN_DIR/b7.json" || rc2=$?
    expect_caught tamper-ledger-row-restore "$OPS_RUN_DIR/b7.json" "$rc2" ledger-chain-rebuilt-outside-postgresql
  else ops_check break-tamper-ledger-row-restore FAIL "backup.sh --allow-inconsistent exited $rc2"; fi
}

# After a restore that was refused before the target was touched, the target must still be empty.
drill_check_untouched() {
  local t
  t=$(ops_sql -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public'")
  if [ "$t" = 0 ]; then ops_check "break-$1-target-untouched" PASS "no table was created in the target"; else
    ops_check "break-$1-target-untouched" FAIL "$t relations exist in the target"; fi
}

# The backup folder itself: modes and secrets.
drill_check_backup_folder() {
  local dir=$1 modes pat
  modes=$(python3 -I -c 'import os,sys
d=sys.argv[1]
bad=[]
if os.stat(d).st_mode & 0o777 != 0o700: bad.append("folder")
for n in sorted(os.listdir(d)):
    m=os.stat(os.path.join(d,n)).st_mode & 0o777
    if m != 0o600: bad.append("%s=%o" % (n, m))
print(" ".join(bad) or "ok")' "$dir")
  if [ "$modes" = ok ]; then ops_check backup-modes PASS "folder 0700, every file 0600"; else ops_check backup-modes FAIL "wrong modes: $modes"; fi
  # No secret value may appear in the backup. The database dump is compressed, so the plain-text form of the
  # same dump is searched too.
  pat="$OPS_RUN_DIR/patterns"
  (umask 077; for s in pg_superuser_password pg_password_api pg_password_worker pg_password_engine; do ops_secret "$s"; echo; done >"$pat")
  local hits=0 f
  for f in "$dir"/*; do grep -a -F -q -f "$pat" "$f" && hits=$((hits + 1)); done
  if docker exec "$OPS_PG" pg_dump -U factory_admin -d factory --format=plain | grep -a -F -q -f "$pat"; then hits=$((hits + 1)); fi
  if [ "$hits" = 0 ]; then ops_check backup-has-no-secrets PASS "none of the 4 generated passwords is in any backup file or in the plain-text dump"; else
    ops_check backup-has-no-secrets FAIL "$hits file(s) contain a secret value"; fi
  rm -f "$pat"
}

case "$mode" in
  artifacts) drill_artifacts_only ;;
  full) drill_full ;;
esac

ops_say "restore-drill: finished in $((SECONDS - started))s"
rc=0
ops_finish "$report" --meta "mode=$mode" --meta "breaks=$breaks" --meta "postgres_image=$OPS_PG_IMAGE_REF" --meta "seconds=$((SECONDS - started))" || rc=$?
if [ "$rc" = 0 ]; then ops_say "restore-drill: PASS"; else ops_say "restore-drill: FAIL"; fi
exit "$rc"
