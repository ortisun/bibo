#!/usr/bin/env bash
# scripts/backup.sh - back up the factory database and the artifact directory of a running local stack.
#
#   scripts/backup.sh [--project NAME] [--out DIR] [--keep N] [--label TEXT] [--allow-live]
#
#   --project NAME  The Compose project of the stack. Default factory-local (scripts/local-up.sh).
#   --out DIR       Where backups go. Default ${FACTORY_BACKUP_DIR:-~/.local/share/factory/backups}. Created 0700.
#   --keep N        Retention: keep the newest N backups in --out and delete older ones. Default 7, at least 1.
#                   Only a folder named factory-backup-* that holds a manifest of this format is ever deleted.
#   --label TEXT    A note stored in the manifest (for example "before upgrade").
#   --allow-live    Back up while the api, worker or engine logins are connected. Without it the script refuses,
#                   because the database dump, the counts and the artifact copy are then taken at different moments.
#   --allow-inconsistent  Back up even if the source already fails its own checks (a broken ledger chain, a
#                   blob that does not match its name, an index row without a blob). Such a backup will fail its
#                   restore verification on purpose: it is a record of a damaged state, not a good copy.
#
# What a backup is: one folder, factory-backup-<UTC time>, mode 0700, every file 0600:
#   database.dump   pg_dump custom format of the factory database: schema, data, owners, grants, row-level
#                   security policies, functions, triggers.
#   globals.sql     the roles, their attributes and memberships, from pg_dumpall --globals-only
#                   --no-role-passwords. No password or password hash is in it: a restore sets the passwords
#                   again from the secret files.
#   artifacts.tar   the artifact directory, with owners and modes.
#   artifacts.list  "<sha256> <size> <path>" for every blob, hashed from the bytes on disk.
#   manifest.json   the versions, the schema version, the roles, fingerprints of the grants and the policies,
#                   the row count and content hash of every table, the head of every hash chain, the hash of every
#                   file above, and the time (read from the system clock here, never in the application).
#   SHA256SUMS      "shasum -a 256 -c SHA256SUMS" checks the folder.
#
# What a backup is not: encrypted. The folder holds tenant data in clear text, protected by file modes only. On
# this machine that is the same exposure as the Docker volumes it copies. Keep it on an encrypted disk (FileVault),
# and encrypt it before it goes anywhere else. No secret is stored (see docs/operations/backup-and-restore.md).
#
# The order is on purpose: the database is dumped first and the artifacts second. A new blob is written before
# its index row, so every row in the dump has its blob in the later copy.
#
# Exit codes: 0 done, 1 failed, 2 wrong arguments, 3 BLOCKED (Docker is missing or not running).

set -euo pipefail
OPS_TOOL=backup
# shellcheck source=lib/ops.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/lib/ops.sh"

OPS_PROJECT=${FACTORY_PROJECT:-factory-local}
out=${FACTORY_BACKUP_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/factory/backups}
keep=7
label=""
allow_live=0
allow_inconsistent=0
while [ $# -gt 0 ]; do
  case "$1" in
    --project) OPS_PROJECT=${2:?--project needs a name}; shift ;;
    --out) out=${2:?--out needs a folder}; shift ;;
    --keep) keep=${2:?--keep needs a number}; shift ;;
    --label) label=${2:?--label needs text}; shift ;;
    --allow-live) allow_live=1 ;;
    --allow-inconsistent) allow_inconsistent=1 ;;
    -h | --help) sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) ops_usage_error "unknown argument '$1' (try --help)" ;;
  esac
  shift
done
case "$keep" in '' | *[!0-9]*) ops_usage_error "--keep must be a whole number" ;; esac

ops_require_python
ops_require_docker
ops_install_traps
ops_new_run
OPS_TEST=${FACTORY_TEST:-false}
ops_find_postgres
docker volume inspect "$OPS_ARTIFACT_VOLUME" >/dev/null 2>&1 || ops_die "the artifact volume $OPS_ARTIFACT_VOLUME does not exist"

umask 077
mkdir -p "$out" && chmod 0700 "$out"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
dest="$out/factory-backup-$stamp"
n=1
while [ -e "$dest" ]; do dest="$out/factory-backup-$stamp-$n"; n=$((n + 1)); done
mkdir -m 0700 "$dest"
OPS_BACKUP_OK=0
ops_on_exit '[ "$OPS_BACKUP_OK" = 1 ] || { rm -rf "$dest"; ops_warn "backup not completed; removed the partial folder"; }'

ops_say "backup: project $OPS_PROJECT, container ${OPS_PG:0:12}, writing $dest"

# 1. The facts of the source, and the refusals.
ops_sql -f - <"$OPS_LIB_DIR/sql/facts.sql" >"$OPS_RUN_DIR/facts.json" || ops_die "could not read the facts of the database"
ops_sql -f - <"$OPS_LIB_DIR/sql/tables.sql" >"$OPS_RUN_DIR/tables.json" || ops_die "could not hash the tables"
major=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["server_version_num"] // 10000)' "$OPS_RUN_DIR/facts.json")
[ "$major" = 18 ] || ops_die "the server is PostgreSQL $major; this stack is PostgreSQL 18 (ADR 0007)"
sessions=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["sessions"])' "$OPS_RUN_DIR/facts.json")
if [ "$sessions" != 0 ] && [ "$allow_live" = 0 ]; then
  ops_die "$sessions session(s) of the api, worker or engine logins are connected. Stop the factory services (scripts/local-up.sh --down keeps the data) or pass --allow-live."
fi
bad=$(python3 -I -c 'import json,sys; c=json.load(open(sys.argv[1]))["chain"]; print(len(c["ledger_bad"]) + len(c["audit_bad"]))' "$OPS_RUN_DIR/facts.json")
if [ "$bad" != 0 ] && [ "$allow_inconsistent" = 0 ]; then
  ops_die "a hash chain in the source database does not verify ($bad bad). Backing it up would copy the damage. Find out why first, or pass --allow-inconsistent."
fi

# 2. The database: the dump, then the roles.
docker exec -i "$OPS_PG" pg_dump -U factory_admin -d factory --format=custom --lock-wait-timeout=30s >"$dest/database.dump" \
  || ops_die "pg_dump failed"
docker exec -i "$OPS_PG" pg_dumpall -U factory_admin --globals-only --no-role-passwords >"$dest/globals.sql" \
  || ops_die "pg_dumpall --globals-only failed"
if grep -qi 'password' "$dest/globals.sql"; then
  ops_die "globals.sql mentions a password. A backup never carries one. Refusing to keep it."
fi

# 3. The artifacts, second.
ops_volume_run "$OPS_ARTIFACT_VOLUME" ro "$OPS_LIST_SCRIPT" >"$dest/artifacts.list" || ops_die "could not list the artifact blobs"
ops_volume_run "$OPS_ARTIFACT_VOLUME" ro "$OPS_STATE_SCRIPT" >"$OPS_RUN_DIR/state.json" || ops_die "could not read the artifact directory state"
ops_volume_run "$OPS_ARTIFACT_VOLUME" ro 'tar --numeric-owner --sort=name -C /v -cf - .' >"$dest/artifacts.tar" \
  || ops_die "could not archive the artifact directory"

# 4. The manifest and the checksums.
image_digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$OPS_PG_IMAGE_REF" 2>/dev/null || echo "$OPS_PG_IMAGE_REF")
dump_tool=$(docker exec "$OPS_PG" pg_dump --version | tr -d '\n')
ops_py manifest --dir "$dest" --facts "$OPS_RUN_DIR/facts.json" --tables "$OPS_RUN_DIR/tables.json" \
  --artifact-list "$dest/artifacts.list" --database factory --image "$image_digest" --dump-tool "$dump_tool" --label "$label"
ops_py sums --dir "$dest"
chmod 0600 "$dest"/*
chmod 0700 "$dest"

# 5. The source must pass its own artifact checks (every blob hashes to its name, every index row has a blob, the
# modes are the storage crate's). A copy of a damaged directory is refused, not hidden.
ops_py compare-artifacts --manifest "$dest/manifest.json" --recorded "$dest/artifacts.list" --found "$dest/artifacts.list" \
  --state "$OPS_RUN_DIR/state.json" --database-facts "$OPS_RUN_DIR/facts.json" >"$OPS_RUN_DIR/source-artifacts.tsv" || {
  cat "$OPS_RUN_DIR/source-artifacts.tsv" >&2
  if [ "$allow_inconsistent" = 0 ]; then ops_die "the artifact directory fails its own checks. Backup refused (--allow-inconsistent keeps it)."; fi
  ops_warn "the artifact directory fails its own checks; kept because of --allow-inconsistent"
}

ops_py check-sums --dir "$dest" >"$OPS_RUN_DIR/sums.tsv" || { cat "$OPS_RUN_DIR/sums.tsv" >&2; ops_die "the new backup does not verify against its own checksums"; }
OPS_BACKUP_OK=1

# 6. Retention.
ops_py prune --root "$out" --keep "$keep"

ops_say "backup: ok. $(wc -c <"$dest/database.dump" | tr -d ' ') bytes of database, $(wc -l <"$dest/artifacts.list" | tr -d ' ') blobs."
ops_say "BACKUP_DIR=$dest"
