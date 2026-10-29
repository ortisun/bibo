# Restore from a backup

- Status: the commands are the real ones, and the full procedure is in [backup and restore](../operations/backup-and-restore.md). The restore drill passed on 2026-10-28 on a laptop with Docker. It was not repeated on this machine, because the Docker daemon did not answer here.
- Form: runbook.
- Goal: bring the database and the artifact store back from a backup into a fresh local stack, and prove that the result is the backup.

## Symptom

The database or the artifact directory is lost or damaged: a deleted volume, a disk failure, a ledger chain that no longer verifies, or a blob that no longer hashes to its own name.

## Before you begin

- A backup folder made by `scripts/backup.sh`, named `factory-backup-<UTC time>`.
- Docker, `psql` and the Diesel command line. Without Docker the scripts exit with code 3 and the word `BLOCKED`.
- The secret files of the stack in `infra/compose/secrets/`, or a folder named with `--secrets-dir`. A backup holds no password. The restore sets the three login passwords from these files.
- The decision signing key, `decision_signing_key` in the same folder, **kept apart from the backup because the backup does not hold it**. Put the old one in the folder of the new stack before step 2. If it is gone, the restore still works, but every decision request that was waiting for a person is rejected as `not_signed` and the person has to repeat it. See [the key is not in the backup](../operations/backup-and-restore.md).
- Stop the API and the worker. A restore goes into a new stack, never over data.

## Steps

### 1. Find out how bad it is

If you can still reach the old database, check the chains first. `scripts/backup.sh` refuses to back up a source whose hash chains do not verify. That refusal is the check:

```bash no-run reason="needs a running local stack"
scripts/backup.sh --out /tmp/scratch-backups
```

If it ends with `a hash chain in the source database does not verify`, the source is damaged. Do not restore this backup over a good copy. Restore the newest backup that verifies.

### 2. Start an empty stack

```bash no-run reason="needs Docker and destroys the local stack"
scripts/local-up.sh --destroy --yes
scripts/local-up.sh --bare
```

`--destroy --yes` deletes the database and the artifacts of the old stack. Run it only when the old data is lost or you have it elsewhere. `--bare` starts PostgreSQL 18 and the artifact volume with no migrations and no logins.

### 3. Restore

```bash no-run reason="needs Docker and a backup folder"
scripts/restore.sh --backup ~/.local/share/factory/backups/factory-backup-TIME --report restore.json
```

The script checks the backup first, refuses a target that is not fresh, then applies the roles, the database and the passwords and unpacks the artifacts. It stops at the first failure and prints one line per check.

### 4. Start the stack and confirm

```bash no-run reason="needs Docker"
scripts/local-up.sh
```

This applies the migrations if any are newer than the backup and checks that each login passes the start-up role check.

## Check that it worked

`scripts/restore.sh` exits with 0 and every line of the report is `PASS`. The checks include the schema version, the roles and grants, the row count and content hash of every table, the head of every chain, the ledger chain rebuilt outside PostgreSQL, the three logins, the isolation between tenants and every artifact file against its recorded hash. Read `restore.json` for the names.

Then start the API and the worker, and read a job you know with `factory-cli status`.

## If something goes wrong

| You see | What to do |
|---|---|
| `FAIL backup-checksums` | The backup folder is damaged. Use an older one. |
| `FAIL target-is-fresh` | The target already holds data. Go back to step 2. |
| `FAIL target-major-version` | The target runs another PostgreSQL major version than the backup. Use the same major version. |
| `FAIL database-restored` | `pg_restore` stopped and rolled back. Read the first two error lines. |
| `BLOCKED` and exit code 3 | Docker, `psql` or the Diesel command line is missing or not running. Nothing was restored. |
| `FAIL backup-holds-only-its-own-files` | A file that a backup does not define is in the folder. If it is a secret file, someone copied it in: take it out, and treat it as exposed. |
| Decisions that were waiting show `decision.rejected` with `not_signed` after the restore | The new stack has another decision signing key than the one that signed them, because the backup does not hold the key. | Each person repeats the decision, without `--key`. See [the key is not in the backup](../operations/backup-and-restore.md). |

[Troubleshooting](../operations/troubleshooting.md), "Restoring", lists every failure with its message and cause.

A backup is not encrypted. It holds tenant data in clear text, protected by file modes only. Keep backups on an encrypted disk.
