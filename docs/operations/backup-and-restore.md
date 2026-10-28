# Backup, restore and the restore drill

- Status: written for the work package `s1-local-deployment`. Every command and result below was run on 2026-10-28 on a macOS laptop with Docker Desktop 29.9.2, PostgreSQL 18.6 in Docker, `psql` 18.6 and Diesel 2.3.11. The results are in the last section.
- Form: how-to guide and reference.
- Goal: take a backup of the factory database and the artifact directory, restore it into a new stack, and know, from a script that exits non-zero on any difference, that the restore is the same system.
- Source: ADR 0007 and 0012 (roles, row-level security), ADR 0008 (artifact layout, the ledger, "backups of the artifact directory are an `sre` item for Slice 1"), `docs/database/ledger-and-audit.md`, `docs/database/for-the-storage-crate.md`.

## Back up

```bash
scripts/backup.sh                          # the stack from scripts/local-up.sh, into ~/.local/share/factory/backups
scripts/backup.sh --project NAME --out DIR --keep 7 --label "before the upgrade"
```

A backup is one folder named `factory-backup-<UTC time>`, mode 0700, every file 0600:

| File | What it holds |
|---|---|
| `database.dump` | `pg_dump --format=custom` of the `factory` database, run inside the PostgreSQL container so the client and the server are the same version. Schema, data, owners, grants (also column grants), row-level security policies and the `FORCE` flags, functions with their `SET search_path`, triggers. |
| `globals.sql` | `pg_dumpall --globals-only --no-role-passwords`: the roles, their attributes and their memberships. **No password and no password hash.** The script stops if the word `password` appears in it. |
| `artifacts.tar` | the artifact directory, with numeric owners and modes. |
| `artifacts.list` | one line per blob, `<sha256> <size> <path>`, hashed from the bytes on disk when the backup was taken. |
| `manifest.json` | see below. |
| `SHA256SUMS` | `shasum -a 256 -c SHA256SUMS` checks the folder. |

The manifest records: the format (`factory-backup/1`), the time (read from the system clock **in the script**; the application never reads a clock for this, ADR 0011), the server version, the image digest, the `pg_dump` version, the schema version (the number of applied migrations and the newest one), every `factory_*` role with its attributes and memberships, fingerprints of the grants, the policies, the functions, the triggers, the constraints and the indexes, the row count and a content hash of every table, the head (sequence and hash) of every ledger chain and audit chain, the artifact count and bytes, the index rows that point at local blobs, and the hash of every file in the folder.

**What it refuses.** A backup is not made while the `api`, `worker` or `engine` logins are connected (the dump, the counts and the artifact copy would be taken at different moments) unless you pass `--allow-live`. It is not made when a ledger or audit chain in the source does not verify, when a blob does not hash to its own file name, when an index row has no blob, or when the artifact modes are not the storage crate's, unless you pass `--allow-inconsistent`, which keeps a record of the damage. A partial folder is removed.

**Order.** The database is dumped first and the artifacts second. A new blob is written before its index row, so every row in the dump has its blob in the later copy.

### Retention

`--keep N` (default 7, never below 1) keeps the newest N folders in `--out` and deletes older ones, after the new backup passed its own checksum check. Only a folder named `factory-backup-*` that holds a `manifest.json` of this format is ever deleted. Anything else in the folder, a person's notes included, is left alone. Checked: five backups with a decoy folder, a folder without a manifest and a folder with another format; the decoys stayed. `--keep 0` still keeps the newest.

### Encryption, and what a backup does not hold

**Backups are not encrypted at rest.** This is a local setup. The folder holds tenant data in clear text, protected by modes 0700 and 0600 and by the user account, which is the same exposure as the Docker volumes it copies. Keep the folder on an encrypted disk (FileVault). Encrypt a backup (for example with `age`) before it goes anywhere else. A shared or production backup needs encryption, a key held elsewhere, and a retention rule that someone owns; this package does not provide them.

**No secret is stored.** The role passwords stay out of `globals.sql`; a restore sets them again from the secret files. The drill searches every backup file, and a plain-text dump of the database, for each of the four generated passwords and requires no match. The database itself should hold no secret (tokens are stored hashed, ADR 0007); that is a property of the application, and this check can only prove the four values it knows about.

## Restore

A restore goes into a **new** stack: a new database volume and a new artifact volume. It will not run over data.

```bash
scripts/local-up.sh --destroy --yes     # only if the old stack must go
scripts/local-up.sh --bare              # PostgreSQL and the artifact volume, empty: no migrations, no logins
scripts/restore.sh --backup ~/.local/share/factory/backups/factory-backup-20261028T133844Z --report restore.json
scripts/local-up.sh                     # optional: confirms the schema is current and the logins work
```

`restore.sh` takes the secrets from `infra/compose/secrets/` (or `--secrets-dir`) and sets the three login passwords from them. It stops at the first failure and prints one line per check.

1. **The backup is checked first.** `SHA256SUMS` against the files, and the manifest against `SHA256SUMS`. A damaged backup is refused before the target is touched.
2. **The target must be PostgreSQL 18 (the same major as the backup) and fresh**: no table in `public`, no `factory_*` role besides the bootstrap superuser, an empty artifact volume.
3. **Roles, then the database, then passwords, then artifacts.** `globals.sql` (without the target's own bootstrap superuser), `pg_restore --exit-on-error --single-transaction` (all or nothing), the passwords, `artifacts.tar`.
4. **Verification**, each a line in the report:

| Check | What it proves |
|---|---|
| `schema-version` | The same number of migrations and the same newest one as the backup. |
| `roles-exist`, `roles-attributes-and-memberships` | The same `factory_*` roles, none superuser or `BYPASSRLS`, the same group memberships (the three logins in the right groups). |
| `fingerprint-tables`, `-columns`, `-functions`, `-schemas`, `-default_acl`, `-policies`, `-triggers`, `-constraints`, `-indexes` | Grants, owners, row-level security flags and policies, and the definitions are the same. A failure names the kind. |
| `tables-exist`, `row-counts`, `content-hash` | Every table has the same number of rows and the same SHA-256 over all its rows. |
| `ledger-heads`, `audit-heads` | The head of every chain equals the one recorded. A chain that lost its tail still verifies on its own (`docs/database/ledger-and-audit.md`), so the head is what notices. |
| `ledger-verify-chain-in-database`, `audit-verify-chain-in-database` | The database's own verifier functions return NULL for every chain. |
| `ledger-chain-rebuilt-outside-postgresql`, `ledger-heads-equal-manifest` | The ledger chain rebuilt in Python from an export of the rows (`SHA-256(prev_entry_hash + "\n" + canonical_json)`), which does not trust the function that lives in the database being checked. |
| `audit-chain-rebuilt-outside-postgresql` | The audit chain of every tenant checked by `docs/database/tools/verify_audit_chain.py`. |
| `login-factory_worker`, `login-factory_api`, `login-factory_engine` | Each logs in over TCP with its restored password and passes the start-up check `role_readiness.sql` with the expected answer. |
| `forced-rls-isolates-tenants` | Through the tenant login: for every tenant and for `jobs`, `ledger_entries` and `audit_events`, the rows it sees with that tenant's setting are exactly that tenant's rows (counted by the superuser) and none of another tenant's; with no setting it sees nothing; the system login cannot read the ledger. |
| `artifacts-same-files`, `artifacts-byte-identical`, `artifacts-hash-equals-name`, `artifacts-list-hash` | The same blobs, each with the recorded hash and size, each hashing to its own file name. |
| `artifact-index-rows-have-blobs` | Every `artifacts` row with backend `local-fs` has a blob on disk. |
| `artifacts-owner-and-modes` | Blobs 0400, folders 0700, owner `10010:10010`, no link or special file, nothing outside `sha256/`. |

Exit 0 means the restore finished and every check passed. Exit 1 means it did not. The report (`--report FILE`, JSON, mode 0600) has the format `factory-report/1`: `result`, `failed` (the names), `counts`, `meta` and every check with `name`, `status` (`PASS`, `FAIL`, `SKIP`) and `detail`.

**What the verification does not do.** It does not run the `rls` suite of `scripts/db-test.sh`: that suite builds its own database from the migrations, creates its own roles and drops them, so it cannot run against a restored database. The isolation check above is a small version of it. It cannot find a ledger or audit chain that someone rewrote from the start with fresh hashes and rewrote in the manifest too; only a copy of the head kept outside the database and outside the backup folder can (`docs/database/ledger-and-audit.md`, "What the chains do not give"; the external anchor is not built). It does not move a backup between PostgreSQL major versions.

**A finding about fingerprints.** The text that `pg_get_constraintdef` prints for a `CHECK` expression is not the same after a dump and a restore: the same chain of `AND` comes back with different brackets (`jobs_pipeline_scope_check`, seen in the first drill). A fingerprint of the exact text failed on a correct restore. The constraint fingerprint therefore ignores brackets in `CHECK` definitions. Every name, operator and value still counts; a changed bracket structure that changes the meaning would not be seen. Policy expressions, which could have the same problem, matched exactly in every run.

## The restore drill

```bash
scripts/restore-drill.sh                     # database and artifacts, about 20 seconds
scripts/restore-drill.sh --artifacts         # artifacts only; no database, no network; about 3 seconds
scripts/restore-drill.sh --breaks            # also damage things on purpose
scripts/restore-drill.sh --artifacts --breaks
scripts/restore-drill.sh --report drill.json
```

It makes one Compose project (`factory-drill-<run>`) with one network and two volumes, every object labelled `factory.test=true`, under the Docker lock, and removes it. The steps: start PostgreSQL 18 with a random loopback port, apply the migrations, create the three logins, seed two tenants, three jobs, three ledger chains (4, 3 and 3 entries), two audit chains (5 events each), five artifact blobs (one of 200 KB, one shared by two tenants) and their index rows, with the fixture builders of `docs/database/tests/00_helpers.sql`; run `scripts/backup.sh`; check the modes and look for the four secrets; destroy the container **and both volumes**; start a fresh container on fresh volumes; run `scripts/restore.sh`.

`--artifacts` does the artifact half alone: seed blobs, archive, delete the volume, make a new one, unpack, compare the list of hashes, sizes and modes.

### The deliberate breaks

`--breaks` damages a copy of the backup, or the target, one thing at a time. A break is **caught** when the restore exits non-zero **and** the check that names the damage is among the failures. All results are from the run of 2026-10-28.

| Break | Caught by | Result |
|---|---|---|
| One byte of `database.dump` flipped, checksums untouched | `backup-checksums` | restore exit 1, the target untouched (no table created) |
| The same, with `SHA256SUMS` and the manifest fixed to match | `database-restored` | exit 1: `pg_restore` stopped and rolled back |
| One blob removed from `artifacts.tar`, checksums fixed | `artifacts-same-files`, `artifact-index-rows-have-blobs` | exit 1 |
| `globals.sql` emptied (restore without the roles), checksums fixed | `database-restored` | exit 1: `pg_restore` failed on the missing roles |
| The manifest says PostgreSQL 17 | `target-major-version` | exit 1 |
| A second restore into the target that already holds the first | `target-is-fresh` | exit 1 |
| One ledger row edited with triggers off (`session_replication_role = replica`), then `backup.sh` | refused by `backup.sh` itself | exit 1: `a hash chain in the source database does not verify` |
| The same row, backed up with `--allow-inconsistent`, then restored | `ledger-verify-chain-in-database`, `ledger-chain-rebuilt-outside-postgresql` | exit 1; row counts and content hashes still equal, because the tamper was consistent in the backup |
| (artifacts) a blob missing from the archive | `artifacts-same-files` | caught |
| (artifacts) one byte of one blob changed on disk | `artifacts-byte-identical`, `artifacts-hash-equals-name` | caught |

The last tamper row matters most. The content hash and the row counts agree with the backup, because the backup was taken after the edit, and only the two chain checks see it.

The first version of the drill got one thing wrong that the breaks exposed: every break was recorded as "exit 0 and failed" because the script lost its exit status in a trap (bash scoping: a function with a local variable named `rc` was written to by the exit trap). The drill showed the restore failing and reported the break as not caught. It is fixed, and the trap now keeps its status under a name no function uses.

## Results of 2026-10-28

Run in a row, on the final commit of the work package, under the shared Docker lock. After the runs the containers, networks and volumes on the machine were the same as before (the only difference was the restart counter of two containers of another stack).

| Command | Result |
|---|---|
| `python3 -I -W error scripts/tests/test_factory_ops.py` | 45 tests passed, 5 seconds, no Docker |
| `scripts/smoke.sh --static` | 12 checks passed; exit 3 with `BLOCKED` when `docker` is not on `PATH`; exit 0 with the daemon unreachable |
| `scripts/smoke.sh` | 27 checks passed, 8 seconds |
| `scripts/restore-drill.sh --artifacts` | 5 checks passed, 2 seconds |
| `scripts/restore-drill.sh` | 45 checks passed, 18 seconds (39 of them are the restore's own) |
| `scripts/restore-drill.sh --breaks` | 54 checks passed, 36 seconds: the 45 above and 9 more, one per break |
| `scripts/restore-drill.sh --artifacts --breaks` | 7 checks passed, 3 seconds |
| operator path: `local-up.sh`, `backup.sh`, `local-up.sh --destroy --yes`, `local-up.sh --bare`, `restore.sh` | restore exit 0 on an empty database; a second backup with `--keep 1` removed the first |

The happy-path restore, in the database drill: PostgreSQL 18.6; 18 migrations, newest `20261027001800`; 22 tables with 224 rows; 3 ledger chains (10 entries) and 2 audit chains (10 events) verified by the database and rebuilt outside it; the three logins passing the role check with the expected answers (`f|f|f|t|f|f|f` for `factory_worker`, `f|f|f|t|f|t|f` for `factory_api`, `f|f|f|f|t|f|f` for `factory_engine`); nine tenant-and-table isolation checks; five blobs byte-identical with mode 0400, folders 0700, owner 10010.
