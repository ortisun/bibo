# Troubleshooting the local deployment

- Status: written for the work package `s1-local-deployment`. Every entry below is a problem that came up while building and running the scripts, or one that was provoked on purpose on a throwaway project (`factory-prov-*`, labelled `factory.test=true`, removed afterwards). The messages are copied from the runs of 2026-10-28. One section lists what was **not** reproduced.
- Form: runbook. Each entry: what you see, why, what to do.
- Related: [local-deployment.md](local-deployment.md), [backup-and-restore.md](backup-and-restore.md), the database notes in [../database/running.md](../database/running.md).

Exit codes of every script here, the same as `scripts/ci.sh`: `0` done, `1` failed, `2` wrong arguments, `3` **BLOCKED** (a prerequisite is missing, so nothing was verified; never a pass).

## Starting the stack

### The port is already in use

- **You see** (`scripts/local-up.sh`):

  ```text
  Error response from daemon: ports are not available: exposing port TCP 127.0.0.1:63456 -> 127.0.0.1:0: listen tcp4 127.0.0.1:63456: bind: address already in use
  local-up: error: the stack did not start or did not become healthy (the reason is in the lines above; ...)
  ```

- **Why.** Another program holds the loopback port. The default is 55432 (`FACTORY_PG_PORT`). A failed start leaves what it had already created: the run showed one container in the state `Created`.
- **Do.** Pick a free port and run again: `FACTORY_PG_PORT=55433 scripts/local-up.sh`. If the failed start left a container, `scripts/local-up.sh --down` removes it. Use the same `FACTORY_PG_PORT` when you later run `scripts/backup.sh`: it finds the port from the container, so it needs no variable.

### The first start said a container "exited (0)"

- **You see** (the first run of the new stack, with `docker compose up --detach --wait`):

  ```text
  container factory-lutest-artifacts-init-1 exited (0)
  ```

- **Why.** The artifact volume is prepared by a one-shot job that finishes at once. Compose 5.6.1 treats a finished container as a failure while `--wait` is waiting, though it ended with 0.
- **Do.** Use `scripts/local-up.sh`, which runs the job first (`docker compose run --rm --no-deps artifacts-init`) and then starts the long-running services by name with `--no-deps`. By hand: those two commands.

### `waiting for the Docker lock (held by: pid ... thread ...)`

- **You see.** One line, then a pause. Seen when the drill started while the sandbox tests of another agent were running:

  ```text
  restore-drill: waiting for the Docker lock (held by: pid 91918 thread contract_claude_code_passes_the_agent_runtime_contract since 1793193517)
  ```

- **Why.** The Docker daemon has a small pool of network addresses shared by every stack on the machine, so the real-Docker tests and these scripts take one machine-wide lock (`${TMPDIR}/factory-docker-network.lock`) while they hold a network. It is waiting for its turn, not hung.
- **Do.** Wait. A taker gives up after 15 minutes with `BLOCKED: waited ...s for the Docker lock ... Another run is using the Docker network pool`. If no test run is alive, the holder died without the file being released (the lock belongs to the open file, so a dead process releases it; this is the case only if something else is holding the file open) and you can remove the file. `FACTORY_DOCKER_LOCK_WAIT_SECONDS` and `FACTORY_DOCKER_HOLD_SECONDS` change the two limits.

### `BLOCKED: the Docker daemon is not running`

- **You see** (provoked with `DOCKER_HOST=unix:///nonexistent.sock scripts/smoke.sh`), exit code 3:

  ```text
  smoke: BLOCKED: the Docker daemon is not running, or this user cannot reach it.
  ```

- **Why.** The script could not reach Docker, so it checked nothing. Docker Desktop is not started, or `DOCKER_HOST` points elsewhere.
- **Do.** Start Docker. `scripts/smoke.sh --static` needs the `docker` CLI and Compose but not the daemon, and with no `docker` on `PATH` it prints `BLOCKED: docker is not installed or not on PATH` and exits 3. CI must read 3 as a failure; `scripts/ci.sh` does.

### `cannot log in as factory_admin with .../pg_superuser_password`

- **You see** (provoked by starting an existing volume with a secrets folder in which `pg_superuser_password` was regenerated), exit 1:

  ```text
  local-up: error: cannot log in as factory_admin with .../pg_superuser_password (psql: error: connection to server at "127.0.0.1", port 63456 failed: FATAL:  password authentication failed for user "factory_admin"). The password is stored inside the database volume when ...
  ```

- **Why.** The PostgreSQL image reads `POSTGRES_PASSWORD_FILE` only when it first creates the cluster, and stores the password in the volume. A new secret file changes nothing there. Before this check existed, `scripts/local-up.sh` finished with `ready` against the same volume, because every step it takes goes through the container's own socket; the wrong superuser secret only showed later, at the first login over TCP.
- **Do.** Put back the secrets folder the volume was created with. If it is gone and the data does not matter, `scripts/local-up.sh --destroy --yes`. If the data matters and you can still get in through the socket, `docker exec -it <container> psql -U factory_admin -d factory` and `ALTER ROLE factory_admin PASSWORD '...'` with the value from the secret file (typed into the session, not on a command line).

### The stack starts empty after an image change (a volume of another PostgreSQL major version)

- **You see** (provoked: the stack made with the 18 image, then started with `FACTORY_PG_IMAGE=postgres:17-alpine`), exit 1:

  ```text
  local-up: error: the volume factory-prov2-62125_pgdata holds PostgreSQL 18 data, and the image is PostgreSQL 17. The image would start a new, empty database next to it and leave your data behind. Use the image that made the volume, ...
  ```

- **Why.** The PostgreSQL 18 image keeps its data in `/var/lib/postgresql/18/docker`, older images in `/var/lib/postgresql/data`. Neither refuses when it finds the other's data: it makes a new cluster beside it. Before the check existed, the same sequence ended in `local-up: applying migrations (none of 18 are applied)` on a stack that had held data: an empty database, and the old data still in the volume where nothing reads it. A major version change is a dump and a restore, not an image swap.
- **Do.** Go back to the image that made the volume. Or: back up with that image (`scripts/backup.sh` needs the 18 stack; for another version, `pg_dump` inside the old container), destroy the volume, start the new image with `scripts/local-up.sh --bare`, and restore. `scripts/restore.sh` refuses to restore a dump from one major into another (below).

### `Pool overlaps` / `all predefined address pools have been fully subnetted` — NOT reproduced

Docker had no free address block. This was not provoked: it would take the shared pool away from every other stack on the machine. When this machine was inspected, the pool had 5 free blocks of 16 (`192.168.x.x/20`) after the `172.x` range was used up, so it can happen. `scripts/local-up.sh`, the smoke script and the drill recognise the two spellings of the error that `crates/sandbox/tests/support/docker_lock.rs` recognises (`address pools have been fully subnetted`, `non-overlapping IPv4/IPv6 address pool`), end with `BLOCKED` (exit 3) and say that nothing was removed that the run did not create. That is covered by a test on the text only. The fix is not in these scripts: wait for another stack to finish, or remove networks **you own and no longer need**. Never `docker network prune`: it removes the networks of stacks that are stopped and will be needed again. The daemon's `default-address-pools` setting can be given smaller blocks (`docs/security/sandbox-policy.md` section 5.4); that was not tried.

## Backing up

### `N session(s) of the api, worker or engine logins are connected`

- **You see** (provoked with a `pg_sleep` session as `factory_worker`), exit 1:

  ```text
  backup: error: 1 session(s) of the api, worker or engine logins are connected. Stop the factory services (scripts/local-up.sh --down keeps the data) or pass --allow-live.
  ```

- **Why.** With writers connected, the dump, the row counts and the artifact copy are taken at different moments and the restore verification would fail on a correct copy.
- **Do.** Stop the factory services. A client that was killed can leave its server session behind until the query it was running ends (the `pg_sleep` session stayed for its whole minute, and the next backup was refused again). End it: `docker exec <container> psql -U factory_admin -d factory -c "select pg_terminate_backend(pid) from pg_stat_activity where usename like 'factory\_%' and usename <> 'factory_admin'"`. Only use `--allow-live` for a copy you will not verify.

### `a hash chain in the source database does not verify`

- **You see** (provoked by editing one ledger row with triggers off), exit 1: `backup: error: a hash chain in the source database does not verify (1 bad). Backing it up would copy the damage.`
- **Why.** `ledger_verify_chain` or `audit_verify_chain` returned a sequence number. Something changed a row of an append-only table, or a head is behind.
- **Do.** Find out why first (`SELECT ledger_verify_chain(tenant_id, job_id)` per job, as the superuser, because the verifiers read under the caller's row-level security). `--allow-inconsistent` keeps the evidence of the damage in a backup, and that backup fails its restore verification on purpose.

## Restoring

Each of these is a failed check in the report of `scripts/restore.sh`. The target was not changed by the first three (the drill shows no table created after the checksum refusal).

### `backup-checksums` fails

- **You see:** `FAIL backup-checksums  database.dump does not match its checksum`.
- **Why.** A byte of the file differs from the one that was checksummed: a bad copy, a full disk during the copy, or damage.
- **Do.** Use another backup. `--keep` exists so there is one. A backup whose checksums were fixed after the damage fails later, at `database-restored` or at the content checks.

### `target-is-fresh` fails (a stale target)

- **You see** (provoked by restoring twice into the same stack), exit 1:

  ```text
  FAIL  target-is-fresh   the target is not empty: 26 relations in public, 7 factory roles, 0 entries in the artifact volume. Restore into a new database volume and a new artifact volume
  ```

- **Why.** The restore will not run over data, because that would hide exactly the damage the verification looks for.
- **Do.** `scripts/local-up.sh --destroy --yes`, then `scripts/local-up.sh --bare`, then restore. A stack from `scripts/local-up.sh` is **not** fresh: it already has the migrations and the logins.

### `target-major-version` fails (a version mismatch)

- **You see** (provoked by restoring a PostgreSQL 18 backup into a PostgreSQL 17 stack), exit 1:

  ```text
  FAIL  target-major-version   the backup is from PostgreSQL 18, the target is PostgreSQL 17. A dump moves between major versions only through a restore into the matching major; see docs/operations/troubleshooting.md
  ```

- **Why.** A dump made by one major version is meant for the same major. A newer `pg_dump` can write syntax an older server rejects, and an older dump can lean on defaults that changed. The script does not guess.
- **Do.** Restore into the stack of the backup's major version. To move to a new major, restore into the old major, then upgrade with `pg_upgrade` or dump and restore with the new client, and run the drill again on the result. Not tried here.

### `database-restored` fails

- **You see:** `FAIL database-restored  pg_restore stopped and rolled back: ...` followed by the first two error lines of `pg_restore`.
- **Why.** Two causes were provoked. A flipped byte inside the compressed dump with the checksums fixed to match: `pg_restore` stopped on the damaged data. A `globals.sql` with the roles removed (a restore without the roles): the dump names owners and grantees such as `factory_lookup`, which did not exist. Either way `--single-transaction` rolled everything back, so the target holds no half database.
- **Do.** For a missing role, use the `globals.sql` of the same backup; do not restore the dump by itself with `pg_restore` by hand. Otherwise use another backup.

### `fingerprint-constraints` fails on a correct restore

- **You saw** this on the first full drill: a backup of `jobs_pipeline_scope_check` printed with different brackets after the restore. It is fixed: the fingerprint ignores brackets in `CHECK` definitions (see [backup-and-restore.md](backup-and-restore.md)). If you see a fingerprint failure now, it is real. The failing name says the kind: `-policies` or `-columns` mean a grant or a row-level security policy differs.

### `ledger-verify-chain-in-database` and `ledger-chain-rebuilt-outside-postgresql` fail

- **Why.** The chain in the restored database does not verify: a row was edited, one is missing, or a head is behind. If `content-hash` and `row-counts` pass, the damage was already in the backup.
- **Do.** The restored database is not trustworthy as evidence. Compare with an older backup (`scripts/restore-drill.sh` shows the procedure) and with any head hash kept outside the database (the pull request body carries one per job, ADR 0008).

## Wrong tools

- `psql` older than 16: BLOCKED by the `rls` suite of `scripts/db-test.sh`; the scripts here use 16 or newer for the same reason (`\gset`, `\gexec`, `\bind`).
- Diesel CLI other than 2.3.11: a warning, because `schema.rs` formats differently; the migrations still run. Install the pinned one: `cargo install diesel_cli --version 2.3.11 --locked --no-default-features --features postgres`.
- bash 3.2 (the macOS default) is supported and was the shell for every run above.

## What stays unverified until the binaries exist

- `api` and `worker` have not started. Nothing was checked about their health checks, their use of the `FACTORY_*` variables, the way they read the secret files, the artifact directory permissions as seen by the storage crate (the volume is `10010:10010 700` and the crate's modes are 0700 and 0400, but no Rust code wrote to it), or how the worker reaches Docker.
- The model broker, the per-job sidecars on the `broker` network, and a sandbox that is started by the supervisor. The smoke test uses the real agent image as a probe on a similar network; it is not the supervisor.
- `docker compose up` of the `factory` profile without the script.
- A Linux host, and the pool-exhaustion case above.
