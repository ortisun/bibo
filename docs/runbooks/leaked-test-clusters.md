# Leaked test clusters and Docker problems

- Status: the commands and the messages come from `scripts/db-test.sh`, the storage crate's test support and [troubleshooting](../operations/troubleshooting.md). The Docker daemon did not answer on the machine used to write this page, so the Docker cases here are described from those documents and were not run again.
- Form: runbook.
- Goal: get the tests and the local stack to start again after an interrupted run or a stuck Docker daemon.

## Symptom

- `scripts/db-test.sh` or a test ends with `BLOCKED: no PostgreSQL server: set FACTORY_DB_ADMIN_URL, install PostgreSQL 16 or later, or start Docker`, and the message adds that macOS allows 32 shared-memory segments.
- A test says `BLOCKED: docker did not answer within 60s`.
- A script says `waiting for the Docker lock (held by: ...)` and does not go on.
- `scripts/local-up.sh` stops with `ports are not available` or a similar error.

## Before you begin

- You know which processes are yours. A shared Docker daemon may run other people's containers. Do not stop or prune what you did not start.
- Do not restart Docker Desktop to fix this unless nothing else runs on it.

## Steps

### 1. Leaked PostgreSQL test clusters

The tests start a private PostgreSQL cluster on a unix socket and remove it at the end. A run killed with `kill -9`, or a crashed run, leaves the cluster running. Each leaked cluster holds a shared-memory segment, and macOS allows 32.

```bash no-run reason="inspects and stops processes on this machine"
ipcs -m
ps aux | grep "factory-pg\|fdb\."
```

A leaked cluster has a data directory named `factory-pg-<run>` or `factory-db-work.<random>/data` under the temporary directory, and a socket directory `/tmp/fdb.<random>`. Stop each one by its data directory:

```bash no-run reason="stops a leaked cluster by its data directory"
pg_ctl -D "$TMPDIR/factory-pg-RUN" -m immediate -w stop
rm -rf "$TMPDIR/factory-pg-RUN" /tmp/fdb.RANDOM
```

Use `pg_ctl` from the same PostgreSQL major version that started the cluster.

### 2. Roles left on a server you provided

When you point `FACTORY_DB_ADMIN_URL` at a server, a run killed with `kill -9` leaves the cluster-wide roles `dbtest_*` behind. Drop them by hand as the superuser. The script leaves `factory_app` on purpose.

### 3. Docker does not answer

```bash no-run reason="asks the local Docker daemon"
timeout 20 docker info
```

If this times out, the daemon is stuck or not running. The scripts stop with `BLOCKED` and exit code 3 in that case. They never report a pass. Start Docker Desktop, or leave the Docker steps BLOCKED.

### 4. The Docker lock

Scripts that create networks hold a machine-wide lock, because the pool of network addresses is shared. The message `waiting for the Docker lock (held by: pid ... thread ...)` means another script holds it. Wait. If the holder is gone, the lock is released when its process ends.

### 5. A stack that did not start

The common causes and fixes are in [troubleshooting](../operations/troubleshooting.md): a port already in use (`FACTORY_PG_PORT=55433 scripts/local-up.sh`), a missing image, a changed PostgreSQL major version in an old volume, and a leftover container from a failed start (`scripts/local-up.sh --down`).

## Check that it worked

`ipcs -m` shows fewer segments. `scripts/db-test.sh statuses` ends with `PASS: statuses`. `timeout 20 docker info` prints the server version instead of timing out.

## If something goes wrong

| You see | What to do |
|---|---|
| `pg_ctl` says there is no such directory | The cluster was already removed. Remove the stray socket directory and look at `ps` again. |
| The segments stay after you stop the clusters | Another program holds them. `ipcs -m` shows the owner. |
| Docker answers but the sandbox tests fail | See the [isolation re-review](../reviews/isolation-core-security-rereview.md) and the sandbox README. Do not weaken a posture check to make a test pass. |

## Related

- [Database tests: running them](../database/running.md).
- [Quickstart](../guides/quickstart.md): which steps need Docker.
