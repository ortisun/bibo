# The local deployment

- Status: written for the work package `s1-local-deployment`. Every command below was run on 2026-10-28 on a macOS laptop (Docker Desktop 29.9.2, Compose 5.6.1, PostgreSQL 18.6). The factory services (`api`, `worker`) do not exist yet, so the part of this page that describes them is a contract, not a result. It says so where it matters.
- Form: how-to guide and reference.
- Goal: run PostgreSQL 18 and the artifact volume on your own machine, laid out the way the security documents ask for, with the places where the factory services plug in already in the file.

This is a local setup. It is not the production deployment, and nothing here makes a claim about one.

## Start and stop

From the repository root:

```bash
scripts/local-up.sh                  # first run: makes the secret files, starts PostgreSQL 18, applies the 18 migrations,
                                     # creates the three logins, checks each one
scripts/local-up.sh --status         # what is running
scripts/local-up.sh --down           # remove the containers and the network, keep the data
scripts/local-up.sh --destroy --yes  # also delete the database and the artifacts
scripts/local-up.sh --bare           # PostgreSQL and the artifact volume only, empty: the target for scripts/restore.sh
scripts/local-up.sh --factory        # also api and worker, once their images exist (see the contract below)
```

It needs Docker with Compose 2.24 or newer, `psql` 16 or newer, and the Diesel CLI 2.3.11 (`cargo install diesel_cli --version 2.3.11 --locked --no-default-features --features postgres`). A missing tool ends the script with exit code 3 and the word `BLOCKED`. Nothing is verified then, and a caller must not read it as success. The migrations are applied from the host by the Diesel CLI, as the owner role, never by the application (ADR 0007).

This stack is separate from `scripts/dev-up.sh`. That script runs PostgreSQL alone, as the Compose project `factory-dev`. This one is the project `factory-local`, with its own volumes and its own port, so the two never touch each other's data. The two files are `infra/compose/docker-compose.yml` with `postgres.yml` (the old one) and `infra/compose/local.yml` (this one).

## What runs

| Service | Profile | Image | What it is |
|---|---|---|---|
| `postgres` | `local`, `test` | `postgres:18.6` pinned by the digest of its multi-platform index | The factory database. Published on `127.0.0.1:55432` (`FACTORY_PG_PORT`). |
| `artifacts-init` | `local`, `test`, `factory` | the same image | A one-shot job. Gives the artifact volume the owner and the mode the storage crate expects (below). No network. |
| `sandbox-probe` | `test` | `factory-sandbox/agent`, by digest, from `infra/sandbox-images/images.json` | The real agent sandbox image run under the sandbox policy flags. Only `scripts/smoke.sh` starts it. |
| `api` | `factory` | `factory-api:local` | **Enabled when the binary exists.** Not started today. |
| `worker` | `factory` | `factory-worker:local` | **Enabled when the binary exists.** Not started today. |

**Profiles.** `local` is what a person runs. `test` is what `scripts/smoke.sh` and `scripts/restore-drill.sh` run: the project name carries a run number, the port is chosen by the script, nothing restarts, and every object is labelled `factory.test=true` and `factory.run=<run>`. `factory` adds the two factory services to either. A service with no profile would start in every case, so every service names its own.

**What is not here, on purpose.**

- NATS. ADR 0004 says Slice 1 has no relay and no NATS dependency. The outbox rows are written, and nothing reads them yet.
- The egress sidecar. It is not a Compose service: the worker's supervisor starts one per job, on that job's own `--internal` network (`docs/security/sandbox-policy.md` section 5). Its image, `factory-sandbox/egress-sidecar`, is in `images.json`.
- An object store. ADR 0008 puts the Slice 1 artifacts on the local file system.
- A Docker socket for the worker. See the note under the contract.

## Network layout

| Network | Internal | On it | Why |
|---|---|---|---|
| `data` | no | `postgres`, `api`, `worker` | The only network PostgreSQL is on. It cannot be internal, because Docker publishes no port from an internal network and the database port is published on the loopback address. |
| `broker` | yes | `worker`, and the per-job egress sidecars the worker starts | The model broker (a listener in the worker) is reachable by the sidecars here, and by nothing else. No route out. |
| `probe_net` | yes | `sandbox-probe` (test profile) | Stands in for a per-job sandbox network. |

A real sandbox sits on its own per-job internal network next to its sidecar, created at run time. It has no address on `data`, and an internal network has no route to this machine. `scripts/smoke.sh` tests that with the real image (below).

**A measurement worth knowing.** When the probe is also put on the `data` network (a deliberate break, below), it can resolve `postgres`, connect to the database address, connect to the *published* database port through `host.docker.internal`, and reach the internet. So a container on any network that is not internal can reach a port published on `127.0.0.1`. Loopback binding keeps other computers out. It does not keep other containers out. Only an internal network does.

## Ports

Every published port is bound to `127.0.0.1`. The smoke script reads `docker inspect` of every container to check it, and also connects to this machine's own LAN address on the database port, which was refused.

| Port | Service | Variable |
|---|---|---|
| `127.0.0.1:55432` | PostgreSQL | `FACTORY_PG_PORT` |
| `127.0.0.1:8080` | `api` (factory profile) | `FACTORY_API_PORT` |

55432 is not 5432 on purpose: other stacks on a developer machine often own 5432.

## Secrets

Compose reads four files from `FACTORY_SECRETS_DIR` (default `infra/compose/secrets/`, created mode 0700 by `scripts/local-up.sh`, every file 0600, random 48-character values, never printed):

| File | Used by |
|---|---|
| `pg_superuser_password` | the `postgres` image, through `POSTGRES_PASSWORD_FILE` |
| `pg_password_api`, `pg_password_worker`, `pg_password_engine` | the three logins; `api` and `worker` mount the ones they need at `/run/secrets/` |

The folder is ignored by Git (`infra/compose/secrets/.gitignore`). No password, token or key is in any committed file, and no secret-looking environment variable holds a value: a secret reaches a program only as the path of a file in a variable whose name ends in `_FILE`. (The repository's secret detector, `scripts/ci.sh --self-test-no-secrets`, flags any Compose key with `PASSWORD` in its name that has a value not starting with `${`, even when the value is a file path. So these paths are written `${FACTORY_RUN_SECRETS_DIR:-/run/secrets}/pg_password_api`. The detector cannot tell a path from a password; letting it skip names that end in `_FILE` would be its owner's change, `s0-ci-pipeline`, and was not made here.) `scripts/smoke.sh --static` checks the second rule on the rendered file. `scripts/ci.sh --only secret-scan` checks the first.

The database stores the superuser password inside its volume when it first creates the cluster. A new secrets folder does not change it. `scripts/local-up.sh` checks that the secret still opens the database and stops with an explanation when it does not.

## The artifact volume

The storage crate (`crates/storage/src/artifact_fs`) writes `<root>/sha256/ab/cd/<hash>`, creates folders with mode 0700 and blobs with mode 0400, opens the root once and never changes its mode. So the root has to exist, belong to the process user and be closed to everyone else before the first write. `artifacts-init` does that: owner and group `10010`, mode 0700, applied to the top folder only, never to the blobs inside, so it is safe to run on a volume that holds data. The factory services run as `10010:10010`. (10001 to 10003 belong to the sandbox images.) `scripts/smoke.sh` reads `10010:10010 700` back from the volume.

## Limits, restarts, hardening

Every service drops all capabilities and adds back only what it proves it needs (`postgres`: `CHOWN`, `DAC_OVERRIDE`, `SETGID`, `SETUID`, because the image starts as root to fix the data folder and then drops to `postgres`; `artifacts-init`: `CHOWN`, `DAC_OVERRIDE`, `FOWNER`). Every service has a read-only root file system, `no-new-privileges`, a memory limit, a process limit, bounded logs, and runs with an init process. PostgreSQL gets 2 GB and 2 CPUs. `scripts/smoke.sh --static` checks all of that on the rendered file, and a service that adds a capability, drops a limit or mounts the Docker socket makes it fail.

`restart: unless-stopped` in the `local` profile, `no` in `test`. The health check of PostgreSQL asks over TCP on `127.0.0.1`, because during first-time setup the image runs a temporary server that listens on the socket only.

## Contract for the factory services

This is the agreement the composition work (`apps/api`, `apps/worker`, `s1-composition-roots`) has to honor. It is written into `infra/compose/local.yml` under the `factory` profile and is checked there. If the composition work needs something different, change this table and that file in the same commit.

**Images.** Built on this machine and never pulled (`pull_policy: never`, so a name that belongs to someone else on a registry is never fetched):

| Variable | Default | What |
|---|---|---|
| `FACTORY_API_IMAGE` | `factory-api:local` | the `api` binary, entry point `/usr/local/bin/factory-api` |
| `FACTORY_WORKER_IMAGE` | `factory-worker:local` | the `worker` binary, entry point `/usr/local/bin/factory-worker` |

**Process.** Runs as `10010:10010` on a read-only root with a `tmpfs` at `/tmp`, no capabilities. The image entry point is the binary, with no command override. Each binary answers `healthcheck` (for example `factory-api healthcheck`) with exit code 0 only when it is ready, which for both means: the schema check passed (the migration count is not behind what the code was built for, ADR 0007) and the start-up role check of each of its pools passed (`docs/database/tests/role_readiness.sql`, expected rows in `docs/database/for-the-storage-crate.md`). The images have no shell and no `curl`, so the binary has to check itself.

**Environment.** Settings are names and paths. A secret is only ever the path of a file.

| Variable | `api` | `worker` | Value in the stack |
|---|---|---|---|
| `FACTORY_PROFILE` | yes | yes | `local` (adapter selection; the production profile refuses fakes) |
| `FACTORY_LISTEN_ADDR` | yes | | `0.0.0.0:8080` (published as `127.0.0.1:${FACTORY_API_PORT}`) |
| `FACTORY_DB_HOST`, `FACTORY_DB_PORT`, `FACTORY_DB_NAME` | yes | yes | `postgres`, `5432`, `factory` |
| `FACTORY_DB_API_USER`, `FACTORY_DB_API_PASSWORD_FILE` | yes | | `factory_api`, `/run/secrets/pg_password_api` |
| `FACTORY_DB_TENANT_USER`, `FACTORY_DB_TENANT_PASSWORD_FILE` | | yes | `factory_worker`, `/run/secrets/pg_password_worker` |
| `FACTORY_DB_SYSTEM_USER`, `FACTORY_DB_SYSTEM_PASSWORD_FILE` | | yes | `factory_engine`, `/run/secrets/pg_password_engine` |
| `FACTORY_ARTIFACT_DIR` | yes | yes | `/var/lib/factory/artifacts` (the shared `artifacts` volume) |
| `FACTORY_BROKER_LISTEN_ADDR` | | yes | `0.0.0.0:8181` |
| `FACTORY_BROKER_NETWORK` | | yes | `factory-local_broker`, the name of the `broker` network, so the supervisor can attach each sidecar to it |
| `FACTORY_SANDBOX_AGENT_IMAGE`, `FACTORY_SANDBOX_VERIFY_IMAGE`, `FACTORY_SANDBOX_SIDECAR_IMAGE` | | yes | image references by digest from `infra/sandbox-images/images.json` (empty until set) |
| `DOCKER_HOST` | | yes | from `FACTORY_WORKER_DOCKER_HOST`, empty by default |

The database roles follow `docs/database/for-the-storage-crate.md`: the API process uses `factory_api`; the worker holds two logins and two pools, `factory_worker` for the tenant pool and `factory_engine` for the system pool, and the two are never the same login.

**Networks and ports.** `api` is on `data` and publishes `8080`. `worker` is on `data` and `broker` and publishes nothing. The model broker listens on `0.0.0.0:8181` inside the worker, so it is also reachable from `data`. That is harmless here (the only other members are PostgreSQL and the API) and would be worth tightening when the broker exists.

**Startup order.** `scripts/local-up.sh --factory` starts PostgreSQL, applies the migrations, creates the logins, checks them, and only then starts `api` and `worker`. Services never run migrations.

**Docker access, an open decision.** The worker has to start sandbox containers, so it needs a Docker API endpoint. A container that can talk to the Docker daemon controls the whole machine, so this file mounts no Docker socket and sets `DOCKER_HOST` from `FACTORY_WORKER_DOCKER_HOST` (empty). With nothing set, the worker cannot start a sandbox and the job is BLOCKED, which is the fail-closed answer `docs/security/sandbox-policy.md` asks for. Two ways forward, both for the security specialist to choose: run the worker on the host in Slice 1 (it then uses the host's Docker and joins the `broker` network by name), or put a reviewed socket proxy in front of the daemon. This work package did not choose.

## The smoke test

```bash
scripts/smoke.sh --static     # reads the rendered Compose file; no Docker daemon needed; this is what CI runs
scripts/smoke.sh              # the whole test: starts a throwaway project, checks it, removes it (about 10 seconds)
scripts/smoke.sh --report FILE
```

`--static` checks PostgreSQL is only on `data`; the sandbox network is internal and shares nothing with PostgreSQL; `broker` is internal; every published port is on `127.0.0.1`; every image is a digest or never pulled; PostgreSQL is 18 by digest; every service drops all capabilities, has a read-only root, `no-new-privileges`, limits and a profile, and mounts no Docker socket; no secret-looking variable holds a value; the factory services run as 10010.

The full run adds: PostgreSQL healthy and the probe running; the artifact volume `10010:10010 700`; the migrations applied and each of the three logins passing the role check over `127.0.0.1`; every container's published ports on `127.0.0.1`; this machine's LAN address refusing the database port; and from inside the probe (the agent sandbox image by digest, `10001:10001`, no capabilities, read-only root, on an internal network) that `postgres` does not resolve, the database address and `host.docker.internal:<port>` and `1.1.1.1:443` cannot be reached. A **control** runs the same connection method from a container on the `data` network and requires it to succeed, so a failure above means "no route" and not "the test cannot connect".

**Results on 2026-10-28.** `scripts/smoke.sh`: 27 checks (12 static, 15 dynamic), all passed, 8 seconds, nothing left over (`containers=0 networks=0 volumes=0`). With a Compose override that puts the probe on `data`, the static part failed four checks and the full run failed five more (the probe resolved `postgres`, connected to the database address, reached the published port and reached `1.1.1.1`). With an override that publishes a second port on `0.0.0.0` both parts failed `ports-loopback-only`. Both exited 1.

**CI.** Two steps are registered in `scripts/ci/steps.d/`. `local-ops-unit-tests` runs 45 tests of the backup, restore and smoke logic without Docker. `local-stack-static` runs `scripts/smoke.sh --static`; it needs the `docker` CLI and its Compose plugin but no daemon, and ends as BLOCKED, never as passed, when the CLI is missing (checked with a `PATH` that has no `docker`: exit 3). The full smoke test, the drill and the backup are **not** CI steps. They start containers, need the agent sandbox image (2 GB, built locally, not published), take the shared Docker lock and compete with other stacks for network addresses. Run them by hand.

## The Docker lock

The Docker daemon hands every network an address block from a small pool, and a machine with a few Compose stacks has used most of it. On this machine the pool held 15 blocks of the `172.x` range and 16 of the `192.168.x` range when this was written, with 5 free. The Rust sandbox tests take one machine-wide lock for as long as they hold a network, so two runs never create networks at once. These scripts take **the same lock**: an exclusive `flock` on `${TMPDIR}/factory-docker-network.lock`, so a shell script and a Rust test exclude each other. A taker waits up to 15 minutes (`FACTORY_DOCKER_LOCK_WAIT_SECONDS`) and then ends with exit 3 and `BLOCKED`. A run that holds the lock for more than 5 minutes (`FACTORY_DOCKER_HOLD_SECONDS`) is ended, so one stuck run cannot hold the machine. `scripts/local-up.sh` holds it only while it creates the network.

Each script creates one Compose project and removes only that project: containers, network, volumes, by `docker compose down --volumes` for that project name, then checks that nothing labelled with the run is left (`left over from run ...: containers=0 networks=0 volumes=0`). A leftover turns the exit code into a failure. No script runs `docker system prune`, `network prune` or `volume prune`. If the address pool is full the script stops with `BLOCKED`; it does not delete anyone's network.

## What is not verified

- Nothing in the `factory` profile has been started. `api`, `worker`, their `healthcheck` subcommands, their variables and the way the worker reaches Docker are a contract. `docker compose config` renders them and the static check covers them; no container of theirs ran.
- `up --wait` with the factory services depending on a one-shot job. The script starts the job first and starts the services by name with `--no-deps`, because Compose 5.6.1 reports a finished one-shot job as a failure while waiting (the first run did exactly that). A plain `docker compose up` of the `factory` profile, without the script, relies on `depends_on: service_completed_successfully`, which was not run.
- Linux. Everything ran on Docker Desktop for macOS (a Linux virtual machine). On a Linux host, published loopback ports and `host.docker.internal` behave differently; the "sandbox cannot reach the published port" result in particular needs a rerun there.
- Address-pool exhaustion. It was not reproduced, on purpose: it would take the pool away from every other stack. The scripts recognise Docker's two spellings of it (the same ones as the Rust lock helper) and end `BLOCKED`; that is tested on the text only.
- Anything about production: no TLS between services, no host firewall, no AppArmor profile (`docs/security/sandbox-policy.md` lists them as required on the Linux production host).
