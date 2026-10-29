# Quickstart: run a test-mode job on your machine

- Status: every step marked `quickstart` below is run by `scripts/docs-check.sh --quickstart` in a clean clone of this repository. The expected output comes from those runs. Steps that need Docker are marked, and the check reports them as BLOCKED when the Docker daemon does not answer.
- Form: how-to guide.
- Goal: build the factory, then run one job from a signed webhook to a completed pull request in test mode, on a developer machine, with no credential and no network.

## What this gives you, and what it does not

You will run the real workflow engine, the real API server and a real PostgreSQL. The agents are a script, and the sandbox and the GitHub host are labelled fakes. No model is called. The result shows that the pieces fit together. It does not show that the factory works against a real model or a real GitHub App. That has never been run. The [production guide](production.md) lists what a person must supply first.

## Before you begin

You need these programs.

| Program | Version | Why |
|---|---|---|
| Rust toolchain | 1.98.0 | `rust-toolchain.toml` selects it. With `rustup` installed it is fetched when you first run `cargo` in the repository. |
| `cargo-nextest` | 0.9.137 | Runs the integration tests. |
| PostgreSQL binaries | 18 | `initdb`, `pg_ctl` and `postgres`, plus `psql`. The tests start a private cluster from them and remove it. On macOS: `brew install postgresql@18`. |
| Diesel command line | 2.3.11 | Applies the migrations: `cargo install diesel_cli --version 2.3.11 --locked --no-default-features --features postgres`. |
| `git`, `python3` | any recent | Cloning, and the helper scripts. |

Docker is optional. The steps below that need it are marked, and you can skip them. The [Docker section](#when-docker-is-missing) says what you lose.

Allow about 2 GB of disk for the build directory.

## Steps

### 1. Get the code and check the toolchain

```bash quickstart step=toolchain expect="cargo 1.98.0"
cargo --version
```

If this prints another version, `rustup` is not in use, or the repository's `rust-toolchain.toml` was not read. Run the command from inside the repository.

### 2. Build the programs

```bash quickstart step=build expect="Finished" timeout=1500
cargo build --locked -p factory-cli -p factory-api -p factory-worker
```

The build needs the crates.io packages in `Cargo.lock`. On a machine with no network, `CARGO_NET_OFFLINE=true` works once the packages are in the local cache. On the laptop used to write this guide the build took 26 seconds, with every crate already in the local cache.

### 3. See the command line

```bash quickstart step=cli-help expect="usage: factory-cli <command> [options]"
target/debug/factory-cli --help
```

The [command reference](../reference/commands.md) explains every command.

### 4. See that the worker refuses to start without a configuration

```bash quickstart step=worker-needs-config exit=2 expect="FACTORY_CONFIG: is not set; there is no default configuration file"
target/debug/factory-worker
```

The exit code is 2: the configuration was refused. The worker and the API take no option. They read the file that `FACTORY_CONFIG` names. See the [configuration reference](../reference/configuration.md).

### 5. Run the checks that need no credential

```bash quickstart step=probe exit=3 expect="OK: policy: loaded from the protected checkout" expect="OK: redactor: built from the policy" expect="BLOCKED is not a pass"
target/debug/factory-cli probe --protected-checkout . --images-catalog infra/sandbox-images/images.json --profile local
```

`probe` loads the policy, builds the redactor and reads the image catalog. It prints `OK:` for each. Then it prints a `BLOCKED:` line for every part it cannot check, such as the agent runtime and the GitHub issue source, and it exits with code 3. BLOCKED means there is no evidence either way. It is never a pass.

### 6. Run a database suite

```bash quickstart step=database needs=postgres expect="PASS: statuses" timeout=900
scripts/db-test.sh statuses
```

This builds a throwaway PostgreSQL database, applies the migrations and proves that the status columns accept only the values of the state machine. `scripts/db-test.sh --list` names the other suites. With no PostgreSQL binaries and no Docker the script exits with code 3 and the word `BLOCKED`.

### 7. Run one job from a webhook to completion

```bash quickstart step=full-run needs=postgres expect="10 tests run: 10 passed" timeout=1500
cargo nextest run --locked -p factory-api --test full_run
```

This is the test `apps/api/tests/full_run.rs`. For the job `word-count` it does what the factory would do for a real issue:

1. It sends a signed webhook for a labelled issue to the API.
2. The worker's hook admits the job, and the engine runs all 13 stages with the real handler of each.
3. An approver approves the specification draft through the API, then the pull request.
4. The job ends `COMPLETED` with an evidence manifest, a documentation gate report and a pull request description stored.

The file holds ten tests: the whole run, a repeat that must agree with it, and eight deliberate breaks, each of which must be caught. The agents and the sandbox are scripted and labelled, and no step calls a model. The [walkthrough](../walkthroughs/test-mode-run.md) follows the same flow from the recordings.

### 8. See what the worker does with a real configuration

```bash quickstart step=worker-blocks needs=postgres expect="4 tests run: 4 passed" timeout=900
cargo nextest run --locked -p factory-worker --test prepare
```

One of these tests starts the real `factory-worker` binary against a private database. It checks that the binary passes its start-up checks, prints one `BLOCKED:` line for each adapter that does not exist yet and exits with code 3. A worker that claims no job is the honest state of the code today.

### 9. Judge a recorded end-to-end scenario

```bash quickstart step=e2e-judge needs=postgres expect="E7 PASSED" expect="SUMMARY: 1 passed, 0 failed, 0 blocked" timeout=1500
scripts/e2e.sh --scenario E7
```

Scenario E7 sends the same signed webhook 50 times and expects one job. The command runs the scenario and writes a new recording to `fixtures/recordings/e2e/E7`, then judges it. To judge the recording that is already committed without running anything, add `--judge-only`. After a real run, restore the committed recording with `git checkout -- fixtures/recordings/e2e/E7`.

### 10. Check the Docker-free part of the local stack

```bash quickstart step=compose-static needs=docker-cli expect="smoke: PASS"
scripts/smoke.sh --static
```

This reads the rendered Compose file and checks the network layout, the loopback ports, the image pins and the hardening. It needs the `docker` command and its Compose plugin. It does not need a running daemon.

### 11. Run the whole smoke test of the local stack (Docker)

```bash quickstart step=smoke needs=docker expect="smoke: PASS" timeout=1500
scripts/smoke.sh
```

This starts a throwaway copy of the local stack and probes its networks with the real sandbox image. It needs Docker, `psql`, the Diesel command line and the sandbox images.

## What you should see

- Steps 1 to 5 pass in a few minutes at most. Step 5 exits with code 3 and that is the expected result.
- Steps 6 to 9 pass when PostgreSQL 18 is installed. Step 7 reports `10 tests run: 10 passed`.
- Steps 10 and 11 pass when Docker is available.

Run `scripts/docs-check.sh --quickstart` to have every marked step run in a fresh clone. The check ends in `PASSED`, `FAILED` or `BLOCKED`. `BLOCKED` is the right answer on a machine without Docker: it says which steps could not run.

## When Docker is missing

Steps 1 to 10 do not need a running Docker daemon. These parts do:

- `scripts/smoke.sh`, `scripts/local-up.sh`, `scripts/restore-drill.sh`, `scripts/backup.sh` and `scripts/restore.sh`.
- `scripts/e2e.sh --check-fixture`, which builds and tests the fixture repository inside the pinned verify image. `--check-fixture-host` does the same on the host.
- The tests that start real containers, in the sandbox, runtime, egress and composition crates. When the daemon does not answer they stop with `BLOCKED: docker did not answer within 60s`. They are never counted as passed.
- `scripts/db-test.sh` when you have no local PostgreSQL binaries. It then falls back to a PostgreSQL container.

On the machine used to write this guide the Docker daemon did not answer, so steps 11 and the Docker tests were BLOCKED there. Nothing in this guide claims they passed.

## Troubleshooting

| You see | Why | What to do |
|---|---|---|
| `BLOCKED: no PostgreSQL server: set FACTORY_DB_ADMIN_URL, install PostgreSQL 16 or later, or start Docker`, exit code 3 | The script found no `initdb`, `pg_ctl` and `postgres`, and no Docker. | Install PostgreSQL 18, or set `FACTORY_PG_BIN` to the directory of its binaries. |
| `cargo nextest` is not found | `cargo-nextest` is not installed. | `cargo install cargo-nextest --version 0.9.137 --locked`. |
| `BLOCKED: the diesel CLI is not installed` | The Diesel command line is not installed. | Install version 2.3.11 as in the table above. |
| `waiting for the Docker lock` | Another script holds the machine-wide Docker lock. | Wait. The lock protects the shared pool of network addresses. |
| A test leaves a PostgreSQL process behind | A run was interrupted. | See the [troubleshooting page](../operations/troubleshooting.md) and the [runbook for leaked test clusters](../runbooks/leaked-test-clusters.md). |

## Next

- Read the [walkthrough](../walkthroughs/test-mode-run.md) to see what the stages did.
- Read the [command reference](../reference/commands.md) and the [configuration reference](../reference/configuration.md).
- Read the [production guide](production.md) before you plan a live run.
