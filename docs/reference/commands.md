# Command reference

- Status: checked against the built `factory-cli --help`, `apps/api/openapi.json` and the scripts' own `--help` output by `scripts/docs-check.sh --commands`. The check reads the command table, the endpoint table, the verb table and the exit code table below in both directions.
- Form: reference.
- Goal: list every program, command, option, endpoint, decision verb, exit code and script of the factory, with what each does.

## Programs

| Program | What it is | Takes |
|---|---|---|
| `factory-cli` | The operator command line. It talks to the API over HTTP. | Commands and options, below. |
| `factory-worker` | The worker. It runs the engine loop. | No option. One environment variable names the configuration file. |
| `factory-api` | The HTTP API. | No option. One environment variable names the configuration file. |
| `factory-egress-sidecar` | The relay that a sandbox uses to reach the model broker. The worker starts one for each job. | Options for the supervisor, below. |

The worker and the API read their settings from a YAML file. See the [configuration reference](configuration.md).

## The operator command line

The address of the API is the `--api` option or the `FACTORY_API_URL` environment variable. The token is read from the file that `--token-file` names. It is never read from an option or from the environment.

### Commands

| Command | Options | Arguments | What it does |
|---|---|---|---|
| `factory-cli health` | `--api` | none | Asks `GET /healthz`, then `GET /readyz`. Prints whether the API is running and ready. |
| `factory-cli submit` | `--api`, `--token-file`, `--repository`, `--text-file`, `--source-ref`, `--key` | none | Submits a request as a job in the state `RECEIVED`. `--repository` is the repository identifier, `--text-file` holds the request text, and `--source-ref` is `OWNER/NAME#N`. |
| `factory-cli status` | `--api`, `--token-file` | `JOB` | Shows the status of a job and its stage runs. |
| `factory-cli timeline` | `--api`, `--token-file` | `JOB` | Shows the state changes of a job and its audit records, in time order. |
| `factory-cli approve` | `--api`, `--token-file`, `--key` | `JOB STAGE_RUN head=H evidence=sha256:D [reason...]` | Records an approval. |
| `factory-cli reject` | `--api`, `--token-file`, `--key` | `JOB STAGE_RUN reason...` | Records a rejection. |
| `factory-cli rework` | `--api`, `--token-file`, `--key` | `JOB STAGE_RUN target=STAGE reason...` | Sends the work back to a stage. |
| `factory-cli pause` | `--api`, `--token-file`, `--key` | `JOB reason...` | Pauses a job. |
| `factory-cli resume` | `--api`, `--token-file`, `--key` | `JOB reason...` | Resumes a paused job. |
| `factory-cli cancel` | `--api`, `--token-file`, `--key` | `JOB reason...` | Cancels a job. |
| `factory-cli approve-dependency` | `--api`, `--token-file`, `--key`, `--stage-run` | `JOB NAME VERSION [CHECKSUM] reason...` | Approves one new direct dependency that the validation stage is waiting on. |
| `factory-cli approve-build-code` | `--api`, `--token-file`, `--key`, `--stage-run` | `JOB NAME VERSION [CHECKSUM] reason...` | Approves the build script or procedural macro of one package that the validation stage is waiting on. |
| `factory-cli probe` | `--protected-checkout`, `--images-catalog`, `--profile` | none | Runs the start-up checks that need no credential and lists what cannot be checked. |

`factory-cli help`, `factory-cli --help` and `factory-cli -h` print the usage text. With no command the usage goes to standard error and the exit code is 1.

### Options

| Option | Meaning |
|---|---|
| `--api` | The address of the API. HTTPS, or an address on this machine. An `http://` address to anything else, or an address with credentials in it, is refused before any request. |
| `--token-file` | A regular file, not a symbolic link, readable by its owner only. It holds the bearer token. |
| `--key` | The idempotency key, 1 to 128 characters. Without it the command makes a random one. A retry with the same key repeats nothing. |
| `--repository` | The identifier of a repository registered for the caller's tenant. A UUID. |
| `--text-file` | A file with the request text. The command reads at most 200 KiB. |
| `--source-ref` | The issue the job is for, written `OWNER/NAME#N`. The repository must be the one that `--repository` names. |
| `--stage-run` | The stage run of a dependency decision. Without it the decision is for the blocked validation stage run of the job. |
| `--protected-checkout` | The checkout of the protected configuration branch, for `probe`. |
| `--images-catalog` | The sandbox image catalog, for `probe`. Without it `probe` reports the catalog as BLOCKED. |
| `--profile` | `production`, `local` or `test`, for `probe`. |

The identifiers `JOB` and `STAGE_RUN` are UUIDs. A word that is not a UUID is not sent.

### The words after the identifiers

A decision uses one grammar in every channel: the command line, a pull request comment that starts with `/factory ` and a dashboard form. One function reads all three.

```text
/factory <verb> [head=<40 or 64 hex digits>] [evidence=<sha256:...>] [target=<STAGE>] [reason text]
```

The `key=value` words come first. The first word that is not a known `key=value` pair starts the reason. A key given twice is an error. A reason has at most 2000 bytes. The decision verbs `merge`, `deploy`, `ready` and `undraft` do not exist. A comment or command that uses one is refused.

### Decision verbs

| Verb | Who may take it | Needs | Effect once the worker applies it |
|---|---|---|---|
| `approve` | `approver` | `head`, `evidence` | Approves the specification draft or the pull request. Bound to the head and the ledger entry the person saw. |
| `reject` | `approver` | a reason | Rejects what the stage run waits on. |
| `rework` | `approver` | `target`, a reason | Sends the work back to the named stage. |
| `pause` | `operator` | a reason | Pauses the job. |
| `resume` | `operator` | a reason | Resumes the job. |
| `cancel` | `operator` | a reason | Cancels the job. |
| `approve-dependency` | `approver` | package, version, a reason of 10 to 500 characters | Lets one new direct dependency pass the supply chain gate. |
| `approve-build-code` | `security_approver` | package, version, a reason of 10 to 500 characters | Lets the build code of one package run. |

The role is a designation on the protected allowlist. A GitHub role never grants one. The API records the decision and answers `202` with `"applied": false`. The worker applies it once, and the job timeline then shows `decision.applied` or `decision.rejected`.

### Exit codes of the command line

| Exit code | Name | Meaning |
|---|---|---|
| `0` | done | The command did what it was asked. |
| `1` | not understood | The command was not understood, or a local check failed: a bad identifier, a token file that others can read, a `FAILED:` line of `probe`. |
| `2` | refused | The API answered with a 4xx status. |
| `3` | blocked | The API is not ready or asked to try later (429 or 5xx), or `probe` found something it cannot check. |
| `4` | unreachable | No connection, or no answer within 30 seconds. |

### What `probe` prints

Each line starts with `OK:`, `FAILED:` or `BLOCKED:`. `probe` checks the policy from the protected checkout, the redactor built from it and the image catalog. It then prints one `BLOCKED:` line for each agent runtime and each adapter or seam method it cannot check, and exits with code 3. A `BLOCKED:` line is never a pass.

### Try it

These two blocks are run by `scripts/docs-check.sh --snippets`. The first prints the usage text of the command line. The second lists the end-to-end scenarios and shows which ones need real adapters.

```bash run expect="usage: factory-cli <command> [options]" expect="approve-build-code"
cargo run --quiet --locked -p factory-cli -- --help
```

```bash run timeout=600 expect="E1   real adapters" expect="E7   test mode with labelled fakes"
scripts/e2e.sh --list
```

## The worker

```text
FACTORY_CONFIG=/etc/factory/worker.yaml factory-worker
```

| Code | Meaning |
|---|---|
| `0` | A clean stop. |
| `1` | An engine error, or a start-up check failed. |
| `2` | The configuration was refused, or `FACTORY_CONFIG` is not set. |
| `3` | BLOCKED. One `BLOCKED:` line on standard error for each adapter or input this build cannot assemble. |
| `4` | An attempt was abandoned at the end of the drain budget. The lease expires and the next worker's sweep marks the attempt lost. |

### The BLOCKED lines of the worker

After the start-up checks pass, the worker prints these lines on standard error and exits with code 3. It claims no job. A line has the form `BLOCKED: <name>: <reason>`.

| Worker line | Why it is blocked |
|---|---|
| `BLOCKED: agent runtime` | A live run needs a model credential and the agent tool in the agent image. |
| `BLOCKED: model router` | `policies/model_routing.yaml` does not exist, so there is no router to read it. |
| `BLOCKED: issue source` | The GitHub issue source needs a registered GitHub App and its private key. |
| `BLOCKED: change host` | The GitHub change host needs a registered GitHub App and its private key. |
| `BLOCKED: RegistryMetadata` | No adapter asks the package registry about a package. The blocked adapter answers unknown, so every new direct dependency goes to a security approver. |
| `BLOCKED: AdvisoryDatabase` | No adapter reports the date of the advisory database. The advisories gate is BLOCKED. |
| `BLOCKED: CapabilityProbes` | The capabilities of a runtime are probed when the runtime exists, and the runtime is blocked. |

The last line reads `BLOCKED is not a pass: the start-up checks passed, and no job was claimed.`

## The API server

```text
FACTORY_CONFIG=/etc/factory/api.yaml factory-api
```

| Code | Meaning |
|---|---|
| `0` | A clean stop. Open requests get `limits.drain_s` seconds to finish. |
| `1` | A start-up check failed, or the listener could not bind. |
| `2` | The configuration was refused, or `FACTORY_CONFIG` is not set. |

### Endpoints

The contract is [`apps/api/openapi.json`](../../apps/api/openapi.json). The server also serves it on `GET /openapi.json`. There is no endpoint that merges or deploys.

| Endpoint | Auth | Role | What it does |
|---|---|---|---|
| `GET /healthz` | none | none | Liveness. The process is running. It never reads the database. |
| `GET /readyz` | none | none | Readiness. It answers 503 when any check fails or could not run, including a database that is behind the code. |
| `GET /openapi.json` | none | none | The API contract. |
| `POST /v1/jobs` | bearer token | `requester` | Stores a request as a `RECEIVED` job. Needs an `Idempotency-Key` header. The same key and request finds the first job with 200. The same key and another request is 409. |
| `GET /v1/jobs` | bearer token | any designation | The jobs of the caller's tenant, newest first. |
| `GET /v1/jobs/{job_id}` | bearer token | any designation | The status of a job and of its stage runs. |
| `GET /v1/jobs/{job_id}/timeline` | bearer token | any designation | The state changes and audit records of a job, in time order. |
| `POST /v1/jobs/{job_id}/decisions` | bearer token | by verb | Records a decision of a person. Needs an `Idempotency-Key` header. |
| `POST /v1/webhooks/github` | HMAC-SHA256 of the raw body | none | A GitHub delivery. Verified on the raw body before anything is parsed. |

The fields of a decision request are `verb`, `stage_run_id`, `head`, `evidence`, `target`, `reason`, `package`, `version` and `checksum`. The OpenAPI document says which verb needs which field.

### Statuses

| Status | Meaning |
|---|---|
| 200, 201, 202 | Done. 201 is a new job. 200 is the job an earlier request with the same key made. 202 is a recorded decision or an accepted webhook. |
| 400 | The request is not valid. The answer names the field. |
| 401 | No usable credential. One answer, with the same bytes, for every reason. |
| 403 | Known, and not permitted. The answer gives no reason. |
| 404 | No such route or object. Another tenant's object has this answer too. |
| 408, 413, 415 | The body was too slow, too large, or not `application/json`. |
| 409 | The request conflicts with a recorded one. |
| 429 | A rate limit is exceeded. A `Retry-After` header comes with it. |
| 503 | The service cannot answer now. |

After a valid signature the webhook endpoint answers `202` with the same body for a new delivery, a repeat, an unknown installation and an event the factory does not act on.

## The egress sidecar

```text
factory-egress-sidecar --mode broker  --listen ADDR:PORT --upstream IP:PORT [--max-bytes N] [--job ID]
factory-egress-sidecar --mode connect --listen ADDR:PORT --allow HOST:PORT ... [--max-bytes N] [--job ID]
```

The worker's supervisor builds this command line. A person does not start the sidecar. The options are `--mode`, `--listen`, `--upstream`, `--allow`, `--max-bytes`, `--max-connections`, `--connect-timeout-secs`, `--idle-timeout-secs`, `--deny-range` and `--job`. A command line the program does not understand ends it with exit code 2 before it listens. A listener that cannot bind ends it with exit code 1. The [sidecar README](../../apps/egress-sidecar/README.md) has the details.

## Scripts

Every script prints its usage with `--help` and ends with these codes: `0` done, `1` failed, `2` wrong arguments, `3` BLOCKED. BLOCKED means a prerequisite is missing, so nothing was verified.

| Script | What it does | Needs |
|---|---|---|
| `scripts/ci.sh` | Runs every check of the repository. `--list` shows the steps and `--only ID` runs some of them. | the tools of each step |
| `scripts/db-test.sh` | Builds a throwaway PostgreSQL database, runs the migrations and proves the schema rules. `--list` names the suites. | PostgreSQL 18 binaries or Docker, `psql`, the pinned Diesel CLI |
| `scripts/e2e.sh` | The end-to-end harness. `--list` names the scenarios, `--scenario ID` runs one, `--check-readability PATH` runs the readability gate. | `cargo`, and PostgreSQL for the scenarios |
| `scripts/docs-check.sh` | Checks these documents. | `python3`, `cargo` |
| `scripts/dev-up.sh` | Starts PostgreSQL alone for development. | Docker |
| `scripts/local-up.sh` | Starts the local stack: PostgreSQL 18 and the artifact volume. | Docker, `psql`, the Diesel CLI |
| `scripts/smoke.sh` | Starts a throwaway copy of the local stack and checks it. `--static` needs no running daemon. | Docker |
| `scripts/backup.sh` | Backs up the database and the artifact directory of a running local stack. | Docker |
| `scripts/restore.sh` | Restores a backup into a fresh local stack and verifies it. `--backup DIR` names the backup. | Docker |
| `scripts/restore-drill.sh` | Proves that a backup restores, on a throwaway stack. | Docker |
| `scripts/db-perf.sh` | Measures the hot queries at volume. | PostgreSQL |
| `scripts/db-compat-rust.sh` | Runs the storage crate as written for an earlier schema against the latest one. | PostgreSQL |

## Repository tools

`cargo xtask` runs the architecture and document checks. Each command exits with 0 when everything holds, 1 when it found something and 2 when it could not run.

| Command | What it checks |
|---|---|
| `cargo xtask check-architecture` | The crate dependency rules and the source scans. |
| `cargo xtask check-links` | Every relative link in the Markdown files, and the heading it names. |
| `cargo xtask check-invariants` | Every state machine invariant has a named test. |
| `cargo xtask check-generated` | Generated files match their sources. |
| `cargo xtask clippy-toml` | Prints the ban list for the inner crates. |
