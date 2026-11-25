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
| `factory-cli status` | `--api`, `--token-file`, `--gates` | `JOB` | Shows the status of a job and its stage runs. With `--gates`, it then lists the gate reports of the job: the stage, the gate, the outcome, the block code and the hash of each report. |
| `factory-cli show-draft` | `--api`, `--token-file`, `--stage-run` | `JOB` | Shows the specification draft a person is asked to approve: the commit that holds it, the head of the ledger, the draft document and the values to give as `head=` and `evidence=`. When the stage asked questions, it lists them and prints the `answer` command that answers them. |
| `factory-cli artifact` | `--api`, `--token-file` | `JOB SHA256` | Prints one stored document of a job, for example a gate report, through the same sanitizer as every other output. A document that is not text is not printed. |
| `factory-cli timeline` | `--api`, `--token-file` | `JOB` | Shows the state changes of a job and its audit records, in time order. |
| `factory-cli approve` | `--api`, `--token-file`, `--key`, `--confirm` | `JOB STAGE_RUN head=H evidence=sha256:D [reason...]` | Records an approval. |
| `factory-cli reject` | `--api`, `--token-file`, `--key` | `JOB STAGE_RUN reason...` | Records a rejection. |
| `factory-cli rework` | `--api`, `--token-file`, `--key` | `JOB STAGE_RUN target=STAGE reason...` | Sends the work back to a stage. |
| `factory-cli answer` | `--api`, `--token-file`, `--key` | `JOB STAGE_RUN text...` | Answers the questions of a stage run that waits for a person. A word `Q-001:` starts a new line, so `Q-001: yes Q-002: no` answers two questions. Put `--` before the text when it holds a word that starts with `--`. |
| `factory-cli pause` | `--api`, `--token-file`, `--key` | `JOB reason...` | Pauses a job. |
| `factory-cli resume` | `--api`, `--token-file`, `--key` | `JOB reason...` | Resumes a paused job. |
| `factory-cli cancel` | `--api`, `--token-file`, `--key` | `JOB reason...` | Cancels a job. |
| `factory-cli unblock` | `--api`, `--token-file`, `--key` | `JOB STAGE_RUN reason...` | Lets a `BLOCKED` stage run go again once the cause is gone. |
| `factory-cli ack-translation-warning` | `--api`, `--token-file`, `--key`, `--confirm` | `JOB STAGE_RUN WARNING reason...` | Records an approver's decision about one open translation warning of the approval request. `WARNING` is its number, from 1. |
| `factory-cli approve-project-build-code` | `--api`, `--token-file`, `--key`, `--stage-run`, `--confirm` | `JOB PATH SHA256 reason...` | Approves one file of build code that the change itself adds, with the exact content the person read. |
| `factory-cli approve-dependency` | `--api`, `--token-file`, `--key`, `--stage-run`, `--confirm` | `JOB NAME VERSION [CHECKSUM] reason...` | Approves one new direct dependency that the validation stage is waiting on. |
| `factory-cli approve-build-code` | `--api`, `--token-file`, `--key`, `--stage-run`, `--confirm` | `JOB NAME VERSION [CHECKSUM] reason...` | Approves the build script or procedural macro of one package that the validation stage is waiting on. |
| `factory-cli repository` | `--api`, `--token-file`, `--key`, `--installation`, `--github-repository`, `--name`, `--default-branch`, `--single-maintainer`, `--wait-seconds` | `register`, `confirm-map`, `enable`, `disable`, `show` or `change`, then its own arguments (see below) | Registers a repository, records that a person confirmed its project map, enables it, disables it, or shows it. The subcommands are in the table after the options. |
| `factory-cli metrics` | `--api`, `--token-file`, `--from`, `--to` | `snapshot` | Prints the measurement entry of the process numbers of the caller's tenant over the window from `--from` to before `--to`, each a UTC instant such as `2026-11-16T00:00:00Z`, compared with the window of the same length right before it ([process metrics](../architecture/process-metrics-and-improvement.md), section "How a person asks for a snapshot"). It stores nothing. |
| `factory-cli probe` | `--protected-checkout`, `--images-catalog`, `--profile` | none | Runs the start-up checks that need no credential and lists what cannot be checked. |

`factory-cli help`, `factory-cli --help` and `factory-cli -h` print the usage text. With no command the usage goes to standard error and the exit code is 1.

### Options

| Option | Meaning |
|---|---|
| `--api` | The address of the API. HTTPS, or an address on this machine. An `http://` address to anything else, or an address with credentials in it, is refused before any request. |
| `--token-file` | A regular file, not a symbolic link, readable by its owner only. It holds the bearer token. |
| `--key` | The idempotency key, 1 to 128 characters. Without it the command makes a random one. A retry with the same key repeats nothing. |
| `--repository` | The identifier of a repository registered for the caller's tenant. A UUID. |
| `--text-file` | A file with the request text. The command reads at most 200 KiB. The text must be the title of the issue that `--source-ref` names, a blank line, and its body, as GitHub shows them when the factory starts the job. The factory ignores only the style of the line ends and white space around the whole text. If it differs in any other way, the job is refused at intake with the reason `text_not_the_issue` and nobody can override that. Put a note in the body of the issue, not in this file. |
| `--source-ref` | The issue the job is for, written `OWNER/NAME#N`. The repository must be the one that `--repository` names. |
| `--stage-run` | The stage run of a dependency or build code decision, or of `show-draft`. Without it a decision is for the blocked validation stage run of the job, and `show-draft` takes the newest specification stage run. |
| `--gates` | With `status`: also list the gate reports of the job. |
| `--confirm` | With `approve`, `approve-dependency`, `approve-build-code`, `approve-project-build-code` and `ack-translation-warning`: the confirmation phrase of the solo mode ([ADR 0022](../adr/0022-solo-approval-mode.md)), quoted as one argument, such as `--confirm "I confirm the solo approval of PR 7 at level high"`. The person who asked for the job and is its only approver sends it for a high or critical pull request and for every decision on a dependency, on build code or on a translation warning. Spaces at the ends, runs of spaces and capital letters of the plain Latin alphabet do not matter. The API keeps only a 16-digit hash of it. Without it, or with another, the API answers `409 confirmation_missing` and the command prints the phrase to send. |
| `--protected-checkout` | The checkout of the protected configuration branch, for `probe`. |
| `--images-catalog` | The sandbox image catalog, for `probe`. Without it `probe` reports the catalog as BLOCKED. |
| `--profile` | `production`, `local` or `test`, for `probe`. |
| `--installation` | With `repository register`: the number of the GitHub App installation that covers the repository. A positive whole number. |
| `--github-repository` | With `repository register`: GitHub's numeric identifier of the repository. A positive whole number. One GitHub repository can be registered once in the whole factory. |
| `--name` | With `repository register`: the repository's name, written `OWNER/NAME`. |
| `--default-branch` | With `repository register`: the name of the default branch. Without it, `main`. |
| `--wait-seconds` | With `repository register`, `confirm-map` and `enable`: how long to wait for the worker to apply the request, a whole number of seconds from 0 to 600. Without it, 60. With 0 the command sends the request, prints its id and does not wait. |
| `--single-maintainer` | With `repository register`: a switch with no value (`--single-maintainer=false` is the default). The person who confirms the project map may also enable the repository. Only for a project owner who works alone. It is written at registration, recorded in the audit log, and cannot be changed afterwards. The API refuses it with the code `single_maintainer_not_allowed` unless the tenant has exactly one active person who holds the designations of the project map and of the enable. |

The identifiers `JOB` and `STAGE_RUN` are UUIDs. A word that is not a UUID is not sent.

### The repository subcommands

A repository takes tickets only after a person has registered it, confirmed its project map and enabled it. The [onboarding guide](../guides/onboarding.md) walks through the order. Each subcommand that changes something takes `--key`, and a retry with the same key and the same words repeats nothing.

`register`, `confirm-map` and `enable` are **requests that the worker applies** (finding REG-2). The API records one signed request and answers `202`; the command then waits for the worker, up to `--wait-seconds`, and prints the repository when it was applied. The exit codes are: 0 applied, 2 refused (by the API at once, or by the worker later, with a code such as `not_permitted`, `conflict`, `enabler_is_attestor`, `expired` or `disabled_since_request`), 3 the worker had not applied it within the wait (the request stays; look again with `change`), 4 unreachable. `disable` is direct and answers at once.

| Subcommand | Arguments | Who may run it | What it does |
|---|---|---|---|
| `register` | `--installation`, `--github-repository`, `--name`, optionally `--default-branch` and `--single-maintainer` | `operator` | Registers the repository. It starts disabled, at autonomy level `L0`, with no project map, under the strict rule (the person who enables it is not the person who confirmed the map) unless `--single-maintainer` is given. Prints its identifier. |
| `confirm-map` | `REPOSITORY COMMIT reason...` | `operator` | Records that the person attests that `COMMIT` (40 lowercase hexadecimal characters) of the default branch holds the project map. The reason has 10 to 500 characters. This is a statement by a person: the engine holds no GitHub credential, does not read the repository and does not check the commit. |
| `enable` | `REPOSITORY COMMIT [reason...]` | `approver` | Lets the repository take tickets, for the map at `COMMIT`, the commit you read. Refused with the code `project_map_not_attested` until a map was confirmed. Refused with the code `project_map_changed` when `COMMIT` is not the commit confirmed now. Refused with the code `enabler_is_attestor` when you confirmed the map and the repository is not a single-maintainer one. A repository that is enabled already is answered at once ("Nothing changed") and no second approver is recorded. |
| `disable` | `REPOSITORY [reason...]` | `operator` | Stops the repository from taking tickets. Its webhooks are dropped and no job can be submitted for it. Existing jobs are not touched: they run on, and their issue keeps its last label. To stop one, cancel it. |
| `change` | `REQUEST` | any designation | Prints where a request to register, confirm or enable stands: `requested`, `applied`, or `refused` with the code. `REQUEST` is the id the change printed. |
| `show` | `REPOSITORY` | any designation | Prints the repository: whether it is enabled and for which map commit, the rule about the enabler, whether it is open for new jobs (an enabled repository whose attestor or enabler is no longer an active human is not), its autonomy ceiling, its version and the attestation of its map. |

After the worker applies `register` or `enable`, it also checks the project's rules for agents and opens a draft pull request that installs or updates `AGENTS.md` when the project needs one. The command does not wait for that pull request, and its exit code does not depend on it. See [the project's rules for agents](../architecture/project-rules.md).

The `REPOSITORY` argument is the identifier that `register` printed. Confirming a map again on an enabled repository switches it off, and you enable it again with the new commit. A reason on `enable` or `disable` is optional and, when given, has 10 to 500 characters. The role is a designation on the protected allowlist, read from the `actions` table of `policies/approval.yaml`: `register_repository`, `confirm_project_map`, `enable_repository` and `disable_repository`. These four are a default that is pending confirmation by the architect. See the architecture decision record (ADR) [0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md).

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
| `answer` | `requester` (of that job), `operator`, `approver` or `org_admin` (`answer_question`) | `stage_run_id`, the text (1 to 900 bytes, one line `Q-001: ...` per question; a text with no such line answers the first question) | Gives the text to the waiting stage run as a new input, and the stage runs again (transition S13). It decides no gate and never raises a budget ceiling. A pull request or issue comment does not take this verb. |
| `pause` | `operator` | a reason | Pauses the job. |
| `resume` | `operator` | a reason | Resumes the job. |
| `cancel` | `operator` | a reason | Cancels the job. |
| `unblock` | `operator` | `stage_run_id`, a reason of 10 to 500 characters | Lets a `BLOCKED` stage run go again (transition S17) when the engine finds the block cleared: a decision for what the run waited for was recorded after the attempt that blocked it, or a capability re-probe passes. It passes no gate and is not an override. |
| `approve-dependency` | `approver` | package, version, a reason of 10 to 500 characters | Lets one new direct dependency pass the supply chain gate. |
| `approve-build-code` | `security_approver` | package, version, a reason of 10 to 500 characters | Lets the build code of one package run. |
| `ack-translation-warning` | `approver` | `stage_run_id` (the approval stage run), `warning` (from 1), a reason of 10 to 500 characters | Decides about one open warning of the documentation reviewer's rule `translation-unfaithful`. The approval of the pull request counts only the decisions of the person who approves, for the request they saw. |
| `approve-project-build-code` | `security_approver` | `path`, `digest` (12 to 64 lower case hex digits of the SHA-256 of the file), a reason of 10 to 500 characters | Lets one file of build code that the change adds run, bound to its path and to the hash of its content. A script that is edited afterwards needs a new decision. |

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

After the start-up checks pass, the worker builds its adapters for the outside world from the configuration. For each one the configuration does not supply, it prints a line on standard error and exits with code 3. It claims no job. A line has the form `BLOCKED: <name>: <key>: <reason>`, and `<key>` is the configuration key to write (see the [configuration reference](configuration.md)). A worker with a complete configuration prints none of these lines and runs the loop.

| Worker line | Why it is blocked |
|---|---|
| `BLOCKED: agent runtime` | `broker.upstreams` lists no provider, so there is no agent tool to run. |
| `BLOCKED: model router` | `broker.upstreams` lists no provider, or enables a model that `policies/model_routing.yaml` does not list for it. |
| `BLOCKED: issue source` | `github` is not set, `github.installations` is empty, or the key file or the API address is unusable. |
| `BLOCKED: change host` | The same keys as the issue source: both ports come from the one GitHub App. |
| `BLOCKED: RegistryMetadata` | `registry.base_url` is not set, or in production its host is not one the egress policy lists for the cargo ecosystem. |
| `BLOCKED: AdvisoryDatabase` | `advisory_database.date_file` is not set. |
| `BLOCKED: CapabilityProbes` | The runtimes could not be probed: the Docker daemon does not answer, the agent image is not on the host, or `worker.tenants` is empty. In the local and test profiles `runtimes.declare_capabilities` takes a declared list instead. |

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
| `POST /v1/jobs` | bearer token | `requester` | Stores a request as a `RECEIVED` job. Needs an `Idempotency-Key` header. The same key and request finds the first job with 200. The same key and another request is 409. The `text` must be the title, a blank line and the body of the issue that `source_ref` names; the API cannot check that, so intake refuses a job whose text is not the live issue's (`text_not_the_issue`). |
| `GET /v1/jobs` | bearer token | any designation | The jobs of the caller's tenant, newest first. |
| `GET /v1/jobs/{job_id}` | bearer token | any designation | The status of a job and of its stage runs. |
| `GET /v1/jobs/{job_id}/timeline` | bearer token | any designation | The state changes and audit records of a job, in time order. |
| `GET /v1/jobs/{job_id}/specification-draft` | bearer token | any designation | The draft a person is asked to approve: the commit that holds it, the head of the ledger, the hash of the draft document and the facts of the approval window. Optional query `stage_run_id`. 503 without an artifact root in the configuration. |
| `GET /v1/jobs/{job_id}/gate-reports` | bearer token | any designation | The gate reports the engine wrote into the ledger of the job, at most 200: the stage, the gate, the outcome, the block code and the hash of each. 503 without an artifact root in the configuration. |
| `GET /v1/jobs/{job_id}/artifacts/{sha256}` | bearer token | any designation | One stored document of the job, as an attachment of at most 4 MiB under `text/plain; charset=utf-8` or `application/octet-stream`, with `X-Content-Type-Options: nosniff`. 404 for a hash that is not one of the job's documents, and for another tenant's. 413 over the cap. |
| `POST /v1/jobs/{job_id}/decisions` | bearer token | by verb | Records a decision of a person. Needs an `Idempotency-Key` header. |
| `GET /v1/process-metrics/snapshot` | bearer token | any designation | The measurement entry of the process numbers of the caller's tenant over the window of the queries `from` and `to` (UTC instants, `to` after `from`, at most 366 days apart), with the window before it. It holds totals and medians only and stores nothing. 400 naming the field for a window that cannot be read. 503 when the build does not know the commit it was made from (`FACTORY_BUILD_COMMIT`). |
| `POST /v1/repositories` | bearer token | `operator` | Asks to register a repository, as a signed request that the worker applies (finding REG-2). It will start disabled, at level `L0`, with no project map. The optional body member `single_maintainer` (default false) is written here and never after. Needs an `Idempotency-Key` header. 202 with a `request_id`; 202 with `changed` false for the request an earlier call with the same key made; 409 for another request under the key. A GitHub repository that is already registered is refused by the worker with the code `conflict`. 409 at once with the code `single_maintainer_not_allowed` for `single_maintainer: true` in a tenant that does not have exactly one active person who holds the designations. |
| `GET /v1/repositories/{repository_id}` | bearer token | any designation | One repository of the caller's tenant, with the rule about the enabler, whether its people still stand (`standing`), the attestation of its project map and what it was enabled for. Another tenant's repository, and one that the caller's allowlist entry is narrowed away from, have the answer of a missing one. |
| `POST /v1/repositories/{repository_id}/project-map` | bearer token | `operator` | Asks to record the commit that holds the project map and the reason, as a signed request that the worker applies: 202. An attestation by a person: the engine does not read the repository. Needs an `Idempotency-Key` header. |
| `POST /v1/repositories/{repository_id}/enable` | bearer token | `approver` | Asks to enable the repository for the map commit named in the body, as a signed request that the worker applies: 202. 409 at once with the code `project_map_not_attested` until a map was attested, with `project_map_changed` when the commit is not the one attested now, and with `enabler_is_attestor` when the caller attested the map of a repository that was not registered as a single-maintainer one. Needs an `Idempotency-Key` header. |
| `POST /v1/repositories/{repository_id}/disable` | bearer token | `operator` | Disables the repository, directly and at once (200): switching off only narrows. Needs an `Idempotency-Key` header. |
| `GET /v1/repository-changes/{request_id}` | bearer token | any designation | Where a request to register, attest or enable stands: `requested`, `applied`, or `refused` with a fixed `code`. The answer holds no text of the request. A request of another tenant has the answer of a missing one. |
| `POST /v1/webhooks/github` | HMAC-SHA256 of the raw body | none | A GitHub delivery. Verified on the raw body before anything is parsed. |

The change to a repository and its audit record are written in one transaction. A caller without the designation gets 403 with no reason, and the attempt is audited. The four actions are `register_repository`, `confirm_project_map`, `enable_repository` and `disable_repository` in the `actions` table of the approval policy.

The fields of a decision request are `verb`, `stage_run_id`, `head`, `evidence`, `target`, `reason`, `package`, `version`, `checksum`, `path`, `digest` and `warning`. The OpenAPI document says which verb needs which field.

### Statuses

| Status | Meaning |
|---|---|
| 200, 201, 202 | Done. 201 is a new job. 200 is the job an earlier request with the same key made. 202 is a recorded decision or an accepted webhook. |
| 400 | The request is not valid. The answer names the field. |
| 401 | No usable credential. One answer, with the same bytes, for every reason. |
| 403 | Known, and not permitted. The answer gives no reason. |
| 404 | No such route or object. Another tenant's object has this answer too. |
| 408, 413, 415 | The body was too slow, too large, or not `application/json`; or, for a download, the document is larger than 4 MiB. |
| 409 | The request conflicts with a recorded one. For a repository it also means that the GitHub repository is already registered, or, with the code `project_map_not_attested`, that a repository cannot be enabled before a person attested its project map, or, with the code `project_map_changed`, that the map was attested again since the approver read it. |
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
| `scripts/worker-host.sh` | Runs the worker on the host beside the local stack, so it can start sandboxes (ADR 0036). `--check` prepares and checks without starting; `--setcap` gives the program `cap_chown` on Linux. | Docker, `cargo`, `uv`, the local stack |
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
