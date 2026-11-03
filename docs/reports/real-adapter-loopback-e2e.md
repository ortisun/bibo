# The real adapters on loopback fakes: an end-to-end run, judged from outside

- Status: written by the software engineer after running the tests named below on one machine (macOS, Docker 29.9.2 with no `factory-sandbox` image, a private PostgreSQL cluster). Nothing here was reviewed by anyone else yet.
- Form: reference.
- Goal: say what a worker started from a configuration file does when GitHub, the model providers and the registry are loopback fakes, where that differs from the runs that use test doubles, what failed or looks wrong, and what none of this proves.

## What was built

| File | What it is |
|---|---|
| [`apps/worker/tests/support/loopback.rs`](../../apps/worker/tests/support/loopback.rs) | The rig. It makes a tenant, a repository and two people (a requester and an approver) in a real PostgreSQL, a protected checkout (a copy of `policies/`, `.specify/` and the Spec Kit skills, plus an allowlist file), FX-GH of the test kit on the system clock, a refusing model-provider server and a refusing registry server, and the configuration file that points every external endpoint at them. It starts the `factory-worker` binary on that file, and it can write the rows the API's webhook handler writes. Every credential is made when the test runs. |
| [`apps/worker/tests/loopback_e2e.rs`](../../apps/worker/tests/loopback_e2e.rs) | The scenarios that start the binary: the design gate (an issue without approval, one approved by a person who is not an approver, one approved by an approver, one off the design track), transient GitHub failures, a refusal with the log filter at `trace`, the real start-up probe, and the deliberate breaks. The judgments are pure functions of what the run left, so each break runs the same judgment on a damaged wiring or on doctored evidence. |
| [`apps/worker/tests/loopback_status.rs`](../../apps/worker/tests/loopback_status.rs) | The status write-back: one job from `ACTIVE` through a wait for a person to `COMPLETED`, written on its issue through the real GitHub adapter, and three deliberate breaks. |
| `apps/worker/tests/support/deployment.rs`, `mod.rs` | `deployment_in`, which lets a test name its own protected checkout. |

The base is commit `3f3f205` of `feat/slice-0-foundation`. The design gate code (`judge_design`, the re-check at delivery) is used as it is on that commit and was not touched. The scenarios of the gate would need a second look if the work that changes it lands.

### How to run it

```text
cargo nextest run -p factory-worker --test loopback_e2e --test loopback_status --no-fail-fast
cargo nextest run -p factory-worker --run-ignored only --test loopback_e2e      # needs the images: BLOCKED here
cargo nextest run -p factory-api --run-ignored only --test live_run             # the whole job: BLOCKED here
```

## What was run, and the result

The first two commands above, on this machine. The third was run once to see the `BLOCKED:` lines. `FINAL-COUNTS` below is filled in from the last run.

| Command | Passed | Failed | Blocked | Ignored |
|---|---|---|---|---|
| `cargo nextest run -p factory-worker --test loopback_e2e --test loopback_status --no-fail-fast` | FINAL-PASSED | 0 | 0 | 1 |
| `cargo nextest run -p factory-worker --run-ignored only --test loopback_e2e` | 0 | 0 | 1 (`BLOCKED: the image factory-sandbox/verify@sha256:5ec059bc... is not on this host`) | 0 |
| `cargo nextest run -p factory-api --run-ignored only --test live_run --no-fail-fast` | 0 | 0 | 4 (each ends `BLOCKED: the image factory-sandbox/verify@sha256:5ec059bc... is not on this host (images are never pulled)`) | 0 |

A `BLOCKED:` panic makes the test fail in nextest's count. It is shown here as blocked because that is what it says, and none of them is a pass.

## What the run showed

### An issue on the design track without approval (the real path, no sandbox)

The worker admitted the job, read the issue through the real GitHub adapter, refused it, posted one comment and blocked the job. From the fake GitHub, the requests were exactly these routes and counts:

```text
GET  /app                                       1
POST /app/installations/{id}/access_tokens      2
GET  /repos/{owner}/{repo}                      1
GET  /repos/{owner}/{repo}/issues/{number}      4   (one 200, three 304)
GET  /repos/{owner}/{repo}/issues/{number}/events 2
GET  /repos/{owner}/{repo}/issues/{number}/comments 1
POST /repos/{owner}/{repo}/issues/{number}/comments 1
DELETE /installation/token                      1
```

- **Labels.** Unchanged: `factory`, `design: in review`. No `factory: <state>` label and no status comment (finding STS-1: a job that intake refuses gets nothing).
- **Comment.** One, the fixed refusal text with its marker, naming no person.
- **Tokens.** Two. The read token asked for `contents`, `issues`, `metadata` and `pull_requests`, all `read`, for the one repository `word-count`. The write token asked for `issues: write` and `metadata: read` only, and was revoked at once. Neither held a permission the security policy forbids.
- **Job.** `BLOCKED`, with the `INTAKE` stage run `BLOCKED` (gate outcome `BLOCKED`) and the other twelve `PENDING`.
- **Events.** `job.admitted`, `stage_run.ready`, `stage_run.started`, `attempt.running`, `attempt.succeeded`, `stage_run.gating`, `stage_run.blocked` (reason code `policy-violation`), `job.blocked`. Every audit and outbox row of the job carries the job's correlation id.
- **Ledger.** Four entries, all written by `workflow.engine` with fidelity `real`, and the chain and the head verify.
- **Audit.** `authorization_decision.denied`: "design gate refused (DESIGN_NOT_APPROVED): ... reason not_approved; design labels seen [`design: in review`]; approved label applied by user id none; ... reply posted".
- **Model providers and registry.** No request reached either fake.
- **Credentials.** The sweep looked at the worker's output, ten tables, the artifact store, everything the fake GitHub received and the comment text, for every token the fake minted, the App key, the provider key, the decision key and the database passwords. It found none, at the default log level and at `trace`.
- **Stop.** The worker exits with code 0 on SIGTERM.

### The same issue approved by an approver

The gate passes: the audit says "design gate passed: ... the approved label was applied by user id 1002, who holds the approver designation". The stage goes on to the router (which picks a model for `INTAKE` from the routing policy) and to the sandbox. There the real Docker adapter finds the agent image missing and the attempt ends `Failed { class: SandboxError, then: Block(ImageUnavailable) }`: the stage run and the job are `BLOCKED`, the audit says "sandbox not created; profile agent; the image is not on this host", and the attempt row has `failure_class = SANDBOX_ERROR`. Nothing is written on the issue and nothing reaches a provider. In the test the agent image is made absent on purpose (a copy of the catalog with a digest no host has), so the result does not depend on the images of the machine.

An approval by someone the allowlist lists only as a requester is refused with `not_applied_by_an_approver`, and one by an approver the allowlist does not list is refused the same way.

### Transient GitHub failures

With a 502 on the first token request, a 429 with `Retry-After: 1` on the first read of the issue and a 502 on the first comment post, the adapter retried the first two inside the call. The failed post failed the attempt (`Failed { class: ToolError, then: Retry }`), the engine ran it again, and the person got one comment. The fake never fails like this.

### The status write-back through the real adapter

Built from the same file by the functions the binary calls (`boot`, `external_ports`, `issue_status`, `token_sweep`) and run in the worker's loop beside the engine suite's scripted stage handlers, one job went `ACTIVE`, `WAITING_FOR_HUMAN`, `COMPLETED`:

```text
POST /repos/{owner}/{repo}/issues/{number}/comments        1
PATCH /repos/{owner}/{repo}/issues/comments/{id}           2
POST /repos/{owner}/{repo}/issues/{number}/labels          3   (factory: working, factory: waiting for a person, factory: done)
DELETE /repos/{owner}/{repo}/issues/{number}/labels/{name} 2   (the two earlier status labels)
POST /app/installations/{id}/access_tokens                 3
DELETE /installation/token                                 3
```

The issue ends with the labels `factory` and `factory: done`, and one comment that was made once and edited twice. Each of the three tokens was narrowed to the one repository and asked for `issues: write` and `metadata: read`; all three were revoked. The audit log has three `issue_status.written` records and no `issue_status.failed`. The trigger label was never touched. While an update is under way the issue briefly shows two status labels (the new one is added before the old one is taken off, by design); the judgments read the end of each state.

### The worker that must probe its tools

Without `runtimes.declare_capabilities`, and with the agent image absent, the worker stops at the probe: exit code 3 and the line `BLOCKED: CapabilityProbes: runtimes: ...` followed by `BLOCKED is not a pass: the start-up checks passed, and no job was claimed.` GitHub is not asked anything. This is the one place where the real path and the declared one part ways at start-up.

## Where the real-adapter path differs from the test-double path

The scenarios E3 to E9 and `full_run.rs` run the real engine, API, store and handlers with scripted agents, a fake sandbox, an in-memory code host and issue source and a stand-in registry. What changes with the real adapters, as seen here:

| Subject | With the test doubles | With the real adapters on loopback fakes |
|---|---|---|
| Reading an issue | A list in memory | An App JWT, an installation token minted for one repository, four reads of the issue (the later ones conditional, answered 304) and two reads of its events for each attempt; who applied the label comes from the events, not from the webhook |
| Tokens | None | Two or three for a refusal, each narrowed to one repository; the read class is `contents`, `issues`, `metadata`, `pull_requests` (read); the write class is `issues: write` and `metadata: read`; the write token is revoked after use, the read one when the job ends |
| Failures | A double does not fail | 502 and 429 are retried inside the adapter; a failed post fails the attempt and the engine retries it |
| Status on the issue | Not wired in any rig of `apps/api/tests` (`LiveRig` has only the token sweep as a step before a claim) | Needs a passed intake, writes one label and one edited comment, paced one update at a time |
| The design gate | Never on the track in E3 to E9 (no design label), tested with fakes in `crates/workflow` and `crates/composition` | Judged from the worker's configuration to the fake GitHub, with the numeric id of the person who applied the label read from the issue's events |
| Capabilities of the tools | A declared list | A probe in a real `agent` container, `BLOCKED` without the image |
| The sandbox | `FakeSandbox` answers | A stage that needs one ends `BLOCKED` with a named cause when the image or the daemon is missing, and nothing says so on the issue (LB-02) |

## Deliberate breaks, shown caught

| Break | Test | What the judgment said |
|---|---|---|
| GitHub adapter pointed at the wrong base URL (the registry fake's) | `break_the_github_adapter_at_the_wrong_base_url_is_caught` | The person got 0 comments, the job is not `BLOCKED`, and the registry fake received GitHub's routes. GitHub received nothing. |
| The App lacks `issues` | `break_an_app_without_the_issues_write_permission_is_caught` | The person got 0 comments. |
| The design policy file is gone | `break_a_missing_design_policy_stops_even_an_approved_issue_and_is_caught` | No record says the gate passed; the worker prints `NOT READY`. The gate fails closed. |
| The approver is not on the allowlist | `break_an_approver_missing_from_the_allowlist_is_refused_and_caught` | The issue that passed is refused with `not_applied_by_an_approver`. |
| Doctored evidence: a merge, a pull request, a push, a collaborator lookup, a route the path never uses, an unnarrowed token (two ways), a forbidden permission, a write token that carries more, a second comment, a status label on a refused issue, a stage that started, a request to a provider, a wrong correlation id, a broken ledger, a leak | `break_doctored_evidence_is_caught_by_each_judgment` | Each one is named in a complaint. |
| A token planted in a log, an audit row and an artifact | `break_the_credential_sweep_finds_a_token_planted_in_a_log_an_audit_row_and_an_artifact` | Three hits. |
| Status write-back switched off (`github.write_issue_status: false`) | `break_the_status_write_back_switched_off_is_caught` | No label was ever written; the comment was not created. |
| The approval policy row `write_status_label` asks for a person | `break_a_policy_row_that_asks_for_a_person_turns_the_write_back_off_and_is_caught` | The job completes and nothing is written; the step is built off. |
| The App lacks `issues` (status) | `break_an_app_without_the_issues_permission_fails_each_write_and_is_caught` | The job completes, `issue_status.failed` records exist and no label was written. |

## Findings

None of these was fixed. Each needs a decision about a configuration key, an ADR or a design that is not the engineer's, or it is a gap in what can be seen.

### LB-01: the worker cannot be told where the Docker daemon is

- **What was seen.** `crates/composition/src/providers.rs` builds the sandbox with `DockerSettings::default()`, so the `docker` client the worker runs gets an empty environment: no `DOCKER_HOST`, no `DOCKER_CONFIG`, no context. The configuration has no key for it. A daemon that is not on the default socket (a rootless Docker, Colima, a remote host) cannot be used.
- **Evidence.** `DOCKER_HOST=unix:///nonexistent/docker.sock docker image inspect nothing` prints `failed to connect to the docker API at unix:///nonexistent/docker.sock; ...`. The same variable on `cargo nextest run -p factory-worker --test loopback_e2e -E 'test(a_design_approved_by_an_approver)'` passes: the worker still reached the daemon and said "the image is not on this host".
- **Severity.** Medium for a deployment that is not on the default socket; none on this machine.
- **Smallest fix.** A `sandbox` key (for example `docker_host`) passed into `DockerSettings.env`, with its row in `docs/reference/configuration.md`. A new key is the architect's call.

### LB-02: an issue that passed the gate and was blocked by the environment gets no word

- **What was seen.** After the design gate passes and the sandbox cannot be made, the job is `BLOCKED` and the issue shows no comment and no `factory:` label. That is what finding STS-1 says (a status is written only after intake has passed), but a requester has nothing to read, and the only trace is the audit log.
- **Evidence.** `a_design_approved_by_an_approver_passes_the_gate_and_stops_at_the_sandbox_with_a_named_cause`: comments `[]`, labels `["factory", "design: approved"]`, job `BLOCKED`.
- **Severity.** Low. It is the design of ADR 0017; it is a gap for the person waiting.
- **Smallest fix.** The architect decides whether a block by the environment after the gate should post one fixed comment, as the refusal does.

### LB-03: the read token of the intake stage is wider than the stage needs

- **What was seen.** The token that reads the issue and its events asks for `contents`, `issues`, `metadata` and `pull_requests`, all `read`. The intake stage reads only the issue and its events. The policy says `permissions: narrowed_per_stage` and "read-only for analysis stages", which the token satisfies.
- **Evidence.** The mint record of the fake GitHub in any refusal run.
- **Severity.** Low.
- **Smallest fix.** A narrower token class for the stages that read only issues.

### LB-04: a blocked job keeps its read token until it expires

- **What was seen.** The write token is revoked at once. The read token of a refused or blocked job is not revoked: `RevokeEndedJobs` revokes for jobs that are over, and `BLOCKED` is not an end state. The token expires by itself after the hour GitHub gives it.
- **Evidence.** `TokenView { id: 1, ..., revoked_at: None, uses: 7, ... }` after the refusal. `crates/composition/src/token_sweep.rs` says why: a job is open unless it is `COMPLETED`, `FAILED`, `CANCELLED` or `REJECTED`, because a job that waits for a person must keep its token.
- **Severity.** Low (read-only, one repository, at most an hour).
- **Smallest fix.** Accept it and say so in the policy (`revoke_on_job_end` means the end of the job, not of the stage), or revoke the read token when the job has been `BLOCKED` for longer than some limit.

### LB-05: a warning at every start of the worker for a secret the worker never holds

- **What was seen.** `{"level":"WARN","fields":{"message":"no secret of a kind the policy lists is registered","kind":"webhook_secret"}}` on every start. The API holds the webhook secret; the worker leaves it out.
- **Severity.** Low. A warning that is always there is ignored when it matters.
- **Smallest fix.** Skip the kinds a binary does not hold in `check_secret_kinds`.

### LB-06: the live-adapters run did not include the status step or the design gate

- **What was seen.** `LiveRig::start` in `apps/api/tests/live/mod.rs` copies the worker's assembly, and its steps before a claim are the token sweep alone. The status write-back had been tested against fakes only (`crates/composition/tests/issue_status.rs`), and no run took the design gate from the worker's configuration to the real adapter (the adapter's reading of the events is tested alone in `crates/github/tests/design_gate_events.rs`). The tests above close both, apart from the whole job, which needs the images.
- **Severity.** Info.
- **Smallest fix.** When the images are present, add the status step to `LiveRig` and assert what `loopback_status.rs` asserts on its end state.

### LB-07: the list of texts that mean "the daemon cannot be reached" is older than the client

- **What was seen.** `daemon_unreachable` in `crates/sandbox/src/container/docker.rs` looks for four phrases. Docker 29.9.2 prints `failed to connect to the docker API at ...`, which is none of them. The result is still right today because `daemon_error` turns every failure that is not a cancel into `DaemonUnavailable`.
- **Severity.** Info.

### LB-08: the status text for a finished job

- **What was seen.** The text of a `COMPLETED` job says a draft pull request is ready and links to `https://github.com/<repository>/pulls?q=...`. The host is fixed. In the status run the job was completed by scripted stages, so no pull request exists; the text is true only for a real run.
- **Severity.** Info for this work; the fixed host matters only for a GitHub Enterprise server.

## What this does not prove

- **Nothing here touched real GitHub, real model providers or real keys.** Every endpoint was a loopback server on `127.0.0.1`, the App key and every token were made when the test ran, and the fake GitHub is FX-GH of the test kit. A fake can agree with the adapter and disagree with GitHub.
- **No agent ran.** The agent runtime adapters were assembled from the configuration (and reached through the router), but the tool runs in a container of the `agent` image, which this machine does not have. No request reached the model-provider fake or the registry fake. How the adapters behave on the wire to a model or to crates.io is shown one by one by `composed_broker.rs`, `external_world.rs` and `crates/runtime/tests`, not by this run.
- **No whole job.** No job passed intake through the binary. No draft pull request, no check run, no approval and no delivery were produced, so assertions such as "one open draft pull request, nothing merged, the base branch did not move" were not made on a real run of the pipeline. `apps/api/tests/live_run.rs` is the test for that, and it is `BLOCKED` here.
- **The status run uses scripted stages.** Its job went through the states of a real one, but the stage handlers are the engine suite's, and its `COMPLETED` has no pull request behind it. The binary was not used for it; the functions it calls were.
- **The API was not run.** The rows its webhook handler writes were written by the rig as the API's login, through the store. `apps/api/tests/webhook.rs` tests the handler.
- **The test that probes in a real container was not run.** It ends at `BLOCKED:` on this machine. The part after the check was written from `apps/api/tests/live/mod.rs` and has never been run.
- **Timing.** A write that should not happen is looked for during three seconds after the job settles. The end-state recheck of the status step (120 seconds later) was not waited for.
- **`FACTORY_E2E_COMPOSED` is still not built.** The scenarios E1 and E2 need a real model key, a registered GitHub App and a protected fixture repository, and stay `BLOCKED` on their own prerequisites. The rig above could become the base of the program; the decisions the worker README lists (which `ProtectionFacts` fields come from GitHub, a credential for the requester, a page in `docs/reference/commands.md`) are still open.
