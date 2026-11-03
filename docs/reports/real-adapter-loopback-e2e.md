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

That second look happened when the text check (DG-3) and the design re-check (DG-8) were merged. One scenario failed on the merge: the judgment for an issue off the design track treated any audit record that names the gate as a judgment, and the text check now writes a record for every job ("carries no design label, so the rule does not apply; text of the job compared with the live issue: same"). The judgment now accepts that record and asks for the text comparison on every job, on the track or off it. All 17 tests pass on the merged branch. The delivery re-check (DG-8) is not exercised here, because no job reaches delivery without the sandbox images.

### How to run it

```text
cargo nextest run -p factory-worker --test loopback_e2e --test loopback_status --no-fail-fast
cargo nextest run -p factory-worker --run-ignored only --test loopback_e2e      # needs the images: BLOCKED here
cargo nextest run -p factory-api --run-ignored only --test live_run             # the whole job: BLOCKED here
```

## What was run, and the result

Run on this machine while other work kept its load average between 22 and 46 on 16 cores.

| Command | Passed | Failed | Blocked | Ignored |
|---|---|---|---|---|
| `cargo nextest run -p factory-worker --test loopback_e2e --test loopback_status --no-fail-fast` | 17 | 0 | 0 | 1 |
| `cargo nextest run -p factory-worker --run-ignored only --test loopback_e2e` | 0 | 0 | 1 (`BLOCKED: the image factory-sandbox/verify@sha256:5ec059bc... is not on this host`) | 0 |
| `cargo nextest run -p factory-api --run-ignored only --test live_run --no-fail-fast` | 0 | 0 | 4 (each ends `BLOCKED: the image factory-sandbox/verify@sha256:5ec059bc... is not on this host (images are never pulled)`) | 0 |
| `cargo nextest run -p factory-worker --no-fail-fast` (the whole crate) | 165 | 1 | 0 | 1 |

The one failure of the whole crate is `composed_start ... stops_on_sigterm_with_code_zero` ("the worker did not stop on SIGTERM"), the test that is known to fail under load. It failed again when run alone at a load average of 23, and again with `apps/worker/tests/support/mod.rs` and `deployment.rs` put back to their state on `3f3f205`, so it does not come from this work.

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

When this report was first written none of these was fixed: each needed a decision about a configuration key, an ADR or a design that is not the engineer's, or it was a gap in what can be seen. The project owner then delegated the open decisions on 2026-11-03. LB-01, LB-05, LB-07 and LB-08 are closed, and so are LB-02, LB-03 and LB-04; see [Fix status](#fix-status). LB-06 is as described.

### LB-01: the worker cannot be told where the Docker daemon is

- **What was seen.** `crates/composition/src/providers.rs` builds the sandbox with `DockerSettings::default()`, so the `docker` client the worker runs gets an empty environment: no `DOCKER_HOST`, no `DOCKER_CONFIG`, no context. The configuration has no key for it. A daemon that is not on the default socket (a rootless Docker, Colima, a remote host) cannot be used.
- **Evidence.** `DOCKER_HOST=unix:///nonexistent/docker.sock docker image inspect nothing` prints `failed to connect to the docker API at unix:///nonexistent/docker.sock; ...`. The same variable on `cargo nextest run -p factory-worker --test loopback_e2e -E 'test(a_design_approved_by_an_approver)'` passes: the worker still reached the daemon and said "the image is not on this host".
- **Severity.** Medium for a deployment that is not on the default socket; none on this machine.
- **Smallest fix.** A `sandbox` key (for example `docker_host`) passed into `DockerSettings.env`, with its row in `docs/reference/configuration.md`. A new key is the architect's call.
- **Status.** Closed. See [Fix status](#fix-status).

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
- **Status.** Closed. See [Fix status](#fix-status).

### LB-06: the live-adapters run did not include the status step or the design gate

- **What was seen.** `LiveRig::start` in `apps/api/tests/live/mod.rs` copies the worker's assembly, and its steps before a claim are the token sweep alone. The status write-back had been tested against fakes only (`crates/composition/tests/issue_status.rs`), and no run took the design gate from the worker's configuration to the real adapter (the adapter's reading of the events is tested alone in `crates/github/tests/design_gate_events.rs`). The tests above close both, apart from the whole job, which needs the images.
- **Severity.** Info.
- **Smallest fix.** When the images are present, add the status step to `LiveRig` and assert what `loopback_status.rs` asserts on its end state.

### LB-07: the list of texts that mean "the daemon cannot be reached" is older than the client

- **What was seen.** `daemon_unreachable` in `crates/sandbox/src/container/docker.rs` looks for four phrases. Docker 29.9.2 prints `failed to connect to the docker API at ...`, which is none of them. The result is still right today because `daemon_error` turns every failure that is not a cancel into `DaemonUnavailable`.
- **Severity.** Info.
- **Status.** Closed. See [Fix status](#fix-status).

### LB-08: the status text for a finished job

- **What was seen.** The text of a `COMPLETED` job says a draft pull request is ready and links to `https://github.com/<repository>/pulls?q=...`. The host is fixed. In the status run the job was completed by scripted stages, so no pull request exists; the text is true only for a real run.
- **Severity.** Info for this work; the fixed host matters only for a GitHub Enterprise server.
- **Status.** Closed. See [Fix status](#fix-status).

## Fix status

| Finding | Status | What was done | The test that holds it |
|---|---|---|---|
| LB-01 | Closed | `sandbox.docker_host`, `sandbox.docker_config` and `sandbox.allow_remote_docker` (see the [configuration reference](../reference/configuration.md#sandbox)). `docker_host` is a `unix://` socket path or a `tcp://` address on the loopback interface; a remote `tcp://` host needs `allow_remote_docker: true`, which the `production` profile refuses. `docker_config` is an absolute directory that must exist. Both reach the `docker` client's environment (`DOCKER_HOST`, `DOCKER_CONFIG`), and nothing else does. A bad value stops the worker at start with a line that begins with the key. | `config::tests` (`a_docker_host_that_is_not_a_socket...`, `a_remote_docker_host_needs_the_explicit_flag...`), `crates/composition/tests/providers.rs` (the keys reach every docker command through a recording runner), `loopback_e2e` (`the_docker_host_of_the_configuration_decides_which_daemon_the_worker_asks`, `a_bad_docker_value_stops_the_worker_at_start_and_names_the_key`) |
| LB-05 | Closed | `check_secret_kinds` takes the kinds the binary does not hold and skips them. The worker passes the webhook secret (`WORKER_DOES_NOT_HOLD`). A kind the binary holds and lacks still stops the `production` profile and is logged in the others, once for each kind. | `crates/composition/tests/secret_kinds.rs`; `loopback_e2e::the_worker_does_not_warn_about_a_secret_kind_it_never_holds` |
| LB-07 | Closed | `daemon_unreachable` also matches `failed to connect to the docker API at`. | `container::docker::tests`, one test for each phrase and one for a daemon that answers with an error |
| LB-08 | Closed | The link in the text of a finished job is built from `github.web_base_url` (default `https://github.com`). The GitHub adapter's list of link hosts now comes from `output_hygiene.allow_link_domains` of the security policy, where before it was the adapter's own default; a web address whose host that list does not have stops the start with the name of the key, because the adapter would strip the link and say nothing. The text of the comment is still true only for a real run (the job in the status test is completed by scripted stages). | `issue_status::tests::the_pull_request_link_is_built_on_the_configured_web_address`, `crates/composition/tests/issue_status.rs::a_finished_job_links_to_the_pull_requests_on_the_configured_host`, `loopback_status` (`a_finished_job_links_to_an_enterprise_host_through_the_real_adapter` and its break) |
| LB-06 | Open | Information only: the next run with the images should add the status step to `LiveRig`. | |
| LB-02, LB-03, LB-04 | Closed | See the table in "The intake cluster" below. | |

Deliberate breaks, each shown caught by the tests named above:

| Break | Caught by |
|---|---|
| `docker_settings_from` leaves `DOCKER_HOST` out | the providers tests and `the_docker_host_of_the_configuration_decides_which_daemon_the_worker_asks` (the worker then starts its loop instead of stopping at the probe) |
| Any `tcp://` host accepted without the flag | the two `config::tests` for the host |
| The `production` profile accepts `allow_remote_docker` | `a_remote_docker_host_needs_the_explicit_flag_and_the_production_profile_refuses_the_flag` |
| The check on `docker_config` being a directory removed | `a_docker_config_that_is_not_a_directory_stops_the_assembly_and_names_the_key` |
| The secret-kind check ignores the kinds the binary does not hold (the old behaviour) | `secret_kinds.rs` and the worker log test |
| The secret-kind check passes everything (fail open) | `secret_kinds.rs` |
| The new Docker client wording removed | the test for that phrase |
| The link builder uses a fixed host again | the unit test and the composition test |
| The adapter ignores the policy's list of link hosts | `a_finished_job_links_to_an_enterprise_host_through_the_real_adapter` |

### The intake cluster (LB-02, LB-03, LB-04)

Written on 2026-11-03. Nothing ran on the real GitHub: every statement below is about the fake GitHub server of the test kit and the tests named.

| ID | Status | What was done, and the proof |
|---|---|---|
| LB-02 | FIXED, in part (the comment; not the label) | The intake stage, after its authorization and its design gate have passed, tells the person who asked when the place where it runs its tools is not available (the router has no tool, the policy or image catalog gives no sandbox spec, the sandbox cannot be made, the probe fails): one closed-template comment (`Reply::EnvironmentBlocked`, no text from the error), under the same cap and the same records as the design replies (DG-9), with the key `environment-<stage run>`. The error is returned unchanged, so the stage run is still `BLOCKED`, and a comment that cannot be posted never changes that. Before the gate has passed the stage says nothing of the kind: the sibling test shows an unreadable rule gets the comment that says the factory could not check, and a refused design gets only the refusal. **The label `factory: blocked` is not written for this case.** The status step writes only after the intake stage run has passed (ADR 0017, finding STS-1, kept as it is), and a run blocked at the sandbox has not. The comment is the part that tells the requester; once an operator repairs the environment and the run passes, the label follows. The alternatives were to let the status step read the audit log for the gate's record (forgeable by the holder of the API database login, REG-2) or to give the stage a status writer and a stamp it does not have; neither was taken. Tests: `a_job_that_passed_the_gate_and_is_blocked_by_the_environment_leaves_one_fixed_comment`, `nothing_is_said_about_the_environment_before_the_checks_of_the_stage_have_passed`, `a_policy_that_cannot_be_read_is_not_told_as_an_accepted_issue_with_a_missing_environment`, `a_comment_that_cannot_be_posted_does_not_change_the_environment_block`, `a_cap_that_is_reached_leaves_the_environment_block_without_a_comment`, `a_working_environment_leaves_no_environment_comment` (`intake_repo/design.rs`); seven breaks in `crates/workflow/tests/mutations/environment_block_breaks.py`, one of which shows that the STS-1 guard of the status step still holds. The loopback judgment of the end state was changed to expect exactly the notice and no label (`judge_reached_the_sandbox` in `apps/worker/tests/loopback_e2e.rs`), and the two loopback tests that reach the sandbox pass with it (PostgreSQL and the fake GitHub, on 2026-11-03; the Docker images are not needed for them). **Not verified:** a real Docker daemon that is down or an image that is missing (the tests lose the sandbox through the spec seam and through the missing agent image of the loopback); the real GitHub. |
| LB-03 | FIXED | A class of its own, `PermissionSet::issue_reader()`: `issues: read` and `metadata: read`. `PermissionSet::for_stage(Intake)` returns it, and every other stage keeps the class it had. The preflight of the protection of the default branch runs under the intake scope and needs the metadata only; a test shows it still works. A comment, a push and a pull request from the intake scope are refused, a comment is not widened to `issues: write`, and a server that answers with more than was asked is refused. The copy of the sets in the test kit follows and a test compares the two. Tests: `lb_03_the_intake_token_is_issues_read_and_metadata_read_whatever_the_call_asks`, `lb_03_a_stage_that_reads_the_repository_does_not_get_the_narrow_token` (`crates/github/tests/negative_tokens.rs`) and three unit tests in `permissions.rs`; six breaks in `crates/github/tests/mutations/read_token_breaks.py`. The policy `security.yaml` has no class table (only `permissions: narrowed_per_stage`); its comment now says what intake asks for. **Not verified:** that GitHub accepts a token request of `issues: read` and `metadata: read` alone for these routes (the fake does). |
| LB-04 | FIXED (the bound is 900 seconds; the first version used 3600, and the owner's delegate changed it because GitHub's own hour made that bound almost useless) | `credentials.github_app.installation_token.revoke_when_blocked_after_s: 900` in `policies/security.yaml` (required; a value under 60 or over 86400 refuses the file). The token sweep notes the first pass that saw a job `BLOCKED` and, when the bound has run, revokes the tokens the job holds **without ending the job** (`GithubAdapter::release_idle_after`): an unblocked job mints a new token, which an ended job cannot do. Only `BLOCKED` counts, so `WAITING_FOR_HUMAN`, `PAUSED` and `ACTIVE` jobs keep their tokens. Tests: `a_job_blocked_for_the_bound_gives_up_its_read_token_and_a_job_waiting_for_a_person_keeps_its` (against PostgreSQL), the three unit tests of `BlockedFor`, `lb_04_an_idle_job_loses_its_tokens_and_can_still_mint_new_ones`, `lb_04_only_the_jobs_named_as_idle_lose_their_tokens_and_a_running_one_is_spared`, `lb_04_a_revocation_that_fails_for_an_idle_job_is_kept_and_tried_again`, `lb_04_the_bound_on_a_blocked_jobs_token_is_required_and_has_to_make_sense`; eight breaks in `crates/composition/tests/mutations/blocked_token_breaks.py`. **Know this:** GitHub expires a token an hour after it was minted, so a bound of one hour revokes only a token that was minted after the block began; it does nothing for the token the stage held when it was blocked. A shorter value (say 900) is what shortens that exposure, and it is a one-line change of the policy. The wiring in `apps/worker/src/pipeline.rs` is compiled and its parts are tested, but no worker was started against a blocked job. |

## What this does not prove

- **Nothing here touched real GitHub, real model providers or real keys.** Every endpoint was a loopback server on `127.0.0.1`, the App key and every token were made when the test ran, and the fake GitHub is FX-GH of the test kit. A fake can agree with the adapter and disagree with GitHub.
- **No agent ran.** The agent runtime adapters were assembled from the configuration (and reached through the router), but the tool runs in a container of the `agent` image, which this machine does not have. No request reached the model-provider fake or the registry fake. How the adapters behave on the wire to a model or to crates.io is shown one by one by `composed_broker.rs`, `external_world.rs` and `crates/runtime/tests`, not by this run.
- **No whole job.** No job passed intake through the binary. No draft pull request, no check run, no approval and no delivery were produced, so assertions such as "one open draft pull request, nothing merged, the base branch did not move" were not made on a real run of the pipeline. `apps/api/tests/live_run.rs` is the test for that, and it is `BLOCKED` here.
- **The status run uses scripted stages.** Its job went through the states of a real one, but the stage handlers are the engine suite's, and its `COMPLETED` has no pull request behind it. The binary was not used for it; the functions it calls were.
- **The API was not run.** The rows its webhook handler writes were written by the rig as the API's login, through the store. `apps/api/tests/webhook.rs` tests the handler.
- **The test that probes in a real container was not run.** It ends at `BLOCKED:` on this machine. The part after the check was written from `apps/api/tests/live/mod.rs` and has never been run.
- **Timing.** A write that should not happen is looked for during three seconds after the job settles. The end-state recheck of the status step (120 seconds later) was not waited for.
- **`FACTORY_E2E_COMPOSED` is still not built.** The scenarios E1 and E2 need a real model key, a registered GitHub App and a protected fixture repository, and stay `BLOCKED` on their own prerequisites. The rig above could become the base of the program; the decisions the worker README lists (which `ProtectionFacts` fields come from GitHub, a credential for the requester, a page in `docs/reference/commands.md`) are still open.
