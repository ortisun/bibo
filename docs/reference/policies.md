# Policy reference

- Status: written from the policy files and the code that loads them on 2026-10-29, and extended on 2026-11-02 with the issue workflow policy. The two policy files still carry `status: designed` and a header that says no code reads them. That header is out of date: the worker, the API and the operator command line load and hash both files at start-up. The `designed` value is the policy's own claim, and nobody has flipped it to `enforced`.
- Form: reference.
- Goal: say what each policy and configuration file controls, who may change it, and where the real file is.

## How policy is loaded

A policy is read from the protected configuration branch, in a checkout that lies outside every job workspace. It is never read from a feature branch, from a builder workspace or from the target repository's working tree. The loader (`load_policy` in `crates/composition/src/startup.rs`) reads `policies/security.yaml` and `policies/approval.yaml` once, at start-up, and computes a SHA-256 over the result. That hash is the policy hash that jobs, approvals and audit events carry.

Three rules hold for every policy file.

- An unknown key is a load error. A misspelled rule never becomes a weaker rule.
- Any matching deny wins over any allow.
- A project's own settings can tighten the central policy and never widen it. A key that would widen it is a load error.

## The files

| File | What it controls | Who may change it |
|---|---|---|
| [`policies/security.yaml`](../../policies/security.yaml) | The default-deny security policy. See the table below. | A pull request on the protected branch, reviewed by a code owner. |
| [`policies/approval.yaml`](../../policies/approval.yaml) | Autonomy levels, who holds which designation, which actions need a person, and what an approval is bound to. | The same. Raising an autonomy level is an action that only an `org_admin` may approve. |
| [`policies/issue-workflow.yaml`](../../policies/issue-workflow.yaml) | The labels an issue carries, who writes each, and which `factory:` label shows which job state. See the section below. | The same. The rendered copy `onboarding/github/issue-workflow.json` is made from it, and a stale copy fails the build. |
| [`policies/model_routing.yaml`](../../policies/model_routing.yaml) | Which models each stage may use and in which order, what each model costs, and the spend ceilings of a stage run and of a job. See the section below for what the code does with it today. | A pull request on the protected branch, reviewed by a code owner. The project owner confirms every number. |
| `.factory/project.yaml` on the default branch of each target repository | The project manifest: the gate commands that the validation stage runs, and the project's own settings. It is read at the base commit of a job, never from the builder's commit. The `unit-tests` gate may name its test report there (`test_report`): the output of the Rust test harness, which is the default, a report in JUnit XML (Extensible Markup Language) or a report in the Test Anything Protocol (TAP). Only the fixture repository holds one ([`fixtures/repos/word-count/.factory/project.yaml`](../../fixtures/repos/word-count/.factory/project.yaml)). See [Prepare a repository](../guides/prepare-a-repository.md) for every key. | A pull request on the target repository's protected branch. The central policy refuses a change to `.factory/**` by a builder. |
| `allowlist/allowlist.yaml` in the protected checkout | Who holds which designation, by numeric GitHub user identifier. It is read on every decision. This repository holds no copy. | An `org_admin`. Widening `security_approver` or `org_admin` needs two distinct `org_admin` people. |
| [`.github/CODEOWNERS`](../../.github/CODEOWNERS) | Who must review a change to a protected path. | A code owner. Today there is one owner, so GitHub cannot count a second review. |
| [`agents/*/manifest.json`](../../agents/README.md) | One specialist agent: tools, permissions, limits, schemas, skills and prompt. | A person, in a reviewed pull request. |
| [`profiles/*/profile.json`](../../profiles/general-software/profile.json) | What a kind of software needs: skills, tools, evidence, mandatory gates. The general software profile names no language, and the factory is not yet equal for every language: the test gate reads the output of the Rust test harness, JUnit XML and TAP, of which only the first has run against a real tool, and the supply-chain gate reads Cargo only ([Prepare a repository](../guides/prepare-a-repository.md), "Limits that exist today"). | A person, in a reviewed pull request. |
| [`infra/sandbox-images/images.json`](../../infra/sandbox-images/images.json) | The pinned sandbox images, by digest and platform. | A person, after the image was rebuilt and tested. |
| [`deny.toml`](../../deny.toml) | The licences, bans and sources allowed for dependencies. | A person. A new licence needs the project owner's approval. |
| [`fixtures/readability/rules.json`](../../fixtures/readability/rules.json) | The rules of the readability gate. | A person, after a case is added. See the [documentation policy](documentation-policy.md). |
| [`.specify/memory/constitution.md`](../../.specify/memory/constitution.md) | The project constitution that Spec Kit reads. | A person. The factory only checks that it exists. |

## What `policies/security.yaml` controls

| Section | What it controls |
|---|---|
| `matching` | How paths and patterns are compared everywhere in the file. |
| `protected_paths` | The paths that no agent may change without a specification that authorizes it, an independent policy review and a human. |
| `path_access` | Which workspace paths the file tools may read and write. |
| `forbidden_command_classes` | Commands that are denied, or sent to a person. |
| `tools` | Each tool, its risk, the profiles it may run in, the roles that may hold it and its per-task limits. |
| `command_sets` | The commands a toolchain may run, with forced and forbidden arguments. |
| `sandbox` | What a container must look like before it starts. A mismatch aborts the job. |
| `egress` | The hosts a sandbox may reach, each with a reason and a review date. Wildcards are off. |
| `secrets` | The patterns that find secrets, and the registry of secret values the factory issued. |
| `credentials` | The GitHub App permissions, token lifetimes, the model-provider credentials and the requirements a repository must meet. `model_providers.mode` is `subscription` (the default, also when the key is absent) or `api_key` (architecture decision record (ADR) 0020). In `subscription` mode the broker holds the owner's Claude subscription token (`subscription_token`): no provider API key and no provider-side spend limit is required, spend is bounded by the factory's ceilings and the plan's limits, and the runtimes in `unavailable_runtimes` (`codex-cli`) do not run. The file is refused unless `subscription_token.never_in_sandbox` is true, `held_by` is `[model_broker]`, `providers` is `[anthropic]` and `registered_for_redaction_as` names a kind of `secrets.exact_values.register_from` (`subscription_token`). In `api_key` mode the broker holds one API key per provider with a provider-side spend limit (`real_keys`). A project policy may not change the mode. The signed exception for a subscription login on a demo host (`subscription_logins`) was removed with the approval row `accept_subscription_login_exception`. `github_app.permissions_required` lists each permission the App must hold, and its level is also the most the App may hold: an App above it is refused like one that holds a name of `permissions_forbidden`, and a file that lists a name in both, or a level other than `read` or `write`, is refused. `administration: read` is required since the owner's decision of 2026-11-12, so that the protection preflight can read classic branch protection with a token of its own (`administration: read`, `metadata: read`); `organization_administration` stays forbidden. `installation_token.revoke_when_blocked_after_s` (900; from 60 to 86400, otherwise the file is refused) is how long a job may stay `BLOCKED` before the worker revokes the tokens it holds. The job is not ended, and a job that waits for a person keeps its token (LB-04). The intake stage asks GitHub for `issues: read` and `metadata: read` only; the other analysis stages read the contents and the pull requests as well (LB-03). `repository_requirements.exposed_workflows` (`cap_at_l0` or `record_only`; any other word and the file is refused) says what a repository pays when the protection preflight finds a workflow that is exposed to factory branches (threat T-48): a cap at level `L0`, unless its owner acknowledged exactly those workflows, or only a line in the audit record. |
| `webhook` | Limits and checks on the webhook intake. |
| `budgets` | The ceilings on time, tokens and cost, and what happens when one is reached: the work goes to a person. |
| `gate_integrity` | The gates that no person may waive. |
| `untrusted_content` | How issue text, repository files and model output are kept out of the instruction channel. |
| `agent_stage_profiles` | The tools and Spec Kit skills each agent stage may use. |
| `output_hygiene` | The checks on text the factory writes to GitHub. |
| `supply_chain` | The rules for new dependencies. |
| `tenancy` | The tenant isolation rules. |
| `audit` | What the audit log records. |

## What `policies/approval.yaml` controls

| Section | What it controls |
|---|---|
| `autonomy` | The levels. `L0` observes only. `L1` makes branches and draft pull requests, and every promotion needs a person. `L2` may mark a pull request ready. The default level is `L1`. |
| `authority` and `roles` | The designations: `requester`, `operator`, `approver`, `security_approver`, `repo_admin` and `org_admin`. A designation comes only from the allowlist. |
| `separation_of_duties` | When the approver must differ from the requester. The factory app never approves. |
| `risk_tiers` and `risk_classification` | How a change gets a risk tier. |
| `actions` | One row for each action the factory may take, with the lowest level at which it exists and whether it needs a person. A missing row needs a person. |
| `always_human` and `never_allowed_even_with_human_via_the_factory` | What always needs a person, and what no person can ask the factory to do. |
| `approval_binding` | What an approval is bound to, and when it stops counting. |
| `commands` | The one command set for the dashboard, the command line and GitHub comments. |
| `intake` | Who may start a job. |

Four rows of `actions` cover the path of a repository: `register_repository` and `confirm_project_map` and `disable_repository` need the `operator` designation, and `enable_repository` needs the `approver`. Confirming a project map is an attestation by a person and not a check: the engine holds no GitHub credential and does not read the repository. The worker reads these rows again when it applies a signed request to register, confirm or enable (finding REG-2): the API checks the designation when it takes the request, and the worker checks it again, by the numeric GitHub id and with the GitHub id of the repository, at the moment of applying. These four rows are a default that is pending confirmation by the architect. See the architecture decision record (ADR) [0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md).

A fifth row, `accept_design_approval`, says who approves a design: a person who holds the `approver` designation and applies the label `design: approved`. The intake stage enforces it. The designation itself is read from `intake_requirements.design_approved_by` in `policies/issue-workflow.yaml`, and a test checks that the row and that key name the same designation. The row is a default that is pending confirmation by the architect, in the same ADR.

Auto-merge and deployment are off. In Slice 1 the factory has no merge method. A person merges outside it.

Two rows concern labels on an issue. Both are marked as pending confirmation by the architect, in the architecture decision record (ADR) [0017](../adr/0017-ports-v1-2-issue-status-writer.md).

| Action | Lowest level | What it allows |
|---|---|---|
| `write_status_label` | `L0` | The one `factory: <state>` label that shows the state of a job. Never the trigger label, never a `design:` label, never a label of any other kind. |
| `close_or_label_issue` | `L1` | Closing an issue, and a label of the factory namespace that is not a status label. There is no such label today. |

A repository without branch-protection rules runs at `L0`, which is why the status label has a row of its own at that level.

**The worker reads `write_status_label`.** The step that writes the status checks the row before it writes. The row must exist and say `requires: none`, and a job is written for only when its autonomy level is at or above the row's lowest level. If an architect changes the row to need a person, or removes it, the worker starts anyway, writes nothing on any issue, and reports a degraded health line.

**No code reads `close_or_label_issue`.** The factory never closes an issue and writes no other label of its namespace. The row is documentation until a consumer exists. Changing it stops nothing.

The records of the step carry a hash that binds `policies/issue-workflow.yaml` to the security and approval policies, so a record says which label map was in force.

## What `policies/model_routing.yaml` controls

The file exists. An earlier version of this page said it did not.

The worker loads it at start-up with the other policies and checks it against the security policy (`load_routing` in `crates/composition/src/startup.rs`). A file that is missing or broken stops the start.

| Part of the file | What the code does with it today |
|---|---|
| `models` | The broker prices every answer with these prices and refuses a model that has none (`price_table` in `crates/composition/src/routing.rs`). |
| `routes` | The router answers from this table. For a stage and a tier it walks the candidates in the order of the file. It returns the first one that is enabled, is not excluded, has the capabilities the stage needs and, for a review, is independent of the author's model (`route_filtered`). |
| `roles`, the ceilings and the caps | A job token holds only the models of the stage's routes and the ceiling of the stage run. The broker holds each request to the caps of the role (`token_request`, `request_caps`). |
| `independence` | The review stage names the model of the author, and the router drops every candidate that the rule refuses. |
| `roles[].escalate_to` and `roles[].escalate_after_failed_repairs` | The loader checks them and the tighten-only check compares them. Nothing acts on them. No code moves a role to its larger model after failed repairs. |

Routing is a static lookup. The router does not measure anything, does not learn and does not escalate. Every stage found by a search of `crates/workflow/src` asks for the `standard` tier, so the routes of the `large` tier are not selected today.

The file was confirmed by the owner on 2026-11-13: its status is `enforced`, and every price carries the date it was read and the price page it was read on. The `production` profile refuses to start when the status is `designed` or a price says `price_checked_on: unchecked` (`confirm_routing` in `crates/composition/src/startup.rs`). The other profiles start and log a warning.

## What `policies/issue-workflow.yaml` controls

The file lists the fifteen labels of the issue workflow: the trigger label `factory`, four `design:` labels that people write, and ten `factory:` labels that the factory writes. It also holds the legal moves between design states.

Two readers use the file in different ways. This difference is on purpose.

- **The intake stage reads it for every attempt, and it is a control.** The stage refuses an issue on the design track whose design is not approved (the section `intake_requirements` below). A file that is missing, sits in a job workspace, does not parse, has a key the loader does not know, lacks `design_approved_by` or breaks a rule gives the stage no rule. The stage then refuses every issue, with or without a design label, and blocks the stage run with the cause `policy_unloadable`. There is no default and no copy of an earlier version. The worker prints `NOT READY: design gate` when it starts, and the health line of the rule is `fail`, never `degraded`. A repaired file takes effect on the next attempt.
- **The worker reads it at start-up to write the status of jobs, and that is observability.** A problem there never stops a job. The next paragraph says what happens.

The worker reads the file at start-up with the same strict loader as the other policies. A file that misses a job state, names a state the engine does not have, puts the trigger label in a namespace or breaks the label length limits is refused, and the worker starts without writing issue status. It reports a degraded health line, records the fact in the audit log, and writes nothing on any issue until a worker starts with a sound file. The trigger label of the file must also be the `intake.trigger_label` of the approval policy, or the step stays off.

| Section | What it controls |
|---|---|
| `namespaces` | The two prefixes, `design: ` and `factory: `, and who writes each. |
| `trigger` | The label that asks the factory to work. No automation applies it. |
| `design_track` | The design states, the legal moves and what approval of a design needs. |
| `factory_track` | One label for each job state of the engine. The status label of a job comes only from here. |
| `intake_requirements` | What intake checks when the trigger label is applied. `design_track_requires` is the design state an issue on the design track needs before a job may start (`approved`). `design_approved_by` is the designation that the person who applied that label must hold (`approver`; never `requester` or `operator`). The engine enforces both. `design_refusal_cap_per_issue` (3), `design_withdrawal_cap_per_issue` (2) and `design_environment_cap_per_issue` (2), each from 1 to 100, and `design_reply_window_hours` (24; from 1 to 168) cap the replies the factory posts on one issue about its design, counted over the window and by kind: the answers of the design gate at intake, the stop before the pull request opens, and the notice about the environment each have a cap and a family of their own, so one kind cannot use up the room of another (DR-4). All four keys are required: a missing key, a zero or a number outside the range is a load error and the gate then refuses every issue, so a zero cannot be read as no limit (DG-9). The key `design_reply_cap_per_issue` that these replaced is not known any more and a file that still has it is refused. The look the adapter takes at the thread before it posts is not a key: it is three pages of 100 comments, fixed in the adapter, and a thread that is longer in the window gets no reply and an audit record that says so. The reply to a label from someone who may not ask has bounds of its own that are not keys of this file (SF-16): one reply to a sender in ten minutes and three in 24 hours, counted in the tenant; a request that is not answered is recorded with `withheld=spacing` or `withheld=cap`. |

**What the intake stage enforces.** An issue that carries a label whose name starts with `design:` (in any letter case, with or without the space) needs the label `design: approved` as its only design label. The labels are read from GitHub at intake, never from the webhook. The person who applied `design: approved` must hold the designation named by `design_approved_by`, found by numeric user ID on the protected allowlist and not narrowed away from the repository. An issue with no such label is not touched. A refusal is the intake outcome `decline`, with the gate `intake-design-approved` reported as BLOCKED and the block code `design_not_approved`. The job shows as blocked. The security policy lists that block in `gate_integrity.non_overridable_blocks`, so no override passes it. The key `design_approved_by` is the engineer's default and is pending confirmation by the architect.

The same gate and the same block code also refuse a job whose text is not the title and the body of its issue as GitHub shows them now. This is checked for every job, on or off the design track, and the refusal has its own reason word, `text_not_the_issue`, in the audit record, the stored design document and the report. The audit line of the design gate ends with `text of the job compared with the live issue: same` or `different`.

| Reason word of a refusal | Meaning |
|---|---|
| `not_approved` | The issue is on the design track and carries no `design: approved`. |
| `design_dropped` | A design label was applied and taken off; the issue is still on the track. |
| `more_than_one_design_label` | `design: approved` is on the issue together with another design label. |
| `approval_label_gone` | The approved label was in the list of labels but was off the issue when its applier was asked for. |
| `not_applied_by_an_approver` | The approved label was applied by somebody who does not hold the designation, or is not a person's account. |
| `text_not_the_issue` | The text the job carries is not the text of the issue now. |

The delivery stage asks the same question again right before it pushes the factory branch and opens the draft pull request. It uses the same code, the same rule and the same allowlist. A design that is no longer approved stops the stage with the block code `design_not_approved` and no stored gate, so no override passes it; a read of GitHub that fails fails the attempt and writes an audit record that says the check was degraded. See [ADR 0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md).

The Python tool `scripts/lib/issue_workflow.py` checks the same file and renders the JSON that the installer and the GitHub Action read. A test compares what the worker reads with that JSON, so the two cannot disagree about a label.

## Where to read more

- The [threat model](../security/threat-model.md) explains each threat identifier that the policy files cite.
- The [sandbox policy](../security/sandbox-policy.md) explains the container flags.
- The [secrets and credentials](../security/secrets-and-credentials.md) document explains the redaction and the GitHub App permissions.
- The [authority review](../reviews/authority-and-evidence-security-review.md) and its [re-review](../reviews/authority-api-supply-chain-security-rereview.md) say where the approval rules held and where they did not.
