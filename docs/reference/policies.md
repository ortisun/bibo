# Policy reference

- Status: written from the policy files and the code that loads them on 2026-10-29. The two policy files still carry `status: designed` and a header that says no code reads them. That header is out of date: the worker, the API and the operator command line load and hash both files at start-up. The `designed` value is the policy's own claim, and nobody has flipped it to `enforced`.
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
| `policies/model_routing.yaml` | Which model serves which stage. **The file does not exist.** Without it the model router is BLOCKED and the worker cannot run a live stage. | A person writes it. See the [production guide](../guides/production.md). |
| `allowlist/allowlist.yaml` in the protected checkout | Who holds which designation, by numeric GitHub user identifier. It is read on every decision. This repository holds no copy. | An `org_admin`. Widening `security_approver` or `org_admin` needs two distinct `org_admin` people. |
| [`.github/CODEOWNERS`](../../.github/CODEOWNERS) | Who must review a change to a protected path. | A code owner. Today there is one owner, so GitHub cannot count a second review. |
| [`agents/*/manifest.json`](../../agents/README.md) | One specialist agent: tools, permissions, limits, schemas, skills and prompt. | A person, in a reviewed pull request. |
| [`profiles/*/profile.json`](../../profiles/general-software/profile.json) | What a kind of software needs: skills, tools, evidence, mandatory gates. | A person, in a reviewed pull request. |
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
| `credentials` | The GitHub App permissions, token lifetimes and the requirements a repository must meet. |
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

Four rows of `actions` cover the path of a repository: `register_repository` and `confirm_project_map` and `disable_repository` need the `operator` designation, and `enable_repository` needs the `approver`. Confirming a project map is an attestation by a person and not a check: the engine holds no GitHub credential and does not read the repository. These four rows are a default that is pending confirmation by the architect. See the architecture decision record (ADR) [0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md).

Auto-merge and deployment are off. In Slice 1 the factory has no merge method. A person merges outside it.

## Where to read more

- The [threat model](../security/threat-model.md) explains each threat identifier that the policy files cite.
- The [sandbox policy](../security/sandbox-policy.md) explains the container flags.
- The [secrets and credentials](../security/secrets-and-credentials.md) document explains the redaction and the GitHub App permissions.
- The [authority review](../reviews/authority-and-evidence-security-review.md) and its [re-review](../reviews/authority-api-supply-chain-security-rereview.md) say where the approval rules held and where they did not.
