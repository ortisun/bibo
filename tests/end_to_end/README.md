# End-to-end acceptance harness

This is the harness that decides whether the Slice 1 proof holds. It holds the scenarios E1 to
E13, the fourteen assertions A1 to A14 of the Slice 1 acceptance section
([`docs/architecture/slice-plan.md`](../../docs/architecture/slice-plan.md), section 10), the issue
texts the scenarios submit, and a runner. Run it with [`scripts/e2e.sh`](../../scripts/e2e.sh).

The rule it follows: a scenario that could not run is `BLOCKED` and the command exits with code 3.
It is never skipped and never a pass. A result from labelled fakes is always labelled.

## What the assertions read

The harness reads stored records and GitHub, not log text. A wiring (see below) collects one
`RunEvidence` for a run: the job and its stage runs, the evidence ledger, the audit stream, the
timeline, the human-facing texts, the contract documents, what GitHub holds, the spans and the
correlation ids, and the spend. The assertions are pure functions of that evidence, so a run can be
saved as JSON, checked again later, and corrupted on purpose.

| Id | What it asserts |
|---|---|
| A1 | The job is `COMPLETED`. Each stage listed for Slice 1 in `docs/architecture/state-machine.json` has exactly one `PASSED` run, and each passed after the stages it requires. The number of stages is read from the file and not written in code. |
| A2 | `DOCUMENTING` and `DOCUMENTATION_REVIEW` finished after `REVIEW` and before `DELIVERY`, by ledger sequence. |
| A3 | One open draft pull request that links the issue, and a head branch with the code commits and then a documentation commit. |
| A4 | The evidence manifest validates, lists limitations and, in a production job, only real adapters. The ledger chain verifies. The head hash in the manifest is the stored entry, and the pull request body carries it. |
| A5 | The specification contract validates, is approved, uses only the four allowed Spec Kit skills, and its artifact hashes match the files on the branch. |
| A6 | The task graph validates and passes the planner checks (unique ids, no cycle, no dangling dependency, no shared file). Every acceptance scenario and requirement is covered. The changed paths are inside the owned files. |
| A7 | Every gate report validates. A `PASSED` report ran every command with exit code 0, in an image pinned by digest, and in a production job with real adapters. |
| A8 | Every human-facing text passes the readability gate. For a request in another language the specification, plan, pull request and documentation are English. |
| A9 | The approval waited for a person, was recorded for a person who is not the requester and who held the approver role in the ledger, and the job then completed. The pull request is not merged and the base branch did not move. |
| A10 | No request merges, enables auto-merge or deploys. No token holds a permission the policy forbids, and each is narrowed to one repository. The head branch is under `factory/`. The base branch needs a review that the App cannot bypass. |
| A11 | Each attempt has one span whose parent is its stage run span. Every captured event, log line and audit event carries the job's correlation id. |
| A12 | The documentation gate report is `PASSED` with the link check and a snippet execution run with exit code 0, or `NOT_APPLICABLE` with a recorded rule. |
| A13 | `DELIVERY` starts only when every stage before it has a current `PASSED` run with passing gate reports. A failing check keeps it from starting. |
| A14 | In a production job no ledger entry and no manifest adapter is a fake. In test mode a fake is allowed only when labelled: it claims no assurance level, and the manifest attains none on it. |

Each assertion is shown to fail. `scripts/e2e.sh --self-test` runs 88 deliberate corruptions of an
honest evidence set, at least two for each assertion, and checks that the assertion fails with a
reason that names the broken fact. The scenario checks have their own corruptions in
`tests/scenario_mutations.rs`.

## Scenarios

`scripts/e2e.sh --list` lists them. E1 to E9 are the scenarios of the plan. E10 to E13 are added for
a request edited after authorization, budget exhaustion, an ambiguous request and an out-of-policy
request.

| Scenario | Adapters | Today |
|---|---|---|
| E1, E2 | Real | `BLOCKED` until the prerequisites and the composed wiring exist. |
| E3 to E13 | Test mode, labelled fakes | Run on the scripted wiring. |

The issue texts are in [`issues/`](issues/README.md).

## Wirings

A wiring is the thing that drives the factory and reads back the evidence. The runner asks it three
things: its protection of the fixture remote, whether it uses real adapters, and to run a scenario.

* **Scripted** (`src/scripted`) is the stand-in that runs today. It runs the real workflow engine
  over the testkit fakes, the fake GitHub server and the scripted adversarial runtime, and it
  captures the spans and events the engine emits. The stage runs, attempts, ledger, audit stream
  and transitions in its evidence are the engine's own. What the stage packages that are not merged
  would write (the specification, the plan, the documentation, the pull request) is scripted. Every
  piece of its evidence says test mode.
* **Composed** is the real one, which the composition package supplies. It has two ways in. It can
  link this library (`default-features = false`) and implement `runner::Wiring`. Or it can provide
  a program that `FACTORY_E2E_COMPOSED` names, with this contract:
  * `PROGRAM protection` prints the protection of the default branch of the fixture remote as
    JSON (the fields of `evidence::ProtectionFacts`).
  * `PROGRAM run SCENARIO_ID` drives the scenario and prints the evidence as JSON (the fields of
    `evidence::RunEvidence`).
  * When it cannot run it prints one `BLOCKED: <reason>` line for each missing item on standard
    error and exits with code 3.

## What a real run needs

E1 and E2 need all of these, and the runner names each one that is missing:

| Variable | What it is |
|---|---|
| `FACTORY_E2E_COMPOSED` | The composed wiring program. |
| `FACTORY_E2E_MODEL_API_KEY` | An API key for the model provider with a provider-side hard spend limit. A subscription login does not count. |
| `FACTORY_E2E_GITHUB_APP_ID`, `FACTORY_E2E_GITHUB_APP_KEY_FILE` | A registered GitHub App and its private key file. |
| `FACTORY_E2E_FIXTURE_REPO` | The fixture repository on GitHub, as `owner/name`. |
| `FACTORY_E2E_REQUESTER_ALLOWLIST` | The named requester allowlist. |

The fixture repository is a copy of [`fixtures/repos/word-count`](../../fixtures/repos/word-count/README.md)
with a branch-protection ruleset. The harness refuses to run a scenario that opens a pull request
against a remote whose protection falls short of `policies/security.yaml` (a pull request and a
review are required, the required check is pinned to the App, stale approvals are dismissed, force
pushes and deletion are off, the App is not on the bypass list, and code owners review protected
paths), and reports `BLOCKED` with the missing rule. Replace the placeholder handles in the
fixture's `CODEOWNERS` with real ones when you copy it.

## Run it

```text
scripts/e2e.sh --list
scripts/e2e.sh --self-test-all
scripts/e2e.sh --check-fixture
scripts/e2e.sh --scenario E3 --scenario E4 --scenario E5 --scenario E6 --scenario E7 --scenario E8 --scenario E9
scripts/e2e.sh --scenario E1 --scenario E2
scripts/e2e.sh --scenario E1 --test-mode
```

The second to last command exits with code 3 until a real run is possible. The last one runs E1 on
the scripted wiring and labels the result `TEST MODE`; it is not the real proof.

The project is its own cargo workspace. It is not a member of the factory workspace, because the
package that owns it does not own the root manifest. The `cargo` commands in `scripts/e2e.sh` build
it into `target/e2e`.

## What the scripted wiring borrows

The engine's own tests build an engine from the fakes in `crates/workflow/tests/support`. The
scripted wiring includes those files as they are, with `#[path]`, so that it and the engine's
scenario tests drive one construction. If the engine package turns that harness into a public
testkit surface, the `#[path]` goes away.

## Two assumptions to settle

* The documentation gate package (`s1-stage-documentation`) is not merged. A12 reads the report for
  a command whose arguments contain `link` and one that contains `snippet`. When that package
  defines how it records its checks, change the three constants at the top of the documentation
  section of `src/assertions/contracts.rs`.
* The planner validator (`s1-stage-architecture-and-planning`) is not merged either, so A6 writes
  out the planner checks itself (`planner_problems`). Replace it with the validator when it exists.
