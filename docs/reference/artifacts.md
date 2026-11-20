# Artifact reference

- Status: written on 2026-10-29 from the schemas under `schemas/`, the stored recordings of test-mode runs and the delivery code. Every example comes from a recording, not from a live run.
- Form: reference.
- Goal: say what the factory stores for a job, which schema each document follows, and how to read the evidence manifest, the documentation gate report and the ledger entries.

## Where artifacts live

The factory keeps the bytes of each artifact in a content-addressed store: the name of a blob is the SHA-256 of its bytes. In Slice 1 the store is a directory on the local disk ([ADR 0008](../adr/0008-artifact-store-and-evidence-ledger.md)). PostgreSQL holds an index row for each blob and the evidence ledger. A tenant can read a blob only when its own index row names the hash.

Every hash is written `sha256:` followed by 64 lowercase hex digits. Every time is UTC and ends with `Z`.

## The schemas

Each document follows one JSON Schema under [`schemas/`](../../schemas/README.md). An object sets `additionalProperties: false`, so a misspelled field is an error. `schemas/validate.sh` checks the schemas and their examples.

| Document | Schema | Written by | Read by |
|---|---|---|---|
| Evidence manifest | [`evidence-manifest`](../../schemas/evidence-manifest.schema.json) | the delivery stage | the pull request, approvers, the end-to-end harness |
| Gate report | [`gate-report`](../../schemas/gate-report.schema.json) | every gate | the stage's gate decision, reviewers, the ledger |
| Review verdict | [`review-verdict`](../../schemas/review-verdict.schema.json) | the reviewer agents | the gate decision, the rework routing |
| Ledger entry | [`evidence-ledger-entry`](../../schemas/evidence-ledger-entry.schema.json) | the engine | storage, delivery, auditors |
| Specification contract | [`specification-contract`](../../schemas/specification-contract.schema.json) | the Spec Kit adapter | every later stage |
| Task plan | [`task-dag`](../../schemas/task-dag.schema.json) | the planning stage | implementation, review, documentation |
| Stage contract | [`stage-contract`](../../schemas/stage-contract.schema.json) | the engine | the engine, the runtime, storage |
| Domain event | [`domain-event`](../../schemas/domain-event.schema.json) | the engine, through the outbox | event consumers, in a later slice |
| Agent manifest | [`agent-manifest`](../../schemas/agent-manifest.schema.json) | people | the registry loader, the policy engine |
| Project manifest | [`project-manifest`](../../schemas/project-manifest.schema.json) | people, in the target repository | intake, validation and documentation |
| Domain capability profile | [`domain-capability-profile`](../../schemas/domain-capability-profile.schema.json) | people | the registry loader, domain discovery |

The documentation plan has its own schema, [`documentation-plan.v1.schema.json`](../../crates/workflow/src/gates/docs/documentation-plan.v1.schema.json), next to the code that reads it.

## The evidence manifest

The delivery stage writes one evidence manifest and attaches its hash to the draft pull request. The manifest answers one question: what exactly supports this pull request, and what does it leave unproven?

| Field | What it holds |
|---|---|
| `metadata`, `title`, `summary` | Identity and a plain-English summary. |
| `ledger` | The number of entries, the sequence and hash of the head, and when the chain was last verified. |
| `specification`, `architecture`, `plan` | The hashes of the frozen specification, the design and the task plan. |
| `change` | The hash of the diff, the number of files changed, insertions and deletions. |
| `gate_reports` | The hash and outcome of every gate report. |
| `reviews` | The hash and verdict of every independent review. |
| `documentation` | The hashes of the documentation plan, the documentation gate report and its review. |
| `assurance` | The assurance levels attained and not attained. `PRODUCTION_READY` is in exactly one of the two lists. |
| `adapters` | Every adapter used, with its fidelity, `real` or `fake`. |
| `risk` | The computed risk tier and score. |
| `approvals_required` | How many approvals the policy asks for. |
| `limitations` | What was not verified, mocked, skipped or left to a person. The list is never empty. |

Evidence from a fake adapter never supports an assurance level. A manifest with a fake adapter in production mode is invalid. The pull request description repeats the manifest hash, the hashes of the specification, the task plan, the design and the documentation plan, and the ledger head. The [walkthrough](../walkthroughs/test-mode-run.md) shows one in a test-mode run.

## Gate reports and the documentation gate

A gate report records one deterministic check. Its outcome is one of four words.

| Outcome | Meaning | The report must hold |
|---|---|---|
| `PASSED` | Every check that applies ran and succeeded. | Commands with exit code 0, or an in-process gate, and no failure. |
| `FAILED` | A check ran and found a problem. | At least one failure with a check identifier and a plain-English message. |
| `BLOCKED` | A required check could not run. | `blocked_reason`: what was missing. |
| `NOT_APPLICABLE` | There is nothing to check. | `not_applicable_reason`: a recorded rule, never an opinion. |

A `warnings` list may sit beside the outcome. A warning never changes it. The report also holds the tool versions, the commands with their exit codes, the hash of the logs, a baseline comparison and an `evidence_hash` over the commands, logs and failures.

The documentation gate runs in the `DOCUMENTATION_REVIEW` stage and writes one gate report for each check. The checks are the readability gate, the binding of the documentation to the code head, the required pages, the changelog, the coverage of the change, links, command names, runnable examples, diagrams and secrets. In the test-mode recording of the end-to-end scenario E5, links, examples and diagrams are `NOT_APPLICABLE` and the others are `PASSED`. An independent reviewer then returns one of `PASS`, `CHANGES_REQUIRED`, `BLOCK` or `NEEDS_HUMAN`. The reviewer cannot overrule a failed gate.

## Ledger entries

The evidence ledger is append-only. It holds one chain for each job. An entry binds one claim to its evidence.

| Field | What it holds |
|---|---|
| `claim` | A `kind` (for example `measured_fact`) and a plain-English `statement`. |
| `evidence` | The list of what supports the claim, such as a gate report identifier and its hash. |
| `confidence` | A `level` and a `rationale`. |
| `metadata` | The entry identifier, the job, the stage run, the attempt, the `sequence`, the time, who recorded it (a component and its fidelity) and the execution mode. |
| `prev_entry_hash` | The hash of the previous entry. It is `null` only for sequence 1. |
| `entry_hash` | SHA-256 over `prev_entry_hash` and the canonical JSON ([RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)) of this entry without `entry_hash`. |
| `invalidates` | Earlier entries this one withdraws. |

To check a chain, recompute each `entry_hash` from the entry before it. The function `factory_domain::ledger::verify_chain` does this, and the end-to-end harness repeats it for every recording. A changed or removed entry breaks every hash after it.

## Other stored documents

- **Stage outputs.** Each stage stores its output under a declared name. The engine refuses a name the stage contract did not declare. A recording keeps four in `stage-outputs/`: the implementation result and evidence, the documentation result and the delivery result.
- **Audit events.** The audit stream records decisions, grants and denials, such as `authorization_decision.granted`, `decision.requested` and `decision.applied`. The job timeline serves them with the state changes.
- **Recordings.** A test-mode run leaves a directory under `fixtures/recordings/e2e/` with the files listed in the [end-to-end harness README](../../tests/end_to_end/README.md). A manifest of hashes catches a file changed after the run.
