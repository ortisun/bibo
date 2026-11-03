# Contract schemas

JSON Schema (draft 2020-12) definitions for the documents the factory passes between stages, agents and storage. They are the contracts that let engineers work in parallel: a producer and a consumer only need to agree on the schema.

Status: Slice 0 baseline, revised on 2026-10-27 (gate report warnings, integer bounds in ledger entries, a wider description of `defect_class`; see ADR 0010 and ADR 0011), and again the same day by [ADR 0014](../docs/adr/0014-ports-v1-1-claim-protocol-and-port-revision.md) after the independent review: a finding of a verdict other than `PASS` cites a file and a line (`review-verdict`), a stage contract's `retry_on` lists `LEASE_LOST` and `TIMED_OUT` (`stage-contract`), and a ledger source URL is an https URL (`evidence-ledger-entry`). These tighten version 1 in place because no document has ever been stored under it; a person may prefer new versions. **The Rust types and tests that read these files fail until the work package `s1-ports-revision` lands.** The `domain` crate has one Rust type for each schema in `crates/domain/src/contracts/`, and its tests read the examples below. Run `schemas/validate.sh` to check the schemas themselves.

## The schemas

| Schema | What it governs | Produced by | Consumed by |
|---|---|---|---|
| [`stage-contract`](stage-contract.schema.json) | The resolved contract for one stage run: inputs and their provenance, methods and rejected alternatives, least-privilege capabilities, acceptance criteria, evaluator, budget, retries, idempotency, escalation | `workflow` | `workflow`, `runtime`, `storage` |
| [`specification-contract`](specification-contract.schema.json) | The typed form of an approved Spec Kit specification, with hashes of the original files | `spec_adapter` | every later stage |
| [`task-dag`](task-dag.schema.json) | The factory's own implementation plan: tasks, ownership, dependencies, cost, required evidence | `workflow` planning stage | implementation, review, documentation |
| [`gate-report`](gate-report.schema.json) | The result of one deterministic gate: commands, exit codes, tool versions, hashes, baseline comparison, failures, and warnings that never change the outcome | `workflow` gates | gate evaluator, reviewers, ledger |
| [`review-verdict`](review-verdict.schema.json) | One independent review: `PASS`, `CHANGES_REQUIRED`, `BLOCK` or `NEEDS_HUMAN`, with findings | reviewer agents via `runtime` | gate evaluator, rework routing |
| [`agent-manifest`](agent-manifest.schema.json) | One specialist agent: tools, permissions, limits, schemas, models, evaluation suite, prompt version | humans, reviewed in pull requests | `registry` loader, policy engine |
| [`domain-capability-profile`](domain-capability-profile.schema.json) | What a kind of software needs: skills, tools, evidence, mandatory gates, forbidden autonomous actions | humans, reviewed in pull requests | `registry` loader, domain discovery stage |
| [`evidence-ledger-entry`](evidence-ledger-entry.schema.json) | One append-only claim bound to its evidence, hash-chained per job | `workflow` | `storage`, delivery, auditors |
| [`domain-event`](domain-event.schema.json) | The envelope of one domain event in the outbox and on the event stream | `workflow` through `storage` | event consumers (Slice 2) |
| [`project-manifest`](project-manifest.schema.json) | The project-local `.factory/project.yaml`: domain tags, sandbox image, gate commands, protected paths, pinned Spec Kit version, required documents, and the warning-only readability rules the repository switches off | humans, in the target repository | `workflow` intake, validation and documentation stages |
| [`evidence-manifest`](evidence-manifest.schema.json) | The summary attached to a draft pull request: hashes of the specification, plan, change, gate reports and reviews, the ledger head, assurance levels attained and not attained, adapters used, limitations | `workflow` delivery stage | the pull request, approvers, the end-to-end test |

`domain-event`, `evidence-manifest` and `project-manifest` are not in the original list of eight. They were added because [ADR 0004](../docs/adr/0004-event-model.md) needs a fixed event envelope, the delivery stage and the end-to-end test need to agree on the pull request evidence, and the intake, validation and documentation stages need to agree on the file that holds a repository's gate commands and protected paths.

## Conventions

- **Dialect and identity.** Every schema declares `https://json-schema.org/draft/2020-12/schema` and has a URN `$id` such as `urn:ortisun:factory:schema:gate-report:1`. The last segment is the major version.
- **Versioning.** Every document carries `schema_version` (an integer). Adding an optional field keeps the version. Removing a field, tightening a rule or changing a meaning needs a new version and a new schema file. Old documents stay valid against the old schema.
- **Plain English for people, identifiers for machines.** Fields named `title`, `summary`, `description`, `reason`, `why_this_matters` and similar hold plain-English text. Every `title` is checked for machine-looking prefixes: `TASK-13: ...`, `FEAT-042 | BE-AUTH | P1 ...`, `[AGENT:BACKEND] ...`. Identifiers live in `id`, `*_id`, `slug` and `metadata` fields and may change without touching the titles. The schema cannot judge whether prose is clear or in English. The Human-Readable Artifact Quality Gate does that.
- **Hashes.** Always `sha256:` followed by 64 lowercase hex characters. Git object ids are 40 or 64 hex characters.
- **Time.** UTC, RFC 3339, with a `Z` suffix and up to nine fraction digits. This is enforced with a pattern, because `format` is not asserted by every validator. The pattern accepts `10:00:00Z` and `10:00:00.000Z`, which are the same instant. A document keeps the spelling it was written with, because its hash is taken over that text. The factory writes the shortest spelling (no trailing zero in the fraction), and compares instants, never text (ADR 0011).
- **Numbers in hashed documents.** A ledger entry is hashed as RFC 8785 canonical JSON, which writes every number as a 64-bit float. Every integer in an entry therefore stays between -9007199254740991 and 9007199254740991 (2^53 - 1), and the schema says so. The other documents are hashed as stored bytes and have no such limit.
- **Warnings.** A gate report lists what stops the work in `failures` and what only deserves attention in `warnings`. A warning has a `check_id`, a plain-English message and a suggested fix, and may have a location. It has no severity field, because a warning never changes the outcome. A PASSED report may carry warnings and still has no failures. A report of a gate that did not run (BLOCKED or NOT_APPLICABLE) carries none.
- **Closed shapes.** Objects set `additionalProperties: false`. A typo in a field name is an error, not a silent extra.
- **Self-contained files.** Each schema repeats the small shared definitions it uses (`uuid`, `sha256`, `slug`, `humanTitle`, `humanText` and a few more) so a validator needs no file resolution. `validate.sh` fails if two copies of the same definition differ.
- **Fake and real.** Gate reports, review verdicts, ledger entries and the specification contract record the adapter `fidelity` (`real` or `fake`) and the job `execution_mode` (`production` or `test`). A fake adapter in production mode is invalid. Evidence from a fake adapter never supports an assurance level. This is how "nothing is mocked without being labelled" becomes checkable.

## What a schema cannot check

These rules need code. The owner is named so they are not forgotten.

| Rule | Checked by |
|---|---|
| Task ids are unique, dependencies exist, the graph has no cycle | planner validator in `workflow` |
| No two tasks own overlapping files without an ordering edge | planner validator |
| Every acceptance scenario is covered by a task, and every requirement cites existing scenarios | planner validator and the specification gate |
| `required_tools` and `tool_probes` of a profile list the same tools | `registry` loader |
| The ledger hash chain is continuous and every `entry_hash` recomputes | `storage` on append, `workflow` before completing a job |
| The permissions in a stage contract are a subset of the agent manifest and the policy grant | policy engine |
| Prose is English, readable, and free of unexplained acronyms | Human-Readable Artifact Quality Gate |
| The line a review finding cites exists in the exported patch (SC-008) | the review gate in `workflow`, using `JobRepo::export_patch` |
| The agent's review output and the stored verdict agree, and the engine-owned fields (`inputs_reviewed`, the reviewer's runtime) are the engine's | the engine, which wraps the agent's findings (ports-v1.1, section 10.3) |

## Check the schemas

```bash
schemas/validate.sh
```

This needs `uv`. It runs [`check-jsonschema`](https://github.com/python-jsonschema/check-jsonschema) pinned to 0.39.0 through `uvx`, together with the `jsonschema` library at 4.25.1: `check-jsonschema` does not pin the library that words its errors, and check 5 compares that wording with the `.expect` sidecars. To use an installed binary, set `CHECK_JSONSCHEMA=/path/to/check-jsonschema`. The script exits non-zero if any check fails.

It checks that every schema passes the 2020-12 metaschema, that shared definitions are identical, that every schema has at least one valid and one invalid example, that valid examples validate, and that each invalid example is rejected with the message written in its `.expect` file. A schema that stops enforcing a rule makes the matching invalid example pass, and the script fails.

To validate one document by hand:

```bash
uvx --from check-jsonschema==0.39.0 --with jsonschema==4.25.1 check-jsonschema \
  --schemafile schemas/gate-report.schema.json path/to/report.json
```

YAML documents work the same way. The domain capability profile example from the master prompt is stored as YAML.

## Examples

`examples/<schema>/valid/` holds documents that must validate. `examples/<schema>/invalid/` holds documents that must be rejected, each with a `.expect` file naming the validator message that shows why.

The examples are synthetic. They use made-up identifiers and hashes that are not the hashes of real files. They describe one imaginary job: adding a `--json` flag to a word count tool, which is also the planned Slice 1 fixture. Do not copy them into evidence.

## Using the schemas from Rust

1. Embed each schema with `include_str!` in the `contracts` crate and validate with a JSON Schema crate. `jsonschema` 0.60.2 is current on crates.io, but support for every keyword used here (`if/then/else`, `dependentSchemas`, `contains`, `oneOf` with `const`) has not been tested. The first test in the `contracts` crate must load all eleven schemas and run `validate.sh`'s examples through it.
2. Write the Rust types by hand in `domain`. Add a conformance test that deserializes every valid example into the matching type, serializes it back, and validates the result against the schema. Add a second test that proves each invalid example is also rejected by the Rust validator. This keeps the types and the schemas from drifting apart.
3. Agent output goes through the engine's validator, never through the provider's. Both agent command line tools have a structured-output option (`--json-schema` for Claude Code, `--output-schema` for Codex). Whether they accept these schemas, which use `if/then`, `oneOf` and `not`, is unverified. If they do not, the runtime adapter passes a reduced schema as a hint and the engine still validates against the full one.

## Changing a schema

1. Write or change the invalid example first, with its `.expect` file, and watch `validate.sh` fail.
2. Change the schema until it passes.
3. If a shared definition changed, change it in every schema that uses it.
4. Update the Rust types and conformance tests in the same pull request.
5. A change in meaning is a new version, not an edit. Ask the software architect to review it.

An optional field keeps the version. Tightening a rule normally means a new version, because documents written under the old rule must stay valid. On 2026-10-27 the integer bounds of the ledger entry were added to version 1 without a new version, because no ledger entry exists outside these examples and the Rust code already refused the same numbers when it computed the hash. The bound moves the refusal to validation time and rejects nothing that could have been hashed.
