# Prepare a repository for the factory

- Status: written on 2026-11-11 from the code that reads the project manifest, the JSON schema `schemas/project-manifest.schema.json` and the fixture repository `fixtures/repos/word-count`. Each statement below names the file it was read from. Nothing here was run against a real repository: the only manifest the factory has read is the fixture's, in test mode.
- Form: how-to, with a reference table of the keys.
- Goal: give a repository the one file the validation stage needs, and say what the factory can and cannot check in that repository today.

**Objective.** The protected default branch of the repository holds a valid `.factory/project.yaml`, and its test names can count as acceptance evidence.
**Done when.** The file is merged to the default branch, it passes the schema, and it defines a `build` gate and a `unit-tests` gate that the command policy allows.

This guide is one part of onboarding. The [onboarding guide](onboarding.md) installs the design tools and registers the repository. The [production guide](production.md) lists what a person must supply before a live run.

## What the file is

`.factory/project.yaml` is the project manifest. It is the project's own configuration for the factory, and the repository keeps it. The factory also accepts the same content as JSON in `.factory/project.json`, and it looks for the YAML file first (`crates/workflow/src/gates/command/definition.rs`).

The manifest matters most in the validation stage. That stage takes its gate commands from the `gates` list of the manifest. A gate is a program with its arguments, a working directory and a time limit. Without the manifest the stage has no build command and no test command to run.

Neither `scripts/install.sh` nor the files under `onboarding/` create the manifest. A person writes it and merges it.

## Where the factory reads it from

The validation stage reads the manifest at the base commit of the job. The base commit is on the protected default branch. It never reads the manifest from the commit that the builder agent made (`load_definitions` in `crates/workflow/src/stages/validation/handler.rs`).

Three things follow.

- The manifest must be merged to the default branch before the first job. A manifest that exists only on a feature branch is not seen.
- A job cannot change its own gates. An edit of the manifest inside a job changes nothing that runs in that job.
- The central policy protects `.factory/**` with the mode `deny_write` (group `factory_config` in `policies/security.yaml`), so a change by the builder to that folder is refused.

The stage reads at most 256 KiB of the file (`max_manifest_bytes` in `crates/workflow/src/stages/validation/config.rs`).

## The keys

The Rust type is `ProjectManifest` in `crates/domain/src/contracts/project_manifest.rs`, and the schema is `schemas/project-manifest.schema.json`. Every key in the table is required unless the table says otherwise. An unknown key is an error at every level.

The last column says what reads the key today. "Checked only" means that the loader validates the value and no product code was found that uses it afterwards.

| Key | What it holds | What reads it today |
|---|---|---|
| `schema_version` | Always `1`. | Checked only. |
| `project.name` | A machine name: lower-case letters, digits, dot, underscore and hyphen. | Checked only. |
| `project.title` | A short plain-English title, 3 to 100 characters. | Checked only. |
| `project.domain_tags` | At least one tag, each a machine name, with no repeats. | Checked only. |
| `project.default_branch` | The name of the default branch. | Checked only. The branch the factory uses comes from the registration of the repository. |
| `sandbox.image` | A logical image name. | Checked only. The image that runs the gates comes from the factory's own configuration and its image catalog. |
| `sandbox.workdir` | An absolute path inside the container. | Checked only. |
| `gates` | A list with at least one entry. At least one entry must have `mandatory: true`. | The validation stage, and the repository intelligence stage for the build and test commands. |
| `gates[].id` | A machine name. Four names have a meaning: `format`, `lint`, `build` and `unit-tests`. | The validation stage. See the next section. |
| `gates[].title` | A short plain-English title. | The gate report. |
| `gates[].argv` | The program and its arguments, as a list. The first element must not be a shell (`sh`, `bash`, `zsh`, `fish`, `dash`, `cmd`, `powershell`, `pwsh`). | The validation stage, after the command policy has allowed it. |
| `gates[].cwd` | Optional. A directory relative to the repository. The default is the repository root. | The validation stage. |
| `gates[].timeout_seconds` | A whole number from 1 to 7200. | The validation stage. |
| `gates[].mandatory` | `true` or `false`. | Checked only. The stage does not read it. See the next section. |
| `protected_paths` | A list of path patterns with no repeats. It must contain `.factory/**`. | The repository intelligence stage records each pattern in the repository profile. The gate that refuses a change to a protected path uses the central policy, not this list. |
| `spec_kit.cli_version` | The pinned version of the Spec Kit command line tool, for example `1.1.2`. | Checked only. |
| `spec_kit.integration` | The name of the integration. | Checked only. |
| `spec_kit.may_initialize` | `true` or `false`. | Checked only. |
| `documentation.required_documents` | A list of entries with a `path` and a `purpose`. The purpose is 10 to 4000 characters. The list may be empty. | Checked only. |
| `documentation.changelog_path` | The path of the changelog. | Checked only. |
| `documentation.disabled_readability_rules` | Optional. The only value allowed is `title-type-tag`. | A function reads it (`crates/workflow/src/gates/readability/options.rs`). Only a test calls that function today. |

A key that is "checked only" still has to be right. A manifest that fails the schema is not read at all, and the gates are then BLOCKED.

## How the validation stage uses the gates

The stage knows four gate names (`gate_id` in `crates/workflow/src/gates/command/definition.rs`, and `crates/workflow/src/stages/validation/set.rs`).

| Gate `id` | When the manifest has no entry with this name | How the result is read |
|---|---|---|
| `format` | The gate is reported as not defined. That is allowed. | Exit code. |
| `lint` | The gate is reported as not defined. That is allowed. | Exit code. |
| `build` | The gate is BLOCKED. | Exit code. |
| `unit-tests` | The gate is BLOCKED. | The output must show tests that ran. See "Limits that exist today". |

An entry with any other name also runs, and it passes on exit code 0.

Four rules apply to every entry.

- **The name decides, not `mandatory`.** `build` and `unit-tests` are required because the stage says so. Setting `mandatory: false` on them does not make them optional.
- **The command policy decides what may run.** Every `argv` passes through the command policy of `policies/security.yaml` for the `verify` profile. A command that the policy denies, or that needs a person, is BLOCKED.
- **Cargo runs offline.** The policy adds `--offline --locked` to every `cargo` command of that profile, except `cargo fmt`, which does not accept them. Cargo then needs a `Cargo.lock` in the repository that is up to date.
- **The tool must be in the image.** Before a gate runs, the stage runs the program with `--version` in the verify image. A program that is missing makes the gate BLOCKED.

The stage runs the `unit-tests` gate twice: on the commit of the job and on the base commit. It compares the two results, and the `test-file-protection` gate uses the comparison.

## A complete example

This is the manifest of the fixture repository, `fixtures/repos/word-count/.factory/project.yaml`, as it is in this repository.

```yaml
schema_version: 1
project:
  name: word-count
  title: Word count command line tool
  domain_tags: [general-software, command-line-tool]
  default_branch: main
sandbox:
  image: rust-fixture
  workdir: /workspace
gates:
  - id: format
    title: Check formatting
    argv: [cargo, fmt, --check]
    timeout_seconds: 120
    mandatory: false
  - id: lint
    title: Check the code with the linter
    argv: [cargo, clippy, --all-targets, --locked, --, -D, warnings]
    timeout_seconds: 600
    mandatory: false
  - id: build
    title: Build the project
    argv: [cargo, build, --locked]
    timeout_seconds: 600
    mandatory: true
  - id: unit-tests
    title: Run the unit and integration tests
    argv: [cargo, test, --locked]
    timeout_seconds: 900
    mandatory: true
protected_paths:
  - ".factory/**"
  - ".github/**"
  - CODEOWNERS
  - "tests/golden/**"
spec_kit:
  cli_version: "1.1.2"
  integration: claude
  may_initialize: true
documentation:
  required_documents:
    - path: README.md
      purpose: Explains what the tool does, how to install it and how to use every option.
  changelog_path: CHANGELOG.md
```

The next command shows that the fixture still defines the four gates that the example lists.

```bash run expect="format" expect="lint" expect="build" expect="unit-tests"
grep -- "- id:" fixtures/repos/word-count/.factory/project.yaml
```

## What happens when the file is missing or wrong

| Situation | What the validation stage reports |
|---|---|
| Neither `.factory/project.yaml` nor `.factory/project.json` is at the base commit | `format`, `lint`, `build` and `unit-tests` are BLOCKED with the reason "The gate definitions could not be read from the protected base commit, so the gate cannot run." |
| The file is there and is not valid | The same four gates are BLOCKED with the same reason. |
| The file is valid and has no `build` or no `unit-tests` entry | That gate is BLOCKED. |
| The command policy refuses the command of an entry | That gate is BLOCKED. |

When the `unit-tests` gate did not run, the `acceptance-evidence` gate is BLOCKED too. It needs a verified test run of the change and a verified test run of the base commit, and it is BLOCKED when either one is missing or cannot be read.

BLOCKED is never a pass. A gate that could not run has shown nothing.

The repository intelligence stage runs earlier and behaves differently. With no manifest it looks for a build system it knows and proposes commands from that. With a manifest that is not valid it stops, and the stage is BLOCKED (`crates/workflow/src/stages/repo_intel/handler.rs`). Its proposal does not replace the manifest. The validation stage takes gate commands from the manifest only.

## Tests that count as acceptance evidence

The specification of a job lists requirements, and each has an identifier such as `FR-001`. The `acceptance-evidence` gate passes only when every requirement has at least one test that names it, that ran and passed on the change, and that did not pass on the base commit (`crates/workflow/src/gates/scope/acceptance.rs`).

A test names a requirement by carrying the identifier in its own name. The gate compares in lower case and reads every character that is not a letter or a digit as an underscore. The identifier must be a whole token of the name.

| Requirement | Test name | Names the requirement |
|---|---|---|
| `FR-001` | `fr_001_counts_a_line` | Yes. |
| `FR-001` | `counts_a_line_fr_001` | Yes. |
| `FR-001` | `fr_0011_counts_a_line` | No. `fr_0011` is another token. |
| `FR-001` | `counts_a_line` | No. The name does not carry the identifier. |

The identifier of an acceptance scenario of the requirement, such as `AS-001`, counts in the same way.

A name is not enough. The validation stage runs the tests twice: on the change, and on the base commit as it was before the change. A test that names a requirement counts only when the second run does not show it as passed.

| The test on the base commit | The test on the change | Counts for the requirement |
|---|---|---|
| Does not exist | Passed | Yes. The report says "new test". |
| Failed | Passed | Yes. The report says "failed on the base commit". |
| Ignored | Passed | Yes. The report says "ignored on the base commit". |
| Passed | Passed | No. The test passed before the change, so it shows nothing about the change. |
| Any | Failed or ignored | No. |

A requirement with no test that counts fails the gate. The failure says which of two things happened: no passed test names the requirement (`requirement-uncovered`), or the only tests that name it already passed on the base commit (`requirement-covered-only-by-old-tests`). The report lists, for each requirement, the tests that cover it and the reason each one counts, in the notes of its baseline comparison.

The builder agent writes these tests during the job. A repository that already uses this naming gives the agent a pattern to follow. A test that is already in the repository and already passes does not count for a later job, even when its name carries the identifier of that job's requirement.

A job that changes no behavior, such as a refactor, has no exemption. The change must add a test, named after the requirement, that pins the behavior the requirement asks to keep. No field of the specification lets a person say that a requirement needs no new test, and the gate does not take that from an agent.

The gate does not read what a test asserts. An empty new test that carries the identifier counts. The new tests are not run against the code of the base commit, so the gate does not show that a new test would fail without the change. A copy of an old test under a new name is a new test. The independent code reviewer is told to open each covering test that the report names and to report a test that asserts nothing, cannot fail or does not exercise the scenario. That is the judgment of a model and not a measurement.

## Make your workflows safe for factory branches

The factory pushes the code of a job to a branch named `factory/job-<id>` of your repository and opens a draft pull request to your default branch. A model wrote that code. GitHub starts your `push` and `pull_request` workflows for it before a person has read it.

Before it admits a job, the factory reads the workflow files of your default branch (`.github/workflows/*.yml` and `*.yaml`). If one of them would run for a factory branch with a secret, a write token or a runner that is not GitHub's in reach, the repository runs at level `L0` and no pull request opens. Threat T-48 in the [threat model](../security/threat-model.md) has the full rules.

The two simplest fixes:

1. **A workflow that needs secrets: leave factory branches out of its `push` trigger.**

   ```yaml
   on:
     push:
       branches-ignore: ['factory/**']
   ```

   A `push` trigger that lists its branches, such as `branches: [main]`, is safe already. Do not give such a workflow a `pull_request` trigger for your default branch.

2. **A pull request check: give it a read-only token and no secret.**

   ```yaml
   on:
     pull_request:

   permissions:
     contents: read

   jobs:
     test:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - run: make test
   ```

   Write `permissions` at the top of the file, name a runner of GitHub (`ubuntu-*`, `windows-*` or `macos-*`) in every job, and read no `secrets.` value except `secrets.GITHUB_TOKEN`.

What the check counts as exposed even if you think it is safe:

- a job behind an `environment:`, because the factory cannot read the protection of an environment;
- `runs-on: ${{ matrix.os }}` or any other expression, a runner group, and a runner label of your own;
- the trigger `pull_request_target`, and a job that calls a reusable workflow;
- a `branches` list that takes factory branches back out with a `!` pattern: use `branches-ignore`, or list the branches by name;
- a workflow that uses YAML anchors or aliases, and any file the check cannot parse.

If such a workflow is exposed on purpose, the operator of the factory can record your acknowledgement of it. The [production guide](production.md#what-the-factory-checks-and-what-it-does-not) says how.

The check reads files and not settings. It cannot see the secrets policy of your organization, the default permissions of the workflow token, or what a script that your workflow runs does. A workflow that passes the check still runs code that a model wrote.

## Limits that exist today

The factory was built and tested against one Rust fixture. Two gates read Rust tooling only.

- **The test gate reads the output of the Rust test harness only.** The `unit-tests` gate parses the output of `cargo test`, which the harness named libtest prints (`crates/workflow/src/gates/command/libtest.rs`). A test command that prints another format is not read as tests that ran, and the gate is BLOCKED (`crates/workflow/src/gates/command/verdict.rs`). A repository whose tests run under pytest, Jest, Go or JUnit cannot pass this gate today.
- **The supply-chain gate reads Cargo only.** The module says "Only Cargo is implemented" (`crates/workflow/src/gates/supply_chain/mod.rs`). Dependencies declared for npm, pip or Go are not checked by it.
- **The acceptance rule depends on the test gate.** It reads the test names from the same parsed output, for the change and for the base commit, so it has the same limit.

The `format`, `lint` and `build` gates read an exit code, so they can run any program that the command policy allows and the verify image holds. The image and the policy were written for Rust.

## Related

- [Onboarding guide](onboarding.md): install the design tools, map the project and register the repository.
- [Production guide](production.md): what a person must supply before a live run.
- [Policy reference](../reference/policies.md): the files that control the factory, including the command policy.
- [Artifacts reference](../reference/artifacts.md): the gate reports that the validation stage stores.
