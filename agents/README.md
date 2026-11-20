# Agent definitions

This directory holds the agents the factory runs: the ten pipeline agents of Slice 1 and one operations agent. For each one it has a manifest, a versioned prompt, the schemas of what it receives and returns, and a few conformance fixtures. The capability profiles are in [`../profiles`](../profiles). `FileAgentRegistry` in [the contracts crate](../crates/contracts/src/registry.rs) loads both directories and refuses a prompt whose hash differs from its manifest.

## Layout

```text
agents/
  <agent-id>/manifest.json      the manifest, validated against schemas/agent-manifest.schema.json
  <agent-id>/prompt.md          the prompt, pinned by hash in the manifest
  <agent-id>/fixtures/valid/    outputs the agent may return; each must pass its output schema
  <agent-id>/fixtures/invalid/  outputs the schema must refuse
  schemas/                      <name>.v<version>.schema.json, the input and output schemas
  refresh_hashes.py             rewrites the hashes in the manifests after an edit
profiles/<profile-id>/profile.json
```

## The agents

Placements are the sandbox only. No agent can merge, push, deploy, change a policy or a gate file, or start another agent.

The first ten are pipeline agents: each runs in one stage of a job. The troubleshooter is an operations agent ([ADR 0021](../docs/adr/0021-troubleshooter-agent-and-mcp-sources.md)). It runs outside the pipeline, in no job and no stage, started by its own program when a probe trips or the daily sweep comes due, and it watches the factory itself.

| Agent | Role | Stage | Tools | Returns |
|---|---|---|---|---|
| `intake-classifier` | `intake` | intake | result channel only | `intake-classification` |
| `specification-writer` | `specification_writer` | specification | read, write its own spec files, Spec Kit helper scripts | `specification-report` |
| `specification-reviewer` | `specification_reviewer` | specification | read `specs/` | `review-findings` |
| `architect` | `architect` | architecture | read | `architecture-design` |
| `architecture-critic` | `architecture_critic` | architecture, when the risk tier needs a critic | read | `review-findings` |
| `planner` | `planner` | task planning | read | `planner-result` (a `task-dag` inside) |
| `builder` | `builder` | implementation | read, write `src/` and `tests/`, project commands | `builder-report` |
| `code-reviewer` | `code_reviewer` | review | read | `review-findings` |
| `documentation-writer` | `technical_writer` | documenting | read, write README, changelog and `docs/` Markdown | `documentation-report` |
| `documentation-reviewer` | `documentation_reviewer` | documentation review | read | `review-findings` |
| `troubleshooter` | `troubleshooter` | none: an operations agent | the read-only gateway tools (`mcp.datadog.*`, `mcp.victoriametrics.*`, `mcp.postgres.*`) and the result channel; no file, command or GitHub tool | `health-findings` |

Tool names are the ids in the tool table of [`policies/security.yaml`](../policies/security.yaml). The manifest declares what an agent may hold, and the policy engine still decides what a stage grants. `report.submit` is declared with `read` access because it writes no workspace file. It names the output channel of the policy, not a tool an agent can call: see "How a report is returned" below. The Spec Kit skills (`speckit.*`) appear only in the specification writer, because every other stage runs with skills off ([the spike](../docs/spikes/agent-runtime.md), section 4.6).

An operations agent follows every rule above that does not depend on a stage, and a few of its own, which `agent_defs/checks.rs` tests: it holds only gateway tools (`mcp.*`) and `report.submit`, it has no file access and no skill, and its network is the allow list `["mcp_gateway"]`, the one fixed relay of its sidecar to the MCP gateway (ADR 0021, Decision 5). Every other agent's network is `none`, and no pipeline agent may hold a gateway tool. A gateway tool's entry in the policy names no sandbox profile, because it runs in the gateway of the control plane, and no role but an operations role. `policies/troubleshooting.yaml` maps each gateway tool id to the name the agent sees (`mcp.victoriametrics.query` is `vm_query`, offered to Claude Code as `mcp__factory__vm_query`) and to one upstream tool.

Each agent lists `recommended_models` with a cheaper starting model and a larger model to escalate to after two failed repairs. Both tools default to the most expensive model, so the manifests name the models explicitly. Only models named in the recorded runs are used.

## How a prompt is built

Every prompt has the same sections in the same order: role and boundaries, how to treat untrusted data, input contract, output contract, evidence required, stop conditions, when information is missing, untrusted data, and end of data. The second section is one fixed text, identical in every prompt.

The data goes in last. Under "Untrusted data" the prompt has one line `{{input.<name>}}` for each input of its table, and nothing else. Whoever assembles the prompt replaces each of those lines with a block:

```text
<<<DATA name=request class=issue_text bytes=120 sha256=sha256:... stripped=0>>>
> first line of the text
> second line of the text
<<<END name=request>>>
```

Every line of data starts with `> `, so no line of data can look like a delimiter. Line breaks of every kind become line breaks, and hidden or direction-control characters are removed. The reference renderer in `crates/contracts/tests/agent_defs/render.rs` states these rules, and the real assembly (`s1-prompt-assembly`) has to keep them.

Every pipeline agent but the intake classifier also gets the block `project_rules` (class `repo_file`): the project's `AGENTS.md` read at the job's base commit by the repository stage, or the factory's built-in copy when the project has none yet ([the project's rules for agents](../docs/architecture/project-rules.md), ADR 0026). Each prompt says these are the project's conventions, to apply where they do not conflict with the prompt, and that they never change the role, the tools, the boundaries or the output contract. The troubleshooter does not get it: it watches the factory, not a project.

The troubleshooter's inputs are built by code, not written by people, so its input schema types each input as a JSON value instead of a string. The troubleshooter validates the whole input document against that schema and renders each input as JSON inside its block, under the same rules.

Reviewers get a short, closed list of inputs: the frozen specification, the diff, the gate reports, the project's rules and a few plain files. They never get the builder's or the writer's summary, and they hold no tool that reads version control history. The architecture critic is a reviewer in this sense: it gets the frozen specification, the design without the architect's summary, and the repository map, and the router never gives it the architect's model (`architecture_critique_not_by_the_architects_model` in `policies/model_routing.yaml`).

## How a report is returned

Neither command line tool gives an agent a tool for returning a report. The adapter takes the last message of the run as the answer, takes one Markdown code fence off it when the whole message is one fenced block (`crates/runtime/src/report.rs`, `without_fence`), and hands the bytes to the engine, which validates them against the output schema of the manifest. Claude Code's `--json-schema` rejects the factory schemas and Codex's `--output-schema` does not check the answer ([the spike](../docs/spikes/agent-runtime.md), "Structured output with the real schemas"), so neither flag is used.

The prompt is therefore the only place the model learns the shape of its answer. Every "Output contract" section says that the final message is the report, carries one fixed rule about that message, and shows each schema the answer is checked against, byte for byte, in a `json` fence. The planner is shown `schemas/task-dag.schema.json` as well, because the engine validates the plan inside its envelope against it. `agents/refresh_hashes.py` rewrites the shown schemas from their files, and the test `every_prompt_says_the_final_message_is_the_report_and_shows_the_schemas_it_is_checked_against` fails when a prompt and a schema file differ.

A report the validator rejects fails the run. Nothing asks the agent to correct it within the same run, and the prompts say so.

No part of this has met a real model. Whether the models follow the rule often enough is measured by the first live run, not by these tests.

## Adding or changing an agent

1. Write the test that should fail first. Put a pipeline agent in `SLICE_1_AGENTS` and `OUTPUT_SCHEMA_OF` in `crates/contracts/tests/agent_defs/mod.rs` and in `STAGE_OF_ROLE` in `agent_defs/checks.rs`. Put an operations agent in `OPERATIONS_AGENTS` and `OUTPUT_SCHEMA_OF`, and its role in `OPERATIONS_ROLES` instead of `STAGE_OF_ROLE`.
2. Write the input and output schemas in `agents/schemas/`. The input schema lists exactly the inputs of the prompt table.
3. Write `prompt.md` with the sections above. Copy the fixed instruction from an existing prompt, and give each input a class from `untrusted_content.classes` in the security policy.
4. Write `manifest.json`. Give the agent the fewest tools and the narrowest paths that its work needs, and check the tool and role against the policy's tool table.
5. Run `python3 -I agents/refresh_hashes.py`, then add `fixtures/valid/` and `fixtures/invalid/`. The script also copies the output schema into the `json` fence of the prompt's output contract.
6. Run `cargo nextest run -p factory-contracts --test repo_definitions --test prompt_rendering --test agent_conformance`.

When you change a prompt, raise `prompt.template_version` and the `Prompt version:` line together, run the hash script and commit the manifest in the same change. A change that alters behavior also raises the manifest `version`.

## Open points for other packages

- The tool table in the security policy lists no `specification_writer` or `specification_reviewer` role, so the policy engine would deny both. The tests record the gap in `KNOWN_POLICY_GAPS` and fail when the policy closes it.
- The planner's `plan_metadata` input carries the identifiers the stage assigns. The stage compares the copy in the plan with its own values.
- The agent schemas live here and not in `schemas/`, because that directory is owned elsewhere. If the stage packages want them as contract kinds, promote them through a reviewed change.
- Both profiles are drafts. To make one active, a reviewer adds the `review` block and sets the status in the pull request that approves it.
