# Agent definitions

This directory holds the agents the factory runs in Slice 1: for each one a manifest, a versioned prompt, the schemas of what it receives and returns, and a few conformance fixtures. The capability profiles are in [`../profiles`](../profiles). `FileAgentRegistry` in [the contracts crate](../crates/contracts/src/registry.rs) loads both directories and refuses a prompt whose hash differs from its manifest.

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

## The nine agents

Placements are the sandbox only. No agent can merge, push, deploy, change a policy or a gate file, or start another agent.

| Agent | Role | Stage | Tools | Returns |
|---|---|---|---|---|
| `intake-classifier` | `intake` | intake | result channel only | `intake-classification` |
| `specification-writer` | `specification_writer` | specification | read, write its own spec files, Spec Kit helper scripts | `specification-report` |
| `specification-reviewer` | `specification_reviewer` | specification | read `specs/` | `review-findings` |
| `architect` | `architect` | architecture | read | `architecture-design` |
| `planner` | `planner` | task planning | read | `planner-result` (a `task-dag` inside) |
| `builder` | `builder` | implementation | read, write `src/` and `tests/`, project commands | `builder-report` |
| `code-reviewer` | `code_reviewer` | review | read | `review-findings` |
| `documentation-writer` | `technical_writer` | documenting | read, write README, changelog and `docs/` Markdown | `documentation-report` |
| `documentation-reviewer` | `documentation_reviewer` | documentation review | read | `review-findings` |

Tool names are the ids in the tool table of [`policies/security.yaml`](../policies/security.yaml). The manifest declares what an agent may hold, and the policy engine still decides what a stage grants. `report.submit` is declared with `read` access because it writes no workspace file. The Spec Kit skills (`speckit.*`) appear only in the specification writer, because every other stage runs with skills off ([the spike](../docs/spikes/agent-runtime.md), section 4.6).

Each agent lists `recommended_models` with a cheaper starting model and a larger model to escalate to after two failed repairs. Both tools default to the most expensive model, so the manifests name the models explicitly. Only models named in the recorded runs are used.

## How a prompt is built

Every prompt has the same sections in the same order: role and boundaries, how to treat untrusted data, input contract, output contract, evidence required, stop conditions, when information is missing, untrusted data, and end of data. The second section is one fixed text, identical in all nine prompts.

The data goes in last. Under "Untrusted data" the prompt has one line `{{input.<name>}}` for each input of its table, and nothing else. Whoever assembles the prompt replaces each of those lines with a block:

```text
<<<DATA name=request class=issue_text bytes=120 sha256=sha256:... stripped=0>>>
> first line of the text
> second line of the text
<<<END name=request>>>
```

Every line of data starts with `> `, so no line of data can look like a delimiter. Line breaks of every kind become line breaks, and hidden or direction-control characters are removed. The reference renderer in `crates/contracts/tests/agent_defs/render.rs` states these rules, and the real assembly (`s1-prompt-assembly`) has to keep them.

Reviewers get a short, closed list of inputs: the frozen specification, the diff, the gate reports and a few plain files. They never get the builder's or the writer's summary, and they hold no tool that reads version control history.

## Adding or changing an agent

1. Write the test that should fail first. Put the agent in `SLICE_1_AGENTS` and `OUTPUT_SCHEMA_OF` in `crates/contracts/tests/agent_defs/mod.rs` and in `STAGE_OF_ROLE` in `agent_defs/checks.rs`.
2. Write the input and output schemas in `agents/schemas/`. The input schema lists exactly the inputs of the prompt table.
3. Write `prompt.md` with the sections above. Copy the fixed instruction from an existing prompt, and give each input a class from `untrusted_content.classes` in the security policy.
4. Write `manifest.json`. Give the agent the fewest tools and the narrowest paths that its work needs, and check the tool and role against the policy's tool table.
5. Run `python3 -I agents/refresh_hashes.py`, then add `fixtures/valid/` and `fixtures/invalid/`.
6. Run `cargo nextest run -p factory-contracts --test repo_definitions --test prompt_rendering --test agent_conformance`.

When you change a prompt, raise `prompt.template_version` and the `Prompt version:` line together, run the hash script and commit the manifest in the same change. A change that alters behavior also raises the manifest `version`.

## Open points for other packages

- The tool table in the security policy lists no `specification_writer` or `specification_reviewer` role, so the policy engine would deny both. The tests record the gap in `KNOWN_POLICY_GAPS` and fail when the policy closes it.
- The planner's `plan_metadata` input carries the identifiers the stage assigns. The stage compares the copy in the plan with its own values.
- The agent schemas live here and not in `schemas/`, because that directory is owned elsewhere. If the stage packages want them as contract kinds, promote them through a reviewed change.
- Both profiles are drafts. To make one active, a reviewer adds the `review` block and sets the status in the pull request that approves it.
