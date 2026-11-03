# Spec Kit integration guide

This guide is for the engineers building the `spec_adapter` crate and the specification gate. It records what the installed GitHub Spec Kit actually does, so the adapter can be built against facts and not against memory of other versions.

The master prompt requires the factory to use the real, installed Spec Kit and not to invent commands (sections 0 and 4). Everything below was checked on 2026-10-27 against the versions in the table that follows.

| Component | Version | Where it came from |
| --- | --- | --- |
| Spec Kit CLI (`specify`) | 1.1.2 | `specify --version` |
| Claude Code | 2.1.311 | `claude --version` |
| Codex CLI | 0.163.0 | `codex --version` |
| Python used by `specify` | 3.14.3 | `specify version --json` |
| Machine | macOS (Darwin 25.3.0), arm64 | `specify version --json` |

## How to read the evidence tags

Each claim carries one of three tags.

- **Verified**: I ran the command or read the installed file. The command or path is given.
- **Documented only**: taken from `--help` output or from documentation shipped inside the installed package, but not exercised.
- **Unverified**: not checked. Section 12 lists every unverified item in one place. Do not build on these without testing them first.

## 1. What to know before reading further

1. **Spec Kit skills are prompts, not commands.** `specify` installs files. It has no subcommand that writes a specification. The specification is written by a coding agent (Claude Code or Codex) that reads a `SKILL.md` file and carries out the procedure in it. The factory drives the specification stage by running a host agent headlessly with a skill invocation as the prompt. The installed package says the same: "These are agent skills, not terminal commands." (Verified, package `METADATA`.)
2. **Skill execution is not deterministic.** The same skill writes slightly different files and runs different shell commands on different hosts and different runs. For example, Claude wrote `.specify/feature.json` with a shell redirect, Codex wrote it with a Python snippet, and the `Feature Branch` field in `spec.md` held the directory name on Claude and the text `main (existing branch; ...)` on Codex. The adapter must check the result of every skill run against deterministic post-conditions (section 8.4) and must never trust the agent's own summary.
3. **The active feature does not come from git.** It comes from the `SPECIFY_FEATURE_DIRECTORY` environment variable, then from `.specify/feature.json`, and otherwise fails. The git branch is never read. See section 7.
4. **`/speckit-checklist` cannot finish its own setup step without a `plan.md`.** The factory does not create plans with Spec Kit, so this is a real incompatibility. See section 11.1.
5. **`/speckit-clarify` is interactive.** It asks one question at a time, up to five per run, and waits for an answer. A headless driver must answer each question or hand it to a human. See section 8.3.
6. **Two Spec Kit assets must never run in the factory.** The bundled workflow `speckit` (`specify workflow run speckit`) runs specify, plan, tasks and implement in sequence. The skill `speckit-taskstoissues` creates GitHub issues titled `T001: ...`, which breaks the readable-title policy.
7. **Initialisation is deterministic and checkable.** Two independent `specify init` runs produced identical file hashes, and `specify integration status --json` reports drift.
8. **The whole specification flow is cheap.** Constitution, specify, clarify (3 questions) and checklist for the Slice 1 feature took 7 conversation turns, about 3.7 minutes and 0.89 US dollars on Claude Sonnet 5.5. See section 8.5.

## 2. Version, provenance and pinning

Verified commands:

```text
$ specify --version
specify 1.1.2

$ specify version --json
{
  "cli_version": "1.1.2",
  "runtime": { "python": "3.14.3", "openssl": "OpenSSL 3.5.5 27 Jan 2026" },
  "system": { "platform": "Darwin", "architecture": "arm64", "os_version": "Darwin Kernel Version 25.3.0: ..." },
  "features": {
    "controlled_multi_install_integrations": true,
    "integration_use_command": true,
    "multi_install_safe_registry_metadata": true,
    "integration_upgrade_command": true,
    "self_check_command": true,
    "workflow_catalog": true,
    "bundled_templates": true
  }
}
```

Provenance of the installed CLI, from the package files on this machine:

- Installed as a `uv` tool. The receipt `~/.local/share/uv/tools/specify-cli/uv-receipt.toml` records `requirements = [{ name = "specify-cli" }]` with no version pin and no source URL.
- The package metadata reads `Name: specify-cli`, `Version: 1.1.2`, `Summary: Specify CLI, part of GitHub Spec Kit`. There is no `direct_url.json`, so it was installed from a package index, not from a Git URL.
- The shipped README gives the install command as `uv tool install specify-cli` and says Python 3.11 or newer is required.
- I did not compare the package against a GitHub release or signature. That the PyPI package is the official one rests on its metadata and README only. **Unverified**: package authenticity.

Pinning rules for the adapter:

1. Install with an exact version, for example `uv tool install specify-cli==1.1.2`. The pinned form is **Unverified** (I did not run an install); the unpinned `uv tool install specify-cli` is **Documented only**.
2. Record the CLI version in the factory's compatibility matrix as a tuple of (`specify` version, host name, host version). Refuse to run the specification stage when the tuple is not in the matrix.
3. After init, the project records the version in three places: `.specify/init-options.json` (`speckit_version`), `.specify/integration.json` (`version`) and each file under `.specify/integrations/*.manifest.json` (`version`). All three read `1.1.2`. Compare them with the installed CLI before every run.
4. Pin skill content by hash. The manifests store a SHA-256 for every installed file. Appendix A lists them for Claude Code and Codex. The Claude Code hashes were identical across two separate init runs, so they make a stable golden test.
5. Never run `specify self upgrade` or `specify self check` from the factory. Both are network operations and the first one changes the installation. **Documented only**: `specify self upgrade --help` says a bare call executes immediately with no confirmation, and supports `--dry-run`.

## 3. Detect, install and verify procedure

Run these in order. Stop at the first failure and report it in plain English. A missing or incompatible Spec Kit blocks the job and never falls back to a generic spec writer.

```text
1. specify --version                      # exit 0; parse "specify X.Y.Z"
2. specify version --json                 # machine-readable; check cli_version and features
3. claude --version / codex --version     # the host CLI that will run the skills
4. specify init --here --force --non-interactive --integration <key>
                                          # only for an uninitialised repository (see 3.2)
5. specify integration status --json      # status must be "ok"
6. compare pinned hashes (Appendix A) and the three version fields
```

### 3.1 Host detection

`specify check` prints a table of host CLIs. It has no `--json` option, so parse it only for display. Verified output on this machine (trimmed):

```text
Check Available Tools
├── ● Claude Code (available)
├── ● Codex CLI (available)
├── ● Gemini CLI (available)
├── ● Antigravity (available)
├── ● Docker Agent (available)
├── ● Grok Build (available)
├── ○ GitHub Copilot (IDE-based, no CLI check)
...
Specify CLI is ready to use!
Tip: Run 'specify self check' to verify you have the latest CLI version
```

For decisions, run the host CLI directly (`claude --version`, `codex --version`) and probe capabilities as described in section 8.

### 3.2 Initialisation

The command that worked for both hosts:

```text
specify init --here --force --non-interactive --integration claude
specify init --here --force --non-interactive --integration codex
```

Verified facts about `init`:

- `--integration` is mandatory in practice. Without it, a non-interactive init silently selects GitHub Copilot and writes `.github/skills/speckit-*`. I ran `specify init probe-default --non-interactive` and got `Selected coding agent integration: copilot`.
- `--here` initialises the current directory. `--force` is required when the directory is not empty. Without it, a non-interactive run stops with `Error: Current directory is not empty and --non-interactive was set. Re-run with --force to merge into it.`
- `init` does not run `git init`, does not create a branch and does not commit. A new project directory created by `specify init <name>` was not a Git repository afterwards (`fatal: not a git repository`), and an existing repository kept its branch and history.
- `init` does not write `CLAUDE.md` or `AGENTS.md`. The integration is the skills directory plus `.specify/`.
- `init` left `README.md`, `.gitignore` and the master prompt byte-identical. I checked SHA-256 before and after in the two throwaway repositories and in this repository. This is verified only for the case where no managed path already existed.
- Re-running `init --here --force` over an initialised project **restores installed files to their original content**. I appended a line to `.claude/skills/speckit-specify/SKILL.md`, re-ran init, and the line was gone. It did not touch `.specify/memory/constitution.md`, `specs/` or `.specify/feature.json`. So the adapter must not call `init` on an already initialised repository. Use `specify integration status --json` to inspect and `specify integration upgrade` to change.
- Exit code was 0 in every successful run. **Unverified**: exit codes on failure other than the not-empty case above.
- The help text says project files "are scaffolded from assets bundled inside the specify-cli package, so initialization does not need network access". **Documented only**: I did not run init with the network disabled.

### 3.3 Integrity check

`specify integration status --json` is the supported way to detect drift. Healthy output:

```json
{
  "status": "ok",
  "default_integration": "claude",
  "installed_integrations": ["claude"],
  "multi_install_safe": true,
  "missing_managed_files": 0,
  "modified_managed_files": 0,
  "findings": []
}
```

After I appended one line to an installed skill, the same command returned `"status": "warning"`, `"modified_managed_files": 1` and a finding with code `managed-files-modified`, suggesting `specify integration upgrade --force`. Verified. The adapter should treat any status other than `ok` as a blocked job, because a modified skill changes what the agent will do.

The command only covers files that Spec Kit installed. It does not cover `.specify/memory/constitution.md`, anything under `specs/`, or `.specify/feature.json`.

### 3.4 Adding a second host later

`specify integration install codex` in a project that already has Claude installed added only the ten `.agents/skills/speckit-*/SKILL.md` files and `.specify/integrations/codex.manifest.json`. It left the default integration as `claude` and reported that 12 shared files "already exist and were not updated". Verified in a throwaway copy.

**Done in this repository on 2026-11-03** (Spec Kit 1.1.2, the pinned version; no network was used, the run took under a second). `specify integration install --help` lists `--script`, `--force` and `--integration-options` and no other flag. Both `claude` and `codex` show "Multi-install Safe: yes" in `specify integration list`, so `--force` was not needed and must not be used. The command changed three things: `.specify/integration.json` (the list `installed_integrations` is now `["claude","codex"]`, the default is still `claude`, and `integration_settings.codex.invoke_separator` is `"-"`), `.specify/integrations/codex.manifest.json` (new) and the ten files under `.agents/skills/` (new). `init-options.json`, the shared files and the Claude Code skills are byte for byte what they were. `specify integration status --json` reports `ok`, with three manifests checked (`claude`, `codex`, `speckit`) and nothing missing or modified. The full SHA-256 values are in the Codex manifest and in `crates/spec_adapter/src/pinned.rs` (`CODEX_SKILLS`). The test `pinned_tables_equal_the_manifests_of_this_repository` fails if a table, a manifest and a file disagree.

Two consequences of the second host:

* **The worker pins the Codex skills too.** `bundle_for_writer` (crate `composition`) refuses to build the specification stage's skills unless, for every skill the writer is given, the same skill under `.agents/skills` hashes to its pin. A listed Codex integration with a missing file is refused, an unlisted Codex directory is refused when a skill is there and not the pinned one, and an installed integration that is not in the host table (`claude`, `codex`) is refused because its skills have no pin. The worker prints `BLOCKED: agent runtime: protected_checkout: the Codex skill speckit-specify is not the pinned file` and exits with code 3. The six skills the writer is not given are covered by `check_installation` on each job, which compares all ten files of the host that runs the job.
* **The installer extends a project.** `scripts/install.sh --checkout PATH` adds the missing integration to a project that already has `.specify/`, with this same command, and reports a skill that is not the pinned file. See `docs/guides/claude-and-codex.md`.

## 4. Per-host invocation matrix

The internal command ids use dots (`speckit.specify`, as in `specify artifact list --json` and the workflow file). The host invocation uses a hyphen. The separator is stored per host in `.specify/integration.json` as `invoke_separator`, and was `"-"` for both Claude Code and Codex. The adapter must read that value and must not hard-code either form. The `/speckit.specify` form in the master prompt is not what 1.1.2 uses on these two hosts.

| Item | Claude Code 2.1.311 | Codex CLI 0.163.0 |
| --- | --- | --- |
| Init flag | `--integration claude` | `--integration codex` |
| Skill files | `.claude/skills/speckit-<name>/SKILL.md` | `.agents/skills/speckit-<name>/SKILL.md` |
| Invocation in chat | `/speckit-<name> <arguments>` | `$speckit-<name> <arguments>` |
| Extra frontmatter | `argument-hint`, `user-invocable: true`, `disable-model-invocation: false` | none |
| Body of the skill | identical to Codex after normalising the sigil and the three Claude-only frontmatter keys (diffed for all ten skills) | identical to Claude after the same normalisation |
| Discovery check | `system/init` event lists `speckit-*` in `skills` and `slash_commands` | `codex debug prompt-input` lists them under the project skill root, with no model call |
| Headless call | `claude -p --input-format stream-json --output-format stream-json ...` | `codex exec -C <dir> -s workspace-write --json -o <file> '$speckit-<name> ...'` |
| Result data | `result` event with cost, duration, turns, permission denials | `turn.completed.usage` with token counts; no cost |
| Skills exercised headlessly | constitution, specify, clarify, checklist | specify only |
| Interactive questions | handled by sending the next user message (Verified for clarify) | **Unverified** |

The `<name>` values installed on both hosts are `constitution`, `specify`, `clarify`, `checklist`, `plan`, `tasks`, `analyze`, `implement`, `converge` and `taskstoissues`.

Other hosts exist (`specify integration list` shows about 40 keys, for example `gemini`, `copilot`, `opencode`). **Unverified**: their syntax. Do not assume it matches.

Codex discovery evidence (Verified, no model call):

```text
$ codex debug prompt-input 'test'      # run inside a project initialised with --integration codex
...
- `r6` = `<project>/.agents/skills`
- speckit-specify: Create or update the feature specification from a natural language feature description. (file: r6/speckit-specify/SKILL.md)
```

## 5. What `specify init` writes

For `--integration claude` it adds 30 files and nothing else. Verified by diffing the file list before and after in this repository.

```text
.claude/skills/speckit-<name>/SKILL.md      10 files, one per skill
.specify/.gitignore                         ignores feature.json and per-machine extension overrides
.specify/init-options.json                  ai, integration, script, feature_numbering, speckit_version
.specify/integration.json                   installed integrations, default, invoke_separator, version
.specify/integrations/claude.manifest.json  SHA-256 of each installed skill file
.specify/integrations/speckit.manifest.json SHA-256 of each shared file below
.specify/memory/constitution.md             copy of the constitution template (placeholders)
.specify/memory/.constitution-template.json hash and source of the template
.specify/scripts/bash/                      check-prerequisites.sh, common.sh, create-new-feature.sh,
                                            resolve-template.sh, setup-plan.sh, setup-tasks.sh
.specify/templates/                         spec, checklist, constitution, plan, tasks templates
.specify/workflows/speckit/workflow.yml     the bundled specify-plan-tasks-implement workflow
.specify/workflows/workflow-registry.json
```

`init-options.json` on this repository:

```json
{ "ai": "claude", "ai_skills": true, "feature_numbering": "sequential",
  "here": true, "integration": "claude", "script": "sh", "speckit_version": "1.1.2" }
```

Files that exist only later:

| Path | Created by | Notes |
| --- | --- | --- |
| `specs/<NNN>-<short-name>/spec.md` | the specify skill | the feature specification |
| `specs/<NNN>-<short-name>/checklists/requirements.md` | the specify skill | built-in quality checklist |
| `specs/<NNN>-<short-name>/checklists/<domain>.md` | the checklist skill | reviewer-owned custom checklist |
| `.specify/feature.json` | the specify skill | the active-feature pointer; gitignored |
| `.specify/extensions.yml` | not created by init | hooks file; absent in this project (see 11.6) |

The installed `.specify/.gitignore` ignores `feature.json`. A fresh clone therefore has no active feature until the adapter sets one.

If a repository's own `.gitignore` ignores `.agents/`, the Codex integration's skills will not be committed. This repository's did (it kept the Solomon harness's local state there). On 2026-11-03 it was changed to track the Spec Kit skills only, and the Codex integration was added next to the Claude Code one. See sections 3.4 and 11.9.

## 6. Skill inventory and factory policy

All ten skills are installed by default. The factory uses four and must refuse the rest unless an explicit, audited compatibility setting enables them (master prompt section 4).

| Skill | What it does, from its `SKILL.md` | Factory policy |
| --- | --- | --- |
| `constitution` | Writes `.specify/memory/constitution.md` from the template and the supplied principles. Has a scope guard that refuses feature work. | **Use**, once per repository, human-approved |
| `specify` | Creates `specs/<NNN>-<name>/spec.md` and `checklists/requirements.md`, writes `.specify/feature.json`. Asks up to 3 questions when it finds `[NEEDS CLARIFICATION]` markers. | **Use** |
| `clarify` | Asks up to 5 questions, one at a time, and records answers under `## Clarifications` and in the requirements. Re-checks `checklists/requirements.md`. | **Use** when ambiguity is material |
| `checklist` | Writes a reviewer-owned requirements-quality checklist. Never ticks its own items. | **Use**, with the workaround in 11.1 |
| `plan` | Writes `plan.md`, `research.md`, `data-model.md`, `contracts/`, `quickstart.md`. | **Do not use.** The factory's architecture and planner stages own this. |
| `tasks` | Writes `tasks.md` from the plan. | **Do not use.** |
| `analyze` | Read-only consistency report across `spec.md`, `plan.md` and `tasks.md`. Requires all three. | **Do not use.** It cannot validate a specification alone, so the factory needs its own gate. |
| `implement` | Executes `tasks.md`. Also reads checklist ticks as a gate. | **Do not use.** |
| `converge` | Appends unbuilt work to `tasks.md`. | **Do not use.** |
| `taskstoissues` | Creates GitHub issues titled `T001: <description>`. | **Never use.** It breaks the plain-English title policy and creates external side effects. |

The bundled workflow in `.specify/workflows/speckit/workflow.yml` runs `speckit.specify`, a review gate, `speckit.plan`, a gate, `speckit.tasks` and `speckit.implement`. It is registered as "Full SDD Cycle". The adapter must never call `specify workflow run`. Verified by reading the file.

Optional extensions and presets add skills and hooks. The shipped README mentions `specify extension add bug` and an idea-assessment extension. None is installed (`specify extension list` and `specify preset list` both report none). The adapter should fail the integrity check if `.specify/extensions.yml` appears or if `specify extension list` stops reporting "No extensions installed."

## 7. Active-feature mechanics

Verified by reading `.specify/scripts/bash/common.sh` and by running `check-prerequisites.sh` in a throwaway project.

Resolution order, in `get_feature_paths`:

1. The `SPECIFY_FEATURE_DIRECTORY` environment variable, if set. A relative value is resolved under the repository root. The value is written to `.specify/feature.json` unless persistence is turned off.
2. The `feature_directory` key in `.specify/feature.json`.
3. Otherwise the script fails with `ERROR: Feature directory not found. Set SPECIFY_FEATURE_DIRECTORY or run the specify command to create .specify/feature.json.`

What does not matter:

- The git branch. `get_current_branch` returns only the `SPECIFY_FEATURE` variable or an empty string. Switching branches never changes the active feature. This matches the warning in the master prompt.
- The `Feature Branch` line inside `spec.md`. It is a text field the agent fills in. Claude wrote `001-end-to-end-mvp`; Codex wrote ``main (existing branch; no branch-creation hook configured)``. Do not parse it.

Other variables the scripts honour. These rows come from reading `common.sh`; I did not run them except where noted.

| Variable | Effect |
| --- | --- |
| `SPECIFY_INIT_DIR` | Points the scripts, and `specify integration` commands, at a project root that contains `.specify/`. Fails if the path is wrong. The CLI error text for `specify integration list` outside a project names it. Useful when the adapter runs from outside the repository. |
| `SPECIFY_FEATURE_NO_PERSIST=1` | No script call writes `.specify/feature.json`. Run: `check-prerequisites.sh --paths-only` never wrote it. |
| `SPECIFY_FEATURE` | Sets only the name shown as `CURRENT_BRANCH`. |

Observed behaviour:

- `check-prerequisites.sh --json --paths-only` with no environment variable and no `feature.json` exits 1 with the error above.
- With `SPECIFY_FEATURE_DIRECTORY=specs/001-stub` and `--paths-only`, it printed the paths and wrote no `feature.json`.
- With the same variable and no `--paths-only`, it wrote `.specify/feature.json` as `{"feature_directory":"specs/001-stub"}` even though the call then failed on the missing `plan.md`. A failed call can still leave a persisted pointer.

Numbering: the specify skill takes `feature_numbering` from `.specify/init-options.json`. `"sequential"` (the default here) scans `specs/` and takes the next three-digit number. `"timestamp"` is described in the skill text as `YYYYMMDD-HHMMSS`. **Documented only** for `timestamp`.

Consequences for the factory:

1. `.specify/feature.json` is one pointer per checkout. Two jobs sharing a checkout would overwrite each other. Run each job in its own worktree or container, and set `SPECIFY_FEATURE_DIRECTORY` explicitly for every skill after the first.
2. Sequential numbering is computed from the local `specs/` directory. Two jobs in separate worktrees can both create `001-...` and collide at merge. Prefer an explicit directory name chosen by the factory, or `feature_numbering: timestamp`. **Unverified**: that the specify skill honours an explicit `SPECIFY_FEATURE_DIRECTORY` passed in its arguments, although its text says it does.
3. After the specify skill returns, the adapter must read `.specify/feature.json`, check that the directory exists and contains `spec.md`, and store the pair. Later skills should receive the directory through the environment variable, so they do not depend on the file.

## 8. Headless driving

### 8.1 Claude Code

Verified. This is the command line the smoke run used, wrapped by the driver in Appendix B:

```text
claude -p \
  --input-format stream-json --output-format stream-json --verbose \
  --session-id <uuid> \
  --model sonnet --effort medium \
  --permission-mode acceptEdits --permission-prompts none \
  --strict-mcp-config --setting-sources project,local \
  --max-budget-usd 10 \
  --disallowedTools AskUserQuestion \
  --allowedTools 'Read,Write,Edit,Glob,Grep,Skill,Bash(.specify/scripts/bash/*),Bash(mkdir:*),Bash(cp:*),Bash(ls:*),Bash(cat:*),Bash(date:*),Bash(wc:*),Bash(test:*),Bash(git status:*),Bash(git rev-parse:*)'
```

Each turn is one JSON line on standard input:

```json
{"type":"user","message":{"role":"user","content":[{"type":"text","text":"/speckit-specify <description>"}]}}
```

What was observed:

- A user message that starts with `/speckit-<name>` is expanded into the skill. The model made no `Skill` tool call. The `system/init` event listed `speckit-analyze` through `speckit-taskstoissues` in both `skills` and `slash_commands`.
- Each turn ends with an event `{"type":"result", ...}`. The driver waits for it before sending the next message. Fields used: `subtype` (`success`), `is_error`, `duration_ms`, `num_turns`, `total_cost_usd`, `permission_denials`, `session_id`, `usage`.
- `total_cost_usd` is **cumulative for the session**, not per turn. Subtract the previous value to get the turn cost.
- The `system/init` event reports `model: claude-sonnet-5-5` and `permissionMode: acceptEdits`.
- `--permission-prompts none` makes anything outside the allowlist fail without asking. In turn 4 the model tried a `python3` heredoc to edit the spec; the call was denied, shown in `permission_denials`, and the model completed the same edit with the `Edit` tool. So denials are recoverable, but the adapter should log them.
- Allowlist matching is by command prefix. In turn 2 the command `mkdir -p ... && printf '...' > .specify/feature.json && git branch --show-current` ran because it began with `mkdir`. An allowlist therefore does not contain the agent. The headless host must run inside the factory sandbox (master prompt section 1), with the repository worktree as its only writable path.

**Unverified**: single-shot `claude -p "/speckit-specify ..."` with plain text input, and continuing a session across separate processes with `--resume <session-id>`. The multi-turn stream-json route is the one that was tested.

### 8.2 Codex

Verified, specify only, in a throwaway project:

```text
codex exec -C <project> -s workspace-write --json -o <last-message-file> \
  '$speckit-specify <description>. Do not ask clarifying questions; record informed defaults as assumptions. Do not run any other Spec Kit skill.'
```

- Single-quote the prompt so the shell does not expand `$speckit-...`.
- Codex found the skill in `.agents/skills`, read `SKILL.md`, ran `.specify/scripts/bash/resolve-template.sh spec-template --json`, created `specs/001-convert-temperature/` with `spec.md` and `checklists/requirements.md`, and wrote `.specify/feature.json`. Exit code 0.
- Standard output is JSONL. Event types seen: `thread.started`, `turn.started`, `item.started`, `item.completed` (item types `agent_message`, `command_execution`, `file_change`) and `turn.completed`. The last one carries `usage` with `input_tokens`, `cached_input_tokens`, `output_tokens` and `reasoning_output_tokens`. There is no cost field.
- Standard error held a line `Reading additional input from stdin...` and one `apply_patch verification failed` error. Codex recovered by writing the file with Python. Treat standard error as diagnostic noise, not as failure.
- Wall time was 186 seconds. Usage was 332,039 input tokens (287,616 cached) and 8,665 output tokens (546 reasoning).
- The model was whatever the local Codex configuration selects. I did not read or record it. **Unverified**: model name.

**Unverified**: `codex exec resume`, the `--output-schema` option for structured final messages, and every skill other than specify.

### 8.3 Handling questions

The specify skill prints at most three questions when it finds `[NEEDS CLARIFICATION]` markers, then waits. The clarify skill asks up to five questions, one per turn, in this shape (Verified, from the Claude Code run):

```text
**Question:** Who counts as an "authorized person" for filing an issue the factory will act on? (FR-001)

Why it matters: ...

**Recommended:** Option A - ...

| Option | Description |
|--------|-------------|
| A | ... |
| Short | Provide a different short answer (<=5 words) |

You can reply with the option letter (e.g., "A"), accept the recommendation by saying "yes" or "recommended", or provide your own short answer.
```

There is no structured signal that a turn is a question. The only markers are the text `**Question:**` and the absence of a completion report. The adapter must therefore:

1. Detect a question turn by pattern and also by the fact that the skill's expected output files did not change.
2. Apply an answer policy that is part of the stage contract: auto-accept the recommended option only for questions the policy classes as routine, and route everything else to a human with the question text unchanged.
3. Count questions and stop at the skill's own limit.

In the smoke run I answered with the letter of the recommended option each time (`A`, `A`, `B`), and the skill recorded each answer correctly under `## Clarifications`. Those answers were mine, not a human's, so they still need human confirmation.

**Unverified**: what the specify skill does in a headless run when it does produce `[NEEDS CLARIFICATION]` markers. In the smoke run it asked none.

### 8.4 Post-conditions the adapter must check after every skill run

Do not rely on the agent's report. After each run, check:

1. The process exited normally and the `result` event has `subtype: success` and `is_error: false` (Claude Code), or exit code 0 and a `turn.completed` event (Codex).
2. `specify integration status --json` still reports `status: ok`. A skill must not modify installed files.
3. `git status --porcelain` shows changes only under the allowed paths for that skill (table below).
4. `.specify/feature.json` is valid JSON, its `feature_directory` exists, and `spec.md` is inside it.
5. No template placeholder text remains in the artifact (`[FEATURE NAME]`, `$ARGUMENTS`, `[###-feature-name]`, `[DATE]`, `[PRINCIPLE_1_NAME]` style tokens).
6. No `plan.md`, `tasks.md`, `research.md`, `data-model.md` or `contracts/` appeared in the feature directory. If one did, a forbidden skill ran.
7. Checklist files are present, and no custom checklist item was ticked by the agent that wrote it.

Allowed write paths, from what each skill wrote in the smoke run:

| Skill | Paths written |
| --- | --- |
| constitution | `.specify/memory/constitution.md` |
| specify | `specs/<dir>/spec.md`, `specs/<dir>/checklists/requirements.md`, `.specify/feature.json` |
| clarify | `specs/<dir>/spec.md` (and ticks in `checklists/requirements.md`) |
| checklist | `specs/<dir>/checklists/<name>.md` |

### 8.5 Measured cost and time

Verified from the `result` events of one Claude Code process, model `claude-sonnet-5-5`. Costs are the difference between consecutive cumulative values.

| Turn | Skill | Wall time | Model calls | Turn cost (USD) |
| --- | --- | --- | --- | --- |
| 1 | constitution | 28 s | 6 | 0.132 |
| 2 | specify | 95 s | 10 | 0.361 |
| 3 | clarify (first question) | 10 s | 2 | 0.059 |
| 4 | answer 1, second question | 28 s | 8 | 0.097 |
| 5 | answer 2, third question | 10 s | 3 | 0.034 |
| 6 | answer 3, completion | 13 s | 4 | 0.041 |
| 7 | checklist | 41 s | 5 | 0.170 |
| Total | | about 224 s | 38 | 0.893 |

A realistic stage budget for a feature of this size is under 2 US dollars and 10 minutes, with room for clarification rounds. Costs on other models, other hosts and larger repositories are **Unverified**. Codex reports tokens only.

## 9. Artifact formats

Everything in this section was read from real output. The factory must preserve these files in their original format (master prompt section 0).

### 9.1 `spec.md`

The template (`.specify/templates/spec-template.md`) defines this structure. The specify skill fills it in and keeps the headings.

```text
# Feature Specification: <name>
**Feature Branch**: `<text>`          free text written by the agent
**Created**: YYYY-MM-DD
**Status**: Draft                      the skill writes "Draft"; no other value is defined
**Input**: User description: "<arguments>"

## Clarifications                      added by clarify, placed before the first story section
### Session YYYY-MM-DD
- Q: <question> → A: <answer>

## User Scenarios & Testing *(mandatory)*
### User Story N - <title> (Priority: P1)
<narrative>
**Why this priority**: ...
**Independent Test**: ...
**Acceptance Scenarios**:
1. **Given** ..., **When** ..., **Then** ...
### Edge Cases
- ...

## Requirements *(mandatory)*
### Functional Requirements
- **FR-001**: System MUST ...
### Key Entities *(include if feature involves data)*
- **<Entity>**: ...

## Success Criteria *(mandatory)*
### Measurable Outcomes
- **SC-001**: ...

## Assumptions
- ...
```

Facts to rely on, all observed in the Slice 1 specification (10 stories and 13 success criteria; 38 scenarios and 39 requirements as generated, 40 and 40 after the review edits):

- There is no section for non-functional requirements, risks, constraints, out-of-scope items or open questions. The template does not define them. Section 10 explains how the adapter should treat that.
- Requirement identifiers (`FR-nnn`, `SC-nnn`) are unique but **not guaranteed to appear in order**. After clarify added requirements, `FR-039` was placed before `FR-024` and `FR-038` before `FR-037`. The skill said it left them unrenumbered on purpose. The parser must key on the identifier and never on position.
- Acceptance scenarios have no identifiers. They are numbered lists inside a story, so their position changes whenever someone inserts one.
- Priorities exist only on user stories (`P1`, `P2`, ...). Requirements carry no priority and no explicit link to a story.
- `[NEEDS CLARIFICATION: ...]` markers are limited to three by the specify skill and are the only machine-detectable form of an open question.
- The `## Clarifications` section is the only place a question and its answer are recorded together.
- The `Status` field was `Draft` in every run. Nothing in Spec Kit moves it forward, so approval and freeze state must live in the factory.

### 9.2 `checklists/requirements.md` (built-in)

Created by specify, 16 items in three groups (Content Quality, Requirement Completeness, Feature Readiness), plus Notes. Specify and clarify re-evaluate and tick it themselves. In the smoke run every item was ticked after the first pass by the same agent that wrote the specification. That is a self-assessment, so the specification gate must not accept those ticks as independent evidence (master prompt section 2, principle 15).

### 9.3 Custom checklists (`checklists/<name>.md`)

Created by the checklist skill. Items are named `CHK001` upward and are written as questions about requirement quality, each with a bracketed tag such as `[Completeness, Spec §FR-012]` or `[Gap]`. The template and skill state that the command must leave every item unchecked and that only a reviewer may tick one. Verified: the 36 items it produced were all unchecked. If the same file is generated again, new items are appended and numbering continues.

### 9.4 `constitution.md`

The template has five principle slots, two free sections and a governance block, and ends with `**Version**: X | **Ratified**: DATE | **Last Amended**: DATE`. The constitution skill:

- Fills every placeholder and may use more or fewer principles when asked.
- Bumps the version using semantic versioning rules stated in the skill.
- Writes a "Sync Impact Report" as an HTML comment at the top of the file. The skill says this is scratch material that "is expected to be removed before the amended constitution file is committed." The comment must be removed by a person or by a deterministic step. In the smoke run it was removed by hand after the run, and that edit is recorded in the worked example.

## 10. Mapping to the `SpecificationContract`

The master prompt (section 4) lists these fields. The table shows where each one comes from, what Spec Kit provides, and what the adapter must derive or the gate must flag.

| Contract field | Source in Spec Kit artifacts | Provided by Spec Kit? | What the adapter or gate does |
| --- | --- | --- | --- |
| `spec_id` | Feature directory name, for example `001-end-to-end-mvp` | Partly. The name is unique only inside one repository, and `NNN` restarts per repository. | The factory assigns an immutable identifier (UUID) in its own metadata. It stores the directory name and repository as lookup keys. Do not use the `Feature Branch` field. |
| `spec_version` | None. `Status` is always `Draft`. | **No** | The factory assigns a monotonically increasing revision at each freeze. A new revision exists when the content hash of the artifact set changes. |
| `commit_sha` | None | **No** | At freeze, require the artifact paths to be committed and clean, then record `git rev-parse HEAD`. Flag the spec as unfrozen if the working tree differs. |
| requirements | `- **FR-nnn**:` lines under `### Functional Requirements`, plus bold group labels | Yes | Parse by identifier. Reject duplicates. Do not rely on order. Keep the exact sentence text. |
| priorities | `(Priority: Pn)` on each `### User Story` heading | Partly. Stories only. | Derive requirement priority from the stories that cite it. Spec Kit gives no link, so the gate flags any requirement that no story or scenario mentions by text. |
| acceptance scenarios | Numbered `**Given** ... **When** ... **Then** ...` lines under each story | Yes, without identifiers | Assign a stable identifier from the story identifier and a hash of the normalised text, so inserting a scenario does not renumber the others. |
| non-functional requirements | No dedicated section. They appear as `FR-nnn` lines and as `SC-nnn` success criteria. | **No** | The adapter cannot separate them reliably. Treat success criteria (`SC-nnn`) as the measurable outcomes, and have a reviewer or a documented classifier tag NFR requirements. The gate flags a specification that has no measurable criterion for performance, security or reliability when the domain profile requires one. |
| risks | None | **No** | Not extractable. In the Slice 1 spec they appear as bullets that start with `Risk:` inside `## Assumptions`, because the specify prompt asked for that. That is a local convention and not part of Spec Kit. The gate flags a specification with no risks recorded. |
| open questions | `[NEEDS CLARIFICATION: ...]` markers, plus unchecked checklist items | Yes, in two forms | Collect both. Answered questions live in `## Clarifications` and are not open. |
| constraints | None. Closest are `## Assumptions` bullets. | **No** | In the Slice 1 spec, bullets that start with `Constraint:`. Local convention only. |
| out of scope | None as a section | **No** | In the Slice 1 spec it is the first bullet under Edge Cases. Local convention. The gate flags a specification with no explicit scope boundary. |
| provenance links | `**Input**:` line (the user description) and the `Created` date | Minimal | The adapter adds the issue number, normalised request hash, original request hash, Spec Kit version, host name and version, skill names, session identifier and model. |
| artifact hashes | None for features. Manifests hash only installed Spec Kit files. | **No** | The adapter computes SHA-256 of `spec.md`, every file under `checklists/`, `.specify/memory/constitution.md`, `.specify/init-options.json` and `.specify/integration.json`. Store the set as the frozen revision. |
| key entities | `### Key Entities` bullets | Yes | Carry as a list of name and description. |
| edge cases | `### Edge Cases` bullets | Yes | Carry as a list. |
| assumptions | `## Assumptions` bullets | Yes | Carry as a list, including any local `Constraint:` and `Risk:` prefixes, tagged as local conventions. |
| clarification decisions | `## Clarifications` bullets | Yes | Carry as question and answer pairs with the session date. The adapter should record who answered each one. |

### 10.1 Deterministic gate rules that the format supports

The following checks run on plain text. I implemented rules 1 to 7 and 9 as a throwaway script and ran it on the Slice 1 specification (10 stories, 40 requirements, 13 success criteria, 40 scenarios) and on the Codex throwaway specification; all of them passed on both. Rules 8 and 10 are proposed and were not scripted.

1. Required top-level sections exist: User Scenarios & Testing, Requirements, Success Criteria, Assumptions.
2. `**Status**`, `**Created**` and `**Input**` are present and `Created` is an ISO date.
3. Every user story heading has a priority of the form `P<number>` and at least one acceptance scenario.
4. Every scenario has Given, When and Then parts.
5. `FR-nnn` identifiers are unique, and `SC-nnn` identifiers are unique.
6. Every requirement sentence contains MUST, MUST NOT, SHOULD or MAY in capitals.
7. No `[NEEDS CLARIFICATION` marker remains, and no template placeholder remains.
8. Every checklist item is either ticked by a reviewer or waived by a person with a reason.
9. No implementation technology names appear in requirements or success criteria. The word list comes from the domain profile.
10. The artifact set is committed and its hashes match the frozen record.

Rules that need a reviewer, not code: whether requirements are testable, unambiguous and free of contradictions. The master prompt already assigns those to an independent reviewer.

## 11. Incompatibilities and known gaps

### 11.1 The checklist skill needs `plan.md`

The first step of `speckit-checklist` runs `.specify/scripts/bash/check-prerequisites.sh --json --template checklist-template`. That mode requires `plan.md` and exits 1 without it. Verified twice, by running the script directly and through the skill:

```text
$ SPECIFY_FEATURE_DIRECTORY=specs/001-stub .specify/scripts/bash/check-prerequisites.sh --json --template checklist-template
ERROR: plan.md not found in .../specs/001-stub
Run /speckit-plan first to create the implementation plan.
exit=1
```

In the smoke run the model reported "The prerequisite script insists on `plan.md`, which this factory deliberately doesn't create. I'll get the paths and the template another way." It then ran `resolve-template.sh checklist-template --json`, read the spec directly, and wrote a good checklist. That worked because the model improvised, not because the skill is designed for it. The init banner also says the checklist belongs "after /speckit-plan".

Options, in order of preference. None is tested.

1. Have the adapter run the equivalent steps itself, then give the skill the results in its arguments. The adapter can call `check-prerequisites.sh --json --paths-only` and `resolve-template.sh checklist-template --json`, both of which work without a plan, and include the paths and template in the prompt.
2. Override the `speckit.checklist` command with a project preset that drops the `plan.md` requirement. Presets are an official mechanism (`specify preset --help`, and `specify artifact info` shows a `strategy` per layer). **Unverified**: whether a preset can replace a command and what `integration status` then reports.
3. Accept the model's improvisation and verify its output afterwards. This is what the smoke run did. It is not reproducible by construction.

Do not create an empty `plan.md` to satisfy the script. That would put a fake planning artifact in the feature directory and break post-condition 6. (With an empty `plan.md`, the script does succeed. I checked.)

### 11.2 No safe way to revise a specification in place

The specify skill is described as "Create or update", but its procedure always creates a new numbered directory and copies the template to `spec.md`. Re-running it on an existing feature could overwrite the existing specification. **Unverified**: I did not run it, because it would risk the real artifact. The clarify skill edits the specification in place, but it is limited to five questions per run and exists to answer questions, not to apply a requirement change.

Master prompt section 4 says a later requirement change creates a new revision. The adapter needs a defined revision method before Slice 1 ships. Candidates: (a) a new feature directory per revision, linked by the factory; (b) in-place edits by clarify or by a person, with each revision committed and hashed. The Slice 1 spec was revised by hand after review (see the worked example), which is option (b) without the tool.

### 11.3 Clarify and checklist are interactive by design

See section 8.3. Because questions arrive as free text, a headless run cannot tell reliably that the agent is waiting. Build the question detector and the answer policy before relying on clarify in a job.

### 11.4 `requirements.md` ticks are self-assessed

See section 9.2. A specification gate that counts `requirements.md` ticks as evidence would let the author grade its own work.

### 11.5 Argument text is trusted input to the skill

Each skill begins with `You **MUST** consider the user input before proceeding`, and the user input is the text after the slash command. If an issue body is placed there, the skill treats it as the user's instruction. Master prompt principle 14 says issues are untrusted data. The adapter must not paste issue text after the command as if it were the user speaking. At minimum, wrap it in a clearly delimited block that states it is untrusted source material, keep the host inside the sandbox, and rely on the specification gate and independent review as the real defence. **Unverified**: how well a delimiter holds against a hostile issue. This needs an adversarial test before Slice 1 is accepted.

### 11.6 Hooks and extensions could add side effects

The skills read `.specify/extensions.yml` for hooks before and after each command, and the specify skill mentions a `before_specify` hook that creates a git branch (the optional git extension). In this project the file does not exist, so no hooks ran, and no branch was created in any run. If an extension is ever installed, skills may create branches or commit. The post-condition checks in 8.4 (item 3) and the integrity check would catch this, but the adapter should also refuse to run when `.specify/extensions.yml` exists unless its hooks are on an allowlist.

### 11.7 Constitution scratch comment

See section 9.4. The Sync Impact Report must be stripped before commit.

### 11.8 The `Feature Branch` field is meaningless without a git extension

See section 7. Do not parse it.

### 11.9 The Codex integration collides with this repository's `.gitignore`

Codex skills install to `.agents/skills/`. This repository ignored `.agents/` and uses `.agents/solomon/` for harness state, so the Codex integration would have been silently ignored. **Resolved on 2026-11-03** with the tracked exception this section proposed: `.gitignore` now ignores `.agents/*`, re-includes `.agents/skills/`, ignores everything in it, and re-includes `.agents/skills/speckit-*/`. `.agents/solomon/` and any other local skill stay ignored (checked with `git check-ignore`). A repository that has its own rule for `.agents/` needs the same exception before the installer adds the Codex integration, and the installer says so when it finds the skills ignored.

### 11.10 Networked and out-of-scope subcommands

`specify self check`, `self upgrade`, `extension add/search`, `preset add/search`, `bundle`, `integration search`, `integration list --catalog` and `workflow add/search` talk to catalogs or the network. The adapter should not call them, and the sandbox should deny egress for the specification stage. I did not run any of them. `specify mcp` starts an experimental "version-only" server and is not needed.

### 11.11 The shared scripts require bash, and `jq` is optional

`.specify/scripts/bash/*.sh` need bash. They use `jq` when present and fall back to `python3`, then to `grep`/`sed`. `init` accepts `--script sh|ps|py`. I used `sh` only. **Unverified**: `ps` and `py` variants.

## 12. Unverified items

1. Authenticity of the `specify-cli` package against a GitHub release.
2. Installing a pinned version (`specify-cli==1.1.2`) with `uv`.
3. `specify init` with the network disabled.
4. Exit codes of `specify` commands on failure, other than the not-empty-directory case.
5. Plain-text `claude -p "/speckit-..."` without stream-json, and `claude --resume`.
6. The specify skill's behaviour when it emits `[NEEDS CLARIFICATION]` markers headlessly.
7. Re-running the specify skill on an existing feature (revision behaviour, possible overwrite).
8. Passing `SPECIFY_FEATURE_DIRECTORY` inside the specify arguments, and `feature_numbering: timestamp`.
9. On Codex: the constitution, clarify and checklist skills, question handling, `codex exec resume`, `--output-schema`, and the model used.
10. Any host other than Claude Code and Codex.
11. Behaviour with the git extension, any other extension, or a preset installed. Replacing the checklist command with a preset.
12. Linux and Windows behaviour, and the `ps` and `py` script types.
13. How the skills resist hostile text in their arguments.
14. Cost and quality on other models, and on larger or non-greenfield repositories.
15. Concurrent skill runs in separate worktrees of one repository.

## Appendix A: pinned hashes for Spec Kit 1.1.2

SHA-256 prefixes (first 16 characters) from the `.specify/integrations/*.manifest.json` files, for reading. The code uses the full 64-character values for all three tables, Codex included (`crates/spec_adapter/src/pinned.rs`). The Codex prefixes below were recorded in October and the full values written by `specify integration install codex` on 2026-11-03 begin with the same characters, so the installer is deterministic.

Claude Code, `.claude/skills/<name>/SKILL.md`:

```text
3237cd827194efaf  speckit-analyze        5dc436df0c727e90  speckit-checklist
164f49ef87cb2e92  speckit-clarify        60c27f3962e78edf  speckit-constitution
9f93c1d573592f14  speckit-converge       7186d59488f89dcf  speckit-implement
9e97fc0b4ce895c7  speckit-plan           d4d93f2444355136  speckit-specify
d148aeda1011260c  speckit-tasks          464bbaf464a28ffa  speckit-taskstoissues
```

Codex, `.agents/skills/<name>/SKILL.md`:

```text
0b3261b13cc33537  speckit-analyze        7ac5cba31a27151a  speckit-checklist
f6acfbc82c96c0d9  speckit-clarify        b2a6a979ef751181  speckit-constitution
5859c9780ddc012f  speckit-converge       848a5c9eff7b99e3  speckit-implement
db2406adfa50103f  speckit-plan           a505028de7f64898  speckit-specify
1086d7885df1188d  speckit-tasks          a349d410c1803852  speckit-taskstoissues
```

Shared files, `.specify/`:

```text
8c908410d177a1ef  .gitignore
daa377146db4fb69  scripts/bash/check-prerequisites.sh
53cb1c23e349db45  scripts/bash/common.sh
972f03ed8ca5ee17  scripts/bash/create-new-feature.sh
829e227096abc8bf  scripts/bash/resolve-template.sh
d0bd298c026446f3  scripts/bash/setup-plan.sh
4a33dd1e6c32ddc7  scripts/bash/setup-tasks.sh
856532b3cb66171c  templates/checklist-template.md
ce7549540fa45543  templates/constitution-template.md
7e637502d41eccf0  templates/plan-template.md
3945437fc35cd30a  templates/spec-template.md
fc29a233f6f5a27c  templates/tasks-template.md
```

## Appendix B: the multi-turn driver used for the smoke run

This is the exact, tested script. It holds one `claude -p` process open, sends each turn from `inbox/turn-N.txt` as a stream-json user message, waits for the `result` event, and writes the turn's text and result to `out/`. The `spec_adapter` should implement the same loop in Rust, with the answer policy from section 8.3 deciding what goes into the next turn.

```python
#!/usr/bin/env python3
"""Throwaway multi-turn driver for a headless `claude -p` session.

Models how a future spec_adapter would hold one session open over
`--input-format stream-json` and feed it one turn at a time.
Turn N is read from <io>/inbox/turn-N.txt; the stream is mirrored to
<io>/out/events.jsonl; each turn's final result goes to <io>/out/turn-N.result.json
and its assistant text to <io>/out/turn-N.text.md. Create <io>/inbox/END to stop.
"""
import json
import os
import subprocess
import sys
import threading
import time

workdir, io_dir, session_id = sys.argv[1], sys.argv[2], sys.argv[3]
extra = sys.argv[4:]
inbox = os.path.join(io_dir, "inbox")
out = os.path.join(io_dir, "out")

cmd = [
    "claude", "-p",
    "--input-format", "stream-json",
    "--output-format", "stream-json",
    "--verbose",
    "--session-id", session_id,
] + extra

proc = subprocess.Popen(
    cmd, cwd=workdir, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    stderr=open(os.path.join(out, "stderr.log"), "w"), text=True, bufsize=1,
)

state = {"turn": 0, "done": threading.Event(), "text": []}
events_f = open(os.path.join(out, "events.jsonl"), "w")


def reader():
    for line in proc.stdout:
        events_f.write(line)
        events_f.flush()
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "assistant":
            for block in ev.get("message", {}).get("content", []):
                if block.get("type") == "text":
                    state["text"].append(block["text"])
        if ev.get("type") == "result":
            n = state["turn"]
            with open(os.path.join(out, f"turn-{n}.result.json"), "w") as f:
                json.dump(ev, f, indent=1)
            with open(os.path.join(out, f"turn-{n}.text.md"), "w") as f:
                f.write("\n\n".join(state["text"]))
            state["text"] = []
            state["done"].set()


t = threading.Thread(target=reader, daemon=True)
t.start()

n = 0
while True:
    n += 1
    path = os.path.join(inbox, f"turn-{n}.txt")
    while not os.path.exists(path):
        if os.path.exists(os.path.join(inbox, "END")) or proc.poll() is not None:
            n = None
            break
        time.sleep(1)
    if n is None:
        break
    time.sleep(0.5)
    with open(path) as f:
        text = f.read().strip()
    state["turn"] = n
    state["done"].clear()
    msg = {"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": text}]}}
    proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    while not state["done"].wait(timeout=2):
        if proc.poll() is not None:
            break
    if proc.poll() is not None:
        break

try:
    proc.stdin.close()
except Exception:
    pass
proc.wait(timeout=60)
with open(os.path.join(out, "exit.txt"), "w") as f:
    f.write(str(proc.returncode))
```

## Appendix C: trimmed transcripts

Install and probe (Verified):

```text
$ specify --version
specify 1.1.2
$ specify integration status --json | head -8
{ "status": "ok", "default_integration": "claude", "installed_integrations": ["claude"], ... }
$ specify artifact list --json      # 19 entries: 10 commands, 5 templates, 4 scripts
command  speckit.analyze ... speckit.taskstoissues
template checklist-template, constitution-template, plan-template, spec-template, tasks-template
script   check-prerequisites, resolve-template, setup-plan, setup-tasks
```

Init in this repository (Verified):

```text
$ specify init --here --force --non-interactive --integration claude
Warning: Current directory is not empty (5 items)
Template files will be merged with existing content and may overwrite existing files
--force supplied: skipping confirmation and proceeding with merge
Initialize Specify Project
├── ● Check required tools (ok)
├── ● Select coding agent integration (claude)
├── ● Select script type (sh)
├── ● Install integration (Claude Code)
├── ● Install shared infrastructure (scripts (sh) + templates)
├── ● Ensure scripts executable (6 updated)
├── ● Constitution setup (copied from template)
├── ● Install bundled workflow (speckit installed)
└── ● Finalize (project ready)
...
  1. You're already in the project directory!
  2. Start Claude in this project directory; spec-kit skills were installed to .claude/skills
  3. Start using skills with your coding agent:
     3.1 /speckit-constitution - Establish project principles
     3.2 /speckit-specify - Create baseline specification
     3.3 /speckit-plan ...
```

Active feature failure and success (Verified):

```text
$ .specify/scripts/bash/check-prerequisites.sh --json --paths-only          # no env, no feature.json
ERROR: Feature directory not found. Set SPECIFY_FEATURE_DIRECTORY or run the specify command to create .specify/feature.json.
ERROR: Failed to resolve feature paths
exit=1
$ SPECIFY_FEATURE_DIRECTORY=specs/001-stub .specify/scripts/bash/check-prerequisites.sh --json --paths-only
{"REPO_ROOT":"...","BRANCH":"001-stub","FEATURE_DIR":".../specs/001-stub","FEATURE_SPEC":".../spec.md","IMPL_PLAN":".../plan.md","TASKS":".../tasks.md"}
exit=0                                                                        # BRANCH is just the directory name
```

Headless run, Claude Code, last turns (Verified, trimmed from the event stream):

```text
turn 7  /speckit-checklist ...
        Bash: check-prerequisites.sh --json --template checklist-template   -> error: plan.md not found
        Bash: resolve-template.sh checklist-template --json                 -> ok
        Write: specs/001-end-to-end-mvp/checklists/requirements-quality.md
result  subtype=success is_error=false num_turns=5 duration_ms=41085 total_cost_usd=0.8925794
```

Headless run, Codex (Verified, trimmed):

```text
$ codex exec -C <project> -s workspace-write --json -o last.txt '$speckit-specify A small command-line tool ...'
{"type":"thread.started","thread_id":"01a17b6e-..."}
{"type":"item.completed","item":{"type":"agent_message","text":"I'll use the `speckit-specify` skill ..."}}
{"type":"item.completed","item":{"type":"command_execution","command":"... cat .agents/skills/speckit-specify/SKILL.md","exit_code":0}}
{"type":"item.completed","item":{"type":"command_execution","command":"... bash .specify/scripts/bash/resolve-template.sh spec-template --json","exit_code":0}}
{"type":"turn.completed","usage":{"input_tokens":332039,"cached_input_tokens":287616,"output_tokens":8665,"reasoning_output_tokens":546}}
exit=0   elapsed=186 s   -> specs/001-convert-temperature/{spec.md,checklists/requirements.md}, .specify/feature.json
```
