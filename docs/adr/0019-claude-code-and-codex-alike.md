# 0019: Prepare a project for Claude Code and for Codex alike

- Status: Proposed. The product owner said on 2026-11-02 that the project must work with Codex and with Claude Code. **Pending confirmation by the architect.** The installer and its tests are built. The design session itself has not been run under Codex.
- Date: 2026-11-02
- Deciders: the product owner for the requirement. The engineer wrote the design and the code.
- Related: [ADR 0005](0005-agent-runtime-adapter-boundary.md), [ADR 0016](0016-design-phase-onboarding-and-issue-workflow.md), [ADR 0018](0018-project-board-mirror-that-adapts.md), [Claude Code and Codex side by side](../guides/claude-and-codex.md)

## Context and problem statement

The engine already runs jobs with either tool: the runtime crate holds `ClaudeCodeRuntime` and `CodexRuntime`, and [ADR 0005](0005-agent-runtime-adapter-boundary.md) probes each tool for the flags it uses. The pieces added by [ADR 0016](0016-design-phase-onboarding-and-issue-workflow.md) and [ADR 0018](0018-project-board-mirror-that-adapts.md) were written for Claude Code alone. The installer installed EGM through `claude plugin`, put the GitHub MCP entry in `.mcp.json`, and told the person to type `/egm:...`. A team that works in Codex could not use the design phase.

How does the installer prepare a project for either tool, or both, without making one of them the real one and the other a copy?

## What was checked

On 2026-11-02. "Verified" means run or read here. "Unverified" means the source is silent or the behavior was not run.

**Codex 0.166.0, on this machine.** Verified:
- `codex plugin` has `add`, `list`, `remove` and `marketplace` (`add`, `list`, `upgrade`, `remove`). **It has no `enable` or `disable`.**
- `codex plugin list --json` prints `{"installed": [{"pluginId": "egm@egm", "version": "0.1.0", "enabled": true, ...}], "available": [...]}`. `codex plugin marketplace list --json` prints `{"marketplaces": [{"name": ...}]}`. The author's machine already had `egm@egm` 0.1.0 enabled in Codex.
- `codex mcp add` writes to the **global** configuration and has no flag for fixed headers. One attempt to set them with `-c` failed with "failed to load bootstrap configuration", and it was not pursued. A `[mcp_servers.NAME]` table with `url`, `bearer_token_env_var` and `http_headers`, written by hand, is accepted, and `codex mcp get --json` shows the headers.
- A project's `.codex/config.toml` **is read, and its `[mcp_servers.github]` is listed, when the project is trusted.** On macOS the temporary folder is `/var/...`, a link to `/private/var/...`. With the trust entry written as `/var/...` the server was not listed; with `/private/var/...` it was. The likely reason is that Codex compares the real path, and that was not confirmed. These runs used a throw-away `CODEX_HOME` and a throw-away project. They did not touch the author's configuration.
- Codex's documentation says it loads project configuration "only when the project is trusted".

**EGM** (read from the installed plugin, version 0.1.0): it installs into Codex with `codex plugin marketplace add google/elephant-goldfish-model` and `codex plugin add egm@egm`. In Codex, a person selects the skill from the skill list. EGM starts a fresh-context reviewer with `fork_context: false` or `fork_turns: "none"` and **stops the review if the host cannot do that**. Its documentation says Claude Code, Codex and Antigravity pass its installation, isolation and end-to-end fixtures. **That statement is EGM's own, and it was not checked here.**

**This repository.** The policy already lists `.codex/**` and `AGENTS.md` among the files a factory run never edits, and `.codex/config.toml` among the repository files a factory run never honors, next to `.mcp.json` and `CLAUDE.md`. The Spec Kit install records only the `claude` integration.

**Unverified:** the whole EGM workflow (brainstorm, draft, review) under Codex, here; `codex plugin marketplace add` and `codex plugin add` on a machine that has never had EGM (the commands were not run against the author's real configuration, which already had the plugin); how Codex names an EGM skill in the prompt; whether a Codex plugin can be disabled in a way that `codex plugin list` reports as `enabled: false` (the field exists; no disabled plugin was seen).

## Considered options

**A. Claude Code only.** Rejected: the requirement says both.

**B. Two installers, one for each tool.** Rejected. The labels, forms, Action, board and project map are the same for both, and two scripts would drift.

**C. One installer with a step for each tool.** Chosen. `--agent auto|claude|codex|both`, with `auto` as the default: it prepares each tool found on the `PATH` and stops when there is none. A tool that is asked for by name and is missing is a block, not a skip.

**D. Where Codex gets the GitHub MCP entry**

1. **The user's global configuration, through `codex mcp add`.** Rejected. It cannot set the lockdown and toolset headers, so the Codex entry would be weaker than the Claude one. Writing the user's global file by hand is more invasive than writing a file of the project.
2. **The project's `.codex/config.toml`.** Chosen. It is the counterpart of `.mcp.json`: it names the variable and holds no token, a pull request reviews it, and Codex loads it only for a project that the person trusts.

**E. How to edit that file.** There is no TOML writer in the Python standard library. Options were to add a dependency, to rewrite the whole file from a parsed form (which loses comments), or to edit one table as text. Chosen: edit the one table `[mcp_servers.github]` as text, refuse any form that is not understood, and parse the result again with `tomllib` where it exists before writing.

## Decision outcome

- **Detection.** Claude Code must be 2.1.271 or later, as EGM requires. Codex is probed for the command the installer uses (`plugin add`), not for a version number, as ADR 0005 does for the engine.
- **The plugin.** Each tool gets `egm@egm` from the same marketplace, found by that tool's own `list --json`. A version other than 0.1.0 is reported as `DRIFT` and kept. Claude Code can enable a disabled plugin and the installer does. Codex cannot, so a disabled plugin is a thing for a person to do.
- **The GitHub MCP entry.** One entry, two files: `.mcp.json` and `.codex/config.toml`. Both name `FACTORY_GITHUB_MCP_TOKEN`. Both carry the same toolsets and the lockdown header. Both are checked for a token, and the value is never printed.
- **What the file editor refuses.** An entry that holds a token is reported and replaced only on `--update`. An entry that runs a command (`command`, `args`, `env`, `http_headers_helper`, `env_http_headers`) or is written in a form the editor does not understand is never edited, even with `--update`. A project file that runs a command is code.
- **Neutral parts.** The forms, the Action, the labels, the board and the map check do not depend on the tool.
- **The hint for the map.** The installer names the right way to start the bootstrap for each tool it prepared.

## Consequences

**Good.** A Codex team and a Claude Code team follow one path, one set of labels and one board. The Codex entry is as strict as the Claude one. The editor cannot lose a person's comments or other servers.

**Costs.**
- **The design session under Codex is not shown to work.** EGM says it does. The first real run is the evidence.
- A Codex entry works only for a trusted project, so a person has to answer Codex's trust prompt once per project. The installer says so and does not edit the user's trust list.
- The text editor of the TOML file is conservative: some valid files are called `unsafe` and left to a person.
- On Codex a disabled plugin stays disabled until a person acts.
- The Spec Kit install recorded only `claude` when this ADR was written. The separator in a skill name (`/speckit-specify` on Claude Code, `$speckit-specify` on Codex) is read from `.specify/integration.json`. **Closed in part on 2026-11-03** (see the revision note at the end).

## What is not built

- A run of brainstorm, draft and review under Codex.
- `codex plugin marketplace add` and `codex plugin add` from the installer on a clean machine.
- A job whose specification stage runs under Codex. The Spec Kit install now records the Codex integration (below), but the Codex runtime of the composition is given no skill bundle, so that stage stays unavailable under Codex, and no real run exists.

## Revision note (2026-11-03, Spec Kit with Codex)

The project owner decided that the installer must make the project's Spec Kit integration cover both tools. What was done, with the Spec Kit 1.1.2 that the repository pins:

- `specify integration install codex` was run in this repository. `specify integration install --help` offers `--script`, `--force` and `--integration-options` only, and both integrations are multi-install safe, so no flag was needed. It works offline. It added `.specify/integrations/codex.manifest.json` and the ten `.agents/skills/speckit-*/SKILL.md` files, and added `codex` to `installed_integrations` in `.specify/integration.json`; the default stays `claude`. `specify integration status --json` reports `ok`.
- `.gitignore` tracks `.agents/skills/speckit-*` and ignores the rest of `.agents/` (the harness keeps local state in `.agents/solomon`).
- The pin of the Codex skills is now the full SHA-256 of each file (it was a 16-character prefix, because the full manifest had not been kept). `bundle_for_writer` pins the Codex skill of every skill the writer is given, as it pins the Claude Code one; a modified Codex skill makes the worker print `BLOCKED: agent runtime: protected_checkout: the Codex skill speckit-specify is not the pinned file` and exit with code 3 (test `a_codex_skill_of_the_installed_spec_kit_that_is_not_the_pinned_one_blocks_the_worker`; the control that an unmodified one does not block is `a_codex_installation_that_is_the_pinned_one_does_not_block_the_worker`). Ten deliberate breaks of this are listed in `crates/composition/tests/mutations/codex_pin_breaks.py`.
- `scripts/install.sh --checkout PATH` adds the missing integration to a project that has `.specify/`, with the same command and no `--force`, and checks every Spec Kit skill of the project against the factory's pins (`.specify/integrations/*.manifest.json` of this repository). A project with no `.specify/` is reported and not initialised: ADR 0006 keeps `init` for the control plane.
- Decisions taken without the owner, all on the safer side: a skill file of a host that is not listed but is there must still be the pinned one; an installed integration outside the host table is refused; the installer prepares both integrations whatever `--agent` says, because the files belong to the project and not to the person running the script.

## Revision note (2026-11-02, independent review PL-7 to PL-9)

The first version of the editor of `.codex/config.toml` could hold the installer for minutes on a few kilobytes of hostile text, deleted the comments above the next table (and, in one form, a whole table), made the file mode 0600, and had no check after the edit on Python below 3.11. It now reads each line in linear time and refuses a line over 4096 characters, treats any line that starts with `[` as the end of a table, keeps the comments of the next table and the mode of the file, refuses to write through a link, and checks the result by structure on every Python and also with `tomllib` where it exists. An entry that runs a command is "unsafe" even when it also holds a token. An entry that names the token variable but points to another address is "redirected", and the install is not ready until a person deals with it. Each of these has a test.
