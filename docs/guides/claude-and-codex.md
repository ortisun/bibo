# Claude Code and Codex side by side

- Status: written on 2026-11-02 from `scripts/install.sh`, `scripts/lib/codex_config.py`, the architecture decision record (ADR) [0019](../adr/0019-claude-code-and-codex-alike.md), the Elephant-Goldfish Model (EGM) plugin version 0.1.0 and runs of `claude` 2.1.316 and `codex` 0.166.0 on the author's machine. The installer was tested with fake `claude`, `codex` and `gh` programs. A design session has not been run under Codex.
- Form: reference, with a short how-to.
- Goal: say what is the same and what differs when a team uses Claude Code, Codex, or both with the factory's design path, including the entry for the Model Context Protocol (MCP) that lets the agent talk to GitHub.

The factory works with either tool. The labels, the issue forms, the Action, the board and the project map do not depend on the tool, and the factory's own engine already runs a job with either one ([ADR 0005](../adr/0005-agent-runtime-adapter-boundary.md)). What differs is how each person's coding agent is set up for the design session.

## Choose the agents

`scripts/install.sh` prepares the agents you have. By default (`--agent auto`) it takes each of `claude` and `codex` that is on the `PATH` and stops if there is none.

| You want | Option |
|---|---|
| Every agent that is installed | nothing, or `--agent auto` |
| Only Claude Code | `--agent claude` |
| Only Codex | `--agent codex` |
| Both, and a block if one is missing | `--agent both` |

## What differs

| | Claude Code | Codex |
|---|---|---|
| Needs | Version 2.1.271 or later, so that EGM's reviewers run in a fresh context. | The `plugin` command. The installer checks the command, not a version number. EGM also needs a way to start a reviewer with no conversation, and it stops the review if the host cannot. |
| Install EGM | `claude plugin marketplace add google/elephant-goldfish-model`, then `claude plugin install egm@egm` | `codex plugin marketplace add google/elephant-goldfish-model`, then `codex plugin add egm@egm` |
| See what is installed | `claude plugin list --json` | `codex plugin list --json` |
| A disabled plugin | The installer runs `claude plugin enable egm@egm`. | **Codex has no command for it.** The installer reports it and a person turns the plugin on in Codex's settings. |
| Start a skill | `/egm:egm-brainstorm`, `/egm:egm-draft`, `/egm:egm-review`, `/egm:egm-bootstrap` | Choose the EGM skill from Codex's skill list, as EGM's Codex guide says. This repository's Spec Kit notes write skills on Codex with a `$` prefix, so typing `$` is a good way to find one. That is unverified for EGM. |
| GitHub MCP file | `.mcp.json` | `.codex/config.toml` |
| Use of that file | Claude Code asks you to approve a project's `.mcp.json` the first time. | Codex reads `.codex/config.toml` **only for a project you trust**. Trust the project when Codex asks. |
| The token | The variable `FACTORY_GITHUB_MCP_TOKEN`, named in the file | The same variable, named in the file |
| Instructions file | `CLAUDE.md` | `AGENTS.md` |
| Where EGM writes its documents | The working folder, or the folder named by a line `EGM artifact directory: <path>` in `CLAUDE.md` or in the prompt | The same, in `AGENTS.md` or in the prompt |
| Fresh reviewers | Registered agents named `egm:egm-...`, which can read but not edit | A general-purpose subagent that reads the reviewer's file |

Both MCP files hold the same server and the same settings: the toolsets `repos`, `issues`, `pull_requests` and `labels`, and the header that turns on GitHub's lockdown mode, a safety setting of the server. GitHub's page lists it and does not define it, so what it filters is not verified here.

## The GitHub entry for Codex

The installer adds this table to the project's `.codex/config.toml`. It holds the **name** of the variable and never a token.

```toml
[mcp_servers.github]
url = "https://api.githubcopilot.com/mcp/"
bearer_token_env_var = "FACTORY_GITHUB_MCP_TOKEN"
http_headers = { "X-MCP-Lockdown" = "true", "X-MCP-Toolsets" = "repos,issues,pull_requests,labels" }
```

It edits that one table and keeps everything else in the file: other tables, comments and blank lines. It refuses to touch a form it does not understand, and it reports a `github` entry that holds a token, without showing the value. An entry that runs a command (`command`, `args`, `env`, `http_headers_helper`) is never edited, even with `--update`, because a project file that runs a command is code and a person must read it.

If you would rather keep the entry out of the project, write the same table in your own `~/.codex/config.toml`. The installer does not do this for you, because the global file is yours.

## Both agents in one project

Run the installer once. It writes `.mcp.json` and `.codex/config.toml`, copies the same issue forms and Action, creates the same labels and maps the same board. It asks for the token once and names both agents in the sentence. For the map step it prints the command for each agent.

```bash no-run reason="it installs a plugin and writes files in a project, and the paths are placeholders"
scripts/install.sh --checkout ../my-project --repo my-org/my-project --agent both
```

## Spec Kit for both tools

A project that uses the factory's specification stage has Spec Kit installed once, and its skills are files in the project: `.claude/skills/speckit-*` for Claude Code and `.agents/skills/speckit-*` for Codex. `scripts/install.sh --checkout PATH` makes the installation cover both, whatever `--agent` says, because the files belong to the project and not to the person who runs the script. It adds the missing integration with `specify integration install claude` or `codex` (no network, no `--force`), then compares every skill file with the hash the factory pins. A file that differs is `DRIFT` and is kept. The skills are written `/speckit-specify` in Claude Code and `$speckit-specify` in Codex; the separator comes from `.specify/integration.json`, where the install records `-` for both. Codex puts its skills in `.agents/skills`, so a project whose ignore rules hide `.agents/` needs the exception in `docs/spec-kit/integration-guide.md`, section 11.9, and the installer stops until it has it.

## What the factory itself never does

For both tools the factory treats the project's own copies as data. A factory run never edits `.mcp.json`, `.claude/**`, `CLAUDE.md`, `.codex/**` or `AGENTS.md`, and it never honors `.mcp.json`, `.codex/config.toml`, `CLAUDE.md` or `AGENTS.md` from a repository. A person changes those files by pull request.

## What is not shown to work

- A design session (brainstorm, draft, review) run under Codex from start to end. EGM's own documentation says Codex passes its fixtures. This repository has not checked that.
- The installer adding EGM to a Codex that has never had it. The author's Codex already had it, so only the check path ran against the real tool.
- A job whose specification stage runs under Codex. The Spec Kit install in this repository now records both integrations (the Codex skills are under `.agents/skills` and the worker refuses to start if one is not the pinned file), but the Codex runtime of the composition is still given no skill bundle, so the stage stays unavailable under Codex until that is built and a real run is shown.

## Troubleshooting

| You see | Cause | Fix |
|---|---|---|
| `BLOCKED agents` and "no coding agent is installed" | Neither `claude` nor `codex` is on the `PATH`. | Install one, or fix the `PATH`. |
| `BLOCKED codex` and "no 'plugin add' command" | This Codex is too old for plugins. | Update Codex. |
| `NEEDS egm-plugin` for `codex` | The plugin is installed and disabled. | Turn it on in Codex's settings. |
| The GitHub server is missing in Codex | The project is not trusted, or the variable is not set. | Trust the project. Export `FACTORY_GITHUB_MCP_TOKEN` in the shell that starts Codex. |
| `DRIFT github-mcp` for `codex` | The entry differs, holds a token, or is in a form the installer will not edit. | Read the line. Use `--update` for the first two. Edit by hand for the third. |

## Where to read more

- [ADR 0019](../adr/0019-claude-code-and-codex-alike.md): the options, what was checked and what is unverified.
- [Onboarding guide](onboarding.md): the whole path, from install to the first ticket.
- EGM's own guides for Claude Code and Codex, in the plugin folder under `docs/claude.md` and `docs/codex.md`.
