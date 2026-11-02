# Install the factory's workflow into an existing project

- Status: written on 2026-11-02 from `scripts/install.sh`, `scripts/lib/project_map.py`, the architecture decision record (ADR) [0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md) and the tests of both. The installer ran against fake `claude` and `gh` programs and, with `--check`, against the real Claude Code on the author's machine. It has not installed the plugin on a machine that never had it, and it has not created labels on GitHub.
- Form: how-to.
- Goal: take a project that already has code and issues to the point where the factory may accept tickets from it.

**Objective.** The design tools and the issue workflow are in place, and the project has been mapped. The design tool is the Elephant-Goldfish Model (EGM), a Claude Code plugin that drafts designs with an agent that knows the project and reviews them with fresh agents that do not. The factory also uses GitHub's server for the Model Context Protocol (MCP), which lets that session read and update issues.
**Done when.** `scripts/install.sh --checkout PATH --repo OWNER/NAME` prints `READY` and exits with code 0, a person has merged the map, and an operator has enabled the repository.

The order matters. The factory takes tickets only after the project is mapped. A project that was installed but never mapped is not ready, and the installer says so.

## Before you start

| You need | Why |
|---|---|
| Claude Code 2.1.271 or later | EGM's reviewers run in fresh contexts that older versions do not isolate. |
| `git`, `python3` | The installer and the map check use them. |
| `gh`, signed in, with permission to manage labels on the repository | Only for `--repo`, which creates the labels. |
| A fine-grained GitHub token for this one repository | For the GitHub MCP server in your design session. Permissions: Issues and Pull requests read and write, Contents and Metadata read. It is your token. The factory's engine never uses it. |

Never paste the token into a chat or a file. Export it in your shell as `FACTORY_GITHUB_MCP_TOKEN` before you start Claude Code. The installer checks that the variable is set and does not read its value.

## Steps

1. **Look first.** From the factory repository, run the installer in check mode against your project. It changes nothing.

   ```bash no-run reason="the paths and the repository are placeholders for your own project"
   scripts/install.sh --check --checkout ../my-project --repo my-org/my-project
   ```

   Each line says `PRESENT`, `WOULD_ADD`, `DRIFT`, `NEEDS`, `BLOCKED` or `SKIPPED`. The end lists what you must do.

2. **Install.** Run it again without `--check`.

   ```bash no-run reason="it installs a plugin and creates labels on a repository, and the paths are placeholders"
   scripts/install.sh --checkout ../my-project --repo my-org/my-project
   ```

   It installs the EGM plugin if it is missing, adds an entry for GitHub's MCP server to `.mcp.json`, copies the issue forms, the Action and its two helper files into `.github/`, and creates the fifteen labels. It does not commit, push or start a job. A file you changed is reported as `DRIFT` and kept. Add `--update` to replace it.

3. **Start a new Claude Code session** in the project, so the `/egm` skills load.

4. **Map the project.** In that session, run:

   ```text
   /egm:egm-bootstrap .
   ```

   It writes a contract file for each directory that holds code, and it asks you before it maps more than 15 subdirectories. If people already maintain READMEs in the project, give it the file name `EGM.md` so that it does not touch them. Read what it wrote. It writes with a model, so check the claims against the code.

5. **Merge the install and the map by pull request.** Review the changed files under `.github/`, `.mcp.json` and the contract files. `.mcp.json` and `.github/workflows/` are protected paths, so only a person can change them, and the factory will never edit them.

6. **Set the Action's variable.** In the repository settings, create the variable `FACTORY_BOT_LOGIN` with the login of the factory's GitHub App, for example `my-factory[bot]`. Until it exists, nobody can set a `factory:` label by hand, which is the safe default.

7. **Check again.** Run the installer in check mode once more. It must print `READY`.

8. **Enable the repository.** An operator turns on `repositories.enabled` for the project. Today this is a database update, because the factory has no registration command yet (ADR 0016, "What is not built"). The [production guide](production.md) lists the other inputs a live run needs.

From this point a named requester can apply the `factory` label. For a new solution, use the [design guide](design-with-egm.md) first.

## What each line of the installer means

| State | Meaning | What you do |
|---|---|---|
| `PRESENT` | Already in place. | Nothing. |
| `ADDED`, `UPDATED` | The installer made the change. | Review it in the pull request. |
| `WOULD_ADD` | `--check` found a change it did not make. | Run without `--check`. |
| `DRIFT` | A file or the plugin differs from what the installer expects. It was kept. | Compare, then use `--update` if you want it replaced. |
| `NEEDS` | A person must act. | Read "Needs you" at the end. |
| `BLOCKED` | The step could not run: a tool is missing or the network failed. | Fix the cause and run again. |
| `SKIPPED` | The step needs a tool that is missing. | Fix the tool step first. |

The exit codes are 0 ready, 1 a step failed, 2 wrong arguments, and 3 not finished. Code 3 covers `BLOCKED` and `NEEDS`, so an unmapped project is exit code 3 and not an error.

## What the installer does not do

- It does not run the bootstrap. The bootstrap asks you first and spends model tokens on every directory.
- It does not write to the GitHub repository except the labels, and it does that only when you pass `--repo`.
- It does not install the factory's engine, database or worker. See the [local deployment guide](../operations/local-deployment.md).
- It does not prove the map is good. It proves that every directory with code has a contract file.

## Troubleshooting

| You see | Cause | Fix |
|---|---|---|
| `BLOCKED tools` and "older than 2.1.271" | Claude Code is too old. | Update Claude Code. |
| `DRIFT egm-plugin` | Another version of EGM is installed. | Read its release notes. The installer keeps what you have. |
| `NEEDS github-token` | `FACTORY_GITHUB_MCP_TOKEN` is not set in this shell. | Export it, then restart Claude Code from that shell. |
| `DRIFT github-mcp` with "may be a token" | A header in `.mcp.json` has a value with no `${VARIABLE}`. | Remove the token, rotate it, and run with `--update`. |
| `NEEDS project-map` | Some directories that hold code have no contract. The lines below it name them. | Step 4. |
| `NEEDS uncommitted` | Installed or generated files are not committed. | Step 5. |

## Where to read more

- [ADR 0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md): the decisions, the options that lost and what is not built.
- [The issue workflow policy](../../policies/issue-workflow.yaml): every label and every move.
- [Design a new solution with EGM](design-with-egm.md): what happens after the project is ready.
