# Install the factory's workflow into an existing project

- Status: written on 2026-11-02 from `scripts/install.sh`, `scripts/lib/project_map.py`, the architecture decision record (ADR) [0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md) and the tests of both. The installer ran against fake `claude`, `codex` and `gh` programs and, with `--check`, against the real Claude Code and Codex on the author's machine. It has not installed the plugin on a machine that never had it, it has not created labels or a board on GitHub, and no design session has run under Codex. Step 8 was added the same day. Its commands ran in tests against a real PostgreSQL and the real API server, and not against a live deployment. The roles it names are a default that is pending confirmation by the architect.
- Form: how-to.
- Goal: take a project that already has code and issues to the point where the factory may accept tickets from it.

**Objective.** The design tools and the issue workflow are in place, and the project has been mapped. The design tool is the Elephant-Goldfish Model (EGM), a plugin for Claude Code and for Codex that drafts designs with an agent that knows the project and reviews them with fresh agents that do not. Everything below works with either tool, or with both: see [Claude Code and Codex side by side](claude-and-codex.md). The factory also uses GitHub's server for the Model Context Protocol (MCP), which lets that session read and update issues.
**Done when.** `scripts/install.sh --checkout PATH --repo OWNER/NAME` prints `READY` and exits with code 0, a person has merged the map, an operator has registered the repository and confirmed the map, and an approver has enabled it.

The order matters. The factory takes tickets only after the project is mapped. A project that was installed but never mapped is not ready, and the installer says so.

## Before you start

| You need | Why |
|---|---|
| Claude Code 2.1.271 or later, or Codex with the `plugin` command, or both | EGM's reviewers run in fresh contexts. Older Claude Code versions do not isolate them, and an older Codex has no plugins. |
| `git`, `python3` | The installer and the map check use them. |
| `gh`, signed in, with permission to manage labels on the repository | Only for `--repo`, which creates the labels. |
| A fine-grained GitHub token for this one repository | For the GitHub MCP server in your design session. Permissions: Issues and Pull requests read and write, Contents and Metadata read. It is your token. The factory's engine never uses it. |

Never paste the token into a chat or a file. Export it in your shell as `FACTORY_GITHUB_MCP_TOKEN` before you start Claude Code or Codex. The installer checks that the variable is set and does not read its value.

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

   It installs the EGM plugin if it is missing, for each of Claude Code and Codex that you have (`--agent` chooses). It adds an entry for GitHub's MCP server to `.mcp.json` for Claude Code and to `.codex/config.toml` for Codex. It copies the issue forms, the Action and its helper files into `.github/`, and creates the fifteen labels. It also looks for a GitHub Projects board: it uses the one linked to the repository, or the one you name with `--project OWNER/NUMBER`, and writes how the stages map onto it to `.github/project-board.json`. Pass `--create-project OWNER` to make a board, or `--no-board` to go without. The [board guide](project-board.md) says how it adapts to a board that already exists. It does not commit, push or start a job. A file you changed is reported as `DRIFT` and kept. Add `--update` to replace it.

3. **Start a new session** of Claude Code or Codex in the project, so the EGM skills load. In Codex, trust the project when it asks: Codex reads `.codex/config.toml` only for a project you trust.

4. **Map the project.** In Claude Code, run:

   ```text
   /egm:egm-bootstrap .
   ```

   In Codex, choose the `egm-bootstrap` skill from the skill list and give it the path `.`. It writes a contract file for each directory that holds code, and it asks you before it maps more than 15 subdirectories. If people already maintain READMEs in the project, give it the file name `EGM.md` so that it does not touch them. Read what it wrote. It writes with a model, so check the claims against the code.

5. **Merge the install and the map by pull request.** Review the changed files under `.github/`, `.mcp.json`, `.codex/config.toml` and the contract files. `.mcp.json`, `.codex/` and `.github/workflows/` are protected paths, so only a person can change them, and the factory will never edit them.

6. **Set the Action's variable.** In the repository settings, create the variable `FACTORY_BOT_LOGIN` with the login of the factory's GitHub App, for example `my-factory[bot]`. Until it exists, nobody can set a `factory:` label by hand, which is the safe default. If you use a board, set its credential as well, as the [board guide](project-board.md) describes.

7. **Check again.** Run the installer in check mode once more. It must print `READY`.

8. **Register the repository, confirm the map and enable it.** The engine accepts tickets from a repository only after these three commands, and the last one is refused until the second has been done. Each command needs the address of the API and the token file of a person who holds the right designation on the protected allowlist. The [commands reference](../reference/commands.md) lists the options.

   **These three commands are requests that the worker applies.** The API records a signed request and answers `202`. The worker verifies the signature, asks the protected allowlist again whether you hold the designation, applies the change and records the result. The command waits for that, one second at a time, for at most 60 seconds (`--wait-seconds N` changes it, `0` does not wait), and prints the repository when the worker has applied the request. So a worker must be running for the commands to finish. If the worker is down or slow, the command ends with exit code 3 and prints the id of the request. Nothing is lost: the request stays until the worker settles it, and `factory-cli repository change REQUEST_ID` shows its state (`requested`, `applied` or `refused` with a code). A script that runs these commands, such as an installer step of your own, should treat exit code 3 as "not yet" and look again, and should treat exit code 2 as final. Disabling is not a request: the API does it at once.

   First, an operator registers the repository. The command needs the number of the GitHub App installation (it is in the address of the installation's settings page) and GitHub's numeric identifier of the repository (`gh api repos/OWNER/NAME --jq .id` prints it). The repository starts **disabled**, at autonomy level `L0`, with no project map. The command prints its identifier, which the next commands take.

   ```bash no-run reason="the address, the token files, the numbers and the names are placeholders for your own deployment"
   factory-cli repository register --api https://factory.example.org --token-file operator.token --installation 123456 --github-repository 7890123 --name my-org/my-project
   ```

   Second, an operator confirms the map. Give the commit of the default branch that holds the merged map files, and say what you read to be able to vouch for them. The reason has at least 10 characters.

   ```bash no-run reason="the identifier, the commit and the reason are placeholders for your own repository"
   factory-cli repository confirm-map --api https://factory.example.org --token-file operator.token REPOSITORY_ID 0123456789abcdef0123456789abcdef01234567 I read the contract files in the merged pull request and they match the code.
   ```

   **This is a statement by a person. The factory does not check it.** The engine holds no GitHub credential and does not read your repository, so it cannot tell whether the commit exists, whether it is on the default branch or whether the map is any good. It records who said so, when, and why. Check the map before you say so.

   **Two different people.** The factory asks for two people. The person who confirms the map is not the person who enables the repository, and the database refuses the same person for every role (finding REG-6). If you work alone, you cannot meet that rule, so register the repository as a single-maintainer one: see "A single-maintainer repository" below. You say so once, when you register, and nothing changes it afterwards.

   Third, an approver enables the repository and names the commit they read. `repository show` prints the commit that was confirmed. The command is refused with the code `project_map_not_attested` while no map was confirmed. It is refused with the code `project_map_changed` when the commit you name is not the one confirmed now. The database refuses the same changes for every role.

   ```bash no-run reason="the identifier and the commit are placeholders for your own repository"
   factory-cli repository enable --api https://factory.example.org --token-file approver.token REPOSITORY_ID 0123456789abcdef0123456789abcdef01234567
   ```

   The worker checks the allowlist again, so a person who was taken off the list between the command and the worker's turn is refused (`not_permitted`), and so is a person who is no longer an active person of the tenant.

   A repository stays enabled only for the map it was enabled for. If an operator confirms another commit later, or the same commit by another person, the repository is switched off by that change. The audit log gets a `repository.disabled` record. An approver then reads the new map and enables the repository again with the new commit.

   **An upgrade switches off the repositories that were enabled.** The database migrations that add the project map and the record of the enabling switch off every repository that was enabled before. They write no audit record, so the log does not say who or what switched them off. After such an upgrade, enable each repository again with this third command.

   `factory-cli repository show REPOSITORY_ID` prints what is recorded, the rule that applies to the repository (strict or single maintainer) and whether the repository is open for new jobs, and `factory-cli repository disable REPOSITORY_ID` stops the repository from taking tickets again: its webhooks are dropped and no job can be submitted for it. Jobs that already exist are not touched, and their issues keep their last label. To stop the work in an incident, follow the [runbook](../runbooks/stop-work-on-a-repository.md). The commands that change something take `--key`, the idempotency key, so that a retry repeats nothing. Every change writes an audit record. The [production guide](production.md) lists the other inputs a live run needs.

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

## A single-maintainer repository

A project owner who works alone holds every designation and is the only person who can attest a map or enable a repository. The strict rule would lock that owner out of their own project, so there is one explicit exception, and it is written down where it is made.

- **How.** Register the repository with the switch `--single-maintainer`.

  ```bash no-run reason="the address, the token file, the numbers and the name are placeholders for your own deployment"
  factory-cli repository register --api https://factory.example.org --token-file operator.token --installation 123456 --github-repository 7890123 --name my-org/my-project --single-maintainer
  ```

  The same person may then run `confirm-map` and `enable`. `repository show` prints "Rule: single maintainer".
- **Who and when.** Only an operator can say it, and only when registering. It is in the audit record of the registration (`repository.registered`, subject `single_maintainer=true`), so the log shows who chose it and when. The database refuses every change of the flag by the API login and by the worker, and no command changes it.
- **What it gives up.** The second pair of eyes on the map. The person who reads the map and the person who lets the repository take tickets are the same, so nothing but that person's care stands between a wrong map and a running factory. Choose it for a project of one person. Do not choose it to save a step in a team.
- **A repository registered before this rule.** The migration `2026-11-03-002600` switches off every enabled repository whose enabler is its attestor, with a `NOTICE`, and writes no audit record. Another person can enable it. A project owner who works alone cannot re-register it (a GitHub repository is registered once), so a database administrator sets the flag by hand with a statement such as `UPDATE repositories SET single_maintainer = true WHERE id = '...'` as the table owner, and writes an audit record that says who asked for it and why. Nobody else can: the API login and the worker have no grant on the column, and a trigger refuses them even if they had one.
- **Not a tenant setting.** The flag is for one repository. Another repository of the same owner is strict unless it was registered with the switch too.

## What the installer does not do

- It does not run the bootstrap. The bootstrap asks you first and spends model tokens on every directory.
- It does not write to the GitHub repository except the labels, and the board when you ask for one with `--create-project`. It does both only when you pass `--repo`.
- It does not install the factory's engine, database or worker. See the [local deployment guide](../operations/local-deployment.md).
- It does not prove the map is good. It proves that every directory with code has a contract file.

## Troubleshooting

| You see | Cause | Fix |
|---|---|---|
| `BLOCKED claude` and "older than 2.1.271" | Claude Code is too old. | Update Claude Code. |
| `BLOCKED codex` or `BLOCKED agents` | Codex has no `plugin add` command, or neither tool is on the `PATH`. | Update or install one. The [side-by-side guide](claude-and-codex.md) has the details. |
| `DRIFT egm-plugin` | Another version of EGM is installed. | Read its release notes. The installer keeps what you have. |
| `NEEDS github-token` | `FACTORY_GITHUB_MCP_TOKEN` is not set in this shell. | Export it, then restart Claude Code or Codex from that shell. |
| `DRIFT github-mcp` with "may be a token" | A header in `.mcp.json` has a value with no `${VARIABLE}`. | Remove the token, rotate it, and run with `--update`. |
| `NEEDS project-map` | Some directories that hold code have no contract. The lines below it name them. | Step 4. |
| `NEEDS uncommitted` | Installed or generated files are not committed. | Step 5. |
| `factory-cli` says the repository has no project map that a person attested | You ran `repository enable` before `repository confirm-map`. | Step 8, second command. |
| `factory-cli` says the project map was attested again since you read it | An operator confirmed another commit after you ran `repository show`. | Run `repository show`, read the new map, and enable the repository with the new commit. |
| A repository that took tickets stopped taking them | An operator confirmed the map again, or an upgrade switched off every enabled repository. | Run `repository show`. The enabled line says no. Enable it again with the commit that was read. |
| `factory-cli` says the request conflicts with a request already recorded, on `repository register` | That GitHub repository is already registered, by you or by someone else, or you reused a key for another request. | Run `repository show` with the identifier you were given. Use a new `--key` for a new request. |
| `factory-cli` says you attested this repository's project map and another person enables it | The repository is strict (the default) and you confirmed the map. | Ask another person with the approver designation to enable it. If you are the only maintainer, see "A single-maintainer repository". |
| `repository show` says the repository is enabled but not open for new jobs | The person who confirmed the map, or the person who enabled the repository, is no longer an active human of the tenant (they were switched off). Webhooks and job submissions are dropped, and jobs that exist go on. | Another operator confirms the map again, and another approver enables it for the new commit. |
| `factory-cli` says the worker refused the request, with "checked the protected allowlist again" | Your entry held the designation when you asked and does not hold it, or does not reach this repository, when the worker applied the request. | Ask the owner of the allowlist. Narrowed entries list the GitHub id of the repository (RR-28). |
| `factory-cli` ends with exit code 3 and "The worker had not applied it" | No worker is running, or it is busy or cannot read the allowlist. | Start or fix the worker, then `factory-cli repository change REQUEST_ID`. Do not send the request again with a new key. |
| `factory-cli` says you are not permitted | Your allowlist entry does not hold the designation. The operator registers, confirms and disables. The approver enables. An entry narrowed to other repositories holds nothing here. | Ask the owner of the allowlist. |

## Where to read more

- [ADR 0016](../adr/0016-design-phase-onboarding-and-issue-workflow.md): the decisions, the options that lost and what is not built.
- [Show the issue workflow on a board](project-board.md) and [Claude Code and Codex side by side](claude-and-codex.md), with their decision records [0018](../adr/0018-project-board-mirror-that-adapts.md) and [0019](../adr/0019-claude-code-and-codex-alike.md).
- [The issue workflow policy](../../policies/issue-workflow.yaml): every label and every move.
- [Design a new solution with EGM](design-with-egm.md): what happens after the project is ready.
