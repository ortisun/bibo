# 0026: The project's rules for agents are installed by a pull request and read from the repository

- Status: **Decided by the owner (the delivery by pull request), proposed for the rest**. Built on the branch `fix/agent-report-channel`. No independent review has covered it.
- Date: 2026-11-20
- Deciders: the owner chose a file in the project, delivered by a pull request the owner approves, over "only in the agents' prompts" and over "both". The engineer chose the rest, recorded below, for the owner to confirm.
- Adds: ports v1.4, the `ProjectRulesHost` port ([ports v1.4](../architecture/ports-v1.4.md); it was v1.3 until develop's troubleshooter took that number in the merge of 2026-11-20). Related: [ADR 0014](0014-ports-v1-1-claim-protocol-and-port-revision.md) decision 7 (the factory never marks a pull request ready), [ADR 0016](0016-design-phase-onboarding-and-issue-workflow.md) (onboarding), [ADR 0017](0017-ports-v1-2-issue-status-writer.md) (a port with a credential of its own), the design in [project-rules.md](../architecture/project-rules.md).
- Revision note, 2026-11-21: [ADR 0031](0031-factory-documents-proposed-through-one-port.md) generalized the port of this record into `ProposalHost`, over a closed set of branches, so that the weekly measurement of ADR 0029 can use it too. The decisions of this record are unchanged; [ports v1.6](../architecture/ports-v1.6.md) lists the renames.

## Context and problem statement

The owner wrote rules for the agents that work on this repository (`AGENTS.md`): finish the work, weigh every option and choose for the architecture and the business, write the documents first, no calculation errors, targeted test runs. The factory's own agents, which work on other projects, did not follow them: nothing gave the rules to them, and nothing put them in the projects.

The owner decided: when a project is onboarded, and whenever the factory is updated, the factory opens a pull request in the project that creates or updates `AGENTS.md` (and the skeleton of `docs/` when it is missing). The owner approves it. The factory never merges and never writes to the default branch. The factory's agents then read the file from the repository as the project's rules.

Seven questions were left to the design. Each is below with the options weighed.

## 1. Where the template lives, and how it is versioned

1. **A Markdown file under `onboarding/project-rules/`, compiled into the binary with `include_str!`, with a version number in the code and a test that pins the digest of the text** (chosen). The files the factory puts into other projects already live under `onboarding/`. The binary needs no file at run time, so a worker cannot read a template that differs from the one it was built with. The pinned digest makes a silent edit under an old version impossible: the test fails until the version is raised.
2. A version line inside the template, parsed at run time. Rejected: a typo in the line breaks every worker at run time instead of one test at build time, and nothing forces the line to change with the text.
3. The template in the policy files (`policies/`), loaded from the protected checkout. Rejected: the policy files are configuration that operators load and hash; the rules are product text that changes with the release. Two workers with different checkouts would propose different texts under one version.

The installed file carries the version in its opening marker (`<!-- factory-rules begin version=N -->`). The factory's section is between that marker and `<!-- factory-rules end -->`; everything after it is the project's and is copied byte for byte on an update. Options weighed for the project's additions: a second file (`AGENTS.local.md`) was rejected because agent tools read one `AGENTS.md`, and a person reading the project would have to find two files; merging line by line was rejected because it is not deterministic and can mix the two texts. Markers keep one file, a stable rendering and a clear owner for each part.

**Cost:** a person who edits the factory's section by hand loses the edit at the next version (the diff of the pull request shows it). The file says so in the project's section.

## 2. A text adapted to each project, or one text for all

1. **One generic text for all projects** (chosen). The test advice says to run the tests of what changed and of what depends on it, with the commands of the project's manifest or build files, and to leave the full suite to the project's continuous integration.
2. A text rendered from the project's manifest (its build and test commands). Rejected: the same version would have different bytes in each project and whenever the manifest changes, so "same version, section changed" could no longer tell a hand edit from a manifest change, and a manifest change would open a pull request. The commands are already given to the agents through the repository map.

## 3. Which credential and port open the pull request

1. **A new port, `ProjectRulesHost`, with a token of its own: `contents: write`, `pull_requests: write`, `metadata: read`, for one repository** (chosen). It follows ADR 0017: a write that belongs to no stage gets a credential minted for that purpose, so no stage token is widened and the delivery token is not borrowed. The App already holds both permissions for the delivery stage, so the App's required permissions do not change.
2. Reuse `ChangeHost`, the delivery stage's port. Rejected: every call of `ChangeHost` carries a `GitScope` with a job and a stage, its token is the stage's, and its push goes through a fetched workspace of a job. The rules pull request has no job: a fake job id would make an audit that lies, and the delivery stage's token would be used for something no stage does.
3. Let the installer script (`scripts/install.sh`) write the file into the checkout, for a person to commit. Rejected by the owner's decision: the factory must do it at onboarding and at each update, and an update happens when the factory changes, not when a person runs the installer.

The factory gains no write to the default branch. The adapter writes only to `refs/heads/factory/project-rules` and refuses any other branch before it sends anything. The default branch is protected by a rule that requires a reviewed pull request, and the preflight checks it.

The pull request is a **draft**. A ready pull request was weighed: it saves the person one click. Rejected: the factory never marks a pull request ready (ADR 0014, decision 7, checked by the architecture rule DEP-09), and an exception for one kind of pull request would make the rule weaker for a small gain.

## 4. When "the factory is updated" is detected, and how duplicates are avoided

Options weighed for the trigger:

1. **At the onboarding acts that the worker applies (register and enable), and before each claim for the repository of each job that waits for admission, at most once an hour for each repository and template version in one worker** (chosen). The first gives the pull request at onboarding, as the owner asked. The second detects an update at the next job of each repository, with no list of repositories to keep and no new store query; it is the set of repositories the protection preflight already reads.
2. At worker start, for every registered repository. Rejected: the store has no list of a tenant's repositories, and adding one (a new query, a new grant and a migration for row-level security) buys only an earlier pull request for a repository that runs no job. A worker that restarts often would also call GitHub for every repository each time.
3. A command a person runs (`factory-cli repository rules`). Rejected as the only trigger: the owner asked for the factory to do it on update, not a person. It can be added later behind the same step.

Options weighed against duplicates:

1. **One fixed head branch, `factory/project-rules`, and a look for the factory's pull request on it before any write** (chosen). GitHub refuses a second open pull request from the same head to the same base, so even two workers that race cannot open two. No state in the database is needed.
2. A row in the database for each proposal. Rejected: a new table, migration and grants, and a second record of something GitHub already knows; the two could disagree.
3. A branch for each version (`factory/project-rules-v2`). Rejected: an old pull request would stay open beside the new one.

A pull request a person closed without merging, for the current version, is a decision: the factory does not propose that version again. The next version is proposed.

## 5. How the agents read the rules

1. **The repository stage reads `AGENTS.md` at the job's base commit and stores it as the output `project-rules`; each agent stage pins it in its contract and gives it as the input block `project_rules`, class `repo_file`** (chosen). The base commit is the one every other repository fact comes from. The repository stage already reads files through the path policy and redacts what later stages read. The stage contract pins the input by digest, so what the agent read is in the evidence.
2. Each agent stage reads the file from the job's object store itself. Rejected: seven readers of the same file, with seven chances to differ on the limit and the fallback, and no single record of what was read.
3. Let the agent tools read `AGENTS.md` from the checkout on their own. Rejected: the adapters neutralize the files a tool reads by itself (threat T-04), on purpose; and the text would not pass the redaction or appear in the context manifest.

The text is untrusted data that the project's owners approved: it goes into a quoted block, never into the instructions, and each prompt says the rules are the project's conventions that never change the role, the tools, the boundaries or the output contract. The limit is 64 KiB. Over it, or not UTF-8, the stage gives the built-in copy and records why in the map. Cutting the text was weighed and rejected: a cut drops rules silently. A file without the factory's markers is given as the pull request would install it (the factory's section, then the project's text), and a missing file as the built-in copy, so the factory's rules apply from the first job, before the pull request is merged.

## 6. `AGENTS.md` in a job

Nothing new is needed. `AGENTS.md` is in the group `agent_instruction_files` of `policies/security.yaml`, mode `deny_write`, so no agent can change it in a job and the ingestion audit refuses the change on the host. A test of the composed path rules keeps this true.

## 7. Threats

A changed `AGENTS.md` in the default branch steers every later agent (prompt injection that persists). The control is the owner's review of what is merged, which the preflight requires; the delimiting of the text in the prompt; and that no text can grant anything. This is threat T-55 in the threat model.

## Consequences

- A new port, its fake and contract suite, an adapter, one route of the fake GitHub server (`PUT /repos/{owner}/{repo}/contents/{path}`), a worker step, a configuration key (`github.propose_project_rules`, default true), one more output of the repository stage, one more input of nine agents (each prompt and input schema changes, so each manifest's prompt version rises).
- The adapter gains its first `PUT`, `Method::PutContents`, which the client and the transport refuse for any path but a file of the contents API, so it cannot reach the merge endpoint. The security test that held "no `PUT` at all" now holds "one `PUT`, contents only, sent only by the rules host". The reference routes (`/git/refs`) appear only in the rules host, built from the constant branch name. The Git data API (blobs, trees, commits) would avoid the `PUT` but needs the reference routes too and three more calls; the narrow `PUT` was chosen.
- The fixed text on untrusted data, the same in all ten prompts, gains one sentence that names the `project_rules` block as the one exception, so every prompt template version rises (the manifests keep version 1.0.0, as for every earlier prompt change). The specification writer gets the rules as the sandbox file `inputs/project-rules.md`, named by one fixed sentence of the skill instruction. The reviewers' closed input lists gain `project_rules`.
- The worker holds a `contents: write` token before admission while the check runs. The loopback scenarios that judge the intake path alone turn the check off.
- Writing a file through the contents API makes one commit for each file. A first install with the skeleton is seven small commits on the factory's branch. The Git data API (tree and commit) would make one, at the price of three more calls and more code to verify against the real GitHub; one commit for each file was chosen for fewer calls and a simpler adapter.
- Not verified against the real GitHub. The paths and the answers were read from GitHub's REST reference: the contents API (`GET` and `PUT /repos/{owner}/{repo}/contents/{path}`), the references API (`GET /repos/{owner}/{repo}/git/ref/heads/{branch}`, `POST /repos/{owner}/{repo}/git/refs`, `PATCH /repos/{owner}/{repo}/git/refs/heads/{branch}`) and the pulls API (`GET /repos/{owner}/{repo}/pulls?head=...&state=all`, `POST` and `PATCH`).

## Confirmation

The commands and their counts are in the report of the change that carries this record. The tests cover: the rendering (stable bytes, the version marker, the project's section kept, a file without markers kept whole), the decision (every row of the table in the design document), the port's contract suite against the fake and against the adapter over the fake GitHub server, the worker step's triggers, and the repository stage and the prompt assembly (the limit and the fallback).
