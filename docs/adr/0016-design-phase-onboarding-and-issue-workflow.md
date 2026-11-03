# 0016: Design new solutions with EGM before the factory, map a project before it takes tickets, and track issues with labels

- Status: Proposed. The product owner chose the shape of the process on 2026-11-02 (design phase before the factory, install into an existing project, map the project first, track issues in GitHub). **Pending confirmation by the architect.** Part of the decision is built (the process layer). The engine work is listed in "What is not built" and is not started.
- Date: 2026-11-02
- Deciders: the product owner for scope and flow. The engineer wrote the design and the code of the process layer.
- Related: [ADR 0006](0006-spec-kit-boundary.md), [ADR 0009](0009-operating-defaults-pending-confirmation.md), [the intake rules](../../policies/approval.yaml) (section `intake`), [the issue workflow policy](../../policies/issue-workflow.yaml), [secrets and credentials](../security/secrets-and-credentials.md), [the onboarding guide](../guides/onboarding.md), [the design guide](../guides/design-with-egm.md)

## Context and problem statement

The factory starts when an authorized person applies the `factory` label to an issue. Everything before that moment is outside the product. Three gaps follow from this.

1. **A vague idea reaches the specification stage.** A new solution needs decisions: scope, trade-offs, failure behavior. The specification stage can ask at most `stages.max_clarification_rounds` questions (default 2). Decisions that need a conversation between a person and an agent that knows the project do not fit in two rounds.
2. **An existing project is a stranger.** Nothing prepares a project that already has code, READMEs and open issues. The factory cannot tell a project that has been read and understood by its owners from one that was only registered.
3. **Issues have no lifecycle before or after the label.** The factory reads labels and writes none. A person cannot see from the issue list whether an idea is being designed, approved, queued, waiting for a person or done.

How does a project come to the factory, how does a new solution get designed before a job starts, and how does a person see where each issue stands?

## What was checked

On 2026-11-02. "Verified" means read from the source named. "Unverified" means taken from a summary or not exercised.

**EGM** (the Elephant-Goldfish Model plugin, Apache-2.0, `google/elephant-goldfish-model`). Verified from the installed copy, version 0.1.0, commit `f0ba151`:
- It has seven skills: brainstorm, draft, review, review loop, resolve, bootstrap and drift report. An **Elephant** (the main session, which holds the project context and talks to a person) drafts. **Goldfish** reviewers are fresh subagents that see the document and the code, not the conversation.
- The skills cannot be started by the model. A person invokes them (`disable-model-invocation: true`), and it needs Claude Code 2.1.271 or later for reviewer isolation.
- `egm-bootstrap` writes a `README.md` (or `EGM.md`, by option) for each directory that holds code. It **asks a person before it maps more than 15 subdirectories**, it never commits, and it leaves review and commit to a person.
- The plugin adds no hook and no permission rule.

**GitHub's remote MCP server and Claude Code.** Verified from the two documentation pages on 2026-11-02: the server is at `https://api.githubcopilot.com/mcp/`; the headers `X-MCP-Toolsets`, `X-MCP-Readonly` and `X-MCP-Lockdown` narrow it; Claude Code expands `${VARIABLE}` in the `headers` of `.mcp.json`, and sends the literal text when the variable is unset. A token passed with `--header` is written to the configuration file. Unverified: what the lockdown mode filters in detail. The page names it and does not define it.

**Prior art** (read on 2026-11-02, README level and the documents named; **not** the source code):
- *super-board* (`EricTechPro/super-board`): a GitHub Projects board drives cards through Ready, Build, QA and Review. Its onboarding is a resumable wizard that checks first, shows a plan, and writes once at the end. It has a routing table from "what you have" to "which path" and a structured ticket format.
- *Fabro* (`fabro-sh/fabro`): workflows are graphs with approval nodes ("Plan, Approve, Implement"). Its installer is a prompt with `OBJECTIVE` and `DONE WHEN`, and its server stays in an install mode, doing no work, until configuration finishes.
- *Foreman* (`vercel-labs/eve-software-factory-template`): the `factory` label starts a pipeline and progress comes back as comments. Its "factory brain" keeps notes about the repository between runs.

**This repository.** Verified from the files:
- `repositories.enabled` already stops a webhook (`apps/api/src/webhook.rs`) and a submitted job (`apps/api/src/jobs.rs`).
- **No code path registers a repository.** Only a load-test script inserts one. A person would use SQL.
- The ports can read labels (`label_application`, `label_actor`) and post a comment. They have **no method that writes a label.**
- The GitHub App already has `Issues: write`, "manage factory labels" ([secrets and credentials](../security/secrets-and-credentials.md), section 3.1). A stage token is narrowed: intake and analysis get `issues: read`.
- `.mcp.json`, `.claude/**` and `CLAUDE.md` are protected paths, and a factory run never honors a project's `.mcp.json` (`policies/security.yaml`).

**Exercised:** the policy check, the rules for deciding on a label event, the installer (with a fake `claude` and a fake `gh`), the project map check and the shipped files, by 84 tests (45, 28 and 11). `actionlint`, `shellcheck` and `pyright` pass on the new files.
**Not exercised:** the Action on GitHub; `gh label create --force` against GitHub; the plugin install on a machine that has never had it; `egm-bootstrap` on any project, including this one; a real design session from brainstorm to merged pull request.

## Considered options

**A. Where EGM sits**

1. **A stage inside the engine.** The engine would call EGM. Rejected: EGM needs a conversation with a person and fresh Claude Code subagents, and the engine is a deterministic shell around agents that only propose. It would also add a stage to the state machine (13 stages today) and change the schemas and the Rust together.
2. **Replace Spec Kit with EGM.** Rejected: ADR 0006 makes Spec Kit the one specification framework, and the specification stage consumes its files through a typed contract. EGM produces a design document, which is a different artifact at a different time.
3. **A human phase before the trigger, with no change to the engine.** Chosen. The output is a design document merged under `docs/designs/` by pull request.

**B. What carries the state of an issue**

1. **Comments only (Foreman).** Rejected for state: a comment cannot be filtered in an issue list or searched, and a bot would have to edit its own comment to avoid noise.
2. **A GitHub Projects board (super-board).** Not chosen now. It needs the Projects permission on the App, which the App does not have and which widens the credential. It reads well, so a board that mirrors the labels may follow. Unverified: the exact permission and token type a board needs.
3. **Labels in two namespaces.** Chosen. `design: ...` is written by people, `factory: ...` by the factory's App, and the trigger label `factory` stays outside both. Labels work in the issue list, in search and in webhooks, and the App already holds the permission.

**C. How a project becomes ready to take tickets**

1. **Nothing: the owner decides.** Rejected: the user asked for the map first, and nothing would check it.
2. **The installer checks, and a person enables the repository** (the process layer now), and later the **engine refuses a repository without a recorded map commit**. Chosen, in two steps. The engine step is not built.
3. **Run the bootstrap inside the installer.** Rejected: the bootstrap asks a person before it maps a large tree, spends model tokens on every directory, and rewrites READMEs. It must not run unattended inside an install script.

**D. Who enforces the moves between design states**

1. **Nobody.** Rejected: two labels at once, or `approved` with no document, would make the list lie.
2. **A GitHub Action that reverts an illegal move.** Chosen as a **consistency tool, not a security control.** The webhook for the `factory` label can reach the engine before the Action reverts anything. The engine must check the design state itself when it accepts an issue.

## Decision outcome

**1. The path of a repository.** Install, then map, then enable.
- `scripts/install.sh` installs the EGM plugin if it is missing, adds an entry for GitHub's MCP server to the project's `.mcp.json`, copies the issue forms and the Action into the project's `.github/`, creates the labels with `gh`, and checks the map. It is idempotent. `--check` changes nothing. It never commits, pushes or starts a job, and it exits with 3 until the project is ready.
- A person runs `/egm:egm-bootstrap` in the project, reads the result and merges it by pull request. `scripts/lib/project_map.py` checks that every directory that holds code has a contract.
- A person enables the repository. **Today that is a database update, because no registration path exists.** The engine work below replaces it.

**2. The path of an issue.** Two tracks.
- A small, clear change uses the *change request* form, has no `design:` label, and a named requester applies `factory`.
- A new solution uses the *new solution* form, which applies `design: proposed`. A person and the Elephant brainstorm, draft and review the design (`design: in progress`, then `in review`). The merged design pull request puts the file under `docs/designs/`, the issue names it in a line `Design document: docs/designs/<name>.md`, and a person applies `design: approved`. Then a named requester applies `factory`.
- The factory writes one `factory: ...` label from the state of the job. The map from job state to label is in the policy and has one label per state of the job machine. A check fails if a state has none.

**3. The labels.** Fifteen: `factory`, four `design:` and ten `factory:`. The policy file `policies/issue-workflow.yaml` is the source. A checked JSON rendering feeds the installer and the Action. A stale rendering fails the build.

**4. Rules that hold everywhere.**
- No automation adds or removes the trigger label. The policy says a label alone never authorizes work (`label_presence_alone_is_authorization: false`). A form that applied `factory` would let a low-privilege author start a job. A test checks every form and the decision code.
- The `factory:` namespace has one writer, the App. The Action compares the login and the account type, and with no login configured nobody may write there.
- Issue text is data. The Action reads the labels and the body from GitHub again instead of trusting the event, accepts the design document only through a fixed pattern with no `..` and no symbolic link, and never builds a command from issue text.
- The MCP entry holds the **name** of a variable and never a token. The installer checks only that the variable is set. It reports a header in `.mcp.json` that has no `${...}` as a possible committed token, without showing it. The token is the operator's own and is for the design session. The engine never uses it and never reads the project's `.mcp.json`.
- The Action asks for `contents: read` and `issues: write`, pins every action to a full commit, and takes event data from the event file, not from the command line.

## Consequences

**Good.**
- The design is a reviewed document in the repository before a job exists, and the specification stage starts from a decision instead of a guess.
- A person can read the state of every issue in the issue list.
- The map is a reviewed set of files in the project, which later runs and Spec Kit can read. It is the same idea as Foreman's "factory brain", except that a person reviews it.
- Nothing in the engine changed, so no existing guarantee moved.

**Costs.**
- **The design gate is advisory until the engine is changed.** Until then a requester can apply `factory` to a design-track issue that is not approved. The Action only comments.
- Fifteen labels is a lot to learn. The `design:` track is optional, so a small change meets two of them at most.
- EGM is a third-party plugin read but not audited, version 0.1.0. The installer reports another version as `DRIFT` and keeps it. EGM reads repository text in a session that has the operator's token, so the text of the repository and of the issues can steer that session. The lockdown header and a token limited to one repository reduce the harm and do not remove it.
- The Action's `FACTORY_BOT_LOGIN` is a repository variable that someone has to set when the factory exists. Until then the `factory:` namespace is locked to everyone, which is the safe side.
- The map check follows the pruning rules of the bootstrap skill by copy, not by calling it. If the skill changes its rules, the two can disagree.
- The factory repository now holds files meant for other repositories (`onboarding/`). `scripts/ci/` and `policies/` are protected paths, so this change needs the code owners.

## What is not built

These are the engine changes the decision needs. None is started. Each changes the state machine, a schema or a port, so each lands together with its Rust and its tests, and the port change gets an independent security review.

1. **Registration and the map gate.** A way to register a repository (`factory-cli repository ...` and an API route, with audit), a `project_map_commit` column, and a rule that `enabled` needs it.
2. **The design gate at intake.** Refuse an issue that carries a `design:` label and no `design: approved`, using the labels the intake already re-reads (`intake_requirements` in the policy).
3. **Writing the state (ports v1.2).** A method that applies one `factory:` label and updates one status comment, an adapter, a fake, contract tests and the mapping from job state to label. It needs its own token narrowed to `issues: write` and nothing else, because a stage token may carry only `issues: read`. It reuses the way the API leaves a signed request for the worker to answer on the issue (as it does for a rejected requester).
4. **Configuration.** `FACTORY_BOT_LOGIN` for the Action, taken from the App's slug.

Open question for the architect: should a board (GitHub Projects) mirror the labels? It reads well and needs a permission the App does not have.

## Revision note (2026-11-02): item 1 of "What is not built" is built

Item 1, registration and the map gate, is built. Items 2, 3 and 4 are not. The status of this record does not change: it is still pending confirmation by the architect, and the roles below are the engineer's default.

**What exists now.**
- Migration `2026-11-02-002400_repository_project_map`: the columns `project_map_commit`, `project_map_attested_by_principal_id` and `project_map_attested_at` on `repositories`, a `CHECK` that a repository cannot be enabled without a map commit (it holds for every role, the table owner included), `enabled` defaulting to false, and a trigger that stamps the time from the database clock. Repositories that were enabled before it are switched off, because none had a map. **That switch-off writes no audit record**, so the audit chain does not say who or what switched them off; a deployment note should carry the count.
- Store methods `register_repository`, `attest_project_map`, `set_repository_enabled` and `find_audit`, in the fake and in PostgreSQL, under one contract suite.
- Five routes under `/v1/repositories` and the command `factory-cli repository register|confirm-map|enable|disable|show`. Each change writes its audit record in the same transaction, and a retried idempotency key repeats nothing.
- Four rows in the `actions` table of `policies/approval.yaml`: the operator registers, confirms the map and disables, and the approver enables. They are pending confirmation by the architect.
- Step 8 of the [onboarding guide](../guides/onboarding.md) now gives the commands.

**What the attestation is.** A statement by a person. The engine holds no GitHub credential, so it does not read the repository and cannot check that the commit exists, that it is on the default branch or that the map is good. It records who said so, when, and why. Nothing in the code, the answers or the documents says otherwise.

**Evidence.** All of it on 2026-11-02, on PostgreSQL 18.6 and one laptop, with no live GitHub and no Docker.
- `scripts/db-test.sh` ran all 20 suites and 1193 checks green, including the new suite `repository_map` (79 checks, with controls that switch each rule off). After the last change to a grant, the 19 suites other than `lease` passed again. `lease` is a timing test and failed while the laptop was heavily loaded; it failed in the same way with the new migration removed.
- The shared Store contract suite passes against the fake and against PostgreSQL with 8 new checks, and each of 5 new deliberate defects of the fake is caught by the check named for it.
- `apps/api/tests/repositories.rs` has 8 tests and `apps/cli/tests/api_calls.rs` 4 new ones. Breaking the role check, the narrowing, the replay check or the role of `enable` makes a named test fail. The typed answer for an enable without a map is a second guard behind the store and the table, so removing it alone changes no test.
- The run of the crates the change touches (2065 tests) passed 2063 and skipped 30. The two failures are not caused by this change: one needs a Docker image that is not on the machine, and the other (`composed_start`, the worker stops on `SIGTERM` after 30 s) fails in the same way on the base commit.

**For the architect.**
1. Are these the right roles, and should the person who confirms the map differ from the one who enables? Today one person who holds both designations can do the whole path.
2. The login of the API could write nothing to `repositories` before. It now holds column grants (insert of six columns, update of four, and since the review fixes two more). Whoever holds that database credential alone, in one session that names a tenant, can register any installation, GitHub repository id and name; write a map attestation in the name of any active human principal of that tenant; enable a repository for the commit on file; switch off every repository; switch back on one that an operator switched off as an incident response; and write the matching `repository.*` audit records with any actor. The audit records are signed by nobody and no decision key is needed. This is weaker than the signed decisions of people, and the migration comment that said "the same limit holds for the decision requests" was out of date once AUT-12 was fixed. Review finding REG-2 lists three ways forward: a signed request for the acts that widen the factory's reach (register, attest, enable), applied by the worker; a function owned by a separate role; or acceptance with an owner and a date. **This record does not choose.** The decision is the product owner's.
3. Registration trusts the operator. A GitHub repository can be registered once in the whole factory, so a wrong or hostile registration blocks the real owner. With one tenant that is harmless for credentials and for authority, and not for operations. **For a second tenant the following five things are HARD PRECONDITIONS, and without them it would be a blocker (review finding REG-3):** (1) registration that asks GitHub, with an installation token, that the repository id exists, that the installation lists it and what its full name and default branch are, and stores those values and not the typed ones; (2) an installation-to-tenant binding made by the installing person at install time and written by the platform; (3) a key on the pair of installation and repository id, and not on the repository id alone; (4) a path to unregister and to transfer a registration, under a designation of the platform; (5) an answer that does not reveal whether an id is registered elsewhere. The [production guide](../guides/production.md) lists them under "Before a second tenant".
4. There is no route that lists repositories. `show` needs the identifier that `register` printed.

## Revision note (ADR 0017)

Written on 2026-11-02. Item 3 of "What is not built", writing the state (ports v1.2), is built. The decision is in [ADR 0017](0017-ports-v1-2-issue-status-writer.md) and the signatures are in [ports v1.2](../architecture/ports-v1.2.md). The rest of this record is unchanged.

What exists now, as evidence:

- **The port, the label type, the fake and the adapter.** `IssueStatusWriter` has two operations, set the one `factory: <state>` label and keep one status comment. The label argument is a type that only `policies/issue-workflow.yaml` can make. The adapter has its own token, `issues: write` for one repository, and the stage tokens did not change. The mapping from job state to label is read by the engine with the strict policy loader, and a test compares it with `onboarding/github/issue-workflow.json`.
- **The worker step.** After a job changes state, the worker writes the label and the comment outside the engine's transaction, with retries, an audit trail and a health line. Failing or stalling GitHub does not change a job. This is tested.
- **The signed request was not reused.** This record suggested leaving a signed request for the worker, as the API does for a rejected requester. The state changes are made by the worker itself, so the step reads the job rows. ADR 0017 explains why.
- **Not verified.** All of this is tested against fakes only: an in-memory fake and the fake GitHub server of the test kit. Nothing ran against the real GitHub, the worker was not started against a database and an App, and the independent security review that this record asks for any port change has not happened.
- **A side effect on the policy file.** The strict loader reads `policy.status` as a closed set, so the file now says `designed` in lower case, and its header says that the worker reads it. The rendered JSON was made again because its source hash changed.

Item 1 is built (see the note above). Items 2 and 4 of "What is not built" are still not built. The question about a board is answered by [ADR 0018](0018-project-board-mirror-that-adapts.md).

## Revision note (review of registration and status write-back)

Written on 2026-11-02, after the independent security review in [the review](../reviews/engine-registration-and-status-security-review.md) (0 blockers, 2 major, 12 minor, 4 notes). The status of this record does not change. What changed in the registration path:

- **An enable is bound to the map the approver read (REG-1).** `POST /v1/repositories/{id}/enable` and `factory-cli repository enable REPOSITORY COMMIT` take the commit. The answer is `409` with the code `project_map_changed` when it is not the commit attested now, as an approval elsewhere in the system is bound to the head the person saw. Enabling a disabled repository again also names the commit.
- **A repository does not stay enabled over another map (REG-1).** Migration `2026-11-02-002500_repository_enabled_is_bound_to_the_map` makes the table switch an enabled repository off when its map commit or its attestor changes, for every writer. The table records the commit it was enabled for, who enabled it and when (`enabled_project_map_commit`, `enabled_by_principal_id`, `enabled_at`), and two CHECK constraints hold the record to the commit on file. Attesting another commit on an enabled repository writes a `repository.disabled` audit record in the same transaction, with the reason "the map was attested again; enable it again". The migration switches off the repositories that were enabled and writes no audit record for it.
- **Smaller fixes.** Reading a repository applies the narrowing of the caller's allowlist entry and answers `404` (REG-4). A replay of a registration is compared with the whole stored registration, not the name (REG-5). A runbook says that disable is not a stop: [stop the work on a repository](../runbooks/stop-work-on-a-repository.md) (REG-8).
- **Not changed, and waiting for a decision by the product owner.** The grants of the API login and the signed-request path (REG-2), and a rule that the person who enables differs from the person who attests (REG-6). The table now records who enabled, so the second needs no new column.

## Revision note (2026-11-02, independent review PL-1 to PL-21)

The independent review of the process layer ([report](../reviews/process-layer-security-review.md)) found that several promises of this record were stronger than the code. What changed, and what did not:

- **The Action checks the whole issue on every run** (PL-1). GitHub keeps one waiting run per issue and cancels an older waiting one, so a run can be skipped; the statement that quick changes are "handled in order" was false. Now each run keeps one `design:` label (the latest), keeps a `factory:` label only if the App set it last (read from the issue events) and keeps one, and removes `design: approved` without a design document. A wrong label can still show until the next run.
- **A symbolic link in any part of the design document path means there is no document** (the record said "no symbolic link" but tested only the last part).
- **Only comments by `github-actions[bot]` silence the design gate comment.**
- **`--check` changes nothing**, as stated, and the installer does not write through a symbolic link, does not let `bash -x` or a child program see the token, and does not call `git` in a way that runs a command of the checkout.
- **The design gate is still advisory**, and still depends on the owner requiring reviewed pull requests on the default branch. That rule is now written in the design guide.

Not changed, and not claimed: the Action was never run on GitHub; the events API and the permission API are used as GitHub documents them and not observed here.

## Revision note (2026-11-02, item 2: the design gate at intake)

Item 2 of "What is not built", the design gate at intake, is built. Item 4 is not. The status of this record does not change: it is still pending confirmation by the architect, and the designation named below is the engineer's default.

**What exists now.**
- **The rule.** At intake, after the stage has re-read the label and the person who applied it, it reads the labels of the issue from GitHub again. The webhook payload is not used. An issue that carries a label whose name starts with `design:` (in any letter case, with or without the space) needs `design: approved` as its only design label. An issue with no such label is not touched. `design: approved` counts only if the person who applied it holds the designation named by the new key `intake_requirements.design_approved_by` of `policies/issue-workflow.yaml` (default `approver`, never `requester` or `operator`). That person is found by numeric user id on the protected allowlist and is not narrowed away from the repository, by the same function that checks the requester. A look-alike (`design:approved`, `Design: approved`, a trailing space, a control character) puts the issue on the track and approves nothing.
- **The outcome.** No job state and no transition is new. Intake returns the outcome `decline`. The new gate `intake-design-approved` reports BLOCKED with the new block code `design_not_approved`, which is added to `schemas/gate-report.schema.json` and to `BlockedCode` together. The stage run is blocked as a policy violation (`S11`) and the job shows as blocked. No sandbox is made and no classifier runs. The block is listed in `gate_integrity.non_overridable_blocks`, so no override passes it: the one way through is the label on the issue, then the requester applies `factory` again. A decline for another reason is still overridable.
- **The comment.** The stage holds a token that reads issues only, so the comment is posted by the composition root through the change host, with the token of the approval stage narrowed to the repository, once for each stage run. It says that the design is not approved yet and what to do, or that the approval came from someone the factory does not accept approvals from, and it names nobody. It does not use the signed request of the refused-requester path. That path protects the worker from an audit row written by the login of the API. Here the decision is made inside the worker, so no untrusted channel stands between the decision and the reply (the same reasoning as ADR 0017 gives for the status writer). A comment that the host cannot take now fails the attempt, which is tried again.
- **Fail closed.** The rule is read from `policies/issue-workflow.yaml` for every attempt. A file that is missing, breaks the strict loader or breaks a rule gives the stage no rule, and the stage refuses every issue, with or without a design label: it blocks the stage run with the environment cause `policy_unloadable`, as it does when the allowlist cannot be read, and says in a comment that it could not check. There is no default and no copy of an earlier file. The worker still starts, because jobs past intake can go on, and prints `NOT READY: design gate`. The health line of the rule is `fail`, never `degraded`: a label that shows state is observability, and a rule that decides who may start work is a control.
- **The rest.** The row `accept_design_approval` of `policies/approval.yaml` (listed in `always_human`) and a test that it names the same designation as the key. The new key in the Python tool. The guide, the policy reference and the threat model (T-23).

**Evidence.** All of it on 2026-11-02, on one laptop, with no live GitHub, no PostgreSQL and no Docker.
- `cargo nextest run` over the eight crates and apps this change touches (domain, contracts, testkit, workflow, composition, worker, api, cli): 3505 tests, 3504 passed, 33 skipped, 1 BLOCKED. The BLOCKED test needs the Docker image `alpine/git`, which is not on the machine, and it is not counted as passed. The scenario and API tests that use intake (`complete_run` and the scenarios E3 to E9) ran on a real PostgreSQL and passed. A first run also failed `composed_start` (the worker stops on `SIGTERM`), which fails under load on the base commit too and passed in the second run.
- 41 new Rust tests. 23 are in `crates/workflow/tests/intake_repo/design.rs`: an unapproved design refused with the comment and the block code beside the same issue accepted; a requester, an operator, a stranger, an approver removed from the allowlist and an approver narrowed to other repositories each refused, beside an approver narrowed to this one accepted; a label removed or added between the webhook and intake changing the outcome; twelve hostile label names; a policy that cannot be read refusing every issue, beside the repaired policy accepting; a comment the host cannot take now and one it refuses; the override of the block refused, beside the same override passing when the entry of `non_overridable_blocks` is missing. The others are in the domain (6), the contracts (4), the intake module (3) and the composition root (5). 4 more cases and one test are added to the Python tests (67 pass).
- `crates/workflow/tests/mutations/design_gate_breaks.py` makes 12 deliberate breaks of the gate and each one is caught by a named test. The first run missed one (the comparison of the approved label, hidden by the second barrier of the lookup of its applier), so the test of look-alike names was changed to remove that second barrier, and the break is caught now.
- `./scripts/ci.sh --only rust-fmt,rust-clippy,architecture-check,policy-yaml,xtask-links,xtask-invariants,xtask-generated,docs-check,p0-coverage,pyright,shellcheck,issue-workflow-policy,issue-workflow-tests`: 13 of 13 passed, which is a partial run and not evidence that the whole of CI passes.

**Not verified.** Everything against the real GitHub: that `label_application` names the person who applied `design: approved` as the adapter's tests assume, and that the labels of a live issue are what the fake returns. A worker started against a database and an App. The scenario tests that need PostgreSQL or the Docker images. The independent security review that this record asks for. The Action was not run, and its comment stays as an early warning that no longer decides anything.

**For the architect.**
1. Is `approver` the right designation for `design: approved`? Should a `security_approver` or an `org_admin` also count? Today only the named designation counts, and a designation does not imply another.
2. With an unusable policy the gate refuses every issue. The milder choice refuses only issues that carry something that looks like a design label. It would let a small change through while the file is broken, and it would have to decide by a hard-coded prefix, which is the default this record refuses to have.
3. The block cannot be overridden. A person with the right role cannot start work on an unapproved design except by applying the label, where everybody can see it. If the project wants a break-glass, remove the entry from `gate_integrity.non_overridable_blocks`.
4. The refused attempt reports its sandbox as ready although none was made, because the engine requires it of a stage whose contract places it in a sandbox. The alternatives are a second contract for intake or a new field. Neither is built.
5. An issue that carries `design: approved` and another design label is refused. A reopened design that nobody cleaned up is not an approved design, at the price of a refusal in the moments before the Action removes the old label.
6. The reply is posted once for each stage run, with no window like the one for a refused requester (SF-16). A requester who labels again gets another comment.

## Revision note (2026-11-02, fixes after the independent review of the design gate)

The independent review ([report](../reviews/design-gate-security-review.md): 0 blockers, 3 major, 6 minor, 3 notes) found that three promises of the gate were stronger than the code. The status of this record does not change. What changed in the gate:

- **The events are read to the end (DG-1).** The adapter reads up to 30 pages of 100 events for the applier of a label, three times the cap of other listings. A list that is still cut then answers `Unavailable` in both cases, whether an event was found or not, so an older application by an approver can no longer stand in for a newer one by someone else. The latest application is the event with the greatest time and then the greatest id, so the answer does not depend on the order of the list, which nobody has observed on the real GitHub. Two events that cannot be told apart are not guessed. The adapter and the fake share one rule for this, `LabelTimeline` in the ports.
- **The design track is sticky (DG-2).** An issue is on the track when it carries a `design:` label now or when its events show that a `design:` label was ever applied. Taking the label off does not leave the track. The way out is one act of an approver: `design: approved`. An issue that was never given a `design:` label is a small change by definition. **This reverses what the guide and the Action's comment said** ("you may remove the label to leave the track"). If the events cannot be read to the end, the attempt fails.
- **Track detection reads what a person reads (DG-4).** Hidden characters (the Unicode category Cf, combining marks, variation selectors) are dropped, leading white space and symbols are skipped, and a non-ASCII character among the first seven takes the place of the one letter it could stand for. Counting as approved stays exact, byte for byte. This is a narrow rule written for the purpose and not Unicode normalization (NFKC); no dependency was added.
- **Only a person's account approves (DG-5).** The account type of the event travels through the port (`AccountType`), and a bot, an organization or an unknown type is refused as not human, even when its numeric id is on the allowlist. The same holds for the `factory` label.
- **A partial answer is not "no labels" (DG-6).** An answer from the issue API whose `labels` member is missing, null or of the wrong type, or whose items are not labels, is `Unavailable`. So is an event list with an entry that is not whole.
- **The audit line cannot be forged (DG-7).** A label name loses the characters that separate fields (`;`, `,`, `[`, `]`, `|`, quotation marks, backslash), the labels are written as a quoted list, and the audit line, the stored document and the report pass through the secret redactor.

**Not changed (when this note was written; DG-3 and DG-8 are built, see the next note).** The text of a job made through `POST /v1/jobs` or `factory-cli submit` is still not tied to the issue the job points at (DG-3). The design is still checked once, at intake (DG-8). The reply to a refusal still has no cap, its de-duplication reads 1000 comments, its token is not revoked on a retry and its audit record is lost when the comment endpoint is down (DG-9). Both are for the product owner (see the review, section 7). The notes DG-10 to DG-12 are untouched. An honest approval on an issue with more than 3000 events fails the attempt and says nothing to the requester, because telling it apart needs a new closed error in the ports.

**Not verified.** All of it ran against fakes, including a fake GitHub that serves events in pages and in either order. Nothing ran against the real GitHub: its event order, the `type` of every actor and the size of the largest list are still assumptions.

## Revision note (2026-11-02, decisions of the product owner on DG-3 and DG-8)

The product owner decided the two findings that the review left to them. The status of this record does not change: it is still pending confirmation by the architect.

- **The text of a job is the live issue's text (DG-3).** The design gate at intake compares the text the job carries with the title, a blank line and the body that the code host shows now, through the same redactor that stores the text of a webhook job. The two must be the same, or the job is refused with the reason `text_not_the_issue`. The comparison ignores only the style of the line ends and white space around the whole text. The choice among the options of the review's fix is the **strict reading**: the factory acts on the live text of the issue and on nothing else. A webhook job matches by construction. A job made through the API or the command line must carry the issue's words; the caller's notes belong in the body of the issue, and the factory keeps no separate "added note". The check is made for every job, on or off the design track, because the bypass was a job with the text of a design that is not approved pointing at an unrelated issue that is off the track. The refusal reuses the gate `intake-design-approved` and its block code `design_not_approved`, so `state-machine.json`, the schemas and `gate_integrity.non_overridable_blocks` did not change; only the reason word, the reply, the explanation and the audit line are new. No override passes it. *Consequence:* a requester can no longer submit text that differs from the issue, and the tests that did (in `apps/worker/tests/smoke.rs` and in the webhook tests) were changed to say the same words as the issue.
- **The design is checked again before the pull request (DG-8).** The delivery stage reads the labels and the events of the issue again right before it pushes the factory branch and opens the draft pull request, with the same judge as intake (`DesignJudge`; it is one code path and not a copy). An issue that is on the track without an approved design now stops the stage with `Blocked(DesignNotApproved)`: the stage run and the job are blocked as a policy violation, one comment says that no pull request was opened, and the status step writes `factory: blocked`. The block names no gate, so no override passes it; an operator unblocks the job after an approver put the label back, or the requester applies `factory` again. A read that fails is not a pass: the attempt fails, nothing is opened, the audit record says that the check could not be made (degraded) and the engine tries again until the retries run out. This also means that an approval can be taken back during the job and that the factory honours it, which changes what an approver's act of revoking means: it now revokes.

**Not changed.** DG-9 (the cap on replies, the de-duplication that reads 1000 comments, the token left after a retry and the audit record lost when the comment endpoint is down), REG-2 and REG-6 are still open and wait for the owner. The re-check posts its comment best effort and writes its audit record first, so it does not repeat the DG-9 ordering; the intake reply is unchanged.

**Not verified.** Nothing ran on the real GitHub. The delivery stage's token (`issues: write`, from the delivery permission set) reading an issue and its events is assumed, not observed. The tests use a fake that can be made unreachable. The window between the re-check and the pull request is one push and one request, not zero: an approver who takes the label back inside it is not stopped.

## Revision note (2026-11-03, decisions of the product owner on REG-6, RR-28 and REG-2)

The project owner delegated the open decisions of the registration review. The status of this record does not change: it is still pending confirmation by the architect. This note grows by one section for each decision as it is built.

### REG-6: the enabler is not the attestor, unless the repository says it has one maintainer

- **The rule.** The person who enables a repository is not the person who attested its project map. The decision was to make it a rule of the table, with a per-repository exception, `single_maintainer`, that exists so that the project owner, who works alone, can still run the factory. The flag defaults to false (strict). It is set only at registration, by an operator, with `factory-cli repository register --single-maintainer` or `"single_maintainer": true` in the body, and the audit record of the registration (`repository.registered`) carries `single_maintainer=true` or `=false` in its subject. No route, no command and no grant changes it afterwards: the API login may insert the column and nobody may update it, and a trigger refuses the API login and the worker even if a grant were given. A database administrator can change it, and the guide says that they write the audit record by hand.
- **No new columns for who enabled it.** The table already recorded `enabled_by_principal_id` and `enabled_project_map_commit` (migration `2026-11-02-002500`). Migration `2026-11-03-002600_repository_enabler_differs_from_attestor` adds the one column `single_maintainer` and the rule, in the trigger `repositories_project_map_guard` (a clear error) and in a CHECK (the second guard, binding for every role). The Store answers `Constraint(EnablerIsAttestor)`; the API answers `409` with the code `enabler_is_attestor`.
- **Fail closed when a person goes.** The attestor and the enabler were checked once, when they acted. A repository whose attestor or enabler is no longer an active human principal of the tenant is now read as closed to new jobs: the Store computes `attestor_is_active` and `enabler_is_active` on every read, `Repository::open_for_new_jobs` is the question the API (job submission, webhook) and the engine (admission) ask, and `show` reports `standing`. The stored flag `enabled` is unchanged so that a person can see what happened; jobs that exist go on (the same reach as a disable, REG-8). A column that is empty is not judged: a privileged writer that enabled without saying who has named nobody.
- **A list.** The review asked for a list of such repositories in the health report. The readiness report is tenant-blind and unauthenticated, so it is the wrong place for tenant data, and the Store has no listing of repositories. `show` reports it for one repository. A listing (`GET /v1/repositories`) needs a Store method and is not built.
- **What it costs.** The migration switches off every repository that is enabled by its own attestor (a `NOTICE`, no audit record, as in the two migrations before it). A project owner who works alone and registered a repository before this rule cannot re-register it, so a database administrator sets the flag by hand.
- **What it does not do.** It stops one person with two designations. It does not stop a holder of the API database login, who names any active human as the enabler: that is REG-2, below. The single-maintainer exception leaves, for the repositories that use it, a gate that says only that one person looked.

### RR-28: the allowlist narrows by GitHub's repository id

- **The decision.** An allowlist entry that is narrowed to repositories may carry GitHub's numeric id of each repository. When a repository that is registered (so it has an id) is asked about, the narrowing compares the id, and the name is only for people to read. A bare name still narrows by name, is the weaker form and produces a warning when the allowlist is read. The format and the loader are described in `crates/composition/README.md`.
- **What it fixes.** A repository that is renamed or transferred keeps the grant of a person who is narrowed to it, and a new repository created under the old name does not inherit it. Before, the name was the only key, so the new repository inherited the grant once it was registered.
- **Who asks with the id.** Everything that holds the registered row: the API (job submission, decisions, stage decisions, reads, the repository routes and the webhook), the claim hook, the admission of a job and the approvals of a dependency. The stages of the workflow crate are given a name and no id; for them an entry with an id means the name recorded next to it. A job or a decision reaches a stage only through one of the gates that asked with the id, so the stages are a second, conjunctive check and not the first. Giving them the id is a larger change to their inputs and is not built.
- **Operating it.** Write each narrowed entry with the id (`gh api repos/OWNER/NAME --jq .id`). A bare name keeps working so that no existing file breaks. The registration of a repository is still typed (REG-3): the id in the allowlist is only as true as the id that was typed at registration, and nothing looks at GitHub.

