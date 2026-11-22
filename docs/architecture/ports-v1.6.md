# Ports v1.6: the proposal host

- Status: proposed on 2026-11-21, **pending confirmation by the architect**. Revises the project rules host of [ports v1.4](ports-v1.4.md). The reasons and the options weighed are in [ADR 0031](../adr/0031-factory-documents-proposed-through-one-port.md).
- Form: reference. Read the ADR first for why, this file for what.
- What this does not change: the four operations of ports v1.4, their errors, idempotency and timeouts; every other port; the credential (`PermissionSet::project_rules`, now used for every proposal); the state machine and the schemas.
- Verified against: the fake GitHub server of the test kit and the in-memory fake. **Not verified against the real GitHub.**

## 1. What changes, and where

| Before (v1.4) | After (v1.6) | Where |
|---|---|---|
| `ProjectRulesHost` | `ProposalHost` | `crates/ports/src/proposal.rs` (was `project_rules.rs`) |
| `RulesScope` | `ProposalScope` | same |
| `RulesPullRequest { pr, lifecycle, proposed_version }` | `ProposalPullRequest { pr, lifecycle, head, marker }` | same. `head` is the commit at the tip of the pull request's branch; `marker` is read by the branch's own form |
| `RulesProposal { base, version, files, title, body }` | `PullRequestProposal { branch, base, marker, files, title, body }` | same |
| `latest_rules_pull_request(scope)` | `latest_pull_request(scope, branch)` | same |
| `RULES_BRANCH`, `proposal_marker`, `proposed_version` | `ProposalBranch`, `ProposalMarker`, `ProposalBranch::marker_of` | same. `RULES_BRANCH` stays as the name of `ProposalBranch::ProjectRules` |
| `GithubProjectRules`, `FakeProjectRulesHost`, the contract suite of the rules host | `GithubProposals`, `FakeProposalHost`, the contract suite of the proposal host | `crates/github`, `crates/testkit` |
| — | `KnowledgeMeasurements`, `github.propose_knowledge_measurements` | `crates/composition/src/knowledge_measurements.rs` (new), `config.rs`, `apps/worker/src/pipeline.rs` |

## 2. The branches and their markers

| `ProposalBranch` | Branch | Marker at the end of the body | Commit message of a file |
|---|---|---|---|
| `ProjectRules` | `factory/project-rules` | `<!-- factory-project-rules version=N -->`, N a whole number from 1 | `Install the factory's rules for agents, version N: <path>` |
| `KnowledgeMeasurements` | `factory/knowledge-measurements` | `<!-- factory-knowledge-measurement id=M-YYYY-Www -->`, the identifier of a week's measurement | `Record the process numbers of <id>: <path>` |

`ProposalMarker` is `RulesVersion(u32)` or `Measurement(EntryId)`. A proposal whose marker is not of its branch's kind is `Rejected(Other)` before any request. `marker_of(body)` reads the last marker of the branch's form; a body without it, or with a marker in another form, gives `None`, as `proposed_version` did.

## 3. The contract

The contract of ports v1.4, section 3, with "`RULES_BRANCH`" read as "the branch of the proposal". In addition:

- `latest_pull_request` looks only at pull requests whose head is the branch named and whose author is the factory's own App, and returns the commit at the tip of that branch as `head`.
- No call writes to a branch that `ProposalBranch` does not name. A base that names any branch of `ProposalBranch` is `BranchNotAllowed`.
