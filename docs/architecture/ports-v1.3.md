# Ports v1.3: the project rules host

- Status: proposed on 2026-11-20, **pending confirmation by the architect**. Specifies an addition to `ports-v1.1` and `ports-v1.2`. The decisions and the reasons are in [ADR 0026](../adr/0026-project-rules-installed-by-pull-request.md); the design is in [project-rules.md](project-rules.md).
- Form: reference. Read the design first for why, this file for what.
- What this does not change: every port of `ports-v1.1` and `ports-v1.2` and its contract, the state machine and the schemas of `schemas/`.
- Verified against: the fake GitHub server of the test kit (FX-GH, which gained one route) and an in-memory fake. **Not verified against the real GitHub.**

## 1. What changes, and where

| Item | Where | Notes |
|---|---|---|
| `ProjectRulesHost`, `RulesScope`, `DefaultBranch`, `FileAt`, `RulesPullRequest`, `ProposedFile`, `RulesProposal`, `RULES_BRANCH`, `RULES_FILE`, `MAX_RULES_FILE_BYTES`, `proposal_marker`, `proposed_version` | `crates/ports/src/project_rules.rs` (new) | The port. Four operations. |
| `TEMPLATE_VERSION`, `render`, `classify`, `decide`, `rules_for_agents` and their types | `crates/domain/src/project_rules.rs` (new) | The template, its rendering and the decision. Pure. |
| `GithubProjectRules`, `PermissionSet::project_rules`, `TokenClass::ProjectRules` | `crates/github/src/project_rules.rs` (new), `permissions.rs`, `token.rs`, `adapter.rs` | The adapter and its credential. |
| `FakeProjectRulesHost`, the contract suite, the route `PUT /repos/{owner}/{repo}/contents/{path}` of FX-GH | `crates/testkit/src/project_rules.rs`, `contracts/project_rules.rs`, `fx/github/routes.rs` | The fake and the suite. |
| `ProjectRulesSync` | `crates/composition/src/project_rules.rs` (new), `pipeline.rs`, `repository_changes.rs` | The worker step and its two triggers. |
| `github.propose_project_rules` | `crates/composition/src/config.rs` | The switch. Default true. |
| The output `project-rules` of the repository stage, the input `project_rules` of nine agents | `crates/workflow/src/stages/`, `agents/` | Not a port change; listed for completeness. |

## 2. The port

```rust
/// The branch every rules pull request of the factory comes from.
pub const RULES_BRANCH: &str = "factory/project-rules";
/// The file the rules live in, at the root of the repository.
pub const RULES_FILE: &str = "AGENTS.md";
/// The most bytes of the rules file the factory reads: 64 KiB.
pub const MAX_RULES_FILE_BYTES: u64 = 65_536;

/// What a rules call may touch. A credential is minted for exactly this. No stage.
pub struct RulesScope {
    pub tenant: TenantId,
    /// The identifier the credential is kept under and ended by (`revoke_job_tokens`).
    /// Not a job: a fresh identifier for each check.
    pub session: JobId,
    pub repo: RepoRef,
}

/// The default branch and the commit at its tip, read together.
pub struct DefaultBranch {
    pub name: BranchName,
    pub commit: CommitSha,
}

/// A file read at one commit.
pub enum FileAt {
    Missing,
    Found(Vec<u8>),
    /// Larger than the limit the caller gave. Its bytes were not read.
    TooLarge,
}

/// The newest pull request of the factory's own App on `RULES_BRANCH`.
pub struct RulesPullRequest {
    pub pr: PullRequestRef,
    pub lifecycle: PullRequestLifecycle,
    /// The version in the hidden marker of its body, or `None` when there is none.
    pub proposed_version: Option<u32>,
}

/// One file to write on the rules branch.
pub struct ProposedFile {
    pub path: RepoPath,
    pub bytes: Vec<u8>,
}

/// What to propose.
pub struct RulesProposal {
    /// The default branch, and the commit a new rules branch starts from.
    pub base: DefaultBranch,
    /// The template version, written in the hidden marker of the body.
    pub version: u32,
    pub files: Vec<ProposedFile>,
    pub title: String,
    pub body: String,
}

#[async_trait]
pub trait ProjectRulesHost: Send + Sync {
    fn fidelity(&self) -> Fidelity;

    /// The default branch of the repository and its tip.
    async fn default_branch(&self, scope: &RulesScope) -> Result<DefaultBranch, GitHostError>;

    /// The file at `path` at `commit`, read only up to `max_bytes`.
    async fn read_file(
        &self,
        scope: &RulesScope,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
    ) -> Result<FileAt, GitHostError>;

    /// The newest pull request that the factory's own App opened from `RULES_BRANCH`, in any
    /// state, or `None`.
    async fn latest_rules_pull_request(
        &self,
        scope: &RulesScope,
    ) -> Result<Option<RulesPullRequest>, GitHostError>;

    /// Writes the files on `RULES_BRANCH` and opens a draft pull request into the default
    /// branch, or updates the open one. Never writes to another branch, never merges, never
    /// marks a pull request ready.
    async fn propose(
        &self,
        scope: &RulesScope,
        proposal: &RulesProposal,
    ) -> Result<PullRequestRef, GitHostError>;
}
```

## 3. The contract

**Preconditions.** The scope names the tenant and one repository. The caller decided that a proposal is needed (the port authorizes nothing). The title and the body come from a closed template, never from a model or from the repository.

**Postconditions.**

- `default_branch` reads the repository's default branch and the commit at its tip.
- `read_file` reads a file at a commit. A path that is not there, or is a directory, is `Missing`. A file over `max_bytes` is `TooLarge` and its bytes are not returned.
- `latest_rules_pull_request` looks only at pull requests whose head is `RULES_BRANCH` and whose author is the factory's own App. A pull request a person opened from a branch of that name is not the factory's. The version is read from the marker `<!-- factory-project-rules version=N -->` at the end of the body; a body without it, or with a marker in any other form, gives `None`.
- `propose`, with no open rules pull request: points `RULES_BRANCH` at `base.commit` (creates it, or moves it there), writes each file whose bytes differ on that branch, and opens a **draft** pull request from `RULES_BRANCH` into `base.name`. With an open one: writes each file that differs on top of the branch, without moving the branch back, and replaces the title and the body. The body passes the secret check and the output hygiene rules, and the marker is added after them.
- No call writes to any branch but `RULES_BRANCH`.

**Errors.** `GitHostError`. `Forbidden` when the credential lacks a permission, `NotFound` for a repository the scope does not cover, `BranchNotAllowed` if a base names `RULES_BRANCH` itself or is not a valid branch, `UnsafeText` when the body holds something that looks like a secret (nothing is sent), `Rejected(TextBounds)` for an empty title or body, `Conflict` when the branch moved while files were written, `RateLimited` and `Unavailable` for the host.

**Idempotency.** `propose` with the same proposal a second time writes no file (the bytes are the same) and opens no second pull request; it updates the title and the body of the open one to the same text. The reads are reads.

**Cancellation and timeouts.** Every call is safe to drop, with the effect of a request already sent being possible: a branch created and no pull request yet. The next call finds the branch and finishes. The adapter sets a request timeout of 30 seconds and reports `Unavailable` when it is exceeded.

## 4. The one `PUT`

A file is written with `PUT /repos/{owner}/{repo}/contents/{path}`. The adapter's wire module gained exactly one method for it, `Method::PutContents`. The client refuses it, before it asks for a token, for any path that is not a file of the contents API (`is_contents_path`), and the transport refuses it again. A merge, also a `PUT`, therefore cannot be sent. `crates/github/tests/security_review/main.rs` holds that `PutContents` is the only `PUT` and that only the rules host and the client's guard name it.

## 5. The credential

`PermissionSet::project_rules`: `metadata: read`, `contents: write`, `pull_requests: write`, for one repository, minted under `TokenClass::ProjectRules`, which does not depend on a stage. The minter checks the answer of GitHub against the request as for every token, so a token wider than this is not used. No stage holds this set, and nothing a sandbox sees carries it.

## 6. The worker step

`ProjectRulesSync` (composition) runs the check for one repository: `default_branch`, `read_file` of `AGENTS.md` and of each skeleton file, `latest_rules_pull_request`, then the pure `decide`, then `propose` when the decision says so. It writes the audit record `project_rules.proposed` when it opened or updated a pull request, and `project_rules.not_proposed` when the installed file cannot be read. It never fails a request, a claim or a job: a failure is logged and tried again at the next occasion after an hour. It is called after the worker applied a register or an enable request, and before each claim for the repository of each job waiting for admission.
