# Ports v1.2: the issue status writer

- Status: proposed on 2026-11-02, **pending confirmation by the architect**. Specifies the addition to `ports-v1.1`. The decisions and the reasons are in [ADR 0017](../adr/0017-ports-v1-2-issue-status-writer.md). Defaults that need a person are listed at the end of that record.
- Form: reference. Read the ADR first for why, this file for what.
- Source of the code below: copied from the repository at the commit that carries this file. The code compiles and its tests pass (the commands are in the ADR, section "Confirmation"). Bodies are abbreviated where the text says so.
- What this does not change: every port of `ports-v1.1` and its contract, the state machine and the schemas. The `Rejection` enum gains one variant. Nothing about a GitHub Projects board is built; the port is kept open to one (see the ADR).
- Verified against: the fake GitHub server of the test kit (FX-GH, which gained five routes) and an in-memory fake. **Not verified against the real GitHub.**

## 1. What changes, and where

| Item | Where | Notes |
|---|---|---|
| `IssueStatusWriter`, `StatusScope`, `StatusStamp`, `StatusComment`, `LabelOutcome`, `CommentWrite` | `crates/ports/src/issue_status.rs` (new) | The port. Two operations. |
| `Rejection::LabelNotAllowed` | `crates/ports/src/githost.rs` | The adapter's answer to a label that is not a status label. |
| `StatusLabel`, `StatusLabels`, `check_status_label_name`, `IssueWorkflowPolicy` and its parts | `crates/domain/src/policy/issue_workflow.rs` (new) | The label type and the typed policy. Pure. |
| `PolicyLoader::load_issue_workflow` | `crates/contracts/src/policy/issue_workflow.rs` (new) | The strict loader. |
| `GithubIssueStatus`, `PermissionSet::issue_status`, `TokenClass::IssueStatus` | `crates/github/src/status.rs` (new), `permissions.rs`, `token.rs`, `adapter.rs` | The adapter and its credential. |
| `FakeIssueStatusWriter`, the contract suite, five routes of FX-GH | `crates/testkit/src/issue_status.rs`, `contracts/issue_status.rs`, `fx/github/routes.rs` | The fake and the suite. |
| `IssueStatusReporter` | `crates/composition/src/issue_status.rs` (new), `apps/worker/src/pipeline.rs`, `main.rs` | The worker step. |
| `CheckStatus::Degraded` | `crates/composition/src/health.rs`, `apps/api/src/health.rs` | A health status that does not stop readiness. |
| `github.write_issue_status` | `crates/composition/src/config.rs` | The switch. |
| `write_status_label`, a narrower `close_or_label_issue` | `policies/approval.yaml`, `crates/domain/tests/fixtures/policy/approval.json` | Policy rows, pending confirmation. |
| A rule for `StatusLabel::forged_for_negative_tests`, and the feature `forge-status-labels` | `docs/architecture/crate-dependency-rules.json` (`source_scans.st_13`, with `any_use`), `crates/domain/Cargo.toml`, `crates/testkit/Cargo.toml` | Only `testkit` may mention it, a call or a pointer. A production build does not contain it. |

## 2. The port

```rust
/// What a status call is allowed to touch. No stage: the credential does not depend on one.
pub struct StatusScope {
    pub tenant: TenantId,
    /// Not the job whose state is written. The tokens of a job end with the job, and its last
    /// state is written after that. A fresh identifier for each round of writes.
    pub session: JobId,
    pub repo: RepoRef,
}

/// Which version of which job a comment shows. Ordered by start time, version, then job id.
pub struct StatusStamp {
    pub started: Timestamp,
    pub version: AggregateVersion,
    pub job: JobId,
}
impl StatusStamp {
    pub fn marker(&self) -> String;                  // <!-- factory-status job=.. started=.. version=.. -->
    pub fn from_text(text: &str) -> Option<Self>;    // the last marker, exactly the written form
    pub fn mentions_marker(text: &str) -> bool;
}

/// Text from a closed template, 1 to 4000 bytes, and its stamp.
pub struct StatusComment { /* stamp, body */ }
impl StatusComment {
    pub fn new(stamp: StatusStamp, body: String) -> Result<Self, BadStatusComment>;
}

pub struct LabelOutcome { pub added: bool, pub removed: u32 }

pub enum CommentWrite {
    Created(CommentRef),
    Updated(CommentRef),
    Unchanged(CommentRef),
    /// A newer stamp is on the issue. Nothing was written; the caller writes no label either.
    Superseded(CommentRef),
}

#[async_trait]
pub trait IssueStatusWriter: Send + Sync {
    fn fidelity(&self) -> Fidelity;

    async fn set_status_label(
        &self, scope: &StatusScope, issue: &IssueRef, label: &StatusLabel,
    ) -> Result<LabelOutcome, GitHostError>;

    async fn upsert_status_comment(
        &self, scope: &StatusScope, issue: &IssueRef, comment: &StatusComment,
    ) -> Result<CommentWrite, GitHostError>;
}
```

The trait documentation states the five headings that `trait_docs_state_the_contract` checks: preconditions, postconditions, errors, idempotency, and cancellation and timeouts.

### Rules of the two operations

| Rule | `set_status_label` | `upsert_status_comment` |
|---|---|---|
| Namespace | Writes only `factory: ` labels. A name that is not one is `Rejected(LabelNotAllowed)` before any request. Takes off only labels that start with `factory: `, in either letter case. | Not applicable. |
| Idempotent | The same call again adds and removes nothing. A label that is already gone is not an error. | The same call again is `Unchanged`. |
| Order | Adds the new label first, then takes the others off, so the issue never has no status. | Never overwrites a newer stamp. |
| Which comment | Not applicable. | The lowest-numbered comment of the App's own account that carries the marker. A marker in anyone else's comment is ignored. |
| Duplicates | Not applicable. | A second comment made by a racing writer is deleted by whoever sees it. |
| Cut listing | A list of labels cut short is `Unavailable`. | A list of comments cut short with no status comment found is `Unavailable`. |
| Scope | An issue of another repository than the scope's is `NotFound`. | The same. |
| Text | Not applicable. | Secret check, then the output hygiene rules, then the marker is added. `UnsafeText` when a secret is found. |
| Pace | At least one second between two requests that change something. | The same. |

## 3. The label type

```rust
pub const STATUS_PREFIX: &str = "factory: ";

pub struct StatusLabel { /* private: name, job state */ }   // no Deserialize, no Default
impl StatusLabel {
    pub fn as_str(&self) -> &str;
    pub fn job_state(&self) -> JobStatus;
    #[cfg(any(test, feature = "forge-status-labels"))]          // only testkit enables the feature
    #[doc(hidden)]
    pub fn forged_for_negative_tests(name: &str) -> Self;       // ST-13: testkit only, any mention
}

pub fn check_status_label_name(name: &str) -> Result<(), BadStatusLabel>;

impl IssueWorkflowPolicy {
    pub fn problems(&self) -> Vec<Problem>;
    pub fn status_labels(&self) -> Result<StatusLabels, Vec<Problem>>;
}
impl StatusLabels {
    pub fn label_for(&self, state: JobStatus) -> &StatusLabel;  // total
}
```

`problems` is the Rust side of `scripts/lib/issue_workflow.py check`. It refuses: a policy id that is not `issue-workflow`; a namespace with another prefix or writer; a trigger label that is inside a namespace; a name over 50 characters or with a character that is not printable ASCII; a description over 100 characters; a color that is not six lower-case hex digits; a duplicate label (case folded); a design state that cannot be reached; a job state that is mapped twice, unknown to the engine or missing. The test `what_the_engine_reads_equals_what_the_tool_renders` compares the loaded values with `onboarding/github/issue-workflow.json`.

## 4. The adapter

The paths were read from the GitHub REST reference on 2026-11-02. The permission each needs is **unverified**; the token asks for `issues: write`.

| Call | Method and path | Notes |
|---|---|---|
| List labels | `GET /repos/{owner}/{repo}/issues/{n}/labels` | Paginated, capped. |
| Add the label | `POST /repos/{owner}/{repo}/issues/{n}/labels` with `{"labels": [name]}` | Skipped when the label is already there. |
| Take a label off | `DELETE /repos/{owner}/{repo}/issues/{n}/labels/{name}` | The name is percent-encoded. A 404 is "already gone". |
| List comments | `GET /repos/{owner}/{repo}/issues/{n}/comments` | Filtered to the App's own account and the marker. |
| Create the comment | `POST /repos/{owner}/{repo}/issues/{n}/comments` | Then a second listing, to find a duplicate. |
| Edit the comment | `PATCH /repos/{owner}/{repo}/issues/comments/{id}` | |
| Delete a duplicate | `DELETE /repos/{owner}/{repo}/issues/comments/{id}` | Best effort. |

The credential is `PermissionSet::issue_status()`: `issues: write` and `metadata: read`, one repository. The test `negative_nt_stat_02_the_token_request_is_exactly_issues_write_for_one_repository` reads the mint request that the fake server recorded.

## 5. The worker step

`IssueStatusReporter` is a `BeforeClaim` hook. It reads job rows, queues one update for each job at its newest version, and starts a task that delivers the updates one at a time. **It queues a job only when the factory has accepted the job on an issue:** the original request names an issue of the job's repository, the repository is enabled, the approval row `write_status_label` allows the job's level, and the intake stage run has passed (`intake_accepted`). `StatusStep::build` loads the policies and gives either this hook or `IssueStatusOff`, which writes nothing, reports degraded and records `issue_status.disabled`. The constants are in `crates/composition/src/issue_status.rs`:

| Constant | Value | Meaning |
|---|---|---|
| `MAX_TRIES` | 6 | Tries for one version of a job. |
| `FIRST_BACKOFF` | 30 s | The wait before the second try. It doubles. |
| `LONGEST_BACKOFF` | 20 min | The ceiling of the wait. |
| `MAX_UPDATES_PER_MINUTE` | 6 | Updates across all tenants of the worker. |
| `MAX_UPDATES_PER_HOUR` | 120 | The same, over an hour. About a fifth of a common hourly budget of an installation. |
| `RECHECK_AFTER` | 2 min | When the end state of a job is written a second time, to put right a late older write. |
| `LONGEST_RETRY_AFTER` | 1 h | The longest `Retry-After` that moves the next try. The next try is not before the larger of that wait and the back-off. |
| `ENROL_WINDOW` | 15 min | How long after its end a job the worker never wrote for is still written. |
| `MUTATION_PAUSE` (adapter) | 1 s | The gap between two requests that change something. |

Audit actions: `issue_status.written` (a success; the subject is `job <id> version <n> state <STATE>`), `issue_status.failed` (a failed try, with a fixed code) and `issue_status.disabled` (the step is off because its policy cannot be used; one record for each tenant). The policy hash on the records binds `policies/issue-workflow.yaml` to the security and approval policies. A status is written only after the job's intake stage has passed. Failure codes: `unavailable`, `rate_limited`, `forbidden`, `not_found`, `refused`, `interrupted`, `not_allowed`. The text of a comment is fixed by the function `status_text`; no model output and no text of the issue is in it.

## 6. The fake and the contract suite

`FakeIssueStatusWriter` reports `fake`. The suite `contracts::issue_status` has twelve checks, and the fake has eleven deliberate defects; `contract_register` requires each check to be named by a defect, and the test `the_status_writer_contract_catches_every_deliberate_defect` runs them. The GitHub adapter passes the same twelve checks against the fake GitHub server.

## 7. Architecture checks

`StatusLabel::forged_for_negative_tests` exists only under the feature `forge-status-labels`, which only `testkit` enables, and has an ST-13 rule with `any_use` that names `testkit` as the only crate that may mention it: a call and a function pointer alike. The source scan in `change_host_behaviour.rs` now names `status.rs` as a user of `Method::Delete` and counts its two uses. The telemetry allowlist test lists the three log fields of the step (`code`, `tries`, `gave_up`) with the reason each is safe.

## 8. What is not verified

- Everything against the real GitHub: the answers of the five routes, the permission they need, the answer to the removal of a label that is not on the issue, whether adding a label creates it, the login of an App on a comment, the real secondary limits, how GitHub renders the cleaned text.
- The worker process. The wiring compiles and the step is tested with an in-memory store, a decorated fake writer and a fake clock. No worker was started against a database and a GitHub App.
- The Action that reverts a `factory:` label written by anyone but the App.
- An independent security review.

## 9. Additive change: `WorkspaceProvider::list_branches` (2026-11-20)

A project that keeps `.factory/repository.json` closes its feature branches with gitflow, and in the `release` mode the factory works from the one open `release/` branch. To find it, `WorkspaceProvider` gains one method:

```rust
async fn list_branches(
    &self,
    job: JobId,
    target: &FetchTarget,
    prefix: &str,
    cancel: &dyn CancelSignal,
) -> Result<Vec<BranchName>, WorkspaceError>;
```

It returns the branches the remote has whose names start with `prefix`, without `refs/heads/`, sorted. The git adapter runs `git ls-remote --heads -- URL refs/heads/PREFIX*` with the fetch credential, the same remote and egress as `fetch`, and fetches nothing. It refuses a prefix that is not a branch-name prefix ending in `/`, or that starts with a character other than a letter or a digit, before git runs. A name that is not a `BranchName` is left out. The in-memory fake lists the branches of its fake remote. Every wrapper (`IndexingWorkspaces` and the test spies) passes the call to the provider it wraps: the method has no default, so a wrapper cannot answer for the provider by accident.

Nothing else of the port changes. No GitHub route, token class or permission is added. The test `list_branches_names_the_remote_branches_under_a_prefix` (`crates/sandbox/tests/workspace/behavior.rs`) runs it against a real bare repository. Like the other changes of this file, it needs an independent review and the architect's confirmation.
