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

## Ports v1.3: the troubleshooter's triage issue writer

- Status: proposed on 2026-11-20, **pending the review ADR 0016 asks for a port change**. The decision is [ADR 0021](../adr/0021-troubleshooter-agent-and-mcp-sources.md), Decision 7; this section is the revision record, in the form of v1.2 above, and no new ADR is written for it.
- What this does not change: every port of v1.2 and its contract. `GitScope`, `StatusScope` and every stage's permission set are unchanged. No existing call site changed.
- Verified against: the fake GitHub server of the test kit (FX-GH, which gained two routes) and an in-memory fake. **Not verified against the real GitHub.**

### What changes, and where

| Item | Where | Notes |
|---|---|---|
| `TriageIssueWriter`, `RunScope`, `OpenedIssue`, `SeenAgainPost` | `crates/ports/src/triage_issue.rs` (new) | The port. Four operations. |
| `Finding`, `FindingFingerprint`, `TriageLabels`, `check_triage_label_name`, `TroubleshootingRunId`; `issue::render_issue`, `issue::render_seen_again`, `TriageIssue`, `SeenAgainComment` | `crates/domain/src/troubleshooting/` (new) | The typed finding, the fingerprint, the labels and the renderer. Pure. |
| `GithubTriageIssues`, `GithubAdapter::triage_issue_writer`, `PermissionSet::troubleshoot_issue`, `TokenClass::TroubleshootIssue` | `crates/github/src/triage.rs` (new), `permissions.rs`, `token.rs`, `client.rs`, `adapter.rs` | The adapter and its credential. The minter keeps tokens per holder (a job or a run) instead of per job. |
| `FakeTriageIssues`, the contract suite, `GET` and `POST /repos/{owner}/{repo}/issues` on FX-GH | `crates/testkit/src/triage_issue.rs`, `contracts/triage_issue.rs`, `fx/github/routes.rs` | The fake and the suite. |
| A note on the token class | `policies/security.yaml`, `credentials.github_app.installation_token` | A comment; no field and no App permission changes. |

### The port

```rust
/// A run is not a job: no stage, and a credential of its own.
pub struct RunScope {
    pub tenant: TenantId,
    pub run: TroubleshootingRunId,
    pub repo: RepoRef, // troubleshooting.issue_repository; the adapter refuses any other
}

#[async_trait]
pub trait TriageIssueWriter: Send + Sync {
    fn fidelity(&self) -> Fidelity;
    async fn find_open_issue(&self, scope: &RunScope, fingerprint: &FindingFingerprint)
        -> Result<Option<IssueRef>, GitHostError>;
    async fn open_issue(&self, scope: &RunScope, issue: &TriageIssue)
        -> Result<OpenedIssue, GitHostError>;           // Opened | AlreadyOpen
    async fn post_seen_again(&self, scope: &RunScope, issue: &IssueRef, comment: &SeenAgainComment)
        -> Result<SeenAgainPost, GitHostError>;         // Posted | AlreadyThere
    async fn revoke_run_tokens(&self, run: &TroubleshootingRunId) -> Result<(), GitHostError>;
}
```

Rules of the operations:

- **The scope.** A parallel `RunScope`, not a variant of `GitScope`, as v1.2 did with `StatusScope`. ADR 0021 says "`GitScope` gains a run scope"; a variant would have changed the type every `ChangeHost` and `IssueSource` call takes, and every call site with it, for a credential that none of them may use. A parallel type changes none of them and makes the wrong call a type error.
- **Find.** The open issues that carry `troubleshooter` are listed (`GET /repos/{owner}/{repo}/issues?state=open&labels=troubleshooter&sort=created&direction=asc`, pages of 100, at most 10 pages); pull requests and issues not opened by the App's bot account are left out; the fingerprint is read from the body only, from a line that is exactly `<!-- troubleshooter-fingerprint: sha256:<hex> -->`. Several matches: the lowest number. Not found in a listing cut short at the cap: `Unavailable`. The search API is not used.
- **Open** looks first and answers `AlreadyOpen` when an issue of the fingerprint is open, so a retry after a lost answer opens nothing new. A closed issue is not reopened; the caller names it in the new issue (`Investigation::earlier_closed_issue`).
- **Seen again** posts unless the App's comment with the same key (`<!-- troubleshooter-seen-again: run=<id> sha256:<hex> -->`) is there.
- **Caps are the caller's.** The day's counts (`max_new_per_day`, `max_comments_per_issue_per_day`) live in the troubleshooter's store; the port takes an action already decided.
- **Text.** Only the renderer of `factory_domain::troubleshooting::issue` makes a `TriageIssue` or a `SeenAgainComment` (private fields). Every agent-written field is cut to its cap, put on one line, stripped of control, bidirectional, zero-width and tag characters, defanged (`<` `>` `@` `#` `://` `www.` and the marker word) and shown in a code span whose delimiter is longer than any backtick run in it. The adapter checks the rendered text and the agent's raw words for secrets and does not run the Markdown cleaner of `text.rs` over the body, because that cleaner does not know code spans.

### The credential

`PermissionSet::troubleshoot_issue()` is `issues: write` and `metadata: read`, for the configured issue repository only. The minter keeps it under a `Holder::Run`, never under a job: a job's scope that asks for `TokenClass::TroubleshootIssue` is `Forbidden` for every stage, a run can ask for no other class, a scope that names another repository is `Forbidden` before any request, and the sweeps of jobs (`sweep_orphans`, `release_idle_after`) do not touch a run's tokens. `revoke_run_tokens` ends the run; a later call for it is `Unauthorized`. The App's own permissions do not change (`issues: write` is already required).

### The fake and the contract suite

`FakeTriageIssues` reports `fake`. The suite `contracts::triage_issue` has nine checks and the fake has eleven deliberate defects; `contract_register` requires each check to be named by a defect. The GitHub adapter passes the same nine checks against FX-GH, plus tests of the request, the marker among several open issues with a spoof in a comment, a listing cut short, another repository, and the separation of the run's token from a job's.

### What is not verified

- Everything against the real GitHub: the label filter of the issue listing and its letter case, that the listing carries pull requests marked `pull_request`, what `POST .../issues` does with a label that does not exist (the installer must create `troubleshooter` and `troubleshooter: triage`), the bot login of an App's issue, how GitHub renders the code spans and the defanged text.
- The troubleshooter's own use of the port (its store of daily counts, the choice between open, comment and nothing): that is the application's, not built here.
