# 0017: Ports v1.2: write the state of a job on its issue through a port of its own, with a label type that only the policy can make

- Status: Proposed. Built and tested against fakes. **Pending confirmation by the architect.** An independent security review was done (see [the review](../reviews/engine-registration-and-status-security-review.md), part B) and its findings are handled in the revision note at the end. Nothing here has run against the real GitHub.
- Date: 2026-11-02
- Deciders: the engineer wrote the design and the code. The product owner asked for the feature in [ADR 0016](0016-design-phase-onboarding-and-issue-workflow.md) ("What is not built", item 3). The architect decides whether to accept it.
- Related: [ADR 0004](0004-event-model.md), [ADR 0009](0009-operating-defaults-pending-confirmation.md), [ADR 0014](0014-ports-v1-1-claim-protocol-and-port-revision.md), [ADR 0016](0016-design-phase-onboarding-and-issue-workflow.md), [ports v1.2](../architecture/ports-v1.2.md) (the signatures and the change tables), [the issue workflow policy](../../policies/issue-workflow.yaml), [secrets and credentials](../security/secrets-and-credentials.md), [the threat model](../security/threat-model.md) (T-42 to T-44)

## Context and problem statement

ADR 0016 gave every issue a lifecycle in labels: the `design:` labels are written by people and ten `factory:` labels are meant to show the state of a job. The policy maps each job state to exactly one label, and a GitHub Action reverts any `factory:` label that the factory's App did not write. Nothing writes them. The ports can read labels (`label_application`, `label_actor`) and post a comment (`ChangeHost::post_comment`), and have no method that writes a label.

Three facts make this more than one new method.

1. **A stage token is narrow on purpose.** The tokens for intake and analysis hold `issues: read`. The delivery token holds much more. Writing a label with either would widen a stage token or borrow a token that can push code.
2. **The label is the trigger's neighbour.** The factory starts work when a named person applies the label `factory`. A defect that makes the factory write that label, or a `design:` label, would start a job without a person or move a design that only people may move. The call must be hard to get wrong.
3. **Labels are observability.** A job must never wait for, fail on or roll back because of a label.

How does the factory write the state of a job on its issue, with a credential no wider than the write, a label that cannot be the wrong one, and no way to hurt a job?

## What was checked

On 2026-11-02. "Verified" means read from the source named. "Unverified" means taken from a summary, or not exercised.

**This repository (verified by reading the files, and by the tests listed under "Confirmation").**
- `crates/ports/src/githost.rs` has no method that writes a label. `post_comment` is at least once by key with a hidden marker.
- `crates/github/src/permissions.rs` and `token.rs`: a token is minted for one repository and one set of permissions, and the minter refuses a token that carries more than was asked. A job's tokens end with the job and a job that ended can never mint again. `crates/composition/src/token_sweep.rs` revokes the tokens of every job that is not open or being worked on.
- `policies/approval.yaml` had `close_or_label_issue` at L1 and no action at L0. A repository without branch-protection rules runs at L0 (ADR 0009 item 3).
- The API's database login may write only a fixed list of audit actions (`migrations/2026-10-29-002100_api_audit_actions`). The worker's login is not held to that list.
- The webhook path makes a job for a labelled issue and leaves the issue only in an audit record. The intake stage later fetches the issue and stores revision 1 of the request, with a pointer to the issue. A job from `POST /v1/jobs` stores that request at submission.
- `crates/contracts` loads each policy through one strict loader: one YAML document in the restricted subset, `schema_version` first, unknown fields denied at every depth.

**GitHub's REST reference, read on 2026-11-02 through a fetch tool that summarises each page.** The wording below is the summary, not a verbatim reading.

| Statement | Status |
|---|---|
| `GET`, `POST` on `/repos/{owner}/{repo}/issues/{issue_number}/labels` list and add labels. `DELETE .../labels/{name}` removes one and "returns a 404 Not Found status if the label does not exist". | VERIFIED for the paths and the 404 sentence |
| Whether a 404 on removal means "not on the issue" or "not in the repository". | UNVERIFIED. The adapter treats every 404 on removal as "already gone". |
| Whether adding a label that does not exist in the repository creates it. | UNVERIFIED. The page does not say. The installer creates the labels first, so the code does not depend on it. |
| `GET .../issues/{n}/comments`, `PATCH .../issues/comments/{id}` and `DELETE .../issues/comments/{id}` list, edit and delete a comment. A comment has a `user` with `login` and `type`, and a nullable `performed_via_github_app`. | VERIFIED for the paths and the fields |
| That the `user.login` of an App's comment is `<slug>[bot]`. | UNVERIFIED. The existing comment lookup relies on it too. |
| The fine-grained permission each endpoint needs. | UNVERIFIED. Neither page names one. The secrets document (section 3.1) says `Issues: write` manages labels, and that is what the token asks for. |
| For many changes, "wait at least one second between each" POST, PATCH, PUT or DELETE, make them serially, honor `retry-after`, and when there is no header wait a minute and back off. | VERIFIED. The page gives no per-minute or per-hour number. |

**Not checked:** any behaviour of the real GitHub, of a real App token, or of a real rate limit. The six updates a minute are a guess that is conservative against the page's advice.

## Decisions

### 1. A new port, `IssueStatusWriter`, not a method on `ChangeHost`

It has two operations: set the status label (add the one, take every other `factory: ` label off, idempotent, a label that is already gone is not an error) and upsert the status comment (found by a hidden marker among the comments of the App's own account, edited in place, never a second one). The scope is a new `StatusScope` with a tenant, a repository and a session identifier, and no stage: the credential does not depend on a stage, and a field that was ignored would mislead. The port is open to a later board in the way the ADR 0016 question asks (the stamp gives it the same "newest wins" rule), and no board is built.

### 2. The label is a type that only the policy can make

`StatusLabel` (in `factory-domain`, module `policy::issue_workflow`) has private fields, no `Deserialize`, no `Default` and no constructor from text. The only way to get one is `StatusLabels::label_for`, and the only way to get `StatusLabels` is `IssueWorkflowPolicy::status_labels`, which refuses a policy that breaks any rule: a missing or invented job state, a state mapped twice, the trigger label inside a namespace, a name over 50 characters, a description over 100. The trigger label, a `design:` label and any other label cannot be represented.

The adapter checks again. `check_status_label_name` is one pure function used when the labels are built and by every adapter before a request: the name must start with `factory: `, have a name after it, be at most 50 printable ASCII characters and have no space at either edge. A value that got past the type is `Rejected(LabelNotAllowed)`, and no request is made, not even the one for a token. The adapter takes off only labels that start with `factory: `, in either letter case, because a look-alike in capitals is still in the namespace that the factory owns.

One function, `StatusLabel::forged_for_negative_tests`, skips the policy so that the adapter's own refusal can be shown to work. **It does not exist in a production build** (review finding STS-5). It is compiled only for the unit tests of `factory-domain` and when the cargo feature `forge-status-labels` is on, and only `testkit` turns that feature on; `testkit` is a dev-dependency of every crate that uses it. A call from production code does not compile. The architecture check ST-13 is a second barrier: it names the one crate (`testkit`) that may mention the function, and it flags any mention of the path, a call or a pointer to the function alike, because `.map(StatusLabel::forged_for_negative_tests)` has no `(` after the path.

### 3. A token of its own: `issues: write` for one repository

`PermissionSet::issue_status()` asks for `issues: write` and `metadata: read` and nothing else, in a new token class that ignores the stage. A stage token stays as narrow as before (a test mints an intake token and a status token in one run and compares them). The `metadata: read` is in every token set of this adapter, because the minter refuses an answer that carries a permission that was not asked for, and the real GitHub is not known to leave it out. It grants no write. This is a small difference from the words "`issues: write` and nothing else", and it is listed in "Decisions that need a person".

A job's tokens end with the job, and the last state (`done`, `failed`) is written after that. So each round of writes uses a **fresh session identifier** as the key of its credential, ends the credential when the round is over, and notes the identifier in the set of jobs the process is working on, so that the sweep of ended jobs leaves it alone while it runs.

Two details came from the review (finding STS-4). The sweep asks which jobs the process is working on **after** it has listed the live tokens, not before it asked the database, so that a round that began meanwhile is spared (a token is minted after its session is noted, so a token in the list has its session in the answer). And a round is a guard: if the task panics or is dropped, the guard lifts the shield and ends the credential from a task of its own, so that neither stays for the life of the process.

### 4. The comment is found by a marker and ordered by a stamp

The marker is `<!-- factory-status job=<id> started=<time> version=<n> -->`, added after the text is cleaned (the cleaning removes HTML comments). It is found only among comments written by the App's own account. A marker pasted by a person is not one. The stamp orders by the job's start time, then its version, then its id, so a later job on the same issue replaces the comment of an earlier one, and within a job a higher version replaces a lower one. A comment that shows a newer stamp is never overwritten (`Superseded`), and the worker then skips the label too, so the comment is the fence for the pair. GitHub has no conditional edit, so a second worker's older write can still land after a newer one (review finding STS-3). For that reason the end state of a job is written a second time after two minutes. The second write is idempotent, never overwrites a newer stamp, is not recorded and is not retried. If two writers create the comment at once, both look again, the lowest id stays and the others delete theirs. A listing that was cut short by the page cap with no comment found is an error, not a reason to post a second comment.

### 5. The worker finds changes by reading job rows, and writes from a task of its own

The step `IssueStatusReporter` runs before each claim. It reads the open jobs and the newest hundred (a few read-only queries) and compares the version of each job with the version it has written. That is level-triggered: a missed signal, a restart or a second worker cannot lose a change. A job that leaves the lists is read by id. The outbox is not used as the read model, which ADR 0014 says it is not. The signed request that ADR 0016 suggested is not used either: that pattern protects the worker from an audit row written by a database login that the API holds, and here the source is the engine's own job rows, written by the worker role.

The writes run in a task that the hook starts and does not wait for, one update at a time, so a slow or failing GitHub never delays a claim. A success is an audit record `issue_status.written` (the API's login cannot write that action), which also tells a restarted worker which jobs it was writing for. A failed try is `issue_status.failed` with a fixed code and no text from GitHub. Retries wait 30 seconds and double, up to six tries, and a refusal that a retry cannot cure (forbidden, refused text, not found) is not retried. When GitHub asked the adapter to wait and the wait was too long to sleep through, the adapter reports it and the next try is not before the larger of that wait and the back-off (review finding STS-2). The next version of the job starts again.

**Which jobs get a status.** The step writes for a job only when the factory has accepted the job on an issue. Exactly this, and nothing less (review finding STS-1):

1. The job's stored original request names an issue in the job's own repository. The repository names are compared without regard to case, as GitHub does, and the issue is addressed with the name as registered.
2. **The intake stage run of the job has passed.** A run that passed and was replaced afterwards counts. Intake is where the label, the person who applied it and the five-second rule are checked against GitHub (AUT-11). Before it passes, the factory has accepted nothing.
3. The repository is registered and enabled. This is checked when the job is read and again before the write.
4. The row `write_status_label` of the approval policy allows the job's autonomy level (see section 6).

The rule covers every job, whoever made it: a job from a webhook, from `POST /v1/jobs`, or from a row that a holder of the API database login inserted. A job that intake refuses, that is refused at admission, or that ends before intake passed gets no status at all, not even its last state. A job in `RECEIVED` has not been through intake, so **the label `factory: queued` exists in the policy (one label for each job state) and the step never writes it**; the first status a job shows is `factory: working`.

*What the first version of this record said, and why it was wrong.* It said the worker writes "only for a job whose stored original request names an issue", and that this kept an issue safe from a forged job row. That holds for a job a webhook made, whose request exists only after intake has fetched the issue. It does not hold for a job made through `POST /v1/jobs`: that request is stored at submission with the caller's `source_ref`, so the step wrote `queued` on any issue number of a registered repository, and `rejected` when intake refused the job. A later job on the same issue also replaced the comment of an earlier one. The check for the stage run closes this.

A job that was already over when the worker first looked, and that it never wrote for, is left alone unless it ended in the last fifteen minutes.

### 6. Policy, configuration and health

- `PolicyLoader::load_issue_workflow` loads `policies/issue-workflow.yaml` with the strict contract. Its `policy.status` now reads `designed` in lower case, as the typed contract of the other policies requires; the old upper case value was never read by anything. The rendered `onboarding/github/issue-workflow.json` was rendered again because its source hash changed.
- `policies/approval.yaml` has a new row, `write_status_label`, at L0, and `close_or_label_issue` is narrowed. Both say "pending confirmation by the architect". **The worker reads `write_status_label`** (review finding STS-6): the row must exist, say `requires: none`, and name a lowest level at or below the job's. If an architect changes it to need a person, the step does not write. `close_or_label_issue` is read by no code; the factory never closes an issue, and the row is documentation until a consumer exists.
- The records of the step carry a policy hash that binds `policies/issue-workflow.yaml` to the security and approval policies, so that a record says which label map was in force.
- **A policy that cannot be used does not stop the worker** (review finding STS-7). If `policies/issue-workflow.yaml` is missing or broken, its trigger label is not the `intake.trigger_label` of the approval policy, or the approval row does not allow the write, the worker starts, writes nothing on any issue, reports a degraded health line with the reason, and records `issue_status.disabled` once for each tenant it serves. The write fails closed; the process does not.
- The key `github.write_issue_status` (default true) turns the writing off.
- The health report has a new status, `degraded`, for what is only observability. A problem with the status writing shows as degraded and never makes the process unready.

### 7. Paced and bounded

The adapter leaves one second between two requests that change something (through the `Sleeper` seam, so a test records the waits) and keeps the rate-limit back-off of the other calls. The worker makes at most six updates a minute and 120 an hour, one at a time, with one update for each job at its newest version. One update is about eight requests, so 120 an hour is a fifth of the 5,000 an hour that an installation commonly has, and the stage tokens share it. A pause when `x-ratelimit-remaining` is low is **not built**: it needs a view of the installation's budget that the status writer and the stage clients share, which is a decision for the architect (review finding STS-2, DEFERRED in part).

## Considered options

**A. Where the two operations live**
1. Add them to `ChangeHost`. Rejected: its calls take a stage token, and the delivery stage is the only one with `issues: write` besides approval. Writing a status would borrow the delivery token or widen a stage.
2. Add them to `IssueSource`. Rejected: it is the read port, and its token is `issues: read` for the stages that use it.
3. A new port. **Chosen.**

**B. The type of the label**
1. A string checked at the call. Rejected: the wrong call can be written, and a check can be forgotten at one call site.
2. A Rust enum with the ten labels written in code. Rejected: the names would live in two places, the code and the policy, and the Python tool and the Action would disagree with the Rust the first time someone edits one.
3. A validated type built only from the loaded policy. **Chosen.**

**C. How the worker finds a change**
1. Read the outbox. Rejected: ADR 0014 made the outbox a notification record, and it has no listing across jobs.
2. A signed request from the API, as for a rejected requester. Rejected: the state changes are made by the worker, so there is no untrusted channel to protect.
3. Read the job rows and compare versions. **Chosen.** Costs a few queries on every claim, bounded by pages and a cap.

**D. Where the writes run**
1. Inside the hook, with a time budget. Rejected: GitHub's pacing (one second between changes) makes one update take seconds, and a failing GitHub would stall the loop for the budget on every backoff expiry.
2. In a task the hook starts. **Chosen.** Costs a guard against two tasks and the shield for the session identifier.

**E. The credential**
1. The approval stage token, as the rejection reply uses. Rejected: it also holds `pull_requests: read` and `contents: read`, and the write would depend on a stage.
2. A token class of its own. **Chosen.**

**F. One comment for what**
1. One for each job. Rejected: an issue that is labelled twice would carry two status comments.
2. One for each issue, ordered by the stamp. **Chosen.**

## Consequences

**Good.**
- A person can read the state of every accepted issue in the issue list, and the comment says what the factory is doing in plain words.
- The wrong label cannot be written by accident in the Rust code, and the adapter refuses it once more.
- The credential of the write is narrow and separate, and a stage token did not change.
- A failure to write cannot touch a job. This is tested with a failing and a stalled GitHub.

**Costs.**
- A new port, a new token class, a new adapter, a fake, a contract suite, three policy and configuration changes, and a new health status. Every adapter of GitHub now carries the pacing.
- **All of it is verified against fakes.** The fake GitHub server of the test kit gained five routes (list, add and remove a label; edit and delete a comment). They were written from the reference pages, not from recorded answers.
- Each update costs a few requests: a list of comments, an edit or a create, a list of labels, an add and a remove. A job that changes state ten times writes ten times, six a minute at most.
- The status of a job is not written until the intake stage has passed, so no job shows `queued`, and an issue the factory refused at the start gets no label (the reply that explains the refusal is still posted).
- The step reads up to 1,100 job rows for each tenant on every claim and, for a job it meets for the first time, its audit records (up to ten pages).
- `Method::Delete` is now used in two more places. The source scan in `change_host_behaviour.rs` names them.

## Confirmation

Run on 2026-11-02 against the commit that carries this record. Counts are in the final report of the work package.

- `cargo test -p factory-contracts --test issue_workflow`: the loaded values equal `onboarding/github/issue-workflow.json`; every job state of `state-machine.json` has exactly one label; a policy that misses a state, names an unknown state, maps a state twice, puts the trigger label in a namespace or breaks a length limit is refused, each beside a sibling that loads.
- `cargo test -p factory-testkit --test issue_status_contract`: the fake passes the contract suite (12 checks) and the suite fails for each of 11 deliberate defects, which `contract_register` requires.
- `cargo test -p factory-github --test issue_status`: the adapter passes the same suite against the fake GitHub server on the loopback interface, and: a wrong label is refused before any request; only `factory: ` labels are taken off; a label that is already gone is not an error and a refusal is; the token request is exactly `issues: write` and `metadata: read` for one repository, apart from an intake token that stays `issues: read`; the comment is edited and not duplicated after a lost answer and when two writers race; changes are a second apart; a short rate limit is waited out and a long one reported.
- `cargo test -p factory-composition --test issue_status`: one label and one comment however many changes; a failing GitHub never changes a job and shows as degraded and ready; a stalled GitHub does not hold up the hook; back-off, give-up and no retry for a refusal; two workers and a restart write once; the newer of two racing updates stays; only enabled repositories and accepted issues; the bound of six updates a minute; the session is shielded from the sweep and ended after the round.
- Deliberate breaks, each shown caught: ten of the adapter in `crates/github/tests/mutations/run_mutations.py` (skip the namespace check, take off every label, ask for the delivery credential, trust any author, overwrite a newer stamp, post without looking and keep the duplicate, read a cut listing as no comment, treat a gone label as an error, skip the pause, skip the cleaning), and ten of the step in `crates/composition/tests/mutations/issue_status_breaks.py`. The repository is checked twice, when the job is read and before the write, so a break that removes one of the two shows nothing by design; the break on file removes both.

**Not verified:** everything against the real GitHub; the permission names of the new routes; the behaviour of a 404 on removal; the real secondary limits; how GitHub renders the cleaned text; the Action that reverts a `factory:` label (it was not run); the worker process (its wiring compiles and the step is tested, but no worker was started against a database and a GitHub App); an independent security review.

## Decisions that need a person

1. **Accept the port, the type and the adapter** (the architect), and order the independent security review that ADR 0016 asks for any port change.
2. **Default of `github.write_issue_status`.** It is on, because the feature is the point and the App already holds `Issues: write`. The cautious alternative is off until the first real run has been watched. Reverse by changing one default and one row of the configuration reference. **Decided on 2026-11-02 by the product owner: on by default**, after the cautious alternative was offered and recommended. The writing has run only against fakes, so the first real run on a fixture repository is the check that this default is safe (decision 7 below).
3. **The two policy rows are pending confirmation by the architect.** `write_status_label` at L0 and the narrowing of `close_or_label_issue`.
4. **`metadata: read` in the status token.** Alternative: ask for `issues: write` alone and learn from the first real run whether GitHub accepts it and whether the minter's check would refuse the answer.
5. **The numbers of the pacing**: one second between changes (from the reference), six updates a minute, six tries, 30 seconds doubling to 20 minutes, a fifteen minute window for a job that ended before the worker looked. They are guesses until a real run.
6. **No status before intake has accepted the issue.** The first version of this record said "no status for a job without an original request", and that writing earlier "would let anyone who can forge a job row write on an issue of a registered repository". That was more than the code did: a job made through `POST /v1/jobs` has its request from the start. The rule is now that the intake stage run has passed (section 5), which also holds against a job row that someone forged, because only the engine makes and passes a stage run. Alternative: write `queued` as soon as a job exists. That would let a requester aim the App at any issue number of a registered repository, and the cost of the rule is that no job ever shows `queued`.
7. **A trial on a real repository** with a real App, before anyone relies on the labels.

## Revision note (review of registration and status write-back)

Written on 2026-11-02, after the independent security review in [the review](../reviews/engine-registration-and-status-security-review.md) (part B: no blocker, no major finding, eight minor ones and two notes). The status of this record does not change. What changed:

- **STS-1.** A status is written only after the intake stage has passed. Section 5 and decision 6 above are corrected.
- **STS-2.** The `Retry-After` of GitHub moves the next try to the larger of the wait and the back-off. An hourly bound of 120 updates is added. The pause on a low `x-ratelimit-remaining` is not built (see section 7).
- **STS-3.** The end state of a job is written a second time after two minutes. A lost update in the middle of a job is repaired by its next change.
- **STS-4.** The sweep asks which jobs are running after it lists the tokens, and a round is a guard that ends its credential when the task panics or is dropped.
- **STS-5.** `forged_for_negative_tests` is compiled only under a feature that only the test kit enables, and ST-13 flags a pointer to it as well as a call.
- **STS-6.** The policy hash on the records binds the issue workflow policy. The worker reads `write_status_label`.
- **STS-7.** A policy that cannot be used turns the step off and degraded. The worker starts.
- **STS-8.** The repository is compared without regard to case in one function, `RepoRef::same_repository`, used by the step, the adapter, the fake and the API.
- **Not changed.** STS-9 and STS-10 are notes. The fake still stands in for GitHub; everything in "Not verified" below is still not verified.
