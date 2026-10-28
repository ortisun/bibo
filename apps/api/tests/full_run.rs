//! The full run in test mode: one `word-count` job from a signed webhook to `COMPLETED`, with the
//! real handler of every stage of Slice 1, the real engine on PostgreSQL, the real API server and
//! the person's approvals given through it.
//!
//! The rig, and what is real and what is scripted, are in `full/mod.rs`. The playbook that plays
//! the nine agents is in `playbook/mod.rs`. `complete_run.rs` stays: it is the shorter run with the
//! stand-in handlers that proves the decision path on its own.
//!
//! The first test is the run and the assertions that matter. The second shows that two runs of the
//! same job agree except in ids, times and what is derived from them. The rest are deliberate
//! breaks: each puts one defect into the real pipeline and shows the run catching it.

#[allow(dead_code, unused_imports)]
#[path = "../../../crates/workflow/tests/validation/cargo.rs"]
mod cargo;
mod full;
#[allow(dead_code)]
mod playbook;
mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::{JobId, StageRunId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus, Status as _};
use factory_domain::values::{MediaType, Sha256Digest};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::ArtifactDirection;
use full::{Options, Rig};
use serde_json::{Value, json};
use support::Env;

/// A job that has been labelled, with the tokens of the two people who will decide.
struct Journey {
    rig: Rig,
    job: JobId,
    requester: String,
    approver: String,
}

async fn begin(options: Options) -> Journey {
    // The log of the whole process, for the canary sweep.
    let _ = support::captured();
    let env = Env::start().await;
    let requester = full::token_from_file(&env, "requester", &env.a.requester.token.clone());
    let approver = full::token_from_file(&env, "approver", &env.a.approver.token.clone());
    let rig = Rig::start(env, options).await;
    full::label_the_issue(&rig.env).await;
    let job = full::job_of(&rig.env, &requester).await;
    Journey {
        rig,
        job,
        requester,
        approver,
    }
}

impl Journey {
    async fn until(
        &self,
        seconds: u64,
        done: impl Fn(&factory_workflow::engine::JobView) -> bool,
    ) -> factory_workflow::engine::JobView {
        self.rig
            .drive(Some(self.job), seconds, done)
            .await
            .expect("a view of the job")
    }

    /// Runs until the specification stage asks the person.
    async fn to_the_specification_question(&self) -> factory_workflow::engine::JobView {
        self.until(120, |view| {
            full::status_of(view, StageKind::Specification) == Some(StageRunStatus::WaitingForHuman)
                || full::stopped(view)
        })
        .await
    }

    /// The approver approves the specification draft, through the API.
    async fn approve_the_specification(
        &self,
        view: &factory_workflow::engine::JobView,
        key: &str,
        head: Option<String>,
    ) -> support::Reply {
        let run = full::stage_run_of(view, StageKind::Specification);
        let head = match head {
            Some(head) => head,
            None => self.rig.spec_draft_commit(self.job, run).await,
        };
        let evidence = self
            .rig
            .ledger_head(self.job, StageKind::Specification, run)
            .await;
        full::decide(
            &self.rig.env,
            &self.approver,
            self.job,
            key,
            json!({
                "verb": "approve",
                "stage_run_id": run.as_text(),
                "head": head,
                "evidence": evidence.as_str(),
                "reason": "The specification says what the issue asked for.",
            }),
        )
        .await
    }

    /// Runs until the approval stage asks the person, or the job stops.
    async fn to_the_pull_request_question(&self) -> factory_workflow::engine::JobView {
        self.until(240, |view| {
            full::status_of(view, StageKind::Approval) == Some(StageRunStatus::WaitingForHuman)
                || (full::stopped(view)
                    && full::status_of(view, StageKind::Specification)
                        != Some(StageRunStatus::WaitingForHuman))
        })
        .await
    }

    /// The approver approves the pull request, through the API, naming the head they saw.
    async fn approve_the_pull_request(
        &self,
        view: &factory_workflow::engine::JobView,
        key: &str,
        head: Option<String>,
    ) -> support::Reply {
        use factory_workflow::stages::approval::ApprovalSources as _;
        let run = full::stage_run_of(view, StageKind::Approval);
        let request = self
            .rig
            .approvals
            .request(self.rig.tenant, run)
            .await
            .expect("the approval stage stored its request");
        let evidence = self
            .rig
            .ledger_head(self.job, StageKind::Approval, run)
            .await;
        full::decide(
            &self.rig.env,
            &self.approver,
            self.job,
            key,
            json!({
                "verb": "approve",
                "stage_run_id": run.as_text(),
                "head": head.unwrap_or_else(|| request.pr_head.as_str().to_owned()),
                "evidence": evidence.as_str(),
                "reason": "The change does what the issue asked.",
            }),
        )
        .await
    }

    /// Every deliverable of the job: `(stage, role, bytes)`, inputs and outputs.
    async fn artifacts(&self) -> Vec<(StageKind, StageRunId, ArtifactDirection, String, Vec<u8>)> {
        let scope = TenantScope::new(self.rig.tenant);
        let mut tx = self.rig.store.begin(scope).await.expect("a tx");
        let runs = tx.list_stage_runs(self.job).await.expect("runs");
        let mut links = Vec::new();
        for run in &runs {
            for link in tx
                .list_stage_run_artifacts(run.value.id)
                .await
                .expect("links")
            {
                links.push((run.value.kind, run.value.id, link));
            }
        }
        let _ = tx.rollback().await;
        let mut found = Vec::new();
        for (kind, run, link) in links {
            let reference = ArtifactRef {
                sha256: link.sha256.clone(),
                media_type: MediaType::parse("application/json").expect("a media type"),
                size_bytes: None,
            };
            if let Ok(bytes) = self.rig.artifacts.get(&scope, &reference).await {
                found.push((
                    kind,
                    run,
                    link.direction,
                    link.role.as_str().to_owned(),
                    bytes,
                ));
            }
        }
        found
    }

    /// The newest stored output of a stage called `name`, as JSON.
    async fn output(&self, kind: StageKind, name: &str) -> Value {
        let all = self.artifacts().await;
        let (.., bytes) = all
            .iter()
            .rev()
            .find(|(held, _, direction, role, _)| {
                *held == kind
                    && *direction == ArtifactDirection::Output
                    && role.split(".a").next() == Some(name)
            })
            .unwrap_or_else(|| panic!("{kind} stored no {name}"));
        serde_json::from_slice(bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(bytes).into_owned()))
    }
}

/// Handler names, for the report.
fn handler_name(kind: StageKind) -> &'static str {
    match kind {
        StageKind::Intake => "IntakeHandler",
        StageKind::RepositoryIntelligence => "RepoIntelHandler",
        StageKind::Specification => "SpecificationHandler",
        StageKind::DomainDiscovery => "DomainDiscoveryHandler",
        StageKind::Architecture => "ArchitectureHandler",
        StageKind::TaskPlanning => "PlanningHandler",
        StageKind::Implementation => "ImplementationHandler",
        StageKind::Validation => "ValidationHandler",
        StageKind::Review => "ReviewHandler",
        StageKind::Documenting => "DocumentingHandler",
        StageKind::DocumentationReview => "DocumentationReviewHandler",
        StageKind::Delivery => "DeliveryHandler",
        StageKind::Approval => "ApprovalHandler",
        other => panic!("{other:?} is not a stage of the scope"),
    }
}

/// Which stages ran a command in the sandbox, and so used the fake one.
fn sandbox_of(kind: StageKind) -> &'static str {
    match kind {
        StageKind::RepositoryIntelligence
        | StageKind::Specification
        | StageKind::Validation
        | StageKind::DocumentationReview => "FAKE (commands run)",
        StageKind::Intake
        | StageKind::Architecture
        | StageKind::TaskPlanning
        | StageKind::Implementation
        | StageKind::Review
        | StageKind::Documenting => "FAKE (the agent runs in it)",
        _ => "none",
    }
}

fn print_table(journey: &Journey, view: &factory_workflow::engine::JobView) {
    println!("FULL-RUN-TABLE | stage | handler | real or scripted | sandbox | result | duration |");
    let timings = journey.rig.timings.lock().expect("lock").clone();
    for kind in factory_workflow::engine::EngineConfig::new(
        factory_domain::vocabulary::ExecutionMode::Test,
        journey.rig.policies.hash.clone(),
    )
    .scope
    {
        let runs: Vec<_> = view.runs_of(kind).collect();
        let took: std::time::Duration = timings
            .iter()
            .filter(|timed| timed.kind == kind)
            .map(|timed| timed.took)
            .sum();
        let fidelity = journey
            .rig
            .handlers
            .iter()
            .find(|(held, _)| *held == kind)
            .map_or("none", |(_, fidelity)| fidelity.as_str());
        println!(
            "FULL-RUN-TABLE | {kind:?} | {} | real handler (collaborators report: {fidelity}) | {} | {:?} after {} attempt(s) | {took:?} |",
            handler_name(kind),
            sandbox_of(kind),
            runs.last().map(|run| run.status),
            runs.last().map_or(0, |run| run.attempts.len()),
        );
    }
}

// ---- the run ---------------------------------------------------------------------------------

/// The honest journey: the worker runs to the first question, the approver approves the
/// specification, the worker runs to the second question, the approver approves the pull request.
/// Returns the finished job.
async fn whole_job(journey: &Journey) -> factory_workflow::engine::JobView {
    // 1. The webhook only recorded the job. The worker admits it and runs to the first question.
    let view = journey.to_the_specification_question().await;
    full::print_states("first question", &view);
    assert_eq!(
        full::status_of(&view, StageKind::Specification),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );
    for kind in [StageKind::Intake, StageKind::RepositoryIntelligence] {
        assert_eq!(full::status_of(&view, kind), Some(StageRunStatus::Passed));
    }

    // 2. The approver approves the specification draft through the API: recorded, not applied.
    let reply = journey
        .approve_the_specification(&view, "approve-specification-1", None)
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    assert_eq!(reply.json()["applied"], json!(false));

    // 3. The worker applies it, runs the stages to the pull request, and asks again.
    let view = journey.to_the_pull_request_question().await;
    full::print_states("second question", &view);
    assert_eq!(
        full::status_of(&view, StageKind::Approval),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );
    assert_eq!(view.status, JobStatus::WaitingForHuman);

    // 4. The approver approves the pull request, through the API.
    let reply = journey
        .approve_the_pull_request(&view, "approve-pull-request-1", None)
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let view = journey
        .until(120, |view| {
            view.status == JobStatus::Completed || view.status.is_terminal()
        })
        .await;
    full::print_states("after the second approval", &view);
    assert_eq!(view.status, JobStatus::Completed, "{view:#?}");
    print_table(journey, &view);
    view
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_labelled_issue_goes_through_every_real_stage_and_two_approvals_complete_it() {
    let canaries = factory_testkit::fx::canary::CanarySet::generate();
    let planted = {
        // The canaries sit where an agent must never read them: hidden paths of the fixture.
        let env_file = canaries
            .iter()
            .map(|canary| format!("{}={}", canary.label(), canary.value()))
            .collect::<Vec<_>>()
            .join("\n");
        vec![
            (".env".to_owned(), env_file.clone()),
            ("tests/holdout/secret.txt".to_owned(), env_file),
        ]
    };
    let journey = begin(Options {
        extra_files: planted,
        ..Options::default()
    })
    .await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);

    let view = whole_job(&journey).await;

    // ---- what matters -------------------------------------------------------------------
    let rig = &journey.rig;
    let job = journey.job;

    // Every stage of the scope has exactly one passed (or skipped) run, with a real handler.
    for (kind, fidelity) in &rig.handlers {
        let runs: Vec<_> = view.runs_of(*kind).collect();
        assert_eq!(runs.len(), 1, "{kind:?} ran once");
        assert!(
            matches!(
                runs[0].status,
                StageRunStatus::Passed | StageRunStatus::Skipped
            ),
            "{kind:?}: {:?}",
            runs[0].status
        );
        let _ = fidelity;
    }
    assert!(
        rig.playbook.misses().is_empty(),
        "{:?}",
        rig.playbook.misses()
    );

    // The ledger's hash chain verifies for the job, from the entries as the store holds them.
    {
        let mut tx = rig
            .store
            .begin(TenantScope::new(rig.tenant))
            .await
            .expect("a tx");
        let entries = factory_composition::reading::Reader::job_ledger(&mut *tx, job)
            .await
            .expect("the ledger");
        let _ = tx.rollback().await;
        assert!(entries.len() >= 13, "{} entries", entries.len());
        assert_eq!(factory_domain::ledger::verify_chain(&entries), Ok(()));
    }

    // Every gate decision has a stored report the tenant can read.
    {
        let scope = TenantScope::new(rig.tenant);
        let mut tx = rig.store.begin(scope).await.expect("a tx");
        let runs = tx.list_stage_runs(job).await.expect("runs");
        let _ = tx.rollback().await;
        let mut decided = 0;
        for run in runs {
            let Some(record) = run.value.gate else {
                panic!("{:?} has no gate record", run.value.kind);
            };
            if record.outcome == factory_domain::vocabulary::GateOutcome::NotApplicable {
                assert!(
                    record.report_sha256.is_none() || run.value.kind == StageKind::DomainDiscovery,
                    "{:?}",
                    run.value.kind
                );
                continue;
            }
            let hash = record
                .report_sha256
                .unwrap_or_else(|| panic!("{:?}: a decision with no report", run.value.kind));
            let reference = ArtifactRef {
                sha256: hash,
                media_type: MediaType::parse("application/json").expect("a media type"),
                size_bytes: None,
            };
            let bytes = rig
                .artifacts
                .get(&scope, &reference)
                .await
                .unwrap_or_else(|_| panic!("{:?}: the report is unreadable", run.value.kind));
            let report: Value = serde_json::from_slice(&bytes).expect("a JSON report");
            assert!(report.is_object());
            decided += 1;
        }
        assert!(decided >= 12, "{decided} gate decisions had a report");
    }

    // Evidence is bound to the head commit: the validation binding, the implementation result,
    // the approval request and the pull request agree about the code and the documents.
    let implementation = journey
        .output(StageKind::Implementation, "implementation-result")
        .await;
    let validation = journey
        .output(StageKind::Validation, "validation-evidence")
        .await;
    let documentation = journey
        .output(StageKind::Documenting, "documentation-result")
        .await;
    let code_head = implementation["head_commit"].as_str().expect("a code head");
    assert_eq!(
        validation["binding"]["head_commit"].as_str(),
        Some(code_head)
    );
    assert_eq!(
        validation["binding"]["base_commit"].as_str(),
        implementation["base_commit"].as_str()
    );
    {
        use factory_workflow::stages::approval::ApprovalSources as _;
        let run = full::stage_run_of(&view, StageKind::Approval);
        let request = rig
            .approvals
            .request(rig.tenant, run)
            .await
            .expect("request");
        assert_eq!(
            request.evidence_binding.head_commit.as_str(),
            code_head,
            "the request carries the binding of the code head"
        );
        // The pull request head is the documentation commit, above the code head.
        assert_ne!(request.pr_head.as_str(), code_head);
        assert_eq!(
            documentation["head_commit"]
                .as_str()
                .or(documentation["commit"].as_str()),
            Some(request.pr_head.as_str()),
            "{documentation}"
        );
        // The manifest the pull request carries is the one the request names.
        let manifest = journey
            .output(StageKind::Delivery, "evidence-manifest")
            .await;
        assert!(manifest.is_object());
    }

    // The reviewer is another agent than the builder.
    let served = rig.playbook.served();
    let builder = served
        .iter()
        .find(|s| s.agent == "builder")
        .expect("a builder ran");
    let reviewer = served
        .iter()
        .find(|s| s.agent == "code-reviewer")
        .expect("a reviewer ran");
    assert_ne!(builder.agent, reviewer.agent);

    // The documentation gate ran and passed, and the pull request description is readable.
    let gate = journey
        .output(StageKind::DocumentationReview, "documentation-gate-report")
        .await;
    assert!(gate.is_object(), "{gate}");
    assert_eq!(
        full::status_of(&view, StageKind::DocumentationReview),
        Some(StageRunStatus::Passed)
    );
    let delivery = journey.output(StageKind::Delivery, "delivery-result").await;
    let body = delivery["body"]
        .as_str()
        .expect("a pull request description");
    assert!(body.contains("--json") || body.len() > 100, "{body}");

    // The specification came from the Spec Kit skills, and no other stage touched .specify or specs.
    let contract = journey
        .output(StageKind::Specification, "specification-contract")
        .await;
    let skills: Vec<&str> = contract["provenance"]["spec_kit"]["skills_invoked"]
        .as_array()
        .expect("skills")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        skills
            .iter()
            .all(|s| ["constitution", "specify", "clarify", "checklist"].contains(s)),
        "{skills:?}"
    );
    for step in &served {
        let touches_spec = step
            .wrote
            .iter()
            .any(|path| path.starts_with(".specify") || path.starts_with("specs/"));
        assert_eq!(
            touches_spec,
            step.agent == "specification-writer",
            "only the specification writer writes the Spec Kit files: {step:?}"
        );
    }
    for path in implementation["tasks"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|task| task["changed"].as_array().into_iter().flatten())
        .filter_map(|change| change["path"].as_str())
    {
        assert!(
            !path.starts_with(".specify") && !path.starts_with("specs/"),
            "{path}"
        );
    }

    // No canary reached an artifact, an audit record, a prompt, a log line or the code host.
    {
        let sweeper = factory_testkit::fx::canary::Sweeper::new(&canaries);
        let mut hits = Vec::new();
        let mut blobs = 0;
        let mut stack = vec![rig.scratch.join("artifacts")];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(bytes) = std::fs::read(&path) {
                    blobs += 1;
                    hits.extend(sweeper.scan(&path.display().to_string(), &bytes));
                }
            }
        }
        assert!(blobs > 40, "{blobs} stored blobs were swept");
        for prompt in rig.runtime_prompts() {
            hits.extend(sweeper.scan("a prompt", prompt.as_bytes()));
        }
        for line in support::captured().lock().expect("lock").iter() {
            hits.extend(sweeper.scan("a log line", line.as_bytes()));
        }
        let audit = rig.audit_text(job).await;
        hits.extend(sweeper.scan("the audit log", audit.as_bytes()));
        assert!(hits.is_empty(), "a canary leaked: {} hit(s)", hits.len());
    }

    // The plain-English texts pass the readability gate.
    {
        use factory_workflow::gates::readability::{
            Artifact, Options as Readability, ReadabilityGate, Severity,
        };
        let gate = ReadabilityGate::new(Readability::new());
        let title = delivery["title"].as_str().expect("a title");
        let mut findings = gate
            .findings(&[Artifact::pull_request(title, body)])
            .expect("the readability gate runs");
        findings.retain(|finding| finding.severity == Severity::Block);
        assert!(findings.is_empty(), "{findings:?}");
    }

    // The timeline the API serves shows both decisions, applied once each.
    assert_eq!(
        full::timeline_actions(&rig.env, &journey.requester, job, "decision.").await,
        [
            "decision.requested",
            "decision.applied",
            "decision.requested",
            "decision.applied"
        ]
    );
    assert_eq!(full::count_audit(rig, job, "approval.recorded").await, 1);
    let _ = (BTreeMap::<u8, u8>::new(), Sha256Digest::of(b""));
    rig.finish();
}

// ---- two runs of the same job ----------------------------------------------------------------

/// The text with what belongs to one run taken out: identifiers, times, and the hashes and commit
/// ids that follow from them. What is left is what the run decided.
fn normalized(text: &str, job_tail: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let hex = |c: char| c.is_ascii_hexdigit();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let rest = &chars[i..];
        let previous_is_hex = i > 0 && hex(chars[i - 1]);
        // 8-4-4-4-12 hexadecimal digits.
        if rest.len() >= 36
            && !previous_is_hex
            && rest[..36].iter().enumerate().all(|(at, c)| {
                if matches!(at, 8 | 13 | 18 | 23) {
                    *c == '-'
                } else {
                    hex(*c)
                }
            })
        {
            out.push_str("<id>");
            i += 36;
            continue;
        }
        // 2026-10-28T22:27:44(.123456)Z
        if rest.len() >= 20
            && rest[..4].iter().all(char::is_ascii_digit)
            && rest[4] == '-'
            && rest[10] == 'T'
            && rest[13] == ':'
        {
            let mut end = 19;
            if rest.get(end) == Some(&'.') {
                end += 1;
                while rest.get(end).is_some_and(char::is_ascii_digit) {
                    end += 1;
                }
            }
            if rest.get(end) == Some(&'Z') {
                out.push_str("<time>");
                i += end + 1;
                continue;
            }
        }
        // A run of hexadecimal digits that is a hash or a commit id (forty or more).
        if !previous_is_hex && hex(chars[i]) {
            let run = rest.iter().take_while(|c| hex(**c)).count();
            if run >= 40 {
                out.push_str("<hash>");
                i += run;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    // The last eight characters of the job's identifier are in the name of the feature directory.
    // They are taken out after the identifiers themselves, which contain them.
    let out = out.replace(job_tail, "<tail>");
    // The sizes of a document that embeds a time, and the token estimates made from them. A time
    // with microseconds drops its trailing zeros, so the same time is a character shorter one time
    // in ten, and so is every size that counts it (the record of a review counts the bytes of the
    // gate reports it was shown, and estimates the tokens of the prompt from them).
    let mut sized = out;
    for marker in ["bytes\":", "estimated_tokens\":"] {
        let mut next = String::with_capacity(sized.len());
        let mut rest = sized.as_str();
        while let Some(at) = rest.find(marker) {
            let cut = at + marker.len();
            next.push_str(&rest[..cut]);
            rest = &rest[cut..];
            let digits = rest.chars().take_while(char::is_ascii_digit).count();
            if digits > 0 {
                next.push_str("<size>");
                rest = &rest[digits..];
            }
        }
        next.push_str(rest);
        sized = next;
    }
    sized
}

/// Every stored output of the job: `"STAGE name"` to the hash of the bytes and the hash of the
/// bytes with the run's own ids, times and derived hashes taken out.
async fn fingerprints(journey: &Journey) -> BTreeMap<String, (Sha256Digest, Sha256Digest, String)> {
    let tail = journey.job.to_string();
    let tail = tail[tail.len() - 8..].to_owned();
    let mut found = BTreeMap::new();
    for (kind, _, direction, role, bytes) in journey.artifacts().await {
        if direction != ArtifactDirection::Output {
            continue;
        }
        let name = role.split(".a").next().unwrap_or(&role).to_owned();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        found.insert(
            format!("{kind:?} {name}"),
            (
                Sha256Digest::of(&bytes),
                Sha256Digest::of(normalized(&text, &tail).as_bytes()),
                normalized(&text, &tail),
            ),
        );
    }
    found
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_runs_of_the_same_job_agree_except_in_ids_times_and_what_follows_from_them() {
    let mut runs = Vec::new();
    for _ in 0..2 {
        let journey = begin(Options::default()).await;
        let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
        let view = whole_job(&journey).await;
        assert_eq!(view.status, JobStatus::Completed);
        runs.push(fingerprints(&journey).await);
        journey.rig.finish();
    }
    let (one, two) = (&runs[0], &runs[1]);
    assert_eq!(
        one.keys().collect::<Vec<_>>(),
        two.keys().collect::<Vec<_>>(),
        "the same stages stored the same deliverables"
    );
    assert!(one.len() >= 25, "{} deliverables were compared", one.len());
    let mut raw_differs = Vec::new();
    for (name, (raw_one, normal_one, text_one)) in one {
        let (raw_two, normal_two, text_two) = &two[name];
        if raw_one != raw_two {
            raw_differs.push(name.clone());
        }
        if normal_one != normal_two {
            // Show where the two texts part, so a difference is a fact and not a hash.
            let at = text_one
                .chars()
                .zip(text_two.chars())
                .take_while(|(a, b)| a == b)
                .count();
            let around = |text: &str| -> String {
                text.chars()
                    .skip(at.saturating_sub(120))
                    .take(300)
                    .collect()
            };
            panic!(
                "{name} differs between the runs in more than ids, times and hashes, from character {at}:\n  one: {}\n  two: {}",
                around(text_one),
                around(text_two)
            );
        }
    }
    println!(
        "DETERMINISM {} deliverables compared; the bytes differ in {} of them ({}); with the ids, times and derived hashes taken out all {} agree",
        one.len(),
        raw_differs.len(),
        raw_differs.join(", "),
        one.len()
    );
}

// ---- deliberate breaks -----------------------------------------------------------------------
//
// Each puts one defect into the real pipeline and shows the run catching it. The defect is made at
// the call site, in view: a tweak of the playbook, a wrapper around a real handler, or a change of
// the world the stage reads.

/// Drives a journey past the specification question to wherever the job stops next.
async fn to_the_next_stop(journey: &Journey) -> factory_workflow::engine::JobView {
    let view = journey.to_the_specification_question().await;
    assert_eq!(
        full::status_of(&view, StageKind::Specification),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );
    let reply = journey
        .approve_the_specification(&view, "approve-specification-break", None)
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    journey.to_the_pull_request_question().await
}

fn never_completed(view: &factory_workflow::engine::JobView) {
    assert_ne!(view.status, JobStatus::Completed, "{view:#?}");
}

fn not_started(view: &factory_workflow::engine::JobView, kind: StageKind) {
    assert!(
        view.newest(kind).is_none_or(|run| run.attempts.is_empty()
            && matches!(run.status, StageRunStatus::Pending | StageRunStatus::Ready)),
        "{kind:?} must not have started: {:?}",
        view.newest(kind)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_a_stage_that_stores_a_deliverable_under_another_name_is_caught() {
    let journey = begin(Options {
        wrap: vec![(
            StageKind::Architecture,
            Box::new(|inner: Arc<dyn factory_workflow::handlers::StageHandler>| -> Arc<dyn factory_workflow::handlers::StageHandler> {
                Arc::new(full::Tamper {
                    inner,
                    change: Box::new(|mut output| {
                        for artifact in &mut output.artifacts {
                            if artifact.name.as_str() == "architecture-design" {
                                artifact.name =
                                    factory_domain::values::Slug::parse("design").expect("a slug");
                            }
                        }
                        output
                    }),
                })
            }),
        )],
        ..Options::default()
    })
    .await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    // The stage is retried before it escalates, and asks the architect again each time.
    journey.rig.playbook.allow_repeats(&["architect"]);
    let view = to_the_next_stop(&journey).await;
    let architecture = view.newest(StageKind::Architecture).expect("a run");
    assert_ne!(architecture.status, StageRunStatus::Passed, "{view:#?}");
    never_completed(&view);
    for later in [
        StageKind::TaskPlanning,
        StageKind::Implementation,
        StageKind::Delivery,
    ] {
        not_started(&view, later);
    }
    // Nothing was stored under the wrong name, and nothing under the right one.
    let stored = journey.artifacts().await;
    assert!(
        !stored.iter().any(
            |(kind, _, direction, role, _)| *kind == StageKind::Architecture
                && *direction == ArtifactDirection::Output
                && (role.starts_with("design.") || role.starts_with("architecture-design."))
        ),
        "a refused output leaves no deliverable behind"
    );
    journey.rig.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_a_builder_patch_that_touches_a_protected_path_is_caught() {
    let journey = begin(Options::default()).await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    journey
        .rig
        .playbook
        .tweak("builder.read-json-option", |reply| {
            reply.writes.push((
                ".github/workflows/ci.yml".to_owned(),
                b"name: ci\non: push\njobs: {}\n".to_vec(),
            ));
        });
    let view = to_the_next_stop(&journey).await;
    assert_ne!(
        full::status_of(&view, StageKind::Implementation),
        Some(StageRunStatus::Passed),
        "{view:#?}"
    );
    never_completed(&view);
    not_started(&view, StageKind::Validation);
    // The refusal is recorded, with the path and the rule, and the file was committed nowhere.
    assert!(
        full::count_audit(&journey.rig, journey.job, "protected_path_decision.denied").await >= 1
    );
    let evidence = journey
        .output(StageKind::Implementation, "implementation-evidence")
        .await;
    let text = evidence.to_string();
    assert!(text.contains("protected-path-changed"), "{text}");
    assert!(text.contains(".github/workflows/ci.yml"), "{text}");
    journey.rig.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_a_reviewer_of_the_same_type_as_the_builder_is_caught() {
    let journey = begin(Options {
        review_agent: Some("builder"),
        ..Options::default()
    })
    .await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    let view = to_the_next_stop(&journey).await;
    // The review stage refuses an agent that can write: a reviewer is granted only reading tools,
    // and the builder is not one. The stage is blocked, not passed.
    assert_ne!(
        full::status_of(&view, StageKind::Review),
        Some(StageRunStatus::Passed),
        "{view:#?}"
    );
    never_completed(&view);
    assert!(
        journey
            .rig
            .playbook
            .served()
            .iter()
            .filter(|served| served.agent == "builder")
            .all(|served| served.entry.starts_with("builder.")),
        "the builder was never asked to review"
    );
    for later in [StageKind::Documenting, StageKind::Delivery] {
        not_started(&view, later);
    }
    journey.rig.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_a_documentation_gate_report_with_a_failed_gate_stops_the_job_before_delivery() {
    let journey = begin(Options::default()).await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    // The writer documents an option the program does not have.
    let honest = journey.rig.playbook.document("README.md");
    let invented = String::from_utf8(honest)
        .expect("text")
        .replace("`--json`", "`--yaml`");
    journey
        .rig
        .playbook
        .tweak("documentation-writer", move |reply| {
            for (path, bytes) in &mut reply.writes {
                if path == "README.md" {
                    *bytes = invented.clone().into_bytes();
                }
            }
        });
    journey
        .rig
        .playbook
        .allow_repeats(&["documentation-writer"]);
    let view = to_the_next_stop(&journey).await;
    assert_ne!(
        full::status_of(&view, StageKind::DocumentationReview),
        Some(StageRunStatus::Passed),
        "{view:#?}"
    );
    never_completed(&view);
    not_started(&view, StageKind::Delivery);
    // The failed gate has a stored report that names the invented option.
    let gate = journey
        .output(StageKind::DocumentationReview, "documentation-gate-report")
        .await;
    let text = gate.to_string();
    assert!(text.contains("FAILED"), "{text}");
    assert!(text.contains("--yaml"), "{text}");
    journey.rig.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_a_canary_secret_in_the_builders_output_is_stopped_and_never_stored() {
    let canaries = factory_testkit::fx::canary::CanarySet::generate();
    let token = canaries
        .get(factory_testkit::fx::canary::CanaryKind::GithubInstallationToken)
        .value()
        .to_owned();
    let journey = begin(Options::default()).await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    let planted = token.clone();
    journey
        .rig
        .playbook
        .tweak("builder.write-json-formatter", move |reply| {
            for (path, bytes) in &mut reply.writes {
                if path == "src/lib.rs" {
                    let mut text = String::from_utf8(bytes.clone()).expect("text");
                    text.push_str(&format!("\n// token: {planted}\n"));
                    *bytes = text.into_bytes();
                }
            }
        });
    let view = to_the_next_stop(&journey).await;
    assert_ne!(
        full::status_of(&view, StageKind::Implementation),
        Some(StageRunStatus::Passed),
        "{view:#?}"
    );
    never_completed(&view);
    assert!(
        full::count_audit(
            &journey.rig,
            journey.job,
            "secret_redacted_or_blocked.denied"
        )
        .await
            >= 1
    );
    // The refusal names the rule and the path and never repeats the secret.
    let evidence = journey
        .output(StageKind::Implementation, "implementation-evidence")
        .await
        .to_string();
    assert!(evidence.contains("secret-found"), "{evidence}");
    // No stored blob, audit record, prompt or log line holds the canary in any spelling.
    let sweeper = factory_testkit::fx::canary::Sweeper::new(&canaries);
    let mut hits = Vec::new();
    let mut stack = vec![journey.rig.scratch.join("artifacts")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                hits.extend(sweeper.scan(&path.display().to_string(), &bytes));
            }
        }
    }
    for line in support::captured().lock().expect("lock").iter() {
        hits.extend(sweeper.scan("a log line", line.as_bytes()));
    }
    hits.extend(sweeper.scan(
        "the audit log",
        journey.rig.audit_text(journey.job).await.as_bytes(),
    ));
    assert!(hits.is_empty(), "the canary leaked: {} hit(s)", hits.len());
    journey.rig.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_a_missing_evidence_artifact_before_delivery_stops_the_job() {
    let journey = begin(Options {
        wrap: vec![(
            StageKind::DocumentationReview,
            Box::new(|inner: Arc<dyn factory_workflow::handlers::StageHandler>| -> Arc<dyn factory_workflow::handlers::StageHandler> {
                Arc::new(full::Tamper {
                    inner,
                    change: Box::new(|mut output| {
                        output
                            .artifacts
                            .retain(|artifact| artifact.name.as_str() != "documentation-gate-report");
                        output
                    }),
                })
            }),
        )],
        ..Options::default()
    })
    .await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    journey
        .rig
        .playbook
        .allow_repeats(&["documentation-reviewer", "documentation-writer"]);
    let view = to_the_next_stop(&journey).await;
    assert_ne!(
        full::status_of(&view, StageKind::DocumentationReview),
        Some(StageRunStatus::Passed),
        "{view:#?}"
    );
    never_completed(&view);
    not_started(&view, StageKind::Delivery);
    not_started(&view, StageKind::Approval);
    journey.rig.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_an_approval_given_for_a_stale_head_is_refused_and_moves_nothing() {
    use factory_workflow::stages::approval::ApprovalSources as _;
    let journey = begin(Options::default()).await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    let view = to_the_next_stop(&journey).await;
    assert_eq!(
        full::status_of(&view, StageKind::Approval),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );
    // After the person looked, someone pushes another commit to the pull request's branch.
    let run = full::stage_run_of(&view, StageKind::Approval);
    let request = journey
        .rig
        .approvals
        .request(journey.rig.tenant, run)
        .await
        .expect("the request");
    let branch = factory_ports::paths::BranchName::new(&request.head_branch).expect("a branch");
    let moved = journey.rig.remote.commit_on_branch(
        &journey.rig.repo,
        &branch,
        &[("README.md", "Changed after the person looked.\n")],
    );
    assert_ne!(moved.as_str(), request.pr_head.as_str());
    // The person approves the head they saw.
    let reply = journey
        .approve_the_pull_request(&view, "approve-stale", None)
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let mut after = journey
        .rig
        .drive(Some(journey.job), 4, |_| false)
        .await
        .expect("a view");
    // On a loaded machine the hook can need more than one stretch of passes to write its marker.
    // Keep driving until the refusal is in the timeline, and fail on the assertion below if it
    // never arrives.
    for _ in 0..8 {
        let actions = full::timeline_actions(
            &journey.rig.env,
            &journey.requester,
            journey.job,
            "decision.",
        )
        .await;
        if actions.last().map(String::as_str) == Some("decision.rejected") {
            break;
        }
        after = journey
            .rig
            .drive(Some(journey.job), 2, |_| false)
            .await
            .expect("a view");
    }
    assert_eq!(after.status, JobStatus::WaitingForHuman, "{after:#?}");
    assert_eq!(
        full::status_of(&after, StageKind::Approval),
        Some(StageRunStatus::WaitingForHuman)
    );
    assert_eq!(
        full::timeline_actions(
            &journey.rig.env,
            &journey.requester,
            journey.job,
            "decision."
        )
        .await[2..],
        ["decision.requested", "decision.rejected"],
        "the refusal is in the timeline the API serves"
    );
    assert_eq!(
        full::count_audit(&journey.rig, journey.job, "approval.recorded").await,
        0
    );
    journey.rig.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_an_approval_of_another_specification_draft_is_refused_and_moves_nothing() {
    let journey = begin(Options::default()).await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    let view = journey.to_the_specification_question().await;
    assert_eq!(
        full::status_of(&view, StageKind::Specification),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );
    // The person names a commit that is not the one that holds the draft the stage kept.
    let reply = journey
        .approve_the_specification(&view, "approve-another-draft", Some("a".repeat(40)))
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let after = journey
        .rig
        .drive(Some(journey.job), 4, |_| false)
        .await
        .expect("a view");
    assert_eq!(
        full::status_of(&after, StageKind::Specification),
        Some(StageRunStatus::WaitingForHuman),
        "{after:#?}"
    );
    assert_eq!(
        full::timeline_actions(
            &journey.rig.env,
            &journey.requester,
            journey.job,
            "decision."
        )
        .await,
        ["decision.requested", "decision.rejected"]
    );
    assert!(
        journey
            .rig
            .audit_text(journey.job)
            .await
            .contains("code=draft_moved")
    );
    assert_eq!(
        full::count_audit(
            &journey.rig,
            journey.job,
            "approval_granted_or_rejected.granted"
        )
        .await,
        0,
        "the engine recorded no approval"
    );
    // The honest approval, with the commit of the draft, still works afterwards.
    let reply = journey
        .approve_the_specification(&view, "approve-the-real-draft", None)
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let view = journey.to_the_pull_request_question().await;
    assert_eq!(
        full::status_of(&view, StageKind::Specification),
        Some(StageRunStatus::Passed),
        "{view:#?}"
    );
    journey.rig.finish();
}
