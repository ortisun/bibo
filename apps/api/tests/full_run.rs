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
    print_table(&journey, &view);

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
