//! A new dependency through the real pipeline: the job whose change adds a dependency stops at
//! `dependency-review` and waits for a person; the person decides through the API; the worker's
//! step applies the decision through the engine; the operator lets the stage run go again; and the
//! stage passes. Build code in the new package asks a security approver, separately.
//!
//! The rig is the one of the full run (`full/mod.rs`): the real engine on PostgreSQL, the real API
//! server, the real handlers of all thirteen stages, assembled by
//! `factory_composition::pipeline::assemble_pipeline`. Scripted, and labelled in the rig: the
//! agents (the playbook), the sandbox (the testkit's, with a scripted `cargo`), the code host, and
//! the registry and advisory-database sources (`SupplyChainSources::stand_in`). The decisions are
//! not scripted: they are read back from the ledger, which only the engine appends to.
//!
//! The breaks at the end each put one defect into the real pipeline and show the journey
//! catching it.

#[allow(dead_code, unused_imports)]
#[path = "../../../crates/workflow/tests/validation/cargo.rs"]
mod cargo;
mod full;
#[allow(dead_code)]
mod playbook;
mod support;

use std::sync::Arc;

use factory_domain::ids::{AuditEventId, JobId};
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{AuditAction, AuditActor, AuditDecision, NewAuditEvent, Store};
use factory_workflow::engine::{EngineError, JobView};
use factory_workflow::gates::supply_chain::facts::{
    RegistryMetadata, RegistryRecord, StaticRegistry,
};
use full::{Options, Rig};
use serde_json::{Value, json};
use support::Env;

const PACKAGE: &str = "tally-counter";
const VERSION: &str = "0.3.1";

fn checksum() -> String {
    "c".repeat(64)
}

/// A registry that knows the package: published long ago, widely used, licensed. A stand-in.
fn known_registry() -> Arc<dyn RegistryMetadata> {
    Arc::new(StaticRegistry::new().with(
        PACKAGE,
        RegistryRecord {
            exists: Some(true),
            first_published: Timestamp::parse("2023-01-01T00:00:00Z").ok(),
            license: Some("MIT".to_owned()),
            repository: Some("https://github.com/example/tally-counter".to_owned()),
            downloads: Some(5_000_000),
        },
    ))
}

struct Journey {
    rig: Rig,
    job: JobId,
    approver: String,
    security: String,
}

async fn begin() -> Journey {
    let _ = support::captured();
    let env = Env::start().await;
    let requester = full::token_from_file(&env, "requester", &env.a.requester.token.clone());
    let approver = full::token_from_file(&env, "approver", &env.a.approver.token.clone());
    let security = full::token_from_file(&env, "security", &env.a.security.token.clone());
    let rig = Rig::start(
        env,
        Options {
            registry: Some(known_registry()),
            ..Options::default()
        },
    )
    .await;
    full::label_the_issue(&rig.env).await;
    let job = full::job_of(&rig.env, &requester).await;
    Journey {
        rig,
        job,
        approver,
        security,
    }
}

impl Journey {
    async fn until(&self, seconds: u64, done: impl Fn(&JobView) -> bool) -> JobView {
        self.rig
            .drive(Some(self.job), seconds, done)
            .await
            .expect("a view of the job")
    }

    /// The builder changes `Cargo.toml` and `Cargo.lock`: the new package, locked from the registry.
    /// `build_code` says whether the package brings a build script, which only `cargo metadata`
    /// (scripted) shows once the package is fetched.
    fn the_builder_adds_the_dependency(&self, build_code: bool) {
        let base = |path: &str| {
            self.rig
                .base_files
                .iter()
                .find(|(held, _)| held == path)
                .map(|(_, text)| text.clone())
                .unwrap_or_else(|| panic!("the fixture has {path}"))
        };
        let manifest = base("Cargo.toml").replace(
            "[dependencies]\n",
            &format!("[dependencies]\n{PACKAGE} = \"{VERSION}\"\n"),
        );
        let lock = base("Cargo.lock").replace(
            "[[package]]\nname = \"word-count\"\nversion = \"0.1.0\"\n",
            &format!(
                "[[package]]\nname = \"{PACKAGE}\"\nversion = \"{VERSION}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{}\"\n\n[[package]]\nname = \"word-count\"\nversion = \"0.1.0\"\ndependencies = [\n \"{PACKAGE}\",\n]\n",
                checksum()
            ),
        );
        assert!(
            manifest.contains(PACKAGE) && lock.contains(PACKAGE),
            "{lock}"
        );
        // The plan owns the two files for the first task: a patch may change only the files its
        // task owns, so the dependency is a change the plan asked for.
        self.rig.playbook.tweak("planner", |reply| {
            let task = &mut reply.output["plan"]["tasks"][0];
            for path in ["Cargo.toml", "Cargo.lock"] {
                task["expected_changes"]
                    .as_array_mut()
                    .expect("the task lists its changes")
                    .push(json!({"path_glob": path, "change": "modify"}));
                task["owned_files"]
                    .as_array_mut()
                    .expect("the task lists its files")
                    .push(json!(path));
            }
        });
        self.rig
            .playbook
            .tweak("builder.write-json-formatter", move |reply| {
                reply
                    .writes
                    .push(("Cargo.toml".to_owned(), manifest.clone().into_bytes()));
                reply
                    .writes
                    .push(("Cargo.lock".to_owned(), lock.clone().into_bytes()));
                if let Some(list) = reply.output["files_changed"].as_array_mut() {
                    list.push(json!("Cargo.toml"));
                    list.push(json!("Cargo.lock"));
                }
            });
        self.rig
            .cargo
            .metadata_of(&[(PACKAGE, VERSION, "MIT", build_code)]);
        // The validation stage runs the tests of the head and of the baseline each time it runs,
        // and it runs again after every decision. The rig queued the first run only.
        for _ in 0..3 {
            for side in ["head", "base"] {
                let recorded = |name: &str| self.rig.playbook.recorded(name);
                self.rig.cargo.queue_test_run(cargo::TestRun {
                    stdout: recorded(&format!("cargo-test.{side}.stdout")),
                    stderr: recorded(&format!("cargo-test.{side}.stderr")),
                    exit: 0,
                });
            }
        }
    }

    /// Runs to the specification question, approves the draft, and runs on until the validation
    /// stage is blocked, or something else stops the job.
    async fn to_the_stop_at_validation(&self) -> JobView {
        let view = self
            .until(120, |view| {
                full::status_of(view, StageKind::Specification)
                    == Some(StageRunStatus::WaitingForHuman)
                    || full::stopped(view)
            })
            .await;
        assert_eq!(
            full::status_of(&view, StageKind::Specification),
            Some(StageRunStatus::WaitingForHuman),
            "{view:#?}"
        );
        let run = full::stage_run_of(&view, StageKind::Specification);
        let head = self.rig.spec_draft_commit(self.job, run).await;
        let evidence = self
            .rig
            .ledger_head(self.job, StageKind::Specification, run)
            .await;
        let reply = full::decide(
            &self.rig.env,
            &self.approver,
            self.job,
            "approve-specification",
            json!({
                "verb": "approve",
                "stage_run_id": run.as_text(),
                "head": head,
                "evidence": evidence.as_str(),
                "reason": "The specification says what the issue asked for.",
            }),
        )
        .await;
        assert_eq!(reply.status, 202, "{}", reply.text());
        self.until(240, |view| self.validation_has_stopped(view))
            .await
    }

    fn validation_has_stopped(&self, view: &JobView) -> bool {
        matches!(
            full::status_of(view, StageKind::Validation),
            Some(StageRunStatus::Blocked | StageRunStatus::Passed | StageRunStatus::Failed)
        ) || full::status_of(view, StageKind::Approval) == Some(StageRunStatus::WaitingForHuman)
    }

    /// A person's decision through the API, and one pass of the worker's step over it.
    async fn decide(
        &self,
        token: &str,
        key: &str,
        verb: &str,
        version: &str,
        checksum: Option<&str>,
    ) -> support::Reply {
        let mut body = json!({
            "verb": verb,
            "package": PACKAGE,
            "version": version,
            "reason": "Read the maintainers, the licence and what the package does.",
        });
        if let Some(checksum) = checksum {
            body["checksum"] = json!(checksum);
        }
        let reply = full::decide(&self.rig.env, token, self.job, key, body).await;
        self.rig.hook.pass(self.rig.tenant).await;
        reply
    }

    async fn recorded(
        &self,
    ) -> Vec<factory_workflow::gates::supply_chain::approval::DependencyApproval> {
        self.rig
            .dependency_approvals
            .for_job(self.rig.tenant, self.job)
            .await
    }

    /// The markers the worker wrote for the decisions on dependencies: `(action, code)`.
    async fn markers(&self) -> Vec<(String, String)> {
        let text = self.rig.audit_text(self.job).await;
        text.lines()
            .filter(|line| {
                (line.starts_with("decision.applied ") || line.starts_with("decision.rejected "))
                    && (line.contains(" verb=approve-dependency ")
                        || line.contains(" verb=approve-build-code "))
                    && line.contains(" code=")
            })
            .filter_map(|line| {
                let action = line.split_whitespace().next()?.to_owned();
                let code = line
                    .split_whitespace()
                    .find_map(|word| word.strip_prefix("code="))?
                    .to_owned();
                Some((action, code))
            })
            .collect()
    }
}

/// The gates of the newest validation evidence, one line each, for the message of a failed test.
async fn gates(journey: &Journey) -> Vec<String> {
    let evidence = journey
        .rig
        .stage_output(journey.job, StageKind::Validation, "validation-evidence")
        .await;
    evidence["reports"]
        .as_array()
        .map(|reports| {
            reports
                .iter()
                .map(|report| {
                    format!(
                        "{} = {} ({}) {}",
                        report["metadata"]["gate_id"].as_str().unwrap_or("?"),
                        report["outcome"].as_str().unwrap_or("?"),
                        report["reason"].as_str().unwrap_or(""),
                        report["blocked_reason"]
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn blocked(view: &JobView) -> bool {
    full::status_of(view, StageKind::Validation) == Some(StageRunStatus::Blocked)
}

fn passed(view: &JobView) -> bool {
    full::status_of(view, StageKind::Validation) == Some(StageRunStatus::Passed)
}

/// What the stage run stored, as the person is shown it.
fn awaiting(evidence: &Value, list: &str) -> Vec<(String, String, String)> {
    evidence["dependency_review"][list]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                // A new direct dependency with a decision on it is listed, with the decision.
                .filter(|entry| entry.get("approval").is_none_or(Value::is_null))
                .map(|entry| {
                    (
                        entry["name"].as_str().unwrap_or_default().to_owned(),
                        entry["version"].as_str().unwrap_or_default().to_owned(),
                        entry["needs"].as_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_dependency_waits_for_a_person_and_the_recorded_decision_lets_the_stage_pass() {
    let journey = begin().await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    journey.the_builder_adds_the_dependency(false);
    let view = journey.to_the_stop_at_validation().await;
    let run = full::stage_run_of(&view, StageKind::Validation);

    // 1. The stage stops at the dependency review and waits for a person. No container was made to
    // fetch anything: nothing is fetched for a package nobody decided on.
    assert!(blocked(&view), "{view:#?}");
    assert_eq!(journey.rig.cargo.ran("fetch"), 0);
    assert_eq!(journey.rig.cargo.ran("audit"), 0);
    let evidence = journey
        .rig
        .stage_output(journey.job, StageKind::Validation, "validation-evidence")
        .await;
    assert_eq!(
        awaiting(&evidence, "new_direct_dependencies"),
        [(
            PACKAGE.to_owned(),
            VERSION.to_owned(),
            "approver".to_owned()
        )],
        "{evidence}"
    );
    assert!(journey.recorded().await.is_empty());

    // 2. The operator cannot let the run go: no decision was recorded, and the engine reads that
    // from what it stored. The caller has no flag to say otherwise.
    let refused = journey.rig.unblock(journey.job, run).await;
    assert!(
        matches!(refused, Err(EngineError::GuardUnmet(_))),
        "{refused:?}"
    );

    // 3. A decision for another version is recorded as a request and is not applied: the stage run
    // waits for 0.3.1, and a decision on a package it does not wait for counts for nothing.
    let reply = journey
        .decide(
            &journey.approver,
            "wrong-version",
            "approve-dependency",
            "0.3.2",
            None,
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    assert!(journey.recorded().await.is_empty());
    assert_eq!(
        journey.markers().await,
        [("decision.rejected".to_owned(), "not_awaited".to_owned())]
    );
    assert!(matches!(
        journey.rig.unblock(journey.job, run).await,
        Err(EngineError::GuardUnmet(_))
    ));

    // 4. The same package with a checksum it does not have is no better.
    let reply = journey
        .decide(
            &journey.approver,
            "wrong-checksum",
            "approve-dependency",
            VERSION,
            Some(&"d".repeat(12)),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    assert!(journey.recorded().await.is_empty());

    // 5. The person who was shown the package decides. The worker applies it through the engine.
    let reply = journey
        .decide(
            &journey.approver,
            "the-decision",
            "approve-dependency",
            VERSION,
            Some(&checksum()[..12]),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let recorded = journey.recorded().await;
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_eq!(recorded[0].subject.name, PACKAGE);
    assert_eq!(recorded[0].subject.version, VERSION);
    assert_eq!(recorded[0].subject.checksum, checksum());
    assert_eq!(
        recorded[0].approver.get(),
        journey.rig.env.a.approver.github_id
    );
    assert!(
        journey
            .markers()
            .await
            .contains(&("decision.applied".to_owned(), "applied".to_owned()))
    );
    // The decision is in the ledger of the job, as a judgment that names the person.
    let ledger = journey
        .rig
        .ledger_head(journey.job, StageKind::Validation, run)
        .await;
    assert!(!ledger.as_str().is_empty());

    // 6. A decision counts while the person still stands on the allowlist. Take the approver off
    // the file and the stage asks again; put them back and the decision counts again.
    let allowlist = journey.rig.env.checkout.join("allowlist/allowlist.yaml");
    let original = std::fs::read_to_string(&allowlist).expect("the allowlist");
    let without: String = original
        .split("  - tenant: ")
        .enumerate()
        .filter(|(_, entry)| {
            !entry.contains(&format!(
                "github_user_id: {}\n",
                journey.rig.env.a.approver.github_id
            ))
        })
        .map(|(index, entry)| {
            if index == 0 {
                entry.to_owned()
            } else {
                format!("  - tenant: {entry}")
            }
        })
        .collect();
    std::fs::write(&allowlist, &without).expect("the allowlist without the approver");
    assert!(
        journey.recorded().await.is_empty(),
        "a decision of a person who left the allowlist does not count"
    );
    std::fs::write(&allowlist, &original).expect("the allowlist again");
    assert_eq!(journey.recorded().await.len(), 1);

    // 7. The operator lets the run go, and the stage passes through the fetch and the audit.
    journey
        .rig
        .unblock(journey.job, run)
        .await
        .expect("a recorded decision clears the block");
    let view = journey
        .until(240, |view| passed(view) || journey_stopped(view))
        .await;
    assert!(passed(&view), "{:#?}\n{view:?}", gates(&journey).await);
    assert!(journey.rig.cargo.ran("fetch") >= 1);
    assert!(journey.rig.cargo.ran("audit") >= 1);
    let evidence = journey
        .rig
        .stage_output(journey.job, StageKind::Validation, "validation-evidence")
        .await;
    assert!(
        awaiting(&evidence, "new_direct_dependencies").is_empty(),
        "nothing is awaited any more: {evidence}"
    );
    journey.rig.finish();
}

fn journey_stopped(view: &JobView) -> bool {
    blocked(view)
        || matches!(
            full::status_of(view, StageKind::Validation),
            Some(StageRunStatus::Failed)
        )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn build_code_in_the_new_package_needs_a_security_approver_and_its_own_decision() {
    let journey = begin().await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    journey.the_builder_adds_the_dependency(true);
    let view = journey.to_the_stop_at_validation().await;
    let run = full::stage_run_of(&view, StageKind::Validation);
    assert!(blocked(&view), "{view:#?}");

    // The dependency first. An approver decides it, and the operator lets the run go.
    journey
        .decide(
            &journey.approver,
            "the-decision",
            "approve-dependency",
            VERSION,
            None,
        )
        .await;
    assert_eq!(journey.recorded().await.len(), 1);
    journey
        .rig
        .unblock(journey.job, run)
        .await
        .expect("a recorded decision clears the block");

    // The package is fetched now, and its build script is seen. The dependency decision does not
    // cover it: the stage blocks again, and asks for the other decision.
    let view = journey
        .until(240, |view| blocked(view) || passed(view))
        .await;
    assert!(
        blocked(&view),
        "the stage must block on the build code: {view:#?}"
    );
    assert!(journey.rig.cargo.ran("fetch") >= 1);
    assert_eq!(
        journey.rig.cargo.ran("audit"),
        0,
        "nothing is scanned while build code awaits a decision"
    );
    let evidence = journey
        .rig
        .stage_output(journey.job, StageKind::Validation, "validation-evidence")
        .await;
    assert_eq!(
        awaiting(&evidence, "build_code_awaiting_a_decision"),
        [(
            PACKAGE.to_owned(),
            VERSION.to_owned(),
            "security_approver".to_owned()
        )],
        "{evidence}"
    );
    assert!(matches!(
        journey.rig.unblock(journey.job, run).await,
        Err(EngineError::GuardUnmet(_))
    ));

    // An approver may not decide on build code: the API says no, and nothing is recorded.
    let reply = journey
        .decide(
            &journey.approver,
            "approver-on-build-code",
            "approve-build-code",
            VERSION,
            None,
        )
        .await;
    assert_eq!(reply.status, 403, "{}", reply.text());
    // A security approver who decides on the wrong package or kind is not heard either.
    let reply = journey
        .decide(
            &journey.security,
            "wrong-checksum",
            "approve-build-code",
            VERSION,
            Some(&"d".repeat(12)),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    assert_eq!(journey.recorded().await.len(), 1, "only the dependency");
    // Build code is not decided by a decision on the dependency (and the evidence does not list
    // the dependency as awaiting any more, so the first is rejected as not awaited).
    let reply = journey
        .decide(
            &journey.security,
            "wrong-kind",
            "approve-dependency",
            VERSION,
            None,
        )
        .await;
    assert_eq!(reply.status, 403, "{}", reply.text());
    assert_eq!(journey.recorded().await.len(), 1);
    assert!(matches!(
        journey.rig.unblock(journey.job, run).await,
        Err(EngineError::GuardUnmet(_))
    ));

    // The security approver decides on the build code of the package they were shown.
    let reply = journey
        .decide(
            &journey.security,
            "the-build-code",
            "approve-build-code",
            VERSION,
            Some(&checksum()[..12]),
        )
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let recorded = journey.recorded().await;
    assert_eq!(recorded.len(), 2, "{recorded:?}");
    assert!(recorded.iter().any(|approval| approval.approver.get()
        == journey.rig.env.a.security.github_id
        && approval.kind
            == factory_workflow::gates::supply_chain::approval::ApprovalKind::BuildCode));
    journey
        .rig
        .unblock(journey.job, run)
        .await
        .expect("a recorded decision clears the block");
    let view = journey
        .until(240, |view| passed(view) || journey_stopped(view))
        .await;
    assert!(passed(&view), "{view:#?}");
    assert!(journey.rig.cargo.ran("audit") >= 1);
    journey.rig.finish();
}

/// The engine has no redactor. The step that calls it has one, and runs the person's reason
/// through it first. The request is written here the way the API writes it, signed with the key
/// the API holds, but with a secret in the reason that the API itself would have refused: the
/// property is that nothing the worker stores holds it, whatever the API did.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reason_of_a_person_is_redacted_before_the_engine_stores_it() {
    use factory_composition::decision_signing::DependencySigning;
    use factory_composition::dependency_decisions::{DependencyFields, REQUESTED};
    use factory_workflow::gates::supply_chain::approval::ApprovalKind;

    let canaries = factory_testkit::fx::canary::CanarySet::generate();
    let canary = canaries
        .get(factory_testkit::fx::canary::CanaryKind::GithubInstallationToken)
        .value()
        .to_owned();
    let journey = begin().await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    journey.the_builder_adds_the_dependency(false);
    let view = journey.to_the_stop_at_validation().await;
    assert!(blocked(&view), "{view:#?}");

    let fields = DependencyFields {
        kind: ApprovalKind::NewDependency,
        job: journey.job,
        stage_run: None,
        package: PACKAGE.to_owned(),
        version: VERSION.to_owned(),
        checksum: None,
    };
    let event = AuditEventId::from_uuid(uuid::Uuid::from_u128(0x5eed_5eed));
    let requested_at = journey.rig.env.state.ports.clock.now().as_text();
    let person = &journey.rig.env.a.approver;
    let subject = journey
        .rig
        .env
        .state
        .decision_keys
        .signed_dependency_subject(&DependencySigning {
            tenant: journey.rig.tenant,
            actor: person.principal,
            event,
            requested_at: &requested_at,
            fields: &fields,
        });
    let scope = TenantScope::new(journey.rig.tenant);
    let mut tx = journey.rig.env.store.begin(scope).await.expect("a tx");
    let correlation = tx
        .get_job(journey.job)
        .await
        .expect("the job")
        .value
        .correlation_id;
    tx.record_audit(NewAuditEvent {
        id: event,
        actor: AuditActor::Human(person.principal),
        action: AuditAction::new(REQUESTED).expect("an action"),
        subject,
        decision: AuditDecision::Record,
        reason: format!("requested: Read the package. The issue pasted {canary} by mistake."),
        policy_hash: journey.rig.policies.hash.clone(),
        job: Some(journey.job),
        stage_run: None,
        correlation_id: correlation,
    })
    .await
    .expect("the request is recorded");
    tx.commit().await.expect("commit");

    journey.rig.hook.pass(journey.rig.tenant).await;
    let recorded = journey.recorded().await;
    assert_eq!(recorded.len(), 1, "the decision is applied: {recorded:?}");
    assert!(
        !recorded[0].reason.contains(&canary),
        "the reason reached the engine unredacted: {}",
        recorded[0].reason
    );
    assert!(recorded[0].reason.starts_with("Read the package."));
    // No blob the worker stored holds the secret in any spelling.
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
    assert!(
        hits.is_empty(),
        "the canary was stored: {} hit(s)",
        hits.len()
    );
    journey.rig.finish();
}

/// A request nobody signed is not a request. The worker rejects it with the fixed code and the
/// decision does not count, whatever its words say.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_for_a_dependency_decision_that_the_api_did_not_sign_is_rejected() {
    use factory_composition::dependency_decisions::{DependencyFields, REQUESTED};
    use factory_workflow::gates::supply_chain::approval::ApprovalKind;

    let journey = begin().await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    journey.the_builder_adds_the_dependency(false);
    let view = journey.to_the_stop_at_validation().await;
    assert!(blocked(&view), "{view:#?}");

    let fields = DependencyFields {
        kind: ApprovalKind::NewDependency,
        job: journey.job,
        stage_run: None,
        package: PACKAGE.to_owned(),
        version: VERSION.to_owned(),
        checksum: None,
    };
    let person = &journey.rig.env.a.approver;
    let scope = TenantScope::new(journey.rig.tenant);
    let mut tx = journey.rig.env.store.begin(scope).await.expect("a tx");
    let correlation = tx
        .get_job(journey.job)
        .await
        .expect("the job")
        .value
        .correlation_id;
    for (index, subject) in [
        // No word at all.
        fields.subject(),
        // A word that is not the API's.
        format!(
            "{} at={} mac={}",
            fields.subject(),
            journey.rig.env.state.ports.clock.now().as_text(),
            "0".repeat(64)
        ),
    ]
    .into_iter()
    .enumerate()
    {
        tx.record_audit(NewAuditEvent {
            id: AuditEventId::from_uuid(uuid::Uuid::from_u128(0x7000 + index as u128)),
            actor: AuditActor::Human(person.principal),
            action: AuditAction::new(REQUESTED).expect("an action"),
            subject,
            decision: AuditDecision::Record,
            reason: "requested: A forged request with a reason of ten characters.".to_owned(),
            policy_hash: journey.rig.policies.hash.clone(),
            job: Some(journey.job),
            stage_run: None,
            correlation_id: correlation,
        })
        .await
        .expect("the request is recorded");
    }
    tx.commit().await.expect("commit");
    journey.rig.hook.pass(journey.rig.tenant).await;
    assert!(journey.recorded().await.is_empty());
    let text = journey.rig.audit_text(journey.job).await;
    assert_eq!(
        text.matches("code=not_signed").count(),
        2,
        "both are rejected with the fixed code: {text}"
    );
    journey.rig.finish();
}
