//! The draft pull request, the evidence manifest and the check runs on the happy path, and a
//! restart in the middle.

use factory_domain::contracts::{Contract, EvidenceManifest};
use factory_domain::vocabulary::GateOutcome;
use factory_ports::githost::{CheckConclusion, CheckStatus, PullRequestRef};
use factory_ports::paths::CommitSha;
use factory_workflow::gates::framework::Resolution;
use factory_workflow::gates::readability::{Artifact, Options, ReadabilityGate, Severity};
use factory_workflow::stages::validation::GATES;
use serde_json::Value;

use crate::schema_check;
use crate::spy::Call;
use crate::world::{Scenario, World};

const MANIFEST_SCHEMA: &str = include_str!("../../../../schemas/evidence-manifest.schema.json");

fn limitations(manifest: &Value) -> Vec<String> {
    manifest["limitations"]
        .as_array()
        .expect("limitations")
        .iter()
        .map(|line| line.as_str().expect("text").to_owned())
        .collect()
}

#[tokio::test]
async fn the_stage_passes_on_the_happy_path() {
    let world = World::new();
    let ran = world.run().await;
    assert_eq!(ran.problem, None);
    assert_eq!(
        ran.resolution,
        Resolution::Pass,
        "{:#?}",
        ran.decision.reports
    );
    for report in &ran.decision.reports {
        assert_eq!(
            report.outcome,
            GateOutcome::Passed,
            "{:?}",
            report.metadata.gate_id
        );
    }
    let names: Vec<&str> = ran.outputs.iter().map(|o| o.name.as_str()).collect();
    assert_eq!(names, ["evidence-manifest", "delivery-result"]);
    assert_eq!(ran.report("readability-gate").outcome, GateOutcome::Passed);
}

#[tokio::test]
async fn manifest_is_complete_and_honest() {
    // One gate has no report, one was blocked and decided by a person: both must be named.
    let mut scenario = Scenario::default();
    scenario.gates.retain(|(gate, _)| gate != "secret-scan");
    for (gate, outcome) in &mut scenario.gates {
        if gate == "lint" {
            *outcome = "BLOCKED";
        }
    }
    scenario.dispositions = vec!["lint".to_owned()];
    let world = World::with(scenario);
    let ran = world.run().await;

    // It validates against its schema file and against the contract type.
    let schema: Value = serde_json::from_str(MANIFEST_SCHEMA).expect("the schema is JSON");
    assert_eq!(
        schema_check::problems(&schema, &ran.manifest),
        Vec::<String>::new()
    );
    let manifest = EvidenceManifest::from_json_value(ran.manifest.clone()).expect("parses");
    manifest.validate().expect("follows its contract");

    // It includes the verified ledger head.
    let sources = world.sources.ledger.lock().expect("lock").clone();
    assert_eq!(manifest.ledger.head_hash, sources.head_hash);
    assert_eq!(
        manifest.ledger.head_sequence.get() as u64,
        sources.head_sequence
    );

    // Its limitations name every gate that did not run and every adapter that was not real.
    let lines = limitations(&ran.manifest);
    let has = |needle: &str| lines.iter().any(|line| line.contains(needle));
    assert!(has("secret-scan has no report"), "{lines:#?}");
    assert!(has("The gate lint could not run"), "{lines:#?}");
    for adapter in ["sandbox", "code host", "artifact store", "agent runtime"] {
        assert!(has(&format!("The {adapter}")), "{adapter}: {lines:#?}");
    }
    assert!(has("a draft"), "{lines:#?}");

    // The blocked gate carries the ledger entry of the person's decision.
    let blocked = ran.manifest["gate_reports"]
        .as_array()
        .expect("gates")
        .iter()
        .find(|gate| gate["gate_id"] == "lint")
        .expect("the lint gate");
    assert_eq!(blocked["outcome"], "BLOCKED");
    assert!(blocked["disposition_ledger_entry_id"].is_string());
}

#[tokio::test]
async fn pull_request_body() {
    let world = World::new();
    let ran = world.run().await;
    let opened = world.host.opened();
    assert_eq!(opened.len(), 1, "one pull request request");
    let request = &opened[0];

    // Draft, from a factory branch, against the protected base.
    assert_eq!(request.head.as_str(), "factory/job-1");
    assert_eq!(request.base.as_str(), "main");
    let pr = PullRequestRef {
        repo: world.repo.clone(),
        number: ran.result["pull_request"].as_u64().expect("a number"),
    };
    let state = factory_ports::githost::ChangeHost::pull_request_state(
        &*world.host,
        &factory_ports::githost::GitScope {
            tenant: world.tenant,
            job: world.job,
            stage: factory_domain::vocabulary::StageKind::Delivery,
            repo: world.repo.clone(),
        },
        &pr,
    )
    .await
    .expect("the pull request");
    assert!(state.draft, "the pull request is a draft");

    // The body carries the manifest hash, the issue, the spec revision and the links.
    let body = &request.body;
    let hash = ran.result["manifest_sha256"].as_str().expect("hash");
    let hex = hash.strip_prefix("sha256:").unwrap_or(hash);
    assert!(body.contains(hex), "the manifest hash: {body}");
    assert!(body.contains("Closes #12"), "{body}");
    assert!(
        body.contains("version 1 of the frozen specification"),
        "{body}"
    );
    assert!(body.contains("docs/adr/0001-json-output.md"), "{body}");
    assert!(body.contains("specs/001-json/tasks.md"), "{body}");
    assert!(
        body.contains("https://github.com/example-org/word-count/blob/"),
        "{body}"
    );
    assert!(body.contains("| unit-tests | passed |"), "{body}");
    assert!(body.contains("verdict pass"), "{body}");
    assert!(body.contains("What was not verified"), "{body}");
    assert!(
        body.contains("The factory does not merge and does not deploy"),
        "{body}"
    );

    // It passes the readability gate: no finding that blocks, and none that warns.
    let findings = ReadabilityGate::new(Options::new())
        .findings(&[Artifact::pull_request(&request.title, &request.body)])
        .expect("the gate runs");
    assert!(
        findings.iter().all(|f| f.severity != Severity::Block),
        "{findings:#?}"
    );
    assert!(findings.is_empty(), "{findings:#?}");
    assert_eq!(ran.resolution, Resolution::Pass);
}

#[tokio::test]
async fn check_runs_follow_the_gate_outcomes() {
    let world = World::new();
    let ran = world.run().await;
    let checks = world.host.checks();
    assert_eq!(checks.len(), 2, "validation and review");
    for check in &checks {
        assert_eq!(
            check.commit.as_str(),
            ran.result["head_commit"].as_str().expect("head")
        );
        assert_eq!(
            check.status,
            CheckStatus::Completed(CheckConclusion::Success)
        );
    }
    let names: Vec<&str> = checks.iter().map(|check| check.name.as_str()).collect();
    assert_eq!(names, ["factory-validation", "factory-review"]);
}

#[tokio::test]
async fn a_blocked_gate_is_never_a_success_check() {
    let mut scenario = Scenario::default();
    for (gate, outcome) in &mut scenario.gates {
        if gate == "build" {
            *outcome = "BLOCKED";
        }
    }
    scenario.dispositions = vec!["build".to_owned()];
    let world = World::with(scenario);
    world.run().await;
    let validation = world
        .host
        .checks()
        .into_iter()
        .find(|check| check.name.as_str() == "factory-validation")
        .expect("the validation check");
    assert_eq!(
        validation.status,
        CheckStatus::Completed(CheckConclusion::ActionRequired)
    );
}

#[tokio::test]
async fn the_stage_restarts_without_a_second_pull_request_or_check_run() {
    let world = World::new();
    let (base, head) = world.commits().await;
    let first = world.run_on(&base, &head).await;
    let second = world.run_on(&base, &head).await;
    assert_eq!(first.result["pull_request"], second.result["pull_request"]);
    // The check runs are on the head of the pull request, which is the documentation commit.
    let pushed = second.result["head_commit"].as_str().expect("a commit");
    let pushed = CommitSha::parse(pushed).expect("a sha");
    assert_ne!(pushed, head);
    assert_eq!(
        world
            .host
            .inner()
            .check_run_count(&pushed, "factory-validation"),
        1
    );
    assert_eq!(
        world
            .host
            .inner()
            .check_run_count(&pushed, "factory-review"),
        1
    );
    // Both runs asked to open it, and the host kept one. The body was written again with the
    // tag it had read.
    assert_eq!(world.host.count(|c| matches!(c, Call::Open { .. })), 2);
    assert_eq!(second.resolution, Resolution::Pass);
}

#[tokio::test]
async fn every_validation_gate_is_in_the_matrix() {
    let world = World::new();
    let ran = world.run().await;
    let body = &world.host.opened()[0].body;
    for (gate, _) in GATES {
        assert!(body.contains(&format!("| {gate} |")), "{gate}");
    }
    assert_eq!(
        ran.manifest["gate_reports"]
            .as_array()
            .expect("gates")
            .len(),
        GATES.len()
    );
}
