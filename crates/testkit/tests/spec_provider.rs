//! The fake specification provider (ports-v1.1). `run` drives a scripted tool in the fake sandbox
//! and reads no file; `assemble` is pure over committed files, refuses a feature without its
//! `spec.md` or with a `spec.md` that is not text, and returns what a test queued.

use std::sync::Arc;

use factory_domain::contracts::specification_contract::OpenQuestion;
use factory_domain::contracts::{Contract, SpecificationContract};
use factory_domain::ids::JobId;
use factory_ports::agent::AgentRunError;
use factory_ports::clock::Uuid;
use factory_ports::paths::{CommitSha, RepoPath};
use factory_ports::sandbox::{SandboxProfile, SandboxProvider};
use factory_ports::spec::{
    FeatureDir, ParseReason, SpecContext, SpecError, SpecFile, SpecFileSet, SpecOperation,
    SpecOutcome, SpecRequest, SpecificationDraft, SpecificationProvider,
};
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::clock::{FakeCancel, FakeClock};
use factory_testkit::fixtures::{self, Ids};
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::spec::{FakeSpecificationProvider, ScriptedRun};

fn request(op: SpecOperation) -> SpecRequest {
    SpecRequest {
        job: JobId::from_uuid(Uuid::from_u128(7)),
        op,
        feature_directory: FeatureDir::new("specs/001-word-count").expect("a feature directory"),
        request_file: RepoPath::new("request.md").expect("a path"),
        answers: Vec::new(),
        revision: None,
        rework: None,
    }
}

fn approved() -> SpecificationContract {
    SpecificationContract::from_json_str(include_str!(
        "../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
    ))
    .expect("a valid specification contract")
}

fn open_question() -> OpenQuestion {
    approved()
        .open_questions
        .into_iter()
        .next()
        .expect("the example has an open question")
}

fn files(spec_bytes: Option<&[u8]>) -> SpecFileSet {
    SpecFileSet {
        commit: CommitSha::parse(&"1".repeat(40)).expect("a sha"),
        files: spec_bytes
            .map(|bytes| SpecFile {
                path: RepoPath::new("specs/001-word-count/spec.md").expect("a path"),
                bytes: bytes.to_vec(),
            })
            .into_iter()
            .collect(),
    }
}

struct Rig {
    sandbox: FakeSandbox,
    runtime: FakeAgentRuntime,
    ids: Ids,
}

fn rig() -> Rig {
    let clock = Arc::new(FakeClock::new());
    let artifacts = Arc::new(InMemoryArtifactStore::new());
    Rig {
        sandbox: FakeSandbox::new(clock, artifacts.clone(), fixtures::sandbox_policy()),
        runtime: FakeAgentRuntime::new(artifacts),
        ids: Ids::new(),
    }
}

#[tokio::test]
async fn assemble_plays_queued_outcomes_after_it_checks_the_files() {
    let provider = FakeSpecificationProvider::new();
    provider.queue(Ok(SpecOutcome::NeedsHuman(vec![open_question()])));
    provider.queue(Ok(SpecOutcome::Draft(Box::new(SpecificationDraft {
        contract: approved(),
        files: Vec::new(),
    }))));
    let request = request(SpecOperation::Specify);

    let first = provider.assemble(&request, &files(Some(b"# A spec\n")));
    assert!(matches!(first, Ok(SpecOutcome::NeedsHuman(ref q)) if q.len() == 1));
    let second = provider.assemble(&request, &files(Some(b"# A spec\n")));
    assert!(matches!(second, Ok(SpecOutcome::Draft(_))));
    // Nothing is queued any more: the fake reports a missing tool, not a made-up result.
    let third = provider.assemble(&request, &files(Some(b"# A spec\n")));
    assert_eq!(third.err(), Some(SpecError::ToolMissing));
}

#[tokio::test]
async fn assemble_refuses_a_missing_spec_and_one_that_is_not_text() {
    let provider = FakeSpecificationProvider::new();
    provider.queue(Ok(SpecOutcome::NeedsHuman(Vec::new())));
    let request = request(SpecOperation::Specify);
    let missing = provider.assemble(&request, &files(None));
    assert!(matches!(
        missing,
        Err(SpecError::ParseError {
            reason: ParseReason::Missing,
            ..
        })
    ));
    let binary = provider.assemble(&request, &files(Some(&[0xff, 0xfe, 0x00])));
    assert!(matches!(
        binary,
        Err(SpecError::ParseError {
            reason: ParseReason::NotText,
            ..
        })
    ));
    // Neither refusal consumed the queued outcome.
    let good = provider.assemble(&request, &files(Some(b"ok")));
    assert!(matches!(good, Ok(SpecOutcome::NeedsHuman(_))));
}

#[tokio::test]
async fn run_executes_the_scripted_tool_in_the_sandbox_and_records_the_request() {
    let rig = rig();
    let mut session = rig
        .sandbox
        .create_verified(
            fixtures::sandbox_spec(&rig.ids, SandboxProfile::Agent),
            &FakeCancel::new(),
        )
        .await
        .expect("an agent sandbox");
    let cancel = FakeCancel::new();
    let provider = FakeSpecificationProvider::new();
    let expected = RepoPath::new("specs/001-word-count/spec.md").expect("a path");
    provider.script_run(ScriptedRun {
        commands: vec![vec!["echo".into(), "specify".into()]],
        expected_files: vec![expected.clone()],
    });
    let mut context = SpecContext {
        session: session.as_mut(),
        runtime: &rig.runtime,
        run_template: fixtures::agent_run_request(&rig.ids),
        cancel: &cancel,
    };
    let report = provider
        .run(&request(SpecOperation::Specify), &mut context)
        .await
        .expect("the scripted run finishes");
    assert_eq!(report.op, SpecOperation::Specify);
    assert_eq!(report.expected_files, vec![expected]);
    assert_eq!(provider.requests().len(), 1);

    // A command that fails in the sandbox fails the run, instead of being ignored.
    provider.script_run(ScriptedRun {
        commands: vec![vec!["false".into()]],
        expected_files: Vec::new(),
    });
    let failed = provider
        .run(&request(SpecOperation::Clarify), &mut context)
        .await;
    assert_eq!(failed.err(), Some(SpecError::ToolMissing));
}

#[tokio::test]
async fn a_cancel_that_is_already_set_stops_the_run() {
    let rig = rig();
    let mut session = rig
        .sandbox
        .create_verified(
            fixtures::sandbox_spec(&rig.ids, SandboxProfile::Agent),
            &FakeCancel::new(),
        )
        .await
        .expect("an agent sandbox");
    let cancel = FakeCancel::new();
    cancel.cancel();
    let provider = FakeSpecificationProvider::new();
    let mut context = SpecContext {
        session: session.as_mut(),
        runtime: &rig.runtime,
        run_template: fixtures::agent_run_request(&rig.ids),
        cancel: &cancel,
    };
    let cancelled = provider
        .run(&request(SpecOperation::Specify), &mut context)
        .await;
    assert_eq!(
        cancelled.err(),
        Some(SpecError::Runtime(AgentRunError::Cancelled))
    );
}
