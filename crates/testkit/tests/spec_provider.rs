//! The fake specification provider plays back queued outcomes, records requests and honours the
//! cancel signal.

use factory_domain::contracts::specification_contract::OpenQuestion;
use factory_domain::contracts::{Contract, SpecificationContract};
use factory_domain::ids::JobId;
use factory_ports::agent::AgentRunError;
use factory_ports::clock::Uuid;
use factory_ports::paths::{CommitSha, RepoGlob, RepoPath, RepoRef};
use factory_ports::sandbox::{SandboxProfile, SandboxProvider};
use factory_ports::spec::{
    FeatureDir, SpecContext, SpecError, SpecOperation, SpecOutcome, SpecRequest,
    SpecificationDraft, SpecificationProvider,
};
use factory_ports::workspace::{WorkspaceProvider, WorkspaceRequest};
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::clock::{FakeCancel, FakeClock};
use factory_testkit::fixtures::{self, Ids};
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::spec::FakeSpecificationProvider;
use factory_testkit::workspace::FakeWorkspaceProvider;
use std::sync::Arc;

fn request(op: SpecOperation) -> SpecRequest {
    SpecRequest {
        job: JobId::from_uuid(Uuid::from_u128(7)),
        op,
        feature_directory: FeatureDir::new("specs/001-word-count").expect("a feature directory"),
        request_file: RepoPath::new("request.md").expect("a path"),
        answers: Vec::new(),
        revision: None,
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

#[tokio::test]
async fn the_fake_plays_queued_outcomes_in_order_and_records_requests() {
    let clock = Arc::new(FakeClock::new());
    let artifacts = Arc::new(InMemoryArtifactStore::new());
    let sandbox = FakeSandbox::new(clock, artifacts.clone(), fixtures::sandbox_policy());
    let ids = Ids::new();
    let mut session = sandbox
        .create_verified(fixtures::sandbox_spec(&ids, SandboxProfile::Agent))
        .await
        .expect("an agent sandbox");
    let repo = RepoRef::parse("example-org/fixture").expect("a repo");
    let base = CommitSha::parse(&"1".repeat(40)).expect("a sha");
    let workspaces =
        FakeWorkspaceProvider::new(repo.clone(), base.clone(), &[("README.md", "# x\n")]);
    let workspace = workspaces
        .create(WorkspaceRequest {
            job: ids.job(),
            repo,
            base,
            hidden: vec![RepoGlob::new("hidden/**").expect("a glob")],
            protected: Vec::new(),
        })
        .await
        .expect("a workspace");
    let runtime = FakeAgentRuntime::new(artifacts);
    let cancel = FakeCancel::new();

    let provider = FakeSpecificationProvider::new();
    provider.queue(Ok(SpecOutcome::NeedsHuman(vec![open_question()])));
    provider.queue(Ok(SpecOutcome::Draft(Box::new(SpecificationDraft {
        contract: approved(),
        files: Vec::new(),
    }))));

    let mut context = SpecContext {
        workspace: workspace.as_ref(),
        session: session.as_mut(),
        runtime: &runtime,
        run_template: fixtures::agent_run_request(&ids),
        cancel: &cancel,
    };

    let first = provider
        .run(request(SpecOperation::Specify), &mut context)
        .await;
    assert!(matches!(first, Ok(SpecOutcome::NeedsHuman(ref questions)) if questions.len() == 1));
    let second = provider
        .run(request(SpecOperation::Clarify), &mut context)
        .await;
    assert!(matches!(second, Ok(SpecOutcome::Draft(_))));
    // Nothing is queued any more: the fake reports a missing tool, not a made-up result.
    let third = provider
        .run(request(SpecOperation::Checklist), &mut context)
        .await;
    assert_eq!(third.err(), Some(SpecError::ToolMissing));

    let seen: Vec<SpecOperation> = provider.requests().iter().map(|r| r.op).collect();
    assert_eq!(
        seen,
        vec![
            SpecOperation::Specify,
            SpecOperation::Clarify,
            SpecOperation::Checklist
        ]
    );

    // A cancel that is already set stops the call, and the queued outcome is not consumed.
    provider.queue(Ok(SpecOutcome::NeedsHuman(Vec::new())));
    cancel.cancel();
    let cancelled = provider
        .run(request(SpecOperation::Specify), &mut context)
        .await;
    assert_eq!(
        cancelled.err(),
        Some(SpecError::Runtime(AgentRunError::Cancelled))
    );
}
