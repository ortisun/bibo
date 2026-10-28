//! The commits: base, code head, documentation head, pushed head.
//!
//! Five stages name a commit, and each has to name the commit the stage before it made. The
//! chain, read from what the real stages stored:
//!
//! ```text
//! base --IMPLEMENTATION--> code head --DOCUMENTING--> documentation head = pushed head
//!        VALIDATION and REVIEW: bound to base and code head
//!        DOCUMENTATION_REVIEW:  bound to base, code head, documentation head, documentation plan
//!        DELIVERY:              pushes the documentation head, cites the code head
//!        APPROVAL:              shows the person the pushed head; the evidence stays on the code head
//! ```

use factory_domain::vocabulary::StageKind;
use factory_ports::githost::{ChangeHost, GitScope, PullRequestRef};
use factory_ports::paths::{BranchName, CommitSha};
use factory_ports::workspace::WorkspaceProvider;
use factory_workflow::stages::approval::ApprovalRequest;
use factory_workflow::stages::validation::Binding;

use crate::chain::Pipeline;
use crate::deliver::Delivery;
use crate::pairs::Whole;

fn commit(document: &serde_json::Value, key: &str) -> CommitSha {
    CommitSha::parse(
        document[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} in {document}")),
    )
    .unwrap_or_else(|_| panic!("{key} is a commit"))
}

#[tokio::test]
async fn the_commits_chain_from_the_base_to_the_head_that_is_pushed_and_approved() {
    let whole = Whole::run().await;
    let pipeline = &whole.pipeline;
    let rig = &pipeline.rig;

    // IMPLEMENTATION: the base is the tip of the protected branch, the code head sits on it.
    let result = pipeline
        .real(StageKind::Implementation, "implementation-result")
        .json();
    let (base, code_head) = (
        commit(&result, "base_commit"),
        commit(&result, "head_commit"),
    );
    assert_eq!(
        base, rig.base,
        "the base is the tip of the protected branch"
    );
    assert_ne!(base, code_head, "the implementation stage made a commit");

    // VALIDATION: the evidence is bound to the base and to the code head, and to that result.
    let evidence = pipeline
        .find(StageKind::Validation, "validation-evidence")
        .json();
    let binding = Binding::from_json(&evidence["binding"]).expect("a binding");
    assert_eq!(binding.base_commit.as_str(), base.as_str());
    assert_eq!(binding.head_commit.as_str(), code_head.as_str());
    assert_eq!(
        binding.implementation_result,
        pipeline
            .real(StageKind::Implementation, "implementation-result")
            .artifact
            .sha256
    );

    // DOCUMENTING: the plan and the result are about the base and the code head, and the
    // documentation head sits on the code head and changes only the documents.
    let plan = pipeline
        .real(StageKind::Documenting, "documentation-plan")
        .json();
    assert_eq!(plan["base_commit"], base.as_str());
    assert_eq!(plan["code_head"], code_head.as_str());
    let documented = pipeline
        .real(StageKind::Documenting, "documentation-result")
        .json();
    assert_eq!(commit(&documented, "base_commit"), base);
    assert_eq!(commit(&documented, "code_head"), code_head);
    let docs_head = commit(&documented, "head_commit");
    assert_ne!(docs_head, code_head, "the writer committed the documents");
    let repo = rig
        .provider
        .repo(rig.job)
        .await
        .expect("the job repository");
    let on_top = repo
        .export_patch(
            &code_head,
            &docs_head,
            1_000_000,
            &factory_testkit::clock::FakeCancel::new(),
        )
        .await
        .expect("the documentation commit is on the code head");
    let mut paths: Vec<&str> = on_top.changes.iter().map(|c| c.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(
        paths,
        ["CHANGELOG.md", "README.md"],
        "only documents changed"
    );

    // DOCUMENTATION_REVIEW: the reports are bound to all of it, and to the plan that was written.
    let gate = pipeline
        .real(StageKind::DocumentationReview, "documentation-gate-report")
        .json();
    assert_eq!(commit(&gate["binding"], "base_commit"), base);
    assert_eq!(commit(&gate["binding"], "code_head"), code_head);
    assert_eq!(commit(&gate["binding"], "documentation_head"), docs_head);
    assert_eq!(
        gate["binding"]["plan_sha256"],
        pipeline
            .real(StageKind::Documenting, "documentation-plan")
            .artifact
            .sha256
            .as_str()
    );

    // DELIVERY: pushes the documentation head, and cites the code head the gates ran on.
    let delivery = whole.delivered.find("delivery-result").json();
    assert_eq!(commit(&delivery, "base_commit"), base);
    assert_eq!(commit(&delivery, "code_head"), code_head);
    assert_eq!(commit(&delivery, "head_commit"), docs_head);
    let manifest = whole.delivered.find("evidence-manifest").json();
    assert_eq!(
        manifest["metadata"]["repository"]["base_commit"],
        base.as_str()
    );
    assert_eq!(
        manifest["metadata"]["repository"]["head_commit"],
        docs_head.as_str()
    );

    // The factory branch on the code host ends at the pushed head.
    let branch = BranchName::new("factory/job-1").expect("a branch");
    assert_eq!(
        rig.remote.branch_tip(&rig.repo, &branch),
        Some(docs_head.clone())
    );

    // APPROVAL: the person is shown the pushed head, and the evidence stays on the code head.
    let request = ApprovalRequest::from_json(&whole.approved.find("approval-request").json())
        .expect("a request");
    assert_eq!(request.pr_head.as_str(), docs_head.as_str());
    assert_eq!(request.base.as_str(), base.as_str());
    assert_eq!(
        request.evidence_binding.head_commit.as_str(),
        code_head.as_str()
    );
    assert_eq!(request.evidence_binding.base_commit.as_str(), base.as_str());
    assert_ne!(
        request.pr_head.as_str(),
        request.evidence_binding.head_commit.as_str()
    );
}

#[tokio::test]
async fn the_delivery_stage_asked_for_the_tree_of_the_pushed_head_and_no_other() {
    let pipeline = Pipeline::documented().await;
    let delivery = Delivery::over(&pipeline).await;
    let upstream = delivery.upstream_of_delivery();
    delivery
        .run(&delivery.delivery_handler(), StageKind::Delivery, &upstream)
        .await
        .expect("the delivery runs");
    let documented = pipeline
        .real(StageKind::Documenting, "documentation-result")
        .json();
    assert_eq!(
        delivery.trees_asked(),
        vec![commit(&documented, "head_commit")]
    );
}

#[tokio::test]
async fn the_pull_request_points_at_the_pushed_head() {
    let pipeline = Pipeline::documented().await;
    let delivery = Delivery::over(&pipeline).await;
    let upstream = delivery.upstream_of_delivery();
    let ran = delivery
        .run(&delivery.delivery_handler(), StageKind::Delivery, &upstream)
        .await
        .expect("the delivery runs");
    let result = ran.find("delivery-result").json();
    let state = delivery
        .host()
        .pull_request_state(
            &GitScope {
                tenant: pipeline.rig.world.tenant,
                job: pipeline.rig.job,
                stage: StageKind::Approval,
                repo: pipeline.rig.repo.clone(),
            },
            &PullRequestRef {
                repo: pipeline.rig.repo.clone(),
                number: result["pull_request"].as_u64().expect("a number"),
            },
        )
        .await
        .expect("a state");
    assert!(state.draft);
    assert_eq!(state.head_sha.as_str(), result["head_commit"]);
}
