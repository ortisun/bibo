//! Each producer to consumer pair along the pipeline.
//!
//! The producer's output is what the real handler stored (see `chain`). It is handed to the
//! consumer's own reader, and the test asserts that it parses, that every field the consumer
//! relies on is present, and that the name it was stored under is the name the consumer asks for.
//!
//! | Pair | Fidelity | Test |
//! |---|---|---|
//! | `INTAKE` to `REPOSITORY_INTELLIGENCE` | real to real | `pair_intake_to_repository_intelligence` |
//! | `REPOSITORY_INTELLIGENCE` to `ARCHITECTURE`, `TASK_PLANNING`, `IMPLEMENTATION` | real to real reader | `pair_repository_intelligence_to_its_readers` |
//! | `SPECIFICATION` to its readers | **pending**: the producer is a placeholder | `pair_specification_is_pending` |
//! | `ARCHITECTURE` to `TASK_PLANNING` | real to real | `pair_architecture_to_task_planning` |
//! | `TASK_PLANNING` to `IMPLEMENTATION` | real to real reader | `pair_task_planning_to_implementation` |
//! | `IMPLEMENTATION` to `VALIDATION` | real to real contract | `pair_implementation_to_validation` |
//! | `IMPLEMENTATION` to `REVIEW`, `DOCUMENTING`, `DOCUMENTATION_REVIEW` | real to real | `pair_implementation_to_the_stages_that_read_its_commits` |
//! | `VALIDATION` to `REVIEW` | serializer to real reader | `pair_validation_to_review` |
//! | `VALIDATION` to `DELIVERY`, `APPROVAL` | serializer to real | `pair_validation_to_delivery_and_approval` |
//! | `REVIEW` to `DELIVERY` | real to real reader | `pair_review_to_delivery` |
//! | `DOCUMENTING` to `DOCUMENTATION_REVIEW` | real to real | `pair_documenting_to_documentation_review` |
//! | `DOCUMENTATION_REVIEW` to `DELIVERY` | real to real | `pair_documentation_review_to_delivery` |
//! | `DOCUMENTATION_REVIEW` to `APPROVAL` | real to real | `pair_documentation_review_to_approval` |
//! | `DELIVERY` to `APPROVAL` | real to real | `pair_delivery_to_approval` |
//! | `APPROVAL` to the approval service | real to reader | `pair_approval_to_the_approval_service` |
//!
//! "Serializer" means the stage that stores the document is a stand-in on the rig, and it writes
//! the document with the producing stage's own function (`validation::evidence_document`).

use factory_domain::contracts::{Contract, ReviewVerdict, SpecificationContract, TaskDag};
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{GateOutcome, StageKind, Verdict};
use factory_workflow::gates::docs::plan::DocPlan;
use factory_workflow::gates::framework::Resolution;
use factory_workflow::stages::approval::ApprovalRequest;
use factory_workflow::stages::architecture::design::Design;
use factory_workflow::stages::delivery::documentation_gate::{DocumentationGate, Expected};
use factory_workflow::stages::delivery::input as delivery_input;
use factory_workflow::stages::implementation::input as implementation_input;
use factory_workflow::stages::implementation::plan as implementation_plan;
use factory_workflow::stages::repo_intel::map as repository_map;
use factory_workflow::stages::review::evidence::Evidence;
use factory_workflow::stages::validation::Binding;

use crate::chain::{Intake, Pipeline, Planned, Universe};
use crate::deliver::{Delivery, Ran, validation_handler};

const SPECIFICATION_EXAMPLE: &str = include_str!(
    "../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
);

fn text(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("a stored document is UTF-8")
}

/// The sha256 a consumer's contract pins for the input `name`.
fn pinned(universe: &Universe, consumer: StageKind, name: &str) -> Sha256Digest {
    universe
        .contract_of(consumer)
        .inputs
        .iter()
        .find(|input| input.name.as_str() == name)
        .unwrap_or_else(|| panic!("the contract of {consumer} has no input {name}"))
        .artifact
        .sha256
        .clone()
}

/// The job through delivery and approval, both run for real.
pub struct Whole {
    pub pipeline: Pipeline,
    pub delivered: Ran,
    pub approved: Ran,
}

impl Whole {
    pub async fn run() -> Self {
        let pipeline = Pipeline::documented().await;
        let (delivered, approved) = {
            let delivery = Delivery::over(&pipeline).await;
            let handler = delivery.delivery_handler();
            let upstream = delivery.upstream_of_delivery();
            let delivered = delivery
                .run(&handler, StageKind::Delivery, &upstream)
                .await
                .expect("the delivery stage accepts what the real stages stored");
            let upstream = delivery.upstream_of_approval(&delivered);
            let approved = delivery
                .run(&delivery.approval_handler(), StageKind::Approval, &upstream)
                .await
                .expect("the approval stage accepts what the real stages stored");
            (delivered, approved)
        };
        Self {
            pipeline,
            delivered,
            approved,
        }
    }
}

// ---- intake, repository intelligence, specification --------------------------------------------

#[tokio::test]
async fn pair_intake_to_repository_intelligence() {
    let job = Intake::run().await;
    let request = job.real(StageKind::Intake, "normalized-request");
    // The repository stage reads the request by its hash and by no field of it, so what the pair
    // guarantees is that the contract it was run under pins the document intake stored.
    assert_eq!(
        pinned(
            &job,
            StageKind::RepositoryIntelligence,
            "normalized-request"
        ),
        request.artifact.sha256
    );
    // The stage after intake only runs when intake passed, so the engine let it start.
    assert!(
        job.all()
            .iter()
            .any(|output| output.kind == StageKind::RepositoryIntelligence)
    );
    // The document is the one the intake stage writes, with the request it came from.
    let document = request.json();
    assert!(document.is_object(), "{document}");
}

#[tokio::test]
async fn pair_repository_intelligence_to_its_readers() {
    let job = Intake::run().await;
    let map = job.real(StageKind::RepositoryIntelligence, "repository-map");
    let document = map.json();
    // The producer's own validator accepts the producer's own output.
    repository_map::validate(&document).expect("the map follows its schema");
    // Architecture, task planning and implementation all read the commit the map was read at.
    let commit = implementation_input::map_commit(&map.bytes).expect("the map names its commit");
    assert_eq!(document["commit_sha"], commit.as_str());
    // The name is the one the three readers ask for.
    assert_eq!(map.name, implementation_input::REPOSITORY_MAP);
}

#[test]
fn pair_specification_is_pending() {
    // No producer exists, so the pair is not run. What can be checked is that the readers accept a
    // document that follows the contract of the specification, under the name they all ask for.
    let specification =
        SpecificationContract::from_json_str(SPECIFICATION_EXAMPLE).expect("a valid specification");
    assert!(specification.metadata.spec_version.get() >= 1);
    assert!(
        crate::registry::PENDING
            .iter()
            .any(|(stage, name)| *stage == StageKind::Specification
                && *name == implementation_input::SPECIFICATION_CONTRACT)
    );
}

// ---- architecture, task planning ---------------------------------------------------------------

#[tokio::test]
async fn pair_architecture_to_task_planning() {
    let job = Planned::run().await;
    let design = job.real(StageKind::Architecture, implementation_input::ARCHITECTURE);
    // The planning stage reads the design with the architecture stage's own reader.
    let read = Design::read(&design.json()).expect("the design follows the shape the reader wants");
    assert!(!read.elements.is_empty(), "the design has elements");
    assert_eq!(
        pinned(
            &job,
            StageKind::TaskPlanning,
            implementation_input::ARCHITECTURE
        ),
        design.artifact.sha256
    );
}

#[tokio::test]
async fn pair_task_planning_to_implementation() {
    let job = Planned::run().await;
    let stored = job.real(StageKind::TaskPlanning, implementation_input::TASK_PLAN);
    // The implementation stage reads the plan with its own reader and orders it.
    let plan = implementation_plan::read(&stored.bytes).expect("the plan is a task graph");
    let order = implementation_plan::order(&plan).expect("the plan has an order");
    assert!(!order.is_empty());
    // The delivery stage reads the same bytes as a task graph.
    TaskDag::from_json_str(text(&stored.bytes)).expect("the delivery stage reads the plan");
}

// ---- implementation ----------------------------------------------------------------------------

#[tokio::test]
async fn pair_implementation_to_validation() {
    let pipeline = Pipeline::documented().await;
    let result = pipeline.real(StageKind::Implementation, "implementation-result");
    // The validation stage reads the base and the head from the document, and nothing else.
    let document = result.json();
    for field in ["base_commit", "head_commit"] {
        assert!(document[field].is_string(), "{field} in {document}");
    }
    // The real validation handler resolves its contract on the real result and pins its hash.
    let delivery = Delivery::over(&pipeline).await;
    let contract = delivery
        .contract(
            &validation_handler(),
            StageKind::Validation,
            &pipeline.upstream(),
        )
        .expect("the validation stage finds what the implementation stage stored");
    let input = contract
        .inputs
        .iter()
        .find(|input| input.name.as_str() == "implementation-result")
        .expect("the result is an input");
    assert_eq!(input.artifact.sha256, result.artifact.sha256);
}

#[tokio::test]
async fn pair_implementation_to_the_stages_that_read_its_commits() {
    let pipeline = Pipeline::documented().await;
    let result = pipeline.real(StageKind::Implementation, "implementation-result");
    // The readers of the commits that exist in this crate give the same answer.
    let by_implementation =
        implementation_input::parse_candidate(&result.bytes).expect("the implementation reader");
    let by_delivery = delivery_input::parse_candidate(&result.bytes).expect("the delivery reader");
    assert_eq!(by_implementation.base.as_str(), by_delivery.base.as_str());
    assert_eq!(by_implementation.head.as_str(), by_delivery.head.as_str());
    assert_ne!(by_implementation.base, by_implementation.head);
    // Review, documenting and documentation review ran for real on it, under contracts that pin it.
    for consumer in [
        StageKind::Review,
        StageKind::Documenting,
        StageKind::DocumentationReview,
    ] {
        assert_eq!(
            pinned(&pipeline, consumer, "implementation-result"),
            result.artifact.sha256,
            "{consumer}"
        );
    }
}

// ---- validation, review ------------------------------------------------------------------------

#[tokio::test]
async fn pair_validation_to_review() {
    let pipeline = Pipeline::documented().await;
    // The stand-in for the validation stage writes the evidence with the stage's own function.
    let evidence = pipeline.find(StageKind::Validation, "validation-evidence");
    let read = Evidence::read(&evidence.bytes).expect("the review stage reads the evidence");
    let candidate = implementation_input::parse_candidate(
        &pipeline
            .real(StageKind::Implementation, "implementation-result")
            .bytes,
    )
    .expect("a candidate");
    let result = &pipeline
        .real(StageKind::Implementation, "implementation-result")
        .artifact
        .sha256;
    let policy = read.binding.policy_hash.clone();
    assert!(
        read.unbound(&candidate, result, &policy).is_empty(),
        "the evidence is bound to the commits the implementation stage made"
    );
    // The real review stage ran on it and stored a verdict instead of a refusal to run.
    assert!(
        pipeline
            .names_of(StageKind::Review)
            .contains("review-verdict")
    );
}

#[tokio::test]
async fn pair_validation_to_delivery_and_approval() {
    let whole = Whole::run().await;
    let evidence = whole
        .pipeline
        .find(StageKind::Validation, "validation-evidence")
        .json();
    // Delivery and approval read the binding and the reports of the same document.
    let binding = Binding::from_json(&evidence["binding"]).expect("a binding");
    let reports = evidence["reports"].as_array().expect("a list of reports");
    assert!(!reports.is_empty());
    // The approval request carries the binding the person is shown, read from that document.
    let request = ApprovalRequest::from_json(&whole.approved.find("approval-request").json())
        .expect("a request");
    assert_eq!(request.evidence_binding, binding);
    assert!(request.gates_clear);
}

#[tokio::test]
async fn pair_review_to_delivery() {
    let pipeline = Pipeline::documented().await;
    let verdict = pipeline.real(StageKind::Review, "review-verdict");
    // The delivery stage reads the verdict as the contract and checks it.
    let read = ReviewVerdict::from_json_str(text(&verdict.bytes)).expect("a review verdict");
    read.validate().expect("a valid verdict");
    assert_eq!(read.verdict, Verdict::Pass);
    // The delivery stage names the verdict by the name the review stage stores it under.
    assert_eq!(verdict.name, delivery_input::REVIEW_VERDICT);
}

// ---- documentation -----------------------------------------------------------------------------

#[tokio::test]
async fn pair_documenting_to_documentation_review() {
    let pipeline = Pipeline::documented().await;
    let plan = pipeline.real(StageKind::Documenting, "documentation-plan");
    let result = pipeline.real(StageKind::Documenting, "documentation-result");
    let gate = pipeline
        .real(StageKind::DocumentationReview, "documentation-gate-report")
        .json();
    // The documentation review stage reads the plan with the plan's own reader.
    DocPlan::from_json(&plan.json()).expect("the plan follows its schema");
    // It reads the commit the documents were committed at, and the code head they were written for.
    let result_document = result.json();
    for field in ["base_commit", "code_head", "head_commit"] {
        assert!(result_document[field].is_string(), "{field}");
    }
    // The reports are about exactly that, and about exactly this plan.
    assert_eq!(
        gate["binding"]["documentation_head"],
        result_document["head_commit"]
    );
    assert_eq!(gate["binding"]["code_head"], result_document["code_head"]);
    assert_eq!(
        gate["binding"]["base_commit"],
        result_document["base_commit"]
    );
    assert_eq!(
        gate["binding"]["plan_sha256"],
        plan.artifact.sha256.as_str()
    );
    assert_eq!(
        pinned(
            &pipeline,
            StageKind::DocumentationReview,
            "documentation-plan"
        ),
        plan.artifact.sha256
    );
    assert_eq!(
        pinned(
            &pipeline,
            StageKind::DocumentationReview,
            "documentation-result"
        ),
        result.artifact.sha256
    );
}

#[tokio::test]
async fn pair_documentation_review_to_delivery() {
    let pipeline = Pipeline::documented().await;
    let delivery = Delivery::over(&pipeline).await;
    let handler = delivery.delivery_handler();
    let upstream = delivery.upstream_of_delivery();
    let contract = delivery
        .contract(&handler, StageKind::Delivery, &upstream)
        .expect("the delivery stage finds what every stage before it stored");
    // The delivery stage's own reader of every input, on what the real stages stored.
    let dossier = delivery_input::read(&*pipeline.rig.artifacts, &pipeline.scope(), &contract)
        .await
        .expect("the delivery stage reads the whole dossier");
    let gate = pipeline.real(StageKind::DocumentationReview, "documentation-gate-report");
    let review = pipeline.real(StageKind::DocumentationReview, "documentation-review");
    assert_eq!(dossier.documentation_gate_sha256, gate.artifact.sha256);
    assert_eq!(dossier.documentation_review_sha256, review.artifact.sha256);
    // The documentation head is the commit the documenting stage made.
    let result = pipeline
        .real(StageKind::Documenting, "documentation-result")
        .json();
    assert_eq!(dossier.pushed_head.as_str(), result["head_commit"]);
    assert_ne!(dossier.pushed_head, dossier.candidate.head);
}

#[tokio::test]
async fn pair_documentation_review_to_approval() {
    let whole = Whole::run().await;
    let pipeline = &whole.pipeline;
    let gate = pipeline.real(StageKind::DocumentationReview, "documentation-gate-report");
    // The approval stage reads the document with the reader it shares with delivery.
    let read = DocumentationGate::from_bytes(&gate.bytes)
        .expect("the approval stage reads the document the documentation review stage stores");
    assert!(read.reports.len() > 1, "a list of reports, not one");
    // And compares what the reports are bound to with the delivery it holds.
    let delivered = whole.delivered.find("delivery-result").json();
    let commit = |key: &str| {
        factory_ports::paths::CommitSha::parse(delivered[key].as_str().expect(key)).expect(key)
    };
    let (base, code_head, pushed) = (
        commit("base_commit"),
        commit("code_head"),
        commit("head_commit"),
    );
    let plan = &pipeline
        .real(StageKind::Documenting, "documentation-plan")
        .artifact
        .sha256;
    read.check(&Expected {
        base_commit: &base,
        code_head: &code_head,
        documentation_head: &pushed,
        plan_sha256: plan,
    })
    .expect("the reports were made for the commits and the plan that were delivered");
}

// ---- delivery, approval ------------------------------------------------------------------------

#[tokio::test]
async fn pair_delivery_to_approval() {
    let whole = Whole::run().await;
    assert_eq!(whole.delivered.resolution, Resolution::Pass);
    assert_eq!(whole.approved.resolution, Resolution::HumanGate);
    // Every gate of the delivery passed on the real documents, and the approval stage is a human
    // gate with one passing report of its own.
    assert_eq!(whole.delivered.decision.reports.len(), 3);
    for report in &whole.delivered.decision.reports {
        assert_eq!(
            report.outcome,
            GateOutcome::Passed,
            "{}",
            report.metadata.gate_id
        );
    }
    assert!(whole.approved.decision.human_gate);
    let result = whole.delivered.find("delivery-result").json();
    // Every field the approval stage relies on is in the delivery result, with the type it reads.
    for field in [
        "repository",
        "head_branch",
        "base_branch",
        "base_commit",
        "head_commit",
        "code_head",
        "tree",
        "manifest_sha256",
    ] {
        assert!(result[field].is_string(), "{field} in {result}");
    }
    assert_eq!(result["delivered"], true);
    assert!(result["pull_request"].is_u64());
    assert!(result["spec_version"].is_u64());
    // The approval request shows the person what was delivered.
    let request = ApprovalRequest::from_json(&whole.approved.find("approval-request").json())
        .expect("a request");
    assert_eq!(request.pr_head.as_str(), result["head_commit"]);
    assert_eq!(request.base.as_str(), result["base_commit"]);
    assert_eq!(request.tree.as_str(), result["tree"]);
    assert_eq!(request.manifest.as_str(), result["manifest_sha256"]);
    assert_eq!(request.pull_request, result["pull_request"]);
    // The hash the person is shown for the manifest is the hash of the manifest document the
    // approval contract pins, so the two cannot name different manifests.
    let manifest = whole.delivered.find("evidence-manifest");
    assert_eq!(manifest.artifact.sha256.as_str(), result["manifest_sha256"]);
}

#[tokio::test]
async fn pair_approval_to_the_approval_service() {
    let whole = Whole::run().await;
    let stored = whole.approved.find("approval-request");
    // The service reads the stored request with `ApprovalRequest::from_json`, in the composition
    // root. A request that does not read back is one no person can approve.
    let request = ApprovalRequest::from_json(&stored.json()).expect("the request reads back");
    assert_eq!(request.to_json(), stored.json());
    assert!(request.gates_clear);
}

/// The contract of every real stage pins, for every input from an earlier stage, the bytes that
/// stage stored. A name that matched while the bytes did not would be a stage reading a stale
/// document.
#[tokio::test]
async fn contracts_pin_what_the_producers_stored() {
    let pipeline = Pipeline::documented().await;
    let intake = Intake::run().await;
    let planned = Planned::run().await;
    for universe in [&*pipeline, &intake, &planned] {
        let runs = universe.upstream();
        for &consumer in &universe.real {
            for input in universe.contract_of(consumer).inputs.iter() {
                let Some(run) = input.provenance.produced_by_stage_run_id else {
                    continue;
                };
                let producer = runs
                    .iter()
                    .find(|candidate| candidate.id == run)
                    .map(|found| found.kind)
                    .expect("the producing run is in the job");
                let stored = universe.find(producer, input.name.as_str());
                assert_eq!(
                    input.artifact.sha256, stored.artifact.sha256,
                    "{consumer} pins {} of {producer}",
                    input.name
                );
            }
        }
    }
}
