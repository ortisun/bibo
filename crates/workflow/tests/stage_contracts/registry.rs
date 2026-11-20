//! The deliverable registry: who produces each deliverable and who reads it, derived from the
//! stage contracts the real handlers resolve, and checked against the pipeline order of
//! `docs/architecture/state-machine.json`.
//!
//! Nothing here is a hand-written list of what a stage produces or reads. A producer's
//! deliverables are the ones its **own contract declares** (the engine refuses a document the
//! contract does not declare). A consumer's reads are the inputs **its own contract resolves**,
//! each pinned to the stage run that produced it. The lists below are the exceptions the contracts
//! cannot show, and each entry says why.

use std::collections::{BTreeMap, BTreeSet};

use factory_domain::contracts::StageContract;
use factory_domain::contracts::stage_contract::InputSource;
use factory_domain::ids::StageRunId;
use factory_domain::vocabulary::StageKind;
use factory_workflow::handlers::UpstreamRun;
use factory_workflow::stages::{architecture, documenting, implementation};
use serde_json::Value;

use crate::chain::{Intake, Pipeline, Planned, Specified};
use crate::deliver::{Delivery, validation_handler};

/// Stages whose module is a placeholder in this checkout, with the deliverable the stages after
/// them read by name. The producer cannot be run, so the pair is **pending**: the expected name is
/// taken from the constants of the consumers, and `the_pending_producers_are_still_placeholders`
/// fails the day a producer exists and this list is not emptied. The specification stage was in
/// this list until its package was merged; it is run for real in `chain::Specified`.
pub const PENDING: [(StageKind, &str); 1] =
    [(StageKind::DomainDiscovery, documenting::DOMAIN_PROFILE)];

/// The document of the design gate of intake (`factory_workflow::stages::intake::design::ARTIFACT`).
const DESIGN_GATE_DOCUMENT: &str = factory_workflow::stages::intake::design::ARTIFACT;

/// Deliverables that are stored and never read by a stage of this crate. Each is a record for a
/// person or for the audit, or is read outside this crate.
pub const TERMINAL: [(StageKind, &str, &str); 12] = [
    (
        StageKind::Specification,
        "specification-evidence",
        "read by the stage's own gates, which judge what the host measured",
    ),
    (
        StageKind::Intake,
        "intake-decision",
        "the engine and the person read the decision",
    ),
    (
        StageKind::Intake,
        "original-request",
        "kept as the text the requester wrote",
    ),
    (
        StageKind::Intake,
        DESIGN_GATE_DOCUMENT,
        "the gate of the stage reads it back, and the person reads what the design gate found",
    ),
    (
        StageKind::RepositoryIntelligence,
        "context-summary",
        "a summary for a person",
    ),
    (
        StageKind::Architecture,
        "architecture-record",
        "the record of how the design was checked",
    ),
    (
        StageKind::Architecture,
        "adr-drafts",
        "drafts for the architect to propose",
    ),
    (
        StageKind::TaskPlanning,
        "plan-traceability",
        "the matrix a person reads",
    ),
    (
        StageKind::TaskPlanning,
        "plan-record",
        "the record of how the plan was checked",
    ),
    (
        StageKind::Review,
        "review-record",
        "what the reviewer was given",
    ),
    (
        StageKind::DocumentationReview,
        "documentation-review-record",
        "what the reviewer was given",
    ),
    (
        StageKind::Approval,
        "approval-request",
        "read by the approval service through ApprovalSources::request, in the composition root",
    ),
];

/// Reads that are not inputs of a contract: a stage that finds a document in the upstream runs
/// to **withhold its hash** from a prompt, so that what a writer said about its own work never
/// reaches its independent reviewer. A name that drifted would turn the guard off silently.
pub const OTHER_READS: [(StageKind, &str, StageKind); 1] = [(
    StageKind::Review,
    implementation::EVIDENCE,
    StageKind::Implementation,
)];

/// Optional deliverables that a later stage requires. Each producer's gate fails when the
/// deliverable is absent, so a passed run always has it.
pub const OPTIONAL_BUT_GATED: [(StageKind, &str); 4] = [
    (
        StageKind::Specification,
        implementation::input::SPECIFICATION_CONTRACT,
    ),
    (StageKind::TaskPlanning, implementation::input::TASK_PLAN),
    (StageKind::Review, "review-verdict"),
    (StageKind::DocumentationReview, "documentation-review"),
];

/// What one stage declares and reads.
#[derive(Debug, Clone)]
pub struct Row {
    pub kind: StageKind,
    /// Deliverable name to whether it is required.
    pub produces: BTreeMap<String, bool>,
    /// The names of the documents of earlier stages it reads, with the stage that stored each.
    pub reads: Vec<(String, StageKind)>,
}

fn row(kind: StageKind, contract: &StageContract, upstream: &[UpstreamRun]) -> Row {
    let runs: BTreeMap<StageRunId, StageKind> =
        upstream.iter().map(|run| (run.id, run.kind)).collect();
    let produces = contract
        .deliverables
        .iter()
        .map(|d| (d.name.as_str().to_owned(), d.required))
        .collect();
    let reads = contract
        .inputs
        .iter()
        .filter(|input| input.provenance.source == InputSource::PreviousStage)
        .map(|input| {
            let run = input
                .provenance
                .produced_by_stage_run_id
                .expect("an input from a previous stage names the run that stored it");
            let producer = runs
                .get(&run)
                .copied()
                .unwrap_or_else(|| panic!("{kind} reads {} from an unknown run", input.name));
            (input.name.as_str().to_owned(), producer)
        })
        .collect();
    Row {
        kind,
        produces,
        reads,
    }
}

/// The registry, from the real contracts of the three jobs and the contracts of the validation,
/// delivery and approval handlers resolved on the real documentation job.
pub async fn rows() -> Vec<Row> {
    let docs = Pipeline::documented().await;
    let intake = Intake::run().await;
    let planned = Planned::run().await;
    let specified = Specified::run().await.universe;
    let mut rows = Vec::new();
    for universe in [&*docs, &intake, &specified, &planned] {
        let upstream = universe.upstream();
        for &kind in &universe.real {
            rows.push(row(kind, universe.contract_of(kind), &upstream));
        }
    }

    // The validation, delivery and approval stages are resolved on the real job: their handlers
    // are the real ones, and what they read is what the real stages stored.
    let delivery = Delivery::over(&docs).await;
    let upstream = delivery.upstream_of_delivery();
    let contract = delivery
        .contract(&validation_handler(), StageKind::Validation, &upstream)
        .expect("the validation contract resolves on the real job");
    rows.push(row(StageKind::Validation, &contract, &upstream));

    let handler = delivery.delivery_handler();
    let contract = delivery
        .contract(&handler, StageKind::Delivery, &upstream)
        .expect("the delivery contract resolves on the real job");
    rows.push(row(StageKind::Delivery, &contract, &upstream));
    let delivered = delivery
        .run(&handler, StageKind::Delivery, &upstream)
        .await
        .expect("the delivery runs on the real job");

    let upstream = delivery.upstream_of_approval(&delivered);
    let contract = delivery
        .contract(&delivery.approval_handler(), StageKind::Approval, &upstream)
        .expect("the approval contract resolves on the real job");
    rows.push(row(StageKind::Approval, &contract, &upstream));
    rows
}

/// The stage kinds in the order of the pipeline, and what each requires, from the state machine.
pub fn pipeline() -> (Vec<StageKind>, BTreeMap<StageKind, Vec<StageKind>>) {
    let document: Value = serde_json::from_str(include_str!(
        "../../../../docs/architecture/state-machine.json"
    ))
    .expect("the state machine is JSON");
    let mut order = Vec::new();
    let mut requires = BTreeMap::new();
    for stage in document["pipeline"]["stages"].as_array().expect("stages") {
        let kind = StageKind::parse(stage["kind"].as_str().expect("a kind")).expect("a stage kind");
        let needs: Vec<StageKind> = stage["requires"]
            .as_array()
            .expect("requires")
            .iter()
            .map(|k| StageKind::parse(k.as_str().expect("a kind")).expect("a stage kind"))
            .collect();
        order.push(kind);
        requires.insert(kind, needs);
    }
    (order, requires)
}

/// Every stage that must have passed before `kind` can run: what it requires, and what those
/// require, and so on.
fn before(kind: StageKind, requires: &BTreeMap<StageKind, Vec<StageKind>>) -> BTreeSet<StageKind> {
    let mut found = BTreeSet::new();
    let mut open = vec![kind];
    while let Some(next) = open.pop() {
        for &needed in requires.get(&next).into_iter().flatten() {
            if found.insert(needed) {
                open.push(needed);
            }
        }
    }
    found
}

/// What `rows` found, as problems in words. Empty when the registry holds.
pub fn problems_of(rows: &[Row], pending: &[(StageKind, &str)]) -> Vec<String> {
    let (order, requires) = pipeline();
    let index = |kind: StageKind| {
        order
            .iter()
            .position(|k| *k == kind)
            .expect("in the pipeline")
    };
    let mut problems: Vec<String> = Vec::new();

    // The producers: the real ones declare, the pending ones are expected.
    let mut producers: BTreeMap<String, BTreeSet<StageKind>> = BTreeMap::new();
    for row in rows {
        for name in row.produces.keys() {
            producers.entry(name.clone()).or_default().insert(row.kind);
        }
    }
    for (kind, name) in pending {
        producers
            .entry((*name).to_owned())
            .or_default()
            .insert(*kind);
    }
    for (name, kinds) in &producers {
        if kinds.len() != 1 {
            problems.push(format!(
                "{name} is produced by more than one stage: {kinds:?}"
            ));
        }
    }

    for row in rows {
        let earlier = before(row.kind, &requires);
        for (name, stored_by) in &row.reads {
            match producers.get(name) {
                None => problems.push(format!(
                    "{} reads {name}, which no stage declares",
                    row.kind
                )),
                Some(kinds) if !kinds.contains(stored_by) => problems.push(format!(
                    "{} reads {name} from {stored_by}, but {kinds:?} declares it",
                    row.kind
                )),
                Some(_) => {}
            }
            if index(*stored_by) >= index(row.kind) {
                problems.push(format!(
                    "{} reads {name} from {stored_by}, which does not run before it",
                    row.kind
                ));
            }
            if !earlier.contains(stored_by) {
                problems.push(format!(
                    "{} reads {name} from {stored_by}, which it does not (transitively) require",
                    row.kind
                ));
            }
        }
    }
    for (reader, name, producer) in OTHER_READS {
        let declared = rows
            .iter()
            .find(|row| row.kind == producer)
            .is_some_and(|row| row.produces.contains_key(name));
        if !declared {
            problems.push(format!(
                "{reader} reads {name}, which {producer} does not declare"
            ));
        }
        if index(producer) >= index(reader) {
            problems.push(format!(
                "{reader} reads {name} from {producer}, which does not run before it"
            ));
        }
    }
    problems
}

/// Every deliverable that a stage reads is produced by exactly one stage, and that stage runs
/// before the reader in the pipeline order of the state machine.
#[tokio::test]
async fn every_deliverable_that_a_stage_reads_is_produced_by_one_earlier_stage() {
    let rows = rows().await;
    let problems = problems_of(&rows, &PENDING);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// An optional deliverable that a later stage requires is listed, with the reason it is safe.
#[tokio::test]
async fn an_optional_deliverable_that_a_later_stage_requires_is_listed() {
    let rows = rows().await;
    let mut unlisted = Vec::new();
    for row in &rows {
        for (name, stored_by) in &row.reads {
            let optional = rows
                .iter()
                .find(|producer| producer.kind == *stored_by)
                .and_then(|producer| producer.produces.get(name))
                .is_some_and(|required| !required);
            if optional && !OPTIONAL_BUT_GATED.contains(&(*stored_by, name.as_str())) {
                unlisted.push(format!("{name} of {stored_by}, read by {}", row.kind));
            }
        }
    }
    assert!(unlisted.is_empty(), "{unlisted:#?}");
}

/// A deliverable that is produced and never read is listed as terminal, and nothing is listed
/// that is read.
#[tokio::test]
async fn every_deliverable_nobody_reads_is_listed_as_terminal() {
    let rows = rows().await;
    let read: BTreeSet<(StageKind, String)> = rows
        .iter()
        .flat_map(|row| row.reads.iter().map(|(name, kind)| (*kind, name.clone())))
        .chain(
            OTHER_READS
                .iter()
                .map(|(_, name, producer)| (*producer, (*name).to_owned())),
        )
        .collect();
    let unread: BTreeSet<(StageKind, String)> = rows
        .iter()
        .flat_map(|row| row.produces.keys().map(|name| (row.kind, name.clone())))
        .filter(|produced| !read.contains(produced))
        .collect();
    let listed: BTreeSet<(StageKind, String)> = TERMINAL
        .iter()
        .map(|(kind, name, _)| (*kind, (*name).to_owned()))
        .collect();
    assert_eq!(
        unread, listed,
        "left: produced and never read; right: the terminal list"
    );
}

/// The domain discovery stage is no longer a placeholder: in Slice 1 it is a recorded skip
/// (`DomainDiscoveryHandler`), so it stores no `domain-profile` and the pair stays **expected and
/// never produced**. The readers (documenting and architecture) read the profile only when it
/// exists, which `pair_domain_discovery_is_pending` records and the worker's `domain_discovery`
/// test shows through a real engine (the stage is `SKIPPED`, the stages after it go on). The day a
/// real discovery stage stores the profile, this fails: empty `PENDING`, run the stage in `chain`,
/// and cover its pairs in `pairs`.
#[test]
fn the_domain_discovery_stage_is_a_recorded_skip_and_still_stores_no_profile() {
    const PLACEHOLDER: &str =
        "Placeholder so that the module line declared by the engine package compiles.";
    let source = include_str!("../../src/stages/domain_discovery/mod.rs");
    assert!(
        !source.contains(PLACEHOLDER),
        "the DOMAIN_DISCOVERY module is real now"
    );
    assert!(
        source.contains("Applicability::NotApplicable")
            && source.contains("SkipBasis::DomainProfile"),
        "the Slice 1 stage records a skip with the basis DomainProfile"
    );
    assert!(
        !source.contains("StageOutput {"),
        "the stage stores nothing; if it does, run it in `chain`, empty PENDING, and cover its pairs"
    );
    assert_eq!(PENDING, [(StageKind::DomainDiscovery, "domain-profile")]);
}

#[test]
fn the_specification_stage_is_real_and_is_not_pending() {
    const PLACEHOLDER: &str =
        "Placeholder so that the module line declared by the engine package compiles.";
    assert!(!include_str!("../../src/stages/specification/mod.rs").contains(PLACEHOLDER));
    assert!(
        !PENDING
            .iter()
            .any(|(stage, _)| *stage == StageKind::Specification)
    );
}

#[test]
fn the_names_a_pending_producer_is_expected_to_store_agree_across_the_consumers() {
    assert_eq!(
        implementation::input::SPECIFICATION_CONTRACT,
        "specification-contract"
    );
    assert_eq!(
        documenting::DOMAIN_PROFILE,
        architecture::handler::DOMAIN_PROFILE
    );
}
