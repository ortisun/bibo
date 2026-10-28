//! The real stages, run through the real engine, and everything they stored, by stage and by the
//! name they stored it under.
//!
//! Three jobs are run, each with the rig of the stage tests that owns the stages it needs:
//!
//! | Job | Real stages | Stand-ins around them |
//! |---|---|---|
//! | [`Pipeline::documented`] | `IMPLEMENTATION`, `REVIEW`, `DOCUMENTING`, `DOCUMENTATION_REVIEW` | the stages before, and `VALIDATION` (which writes through the validation stage's own function) |
//! | [`Intake::run`] | `INTAKE`, `REPOSITORY_INTELLIGENCE` | none before them |
//! | [`Planned::run`] | `ARCHITECTURE`, `TASK_PLANNING` | the stages before them |
//!
//! A stand-in stores a document its author chose. A test that read one as if a real stage had
//! written it would prove nothing, so [`Universe::real`] is the only way to ask for a producer's
//! output, and it refuses a stage that is a stand-in in that job.

use std::collections::BTreeSet;

use factory_domain::contracts::{ArtifactRef, Contract, StageContract};
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::values::{MediaType, Slug};
use factory_domain::vocabulary::StageKind;
use factory_ports::artifact::ArtifactStore;
use factory_ports::store::ArtifactDirection;
use factory_testkit::agent::AdversarialScript;
use factory_workflow::engine::AttemptOutcome;
use factory_workflow::handlers::{NamedArtifact, UpstreamRun};
use serde_json::{Value, json};

use crate::rig::{Options, Rig, documented_scope, write};
use crate::support::world::World;

const README: &str = "# Word count\n\nWord count prints the number of lines, words and characters of a text file.\n\n## Usage\n\nRun the tool with a file name. Add `--json` to print the counts as JSON.\n\n```console\n$ word-count --json notes.txt\n{\"lines\":1,\"words\":2,\"characters\":9}\n```\n\nThe [changelog](CHANGELOG.md#unreleased) lists what changed.\n";
const CHANGELOG: &str =
    "# Changelog\n\n## Unreleased\n\n- Added the `--json` flag, which prints the counts as JSON.\n";

/// One deliverable as a stage run stored it.
#[derive(Debug, Clone)]
pub struct Output {
    /// The stage run that stored it.
    pub run: StageRunId,
    /// The stage.
    pub kind: StageKind,
    /// The name it was stored under: the name the stages after it must read it by.
    pub name: String,
    /// Where it is in the artifact store.
    pub artifact: ArtifactRef,
    /// The stored bytes.
    pub bytes: Vec<u8>,
}

impl Output {
    /// The stored document.
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes)
            .unwrap_or_else(|e| panic!("{} of {} is not JSON: {e}", self.name, self.kind))
    }
}

/// A stage run's contract, as the engine resolved and stored it.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub kind: StageKind,
    pub contract: StageContract,
}

/// What one job stored.
#[derive(Debug, Clone)]
pub struct Universe {
    /// The stages that are the real handlers in this job.
    pub real: Vec<StageKind>,
    outputs: Vec<Output>,
    contracts: Vec<Resolved>,
}

impl Universe {
    /// Every deliverable of the job.
    pub fn all(&self) -> &[Output] {
        &self.outputs
    }

    /// The deliverable `name` of a **real** stage. A stage that is a stand-in in this job has no
    /// producer here, and asking for its output is a mistake of the test.
    pub fn real(&self, kind: StageKind, name: &str) -> &Output {
        assert!(
            self.real.contains(&kind),
            "{kind} is a stand-in in this job, so {name} has no real producer here"
        );
        self.find(kind, name)
    }

    /// The deliverable `name` of a stage, real or not.
    pub fn find(&self, kind: StageKind, name: &str) -> &Output {
        self.outputs
            .iter()
            .find(|output| output.kind == kind && output.name == name)
            .unwrap_or_else(|| {
                panic!(
                    "{kind} did not store {name}; it stored {:?}",
                    self.names_of(kind)
                )
            })
    }

    /// The names a stage stored.
    pub fn names_of(&self, kind: StageKind) -> BTreeSet<String> {
        self.outputs
            .iter()
            .filter(|output| output.kind == kind)
            .map(|output| output.name.clone())
            .collect()
    }

    /// The contract the engine resolved for the newest passed run of a stage.
    pub fn contract_of(&self, kind: StageKind) -> &StageContract {
        &self
            .contracts
            .iter()
            .rev()
            .find(|resolved| resolved.kind == kind)
            .unwrap_or_else(|| panic!("{kind} has no resolved contract in this job"))
            .contract
    }

    /// The stage runs as a later stage sees them: passed, with what each stored.
    pub fn upstream(&self) -> Vec<UpstreamRun> {
        let mut runs: Vec<UpstreamRun> = Vec::new();
        for output in &self.outputs {
            let named = NamedArtifact {
                name: Slug::parse(&output.name).expect("a stored name is a slug"),
                artifact: output.artifact.clone(),
            };
            match runs.iter_mut().find(|run| run.id == output.run) {
                Some(run) => run.outputs.push(named),
                None => runs.push(UpstreamRun {
                    id: output.run,
                    kind: output.kind,
                    status: StageRunStatus::Passed,
                    outputs: vec![named],
                }),
            }
        }
        runs
    }
}

/// What every passed stage run of a job stored, by the name it stored it under, and the contract
/// each was resolved with.
async fn collect(
    world: &World,
    tenant: TenantId,
    job: JobId,
    store: &dyn ArtifactStore,
    real: &[StageKind],
) -> Universe {
    let scope = TenantScope::new(tenant);
    let json_type = MediaType::parse("application/json").expect("a media type");
    let view = world.view(job).await;
    let mut outputs = Vec::new();
    let mut contracts = Vec::new();
    for run in &view.stage_runs {
        if run.status != StageRunStatus::Passed {
            continue;
        }
        let row = world.stage_run(run.id).await;
        if let Some(sha256) = row.contract_sha256 {
            let reference = ArtifactRef {
                sha256,
                media_type: json_type.clone(),
                size_bytes: None,
            };
            let bytes = store
                .get(&scope, &reference)
                .await
                .unwrap_or_else(|e| panic!("the contract of {} is not stored: {e:?}", run.kind));
            let contract =
                StageContract::from_json_str(std::str::from_utf8(&bytes).expect("UTF-8"))
                    .unwrap_or_else(|e| {
                        panic!("the stored contract of {} is invalid: {e}", run.kind)
                    });
            contracts.push(Resolved {
                kind: run.kind,
                contract,
            });
        }
        for link in world.links(run.id).await {
            if link.direction != ArtifactDirection::Output {
                continue;
            }
            // The engine stores a link under the role `<name>.a<attempt>`.
            let Some((name, _)) = link.role.as_str().rsplit_once(".a") else {
                continue;
            };
            let artifact = ArtifactRef {
                sha256: link.sha256.clone(),
                media_type: json_type.clone(),
                size_bytes: None,
            };
            let bytes = store
                .get(&scope, &artifact)
                .await
                .unwrap_or_else(|e| panic!("{name} of {} is not readable: {e:?}", run.kind));
            outputs.push(Output {
                run: run.id,
                kind: run.kind,
                name: name.to_owned(),
                artifact,
                bytes,
            });
        }
    }
    Universe {
        real: real.to_vec(),
        outputs,
        contracts,
    }
}

// ---- the job through the documentation stages --------------------------------------------------

/// The job, run through the documentation review stage.
pub struct Pipeline {
    pub rig: Rig,
    universe: Universe,
}

impl std::ops::Deref for Pipeline {
    type Target = Universe;
    fn deref(&self) -> &Universe {
        &self.universe
    }
}

fn writer_done() -> Value {
    json!({
        "schema_version": 1,
        "status": "DONE",
        "summary": "The README and the changelog now describe the new flag, with a runnable example.",
        "files_written": ["README.md", "CHANGELOG.md"],
        "plan_coverage": [
            { "plan_item": "usage", "status": "covered", "files": ["README.md"] },
            { "plan_item": "changelog-entry", "status": "covered", "files": ["CHANGELOG.md"] }
        ],
        "claims": [{ "claim": "The flag prints the counts as JSON.", "evidence_path": "src/main.rs" }],
        "ignored_instructions": []
    })
}

fn code_review_passes() -> Value {
    json!({
        "schema_version": 1,
        "verdict": "PASS",
        "title": "Code review",
        "summary": "The change does what the specification asks and its tests cover it.",
        "findings": [],
        "confidence_overall": 0.9,
        "residual_risks": [],
        "ignored_instructions": []
    })
}

fn reviewer_passes() -> Value {
    json!({
        "schema_version": 1,
        "verdict": "PASS",
        "title": "Documentation review",
        "summary": "The documents match the change and the gate reports show no failure.",
        "findings": [],
        "confidence_overall": 0.9,
        "residual_risks": [],
        "ignored_instructions": []
    })
}

/// Claims the next stage run of a rig, checks which stage it is, and runs it to success.
async fn run(rig: &Rig, kind: StageKind) {
    let (claimed, outcome) = rig.run_next().await;
    assert_eq!(claimed.kind, kind);
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{kind}");
}

impl Pipeline {
    /// Runs the job from the intake stand-in to the documentation review stage, with every real
    /// stage passing.
    pub async fn documented() -> Self {
        let rig = Rig::build(Options {
            scope: documented_scope(),
            // The real review handler, not the stand-in.
            review: true,
            ..Options::default()
        })
        .await;
        rig.run_until_implementation().await;
        rig.builder_does_the_plan();
        for kind in [StageKind::Implementation, StageKind::Validation] {
            run(&rig, kind).await;
        }
        rig.runtime
            .inner
            .queue(AdversarialScript::returning(code_review_passes()));
        run(&rig, StageKind::Review).await;
        rig.runtime.edits(
            "documentation-writer",
            vec![write("README.md", README), write("CHANGELOG.md", CHANGELOG)],
        );
        rig.runtime
            .inner
            .queue(AdversarialScript::returning(writer_done()));
        run(&rig, StageKind::Documenting).await;
        rig.runtime
            .inner
            .queue(AdversarialScript::returning(reviewer_passes()));
        run(&rig, StageKind::DocumentationReview).await;
        let universe = collect(
            &rig.world,
            rig.world.tenant,
            rig.job,
            &*rig.artifacts,
            &[
                StageKind::Implementation,
                StageKind::Review,
                StageKind::Documenting,
                StageKind::DocumentationReview,
            ],
        )
        .await;
        Self { rig, universe }
    }

    /// The scope of the tenant, for reading the store.
    pub fn scope(&self) -> TenantScope {
        TenantScope::new(self.rig.world.tenant)
    }
}

// ---- the job through intake and repository intelligence ----------------------------------------

/// The job through the two first stages, both real.
pub struct Intake;

impl Intake {
    pub async fn run() -> Universe {
        use crate::harness::{Options, Rig, USUAL_REQUEST, usual};
        let rig = Rig::build(Options {
            real_repo: true,
            ..Options::default()
        })
        .await;
        let job = rig.job(USUAL_REQUEST).await;
        rig.classifier_returns(usual());
        for kind in [StageKind::Intake, StageKind::RepositoryIntelligence] {
            let (claimed, outcome) = rig.run_next().await;
            assert_eq!(claimed.kind, kind);
            assert_eq!(outcome, AttemptOutcome::Succeeded, "{kind}");
        }
        collect(
            &rig.world,
            rig.world.tenant,
            job,
            &*rig.world.artifacts,
            &[StageKind::Intake, StageKind::RepositoryIntelligence],
        )
        .await
    }
}

// ---- the job through architecture and task planning --------------------------------------------

/// The job through the architecture and the task planning stage, both real.
pub struct Planned;

impl Planned {
    pub async fn run() -> Universe {
        use crate::planning_rig::{Options, Rig, design};
        let rig = Rig::build(Options::default()).await;
        rig.run_until_architecture().await;
        rig.architecture_passes(design()).await;
        rig.planner_plans(|_| {});
        let (claimed, outcome) = rig.run_next().await;
        assert_eq!(claimed.kind, StageKind::TaskPlanning);
        assert_eq!(outcome, AttemptOutcome::Succeeded);
        collect(
            &rig.world,
            rig.world.tenant,
            rig.job,
            &*rig.artifacts,
            &[StageKind::Architecture, StageKind::TaskPlanning],
        )
        .await
    }
}
