//! What an assertion is, what it returns, and what it needs besides the evidence.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use factory_workflow::gates::readability::Catalog;
use serde_json::Value;

use crate::evidence::RunEvidence;

/// The answer of one assertion: pass or fail, and the reason in a sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The assertion id, such as `A1`.
    pub id: String,
    /// Whether the assertion holds.
    pub pass: bool,
    /// Why. A passing verdict says what was seen, a failing one says what is wrong.
    pub reason: String,
}

impl Verdict {
    /// A passing verdict.
    pub fn pass(id: &str, reason: impl Into<String>) -> Self {
        Self {
            id: id.to_owned(),
            pass: true,
            reason: reason.into(),
        }
    }

    /// A failing verdict.
    pub fn fail(id: &str, reason: impl Into<String>) -> Self {
        Self {
            id: id.to_owned(),
            pass: false,
            reason: reason.into(),
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = if self.pass { "PASS" } else { "FAIL" };
        write!(f, "{word} {}: {}", self.id, self.reason)
    }
}

/// One machine-checkable assertion: a pure function from the evidence of a run to a verdict.
#[derive(Clone, Copy)]
pub struct Check {
    /// The id: `A1` to `A14`, or a scenario check such as `E3.rework-cap`.
    pub id: &'static str,
    /// What it asserts, in one sentence.
    pub title: &'static str,
    /// The function.
    pub run: fn(&RunEvidence, &Env) -> Verdict,
}

impl fmt::Debug for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Check({})", self.id)
    }
}

impl Check {
    /// Runs the check.
    #[must_use]
    pub fn apply(&self, evidence: &RunEvidence, env: &Env) -> Verdict {
        (self.run)(evidence, env)
    }
}

/// One stage of the pipeline, as `docs/architecture/state-machine.json` lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageSpec {
    /// The stage kind, such as `REVIEW`.
    pub kind: String,
    /// The stage kinds whose passed run must exist before this one can start.
    pub requires: Vec<String>,
}

/// What the assertions need besides the evidence.
#[derive(Clone)]
pub struct Env {
    /// The stages of Slice 1, in pipeline order. Read from the state machine file, never counted
    /// in code (ADR 0014).
    pub stages: Vec<StageSpec>,
    /// The readability catalog that the gate uses.
    pub catalog: Arc<Catalog>,
    /// Whether `policies/approval.yaml` switches the solo mode on (`solo_mode.enabled`, ADR 0021):
    /// the owner who works alone approves their own request, and the engine checks the conditions
    /// of the mode, its wait and its phrase at each decision.
    pub solo_mode: bool,
}

impl fmt::Debug for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Env")
            .field("stages", &self.stages.len())
            .finish_non_exhaustive()
    }
}

impl Env {
    /// Loads the environment from the repository that holds `docs/architecture/state-machine.json`.
    ///
    /// # Errors
    /// A sentence saying what could not be read.
    pub fn load(repository_root: &Path) -> Result<Self, String> {
        let path = repository_root.join("docs/architecture/state-machine.json");
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        let stages = stages_in_slice(&text, 1)?;
        let catalog = Catalog::embedded()
            .map_err(|error| format!("the readability catalog did not load: {error:?}"))?;
        Ok(Self {
            stages,
            catalog,
            solo_mode: crate::prerequisites::solo_mode_enabled(repository_root),
        })
    }

    /// The spec of one stage.
    #[must_use]
    pub fn stage(&self, kind: &str) -> Option<&StageSpec> {
        self.stages.iter().find(|stage| stage.kind == kind)
    }
}

/// The stages of the pipeline whose `slice` is `slice` or earlier, in pipeline order.
///
/// # Errors
/// A sentence saying what is wrong with the document.
pub fn stages_in_slice(state_machine_json: &str, slice: u64) -> Result<Vec<StageSpec>, String> {
    let document: Value = serde_json::from_str(state_machine_json)
        .map_err(|error| format!("the state machine file is not JSON: {error}"))?;
    let list = document["pipeline"]["stages"]
        .as_array()
        .ok_or("the state machine file has no pipeline.stages list")?;
    let mut stages = Vec::new();
    for entry in list {
        let kind = entry["kind"]
            .as_str()
            .ok_or("a pipeline stage has no kind")?;
        let stage_slice = entry["slice"]
            .as_u64()
            .ok_or("a pipeline stage has no slice")?;
        if stage_slice > slice {
            continue;
        }
        let requires = entry["requires"]
            .as_array()
            .ok_or("a pipeline stage has no requires list")?
            .iter()
            .filter_map(|value| value.as_str().map(str::to_owned))
            .collect();
        stages.push(StageSpec {
            kind: kind.to_owned(),
            requires,
        });
    }
    if stages.is_empty() {
        return Err("the state machine file lists no stage for this slice".to_owned());
    }
    Ok(stages)
}
