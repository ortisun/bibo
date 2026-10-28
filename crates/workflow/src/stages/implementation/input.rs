//! What the implementation and review stages take from the stage runs before them, by the name of
//! the deliverable.
//!
//! The names of the deliverables of other stages are the interface between the packages. The
//! validation stage already fixes two of them (`implementation-result` and
//! `specification-contract`). The others are the names the stage contracts of the earlier
//! stages use, and a package that names its deliverable differently changes one constant here.

use factory_domain::contracts::{ArtifactRef, StageContract};
use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::StageKind;
use factory_ports::paths::CommitSha;

use crate::handlers::UpstreamRun;

// The implementation result is read by one function for every stage that takes it (validation,
// delivery and the stages that follow implementation), so the commits a stage verifies, delivers
// and documents cannot come from three readers that drift apart.
pub use crate::stages::validation::{
    Candidate, IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, parse_candidate,
};

/// The validated task plan (`task-dag`), written by the task planning stage.
pub const TASK_PLAN: &str = "task-plan";
/// The approved architecture document, written by the architecture stage.
pub const ARCHITECTURE: &str = "architecture-design";
/// The repository map, written by the repository stage. Its `commit_sha` is the base commit.
pub const REPOSITORY_MAP: &str = "repository-map";
/// The evidence of the validation stage: the gate reports and the binding.
pub const VALIDATION_EVIDENCE: &str = "validation-evidence";

/// The newest passed run of `kind` that produced a deliverable called `name`.
#[must_use]
pub fn upstream_output<'a>(
    upstream: &'a [UpstreamRun],
    kind: StageKind,
    name: &str,
) -> Option<(&'a UpstreamRun, &'a ArtifactRef)> {
    upstream
        .iter()
        .rev()
        .filter(|run| run.kind == kind && run.status == StageRunStatus::Passed)
        .find_map(|run| {
            run.outputs
                .iter()
                .find(|output| output.name.as_str() == name)
                .map(|output| (run, &output.artifact))
        })
}

/// The artifact the contract recorded as the input called `name`.
#[must_use]
pub fn input_artifact(contract: &StageContract, name: &str) -> Option<ArtifactRef> {
    contract
        .inputs
        .iter()
        .find(|input| input.name.as_str() == name)
        .map(|input| input.artifact.clone())
}

/// The commit the repository map was read at: the base of the job.
#[must_use]
pub fn map_commit(bytes: &[u8]) -> Option<CommitSha> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    CommitSha::parse(value.get("commit_sha")?.as_str()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C-d: validation, delivery and implementation read the implementation result with one
    /// function and one type. The binding below does not compile when the implementation stage
    /// has a candidate of its own, and the refusals are the validation stage's own test.
    #[test]
    fn the_candidate_is_the_one_the_validation_stage_reads() {
        let good = format!(
            r#"{{"base_commit":"{}","head_commit":"{}"}}"#,
            "a".repeat(40),
            "b".repeat(40)
        );
        let candidate: crate::stages::validation::Candidate =
            parse_candidate(good.as_bytes()).expect("a candidate");
        assert_eq!(candidate.head.as_str(), "b".repeat(40));
        for bad in ["{}", r#"{"base_commit":"zz","head_commit":"zz"}"#, "no"] {
            assert_eq!(parse_candidate(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn the_base_of_the_job_is_the_commit_of_the_map() {
        let map = format!(r#"{{"commit_sha":"{}"}}"#, "c".repeat(40));
        assert_eq!(
            map_commit(map.as_bytes()).map(|c| c.as_str().to_owned()),
            Some("c".repeat(40))
        );
        assert_eq!(map_commit(b"{}"), None);
    }
}
