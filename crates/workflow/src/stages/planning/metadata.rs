//! The identifiers, hashes and time that the factory assigns to a plan, and the comparison with
//! what the planner wrote.
//!
//! The planner is asked to copy these values into the plan unchanged. It is not trusted to: the
//! stage keeps its own copy, made before the planner ran, and compares every field of the plan's
//! metadata with it. A plan whose metadata differs in any field is not the plan that was asked
//! for, whatever the rest of it says.

use factory_domain::contracts::task_dag::{ArchitectureRef, PlanMetadata, SpecRef};
use factory_domain::ids::{JobId, PlanId, SpecId};
use factory_domain::values::{PositiveInt, Sha256Digest, Timestamp};
use factory_domain::vocabulary::ExecutionMode;

/// The values the factory assigned to one plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected(PlanMetadata);

/// What the factory knows when it assigns the values.
#[derive(Debug, Clone)]
pub struct Assigned {
    /// The new plan.
    pub plan: PlanId,
    /// Which plan this is for the job, from 1.
    pub version: u32,
    /// The job.
    pub job: JobId,
    /// Test or production.
    pub mode: ExecutionMode,
    /// The specification the plan follows.
    pub spec: SpecId,
    /// The version of that specification.
    pub spec_version: i64,
    /// The hash of the stored specification contract.
    pub spec_sha256: Sha256Digest,
    /// The hash of the stored architecture design.
    pub architecture_sha256: Sha256Digest,
    /// When the plan was asked for.
    pub created_at: Timestamp,
}

impl Expected {
    /// The values for one plan. `None` when a version is not a positive whole number, which only
    /// a fault in the caller causes.
    #[must_use]
    pub fn assign(assigned: Assigned) -> Option<Self> {
        Some(Self(PlanMetadata {
            plan_id: assigned.plan,
            plan_version: PositiveInt::new(i64::from(assigned.version)).ok()?,
            job_id: assigned.job,
            execution_mode: assigned.mode,
            spec_ref: SpecRef {
                spec_id: assigned.spec,
                spec_version: PositiveInt::new(assigned.spec_version).ok()?,
                sha256: assigned.spec_sha256,
            },
            architecture_ref: ArchitectureRef {
                sha256: assigned.architecture_sha256,
            },
            created_at: assigned.created_at,
        }))
    }

    /// The values as the document the planner is shown and the record keeps.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.0).unwrap_or(serde_json::Value::Null)
    }

    /// Reads the values back from the record.
    #[must_use]
    pub fn from_json(value: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(value.clone()).ok().map(Self)
    }

    /// The values as text for the planner's prompt.
    #[must_use]
    pub fn render(&self) -> String {
        serde_json::to_string_pretty(&self.to_json()).unwrap_or_default()
    }

    /// The version of the plan.
    #[must_use]
    pub fn version(&self) -> i64 {
        self.0.plan_version.get()
    }

    /// The fields of the plan's metadata that differ from the assigned values, by name.
    #[must_use]
    pub fn mismatches(&self, actual: &PlanMetadata) -> Vec<&'static str> {
        let expected = &self.0;
        let mut found = Vec::new();
        let mut check = |name: &'static str, same: bool| {
            if !same {
                found.push(name);
            }
        };
        check("plan_id", expected.plan_id == actual.plan_id);
        check("plan_version", expected.plan_version == actual.plan_version);
        check("job_id", expected.job_id == actual.job_id);
        check(
            "execution_mode",
            expected.execution_mode == actual.execution_mode,
        );
        check(
            "spec_ref.spec_id",
            expected.spec_ref.spec_id == actual.spec_ref.spec_id,
        );
        check(
            "spec_ref.spec_version",
            expected.spec_ref.spec_version == actual.spec_ref.spec_version,
        );
        check(
            "spec_ref.sha256",
            expected.spec_ref.sha256 == actual.spec_ref.sha256,
        );
        check(
            "architecture_ref.sha256",
            expected.architecture_ref.sha256 == actual.architecture_ref.sha256,
        );
        check("created_at", expected.created_at == actual.created_at);
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::contracts::{Contract, TaskDag};

    const PLAN: &str =
        include_str!("../../../../../schemas/examples/task-dag/valid/json-output-flag-plan.json");

    fn matching() -> (Expected, TaskDag) {
        let plan = TaskDag::from_json_str(PLAN).expect("a plan");
        let expected = Expected::from_json(&serde_json::to_value(&plan.metadata).expect("JSON"))
            .expect("the metadata of the example");
        (expected, plan)
    }

    #[test]
    fn a_plan_that_copied_the_values_has_no_mismatch() {
        let (expected, plan) = matching();
        assert!(expected.mismatches(&plan.metadata).is_empty());
        assert_eq!(expected.version(), 1);
        assert!(expected.render().contains("plan_id"));
    }

    #[test]
    fn every_field_that_differs_is_named() {
        let (expected, mut plan) = matching();
        plan.metadata.plan_version = PositiveInt::new(7).expect("positive");
        plan.metadata.spec_ref.sha256 = Sha256Digest::of(b"another specification");
        plan.metadata.execution_mode = ExecutionMode::Test;
        let found = expected.mismatches(&plan.metadata);
        assert!(found.contains(&"plan_version"));
        assert!(found.contains(&"spec_ref.sha256"));
        assert!(found.contains(&"execution_mode"));
        assert!(!found.contains(&"job_id"));
    }
}
