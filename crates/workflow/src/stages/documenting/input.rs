//! The names of the deliverables the documentation stages read and write.
//!
//! The delivery stage reads `documentation-plan`, `documentation-gate-report` and
//! `documentation-review` by these exact names (`stages::delivery::input`). A package that names
//! them differently changes one constant there.

pub use crate::stages::implementation::input::{
    Candidate, IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, input_artifact, parse_candidate,
    upstream_output,
};

/// The plan the `DOCUMENTING` stage derives. Read by the delivery stage.
pub const DOCUMENTATION_PLAN: &str = "documentation-plan";
/// What the `DOCUMENTING` stage did: the commits, the changed paths, the cited claims.
pub const DOCUMENTATION_RESULT: &str = "documentation-result";
/// The reports of the Documentation Quality Gate. Written by the `DOCUMENTATION_REVIEW` stage and
/// read by the delivery stage.
pub const DOCUMENTATION_GATE_REPORT: &str = "documentation-gate-report";
/// The independent documentation reviewer's verdict. Read by the delivery stage.
pub const DOCUMENTATION_REVIEW: &str = "documentation-review";
/// What the reviewer was given and what it returned.
pub const DOCUMENTATION_REVIEW_RECORD: &str = "documentation-review-record";
/// The domain profile written by the domain discovery stage. The documenting stage reads it when
/// it exists.
pub const DOMAIN_PROFILE: &str = "domain-profile";

/// The model whose documentation the `DOCUMENTATION_REVIEW` stage judges, as the router names it:
/// the writer of the newest passed `DOCUMENTING` run among `upstream`, read from the
/// `documentation-result` that run stored. `None` when there is no such run, the document cannot
/// be read, or the writer did not run (nothing needed writing). The reviewing stage is then routed
/// as if its author were unknown, and the order of the routes alone keeps the reviewer apart.
pub async fn writer_selection(
    artifacts: &dyn factory_ports::artifact::ArtifactStore,
    tenant: &factory_domain::scope::TenantScope,
    upstream: &[crate::handlers::UpstreamRun],
) -> Option<factory_ports::agent::ModelSelection> {
    let (_, stored) = upstream_output(
        upstream,
        factory_domain::vocabulary::StageKind::Documenting,
        DOCUMENTATION_RESULT,
    )?;
    let bytes = artifacts.get(tenant, stored).await.ok()?;
    let (runtime, model) = writer_model_of(&bytes)?;
    Some(factory_ports::agent::ModelSelection {
        runtime: factory_ports::agent::RuntimeId::new(&runtime).ok()?,
        model: factory_domain::values::NonEmptyString::parse(&model).ok()?,
    })
}

/// The runtime and the model that wrote the documentation, read from a stored
/// `documentation-result`. `None` when the document is not one, or names no writer model.
#[must_use]
pub fn writer_model_of(bytes: &[u8]) -> Option<(String, String)> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value.get("kind")?.as_str()? != DOCUMENTATION_RESULT {
        return None;
    }
    let found = value.get("writer_model")?;
    Some((
        found.get("runtime")?.as_str()?.to_owned(),
        found.get("model")?.as_str()?.to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_writer_model_is_read_from_a_documentation_result() {
        let stored = serde_json::json!({
            "kind": DOCUMENTATION_RESULT,
            "writer_model": { "runtime": "claude-code-cli", "model": "claude-sonnet-5-5" },
        });
        let bytes = serde_json::to_vec(&stored).expect("json");
        assert_eq!(
            writer_model_of(&bytes),
            Some(("claude-code-cli".to_owned(), "claude-sonnet-5-5".to_owned()))
        );
    }

    #[test]
    fn a_result_with_no_writer_or_of_another_kind_names_no_model() {
        let skipped = serde_json::json!({ "kind": DOCUMENTATION_RESULT, "writer_model": null });
        assert_eq!(
            writer_model_of(&serde_json::to_vec(&skipped).expect("json")),
            None
        );
        let other = serde_json::json!({
            "kind": "implementation-evidence",
            "writer_model": { "runtime": "claude-code-cli", "model": "claude-sonnet-5-5" },
        });
        assert_eq!(
            writer_model_of(&serde_json::to_vec(&other).expect("json")),
            None
        );
    }
}
