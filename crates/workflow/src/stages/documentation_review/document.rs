//! The document the `DOCUMENTATION_REVIEW` stage stores as `documentation-gate-report`.
//!
//! The stage stores one document that holds every report of the Documentation Quality Gate, not a
//! single gate report. The document says which commits and which plan the reports are about, so
//! that a stage that reads it later can tell a report that was made for other commits from one
//! that was made for these. [`gate_document`] is the one function that writes it; `execute` calls
//! it and the stages that read the document are tested against what it returns.

use factory_domain::values::Sha256Digest;
use factory_ports::paths::CommitSha;
use serde_json::{Value, json};

use crate::stages::documenting::input::DOCUMENTATION_GATE_REPORT;

/// What the reports are about: the commits and the documents they were made over.
#[derive(Debug, Clone, Copy)]
pub struct GateBinding<'a> {
    /// The protected branch tip the change is relative to.
    pub base_commit: &'a CommitSha,
    /// The code head: the commit the gates of the validation stage ran on.
    pub code_head: &'a CommitSha,
    /// The documentation commit: the commit the checks read the pages at.
    pub documentation_head: &'a CommitSha,
    /// The hash of the documentation plan the checks compared the pages with.
    pub plan_sha256: &'a Sha256Digest,
    /// The hash of the frozen specification.
    pub specification_sha256: &'a Sha256Digest,
}

/// The document as it is stored: the binding, the sandbox the checks ran in, how many external
/// links were not checked, and every report.
#[must_use]
pub fn gate_document(
    binding: &GateBinding<'_>,
    sandbox_id: Option<&str>,
    external_links_not_checked: usize,
    reports: &[Value],
) -> Value {
    json!({
        "schema_version": 1,
        "kind": DOCUMENTATION_GATE_REPORT,
        "binding": {
            "base_commit": binding.base_commit.as_str(),
            "code_head": binding.code_head.as_str(),
            "documentation_head": binding.documentation_head.as_str(),
            "plan_sha256": binding.plan_sha256,
            "specification_sha256": binding.specification_sha256,
        },
        "sandbox_id": sandbox_id,
        "external_links_not_checked": external_links_not_checked,
        "reports": reports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commit(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).expect("a commit")
    }

    #[test]
    fn the_document_names_its_commits_its_plan_and_its_reports() {
        let (base, code, docs) = (commit('a'), commit('b'), commit('c'));
        let (plan, spec) = (Sha256Digest::of(b"plan"), Sha256Digest::of(b"spec"));
        let document = gate_document(
            &GateBinding {
                base_commit: &base,
                code_head: &code,
                documentation_head: &docs,
                plan_sha256: &plan,
                specification_sha256: &spec,
            },
            Some("sandbox-1"),
            2,
            &[json!({ "outcome": "PASSED" })],
        );
        assert_eq!(document["kind"], "documentation-gate-report");
        assert_eq!(document["schema_version"], 1);
        assert_eq!(document["binding"]["base_commit"], base.as_str());
        assert_eq!(document["binding"]["code_head"], code.as_str());
        assert_eq!(document["binding"]["documentation_head"], docs.as_str());
        assert_eq!(document["binding"]["plan_sha256"], plan.to_string());
        assert_eq!(
            document["binding"]["specification_sha256"],
            spec.to_string()
        );
        assert_eq!(document["sandbox_id"], "sandbox-1");
        assert_eq!(document["external_links_not_checked"], 2);
        assert_eq!(document["reports"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn a_stage_that_ran_no_sandbox_stores_null() {
        let sha = commit('a');
        let digest = Sha256Digest::of(b"x");
        let document = gate_document(
            &GateBinding {
                base_commit: &sha,
                code_head: &sha,
                documentation_head: &sha,
                plan_sha256: &digest,
                specification_sha256: &digest,
            },
            None,
            0,
            &[],
        );
        assert!(document["sandbox_id"].is_null());
    }
}
