//! The documentation gate report, read by the stages after `DOCUMENTATION_REVIEW`.
//!
//! The `DOCUMENTATION_REVIEW` stage stores `documentation-gate-report` as one document: a
//! binding that names the commits and the plan, and the typed reports of every gate of the
//! Documentation Quality Gate (`documentation_review::gate_document` writes it). It is not a
//! single gate report. The delivery and the approval stage read it here, so that the two read
//! the same document in the same way.
//!
//! # A report made for other documents is refused
//!
//! The stages read this document by the hash their contract pinned, and a hash only says that the
//! bytes are the ones that were stored. It does not say that the reports were made for the commits
//! and the plan that are being delivered. [`DocumentationGate::check`] compares the binding of the
//! document with the commits and the plan hash the reader holds. A difference is a report made for
//! something else, and it does not count.

use factory_domain::contracts::{Contract, GateReport, ReviewVerdict};
use factory_domain::ids::GateReportId;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::Verdict;
use factory_ports::paths::CommitSha;
use serde_json::Value;

use super::input::DOCUMENTATION_GATE;

/// The only version of the document that is read.
pub const SCHEMA_VERSION: u64 = 1;

/// Why the document could not be used. The set is closed and carries no document text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GateProblem {
    /// The bytes are not the document the documentation review stage stores: a field is missing, a
    /// commit or a hash is malformed, or a report is not a valid gate report.
    #[error("the documentation gate report is not the document the documentation review stores")]
    Invalid,
    /// The document is well formed and was made for other commits or another plan than the ones it
    /// is read against. The names are the fields of the binding that differ.
    #[error("the documentation gate report was made for other commits or another plan")]
    Stale(Vec<&'static str>),
}

/// Why the documentation reviewer's verdict could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReviewProblem {
    /// The bytes are not a valid review verdict.
    #[error("the documentation review is not a valid review verdict")]
    Invalid,
    /// The verdict is not `PASS`. Delivery follows work that passed.
    #[error("the documentation review is not a pass")]
    NotPass,
    /// The verdict was made over other reports or another specification than the ones that are
    /// delivered. The names say which.
    #[error("the documentation review was made over other reports or another specification")]
    Stale(Vec<&'static str>),
}

/// What the reports in the document are about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateBinding {
    /// The protected branch tip the change is relative to.
    pub base_commit: CommitSha,
    /// The commit the gates of the validation stage ran on.
    pub code_head: CommitSha,
    /// The documentation commit, the one that is pushed.
    pub documentation_head: CommitSha,
    /// The hash of the documentation plan the checks compared the pages with.
    pub plan_sha256: Sha256Digest,
    /// The hash of the frozen specification.
    pub specification_sha256: Sha256Digest,
}

/// What the reader holds, to compare the binding with.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The base commit of the delivery.
    pub base_commit: &'a CommitSha,
    /// The code head: the commit the evidence binding names.
    pub code_head: &'a CommitSha,
    /// The commit that is pushed and shown to the person.
    pub documentation_head: &'a CommitSha,
    /// The hash of the documentation plan the contract pinned.
    pub plan_sha256: &'a Sha256Digest,
}

/// The document, parsed.
#[derive(Debug, Clone)]
pub struct DocumentationGate {
    /// What the reports are about.
    pub binding: GateBinding,
    /// One typed report for each gate.
    pub reports: Vec<GateReport>,
    /// The identifier and the hash of each report as it is stored, in the order of `reports`. The
    /// reviewer's verdict names the reports it read by these.
    pub stored: Vec<(GateReportId, Sha256Digest)>,
}

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

impl GateBinding {
    fn from_json(value: &Value) -> Option<Self> {
        let commit = |key: &str| CommitSha::parse(text(value, key)?).ok();
        let digest = |key: &str| Sha256Digest::parse(text(value, key)?).ok();
        Some(Self {
            base_commit: commit("base_commit")?,
            code_head: commit("code_head")?,
            documentation_head: commit("documentation_head")?,
            plan_sha256: digest("plan_sha256")?,
            specification_sha256: digest("specification_sha256")?,
        })
    }

    /// The names of the fields of the binding that differ from what the reader holds.
    #[must_use]
    pub fn differences(&self, expected: &Expected<'_>) -> Vec<&'static str> {
        let mut differing = Vec::new();
        if &self.base_commit != expected.base_commit {
            differing.push("base_commit");
        }
        if &self.code_head != expected.code_head {
            differing.push("code_head");
        }
        if &self.documentation_head != expected.documentation_head {
            differing.push("documentation_head");
        }
        if &self.plan_sha256 != expected.plan_sha256 {
            differing.push("plan_sha256");
        }
        differing
    }
}

impl DocumentationGate {
    /// Reads the document.
    ///
    /// # Errors
    /// [`GateProblem::Invalid`] for anything that is not the document the documentation review
    /// stage stores.
    pub fn from_json(value: &Value) -> Result<Self, GateProblem> {
        if text(value, "kind") != Some(DOCUMENTATION_GATE)
            || value.get("schema_version").and_then(Value::as_u64) != Some(SCHEMA_VERSION)
        {
            return Err(GateProblem::Invalid);
        }
        let binding = value
            .get("binding")
            .and_then(GateBinding::from_json)
            .ok_or(GateProblem::Invalid)?;
        let items = value
            .get("reports")
            .and_then(Value::as_array)
            .ok_or(GateProblem::Invalid)?;
        let reports = items
            .iter()
            .map(|item| GateReport::from_json_value(item.clone()).map_err(|_| GateProblem::Invalid))
            .collect::<Result<Vec<_>, _>>()?;
        if reports.is_empty() {
            return Err(GateProblem::Invalid);
        }
        let stored = reports
            .iter()
            .zip(items)
            .map(|(report, item)| {
                (
                    report.metadata.gate_report_id,
                    Sha256Digest::of(&serde_json::to_vec(item).unwrap_or_default()),
                )
            })
            .collect();
        Ok(Self {
            binding,
            reports,
            stored,
        })
    }

    /// Checks the reviewer's verdict against this document.
    ///
    /// The verdict must be `PASS`, must name exactly the reports of this document (by identifier
    /// and by the hash of the stored report), and must have read the specification the reader
    /// holds. A `PASS` over other reports is a verdict about something else: the reports are bound
    /// to the commits and the plan by [`check`](Self::check), and the verdict is bound to the
    /// reports here.
    ///
    /// # Errors
    /// [`ReviewProblem::NotPass`] for any other verdict, [`ReviewProblem::Stale`] for a verdict
    /// made over other reports or another specification.
    pub fn check_review(
        &self,
        review: &ReviewVerdict,
        specification_sha256: &Sha256Digest,
    ) -> Result<(), ReviewProblem> {
        if review.verdict != Verdict::Pass {
            return Err(ReviewProblem::NotPass);
        }
        let mut differing = Vec::new();
        let mut named: Vec<(GateReportId, Sha256Digest)> = review
            .inputs_reviewed
            .gate_reports
            .iter()
            .map(|reference| (reference.gate_report_id, reference.sha256.clone()))
            .collect();
        let mut held = self.stored.clone();
        named.sort_by_key(|(id, _)| id.to_string());
        held.sort_by_key(|(id, _)| id.to_string());
        if named != held {
            differing.push("gate_reports");
        }
        if review.inputs_reviewed.frozen_spec_sha256 != *specification_sha256 {
            differing.push("frozen_spec_sha256");
        }
        if differing.is_empty() {
            Ok(())
        } else {
            Err(ReviewProblem::Stale(differing))
        }
    }

    /// Reads the document from the bytes that were stored.
    ///
    /// # Errors
    /// [`GateProblem::Invalid`], as [`from_json`](Self::from_json), and for bytes that are not JSON.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GateProblem> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| GateProblem::Invalid)?;
        Self::from_json(&value)
    }

    /// Checks that the reports were made for the commits and the plan the reader holds.
    ///
    /// # Errors
    /// [`GateProblem::Stale`] with the names of the fields that differ.
    pub fn check(&self, expected: &Expected<'_>) -> Result<(), GateProblem> {
        let differing = self.binding.differences(expected);
        if differing.is_empty() {
            Ok(())
        } else {
            Err(GateProblem::Stale(differing))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sha(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).expect("a commit")
    }

    fn binding() -> GateBinding {
        GateBinding {
            base_commit: sha('a'),
            code_head: sha('b'),
            documentation_head: sha('c'),
            plan_sha256: Sha256Digest::of(b"plan"),
            specification_sha256: Sha256Digest::of(b"spec"),
        }
    }

    #[test]
    fn a_binding_that_equals_what_the_reader_holds_has_no_difference() {
        let held = binding();
        let (a, b, c) = (sha('a'), sha('b'), sha('c'));
        let plan = Sha256Digest::of(b"plan");
        let expected = Expected {
            base_commit: &a,
            code_head: &b,
            documentation_head: &c,
            plan_sha256: &plan,
        };
        assert!(held.differences(&expected).is_empty());
    }

    #[test]
    fn each_field_of_the_binding_is_compared_on_its_own() {
        let held = binding();
        let (a, b, c, d) = (sha('a'), sha('b'), sha('c'), sha('d'));
        let plan = Sha256Digest::of(b"plan");
        let other = Sha256Digest::of(b"another plan");
        let with = |base: &CommitSha, code: &CommitSha, docs: &CommitSha, plan: &Sha256Digest| {
            held.differences(&Expected {
                base_commit: base,
                code_head: code,
                documentation_head: docs,
                plan_sha256: plan,
            })
        };
        assert_eq!(with(&d, &b, &c, &plan), ["base_commit"]);
        assert_eq!(with(&a, &d, &c, &plan), ["code_head"]);
        assert_eq!(with(&a, &b, &d, &plan), ["documentation_head"]);
        assert_eq!(with(&a, &b, &c, &other), ["plan_sha256"]);
        assert_eq!(
            with(&d, &d, &d, &other),
            [
                "base_commit",
                "code_head",
                "documentation_head",
                "plan_sha256"
            ]
        );
    }

    #[test]
    fn a_single_gate_report_is_not_the_document() {
        // The shape the approval stage used to read: a gate report on its own.
        let value = json!({ "metadata": { "gate_id": "readability-gate" }, "outcome": "PASSED" });
        assert_eq!(
            DocumentationGate::from_json(&value).unwrap_err(),
            GateProblem::Invalid
        );
    }

    #[test]
    fn a_document_without_reports_or_with_a_broken_binding_is_invalid() {
        let good_binding = json!({
            "base_commit": "a".repeat(40),
            "code_head": "b".repeat(40),
            "documentation_head": "c".repeat(40),
            "plan_sha256": Sha256Digest::of(b"plan"),
            "specification_sha256": Sha256Digest::of(b"spec"),
        });
        let frame = |binding: Value, reports: Value| {
            json!({
                "schema_version": 1,
                "kind": "documentation-gate-report",
                "binding": binding,
                "reports": reports,
            })
        };
        for document in [
            frame(good_binding.clone(), json!([])),
            frame(good_binding.clone(), json!("not a list")),
            frame(good_binding.clone(), json!([{ "outcome": "PASSED" }])),
            frame(json!({ "base_commit": "a".repeat(40) }), json!([])),
            frame(
                json!({
                    "base_commit": "not a commit",
                    "code_head": "b".repeat(40),
                    "documentation_head": "c".repeat(40),
                    "plan_sha256": Sha256Digest::of(b"plan"),
                    "specification_sha256": Sha256Digest::of(b"spec"),
                }),
                json!([]),
            ),
        ] {
            assert_eq!(
                DocumentationGate::from_json(&document).unwrap_err(),
                GateProblem::Invalid,
                "{document}"
            );
        }
    }

    #[test]
    fn a_document_of_another_kind_or_version_is_invalid() {
        for (kind, version) in [
            ("documentation-result", 1),
            ("documentation-gate-report", 2),
        ] {
            let value =
                json!({ "schema_version": version, "kind": kind, "binding": {}, "reports": [] });
            assert_eq!(
                DocumentationGate::from_json(&value).unwrap_err(),
                GateProblem::Invalid
            );
        }
    }

    #[test]
    fn bytes_that_are_not_json_are_invalid() {
        assert_eq!(
            DocumentationGate::from_bytes(b"{").unwrap_err(),
            GateProblem::Invalid
        );
    }
}
