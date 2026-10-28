//! The evidence of the validation stage, as the review stage reads it.
//!
//! The validation stage writes one document, `validation-evidence`: the gate reports it made and a
//! binding that says what they are about (the implementation result, the two commits, the policy,
//! the image and the gate definitions). The review stage reads that document by the hash its
//! contract pinned, parses each report through the `gate-report` contract, and compares the binding
//! with values it has from other places: the implementation result it read, and its own contract.
//!
//! A report is evidence only for the commit it ran on. A binding that names another commit, another
//! implementation result or another policy means the reports are about something that is not the
//! change under review, and the reviewer is not given them as if they were.

use factory_domain::contracts::{Contract, GateReport};
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::GateOutcome;
use serde_json::Value;

use crate::stages::implementation::input::Candidate;
use crate::stages::validation::Binding;

/// Why the evidence cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceProblem {
    /// The bytes are not the document the validation stage writes.
    #[error("the validation evidence is not the document the validation stage writes")]
    NotEvidence,
    /// The document holds no gate report.
    #[error("the validation evidence holds no gate report")]
    NoReports,
}

/// The evidence, parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct Evidence {
    /// What the reports are about, as the validation stage wrote it.
    pub binding: Binding,
    /// Each report, typed, with the value it was read from.
    pub reports: Vec<(GateReport, Value)>,
}

impl Evidence {
    /// Reads the document.
    ///
    /// # Errors
    /// [`EvidenceProblem`].
    pub fn read(bytes: &[u8]) -> Result<Self, EvidenceProblem> {
        let document: Value =
            serde_json::from_slice(bytes).map_err(|_| EvidenceProblem::NotEvidence)?;
        let binding = document
            .get("binding")
            .and_then(Binding::from_json)
            .ok_or(EvidenceProblem::NotEvidence)?;
        let mut reports = Vec::new();
        for value in document
            .get("reports")
            .and_then(Value::as_array)
            .ok_or(EvidenceProblem::NotEvidence)?
        {
            let report = GateReport::from_json_value(value.clone())
                .map_err(|_| EvidenceProblem::NotEvidence)?;
            reports.push((report, value.clone()));
        }
        if reports.is_empty() {
            return Err(EvidenceProblem::NoReports);
        }
        Ok(Self { binding, reports })
    }

    /// The names of the values the binding gets wrong. Empty when the reports are about the change
    /// under review.
    #[must_use]
    pub fn unbound(
        &self,
        candidate: &Candidate,
        result: &Sha256Digest,
        policy: &Sha256Digest,
    ) -> Vec<&'static str> {
        let mut wrong = Vec::new();
        if &self.binding.implementation_result != result {
            wrong.push("implementation_result");
        }
        if self.binding.base_commit.as_str() != candidate.base.as_str() {
            wrong.push("base_commit");
        }
        if self.binding.head_commit.as_str() != candidate.head.as_str() {
            wrong.push("head_commit");
        }
        if &self.binding.policy_hash != policy {
            wrong.push("policy_hash");
        }
        wrong
    }

    /// The failed checks of the reports that failed, as `(check id, message)`. A failed report
    /// that lists no check still counts, under the id of its gate.
    #[must_use]
    pub fn failures(&self) -> Vec<(String, String)> {
        let mut found = Vec::new();
        for (report, _) in &self.reports {
            if report.outcome != GateOutcome::Failed {
                continue;
            }
            let gate = report.metadata.gate_id.as_str();
            let listed = report.failures.as_deref().unwrap_or_default();
            if listed.is_empty() {
                found.push((
                    slug_of(gate),
                    format!("The gate {gate} failed in the validation stage."),
                ));
            }
            for failure in listed {
                found.push((
                    slug_of(&format!("{gate}.{}", failure.check_id.as_str())),
                    failure.message.as_str().to_owned(),
                ));
            }
        }
        found
    }

    /// The gates whose reports say they could not run.
    #[must_use]
    pub fn blocked(&self) -> Vec<String> {
        self.reports
            .iter()
            .filter(|(report, _)| report.outcome == GateOutcome::Blocked)
            .map(|(report, _)| report.metadata.gate_id.as_str().to_owned())
            .collect()
    }

    /// The reports as the reviewer reads them: one JSON array, in the order the validation stage
    /// wrote them.
    #[must_use]
    pub fn render(&self) -> String {
        let values: Vec<&Value> = self.reports.iter().map(|(_, value)| value).collect();
        serde_json::to_string_pretty(&values).unwrap_or_default()
    }

    /// Each report's identifier and the hash of the report as it was written.
    #[must_use]
    pub fn references(&self) -> Vec<(factory_domain::ids::GateReportId, Sha256Digest)> {
        self.reports
            .iter()
            .map(|(report, value)| {
                (
                    report.metadata.gate_report_id,
                    Sha256Digest::of(value.to_string().as_bytes()),
                )
            })
            .collect()
    }
}

/// A check identifier from text: lowercase letters, digits, dots, underscores and hyphens, at most
/// 63 characters, starting and ending with a letter or a digit.
fn slug_of(text: &str) -> String {
    let mut slug: String = text
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(63)
        .collect();
    while slug.ends_with(|c: char| !c.is_ascii_alphanumeric()) {
        slug.pop();
    }
    let slug = slug.trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
    if slug.is_empty() {
        "gate-failed".to_owned()
    } else {
        slug.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_check_identifier_is_always_a_slug() {
        for text in [
            "unit-tests.unit-test-failed",
            "Gate With Spaces.Check!",
            "---",
            "",
            &"a".repeat(200),
        ] {
            let slug = slug_of(text);
            assert!(
                factory_domain::values::Slug::parse(&slug).is_ok(),
                "{text:?} -> {slug:?}"
            );
        }
    }

    #[test]
    fn bytes_that_are_not_the_validation_document_are_not_read() {
        for bad in [&b"not json"[..], b"{}", br#"{"binding":{},"reports":[]}"#] {
            assert!(Evidence::read(bad).is_err());
        }
    }
}
