//! From what the reviewer returned to the verdict the factory stores.
//!
//! The reviewer returns a `review-findings` document: a verdict, a title, a summary, the findings
//! and its overall confidence. It does not say what it was shown, who it is, when it ran or which
//! gate reports it read. The factory adds those fields itself (`inputs_reviewed`, `metadata`),
//! so a reviewer cannot claim to have seen less or more than it was given, and cannot set the
//! flag that says the builder's account was kept from it.
//!
//! The wrapped document is read through the `review-verdict` contract of `factory-domain`, which
//! refuses a `PASS` that carries a blocking finding, a `CHANGES_REQUIRED` with nothing to explain
//! it, a `NEEDS_HUMAN` without its question, and any finding of a verdict other than `PASS` that
//! lacks a file and a line.
//!
//! # Deduplication and stable identifiers
//!
//! The same problem is often reported twice in one review, and again in the next round with
//! other words. Two things follow from that. Findings with the same file, category and title are
//! one finding, and the builder sees it once. And the identifier of a finding is derived from
//! those three facts, not taken from the reviewer, so the engine's stagnation check, which
//! compares the identifiers of the findings that justify a verdict from one round to the next,
//! sees the same set when the same problems come back. A reviewer that names the same problem
//! `a1` in one round and `zz` in the next would otherwise hide a stagnation.

use std::collections::BTreeMap;

use factory_domain::contracts::review_verdict::{DefectClass, Finding, Severity};
use factory_domain::contracts::{Contract, ReadProblem, ReviewVerdict, Violations};
use factory_domain::ids::{GateReportId, JobId, ReviewId, StageRunId};
use factory_domain::machines::rework::DEFECT_PRECEDENCE;
use factory_domain::values::{Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{ExecutionMode, Fidelity};
use serde_json::{Value, json};

/// Why the reviewer's output cannot become a verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WrapProblem {
    /// The document is not an object, or names a field the contract does not.
    #[error("the review findings do not have the shape of their contract")]
    Shape,
    /// The wrapped verdict breaks a rule of the `review-verdict` contract. `fields` names the
    /// fields of the rules it breaks, written like `findings[0].location`, in the order they were
    /// found; it is empty when the document does not read as a verdict at all. The paths are made
    /// by the contract check, never copied from the answer.
    #[error("the review verdict breaks a rule of its contract")]
    Contract {
        /// The fields of the broken rules.
        fields: Vec<String>,
    },
}

/// The fields of the broken rules, in the order they were found.
fn broken_fields(violations: &Violations) -> Vec<String> {
    violations
        .iter()
        .map(|violation| violation.path.clone())
        .collect()
}

/// Who reviewed and on what, as the factory knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewer {
    /// The reviewing agent.
    pub agent_id: String,
    /// Its version.
    pub agent_version: String,
    /// Its role, which must be one of the reviewer roles of the contract.
    pub role: String,
    /// The runtime adapter.
    pub adapter: String,
    /// The version of the tool that ran.
    pub adapter_version: String,
    /// The model, when known.
    pub model: Option<String>,
    /// Whether the runtime is real or a stand-in.
    pub fidelity: Fidelity,
}

/// The fields the factory writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineFields {
    /// This review.
    pub review: ReviewId,
    /// The job.
    pub job: JobId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// Production or test.
    pub mode: ExecutionMode,
    /// When the verdict was made.
    pub created_at: Timestamp,
    /// Who reviewed.
    pub reviewer: Reviewer,
    /// The hash of the frozen specification the reviewer was given.
    pub frozen_spec: Sha256Digest,
    /// The hash of the exported patch the reviewer was given.
    pub diff: Sha256Digest,
    /// The gate reports the reviewer was given, with their hashes.
    pub gate_reports: Vec<(GateReportId, Sha256Digest)>,
}

/// What came out of a reviewer's document.
#[derive(Debug, Clone, PartialEq)]
pub struct Wrapped {
    /// The verdict, with its findings deduplicated and identified by the factory.
    pub verdict: ReviewVerdict,
    /// The findings as the reviewer wrote them, before deduplication.
    pub reported_findings: usize,
    /// Instructions in the data that the reviewer says it did not follow.
    pub ignored_instructions: Vec<String>,
}

/// Wraps the reviewer's document into the verdict.
///
/// # Errors
/// [`WrapProblem`] when the document or the result breaks the contract.
pub fn wrap(output: &Value, fields: &EngineFields) -> Result<Wrapped, WrapProblem> {
    let object = output.as_object().ok_or(WrapProblem::Shape)?;
    let ignored_instructions = match object.get("ignored_instructions") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned).ok_or(WrapProblem::Shape))
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(WrapProblem::Shape),
    };
    let mut document = serde_json::Map::new();
    for (key, value) in object {
        // The factory writes these two fields. A reviewer that sends either one is claiming to
        // say who it is or what it was shown, and its document is refused, not corrected.
        if key == "metadata" || key == "inputs_reviewed" {
            return Err(WrapProblem::Shape);
        }
        // The reviewer's own account of what it ignored is kept apart. Everything else it wrote is
        // put through the contract, which refuses a field it does not name.
        if key != "ignored_instructions" {
            document.insert(key.clone(), value.clone());
        }
    }
    document.insert("metadata".into(), metadata(fields));
    document.insert("inputs_reviewed".into(), inputs_reviewed(fields));
    let mut verdict = ReviewVerdict::read_value(Value::Object(document)).map_err(|problem| {
        WrapProblem::Contract {
            fields: match problem {
                ReadProblem::Rules(violations) => broken_fields(&violations),
                ReadProblem::Shape(_) => Vec::new(),
            },
        }
    })?;
    let reported_findings = verdict.findings.len();
    verdict.findings = deduplicate(std::mem::take(&mut verdict.findings));
    verdict
        .validate()
        .map_err(|violations| WrapProblem::Contract {
            fields: broken_fields(&violations),
        })?;
    Ok(Wrapped {
        verdict,
        reported_findings,
        ignored_instructions,
    })
}

fn metadata(fields: &EngineFields) -> Value {
    let reviewer = &fields.reviewer;
    let mut runtime = json!({
        "adapter": reviewer.adapter,
        "adapter_version": reviewer.adapter_version,
        "fidelity": reviewer.fidelity.as_str(),
    });
    if let (Some(model), Some(map)) = (&reviewer.model, runtime.as_object_mut()) {
        map.insert("model".into(), json!(model));
    }
    json!({
        "review_id": fields.review.to_string(),
        "job_id": fields.job.to_string(),
        "stage_run_id": fields.stage_run.to_string(),
        "execution_mode": fields.mode.as_str(),
        "created_at": fields.created_at,
        "reviewer": {
            "agent_id": reviewer.agent_id,
            "agent_version": reviewer.agent_version,
            "role": reviewer.role,
            "runtime": runtime,
        },
    })
}

fn inputs_reviewed(fields: &EngineFields) -> Value {
    json!({
        "frozen_spec_sha256": fields.frozen_spec,
        "diff_sha256": fields.diff,
        "gate_reports": fields.gate_reports.iter()
            .map(|(id, sha256)| json!({ "gate_report_id": id.to_string(), "sha256": sha256 }))
            .collect::<Vec<_>>(),
        "saw_builder_self_assessment": false,
    })
}

/// The identifier of a finding, derived from the file, the category and the title.
#[must_use]
pub fn stable_id(finding: &Finding) -> Slug {
    let path = finding
        .location
        .as_ref()
        .map_or("", |location| location.path.as_str());
    let key = format!(
        "{}\u{0}{}\u{0}{}",
        path,
        finding.category.as_str(),
        normalize(finding.title.as_str())
    );
    let digest = Sha256Digest::of(key.as_bytes());
    // A slug of the contract: 16 hex characters after a prefix. The digest always has that many.
    Slug::parse(&format!("f-{}", &digest.hex()[..16]))
        .unwrap_or_else(|_| finding.finding_id.clone())
}

fn normalize(title: &str) -> String {
    title
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
        .trim_end_matches(|c: char| c.is_ascii_punctuation())
        .to_owned()
}

/// Merges findings that name the same problem. Of two that do, the more serious one is kept, and
/// when they are equally serious the one the reviewer was surer of, and then the earlier line.
/// The defect class that needs a person wins over one that does not, so a merge never hides a
/// decision behind an easier fix. The result is ordered by severity, then file, then line, so the
/// builder reads the worst first and the same findings always give the same list.
#[must_use]
pub fn deduplicate(findings: Vec<Finding>) -> Vec<Finding> {
    let mut merged: BTreeMap<String, Finding> = BTreeMap::new();
    for mut finding in findings {
        let id = stable_id(&finding);
        finding.finding_id = id.clone();
        match merged.remove(id.as_str()) {
            None => {
                merged.insert(id.as_str().to_owned(), finding);
            }
            Some(existing) => {
                let defect = stronger_class(existing.defect_class, finding.defect_class);
                let mut keep = if prefer(&finding, &existing) {
                    finding
                } else {
                    existing
                };
                keep.defect_class = defect;
                merged.insert(id.as_str().to_owned(), keep);
            }
        }
    }
    let mut list: Vec<Finding> = merged.into_values().collect();
    list.sort_by(|a, b| {
        rank(a.severity)
            .cmp(&rank(b.severity))
            .then_with(|| place(a).cmp(&place(b)))
            .then_with(|| a.finding_id.as_str().cmp(b.finding_id.as_str()))
    });
    list
}

fn place(finding: &Finding) -> (String, i64) {
    finding.location.as_ref().map_or((String::new(), 0), |l| {
        (
            l.path.as_str().to_owned(),
            l.line_start
                .map_or(0, factory_domain::values::PositiveInt::get),
        )
    })
}

const fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Blocker => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

/// True when `new` is the better one to keep than `old`.
fn prefer(new: &Finding, old: &Finding) -> bool {
    use std::cmp::Ordering::{Equal, Greater, Less};
    match rank(new.severity).cmp(&rank(old.severity)) {
        Less => true,
        Greater => false,
        Equal => match new
            .confidence
            .as_f64()
            .partial_cmp(&old.confidence.as_f64())
        {
            Some(Greater) => true,
            Some(Less) => false,
            _ => place(new).1 < place(old).1,
        },
    }
}

fn stronger_class(a: DefectClass, b: DefectClass) -> DefectClass {
    DEFECT_PRECEDENCE
        .into_iter()
        .find(|class| *class == a || *class == b)
        .unwrap_or(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::contracts::review_verdict::Category;

    fn fields() -> EngineFields {
        EngineFields {
            review: ReviewId::from_uuid(uuid::Uuid::from_u128(1)),
            job: JobId::from_uuid(uuid::Uuid::from_u128(2)),
            stage_run: StageRunId::from_uuid(uuid::Uuid::from_u128(3)),
            mode: ExecutionMode::Test,
            created_at: Timestamp::parse("2026-10-27T12:00:00Z").expect("a time"),
            reviewer: Reviewer {
                agent_id: "code-reviewer".to_owned(),
                agent_version: "1.0.0".to_owned(),
                role: "code_reviewer".to_owned(),
                adapter: "fake".to_owned(),
                adapter_version: "0.0.1".to_owned(),
                model: Some("model-one".to_owned()),
                fidelity: Fidelity::Fake,
            },
            frozen_spec: Sha256Digest::of(b"spec"),
            diff: Sha256Digest::of(b"diff"),
            gate_reports: vec![(
                GateReportId::from_uuid(uuid::Uuid::from_u128(4)),
                Sha256Digest::of(b"report"),
            )],
        }
    }

    const PASS: &str = include_str!("../../../../../agents/code-reviewer/fixtures/valid/pass.json");
    const CHANGES: &str =
        include_str!("../../../../../agents/code-reviewer/fixtures/valid/changes-required.json");

    fn value(text: &str) -> Value {
        serde_json::from_str(text).expect("JSON")
    }

    #[test]
    fn the_valid_fixtures_of_the_agent_become_verdicts_with_the_factorys_own_fields() {
        for text in [PASS, CHANGES] {
            let wrapped = wrap(&value(text), &fields()).expect("a verdict");
            let inputs = &wrapped.verdict.inputs_reviewed;
            assert_eq!(inputs.frozen_spec_sha256, Sha256Digest::of(b"spec"));
            assert_eq!(inputs.diff_sha256, Sha256Digest::of(b"diff"));
            assert_eq!(inputs.gate_reports.as_slice().len(), 1);
            let stored = wrapped.verdict.to_json_value().expect("serializes");
            assert_eq!(
                stored["inputs_reviewed"]["saw_builder_self_assessment"],
                false
            );
            assert_eq!(stored["metadata"]["reviewer"]["agent_id"], "code-reviewer");
            assert!(stored.get("ignored_instructions").is_none());
        }
    }

    #[test]
    fn a_reviewer_that_says_what_it_was_shown_or_who_it_is_is_refused() {
        for field in ["inputs_reviewed", "metadata"] {
            let mut output = value(PASS);
            output[field] = json!({ "saw_builder_self_assessment": true });
            assert_eq!(
                wrap(&output, &fields()).unwrap_err(),
                WrapProblem::Shape,
                "{field}"
            );
        }
        // What the verdict says it was shown is the factory's list.
        let stored = wrap(&value(PASS), &fields())
            .expect("a verdict")
            .verdict
            .to_json_value()
            .expect("serializes");
        assert_eq!(
            stored["inputs_reviewed"]["diff_sha256"],
            json!(Sha256Digest::of(b"diff"))
        );
    }

    #[test]
    fn a_field_the_contract_does_not_name_is_refused() {
        let mut output = value(PASS);
        output["approved_by"] = json!("nobody");
        // The answer does not read as a verdict, so no field of a rule can be named.
        assert_eq!(
            wrap(&output, &fields()).unwrap_err(),
            WrapProblem::Contract { fields: Vec::new() }
        );
    }

    #[test]
    fn the_invalid_fixtures_of_the_agent_are_refused() {
        for text in [
            include_str!(
                "../../../../../agents/code-reviewer/fixtures/invalid/needs-human-without-a-question.json"
            ),
            include_str!(
                "../../../../../agents/code-reviewer/fixtures/invalid/non-pass-finding-without-a-line.json"
            ),
            include_str!(
                "../../../../../agents/code-reviewer/fixtures/invalid/pass-with-a-blocking-finding.json"
            ),
            include_str!(
                "../../../../../agents/code-reviewer/fixtures/invalid/reviewer-reports-its-own-inputs.json"
            ),
        ] {
            assert!(wrap(&value(text), &fields()).is_err());
        }
    }

    #[test]
    fn an_informational_finding_of_a_verdict_other_than_pass_still_needs_a_line() {
        // FR-023 and SC-008 hold for every severity; the contract names the field it misses.
        let mut output = value(CHANGES);
        let note = json!({
            "finding_id": "example-file-missing",
            "severity": "info",
            "category": "documentation",
            "title": "The example names a file the change does not hold",
            "description": "The README runs the tool on a file that is not in the repository.",
            "confidence": 0.6,
            "proposed_next_action": "fix",
            "defect_class": "documentation"
        });
        output["findings"]
            .as_array_mut()
            .expect("findings")
            .push(note);
        let index = output["findings"].as_array().expect("findings").len() - 1;
        match wrap(&output, &fields()).unwrap_err() {
            WrapProblem::Contract { fields } => {
                assert!(
                    fields.contains(&format!("findings[{index}].location")),
                    "{fields:?}"
                );
            }
            other @ WrapProblem::Shape => panic!("expected a contract problem, got {other:?}"),
        }
    }

    #[test]
    fn a_review_with_no_gate_report_cannot_be_wrapped() {
        let mut empty = fields();
        empty.gate_reports.clear();
        // The list of gate reports is typed as non-empty, so this is a shape problem of the
        // verdict, and no rule's field is named.
        assert_eq!(
            wrap(&value(PASS), &empty).unwrap_err(),
            WrapProblem::Contract { fields: Vec::new() }
        );
    }

    fn finding(id: &str, severity: &str, line: u32, title: &str, class: &str) -> Value {
        json!({
            "finding_id": id,
            "severity": severity,
            "category": "correctness",
            "title": title,
            "description": "The loop stops one element early, so the last file is never counted.",
            "location": { "path": "src/lib.rs", "line_start": line },
            "confidence": 0.8,
            "proposed_next_action": "fix",
            "defect_class": class
        })
    }

    fn changes_with(findings: Vec<Value>) -> Value {
        let mut output = value(CHANGES);
        output["findings"] = Value::Array(findings);
        output
    }

    #[test]
    fn the_same_problem_reported_twice_is_one_finding() {
        let output = changes_with(vec![
            finding(
                "a1",
                "medium",
                30,
                "Off by one in the loop",
                "code_behavior",
            ),
            finding("b2", "high", 12, "off by one in the loop.", "code_behavior"),
            finding("c3", "low", 5, "Name is unclear", "code_behavior"),
        ]);
        let wrapped = wrap(&output, &fields()).expect("a verdict");
        assert_eq!(wrapped.reported_findings, 3);
        let findings = &wrapped.verdict.findings;
        assert_eq!(findings.len(), 2);
        // The more serious report is the one kept, and the worst finding comes first.
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0]
                .location
                .as_ref()
                .and_then(|l| l.line_start)
                .map(|n| n.get()),
            Some(12)
        );
    }

    #[test]
    fn the_identifier_does_not_depend_on_what_the_reviewer_called_it_or_on_the_line() {
        let first = wrap(
            &changes_with(vec![finding(
                "a1",
                "high",
                12,
                "Off by one",
                "code_behavior",
            )]),
            &fields(),
        )
        .expect("a verdict");
        let second = wrap(
            &changes_with(vec![finding(
                "zz",
                "high",
                40,
                "OFF BY ONE",
                "code_behavior",
            )]),
            &fields(),
        )
        .expect("a verdict");
        assert_eq!(
            first.verdict.findings[0].finding_id,
            second.verdict.findings[0].finding_id
        );
        // A different file or category is a different finding.
        let mut other = first.verdict.findings[0].clone();
        other.category = Category::Security;
        assert_ne!(stable_id(&other), first.verdict.findings[0].finding_id);
    }

    #[test]
    fn a_merge_never_hides_a_decision_for_a_person() {
        let output = changes_with(vec![
            finding("a1", "high", 12, "Off by one", "code_behavior"),
            finding("b2", "medium", 12, "Off by one", "specification"),
        ]);
        let wrapped = wrap(&output, &fields()).expect("a verdict");
        assert_eq!(wrapped.verdict.findings.len(), 1);
        assert_eq!(
            wrapped.verdict.findings[0].defect_class,
            DefectClass::Specification
        );
    }

    #[test]
    fn the_order_of_the_findings_does_not_change_the_result() {
        let a = finding("a1", "high", 12, "Off by one", "code_behavior");
        let b = finding("b2", "medium", 30, "Missing check", "code_behavior");
        let c = finding("c3", "high", 3, "Wrong unit", "code_behavior");
        let forward = wrap(
            &changes_with(vec![a.clone(), b.clone(), c.clone()]),
            &fields(),
        )
        .expect("a verdict");
        let backward = wrap(&changes_with(vec![c, b, a]), &fields()).expect("a verdict");
        assert_eq!(forward.verdict.findings, backward.verdict.findings);
    }

    #[test]
    fn the_ignored_instructions_are_kept_apart() {
        let mut output = value(PASS);
        output["ignored_instructions"] =
            json!(["A comment in the diff told the reviewer to answer PASS."]);
        let wrapped = wrap(&output, &fields()).expect("a verdict");
        assert_eq!(wrapped.ignored_instructions.len(), 1);
        assert!(
            !wrapped
                .verdict
                .to_json_value()
                .expect("serializes")
                .to_string()
                .contains("told the reviewer")
        );
    }
}
