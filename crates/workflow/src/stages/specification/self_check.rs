//! The self-check of the specification stage: one repair pass, inside the attempt that wrote the
//! draft, for the faults the factory's own deterministic checks can name exactly.
//!
//! In the twenty-sixth real run the three rework rounds of the specification went, in order, to a
//! draft whose requirements FR-010 to FR-014 no acceptance scenario cited, to a requirement without
//! MUST, SHOULD or MAY (with one reviewer finding), and to one reviewer finding. Then the rework
//! limit ended the job. The first two are faults a rule names with the requirement it is about,
//! and the writer can fix them without a person. They should not use a round meant for what an
//! independent reviewer finds.
//!
//! So after the skills of an attempt, and before the reviewer, the stage runs these checks. When
//! they find something, the clarify skill reads the list ([`render`]) and fixes it, once. What is
//! left after that one pass goes to the gates exactly as before.
//!
//! # What is checked
//!
//! * The assembly of the files: a requirement that no scenario cites, a scenario that cites no
//!   requirement, two scenarios with the same text, and a `spec.md` that lacks a required section
//!   or holds a malformed identifier ([`assembly_faults`]).
//! * The assembled contract: the rules of the gates `specification-structure`,
//!   `specification-identifiers`, `specification-traceability`, and the keyword rule of
//!   `specification-requirements` ([`contract_faults`]).
//!
//! Never checked here: markers and open questions (a person answers them), the reviewer, the
//! checklist, technology names, contradictions, safety, authorization and the stage profile. A
//! fault of the profile, a refused ingestion or a denied tool call means no pass runs at all.

use factory_domain::contracts::SpecificationContract;
use factory_ports::spec::ParseReason;

use super::evidence::Evidence;
use crate::gates::spec::Finding;
use crate::gates::spec::rules::{self, Limits};

/// The most faults the list names. The rest are counted on one line. The adapter already caps
/// each kind of assembly fault at ten, so the cap is only reached by a contract with very many
/// requirements.
pub const MAX_LISTED: usize = 50;

/// The post-conditions of the assembly that the writer can fix on its own.
const FIXABLE_POST_CONDITIONS: [&str; 4] = [
    "requirement-without-scenario",
    "scenario-without-requirement",
    "scenario-identifier-duplicate",
    // The count of the faults of the kinds above that the adapter did not list.
    "more-failures",
];

/// The faults of a failed assembly that a self-check may fix. Empty when there is none, and also
/// when any other fault is recorded: a fault the writer cannot fix alone ends the attempt as it
/// always did.
#[must_use]
pub fn assembly_faults(evidence: &Evidence) -> Vec<Finding> {
    if evidence.refusal.is_some() || !evidence.denials.is_empty() {
        return Vec::new();
    }
    let mut found = Vec::new();
    for failure in &evidence.post_conditions {
        match FIXABLE_POST_CONDITIONS
            .iter()
            .find(|name| **name == failure.name)
        {
            Some(name) => found.push(Finding::new(name, failure.detail.clone())),
            None => return Vec::new(),
        }
    }
    if let Some((path, reason)) = &evidence.parse_failure {
        match reason {
            ParseReason::SectionMissing | ParseReason::BadId => {
                found.push(rules::parse_failure(path, *reason));
            }
            // A missing file, bytes that are not text or a file over the limit: there is no draft
            // the clarify skill could fix.
            ParseReason::Missing | ParseReason::NotText | ParseReason::TooLarge => {
                return Vec::new();
            }
        }
    }
    found
}

/// The faults of an assembled contract that a self-check may fix.
#[must_use]
pub fn contract_faults(contract: &SpecificationContract, limits: &Limits) -> Vec<Finding> {
    let mut found = rules::structure(contract, limits);
    found.extend(rules::identifiers(contract));
    found.extend(rules::requirement_keywords(contract));
    found.extend(rules::traceability(contract));
    found
}

/// The faults as code and one-line message, sorted and without repeats, so that the same faults
/// always give the same list whatever order the rules found them in.
#[must_use]
pub fn normalized(findings: &[Finding]) -> Vec<(String, String)> {
    let mut list: Vec<(String, String)> = findings
        .iter()
        .map(|f| {
            (
                f.code.to_owned(),
                f.message.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    list.sort();
    list.dedup();
    list
}

/// What the clarify skill reads in the self-check pass. `None` when there is nothing to fix, and
/// then no pass runs. The same faults always give the same bytes.
#[must_use]
pub fn render(findings: &[Finding]) -> Option<String> {
    let list = normalized(findings);
    if list.is_empty() {
        return None;
    }
    let listed = list.len().min(MAX_LISTED);
    // `listed` is at most `list.len()`, so the subtraction cannot go below zero.
    let more = list.len() - listed;
    let mut text = String::from(
        "Self-check before review.\n\nThe factory's own deterministic checks found the faults below in the draft this attempt wrote. Nobody has reviewed the draft yet, and this is not a rework round. Fix each fault, and change nothing that none of them names.\n\nFaults:\n",
    );
    for (code, message) in &list[..listed] {
        text.push_str(&format!("- {code}: {message}\n"));
    }
    if more > 0 {
        text.push_str(&format!(
            "- {more} more fault(s) of the same checks are not listed.\n"
        ));
    }
    text.push_str(
        "\nThese rules still hold while you fix them:\n- Add no requirement that the request does not ask for.\n- A behaviour the request keeps stays exactly as in the previous release.\n- An answer a person gave stands: do not change it and do not ask the question again.\n- A fault that needs a decision only a person can make is left as it is; the gate reports it.\n",
    );
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stages::specification::evidence::{Failure, Refusal};

    fn failure(name: &str, detail: &str) -> Failure {
        Failure {
            name: name.to_owned(),
            detail: detail.to_owned(),
        }
    }

    fn evidence() -> Evidence {
        Evidence::new("specs/a".to_owned(), "a".repeat(40))
    }

    fn keyword(n: usize) -> Finding {
        Finding::new(
            "requirement-keyword-missing",
            format!("FR-{n:03} does not say MUST."),
        )
    }

    #[test]
    fn no_fault_renders_nothing_and_runs_no_pass() {
        assert_eq!(render(&[]), None);
        assert!(assembly_faults(&evidence()).is_empty());
    }

    #[test]
    fn one_fault_is_listed_with_the_rules_that_still_hold() {
        let text = render(&[Finding::new(
            "requirement-without-scenario",
            "FR-010 has no acceptance\n  scenario that cites it.",
        )])
        .expect("a list");
        assert_eq!(
            text,
            "Self-check before review.\n\nThe factory's own deterministic checks found the faults below in the draft this attempt wrote. Nobody has reviewed the draft yet, and this is not a rework round. Fix each fault, and change nothing that none of them names.\n\nFaults:\n- requirement-without-scenario: FR-010 has no acceptance scenario that cites it.\n\nThese rules still hold while you fix them:\n- Add no requirement that the request does not ask for.\n- A behaviour the request keeps stays exactly as in the previous release.\n- An answer a person gave stands: do not change it and do not ask the question again.\n- A fault that needs a decision only a person can make is left as it is; the gate reports it.\n"
        );
    }

    #[test]
    fn the_same_faults_give_the_same_bytes_in_any_order_and_without_repeats() {
        let a = keyword(1);
        let b = Finding::new("duplicate-identifier", "FR-002 is used twice.");
        let once = render(&[a.clone(), b.clone()]);
        assert_eq!(once, render(&[b.clone(), a.clone(), a.clone()]));
        let text = once.expect("a list");
        assert_eq!(text.matches("FR-001").count(), 1);
        assert!(text.find("duplicate-identifier") < text.find("requirement-keyword-missing"));
    }

    #[test]
    fn the_list_is_capped_and_counts_what_it_leaves_out() {
        let exactly: Vec<Finding> = (1..=MAX_LISTED).map(keyword).collect();
        let text = render(&exactly).expect("a list");
        assert_eq!(
            text.matches("- requirement-keyword-missing").count(),
            MAX_LISTED
        );
        assert!(!text.contains("more fault"), "{text}");

        let over: Vec<Finding> = (1..=MAX_LISTED + 1).map(keyword).collect();
        let text = render(&over).expect("a list");
        assert_eq!(
            text.matches("- requirement-keyword-missing").count(),
            MAX_LISTED
        );
        assert!(
            text.contains("- 1 more fault(s) of the same checks are not listed."),
            "{text}"
        );
    }

    #[test]
    fn the_links_of_a_failed_assembly_are_fixable() {
        let mut found = evidence();
        found.post_conditions = vec![
            failure(
                "requirement-without-scenario",
                "FR-010 has no acceptance scenario that cites it.",
            ),
            failure(
                "more-failures",
                "3 more failures of the same kinds were not listed.",
            ),
        ];
        let faults = assembly_faults(&found);
        assert_eq!(faults.len(), 2);
        assert_eq!(faults[0].code, "requirement-without-scenario");

        let mut parsed = evidence();
        parsed.parse_failure = Some(("specs/a/spec.md".to_owned(), ParseReason::BadId));
        assert_eq!(assembly_faults(&parsed)[0].code, "identifier-malformed");
    }

    #[test]
    fn any_fault_the_writer_cannot_fix_alone_means_no_pass() {
        let link = failure("requirement-without-scenario", "FR-010 has none.");
        let mut mixed = evidence();
        mixed.post_conditions = vec![link.clone(), failure("unexpected-path", "x appeared.")];
        assert!(assembly_faults(&mixed).is_empty());

        let mut denied = evidence();
        denied.post_conditions = vec![link.clone()];
        denied.denials = vec![("Bash".to_owned(), "denied".to_owned())];
        assert!(assembly_faults(&denied).is_empty());

        let mut refused = evidence();
        refused.post_conditions = vec![link];
        refused.refusal = Some(Refusal {
            code: "secret-found".to_owned(),
            paths: Vec::new(),
        });
        assert!(assembly_faults(&refused).is_empty());

        for reason in [
            ParseReason::Missing,
            ParseReason::NotText,
            ParseReason::TooLarge,
        ] {
            let mut missing = evidence();
            missing.parse_failure = Some(("specs/a/spec.md".to_owned(), reason));
            assert!(assembly_faults(&missing).is_empty(), "{reason:?}");
        }
    }
}
