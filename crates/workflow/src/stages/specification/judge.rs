//! The judgement of the specification stage: every rule of the gate, run over the contract and the
//! evidence. `execute` runs it to know whether a person is worth asking, and `evaluate` runs it
//! again over the stored artifacts and reports. The two cannot disagree because there is one
//! function.

use std::collections::BTreeMap;

use factory_domain::contracts::SpecificationContract;
use factory_domain::values::Sha256Digest;

use super::evidence::{Evidence, ReviewRecord};
use crate::gates::spec::checklist::{self, ChecklistInput, Waiver};
use crate::gates::spec::profile::{ProfileEvidence, ProfileRules};
use crate::gates::spec::rules::{self, Limits};
use crate::gates::spec::{self, Family, Finding, family_of};
use crate::stages::architecture::critic::{Review, Verdict};

/// The gate for the independent review.
pub const REVIEW: &str = "specification-review";

/// One gate with what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judged {
    /// The gate id.
    pub id: &'static str,
    /// A title in plain English.
    pub title: &'static str,
    /// The definition text, hashed into the report.
    pub text: &'static str,
    /// What it found. None means it passed.
    pub findings: Vec<Finding>,
    /// The gate could not run: the code and what was missing.
    pub blocked: Option<(&'static str, String)>,
}

impl Judged {
    fn new(
        id: &'static str,
        title: &'static str,
        text: &'static str,
        findings: Vec<Finding>,
    ) -> Self {
        Self {
            id,
            title,
            text,
            findings,
            blocked: None,
        }
    }
}

/// Everything the judgement reads.
pub struct JudgeInput<'a> {
    /// The contract the stage stored, when there is one.
    pub contract: Option<&'a SpecificationContract>,
    /// The evidence.
    pub evidence: &'a Evidence,
    /// The waivers of people.
    pub waivers: &'a [Waiver],
    /// The word lists.
    pub limits: &'a Limits,
    /// The rules of the stage profile.
    pub profile: &'a ProfileRules,
    /// The stored transcripts.
    pub transcripts: &'a [Vec<u8>],
    /// The hash of every recorded file as the host measured it in the commit.
    pub committed: &'a BTreeMap<String, Sha256Digest>,
    /// The files under the feature directory that the contract does not record.
    pub unlisted: &'a [String],
    /// For an approved contract: whether the approval it carries is the one the engine recorded.
    pub approval_recorded: Option<bool>,
    /// The writer's agent id, for the independence check.
    pub writer: &'a str,
}

/// The code a post-condition of the adapter is reported under.
fn code_of(name: &str) -> &'static str {
    match name {
        "feature-file-written" => "feature-file-written",
        "feature-pointer-valid" => "feature-pointer-valid",
        "no-template-placeholder" => "template-placeholder",
        "checklist-present" => "checklist-missing",
        "custom-checklist-ticked" => "custom-checklist-ticked",
        "requirement-without-scenario" => "requirement-without-scenario",
        "scenario-without-requirement" => "scenario-without-requirement",
        "scenario-identifier-duplicate" => "duplicate-identifier",
        "more-failures" => "more-failures",
        "forbidden-skill-invoked" => "forbidden_skill_invoked",
        "no-forbidden-artifact" => "forbidden_artifact_present",
        "unexpected-path" => "write_outside_profile",
        "skill-arguments-fixed" => "skill_arguments_leak",
        "run-succeeded" => "run-not-successful",
        "installation-not-ok" => "installation_not_ok",
        "frozen-specification-changed" => "frozen_specification_changed",
        "extensions-present" => "extensions_present",
        _ => "post-condition-failed",
    }
}

fn of_family(evidence: &Evidence, family: Family) -> Vec<Finding> {
    evidence
        .post_conditions
        .iter()
        .filter(|f| family_of(&f.name) == family)
        .map(|f| Finding::new(code_of(&f.name), f.detail.clone()))
        .collect()
}

const NO_SPEC: &str = "There is no specification to judge: the files were not understood.";

/// Runs every rule.
#[must_use]
pub fn judge(input: &JudgeInput<'_>) -> Vec<Judged> {
    let evidence = input.evidence;
    let limits = input.limits;
    let waived = checklist::waived(input.waivers);
    let missing = || vec![Finding::new("no-specification-to-judge", NO_SPEC)];
    let with =
        |f: &dyn Fn(&SpecificationContract) -> Vec<Finding>| input.contract.map_or_else(missing, f);

    let mut structure = of_family(evidence, Family::Structure);
    if let Some((path, reason)) = &evidence.parse_failure {
        structure.push(rules::parse_failure(path, *reason));
    }
    if let Some(contract) = input.contract {
        structure.extend(rules::structure(contract, limits));
    }

    let mut requirements = with(&|c| rules::requirement_keywords(c));
    if let Some(contract) = input.contract {
        requirements.extend(rules::technology_names(contract, limits));
    }
    let mut traceability = of_family(evidence, Family::Traceability);
    if let Some(contract) = input.contract {
        traceability.extend(rules::traceability(contract));
    }

    let (reviewer_passed, finding_texts, review_findings) = review_view(evidence, input.writer);
    let checklist_findings = input.contract.map_or_else(missing, |contract| {
        let resolution = checklist::resolve(
            contract,
            &ChecklistInput {
                reviewer_passed,
                finding_texts: &finding_texts,
                waivers: input.waivers,
            },
        );
        checklist::findings(&resolution)
    });

    let mut authorization: Vec<Finding> = evidence
        .draft_authorization
        .iter()
        .map(|(code, message)| Finding::new(static_authorization_code(code), message.clone()))
        .collect();
    if input.approval_recorded == Some(false) {
        authorization.push(Finding::new(
            "approval-not-recorded",
            "The contract carries an approval that the engine did not record for this draft.",
        ));
    }

    let mut profile = of_family(evidence, Family::Profile);
    let denials = &evidence.denials;
    profile.extend(input.profile.check(&ProfileEvidence {
        denials,
        transcripts: input.transcripts,
        changed: &evidence.changed,
        committed: &evidence.committed.keys().cloned().collect::<Vec<_>>(),
    }));
    // What reached the arguments of each skill, read from the run's own transcript.
    profile.extend(
        input
            .profile
            .check_invocations(&evidence.invocations, input.transcripts),
    );
    if let Some(refusal) = &evidence.refusal {
        profile.push(Finding::new(
            "ingestion-refused",
            format!(
                "The audit of the sandbox tree refused the change ({}).",
                refusal.code
            ),
        ));
    }
    dedup(&mut profile);

    vec![
        Judged::new(
            spec::STRUCTURE,
            "The files are understood and complete",
            "specification-structure 1.0.0: the files parse, and the specification names a scope boundary, its risks and a measurable criterion.",
            structure,
        ),
        Judged::new(
            spec::IDENTIFIERS,
            "Identifiers are unique",
            "specification-identifiers 1.0.0: no requirement, scenario, criterion or question identifier is used twice.",
            with(&|c| rules::identifiers(c)),
        ),
        Judged::new(
            spec::REQUIREMENTS,
            "Requirements are testable and name no technology",
            "specification-requirements 1.0.0: every requirement holds MUST, SHOULD or MAY in capitals, and none names an implementation technology.",
            requirements,
        ),
        Judged::new(
            spec::TRACEABILITY,
            "Requirements and scenarios trace to each other",
            "specification-traceability 1.0.0: every requirement has a scenario, every scenario names a requirement, and every reference resolves.",
            traceability,
        ),
        Judged::new(
            spec::CLARITY,
            "Nothing is left unclear",
            "specification-clarity 1.0.0: no marker, no placeholder and no open blocking question remains beyond what a person waived.",
            with(&|c| rules::clarity(c, &waived)),
        ),
        Judged::new(
            spec::CONTRADICTIONS,
            "Requirements do not contradict each other",
            "specification-contradictions 1.0.0: no duty and ban on the same words, no bounds that cannot both hold, no sentence with two priorities.",
            with(&|c| rules::contradictions(c)),
        ),
        Judged::new(
            spec::SAFETY,
            "Safety constraints hold",
            "specification-safety 1.0.0: a high risk has a mitigation or a safety constraint, and no requirement asks to bypass a control.",
            with(&|c| rules::safety(c, limits)),
        ),
        Judged::new(
            spec::AUTHORIZATION,
            "Authorization is a recorded decision",
            "specification-authorization 1.0.0: the writer's draft carries no approval, and an approved contract carries the approval the engine recorded.",
            authorization,
        ),
        Judged::new(
            spec::CHECKLIST,
            "Every checklist item is verified or waived",
            "specification-checklist 1.0.0: every checklist item is verified by the independent reviewer or waived by a person with a reason. Ticks written by the author carry no weight.",
            checklist_findings,
        ),
        Judged::new(
            spec::ARTIFACTS,
            "The committed files are the recorded files",
            "specification-artifacts 1.0.0: the files in the commit are the recorded set and their hashes match.",
            with(&|c| rules::artifacts(c, input.committed, input.unlisted)),
        ),
        Judged::new(
            REVIEW,
            "An independent reviewer agrees",
            "specification-review 1.0.0: a reviewer that is not the writer read the specification and found nothing that must change.",
            review_findings,
        ),
        Judged::new(
            spec::STAGE_PROFILE,
            "Only the four skills ran, and they wrote only their files",
            "stage_profile_check 1.1.0: no skill outside the profile ran or was visible, no file of one exists, no path outside the writes of the four skills changed, and the transcript of each skill run shows the invocation the factory sent, with the fixed instruction as its arguments, exactly once and with no other Spec Kit invocation. It cannot be waived.",
            profile,
        ),
    ]
}

fn dedup(findings: &mut Vec<Finding>) {
    let mut seen = std::collections::BTreeSet::new();
    findings.retain(|f| seen.insert((f.code, f.message.clone())));
}

fn static_authorization_code(code: &str) -> &'static str {
    match code {
        "specification-arrived-approved" => "specification-arrived-approved",
        _ => "approval-written-by-the-writer",
    }
}

/// Whether the reviewer passed, the text of every finding it made, and the findings of the
/// review gate.
fn review_view(evidence: &Evidence, writer: &str) -> (bool, Vec<String>, Vec<Finding>) {
    match &evidence.review {
        ReviewRecord::NotRun(reason) => {
            let earlier = evidence.parse_failure.is_some()
                || !evidence.post_conditions.is_empty()
                || evidence.refusal.is_some();
            let finding = if earlier {
                Finding::new(
                    "review-skipped",
                    "The files failed their checks first, so the reviewer was not asked to read them.",
                )
            } else {
                Finding::new(
                    "review-did-not-run",
                    format!("No independent reviewer read the specification ({reason})."),
                )
            };
            (false, Vec::new(), vec![finding])
        }
        ReviewRecord::Answered { agent, answer, .. } => {
            let Ok(review) = Review::read(answer) else {
                return (
                    false,
                    Vec::new(),
                    vec![Finding::new(
                        "review-unreadable",
                        "The reviewer's answer is not shaped like its schema or contradicts itself.",
                    )],
                );
            };
            let texts: Vec<String> = review
                .findings
                .iter()
                .map(|f| format!("{} {}", f.title, f.description))
                .collect();
            let mut found: Vec<Finding> = Vec::new();
            if agent == writer {
                found.push(Finding::new(
                    "reviewer-not-independent",
                    "The reviewer is the writer, so the review is not independent.",
                ));
            }
            match review.verdict {
                Verdict::Pass => {}
                Verdict::NeedsHuman => found.push(Finding::new(
                    "reviewer-asks-a-person",
                    "The reviewer asked a person to decide.",
                )),
                Verdict::ChangesRequired | Verdict::Block => {
                    for finding in review.blocking() {
                        found.push(Finding::new(
                            "review-finding",
                            format!("{}: {}", finding.title, finding.description),
                        ));
                    }
                }
            }
            (
                review.verdict == Verdict::Pass && found.is_empty(),
                texts,
                found,
            )
        }
    }
}

/// How every checklist item of the contract stands, by the reviewer's answer and the waivers of
/// people. `freeze` records each as an answered question.
#[must_use]
pub fn checklist_resolution(
    contract: &SpecificationContract,
    evidence: &Evidence,
    waivers: &[Waiver],
    writer: &str,
) -> checklist::Resolution {
    let (reviewer_passed, finding_texts, _) = review_view(evidence, writer);
    checklist::resolve(
        contract,
        &ChecklistInput {
            reviewer_passed,
            finding_texts: &finding_texts,
            waivers,
        },
    )
}

/// True when no gate found anything and none was blocked.
#[must_use]
pub fn all_clear(judged: &[Judged]) -> bool {
    judged
        .iter()
        .all(|gate| gate.findings.is_empty() && gate.blocked.is_none())
}
