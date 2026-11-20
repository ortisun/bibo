//! `evaluate` of the architecture stage: the evidence the engine judges.
//!
//! The gates read the stored design and the stored record, and read the frozen specification again
//! by the hash the contract pinned. They compute everything that can be computed (the mapping, the
//! alternatives, the readability) and take from the record only what the stage measured at run
//! time: the risk tier and what happened about the critic. Nothing the architect says about its own
//! work is evidence, so a design that says it is done is judged by the same checks as any other.
//!
//! A gate that has nothing to check says so with a report that does not apply, and says who
//! decided. A required critic that does not exist is a report that could not run, never a pass.

use factory_domain::contracts::gate_report::{NotApplicableCode, NotApplicableDecider};
use factory_domain::contracts::{Contract, GateReport, SpecificationContract};
use factory_domain::vocabulary::RiskTier;
use serde_json::Value;

use super::checks::{self, Complexity, Finding, SpecIds};
use super::critic::{self, Outcome, Verdict};
use super::design::{Design, Status};
use super::handler::{
    ArchitectureHandler, COMPLETENESS_GATE, CRITIC_GATE, DESIGN, RECORD, TRACEABILITY_GATE,
};
use super::shared::{
    definition, facts, not_applicable, output, read_for_gate, readability_report, subject,
};
use crate::gates::framework::GateDecision;
use crate::gates::readability::Artifact;
use crate::handlers::{GateContext, StageError};
use crate::stages::implementation::input::{SPECIFICATION_CONTRACT, input_artifact};
use crate::stages::intake::common::gate_report;

const TRACEABILITY_TEXT: &str = "architecture-traceability 1.0.0: every requirement and success criterion of the frozen specification is satisfied by at least one design element, and every design element names at least one requirement that exists.";
const COMPLETENESS_TEXT: &str = "architecture-completeness 1.0.0: a change that is not trivial weighed at least the configured number of alternatives and named how it could fail, no identifier is repeated, the design is not larger than its requirements justify, and no path that policy protects is touched.";
const CRITIC_TEXT: &str = "architecture-critic 1.0.0: when the risk tier requires an independent critic, an agent that is not the architect reviewed the design and agreed, or the stage says that none could.";

fn failures(findings: &[Finding]) -> Vec<(String, String)> {
    findings
        .iter()
        .map(|finding| (finding.check_id(), finding.message.clone()))
        .collect()
}

fn tier_of(record: &Value) -> Option<RiskTier> {
    match record.pointer("/risk/tier")?.as_str()? {
        "low" => Some(RiskTier::Low),
        "medium" => Some(RiskTier::Medium),
        "high" => Some(RiskTier::High),
        "critical" => Some(RiskTier::Critical),
        _ => None,
    }
}

/// Why the design is in its tier, in plain English, from what the stage measured at run time: the
/// criteria of the policy that held, the claim of the intake classifier, the sensitive paths and
/// the decisions for a person. A blocked or skipped critic gate says it, so that a person reading
/// the report sees what put the design at a tier that needs a critic.
fn why_this_tier(record: &Value, tier: RiskTier) -> String {
    // At most this many items of a list are named, so that the reason stays within the length the
    // report schema allows whatever the design holds.
    const SHOWN: usize = 8;
    let texts = |pointer: &str| -> Vec<String> {
        let all: Vec<String> = record
            .pointer(pointer)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|item| item.chars().take(80).collect())
                    .collect()
            })
            .unwrap_or_default();
        let mut named: Vec<String> = all
            .iter()
            .take(SHOWN)
            .map(|item| format!("`{item}`"))
            .collect();
        if all.len() > SHOWN {
            named.push(format!("and {} more", all.len() - SHOWN));
        }
        named
    };
    let text = |pointer: &str| record.pointer(pointer).and_then(Value::as_str);
    let mut why = format!("The design is in the {} tier.", tier.as_str());
    let matched = texts("/risk/matched");
    if record.pointer("/risk/unclassified") == Some(&Value::Bool(true)) || matched.is_empty() {
        why.push_str(
            " No criterion of the policy held for it, and the policy puts a change it cannot classify in the high tier.",
        );
    } else {
        why.push_str(&format!(
            " The policy computed the {} tier from the criteria that held: {}.",
            text("/risk/computed").unwrap_or("unknown"),
            matched.join(", ")
        ));
    }
    if let Some(claim) = text("/risk/agent_claim") {
        if text("/risk/computed") == Some(tier.as_str()) {
            why.push_str(&format!(
                " The intake classifier claimed the {claim} tier, and a claim never lowers the tier."
            ));
        } else {
            why.push_str(&format!(
                " The intake classifier claimed the {claim} tier, which raised it."
            ));
        }
    }
    let sensitive = texts("/risk/sensitive_paths");
    if !sensitive.is_empty() {
        why.push_str(&format!(
            " The design says it changes files that the path policy marks sensitive: {}.",
            sensitive.join(", ")
        ));
    }
    let decisions = texts("/risk/decisions_for_a_person");
    if !decisions.is_empty() {
        why.push_str(&format!(
            " These decisions need a person, and each counts as a new dependency: {}.",
            decisions.join(", ")
        ));
    }
    why
}

fn not_a_design() -> &'static str {
    "The architect asked a person a question, so there is no finished design to check."
}

pub(super) async fn evaluate(
    handler: &ArchitectureHandler,
    ctx: &GateContext<'_>,
) -> Result<GateDecision, StageError> {
    let (Some(design_named), Some(record_named)) = (output(ctx, DESIGN), output(ctx, RECORD))
    else {
        return Err(StageError::InvalidOutput);
    };
    let design_bytes = read_for_gate(ctx, &design_named.artifact).await?;
    let record_bytes = read_for_gate(ctx, &record_named.artifact).await?;
    let design_json: Value =
        serde_json::from_slice(&design_bytes).map_err(|_| StageError::InvalidOutput)?;
    let record: Value =
        serde_json::from_slice(&record_bytes).map_err(|_| StageError::InvalidOutput)?;
    let design = Design::read(&design_json).map_err(|_| StageError::InvalidOutput)?;
    let tier = tier_of(&record).ok_or(StageError::InvalidOutput)?;
    let critic_outcome = record
        .get("critic")
        .and_then(Outcome::from_json)
        .ok_or(StageError::InvalidOutput)?;

    let spec_ref =
        input_artifact(ctx.contract, SPECIFICATION_CONTRACT).ok_or(StageError::InvalidOutput)?;
    let spec_bytes = read_for_gate(ctx, &spec_ref).await?;
    let spec = std::str::from_utf8(&spec_bytes)
        .ok()
        .and_then(|text| SpecificationContract::from_json_str(text).ok())
        .ok_or(StageError::InvalidOutput)?;
    let spec_ids = SpecIds::from_contract(&spec);
    let protected = super::risk::protected_paths(&design, &handler.policy);
    let rules = handler.config.rules;
    let commit = &handler.config.definition_commit;

    let asks_a_person = design.status == Status::NeedsHuman;
    let outcome = checks::check(&design, &spec_ids, tier, &protected, &rules);

    // Gate: every requirement has a design element, and the other way round.
    let trace_facts = |outcome: &'static str, title: &str, reason: &str, list: &[Finding]| {
        facts(
            definition(TRACEABILITY_GATE, TRACEABILITY_TEXT, commit),
            outcome,
            title,
            reason,
            failures(list),
            vec![
                format!("design={}", design_named.artifact.sha256),
                format!("specification={}", spec_ref.sha256),
                format!("requirements={}", spec_ids.all().len()),
                format!("findings={}", list.len()),
            ],
        )
    };
    let traceability = if asks_a_person {
        not_applicable(
            &subject(ctx),
            trace_facts("PASSED", "The design is not finished", not_a_design(), &[]),
            NotApplicableCode::NoMatchingFiles,
            NotApplicableDecider::DeterministicRule,
            not_a_design(),
        )?
    } else if outcome.traceability.is_empty() {
        gate_report(
            &subject(ctx),
            &trace_facts(
                "PASSED",
                "Every requirement has a design element",
                "Every requirement and success criterion of the frozen specification is satisfied by a design element, and every design element answers a requirement that exists.",
                &[],
            ),
        )?
    } else {
        gate_report(
            &subject(ctx),
            &trace_facts(
                "FAILED",
                "The design and the specification do not match",
                "The design leaves a requirement without an element, or names a requirement that does not exist.",
                &outcome.traceability,
            ),
        )?
    };

    // Gate: the design is complete.
    let complete_facts = |outcome: &'static str, title: &str, reason: &str, list: &[Finding]| {
        facts(
            definition(COMPLETENESS_GATE, COMPLETENESS_TEXT, commit),
            outcome,
            title,
            reason,
            failures(list),
            vec![
                format!("design={}", design_named.artifact.sha256),
                format!("tier={}", tier.as_str()),
                format!("alternatives={}", checks::alternatives(&design)),
                format!("findings={}", list.len()),
            ],
        )
    };
    let completeness = if asks_a_person {
        not_applicable(
            &subject(ctx),
            complete_facts("PASSED", "The design is not finished", not_a_design(), &[]),
            NotApplicableCode::NoMatchingFiles,
            NotApplicableDecider::DeterministicRule,
            not_a_design(),
        )?
    } else if outcome.completeness.is_empty() {
        let reason = match &outcome.complexity {
            Complexity::Trivial(why) => {
                format!("The design is complete for a trivial change. {why}")
            }
            Complexity::NonTrivial => format!(
                "The design weighed {} alternatives, named how it could fail, and added nothing its requirements do not need.",
                checks::alternatives(&design)
            ),
        };
        gate_report(
            &subject(ctx),
            &complete_facts("PASSED", "The design is complete", &reason, &[]),
        )?
    } else {
        gate_report(
            &subject(ctx),
            &complete_facts(
                "FAILED",
                "The design is not complete",
                "The design lacks alternatives or failure modes for a change that is not trivial, is larger than its requirements justify, repeats an identifier, or touches a protected path.",
                &outcome.completeness,
            ),
        )?
    };

    // Gate: the independent critic.
    let mut human_gate = asks_a_person
        || tier >= rules.human_from
        || design
            .decisions
            .iter()
            .any(|decision| decision.needs_person);
    let why_tier = why_this_tier(&record, tier);
    let critic_facts = |outcome: &'static str,
                        title: &str,
                        reason: &str,
                        list: Vec<(String, String)>,
                        evidence: String| {
        facts(
            definition(CRITIC_GATE, CRITIC_TEXT, commit),
            outcome,
            title,
            &format!("{reason} {why_tier}"),
            list,
            vec![format!("tier={}", tier.as_str()), evidence],
        )
    };
    let critic_report = match &critic_outcome {
        Outcome::NotRequired => {
            let reason = format!(
                "The policy requires an independent critic from the {} tier, and this design is in the {} tier.",
                rules.critic_from.as_str(),
                tier.as_str()
            );
            not_applicable(
                &subject(ctx),
                critic_facts(
                    "PASSED",
                    "No independent critic is required",
                    &reason,
                    Vec::new(),
                    "critic=not-required".into(),
                ),
                NotApplicableCode::PolicyExcludesGate,
                NotApplicableDecider::Policy,
                &reason,
            )?
        }
        Outcome::SkippedDesignFailed => {
            let reason = "The design failed the deterministic checks first and goes back to the architect, so a critic was not asked to review a design that is being changed.";
            not_applicable(
                &subject(ctx),
                critic_facts(
                    "PASSED",
                    "The critic waits for a design that passes the checks",
                    reason,
                    Vec::new(),
                    "critic=skipped".into(),
                ),
                NotApplicableCode::ChangeTypeExcludesGate,
                NotApplicableDecider::DeterministicRule,
                reason,
            )?
        }
        Outcome::Absent(why) => {
            human_gate = true;
            let mut blocked = critic_facts(
                "BLOCKED",
                "No independent critic could review this design",
                &format!(
                    "The policy requires an independent critic from the {} tier and none could be used, so no critic reviewed the design. A person must decide.",
                    rules.critic_from.as_str()
                ),
                Vec::new(),
                format!("critic=absent:{}", why.code()),
            );
            blocked.blocked = Some((
                "tool_unavailable",
                match why {
                    critic::Absent::NoSuchAgent => {
                        "an independent architecture critic: the agent registry has no such agent".to_owned()
                    }
                    critic::Absent::Unusable => {
                        "an independent architecture critic: the agent definition cannot be used as one".to_owned()
                    }
                },
            ));
            gate_report(&subject(ctx), &blocked)?
        }
        Outcome::Ran { agent, review, .. } => {
            if review.asks_a_person() {
                human_gate = true;
                let reason = "The critic could not decide and asked a person, so a person decides.";
                not_applicable(
                    &subject(ctx),
                    critic_facts(
                        "PASSED",
                        "The critic asked a person",
                        reason,
                        Vec::new(),
                        format!("critic={agent}:needs-human"),
                    ),
                    NotApplicableCode::ChangeTypeExcludesGate,
                    NotApplicableDecider::DeterministicRule,
                    reason,
                )?
            } else if review.agrees() {
                gate_report(
                    &subject(ctx),
                    &critic_facts(
                        "PASSED",
                        "The independent critic agrees with the design",
                        "An agent that is not the architect reviewed the design and found nothing that must change.",
                        Vec::new(),
                        format!("critic={agent}:pass"),
                    ),
                )?
            } else {
                let list: Vec<(String, String)> = review
                    .blocking()
                    .iter()
                    .map(|finding| {
                        (
                            finding_id(&finding.id),
                            format!("{} {}", finding.title, finding.description),
                        )
                    })
                    .collect();
                gate_report(
                    &subject(ctx),
                    &critic_facts(
                        "FAILED",
                        "The independent critic does not agree with the design",
                        "An agent that is not the architect reviewed the design and found problems that must be fixed.",
                        list,
                        format!(
                            "critic={agent}:{}",
                            match review.verdict {
                                Verdict::Block => "block",
                                _ => "changes-required",
                            }
                        ),
                    ),
                )?
            }
        }
    };

    // Gate: plain English.
    let texts = design.readable_texts();
    let artifacts: Vec<Artifact<'_>> = texts
        .iter()
        .map(|(title, body)| Artifact::request(title, body))
        .collect();
    let readability: GateReport = readability_report(ctx, commit, &artifacts)?;

    Ok(GateDecision {
        reports: vec![traceability, completeness, critic_report, readability],
        review: None,
        human_gate,
        policy_violation: false,
        assurance: Vec::new(),
    })
}

/// A finding identifier of the critic as a check identifier: lowercase, digits, dot, hyphen and
/// underscore, at most 64 characters.
fn finding_id(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(60)
        .collect();
    let trimmed = cleaned.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() {
        "critic-finding".to_owned()
    } else {
        format!("critic.{trimmed}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_reason_names_the_criteria_the_claim_the_paths_and_the_decisions() {
        let record = json!({ "risk": {
            "tier": "high", "computed": "high", "unclassified": false, "agent_claim": "low",
            "matched": ["public_api_change", "sensitive_file_change"],
            "sensitive_paths": ["Cargo.toml"], "decisions_for_a_person": ["add-a-json-library"],
        }});
        let why = why_this_tier(&record, RiskTier::High);
        assert!(why.starts_with("The design is in the high tier."), "{why}");
        assert!(
            why.contains(
                "the high tier from the criteria that held: `public_api_change`, `sensitive_file_change`."
            ),
            "{why}"
        );
        assert!(
            why.contains("claimed the low tier, and a claim never lowers the tier"),
            "{why}"
        );
        assert!(why.contains("marks sensitive: `Cargo.toml`."), "{why}");
        assert!(why.contains("`add-a-json-library`"), "{why}");
    }

    #[test]
    fn the_reason_says_when_the_claim_raised_the_tier_or_nothing_matched() {
        let raised = json!({ "risk": {
            "tier": "high", "computed": "medium", "unclassified": false, "agent_claim": "high",
            "matched": ["public_api_change"], "sensitive_paths": [], "decisions_for_a_person": [],
        }});
        let why = why_this_tier(&raised, RiskTier::High);
        assert!(
            why.contains("claimed the high tier, which raised it"),
            "{why}"
        );
        assert!(!why.contains("sensitive"), "{why}");
        let unknown = json!({ "risk": {
            "tier": "high", "computed": "high", "unclassified": true, "matched": [],
        }});
        let why = why_this_tier(&unknown, RiskTier::High);
        assert!(
            why.contains("No criterion of the policy held for it"),
            "{why}"
        );
    }

    #[test]
    fn a_long_list_is_cut_so_the_reason_fits_the_report() {
        let paths: Vec<String> = (0..200)
            .map(|i| format!("{}/Cargo.toml", "d".repeat(500 + i)))
            .collect();
        let record = json!({ "risk": {
            "tier": "high", "computed": "high", "unclassified": false,
            "matched": ["sensitive_file_change"], "sensitive_paths": paths,
            "decisions_for_a_person": paths,
        }});
        let why = why_this_tier(&record, RiskTier::High);
        assert!(why.contains("and 192 more"), "{why}");
        // The longest fixed text of a critic report is under 300 characters, and the report
        // allows 4000.
        assert!(why.chars().count() + 300 < 4000, "{}", why.chars().count());
    }
}
