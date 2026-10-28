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
    let critic_facts = |outcome: &'static str,
                        title: &str,
                        reason: &str,
                        list: Vec<(String, String)>,
                        evidence: String| {
        facts(
            definition(CRITIC_GATE, CRITIC_TEXT, commit),
            outcome,
            title,
            reason,
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
                "The policy requires an independent critic for this risk tier and none could be used, so no critic reviewed the design. A person must decide.",
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
