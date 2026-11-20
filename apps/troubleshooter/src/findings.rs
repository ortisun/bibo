//! What the troubleshooter accepts from its agent, and the findings it raises on its own.
//!
//! # The report
//!
//! The agent's bytes go through the `health-findings` v1 schema first (size, UTF-8, depth, a
//! strict parse that refuses a repeated key, then the closed schema). A report that fails is
//! `report_invalid` and nothing is filed from it.
//!
//! # The evidence (ADR 0021 Decision 7, security review finding TR-5)
//!
//! Every observation of every finding cites a call id. It is accepted only when all three hold:
//!
//! 1. the id is in this run's gateway record (agent calls and the probes' control-plane calls
//!    share one record and one numbering);
//! 2. that call ended `ok`: a refused, timed-out, failed or erroring call showed nothing to cite;
//! 3. the observation's `tool` is the gateway tool the record holds for that call.
//!
//! One observation that fails refuses the whole report (`evidence_mismatch`): a report that
//! invents one citation cannot be trusted for the others. The check reads only the public record
//! (`RunRecord::call`, the call's `outcome` and `gateway_tool`).
//!
//! # The fingerprint (finding TR-8)
//!
//! The fingerprint of a finding is computed from what code knows, never from the tools the agent
//! chose to cite: the probes of this run that tripped and that the finding names, or, when it
//! names none of them, its category and component alone. The domain's fingerprint uses the
//! observation tools when a finding has no probe, so a finding without a tripped probe is handed
//! to it with the one code-chosen source [`SWEEP_SOURCE`] in place of the agent's probe list.
//!
//! # Findings without the model
//!
//! A source that did not answer a probe is a `source_unavailable` finding (Decision 2), one per
//! source, citing the probe calls that failed. Code writes every field.

use std::collections::BTreeSet;

use factory_contracts::agent_schema::AgentSchema;
use factory_domain::policy::troubleshooting::Upstream;
use factory_domain::redaction::Redactor;
use factory_domain::troubleshooting::{
    Finding, FindingCategory, FindingComponent, FindingSeverity, GatewayToolName, Observation,
};
use factory_domain::values::Slug;
use factory_mcp_gateway::{Outcome, RunRecord};
use factory_storage::pg::troubleshooting::ProbeOutcome;
use serde::Deserialize;

use crate::probes::{ProbeObservation, gateway_tool};

/// The one source a finding without a tripped probe is fingerprinted by: its category and
/// component then make the fingerprint.
pub const SWEEP_SOURCE: &str = "sweep";

/// The status of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Nothing is wrong.
    Healthy,
    /// At least one finding.
    Findings,
    /// A person must answer a question.
    NeedsHuman,
    /// The run could not investigate.
    Blocked,
}

/// A report that passed the schema.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Report {
    /// The status.
    pub status: ReportStatus,
    /// The findings.
    pub findings: Vec<Finding>,
}

/// Why a report was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The bytes did not pass the `health-findings` schema.
    Invalid(String),
    /// An observation cites a call that is not citable: the id, and why.
    Evidence(String),
}

/// Checks the report bytes against the schema, then every citation against the gateway record.
///
/// # Errors
/// [`Refused`].
pub fn check_report(
    bytes: &[u8],
    schema: &AgentSchema,
    record: &RunRecord,
) -> Result<Report, Refused> {
    let value = schema.parse_and_validate(bytes).map_err(|issues| {
        Refused::Invalid(format!(
            "{} problem(s) against health-findings v1",
            issues.len()
        ))
    })?;
    let report: Report = serde_json::from_value(value)
        .map_err(|_| Refused::Invalid("the findings do not read as findings".to_owned()))?;
    for finding in &report.findings {
        for observation in &finding.observations {
            citable(observation, record)?;
        }
    }
    Ok(report)
}

/// Whether one observation cites a call it may cite (rules 1 to 3 of the module notes).
///
/// # Errors
/// [`Refused::Evidence`].
pub fn citable(observation: &Observation, record: &RunRecord) -> Result<(), Refused> {
    let id = observation.call_id.as_str();
    let call = record
        .call(id)
        .ok_or_else(|| Refused::Evidence(format!("{id} is not in the run's gateway record")))?;
    if call.outcome != Outcome::Ok {
        return Err(Refused::Evidence(format!(
            "{id} ended {} and showed nothing to cite",
            call.outcome
        )));
    }
    if call.gateway_tool != observation.tool.as_str() {
        return Err(Refused::Evidence(format!(
            "{id} was a call of another tool than the one the observation names"
        )));
    }
    Ok(())
}

/// The finding as the renderer gets it: the agent's texts redacted with the factory's redactor,
/// and the probe list replaced by the code-derived sources of the fingerprint (TR-8). `None` when
/// a text cannot be checked for secrets: the finding is then not filed.
#[must_use]
pub fn prepared(finding: &Finding, tripped: &[String], redactor: &Redactor) -> Option<Finding> {
    let clean = |text: &str| -> Option<String> {
        redactor
            .redact_str(text)
            .ok()
            .map(|redacted| redacted.output.into_owned())
    };
    let tripped: BTreeSet<&str> = tripped.iter().map(String::as_str).collect();
    let mut probes: Vec<Slug> = finding
        .probe_ids
        .iter()
        .filter(|probe| tripped.contains(probe.as_str()))
        .cloned()
        .collect();
    if probes.is_empty() {
        probes.push(Slug::parse(SWEEP_SOURCE).ok()?);
    }
    let mut observations = Vec::with_capacity(finding.observations.len());
    for observation in &finding.observations {
        observations.push(Observation {
            call_id: observation.call_id.clone(),
            tool: observation.tool.clone(),
            observed: clean(&observation.observed)?,
        });
    }
    Some(Finding {
        category: finding.category,
        severity: finding.severity,
        component: finding.component,
        title: clean(&finding.title)?,
        probe_ids: probes,
        observations,
        hypothesis: clean(&finding.hypothesis)?,
        confidence: finding.confidence,
        next_checks: finding
            .next_checks
            .iter()
            .map(|check| clean(check))
            .collect::<Option<Vec<_>>>()?,
    })
}

/// The `source_unavailable` findings of a probe pass: one per source whose probes could not run
/// and whose calls the gateway recorded. Code writes every field; no model is involved.
#[must_use]
pub fn source_unavailable(observations: &[ProbeObservation]) -> Vec<Finding> {
    let mut found = Vec::new();
    for upstream in Upstream::ALL {
        let failed: Vec<&ProbeObservation> = observations
            .iter()
            .filter(|o| {
                o.outcome == ProbeOutcome::SourceUnavailable && o.upstream == Some(upstream)
            })
            .collect();
        let cited: Vec<Observation> = failed
            .iter()
            .filter_map(|o| {
                let (tool, _) = gateway_tool(o.probe.kind)?;
                Some(Observation {
                    call_id: o.call_id.clone()?,
                    tool: GatewayToolName::parse(tool).ok()?,
                    observed: format!(
                        "The probe {} could not run: the call to {} ended {}.",
                        o.probe.id,
                        upstream.as_str(),
                        o.reason.as_deref().unwrap_or("without an answer")
                    ),
                })
            })
            .collect();
        if cited.is_empty() {
            continue;
        }
        let (category, component) = match upstream {
            Upstream::Postgres => (FindingCategory::Database, FindingComponent::Database),
            Upstream::Victoriametrics | Upstream::Datadog => {
                (FindingCategory::TelemetryGap, FindingComponent::Telemetry)
            }
        };
        let mut probe_ids: Vec<Slug> = failed
            .iter()
            .filter_map(|o| Slug::parse(&o.probe.id).ok())
            .collect();
        probe_ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        probe_ids.dedup();
        found.push(Finding {
            category,
            severity: FindingSeverity::High,
            component,
            title: format!(
                "Source unavailable: {} did not answer the probes",
                upstream.as_str()
            ),
            probe_ids,
            observations: cited,
            hypothesis: format!(
                "The troubleshooter could not read {} through its gateway, so the probes that \
                 depend on it say nothing. The source, the gateway's credential for it, or the \
                 network between them may be down.",
                upstream.as_str()
            ),
            confidence: 1.0,
            next_checks: vec![format!(
                "Check that {} is up and that the troubleshooter's credential for it is valid.",
                upstream.as_str()
            )],
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::troubleshooting::FindingFingerprint;

    fn finding(probes: &[&str], tool: &str) -> Finding {
        serde_json::from_value(serde_json::json!({
            "category": "retries",
            "severity": "medium",
            "component": "worker",
            "title": "Retries pile up",
            "probe_ids": probes,
            "observations": [{"call_id": "call-3", "tool": tool, "observed": "It rose by twelve."}],
            "hypothesis": "The sandbox fails its self-check.",
            "confidence": 0.5,
            "next_checks": ["Read the failure classes of the last hour."]
        }))
        .expect("a finding")
    }

    fn redactor() -> Redactor {
        Redactor::builder().build().expect("a redactor")
    }

    #[test]
    fn the_fingerprint_comes_from_the_tripped_probes_the_finding_names() {
        let tripped = vec!["retries".to_owned()];
        let ready = prepared(
            &finding(&["retries", "not_tripped"], "vm_query"),
            &tripped,
            &redactor(),
        )
        .expect("prepared");
        let probes: Vec<&str> = ready.probe_ids.iter().map(Slug::as_str).collect();
        assert_eq!(
            probes,
            ["retries"],
            "a probe that did not trip in this run is dropped"
        );
        assert_eq!(
            FindingFingerprint::of(&ready),
            FindingFingerprint::compute(
                FindingCategory::Retries,
                FindingComponent::Worker,
                &["retries"]
            )
        );
    }

    #[test]
    fn without_a_tripped_probe_the_cited_tools_do_not_change_the_fingerprint() {
        let none: Vec<String> = Vec::new();
        let one = prepared(&finding(&[], "vm_query"), &none, &redactor()).expect("prepared");
        let other =
            prepared(&finding(&["made_up"], "pg_query"), &none, &redactor()).expect("prepared");
        assert_eq!(FindingFingerprint::of(&one), FindingFingerprint::of(&other));
        assert_eq!(
            FindingFingerprint::of(&one),
            FindingFingerprint::compute(
                FindingCategory::Retries,
                FindingComponent::Worker,
                &[SWEEP_SOURCE]
            )
        );
    }

    #[test]
    fn agent_text_is_redacted_before_rendering() {
        let redactor = redactor();
        redactor
            .register("planted", "planted-value-for-a-redaction-test")
            .expect("registered");
        let mut leaky = finding(&[], "vm_query");
        leaky.hypothesis = "It printed planted-value-for-a-redaction-test in a log.".to_owned();
        let ready = prepared(&leaky, &[], &redactor).expect("prepared");
        assert!(
            !ready
                .hypothesis
                .contains("planted-value-for-a-redaction-test")
        );
    }
}
