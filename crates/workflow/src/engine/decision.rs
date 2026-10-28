//! The document that a decision of the engine rests on when no gate produced a report.
//!
//! A stage run that passes, fails or is blocked records a gate outcome, and the store keeps the
//! hash of the report that backs it (`GateRecord::report_sha256`, `None` only for
//! `NOT_APPLICABLE`; ports-v1.1, section 5.2, and the amendment at the end of ADR 0014). A gate
//! hands the engine its own reports. Three decisions have none, because no gate ran:
//!
//! * a person approves a stage run (`S14`): the document names who decided, in which role, and
//!   which evidence they had seen;
//! * the environment is missing or unsafe (`S21`): the document names the cause, so the reason for
//!   a block is not lost with the failed attempt;
//! * a gate could not run or its evidence was refused (`S11`): the document names the engine's
//!   cause. A refused document is neither stored nor cited, so only the cause code appears.
//!
//! The document is small JSON, stored by its hash like every artifact, and indexed for the tenant
//! in the transaction that records the decision, as the stage contract is. The bytes are written
//! to the artifact store after the commit ([`Cx::defer_blob`]).
//!
//! The document is not secret and carries no text a person wrote: identifiers, codes and times.

use factory_domain::ids::StageRunId;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_domain::vocabulary::{GateOutcome, StageKind};
use factory_ports::store::Tx;
use serde_json::{Map, Value, json};

use super::error::EngineError;
use super::record::{Cx, index_entry};

/// The version of the document's shape. A change of field names or meaning raises it.
pub(crate) const SCHEMA_VERSION: u64 = 1;

/// Which decision a document records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecisionKind {
    /// A person approved the stage run.
    HumanApproval,
    /// The environment the stage needs is missing or unsafe.
    EnvironmentBlock,
    /// The engine's own decision about a gate that produced no report.
    GateDecision,
}

impl DecisionKind {
    /// The value of the `kind` field.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::HumanApproval => "human-approval",
            Self::EnvironmentBlock => "environment-block",
            Self::GateDecision => "gate-decision",
        }
    }
}

/// One decision of the engine, as the document states it.
pub(crate) struct DecisionReport<'a> {
    /// Which decision this is.
    pub(crate) kind: DecisionKind,
    /// The gate outcome the decision records on the stage run.
    pub(crate) outcome: GateOutcome,
    /// The stage run the decision is about.
    pub(crate) stage_run: StageRunId,
    /// Its stage.
    pub(crate) stage: StageKind,
    /// The short machine code that says why (the cause of the move).
    pub(crate) cause: &'a str,
    /// Facts specific to the kind: identifiers, codes and hashes. Never free text.
    pub(crate) details: Map<String, Value>,
}

impl DecisionReport<'_> {
    /// The document's bytes. The order of the fields is fixed, so equal decisions at one time give
    /// one hash.
    fn to_bytes(&self, cx: &Cx<'_>) -> Result<Vec<u8>, EngineError> {
        let document = json!({
            "schema_version": SCHEMA_VERSION,
            "kind": self.kind.as_str(),
            "outcome": self.outcome.as_str(),
            "job_id": cx.job.to_string(),
            "stage_run_id": self.stage_run.to_string(),
            "stage": self.stage.as_str(),
            "cause": self.cause,
            "recorded_at": cx.now.as_text(),
            "details": Value::Object(self.details.clone()),
        });
        serde_json::to_vec(&document).map_err(|error| EngineError::Invalid(error.to_string()))
    }
}

impl Cx<'_> {
    /// Stores the document of a decision that has no gate report, indexes it for the tenant in
    /// this transaction, and returns its hash for the gate record.
    ///
    /// # Errors
    /// The store errors of the index write.
    pub(crate) async fn record_decision(
        &self,
        tx: &mut dyn Tx,
        report: &DecisionReport<'_>,
    ) -> Result<Sha256Digest, EngineError> {
        let bytes = report.to_bytes(self)?;
        let stored = self.defer_blob(bytes, MediaType::parse("application/json")?);
        tx.index_artifact(index_entry(&stored, self.job, report.stage_run)?)
            .await?;
        Ok(stored.sha256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_has_its_own_name() {
        let names = [
            DecisionKind::HumanApproval,
            DecisionKind::EnvironmentBlock,
            DecisionKind::GateDecision,
        ]
        .map(DecisionKind::as_str);
        assert_eq!(
            names,
            ["human-approval", "environment-block", "gate-decision"]
        );
    }
}
