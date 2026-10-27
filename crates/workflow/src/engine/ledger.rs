//! Writing to the evidence ledger (ADR 0008).
//!
//! One entry is one claim bound to the evidence behind it. Entries of a job form a hash chain:
//! the domain computes the hash, the store checks the previous hash and the position on every
//! append, and the engine runs the verifier before it completes a job (`J13`).
//!
//! Every entry the engine writes names the execution mode of the job and the fidelity of the
//! component that made it. In a production run every component is real, because the engine
//! refuses to start with a fake. In test mode an entry made through a fake is labelled `fake`, and
//! the domain refuses a `fake` entry that claims an assurance level (INV-08).

use factory_domain::contracts::Contract;
use factory_domain::contracts::EvidenceLedgerEntry;
use factory_domain::contracts::evidence_ledger_entry::{ClaimKind, Evidence};
use factory_domain::ids::{AttemptId, StageRunId};
use factory_domain::ledger::verify_chain;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{AssuranceLevel, ConfidenceLevel};
use factory_ports::store::Tx;
use serde_json::{Value, json};

use super::error::EngineError;
use super::record::{COMPONENT, Cx};

/// A claim to record.
#[derive(Debug, Clone)]
pub(crate) struct ClaimSpec {
    /// What is claimed, in plain English. At least ten characters.
    pub(crate) statement: String,
    /// Fact, simulation, assumption, hypothesis or judgment.
    pub(crate) kind: ClaimKind,
    /// The assurance level the claim supports, if any.
    pub(crate) assurance_level: Option<AssuranceLevel>,
    /// How sure the engine is.
    pub(crate) confidence: ConfidenceLevel,
    /// Why, in plain English.
    pub(crate) rationale: String,
}

/// How many entries one read asks for.
const PAGE: u32 = 500;

impl Cx<'_> {
    /// Appends one entry after the job's current head and returns its hash.
    ///
    /// # Errors
    /// The store errors of the append (`Conflict` when another writer appended first), and
    /// [`EngineError::Invalid`] when the domain refuses the entry.
    pub(crate) async fn record_claim(
        &self,
        tx: &mut dyn Tx,
        run: StageRunId,
        attempt: Option<AttemptId>,
        spec: &ClaimSpec,
        evidence: &[Evidence],
    ) -> Result<Sha256Digest, EngineError> {
        let head = tx.ledger_head(self.job).await?;
        let (sequence, previous) = match &head {
            Some(head) => (head.sequence + 1, Some(head.hash.to_string())),
            None => (1, None),
        };
        let mut claim = json!({ "statement": spec.statement, "kind": spec.kind.as_str() });
        if let (Some(level), Some(object)) = (spec.assurance_level, claim.as_object_mut()) {
            object.insert("assurance_level".to_owned(), json!(level.as_str()));
        }
        let mut metadata = json!({
            "entry_id": uuid_text(self.engine.deps.ids.new_uuid()),
            "job_id": self.job.to_string(),
            "stage_run_id": run.to_string(),
            "sequence": sequence,
            "recorded_at": self.now.to_string(),
            "execution_mode": self.engine.config.mode.as_str(),
            "recorded_by": {
                "component": COMPONENT,
                "fidelity": self.engine.fidelity.as_str(),
            },
        });
        if let (Some(attempt), Some(object)) = (attempt, metadata.as_object_mut()) {
            object.insert("attempt_id".to_owned(), json!(attempt.to_string()));
        }
        let evidence_values = evidence
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<Value>, _>>()
            .map_err(|error| EngineError::Invalid(error.to_string()))?;
        let document = json!({
            "schema_version": 1,
            "metadata": metadata,
            "claim": claim,
            "evidence": evidence_values,
            "confidence": { "level": spec.confidence.as_str(), "rationale": spec.rationale },
            "prev_entry_hash": previous,
            "entry_hash": format!("sha256:{}", "0".repeat(64)),
        });
        let entry = EvidenceLedgerEntry::from_json_value(document)
            .map_err(|error| EngineError::Invalid(error.to_string()))?
            .sealed()
            .map_err(|error| EngineError::Invalid(error.to_string()))?;
        let hash = entry.entry_hash.clone();
        tx.append_ledger_entry(entry).await?;
        Ok(hash)
    }
}

fn uuid_text(uuid: uuid::Uuid) -> String {
    uuid.hyphenated().to_string()
}

/// Reads the whole ledger of a job, oldest entry first.
///
/// # Errors
/// The store errors of the read.
pub(crate) async fn read_all_ledger(
    tx: &mut dyn Tx,
    job: factory_domain::ids::JobId,
) -> Result<Vec<EvidenceLedgerEntry>, EngineError> {
    let mut entries = Vec::new();
    let mut from = 1_u64;
    loop {
        let page = tx.read_ledger(job, from, PAGE).await?;
        let count = page.len();
        entries.extend(page);
        if count < PAGE as usize {
            return Ok(entries);
        }
        from = from.saturating_add(u64::from(PAGE));
    }
}

/// Reads the whole ledger of a job and checks its hash chain.
///
/// # Errors
/// The store errors of the read. A chain that does not verify is `Ok(false)`: it is a finding, not
/// a fault of the read.
pub(crate) async fn ledger_verifies(
    tx: &mut dyn Tx,
    job: factory_domain::ids::JobId,
) -> Result<bool, EngineError> {
    let entries = read_all_ledger(tx, job).await?;
    Ok(verify_chain(&entries).is_ok())
}
