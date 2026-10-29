//! The `RiskSource` seam of the architecture and planning stages.
//!
//! What is known about the risk of a job before its design exists comes from the intake stage.
//! The normalized request that intake stored carries the classifier's `risk_hint`. That hint is
//! an agent's claim: it can raise the tier the policy engine computes and never lowers it, so it
//! goes into [`JobRisk::agent_claim`] and nowhere else. The factual flags ([`RiskFacts`]) are what
//! the factory knows about the domain. Slice 1 resolves one static profile, `general-software`
//! (`crates/workflow` deferred list, "domain_registry"), which states no regulated workflow, no
//! money movement, no physical actuation and no production data access, so every flag is false.
//! A second profile would add its flags here and nowhere else.
//!
//! A job whose intake cannot be read, or whose hint is missing or not a tier, is `Unavailable`:
//! the stage fails closed and does not guess a low tier.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::policy::risk::RiskFacts;
use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::artifact::ArtifactStore;
use factory_ports::store::Store;
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::architecture::seams::{JobRisk, RiskSource};
use factory_workflow::stages::intake::seams::SeamError;

use crate::reading::Reader;

/// The deliverable of the intake stage that holds the classification.
const NORMALIZED_REQUEST: &str = "normalized-request";

/// Reads the risk of a job from its intake.
#[derive(Clone)]
pub struct StoreRisk {
    reader: Reader,
}

impl StoreRisk {
    /// A source over the store and the artifact store.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, artifacts: Arc<dyn ArtifactStore>) -> Self {
        Self {
            reader: Reader::new(store, artifacts),
        }
    }
}

/// The tier a hint names.
fn tier(hint: &str) -> Option<RiskTier> {
    match hint {
        "low" => Some(RiskTier::Low),
        "medium" => Some(RiskTier::Medium),
        "high" => Some(RiskTier::High),
        "critical" => Some(RiskTier::Critical),
        _ => None,
    }
}

#[async_trait]
impl RiskSource for StoreRisk {
    fn fidelity(&self) -> Fidelity {
        self.reader.fidelity()
    }

    async fn of(&self, run: &RunIdentity) -> Result<JobRisk, SeamError> {
        let mut tx = self.reader.begin(run.tenant).await?;
        let outcome = async {
            let runs = tx
                .list_stage_runs(run.job)
                .await
                .map_err(|_| SeamError::Unavailable)?;
            let intake = runs
                .iter()
                .rfind(|candidate| {
                    candidate.value.kind == StageKind::Intake
                        && candidate.value.status == StageRunStatus::Passed
                })
                .ok_or(SeamError::Unavailable)?;
            let outputs = Reader::outputs(&mut *tx, intake.value.id).await?;
            let hash = outputs
                .get(NORMALIZED_REQUEST)
                .ok_or(SeamError::Unavailable)?;
            let bytes = self
                .reader
                .bytes(&mut *tx, run.tenant, hash)
                .await
                .map_err(|_| SeamError::Unavailable)?;
            let hint = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| {
                    value
                        .get("risk_hint")
                        .and_then(serde_json::Value::as_str)
                        .and_then(tier)
                })
                .ok_or(SeamError::Unavailable)?;
            Ok(JobRisk {
                facts: RiskFacts::default(),
                agent_claim: Some(hint),
            })
        }
        .await;
        let _ = tx.rollback().await;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hint_names_a_tier_and_nothing_else_does() {
        assert_eq!(tier("low"), Some(RiskTier::Low));
        assert_eq!(tier("critical"), Some(RiskTier::Critical));
        assert_eq!(tier("LOW"), None);
        assert_eq!(tier("none"), None);
        assert_eq!(tier(""), None);
    }
}
