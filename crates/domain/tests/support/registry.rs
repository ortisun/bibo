//! Which Rust type reads which schema.

use factory_domain::contracts::{
    AgentManifest, Contract, DomainCapabilityProfile, DomainEvent, EvidenceLedgerEntry,
    EvidenceManifest, GateReport, ProjectManifest, ReviewVerdict, SpecificationContract,
    StageContract, TaskDag,
};
use serde_json::Value;

/// Reads `text` as the type registered for `schema` and writes it back as a JSON value.
pub fn round_trip(schema: &str, text: &str) -> Result<Value, String> {
    fn through<T: Contract>(text: &str) -> Result<Value, String> {
        let value = T::from_json_str(text).map_err(|error| error.to_string())?;
        value.to_json_value().map_err(|error| error.to_string())
    }
    match schema {
        "agent-manifest" => through::<AgentManifest>(text),
        "domain-capability-profile" => through::<DomainCapabilityProfile>(text),
        "domain-event" => through::<DomainEvent>(text),
        "evidence-ledger-entry" => through::<EvidenceLedgerEntry>(text),
        "evidence-manifest" => through::<EvidenceManifest>(text),
        "gate-report" => through::<GateReport>(text),
        "project-manifest" => through::<ProjectManifest>(text),
        "review-verdict" => through::<ReviewVerdict>(text),
        "specification-contract" => through::<SpecificationContract>(text),
        "stage-contract" => through::<StageContract>(text),
        "task-dag" => through::<TaskDag>(text),
        other => panic!("no Rust type is registered for the schema {other}"),
    }
}

/// Like [`round_trip`], for a document that is already a JSON value.
pub fn round_trip_value(schema: &str, value: &Value) -> Result<Value, String> {
    round_trip(schema, &value.to_string())
}
