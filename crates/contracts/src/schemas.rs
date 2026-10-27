//! The eleven contract schemas, embedded in the binary at compile time.
//!
//! The text of each schema is read from `schemas/` by `include_str!`, so the compiler rebuilds
//! this crate when a schema file changes and a deployed binary carries the schemas it was tested
//! with. Nothing here reads the file system at run time, which means a schema cannot be swapped
//! after the build.
//!
//! The integration test `schemas_match_the_files_in_the_schemas_directory` (in
//! `tests/schema_examples.rs`) reads the directory and fails when a file is added, removed or
//! differs from its embedded copy.

use factory_ports::registry::ContractKind;

/// The schema major version this build validates against. It is the last segment of every
/// schema's `$id`, such as `urn:ortisun:factory:schema:gate-report:1`.
pub const SCHEMA_VERSION: u32 = 1;

/// One embedded schema.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedSchema {
    /// The kind of document the schema governs.
    pub kind: ContractKind,
    /// The file name inside `schemas/`, such as `gate-report.schema.json`.
    pub file_name: &'static str,
    /// The text of the file.
    pub text: &'static str,
}

macro_rules! embed {
    ($kind:ident, $file:literal) => {
        EmbeddedSchema {
            kind: ContractKind::$kind,
            file_name: $file,
            text: include_str!(concat!("../../../schemas/", $file)),
        }
    };
}

/// Every schema, in the order of [`ContractKind::ALL`].
pub const EMBEDDED: [EmbeddedSchema; 11] = [
    embed!(AgentManifest, "agent-manifest.schema.json"),
    embed!(
        DomainCapabilityProfile,
        "domain-capability-profile.schema.json"
    ),
    embed!(DomainEvent, "domain-event.schema.json"),
    embed!(EvidenceLedgerEntry, "evidence-ledger-entry.schema.json"),
    embed!(EvidenceManifest, "evidence-manifest.schema.json"),
    embed!(GateReport, "gate-report.schema.json"),
    embed!(ProjectManifest, "project-manifest.schema.json"),
    embed!(ReviewVerdict, "review-verdict.schema.json"),
    embed!(SpecificationContract, "specification-contract.schema.json"),
    embed!(StageContract, "stage-contract.schema.json"),
    embed!(TaskDag, "task-dag.schema.json"),
];

/// The embedded schema for a kind.
#[must_use]
pub fn embedded(kind: ContractKind) -> &'static EmbeddedSchema {
    &EMBEDDED[position(kind)]
}

/// Where a kind sits in [`EMBEDDED`]. A `match` with no wildcard arm, so adding a kind to the
/// ports without adding it here does not compile.
const fn position(kind: ContractKind) -> usize {
    match kind {
        ContractKind::AgentManifest => 0,
        ContractKind::DomainCapabilityProfile => 1,
        ContractKind::DomainEvent => 2,
        ContractKind::EvidenceLedgerEntry => 3,
        ContractKind::EvidenceManifest => 4,
        ContractKind::GateReport => 5,
        ContractKind::ProjectManifest => 6,
        ContractKind::ReviewVerdict => 7,
        ContractKind::SpecificationContract => 8,
        ContractKind::StageContract => 9,
        ContractKind::TaskDag => 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_exactly_one_embedded_schema() {
        for kind in ContractKind::ALL {
            let count = EMBEDDED.iter().filter(|schema| schema.kind == kind).count();
            assert_eq!(count, 1, "{kind:?}");
            assert_eq!(EMBEDDED[position(kind)].kind, kind);
            assert_eq!(
                embedded(kind).file_name,
                format!("{}.schema.json", kind.schema_name())
            );
        }
        assert_eq!(EMBEDDED.len(), ContractKind::ALL.len());
    }

    #[test]
    fn every_embedded_schema_declares_its_own_id_and_the_supported_version() {
        for schema in &EMBEDDED {
            let document: serde_json::Value =
                serde_json::from_str(schema.text).expect("the schema is JSON");
            let id = document["$id"].as_str().expect("the schema has an $id");
            assert_eq!(
                id,
                format!(
                    "urn:ortisun:factory:schema:{}:{SCHEMA_VERSION}",
                    schema.kind.schema_name()
                ),
                "{}",
                schema.file_name
            );
            assert_eq!(
                document["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
        }
    }
}
