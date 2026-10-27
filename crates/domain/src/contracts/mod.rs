//! One Rust type for each contract schema in `schemas/`.
//!
//! The types are written by hand and mirror the schemas field for field. Three things keep them
//! honest:
//!
//! * Shapes live in the types. A closed set is an enum, an identifier or a hash is a checked
//!   wrapper, an array that must not be empty is a [`NonEmptyVec`](crate::values::NonEmptyVec),
//!   and an object that allows no extra fields says so with `deny_unknown_fields`.
//! * Rules that a schema writes with `if` and `then` ("a PASSED report needs every command to
//!   exit with code 0") are checked when a document is read. A document that breaks one is
//!   rejected, so a value of one of these types is always valid. The same check is available as
//!   [`Contract::validate`] for values built in code.
//! * `tests/contract_examples.rs` reads every example in `schemas/examples`, and compares
//!   patterns, closed sets, required fields and unknown fields with the schema files.
//!
//! Where a type is stricter than its schema, the doc comment says so and why.

mod violations;

pub mod agent_manifest;
pub mod common;
pub mod domain_capability_profile;
pub mod domain_event;
pub mod evidence_ledger_entry;
pub mod evidence_manifest;
pub mod gate_report;
pub mod project_manifest;
pub mod review_verdict;
pub mod specification_contract;
pub mod stage_contract;
pub mod task_dag;

pub use agent_manifest::AgentManifest;
pub use common::{ArtifactRef, SchemaRef, SchemaVersion, VersionedRef};
pub use domain_capability_profile::DomainCapabilityProfile;
pub use domain_event::DomainEvent;
pub use evidence_ledger_entry::EvidenceLedgerEntry;
pub use evidence_manifest::EvidenceManifest;
pub use gate_report::GateReport;
pub use project_manifest::ProjectManifest;
pub use review_verdict::ReviewVerdict;
pub use specification_contract::SpecificationContract;
pub use stage_contract::StageContract;
pub use task_dag::TaskDag;
pub use violations::{Violation, Violations};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// A document type that mirrors one schema file.
///
/// Reading a document through `serde` already runs [`validate`](Contract::validate), so a value
/// that came from a document is valid. `validate` matters for a value built or changed in code.
pub trait Contract: Serialize + DeserializeOwned + Sized {
    /// The schema's file stem, such as `gate-report`.
    const SCHEMA: &'static str;

    /// Every rule the value breaks, including the ones a schema writes with `if` and `then`.
    fn violations(&self) -> Violations;

    /// Succeeds when the value breaks no rule.
    ///
    /// # Errors
    /// Returns every broken rule.
    fn validate(&self) -> Result<(), Violations> {
        self.violations().into_result()
    }

    /// Reads a JSON document and checks it.
    ///
    /// # Errors
    /// Returns the first shape problem, or all rule breaks if the shape is right.
    fn from_json_str(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// Reads a JSON value and checks it.
    ///
    /// # Errors
    /// Returns the first shape problem, or all rule breaks if the shape is right.
    fn from_json_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }

    /// Writes the document as a JSON value.
    ///
    /// # Errors
    /// Returns an error only if a value cannot be represented in JSON, which no field of these
    /// types can cause.
    fn to_json_value(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

/// Defines a contract document: the public struct, a `Serialize` that writes it, a `Deserialize`
/// that reads it and checks its rules, and the [`Contract`] impl.
///
/// The struct is written once, between the braces, with serde attributes on its fields. The macro
/// copies the fields into a private "wire" struct that derives `Deserialize` with
/// `deny_unknown_fields`, reads that, moves the fields into the public struct and calls
/// [`Contract::validate`]. The only public `Deserialize` is therefore the validating one. (A
/// shortcut with `#[serde(remote = "Self")]` was tried and dropped: it adds a public inherent
/// `deserialize` that skips the check and that a call like `Document::deserialize(d)` picks
/// first.) The struct needs `fn check(&self, &mut Violations)`.
macro_rules! contract {
    (
        $schema:literal;
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $( $(#[$fmeta:meta])* $fvis:vis $field:ident : $ty:ty ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $( $(#[$fmeta])* $fvis $field : $ty ),*
        }

        const _: () = {
            #[derive(::serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Wire {
                $( $(#[$fmeta])* $field : $ty ),*
            }

            impl<'de> ::serde::Deserialize<'de> for $name {
                fn deserialize<D: ::serde::Deserializer<'de>>(
                    deserializer: D,
                ) -> Result<Self, D::Error> {
                    let wire = <Wire as ::serde::Deserialize>::deserialize(deserializer)?;
                    let document = $name { $( $field : wire.$field ),* };
                    $crate::contracts::Contract::validate(&document)
                        .map_err(::serde::de::Error::custom)?;
                    Ok(document)
                }
            }
        };

        impl $crate::contracts::Contract for $name {
            const SCHEMA: &'static str = $schema;

            fn violations(&self) -> $crate::contracts::Violations {
                let mut found = $crate::contracts::Violations::new();
                self.check(&mut found);
                found
            }
        }
    };
}
pub(crate) use contract;
