//! Pieces that several contracts share.

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::ValueError;
use crate::macros::{patterned_string, string_enum};
use crate::patterns;
use crate::values::{MediaType, NonNegativeInt, PositiveInt, SemanticVersion, Sha256Digest, Slug};

/// The only schema version this crate reads and writes. A document with another version is
/// refused, because the rules for it are in another schema file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SchemaVersion;

impl SchemaVersion {
    /// The number as written in documents.
    pub const NUMBER: u64 = 1;
}

impl Serialize for SchemaVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(Self::NUMBER)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let number = <u64 as Deserialize>::deserialize(deserializer)?;
        if number == Self::NUMBER {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(format!(
                "schema version {number} is not supported: this crate reads schema version {}",
                Self::NUMBER
            )))
        }
    }
}

/// Defines a field that has exactly one allowed string value.
macro_rules! const_string {
    ($(#[$meta:meta])* $name:ident ($what:literal) = $value:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name;

        impl $name {
            /// The one allowed value.
            pub const VALUE: &'static str = $value;
        }

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(Self::VALUE)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = <String as Deserialize>::deserialize(deserializer)?;
                if text == Self::VALUE {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::custom(ValueError::new(
                        $what,
                        &text,
                        concat!("the only allowed value is ", $value),
                    )))
                }
            }
        }
    };
}

const_string! {
    /// An agent never gets access to production. The field exists so that the document says so.
    ProductionAccessNone("production access") = "none"
}

const_string! {
    /// A review listed in an evidence manifest has passed. Reviews that did not pass block delivery.
    PassVerdict("review verdict") = "PASS"
}

const_string! {
    /// The marker Spec Kit leaves in a specification where a decision is missing.
    NeedsClarification("source marker") = "NEEDS CLARIFICATION"
}

/// The builder's own account of its work is never part of a review. The field is always `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BuilderSummaryNotSeen;

impl Serialize for BuilderSummaryNotSeen {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(false)
    }
}

impl<'de> Deserialize<'de> for BuilderSummaryNotSeen {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if <bool as Deserialize>::deserialize(deserializer)? {
            Err(serde::de::Error::custom(
                "the reviewer saw the builder's own account of the work, which a review must never see",
            ))
        } else {
            Ok(Self)
        }
    }
}

/// Reads a field that must be present but may be `null`.
///
/// Serde treats a missing `Option` field as `None`, which would let a document leave out a field
/// that the schema requires. With this function the key must be there.
pub(crate) fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// A pointer to an immutable stored artifact, by content hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    /// The content hash.
    pub sha256: Sha256Digest,
    /// What kind of bytes it is.
    pub media_type: MediaType,
    /// The size, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<NonNegativeInt>,
}

/// A reference to a versioned JSON Schema by name, version and content hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaRef {
    /// The schema's name.
    pub name: Slug,
    /// Its major version.
    pub version: PositiveInt,
    /// The hash of the schema file.
    pub sha256: Sha256Digest,
}

/// An agent or skill and the version of it that was used.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedRef {
    /// The identifier.
    pub id: Slug,
    /// The semantic version.
    pub version: SemanticVersion,
}

patterned_string! {
    /// A Spec Kit requirement id such as `FR-001`. Machine metadata, never a title.
    pub struct RequirementId("requirement id") = patterns::REQUIREMENT_ID,
        "use FR- followed by at least three digits, for example FR-001"
}

patterned_string! {
    /// A Spec Kit acceptance scenario id such as `AS-001`. Machine metadata, never a title.
    pub struct ScenarioId("acceptance scenario id") = patterns::SCENARIO_ID,
        "use AS- followed by at least three digits, for example AS-001"
}

string_enum! {
    /// Whether an agent may reach the network.
    pub enum NetworkMode("network mode") {
        /// No network at all.
        None = "none",
        /// Only the hosts on the allow list.
        Allowlist = "allowlist",
    }
}

string_enum! {
    /// How an agent may run commands. There is no value for an unrestricted shell.
    pub enum ShellMode("shell mode") {
        /// No commands.
        None = "none",
        /// Typed commands inside the sandbox.
        SandboxedTypedWrapper = "sandboxed_typed_wrapper",
    }
}
