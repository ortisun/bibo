//! Types and macros shared by the two policy documents.

use std::fmt;

use regex::Regex;
use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};

/// Declares a struct that rejects unknown keys. Every struct in the policy documents is declared
/// with it, so an unknown key is an error at any depth, never ignored (the parser contract in the
/// header of `policies/security.yaml`).
macro_rules! strict {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            $( $(#[$fmeta:meta])* pub $field:ident : $ty:ty ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            $( $(#[$fmeta])* pub $field : $ty ),*
        }
    };
}
pub(crate) use strict;

/// Declares a closed set of values that a policy document spells in `snake_case`.
macro_rules! closed_set {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name {
            $( $(#[$vmeta])* $variant ),+
        }
    };
}
pub(crate) use closed_set;

/// The only schema version this build reads. A document with another number is refused before
/// anything else about it is looked at, and a value that gets past that check is refused here too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaVersionOne;

/// The version number written as `schema_version`.
pub const SUPPORTED_SCHEMA_VERSION: u64 = 1;

impl Serialize for SchemaVersionOne {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(SUPPORTED_SCHEMA_VERSION)
    }
}

impl<'de> Deserialize<'de> for SchemaVersionOne {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = SchemaVersionOne;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "the number {SUPPORTED_SCHEMA_VERSION}")
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<SchemaVersionOne, E> {
                if v == SUPPORTED_SCHEMA_VERSION {
                    Ok(SchemaVersionOne)
                } else {
                    Err(E::custom(format!(
                        "schema_version is {v} but this build reads only version {SUPPORTED_SCHEMA_VERSION}"
                    )))
                }
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<SchemaVersionOne, E> {
                u64::try_from(v)
                    .map_err(|_| E::custom("schema_version must be a positive whole number"))
                    .and_then(|v| self.visit_u64(v))
            }
        }
        deserializer.deserialize_any(V)
    }
}

/// A threat identifier such as `T-15`. The set of known threats is in the threat model, and a test
/// (ST-06) checks that every identifier a policy cites exists there.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct ThreatId(String);

impl ThreatId {
    /// The text, such as `T-15`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ThreatId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let well_formed = text.len() == 4
            && text.starts_with("T-")
            && text[2..].bytes().all(|b| b.is_ascii_digit());
        if well_formed {
            Ok(Self(text))
        } else {
            Err(de::Error::custom(
                "a threat identifier is `T-` and two digits, such as `T-15`",
            ))
        }
    }
}

closed_set! {
    /// Whether a policy document is only designed or enforced by product code.
    pub enum PolicyStatus {
        /// Written, not yet enforced. No product code depends on it.
        Designed,
        /// Enforced. Its owner flips this when the tests pass.
        Enforced,
    }
}

closed_set! {
    /// How two matching rules combine. The only value is the one that makes a deny win.
    pub enum ConflictResolution {
        /// Any matching deny wins over any allow.
        DenyOverrides,
    }
}

closed_set! {
    /// What a project-local policy may do to the central one. The only value is tightening.
    pub enum ProjectOverrides {
        /// May add protected paths, add forbidden commands, remove egress hosts and lower
        /// limits. May never widen anything.
        TightenOnly,
    }
}

closed_set! {
    /// Where the policy file must be read from.
    pub enum ConfigSource {
        /// The protected default branch of the factory configuration source.
        ProtectedDefaultBranch,
        /// A signed release artifact.
        SignedRelease,
    }
}

/// A regular expression field. It is kept as text, and the loader proves it compiles in the
/// dialect the policy names (the Rust `regex` crate: RE2-like, no look-around, no
/// back-references, linear time).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RegexText(pub String);

impl RegexText {
    /// Compiles the expression, with a size limit so a huge pattern cannot be built.
    ///
    /// # Errors
    /// The compiler's message.
    pub fn compile(&self) -> Result<Regex, String> {
        regex::RegexBuilder::new(&self.0)
            .size_limit(1 << 20)
            .build()
            .map_err(|e| e.to_string())
    }
}

/// A glob field. The loader proves it compiles in the dialect the policy names (the Rust `globset`
/// crate: `**` crosses directories, `*` and `?` do not cross `/`, `{a,b}` is allowed). A leading
/// `!` marks a re-inclusion, which the loader applies last, and is not part of the glob.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GlobText(pub String);

impl GlobText {
    /// The glob without a leading `!`.
    #[must_use]
    pub fn pattern(&self) -> &str {
        self.0.strip_prefix('!').unwrap_or(&self.0)
    }

    /// True when the glob re-includes paths an earlier glob excluded.
    #[must_use]
    pub fn is_reinclusion(&self) -> bool {
        self.0.starts_with('!')
    }

    /// Compiles the glob with `*` and `?` not crossing `/`.
    ///
    /// # Errors
    /// The compiler's message.
    pub fn compile(&self) -> Result<globset::Glob, String> {
        globset::GlobBuilder::new(self.pattern())
            .literal_separator(true)
            .build()
            .map_err(|e| e.to_string())
    }
}
