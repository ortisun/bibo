//! The two policy files, `policies/security.yaml` and `policies/approval.yaml`, loaded into typed
//! values.
//!
//! # What loading guarantees
//!
//! A [`LoadedPolicy`] exists only if the file passed every rule below. Any failure is an error and
//! no policy value is built, so the scheduler has nothing to start jobs with (NT-POL-03).
//!
//! * The text is a single document in the restricted YAML subset: no anchors, aliases, tags,
//!   directives, merge keys, duplicate keys, nulls or ambiguous scalars (see [`crate::yaml`]).
//! * `schema_version` equals the version this build reads, and is checked before anything else
//!   about the document.
//! * The document decodes into structs that reject unknown keys at every depth, with every
//!   required key present and every value of the right type.
//! * Every regular expression compiles in the Rust `regex` dialect and every glob compiles in the
//!   `globset` dialect.
//! * Identifiers that must be unique are, and every name used in one place is defined in another.
//! * `policy.default_action` is present and is the one value the dialect allows (`deny` for the
//!   security policy, `require_human` for the approval policy).
//!
//! # Where a policy may come from (NT-POL-01)
//!
//! A policy is read only through a [`ProtectedPolicySource`], which stands for a checkout of the
//! protected default branch of the factory configuration source. The loader:
//!
//! * reads the two fixed file names `policies/security.yaml` and `policies/approval.yaml` under
//!   that checkout, and no other path;
//! * never reads an environment variable. A test scans this crate's source for any use of the
//!   process environment;
//! * refuses a checkout that lies inside a directory the caller names as untrusted, such as a job
//!   workspace or a target repository's working tree;
//! * refuses a file that is a symbolic link;
//! * refuses a file whose own `policy.config_source` is not the source it was read from;
//! * has no default policy and no fallback: when the file is missing the call fails, and the
//!   composition root must refuse to run jobs.
//!
//! The loader cannot tell a protected default branch from a feature branch by looking at files.
//! The composition root is responsible for handing it a checkout of the right branch. What the
//! loader adds is that nothing else can reach it by a side door.
//!
//! No policy type implements `Default`. The first example proves the type is where it is said to be,
//! so the second fails for the right reason:
//!
//! ```
//! let _: Option<factory_contracts::policy::SecurityPolicy> = None;
//! ```
//!
//! ```compile_fail
//! let _ = factory_contracts::policy::SecurityPolicy::default();
//! ```
//!
//! # The policy hash
//!
//! [`PolicyHash`] is the SHA-256 of the RFC 8785 canonical JSON of the typed document. It does not
//! depend on key order, comments, quoting, or block versus flow style, and it changes when any
//! value changes. The hash of a merged policy (central policy plus a project's tightening) is
//! taken the same way with [`PolicyHash::of`].

pub mod check;

// The typed documents live in `factory-domain` so that the policy evaluators, which are ring 0, can
// name them. They are re-exported here under the paths this crate has always had.
pub use factory_domain::policy::{approval, common, security};

use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use factory_domain::values::Sha256Digest;
use serde::Serialize;
use serde::de::DeserializeOwned;

pub use approval::ApprovalPolicy;
pub use common::{ConfigSource, GlobText, PolicyStatus, RegexText, ThreatId};
pub use security::SecurityPolicy;

use crate::yaml::{self, Content, Document, YamlError, YamlErrorKind, YamlLimits};
use check::{Problem, ProblemKind};
use common::SUPPORTED_SCHEMA_VERSION;

/// The security policy file, relative to the checkout.
pub const SECURITY_FILE: &str = "policies/security.yaml";
/// The approval policy file, relative to the checkout.
pub const APPROVAL_FILE: &str = "policies/approval.yaml";

/// What kind of problem a policy load found. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyErrorKind {
    /// The file is missing, unreadable, or a symbolic link.
    Unavailable,
    /// The checkout is inside a location the caller named as untrusted.
    UntrustedLocation,
    /// The file is over the size limit.
    TooLarge,
    /// The file is not UTF-8.
    NotUtf8,
    /// The YAML reader refused the text: an anchor, alias, tag, merge key, duplicate key, null,
    /// ambiguous scalar, limit or syntax error.
    Yaml(YamlErrorKind),
    /// `schema_version` is not the version this build reads.
    SchemaVersion,
    /// The document does not fit the typed policy: an unknown key, a missing key, a wrong type or
    /// a value outside a closed set.
    Type,
    /// The file is the wrong policy, such as the approval policy loaded as the security policy.
    WrongPolicy,
    /// The file says it must be read from a different source than the one it was read from.
    WrongSource,
    /// A regular expression that does not compile.
    InvalidRegex,
    /// A glob that does not compile.
    InvalidGlob,
    /// An identifier used twice.
    DuplicateId,
    /// A name that nothing defines.
    UnknownReference,
    /// Another rule of the policy.
    Constraint,
}

/// Why a policy could not be loaded: which file, which key and which line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    /// The file.
    pub file: String,
    /// The line, counting from 1.
    pub line: Option<usize>,
    /// The key path, such as `secrets.patterns[3].regex`.
    pub key: Option<String>,
    /// What kind of problem.
    pub kind: PolicyErrorKind,
    /// Plain English: what is wrong and what to change.
    pub message: String,
    /// Further problems found in the same pass.
    pub others: Vec<String>,
}

impl PolicyError {
    fn new(file: &str, kind: PolicyErrorKind, message: impl Into<String>) -> Self {
        Self {
            file: file.to_owned(),
            line: None,
            key: None,
            kind,
            message: message.into(),
            others: Vec::new(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.file)?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        if let Some(key) = &self.key {
            write!(f, " (key `{key}`)")?;
        }
        write!(f, ": {}", self.message)?;
        if !self.others.is_empty() {
            write!(
                f,
                " ({} more: {})",
                self.others.len(),
                self.others.join("; ")
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for PolicyError {}

/// The SHA-256 of the canonical JSON of a policy. See the module notes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PolicyHash(Sha256Digest);

impl PolicyHash {
    /// Hashes any serializable value as its RFC 8785 canonical JSON.
    ///
    /// # Errors
    /// A message when the value cannot be written as JSON, which no policy value can cause.
    pub fn of<T: Serialize>(value: &T) -> Result<Self, String> {
        let json = serde_json::to_value(value).map_err(|e| e.to_string())?;
        let canonical = serde_jcs::to_vec(&json).map_err(|e| e.to_string())?;
        Ok(Self(Sha256Digest::of(&canonical)))
    }

    /// The digest, written `sha256:` and 64 hex characters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The digest as the domain type.
    #[must_use]
    pub fn digest(&self) -> &Sha256Digest {
        &self.0
    }
}

impl fmt::Display for PolicyHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

/// A policy that passed every rule, with its hash and where it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadedPolicy<T> {
    /// The typed document.
    pub document: T,
    /// The hash of its canonical form. Stored on every job, approval and audit event.
    pub hash: PolicyHash,
    /// The SHA-256 of the file's bytes, for the audit trail.
    pub file_sha256: Sha256Digest,
    /// The file that was read.
    pub file: String,
}

/// A checkout of the protected default branch of the factory configuration source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPolicySource {
    root: PathBuf,
}

impl ProtectedPolicySource {
    /// Names the checkout to read from. `untrusted_roots` lists the places a policy must never
    /// come from: job workspaces and target repository working trees. The checkout is refused if
    /// it is one of them or lies inside one.
    ///
    /// The caller is responsible for the checkout being the protected default branch. See the
    /// module notes.
    ///
    /// # Errors
    /// [`PolicyErrorKind::Unavailable`] when the checkout cannot be resolved,
    /// [`PolicyErrorKind::UntrustedLocation`] when it lies inside an untrusted root.
    pub fn protected_default_branch(
        checkout: &Path,
        untrusted_roots: &[&Path],
    ) -> Result<Self, PolicyError> {
        let label = checkout.display().to_string();
        let root = fs::canonicalize(checkout).map_err(|_| {
            PolicyError::new(
                &label,
                PolicyErrorKind::Unavailable,
                "the protected configuration checkout does not exist; the factory cannot run jobs without its policy",
            )
        })?;
        for untrusted in untrusted_roots {
            // A root that does not exist cannot contain the checkout.
            if let Ok(untrusted) = fs::canonicalize(untrusted)
                && root.starts_with(&untrusted)
            {
                return Err(PolicyError::new(
                    &label,
                    PolicyErrorKind::UntrustedLocation,
                    format!(
                        "the policy checkout lies inside {}, which is a job workspace or a target repository; a policy is read only from the protected configuration source",
                        untrusted.display()
                    ),
                ));
            }
        }
        Ok(Self { root })
    }

    /// The checkout.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// Loads the two policy files.
#[derive(Debug, Clone, Copy, Default)]
pub struct PolicyLoader;

impl PolicyLoader {
    /// Loads `policies/security.yaml`.
    ///
    /// # Errors
    /// A [`PolicyError`]. No policy value exists after an error.
    pub fn load_security(
        source: &ProtectedPolicySource,
    ) -> Result<LoadedPolicy<SecurityPolicy>, PolicyError> {
        let (label, text, file_sha256) = read_policy_file(source, SECURITY_FILE)?;
        load_document(
            &label,
            &text,
            file_sha256,
            |p: &SecurityPolicy| p.policy.config_source,
            check::security_problems,
        )
    }

    /// Loads `policies/approval.yaml`.
    ///
    /// # Errors
    /// A [`PolicyError`]. No policy value exists after an error.
    pub fn load_approval(
        source: &ProtectedPolicySource,
    ) -> Result<LoadedPolicy<ApprovalPolicy>, PolicyError> {
        let (label, text, file_sha256) = read_policy_file(source, APPROVAL_FILE)?;
        load_document(
            &label,
            &text,
            file_sha256,
            |p: &ApprovalPolicy| p.policy.config_source,
            check::approval_problems,
        )
    }
}

fn read_policy_file(
    source: &ProtectedPolicySource,
    relative: &str,
) -> Result<(String, String, Sha256Digest), PolicyError> {
    let path = source.root.join(relative);
    let label = path.display().to_string();
    let unavailable = |why: &str| {
        PolicyError::new(
            &label,
            PolicyErrorKind::Unavailable,
            format!("{why}; the factory cannot run jobs without its policy and has no default"),
        )
    };
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| unavailable("the policy file is missing"))?;
    if metadata.file_type().is_symlink() {
        return Err(unavailable(
            "the policy file is a symbolic link, which is not followed",
        ));
    }
    if !metadata.is_file() {
        return Err(unavailable("the policy path is not a regular file"));
    }
    let limit = YamlLimits::POLICY.max_bytes();
    if metadata.len() > limit as u64 {
        return Err(PolicyError::new(
            &label,
            PolicyErrorKind::TooLarge,
            format!(
                "the file is {} bytes; the limit is {limit} bytes",
                metadata.len()
            ),
        ));
    }
    let mut bytes = Vec::new();
    File::open(&path)
        .map_err(|_| unavailable("the policy file cannot be opened"))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable("the policy file cannot be read"))?;
    if bytes.len() > limit {
        return Err(PolicyError::new(
            &label,
            PolicyErrorKind::TooLarge,
            "the file grew while it was read",
        ));
    }
    let file_sha256 = Sha256Digest::of(&bytes);
    let text = String::from_utf8(bytes).map_err(|e| {
        PolicyError::new(
            &label,
            PolicyErrorKind::NotUtf8,
            format!(
                "the file is not valid UTF-8 (first bad byte at offset {})",
                e.utf8_error().valid_up_to()
            ),
        )
    })?;
    Ok((label, text, file_sha256))
}

/// Parses, decodes and checks one policy document.
fn load_document<T: Serialize + DeserializeOwned>(
    label: &str,
    text: &str,
    file_sha256: Sha256Digest,
    declared_source: impl Fn(&T) -> ConfigSource,
    problems: impl Fn(&T) -> Vec<Problem>,
) -> Result<LoadedPolicy<T>, PolicyError> {
    let document = yaml::read(text, YamlLimits::POLICY).map_err(|e| from_yaml(label, &e))?;
    check_schema_version(label, &document)?;
    let typed: T = document.decode().map_err(|e| from_yaml(label, &e))?;

    if declared_source(&typed) != ConfigSource::ProtectedDefaultBranch {
        let key = "policy.config_source";
        let mut error = PolicyError::new(
            label,
            PolicyErrorKind::WrongSource,
            "the file says it must come from a signed release, but it was read from the protected default branch checkout; this build has no signed-release source, so it refuses the file",
        );
        error.line = document.locate(key).map(|(line, _)| line);
        error.key = Some(key.to_owned());
        return Err(error);
    }

    let mut found = problems(&typed);
    if !found.is_empty() {
        let first = found.remove(0);
        let mut error = PolicyError::new(
            label,
            match first.kind {
                ProblemKind::InvalidRegex => PolicyErrorKind::InvalidRegex,
                ProblemKind::InvalidGlob => PolicyErrorKind::InvalidGlob,
                ProblemKind::DuplicateId => PolicyErrorKind::DuplicateId,
                ProblemKind::UnknownReference => PolicyErrorKind::UnknownReference,
                ProblemKind::Constraint => {
                    if first.path == "policy.id" {
                        PolicyErrorKind::WrongPolicy
                    } else {
                        PolicyErrorKind::Constraint
                    }
                }
            },
            first.message,
        );
        error.line = document.locate(&first.path).map(|(line, _)| line);
        error.key = Some(first.path);
        error.others = found
            .iter()
            .take(8)
            .map(|p| format!("{}: {}", p.path, p.message))
            .collect();
        return Err(error);
    }

    let hash = PolicyHash::of(&typed).map_err(|reason| {
        PolicyError::new(
            label,
            PolicyErrorKind::Constraint,
            format!("the policy cannot be hashed: {reason}"),
        )
    })?;
    Ok(LoadedPolicy {
        document: typed,
        hash,
        file_sha256,
        file: label.to_owned(),
    })
}

/// Refuses a `schema_version` other than 1 before anything else about the document is read.
fn check_schema_version(label: &str, document: &Document) -> Result<(), PolicyError> {
    let Content::Map(entries) = &document.root().content else {
        return Err(PolicyError::new(
            label,
            PolicyErrorKind::Type,
            "a policy file is a mapping of sections, starting with `schema_version`",
        ));
    };
    let Some(entry) = entries.iter().find(|e| e.key == "schema_version") else {
        return Err(PolicyError::new(
            label,
            PolicyErrorKind::SchemaVersion,
            format!(
                "`schema_version` is missing; this build reads only version {SUPPORTED_SCHEMA_VERSION}"
            ),
        ));
    };
    let supported = match &entry.value.content {
        Content::Int(n) => u64::try_from(*n) == Ok(SUPPORTED_SCHEMA_VERSION),
        Content::UInt(n) => *n == SUPPORTED_SCHEMA_VERSION,
        _ => false,
    };
    if supported {
        Ok(())
    } else {
        let mut error = PolicyError::new(
            label,
            PolicyErrorKind::SchemaVersion,
            format!(
                "`schema_version` is not {SUPPORTED_SCHEMA_VERSION}; this build reads only version {SUPPORTED_SCHEMA_VERSION}, so the factory refuses to start with this file"
            ),
        );
        error.line = Some(entry.line);
        error.key = Some("schema_version".to_owned());
        Err(error)
    }
}

fn from_yaml(label: &str, error: &YamlError) -> PolicyError {
    let kind = match error.kind {
        YamlErrorKind::TooLarge => PolicyErrorKind::TooLarge,
        YamlErrorKind::Decode => PolicyErrorKind::Type,
        other => PolicyErrorKind::Yaml(other),
    };
    let mut policy_error = PolicyError::new(label, kind, error.detail());
    policy_error.line = error.line;
    policy_error.key.clone_from(&error.key);
    policy_error
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hash_of_a_value_does_not_depend_on_key_order() {
        let a = PolicyHash::of(&serde_json::json!({"b": 1, "a": [true, 2.5]})).expect("hash");
        let b = PolicyHash::of(&serde_json::json!({"a": [true, 2.5], "b": 1})).expect("hash");
        let c = PolicyHash::of(&serde_json::json!({"a": [true, 2.5], "b": 2})).expect("hash");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(a.as_str().starts_with("sha256:"));
    }
}
