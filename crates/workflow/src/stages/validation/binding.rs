//! The evidence binding: what a set of gate reports is about.
//!
//! A gate report is evidence only for the commit it ran on, under the policy and the image in
//! force at the time, with the definitions of the base commit. The binding names all of them
//! (`gate_integrity.evidence_binding`). It is written with the reports, and the gate that
//! evaluates them computes the same values again from independent sources and compares. Evidence
//! for an older commit, a changed policy, another image or other definitions therefore does not
//! count.

use factory_domain::values::{GitSha, Sha256Digest};
use serde_json::{Value, json};

/// The values a set of reports is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The hash of the implementation result that named the commits.
    pub implementation_result: Sha256Digest,
    /// The base commit: the protected branch tip the change is relative to.
    pub base_commit: GitSha,
    /// The head commit: the candidate that was verified.
    pub head_commit: GitSha,
    /// The hash of the policy bundle in force.
    pub policy_hash: Sha256Digest,
    /// The digest of the verify image.
    pub image_digest: Sha256Digest,
    /// The hash of the resolved gate definitions.
    pub definition_hash: Sha256Digest,
}

/// The names of the bound values, in the order they are compared.
pub const FIELDS: [&str; 6] = [
    "implementation_result",
    "base_commit",
    "head_commit",
    "policy_hash",
    "image_digest",
    "definition_hash",
];

impl Binding {
    /// The binding as a JSON object.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "implementation_result": self.implementation_result.as_str(),
            "base_commit": self.base_commit.as_str(),
            "head_commit": self.head_commit.as_str(),
            "policy_hash": self.policy_hash.as_str(),
            "image_digest": self.image_digest.as_str(),
            "definition_hash": self.definition_hash.as_str(),
        })
    }

    /// Reads a binding written by [`to_json`](Self::to_json). `None` for anything else.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let field = |name: &str| value.get(name).and_then(Value::as_str);
        Some(Self {
            implementation_result: Sha256Digest::parse(field("implementation_result")?).ok()?,
            base_commit: GitSha::parse(field("base_commit")?).ok()?,
            head_commit: GitSha::parse(field("head_commit")?).ok()?,
            policy_hash: Sha256Digest::parse(field("policy_hash")?).ok()?,
            image_digest: Sha256Digest::parse(field("image_digest")?).ok()?,
            definition_hash: Sha256Digest::parse(field("definition_hash")?).ok()?,
        })
    }

    /// A hash of the binding, which enters the evidence hash of every report.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::of(self.to_json().to_string().as_bytes())
    }

    /// The names of the values that differ between this binding and `expected`.
    #[must_use]
    pub fn differences(&self, expected: &Self) -> Vec<&'static str> {
        let pairs = [
            (self.implementation_result == expected.implementation_result),
            (self.base_commit == expected.base_commit),
            (self.head_commit == expected.head_commit),
            (self.policy_hash == expected.policy_hash),
            (self.image_digest == expected.image_digest),
            (self.definition_hash == expected.definition_hash),
        ];
        FIELDS
            .iter()
            .zip(pairs)
            .filter(|(_, same)| !same)
            .map(|(name, _)| *name)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> Binding {
        Binding {
            implementation_result: Sha256Digest::of(b"result"),
            base_commit: GitSha::parse(&"a".repeat(40)).expect("a sha"),
            head_commit: GitSha::parse(&"b".repeat(40)).expect("a sha"),
            policy_hash: Sha256Digest::of(b"policy"),
            image_digest: Sha256Digest::of(b"image"),
            definition_hash: Sha256Digest::of(b"definitions"),
        }
    }

    #[test]
    fn a_binding_survives_its_json_form() {
        let original = binding();
        assert_eq!(Binding::from_json(&original.to_json()), Some(original));
    }

    #[test]
    fn each_changed_value_is_named() {
        let expected = binding();
        let mut other = binding();
        assert!(other.differences(&expected).is_empty());
        other.head_commit = GitSha::parse(&"c".repeat(40)).expect("a sha");
        other.policy_hash = Sha256Digest::of(b"another policy");
        other.image_digest = Sha256Digest::of(b"another image");
        assert_eq!(
            other.differences(&expected),
            vec!["head_commit", "policy_hash", "image_digest"]
        );
        assert_ne!(other.digest(), expected.digest());
    }

    #[test]
    fn a_binding_with_a_missing_or_malformed_value_is_not_read() {
        let mut value = binding().to_json();
        value["head_commit"] = json!("not a sha");
        assert_eq!(Binding::from_json(&value), None);
        assert_eq!(Binding::from_json(&json!({})), None);
    }
}
