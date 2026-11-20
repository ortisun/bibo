//! The comparison of what the gate reports are bound to with what is true now.
//!
//! The reports of the validation stage are evidence for one base commit, one set of gate
//! definitions, one policy and one image (`gate_integrity.evidence_binding`). Two points use this
//! comparison and no other: before the delivery stage pushes, and when an approval is recorded
//! (ADR 0010). The function is pure; the caller reads the current values.

use factory_domain::values::{GitSha, Sha256Digest};
use factory_ports::paths::CommitSha;

use super::seams::CurrentValues;
use crate::stages::validation::Binding;

/// The values that can change in the world while the evidence stays as it is. A change of one of
/// them supersedes the runs that depend on the evidence (ADR 0010). The two other values of a
/// binding, the head commit and the implementation result, are about which documents belong
/// together, and a difference there is a contradiction and not a change.
pub const DRIFT_FIELDS: [&str; 4] = [
    "base_commit",
    "policy_hash",
    "image_digest",
    "definition_hash",
];

/// What is true now.
#[derive(Debug, Clone)]
pub struct Now<'a> {
    /// The commit the base branch points at on the code host.
    pub live_base: &'a CommitSha,
    /// The gate definition hash and the image digest in force.
    pub current: &'a CurrentValues,
    /// The hash of the policy bundle in force.
    pub policy_hash: &'a Sha256Digest,
    /// The commit that is delivered.
    pub head: &'a CommitSha,
    /// The hash of the implementation result that names the commits.
    pub implementation_sha256: &'a Sha256Digest,
}

/// The names of the bound values that differ. `None` when a commit is not a git object id, which
/// no stored commit is.
#[must_use]
pub fn differences(recorded: &Binding, now: &Now<'_>) -> Option<Vec<&'static str>> {
    let expected = Binding {
        implementation_result: now.implementation_sha256.clone(),
        base_commit: GitSha::parse(now.live_base.as_str()).ok()?,
        head_commit: GitSha::parse(now.head.as_str()).ok()?,
        policy_hash: now.policy_hash.clone(),
        image_digest: now.current.image_digest.clone(),
        definition_hash: now.current.definition_hash.clone(),
    };
    Some(recorded.differences(&expected))
}

/// True when every difference is a change in the world and none is a contradiction between
/// documents.
#[must_use]
pub fn is_drift(differences: &[&'static str]) -> bool {
    !differences.is_empty() && differences.iter().all(|name| DRIFT_FIELDS.contains(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(c: char) -> CommitSha {
        CommitSha::parse(&c.to_string().repeat(40)).expect("a sha")
    }

    fn recorded() -> Binding {
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
    fn a_changed_world_is_a_drift_and_a_contradiction_is_not() {
        let values = CurrentValues {
            definition_hash: Sha256Digest::of(b"definitions"),
            image_digest: Sha256Digest::of(b"image"),
        };
        let policy = Sha256Digest::of(b"policy");
        let result = Sha256Digest::of(b"result");
        let (a, b, c) = (sha('a'), sha('b'), sha('c'));
        let now = |base: &CommitSha, head: &CommitSha| {
            differences(
                &recorded(),
                &Now {
                    live_base: base,
                    current: &values,
                    policy_hash: &policy,
                    head,
                    implementation_sha256: &result,
                },
            )
            .expect("commits")
        };
        assert!(now(&a, &b).is_empty());
        let moved = now(&c, &b);
        assert_eq!(moved, vec!["base_commit"]);
        assert!(is_drift(&moved));
        let other_head = now(&a, &c);
        assert_eq!(other_head, vec!["head_commit"]);
        assert!(!is_drift(&other_head));
        assert!(!is_drift(&[]));
    }
}
