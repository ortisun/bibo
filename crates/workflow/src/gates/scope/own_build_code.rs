//! The decision of a security approver on the project's own new build code, and what it is bound to.
//!
//! [`build_code`](super::build_code) holds the build code that the change adds to the project: a
//! `build.rs`, a procedural macro, build dependencies. The gate `build` is BLOCKED with the code
//! `policy_unresolvable` until a person decides, and no command runs before they do. The decision
//! is the action `approve_build_code` of `policies/approval.yaml`, whose row names the security
//! approver. For a *package* the decision is bound to the name, the version and the checksum
//! (`gates::supply_chain::approval`). The project's own code has no such identity, so the decision
//! is bound to what the reviewer read: the **path** of the file and the **hash of its content** in
//! the head commit of the change.
//!
//! * A decision counts for exactly that content. A script that is edited afterwards has another
//!   hash and needs a decision of its own; so does the same text at another path.
//! * A decision is for the tenant and the job it was taken for, under the policy bundle in force
//!   when it was taken, and it counts while the person still holds the designation (the
//!   composition root drops one whose person left the allowlist).
//! * Only the policy engine can make the proof the record is made from
//!   ([`AuthorizedApproval`]), and only the engine appends the ledger entry the gate reads it
//!   back from (`Engine::record_project_build_code_decision`).
//! * The words a person writes are never the subject. The subject is what the blocked stage run
//!   stored as awaited ([`awaited`]); the person's words select one entry of it.

use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::decision::{AuthorizedApproval, Designation, GithubUserId};
use factory_domain::values::{Sha256Digest, Timestamp};
use serde_json::{Value, json};

use super::build_code;
use super::diff::FileChange;
use crate::gates::supply_chain::approval::{
    ApprovalError, BUILD_CODE_ACTION, DecisionScope, MAX_REASON_CHARS, MIN_REASON_CHARS,
};

/// How the statement of the ledger claim of a recorded decision begins.
pub const STATEMENT_PREFIX: &str =
    "A security approver decided on the project's own build code in ";

/// The description of the artifact evidence that holds the decision.
pub const ARTIFACT_NOTE: &str = "project-build-code-decision";

/// The key of the section of the validation evidence that lists the build code of the project.
pub const EVIDENCE_KEY: &str = "project_build_code";

/// One file of build code: where it is and what it holds.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BuildScript {
    /// The path in the repository, as the object store names it.
    pub path: String,
    /// The SHA-256 of the content of the file in the head commit.
    pub sha256: Sha256Digest,
}

impl BuildScript {
    /// The entry of the evidence document.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({"path": self.path, "sha256": self.sha256.as_str()})
    }

    /// Reads an entry of the evidence document back.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            path: value.get("path")?.as_str()?.to_owned(),
            sha256: Sha256Digest::parse(value.get("sha256")?.as_str()?).ok()?,
        })
    }
}

/// The files of build code that the change adds, each with the hash of its content in the head
/// commit, one entry for each path, in the order of the paths.
///
/// A file counts when [`build_code::added`] finds a hit in it. A manifest that gains a `build` key
/// is listed with the hash of the manifest, because that is the file a reviewer reads.
#[must_use]
pub fn awaited(files: &[FileChange]) -> Vec<BuildScript> {
    let hits = build_code::added(files);
    let mut found: Vec<BuildScript> = Vec::new();
    for file in files {
        let hit = hits
            .iter()
            .any(|violation| violation.path.as_deref() == Some(file.path.as_str()));
        if hit {
            found.push(BuildScript {
                path: file.path.clone(),
                sha256: Sha256Digest::of(file.after_or_empty()),
            });
        }
    }
    found.sort();
    found.dedup();
    found
}

/// The record of one authorized decision on one file of build code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectBuildCodeApproval {
    /// What was approved.
    pub script: BuildScript,
    /// The numeric id of the person.
    pub approver: GithubUserId,
    /// The designation the allowlist gave them, which the decision relied on.
    pub designation: Designation,
    /// The version of the allowlist the decision was read from.
    pub allowlist_version: String,
    /// The hash of the policy bundle in force when it was decided.
    pub policy_hash: Sha256Digest,
    /// The tenant and the job it was decided for.
    pub scope: DecisionScope,
    /// Why, in the person's words.
    pub reason: String,
    /// When.
    pub decided_at: Timestamp,
}

impl ProjectBuildCodeApproval {
    /// Records a decision.
    ///
    /// # Errors
    /// [`ApprovalError::WrongAction`] when the proof is for another action, and
    /// [`ApprovalError::NoReason`] when the reason is shorter than the policy asks.
    pub fn record(
        authorization: &AuthorizedApproval,
        script: BuildScript,
        policy_hash: Sha256Digest,
        scope: DecisionScope,
        reason: &str,
    ) -> Result<Self, ApprovalError> {
        if authorization.action() != BUILD_CODE_ACTION {
            return Err(ApprovalError::WrongAction);
        }
        let reason = reason.trim();
        if reason.chars().count() < MIN_REASON_CHARS {
            return Err(ApprovalError::NoReason);
        }
        Ok(Self {
            script,
            approver: authorization.approver(),
            designation: authorization.designation(),
            allowlist_version: authorization.allowlist_version().to_owned(),
            policy_hash,
            scope,
            reason: reason.chars().take(MAX_REASON_CHARS).collect(),
            decided_at: *authorization.decided_at(),
        })
    }

    /// True when the person who decided is a security approver, which is what the action row names.
    #[must_use]
    pub fn by_a_security_approver(&self) -> bool {
        self.designation == Designation::SecurityApprover
    }

    /// True when this decision is for exactly this path with exactly this content.
    #[must_use]
    pub fn covers(&self, script: &BuildScript) -> bool {
        self.script == *script
    }

    /// True when the decision was taken for this tenant and job, under this policy bundle.
    #[must_use]
    pub fn is_valid_for(&self, scope: &DecisionScope, policy_hash: &Sha256Digest) -> bool {
        self.scope == *scope && self.policy_hash == *policy_hash
    }

    /// The statement of the ledger claim for the decision.
    #[must_use]
    pub fn statement(&self) -> String {
        format!("{STATEMENT_PREFIX}{}.", self.script.path)
    }

    /// The document stored as the artifact of the ledger entry.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "action": BUILD_CODE_ACTION,
            "kind": "project-build-code",
            "path": self.script.path,
            "sha256": self.script.sha256.as_str(),
            "approver_id": self.approver.get(),
            "designation": self.designation.as_str(),
            "allowlist_version": self.allowlist_version,
            "policy_hash": self.policy_hash.as_str(),
            "tenant_id": self.scope.tenant.as_text(),
            "job_id": self.scope.job.as_text(),
            "reason": self.reason,
            "decided_at": self.decided_at.as_text(),
        })
    }

    /// Reads a document written by [`to_json`](Self::to_json). `None` for anything else, which
    /// includes a record of a package decision and a record with no numeric id of the person.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let text = |name: &str| value.get(name).and_then(Value::as_str);
        if text("action")? != BUILD_CODE_ACTION || text("kind")? != "project-build-code" {
            return None;
        }
        let reason = text("reason")?;
        if reason.chars().count() < MIN_REASON_CHARS {
            return None;
        }
        Some(Self {
            script: BuildScript {
                path: text("path")?.to_owned(),
                sha256: Sha256Digest::parse(text("sha256")?).ok()?,
            },
            approver: GithubUserId::new(value.get("approver_id")?.as_u64()?)?,
            designation: Designation::parse(text("designation")?)?,
            allowlist_version: text("allowlist_version")?.to_owned(),
            policy_hash: Sha256Digest::parse(text("policy_hash")?).ok()?,
            scope: DecisionScope {
                tenant: TenantId::parse(text("tenant_id")?).ok()?,
                job: JobId::parse(text("job_id")?).ok()?,
            },
            reason: reason.to_owned(),
            decided_at: Timestamp::parse(text("decided_at")?).ok()?,
        })
    }
}

/// The files of `awaited` that no valid decision of a security approver covers.
///
/// A decision counts when it is for this tenant and job and this policy bundle, was taken by a
/// security approver, and names the same path and the same content. Anything else is ignored, so
/// a decision for a script that has since changed leaves the new content undecided.
#[must_use]
pub fn undecided(
    awaited: &[BuildScript],
    approvals: &[ProjectBuildCodeApproval],
    scope: &DecisionScope,
    policy_hash: &Sha256Digest,
) -> Vec<BuildScript> {
    awaited
        .iter()
        .filter(|script| {
            !approvals.iter().any(|approval| {
                approval.is_valid_for(scope, policy_hash)
                    && approval.by_a_security_approver()
                    && approval.covers(script)
            })
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use factory_ports::workspace::ChangeKind;

    use super::*;

    fn change(path: &str, after: &str) -> FileChange {
        FileChange {
            path: path.to_owned(),
            kind: ChangeKind::Added,
            before: None,
            after: Some(after.as_bytes().to_vec()),
            readable: true,
        }
    }

    const SCRIPT: &str = "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n";

    fn scope() -> DecisionScope {
        DecisionScope {
            tenant: TenantId::from_uuid(uuid::Uuid::from_u128(1)),
            job: JobId::from_uuid(uuid::Uuid::from_u128(2)),
        }
    }

    fn approval(script: &BuildScript, designation: Designation) -> ProjectBuildCodeApproval {
        ProjectBuildCodeApproval {
            script: script.clone(),
            approver: GithubUserId::new(1004).expect("an id"),
            designation,
            allowlist_version: "sha256:aa".to_owned(),
            policy_hash: Sha256Digest::of(b"policy"),
            scope: scope(),
            reason: "Read the script; it only prints cargo directives.".to_owned(),
            decided_at: Timestamp::parse("2026-10-29T12:00:00Z").expect("a time"),
        }
    }

    #[test]
    fn the_awaited_files_are_the_hits_with_the_hash_of_their_content() {
        let files = [
            change("build.rs", SCRIPT),
            change("src/lib.rs", "pub fn a() {}\n"),
            change("crates/a/build.rs", SCRIPT),
        ];
        let found = awaited(&files);
        assert_eq!(
            found.iter().map(|s| s.path.as_str()).collect::<Vec<_>>(),
            ["build.rs", "crates/a/build.rs"]
        );
        assert!(
            found
                .iter()
                .all(|script| script.sha256 == Sha256Digest::of(SCRIPT.as_bytes()))
        );
        assert!(awaited(&[change("src/lib.rs", "pub fn a() {}\n")]).is_empty());
    }

    #[test]
    fn a_decision_covers_the_exact_path_and_content_and_nothing_else() {
        let policy = Sha256Digest::of(b"policy");
        let script = awaited(&[change("build.rs", SCRIPT)]).remove(0);
        let by_security = approval(&script, Designation::SecurityApprover);
        // The same content at the path: decided.
        assert!(
            undecided(
                std::slice::from_ref(&script),
                std::slice::from_ref(&by_security),
                &scope(),
                &policy
            )
            .is_empty()
        );
        // The script was edited after the decision: its new content is undecided.
        let edited =
            awaited(&[change("build.rs", &format!("{SCRIPT}// one more line\n"))]).remove(0);
        assert_eq!(
            undecided(
                std::slice::from_ref(&edited),
                std::slice::from_ref(&by_security),
                &scope(),
                &policy
            )
            .len(),
            1
        );
        // The same content at another path is another file.
        let moved = awaited(&[change("tools/build.rs", SCRIPT)]).remove(0);
        assert_eq!(
            undecided(
                std::slice::from_ref(&moved),
                std::slice::from_ref(&by_security),
                &scope(),
                &policy
            )
            .len(),
            1
        );
        // An approver is not a security approver.
        let by_approver = approval(&script, Designation::Approver);
        assert_eq!(
            undecided(
                std::slice::from_ref(&script),
                std::slice::from_ref(&by_approver),
                &scope(),
                &policy
            )
            .len(),
            1
        );
        // Another job, another tenant and another policy bundle do not carry over.
        let other_job = DecisionScope {
            job: JobId::from_uuid(uuid::Uuid::from_u128(3)),
            ..scope()
        };
        let other_tenant = DecisionScope {
            tenant: TenantId::from_uuid(uuid::Uuid::from_u128(4)),
            ..scope()
        };
        for other in [other_job, other_tenant] {
            assert_eq!(
                undecided(
                    std::slice::from_ref(&script),
                    std::slice::from_ref(&by_security),
                    &other,
                    &policy
                )
                .len(),
                1
            );
        }
        assert_eq!(
            undecided(
                std::slice::from_ref(&script),
                std::slice::from_ref(&by_security),
                &scope(),
                &Sha256Digest::of(b"another policy")
            )
            .len(),
            1
        );
    }

    #[test]
    fn a_record_reads_back_as_it_was_written_and_a_package_decision_is_not_one() {
        let script = awaited(&[change("build.rs", SCRIPT)]).remove(0);
        let written = approval(&script, Designation::SecurityApprover);
        assert_eq!(
            ProjectBuildCodeApproval::from_json(&written.to_json()),
            Some(written.clone())
        );
        let mut package = written.to_json();
        package["kind"] = json!("package");
        assert_eq!(ProjectBuildCodeApproval::from_json(&package), None);
        let mut short = written.to_json();
        short["reason"] = json!("ok");
        assert_eq!(ProjectBuildCodeApproval::from_json(&short), None);
        let mut by_login = written.to_json();
        by_login["approver_id"] = json!("octocat");
        assert_eq!(ProjectBuildCodeApproval::from_json(&by_login), None);
    }
}
