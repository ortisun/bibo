//! The real policy files in `policies/` load without error, and what they contain is what the
//! rest of the factory relies on.

mod support;

use factory_contracts::policy::security::ProtectionMode;
use factory_contracts::policy::{
    ApprovalPolicy, PolicyHash, PolicyLoader, PolicyStatus, ProtectedPolicySource, SecurityPolicy,
};
use support::repo_root;

fn source() -> ProtectedPolicySource {
    ProtectedPolicySource::protected_default_branch(&repo_root(), &[])
        .expect("the repository root exists")
}

#[test]
fn the_security_policy_in_policies_loads_without_error() {
    let loaded = PolicyLoader::load_security(&source()).unwrap_or_else(|e| panic!("{e}"));
    let policy: &SecurityPolicy = &loaded.document;
    assert_eq!(policy.policy.id, "security");
    assert!(loaded.file.ends_with("policies/security.yaml"));
    assert!(loaded.hash.as_str().starts_with("sha256:"));
    assert!(loaded.file_sha256.as_str().starts_with("sha256:"));
}

#[test]
fn the_approval_policy_in_policies_loads_without_error() {
    let loaded = PolicyLoader::load_approval(&source()).unwrap_or_else(|e| panic!("{e}"));
    let policy: &ApprovalPolicy = &loaded.document;
    assert_eq!(policy.policy.id, "approval");
    assert_eq!(policy.autonomy.default_level, "L1");
    assert!(loaded.file.ends_with("policies/approval.yaml"));
}

#[test]
fn the_two_policies_have_different_hashes_and_each_hash_is_stable() {
    let security_a = PolicyLoader::load_security(&source()).expect("security");
    let security_b = PolicyLoader::load_security(&source()).expect("security again");
    let approval = PolicyLoader::load_approval(&source()).expect("approval");
    assert_eq!(security_a.hash, security_b.hash);
    assert_ne!(security_a.hash, approval.hash);
    // The hash is also what `PolicyHash::of` gives for the typed document.
    assert_eq!(
        security_a.hash,
        PolicyHash::of(&security_a.document).expect("hash")
    );
}

#[test]
fn the_security_policy_says_what_the_other_work_packages_depend_on() {
    let loaded = PolicyLoader::load_security(&source()).expect("security");
    let policy = loaded.document;

    // Every list that grants something is an allow list: the default for a tool or a command
    // with no entry is deny.
    let shell = policy
        .tools
        .entries
        .iter()
        .find(|t| t.id == "exec.shell")
        .expect("the shell tool is listed, as a tool that is off");
    assert_eq!(shell.enabled, Some(false));
    assert!(shell.roles.is_empty() && shell.profiles.is_empty());
    assert!(policy.tools.entries.iter().any(|t| t.id == "report.submit"));
    assert!(!policy.tools.agents_may_self_grant);
    assert!(policy.tools.never_grantable.contains(&"merge".to_owned()));

    // Protected paths: the CI definitions are write-denied, secret files are hidden.
    let group = |id: &str| {
        policy
            .protected_paths
            .groups
            .iter()
            .find(|g| g.id == id)
            .unwrap_or_else(|| panic!("no group {id}"))
    };
    assert_eq!(group("ci_workflows").mode, ProtectionMode::DenyWrite);
    assert_eq!(group("secret_bearing_files").mode, ProtectionMode::Hidden);
    assert!(
        group("secret_bearing_files")
            .globs
            .iter()
            .any(|g| g.is_reinclusion())
    );

    // The rework cap in the file is the default the architect decided.
    assert!(policy.budgets.hard_ceilings.per_job.max_rework_iterations <= 2);
    assert!(
        policy
            .budgets
            .hard_ceilings
            .per_job
            .max_documentation_rework_iterations
            <= 2
    );
    assert_eq!(policy.budgets.rework.default_rounds, 2);

    // The one-line controls the threat model relies on.
    assert!(!policy.egress.allow_wildcards);
    // ADR 0020: the owner's subscription is the default, and its token stays in the broker.
    let providers = &policy.credentials.model_providers;
    assert_eq!(
        providers.mode,
        factory_contracts::policy::security::ProviderCredentialMode::Subscription
    );
    assert!(providers.subscription_token.never_in_sandbox);
    assert_eq!(providers.subscription_token.held_by, ["model_broker"]);
    assert!(
        !providers
            .subscription_token
            .provider_side_spend_limit_required
    );
    assert_eq!(
        providers.subscription_token.unavailable_runtimes,
        ["codex-cli"]
    );
    // The API-key mode keeps its provider-side limit.
    assert!(providers.real_keys.hard_spend_limit_required);
    assert!(policy.sandbox.fail_closed);
    assert!(!policy.gate_integrity.reviewer_verdict_can_override_gate);
}

#[test]
fn the_approval_policy_says_what_the_other_work_packages_depend_on() {
    let loaded = PolicyLoader::load_approval(&source()).expect("approval");
    let policy = loaded.document;
    let levels: Vec<&str> = policy
        .autonomy
        .levels
        .iter()
        .map(|l| l.id.as_str())
        .collect();
    assert_eq!(levels, ["L0", "L1", "L2", "L3"]);
    assert!(!policy.autonomy.auto_merge.enabled);
    assert!(!policy.autonomy.deploy.enabled);
    assert!(!policy.authority.github_permission.can_grant_authority);
    assert!(!policy.separation_of_duties.factory_app_may_approve);
    assert_eq!(policy.risk_tiers.len(), 4);
    assert!(policy.actions.iter().any(|a| a.id == "merge_pr"));
}

#[test]
fn the_files_are_designed_not_enforced_until_their_owner_says_so() {
    // `policy.status` is flipped by the policy owner when the evaluation tests pass. This test
    // records the state the files are in when the loader was written, and only fails if the
    // loader stops reading the field.
    let security = PolicyLoader::load_security(&source()).expect("security");
    let approval = PolicyLoader::load_approval(&source()).expect("approval");
    assert!(matches!(
        security.document.policy.status,
        PolicyStatus::Designed | PolicyStatus::Enforced
    ));
    assert!(matches!(
        approval.document.policy.status,
        PolicyStatus::Designed | PolicyStatus::Enforced
    ));
}
