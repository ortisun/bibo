//! The domain crate cannot read YAML, and it may not depend on this crate even for tests. Its
//! policy tests (`crates/domain/tests/policy.rs`) read the real policies from two JSON files made
//! from the loaded, validated documents. This test keeps them equal to `policies/`: if a policy
//! file changes, it fails until the fixtures are regenerated, so the domain tests never run
//! against a stale policy.
//!
//! To regenerate after an intended change to a policy file:
//!
//! ```text
//! cargo test -p factory-contracts --test policy_domain_fixture -- --ignored regenerate
//! ```

mod support;

use std::path::PathBuf;

use factory_contracts::policy::{PolicyLoader, ProtectedPolicySource};
use support::repo_root;

fn fixture_dir() -> PathBuf {
    repo_root().join("crates/domain/tests/fixtures/policy")
}

fn rendered() -> (String, String) {
    let source = ProtectedPolicySource::protected_default_branch(&repo_root(), &[])
        .expect("the repository root exists");
    let security = PolicyLoader::load_security(&source).expect("security policy loads");
    let approval = PolicyLoader::load_approval(&source).expect("approval policy loads");
    let render = |value: serde_json::Value| {
        let mut text = serde_json::to_string_pretty(&value).expect("a policy is JSON");
        text.push('\n');
        text
    };
    (
        render(serde_json::to_value(&security.document).expect("security as JSON")),
        render(serde_json::to_value(&approval.document).expect("approval as JSON")),
    )
}

#[test]
fn the_domain_fixtures_equal_the_loaded_policy_files() {
    let (security, approval) = rendered();
    let on_disk = |name: &str| {
        std::fs::read_to_string(fixture_dir().join(name)).unwrap_or_else(|e| {
            panic!(
                "cannot read the domain fixture {name}: {e}. Regenerate with `cargo test -p factory-contracts --test policy_domain_fixture -- --ignored regenerate`"
            )
        })
    };
    assert!(
        on_disk("security.json") == security,
        "crates/domain/tests/fixtures/policy/security.json is out of date with policies/security.yaml; regenerate it (see the top of this file)"
    );
    assert!(
        on_disk("approval.json") == approval,
        "crates/domain/tests/fixtures/policy/approval.json is out of date with policies/approval.yaml; regenerate it (see the top of this file)"
    );
}

#[test]
#[ignore = "writes the domain fixtures; run it by hand after an intended policy change"]
fn regenerate() {
    let (security, approval) = rendered();
    std::fs::create_dir_all(fixture_dir()).expect("create the fixture directory");
    std::fs::write(fixture_dir().join("security.json"), security).expect("write security.json");
    std::fs::write(fixture_dir().join("approval.json"), approval).expect("write approval.json");
}
