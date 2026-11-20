//! The real security policy as a second look at a change set.
//!
//! The path rules of a request are built from the policy groups (the same construction the
//! contracts crate checks against the compiled policy). The compiled policy, when the provider is
//! given it, folds more spellings than the ports rules do, and it can only make an answer
//! stricter.

use std::sync::Arc;

use factory_domain::policy::paths::PathPolicy;
use factory_domain::policy::security::{AppliesTo, ProtectionMode};
use factory_domain::policy::{RepoKind, SecurityPolicy};
use factory_ports::paths::{PathMode, PathRule, PathRules, RepoGlob};
use factory_ports::workspace::{Workspace, WorkspaceError};
use factory_sandbox::workspace::PathPolicyLayer;
use factory_testkit::clock::FakeCancel;

use crate::world::{Options, World};

const SECURITY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");

fn policy() -> SecurityPolicy {
    serde_json::from_str(SECURITY).expect("the security fixture is a valid SecurityPolicy")
}

/// The ports rules for a target repository, built from the policy groups in policy order.
fn ports_rules(policy: &SecurityPolicy) -> PathRules {
    let mut rules = Vec::new();
    for group in &policy.protected_paths.groups {
        if matches!(group.applies_to, AppliesTo::FactoryRepo) {
            continue;
        }
        let mode = match group.mode {
            ProtectionMode::Hidden => PathMode::Hidden,
            ProtectionMode::DenyWrite => PathMode::DenyWrite,
            ProtectionMode::AppendOnly => PathMode::AppendOnly,
            ProtectionMode::AdditionsOnly => PathMode::AdditionsOnly,
        };
        for glob in &group.globs {
            let Ok(parsed) = RepoGlob::new(glob.pattern()) else {
                continue;
            };
            let rule = if glob.is_reinclusion() {
                PathRule::Reinclude {
                    glob: parsed,
                    group: group.id.clone(),
                }
            } else {
                PathRule::Mode { glob: parsed, mode }
            };
            rules.push((group.id.clone(), rule));
        }
    }
    PathRules::new(rules)
}

fn files() -> Vec<(String, String)> {
    [
        ("README.md", "# Fixture\n"),
        ("src/lib.rs", "pub fn answer() -> u32 { 42 }\n"),
        (".github/workflows/ci.yml", "name: ci\n"),
    ]
    .iter()
    .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
    .collect()
}

async fn world(with_layer: bool) -> World {
    let policy = policy();
    let rules = ports_rules(&policy);
    let layer = with_layer.then(|| {
        PathPolicyLayer::new(
            Arc::new(PathPolicy::from_policy(&policy).expect("the compiled policy")),
            RepoKind::Target,
        )
    });
    World::with(Options {
        rules,
        files: files(),
        layer,
        ..Options::default()
    })
    .await
}

async fn refused(ws: &dyn Workspace) -> Option<Vec<(String, PathMode)>> {
    match ws.ingest(&FakeCancel::new()).await {
        Err(WorkspaceError::ProtectedPathChanged(list)) => Some(
            list.into_iter()
                .map(|v| (v.path.as_str().to_owned(), v.mode))
                .collect(),
        ),
        Ok(_) => None,
        Err(other) => panic!("unexpected {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_real_policy_protects_the_workflows_with_or_without_the_second_look() {
    for with_layer in [false, true] {
        let world = world(with_layer).await;
        let (ws, _) = world.open(1).await;
        let dir = ws.mounts().workspace;
        assert!(
            ws.mounts()
                .protected_overlays
                .iter()
                .any(|p| p.as_str() == ".github/workflows/ci.yml")
        );
        std::fs::write(dir.join(".github/workflows/ci.yml"), "name: hijacked\n").expect("edit");
        let found = refused(&ws).await.expect("refused");
        assert_eq!(
            found,
            vec![(".github/workflows/ci.yml".to_owned(), PathMode::DenyWrite)]
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_compiled_policy_refuses_a_spelling_the_ports_rules_let_through() {
    // A fullwidth spelling of `.github`. The ports rules fold case and Unicode composition only,
    // so they call it a free path. The compiled policy maps fullwidth letters to ASCII first.
    let lookalike = ".\u{ff47}\u{ff49}\u{ff54}\u{ff48}\u{ff55}\u{ff42}/workflows/ci.yml";

    let without = world(false).await;
    let (ws, _) = without.open(1).await;
    let dir = ws.mounts().workspace;
    std::fs::create_dir_all(
        dir.join(".\u{ff47}\u{ff49}\u{ff54}\u{ff48}\u{ff55}\u{ff42}/workflows"),
    )
    .expect("dirs");
    std::fs::write(dir.join(lookalike), "name: sneaky\n").expect("write");
    assert!(
        refused(&ws).await.is_none(),
        "control: the ports rules alone accept it"
    );

    let with = world(true).await;
    let (ws, _) = with.open(1).await;
    let dir = ws.mounts().workspace;
    std::fs::create_dir_all(
        dir.join(".\u{ff47}\u{ff49}\u{ff54}\u{ff48}\u{ff55}\u{ff42}/workflows"),
    )
    .expect("dirs");
    std::fs::write(dir.join(lookalike), "name: sneaky\n").expect("write");
    let found = refused(&ws).await.expect("the second look refuses it");
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].1, PathMode::DenyWrite);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_link_to_a_hidden_path_is_refused_with_the_real_hidden_groups() {
    let world = world(true).await;
    let (ws, _) = world.open(1).await;
    let dir = ws.mounts().workspace;
    std::os::unix::fs::symlink("../.env", dir.join("src/secret-link")).expect("link");
    assert!(matches!(
        ws.ingest(&FakeCancel::new()).await,
        Err(WorkspaceError::EscapingSymlink(_))
    ));
    std::fs::remove_file(dir.join("src/secret-link")).expect("remove");
    std::os::unix::fs::symlink("../src/lib.rs", dir.join("src/ok-link")).expect("link");
    ws.ingest(&FakeCancel::new())
        .await
        .expect("a link inside the tree is fine");
}
