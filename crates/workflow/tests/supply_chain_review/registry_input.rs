//! Attack: a package name that is not a name, sent to the registry client.
//!
//! `gate::run` asks the registry source for the facts of every new direct dependency **before**
//! the policy engine validates the name (`DependencyPolicy::decide` refuses a name that is not a
//! crate name, but it runs afterwards, inside `Plan::new`). The name and the version are text from
//! the candidate's lockfile. The registry source is the composition root's code and it speaks
//! HTTP, so a name such as `../../x` or `a?b` arrives in the path of a request the control plane
//! makes with its own credentials and its own egress path.

use std::sync::Mutex;

use async_trait::async_trait;
use factory_workflow::gates::supply_chain::facts::{RegistryMetadata, RegistryRecord};

use factory_workflow::gates::supply_chain::report::gate;

use crate::files::{Files, base, files, lock, manifest, member, reg};
use crate::world::World;

/// A registry source that writes down what it was asked.
struct Recording(Mutex<Vec<(String, String)>>);

#[async_trait]
impl RegistryMetadata for Recording {
    async fn lookup(&self, name: &str, version: &str) -> RegistryRecord {
        self.0
            .lock()
            .expect("the list")
            .push((name.to_owned(), version.to_owned()));
        RegistryRecord::default()
    }
}

/// The names a crate may have on crates.io: ASCII letters, digits, `-` and `_`, starting with a
/// letter, at most 64 characters.
fn is_a_crate_name(name: &str) -> bool {
    name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn head_with_hostile_names() -> Files {
    let names = ["../../admin", "a?b=c", "a b", "x%2f%2e%2e"];
    let manifest_body: String = std::iter::once("[dependencies]\nserde = \"1\"\n".to_owned())
        .chain(names.iter().map(|name| format!("\"{name}\" = \"0.1.0\"\n")))
        .collect();
    files(&[
        ("Cargo.toml", manifest("app", &manifest_body)),
        (
            "Cargo.lock",
            lock(&[
                member(
                    "app",
                    &["../../admin", "a?b=c", "a b", "x%2f%2e%2e", "serde"],
                ),
                reg("../../admin", "0.1.0", '1'),
                reg("a?b=c", "0.1.0", '2'),
                reg("a b", "0.1.0", '3'),
                reg("x%2f%2e%2e", "0.1.0", '4'),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ])
}

/// The same, with hostile names that the lockfile can reference without another finding (a space
/// in a name splits the reference into a name and a version, which is a dangling reference of its
/// own and stops the lookups before they start), and one ordinary new dependency. The ordinary
/// one proves that the lookups ran: the test fails when they do not, and when a hostile name is
/// among them.
fn head_with_hostile_names_and_one_ordinary() -> Files {
    let hostile = ["../../admin", "a?b=c", "x%2f%2e%2e"];
    let manifest_body: String =
        std::iter::once("[dependencies]\nserde = \"1\"\nsome-crate = \"0.1.0\"\n".to_owned())
            .chain(
                hostile
                    .iter()
                    .map(|name| format!("\"{name}\" = \"0.1.0\"\n")),
            )
            .collect();
    files(&[
        ("Cargo.toml", manifest("app", &manifest_body)),
        (
            "Cargo.lock",
            lock(&[
                member(
                    "app",
                    &["../../admin", "a?b=c", "x%2f%2e%2e", "some-crate", "serde"],
                ),
                reg("../../admin", "0.1.0", '1'),
                reg("a?b=c", "0.1.0", '2'),
                reg("x%2f%2e%2e", "0.1.0", '4'),
                reg("some-crate", "0.1.0", 'c'),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ])
}

#[tokio::test]
async fn sc7_only_the_ordinary_name_reaches_the_registry_source() {
    let world = World::new();
    let registry = Recording(Mutex::new(Vec::new()));
    let ran = world
        .gate(
            &base(),
            &head_with_hostile_names_and_one_ordinary(),
            &registry,
            &[],
            false,
        )
        .await
        .expect("the gate runs");
    let asked = registry.0.lock().expect("the list").clone();
    assert_eq!(
        asked,
        vec![("some-crate".to_owned(), "0.1.0".to_owned())],
        "only the valid request is sent out"
    );
    // The hostile names are refused by name afterwards.
    assert!(
        ran.failure_checks(gate::REVIEW)
            .contains(&"invalid-dependency-request".to_owned())
    );
}

#[tokio::test]
async fn sc7_the_registry_source_is_never_asked_about_a_name_that_is_not_a_crate_name() {
    let world = World::new();
    let registry = Recording(Mutex::new(Vec::new()));
    // The gate refuses the change afterwards (`invalid-dependency-request`); what matters here is
    // what was sent out first.
    let _ran = world
        .gate(&base(), &head_with_hostile_names(), &registry, &[], false)
        .await
        .expect("the gate runs");
    let asked = registry.0.lock().expect("the list").clone();
    let bad: Vec<&(String, String)> = asked
        .iter()
        .filter(|(name, _)| !is_a_crate_name(name))
        .collect();
    assert!(
        bad.is_empty(),
        "the registry source was asked about names that are not crate names: {bad:?}"
    );
}
