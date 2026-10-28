//! What held under attack. These tests pass today and pin the behaviour so that a later change
//! cannot loosen it unnoticed. Each one is an attack the reviewer tried that the gate stopped.

use factory_domain::policy::decision::Designation;
use factory_workflow::gates::supply_chain::approval::{DependencyApproval, Subject};
use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::facts::RegistryRecord;
use factory_workflow::gates::supply_chain::findings::check;
use factory_workflow::gates::supply_chain::integrity::{Context, inspect};
use factory_workflow::gates::supply_chain::licenses::{Denial, LicensePolicy};
use factory_workflow::gates::supply_chain::model::normalize;
use factory_workflow::gates::supply_chain::names::PopularNames;
use factory_workflow::gates::supply_chain::review::{Plan, RegistryTable, Settings};
use serde_json::json;

use crate::files::{Files, base, files, judge, lock, manifest, member, reg, side, sum, with};
use crate::people::{APPROVER, approve, engine, now, policy_hash, scope};

fn plan_for(base: &Files, head: &Files, registry: &RegistryTable) -> Plan {
    let popular = PopularNames::bundled().expect("the bundled list");
    let cx = Context {
        internal_names: &[],
        popular: &popular,
    };
    let integrity = inspect(&CargoFormat, &side(base), &side(head), &cx).expect("readable");
    let licenses = LicensePolicy::owner_approved();
    Plan::new(
        integrity,
        registry,
        &[],
        &Settings {
            dependency: &engine().dependency,
            licenses: &licenses,
            internal_names: &[],
            popular: &popular,
            now: now(),
            scope: scope(),
            policy_hash: &policy_hash(),
        },
    )
}

// ---------------------------------------------------------------------------------------------
// The build configuration
// ---------------------------------------------------------------------------------------------

/// Every key of `.cargo/config.toml` that redirects a fetch, names a program, sets an
/// environment, or is simply unknown, fails the gate when the candidate adds it. The spellings
/// that try to hide a key (a quoted key that holds a dot, an inline table, an `include`) are in
/// the list.
#[test]
fn a_new_configuration_key_that_redirects_or_runs_code_fails_the_gate() {
    let hostile = [
        "[net]\ngit-fetch-with-cli = true\n",
        "[http]\nproxy = \"http://proxy.test:3128\"\n",
        "[env]\nFOO = \"1\"\n",
        "[alias]\naudit = \"run --bin x\"\n",
        "[build]\nrustc-wrapper = \"/tmp/wrapper\"\n",
        "[build]\nrustc-workspace-wrapper = \"/tmp/wrapper\"\n",
        "[build]\nrustflags = [\"-C\", \"linker=/tmp/l\"]\n",
        "include = [\"extra.toml\"]\n",
        "[target.x86_64-unknown-linux-gnu]\nlinker = \"/tmp/l\"\nrunner = \"/tmp/r\"\n",
        "[target.'cfg(unix)']\nrustflags = [\"-C\", \"x\"]\n",
        "[registry]\nglobal-credential-providers = [\"/tmp/provider\"]\n",
        "[registries.corp]\nindex = \"sparse+https://corp.test/\"\n",
        "[source.crates-io]\nreplace-with = \"mirror\"\n[source.mirror]\nregistry = \"sparse+https://mirror.test/\"\n",
        "[source.vendored]\ndirectory = \"vendor\"\n",
        "[patch.crates-io]\nserde = { path = \"x\" }\n",
        "paths = [\"../local\"]\n",
        "[credential-alias]\nx = \"/tmp/provider\"\n",
        "[install]\nroot = \"/tmp/x\"\n",
        "[doc]\nbrowser = \"/tmp/browser\"\n",
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n",
        "[resolver]\nincompatible-rust-versions = \"fallback\"\n",
        "\"build.rustc-wrapper\" = \"/tmp/wrapper\"\n",
        "build = { rustc-wrapper = \"/tmp/wrapper\" }\n",
        "[profile.dev]\nrustflags = [\"-C\", \"x\"]\n",
    ];
    for text in hostile {
        let head = with(base(), ".cargo/config.toml", text);
        let integrity = judge(&base(), &head);
        assert!(
            integrity.has_violation(),
            "this configuration was let through: {text}"
        );
    }
}

/// The file is found wherever cargo would look for it, and under the older name.
#[test]
fn a_configuration_file_is_recognised_under_every_name_and_directory_cargo_reads() {
    let text = "[build]\nrustc-wrapper = \"/tmp/wrapper\"\n";
    for path in [
        ".cargo/config.toml",
        ".cargo/config",
        "crates/a/.cargo/config.toml",
        "crates/a/.cargo/config",
    ] {
        let head = with(base(), path, text);
        assert!(judge(&base(), &head).has_violation(), "{path}");
    }
}

#[test]
fn a_harmless_configuration_is_allowed() {
    let head = with(base(), ".cargo/config.toml", "[term]\ncolor = \"never\"\n");
    assert!(!judge(&base(), &head).has_violation());
}

// ---------------------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------------------

/// Crate names are ASCII. A name with a look-alike letter (Cyrillic `е`) is not a name of the
/// registry, so the policy engine refuses the request instead of sending it to a person.
#[test]
fn a_name_with_a_homoglyph_is_refused() {
    let lookalike: &'static str = "s\u{0435}rde";
    let head = files(&[
        (
            "Cargo.toml",
            manifest(
                "app",
                &format!("[dependencies]\nserde = \"1\"\n\"{lookalike}\" = \"1\"\n"),
            ),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["serde", lookalike]),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
                reg(lookalike, "0.1.0", 'd'),
            ]),
        ),
    ]);
    let plan = plan_for(&base(), &head, &RegistryTable::new());
    assert!(plan.refused(), "{:?}", plan.findings);
    assert!(plan.violations().any(|f| f.check == check::INVALID_REQUEST));
}

/// Cargo treats `-` and `_` as one letter and ignores case; so does the gate. Adding
/// `Serde-Derive` when `serde_derive` is in the base lockfile is not a new name.
#[test]
fn names_are_compared_the_way_cargo_compares_them() {
    assert_eq!(normalize("Serde-Derive"), normalize("serde_derive"));
}

// ---------------------------------------------------------------------------------------------
// The approval record
// ---------------------------------------------------------------------------------------------

fn subject() -> Subject {
    Subject {
        name: "some-crate".to_owned(),
        version: "0.1.0".to_owned(),
        checksum: sum('c'),
    }
}

/// A stored record is an approval only when it names a person by number, carries a lowercase
/// checksum, and has every field. Every variation the reviewer tried is refused.
#[test]
fn a_stored_record_that_is_not_complete_and_numeric_is_not_an_approval() {
    let good = approve(APPROVER, "bob", Designation::Approver, &subject())
        .expect("recorded")
        .to_json();
    assert!(DependencyApproval::from_json(&good).is_some());

    let mut variants: Vec<(&str, serde_json::Value)> = Vec::new();
    let mut with_field = |label: &'static str, field: &str, value: serde_json::Value| {
        let mut doc = good.clone();
        doc[field] = value;
        variants.push((label, doc));
    };
    with_field("id as text", "approver_id", json!("1004"));
    with_field("id zero", "approver_id", json!(0));
    with_field("id negative", "approver_id", json!(-1004));
    with_field("id fractional", "approver_id", json!(1004.5));
    with_field("id null", "approver_id", json!(null));
    with_field("upper-case checksum", "checksum", json!("A".repeat(64)));
    with_field("short checksum", "checksum", json!("a".repeat(63)));
    with_field("other action", "action", json!("change_protected_path"));
    with_field("other ecosystem", "ecosystem", json!("npm"));
    with_field("short reason", "reason", json!("ok"));
    with_field("bad time", "decided_at", json!("yesterday"));
    with_field("bad policy hash", "policy_hash", json!("not a digest"));
    with_field("unknown designation", "designation", json!("superuser"));
    for (label, doc) in variants {
        assert!(DependencyApproval::from_json(&doc).is_none(), "{label}");
    }
    let mut missing = good.clone();
    missing
        .as_object_mut()
        .expect("an object")
        .remove("allowlist_version");
    assert!(DependencyApproval::from_json(&missing).is_none());
}

// ---------------------------------------------------------------------------------------------
// Shape of the lockfiles
// ---------------------------------------------------------------------------------------------

/// With no lockfile at the base commit, nothing is known, so every direct dependency in the
/// candidate's lockfile is new and goes to a person.
#[test]
fn with_no_lockfile_at_the_base_every_direct_dependency_is_new() {
    let base_without_lock: Files = files(&[(
        "Cargo.toml",
        manifest("app", "[dependencies]\nserde = \"1\"\n"),
    )]);
    // The manifest changes too (a requirement is written another way), so the lockfile is not
    // "an edit with no manifest behind it".
    let head = with(
        base(),
        "Cargo.toml",
        &manifest("app", "[dependencies]\nserde = \"1.0\"\n"),
    );
    let plan = plan_for(&base_without_lock, &head, &RegistryTable::new());
    assert!(!plan.refused(), "{:?}", plan.integrity.findings);
    assert!(
        plan.needs.iter().any(|need| need.subject.name == "serde"),
        "{:?}",
        plan.needs
    );
}

/// Fail-closed side effect, recorded because it blocks legitimate work: a project that never
/// committed a lockfile cannot add its first one through the factory unless a manifest changes in
/// the same commit (`lockfile-only-edit`).
#[test]
fn a_first_lockfile_with_no_manifest_change_is_refused() {
    let base_without_lock: Files = files(&[(
        "Cargo.toml",
        manifest("app", "[dependencies]\nserde = \"1\"\n"),
    )]);
    let integrity = judge(&base_without_lock, &base());
    assert!(
        integrity.has(check::LOCKFILE_ONLY),
        "{:?}",
        integrity.findings
    );
}

/// A lockfile that appears in a nested directory is compared with nothing, so its direct
/// dependencies are new unless the base commit holds the name somewhere.
#[test]
fn a_nested_lockfile_cannot_bring_in_a_name_the_base_does_not_hold() {
    let mut head = base();
    head.push((
        "tools/Cargo.toml".to_owned(),
        manifest("tools", "[dependencies]\nnew-thing = \"0.1\"\n"),
    ));
    head.push((
        "tools/Cargo.lock".to_owned(),
        lock(&[
            member("tools", &["new-thing"]),
            reg("new-thing", "0.1.0", 'a'),
        ]),
    ));
    let integrity = judge(&base(), &head);
    assert!(
        integrity
            .new_direct
            .iter()
            .any(|entry| entry.package.name == "new-thing"),
        "{:?}",
        integrity.new_direct
    );
}

#[test]
fn a_lockfile_layout_this_reader_does_not_know_is_refused_in_the_candidate() {
    for version in ["1", "5", "\"4\"", "4.0"] {
        let head = with(
            base(),
            "Cargo.lock",
            &format!("version = {version}\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n"),
        );
        assert!(
            judge(&base(), &head).has(check::UNREADABLE),
            "version = {version}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Licenses
// ---------------------------------------------------------------------------------------------

/// Expressions that try to slip a denied license through an operator or a spelling.
#[test]
fn a_license_expression_cannot_hide_a_denied_license() {
    let policy = LicensePolicy::owner_approved();
    for (text, expected) in [
        ("MIT AND GPL-3.0-only", Err(Denial::NotListed)),
        ("GPL-3.0-only AND MIT", Err(Denial::NotListed)),
        (
            "(MIT AND GPL-3.0-only) OR LGPL-2.1-only",
            Err(Denial::NotListed),
        ),
        ("Apache-2.0 WITH GPL-exception", Err(Denial::NotListed)),
        ("LicenseRef-proprietary", Err(Denial::NotListed)),
        ("MIT OR", Err(Denial::Unreadable)),
        ("OR MIT", Err(Denial::Unreadable)),
        ("(MIT", Err(Denial::Unreadable)),
        ("MIT)", Err(Denial::Unreadable)),
        ("MIT GPL-3.0-only", Err(Denial::Unreadable)),
        ("MIT; GPL-3.0-only", Err(Denial::Unreadable)),
        ("", Err(Denial::Unknown)),
        ("   ", Err(Denial::Unknown)),
        ("MIT OR GPL-3.0-only", Ok(())),
        ("(MIT OR Apache-2.0) AND Unicode-3.0", Ok(())),
    ] {
        assert_eq!(policy.check(Some(text)), expected, "{text:?}");
    }
    assert_eq!(policy.check(None), Err(Denial::Unknown));
    let long = format!("MIT OR {}", "MIT OR ".repeat(100));
    assert_eq!(policy.check(Some(&long)), Err(Denial::Unreadable));
}

/// A registry source that knows nothing makes every fact the worst case: the dependency goes to
/// a security approver.
#[test]
fn unknown_registry_facts_send_the_dependency_to_a_security_approver() {
    let head = crate::files::head_adding("some-crate", "0.1.0", 'c');
    let mut table = RegistryTable::new();
    table.insert(normalize("some-crate"), RegistryRecord::default());
    let plan = plan_for(&base(), &head, &table);
    assert_eq!(plan.needs.len(), 1);
    assert_eq!(plan.needs[0].designation, Designation::SecurityApprover);
}
