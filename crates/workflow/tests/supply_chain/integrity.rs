//! The integrity checks: tampering with the lockfile, the sources and the build configuration
//! (NT-SUP-03), and the finding of new direct dependencies.

use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::findings::{Finding, Severity, check};
use factory_workflow::gates::supply_chain::integrity::{Context, Integrity, inspect};
use factory_workflow::gates::supply_chain::model::Side;
use factory_workflow::gates::supply_chain::names::PopularNames;

use super::files::{CRATES_IO, Pkg, files, lock, manifest, member, reg, sum};

type Files = Vec<(String, String)>;

/// The base commit: an application that depends on `serde`, which depends on `serde_derive`.
fn base() -> Files {
    files(&[
        (
            "Cargo.toml",
            manifest("app", "[dependencies]\nserde = \"1\"\n"),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["serde"]),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ])
}

fn with(mut list: Files, path: &str, text: &str) -> Files {
    list.retain(|(existing, _)| existing != path);
    list.push((path.to_owned(), text.to_owned()));
    list
}

fn side(list: &Files) -> Side {
    Side::of(
        &CargoFormat,
        list.iter().map(|(p, t)| (p.as_str(), t.as_str())),
    )
}

fn judge_with(base: &Files, head: &Files, internal: &[String]) -> Integrity {
    let popular = PopularNames::bundled().expect("the bundled list");
    let cx = Context {
        internal_names: internal,
        popular: &popular,
    };
    inspect(&CargoFormat, &side(base), &side(head), &cx).expect("the base is readable")
}

fn judge(base: &Files, head: &Files) -> Integrity {
    judge_with(base, head, &[])
}

fn violations(found: &Integrity) -> Vec<&'static str> {
    found
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Violation)
        .map(|f| f.check)
        .collect()
}

fn warnings(found: &Integrity) -> Vec<&'static str> {
    found
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .map(|f| f.check)
        .collect()
}

#[test]
fn a_change_that_adds_no_dependency_passes_quickly() {
    let found = judge(&base(), &base());
    assert!(found.findings.is_empty(), "{:?}", found.findings);
    assert!(found.diff.is_empty());
    assert!(found.new_direct.is_empty());
    assert!(!found.lock_changed());
}

#[test]
fn a_new_direct_dependency_is_found_and_a_transitive_one_is_not_direct() {
    let head = files(&[
        (
            "Cargo.toml",
            manifest("app", "[dependencies]\nserde = \"1\"\nrand = \"0.8\"\n"),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["rand", "serde"]),
                reg("rand", "0.8.5", 'c').with_deps(&["rand_core"]),
                reg("rand_core", "0.6.4", 'd'),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ]);
    let found = judge(&base(), &head);
    let direct: Vec<&str> = found
        .new_direct
        .iter()
        .map(|d| d.package.name.as_str())
        .collect();
    assert_eq!(direct, vec!["rand"]);
    assert_eq!(
        found.diff.added.len(),
        2,
        "rand and rand_core are both new packages"
    );
    assert!(violations(&found).is_empty(), "{:?}", found.findings);
}

#[test]
fn a_name_that_is_already_in_the_base_lockfile_is_not_new() {
    // `serde_derive` was a transitive package at the base commit. Making it direct adds no name.
    let head = files(&[
        (
            "Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nserde = \"1\"\nserde_derive = \"1\"\n",
            ),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["serde", "serde_derive"]),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ]);
    let found = judge(&base(), &head);
    assert!(found.new_direct.is_empty());
    assert!(violations(&found).is_empty(), "{:?}", found.findings);
}

#[test]
fn negative_nt_sup_03_a_lockfile_source_edit_fails() {
    // The builder points `serde` at a git repository in the lockfile only.
    let head = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde"]),
            reg("serde", "1.0.100", 'a')
                .at_source("git+https://attacker.test/serde?rev=1#abc")
                .without_checksum()
                .with_deps(&["serde_derive"]),
            reg("serde_derive", "1.0.100", 'b'),
        ]),
    );
    let found = judge(&base(), &head);
    assert!(found.has(check::SOURCE), "{:?}", found.findings);
    assert!(
        found
            .findings
            .iter()
            .any(|f| f.message.contains("attacker.test") && !f.message.contains("rev=1")),
        "the host is named and the path and query are not: {:?}",
        found.findings
    );
}

#[test]
fn negative_nt_sup_03_a_lockfile_checksum_edit_fails() {
    let head = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde"]),
            reg("serde", "1.0.100", 'e').with_deps(&["serde_derive"]),
            reg("serde_derive", "1.0.100", 'b'),
        ]),
    );
    let found = judge(&base(), &head);
    assert!(found.has(check::CHECKSUM_CHANGED), "{:?}", found.findings);
    assert!(found.has_violation());
}

#[test]
fn negative_nt_sup_03_a_git_dependency_fails() {
    let head = files(&[
        (
            "Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nserde = \"1\"\nevil = { git = \"https://attacker.test/evil\" }\n",
            ),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["evil", "serde"]),
                reg("evil", "0.1.0", 'f')
                    .at_source("git+https://attacker.test/evil#abc")
                    .without_checksum(),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ]);
    let found = judge(&base(), &head);
    assert!(found.has(check::GIT), "{:?}", found.findings);
    assert!(
        found.has(check::SOURCE),
        "the lockfile package is flagged as well"
    );
}

#[test]
fn negative_nt_sup_03_a_path_dependency_fails() {
    let head = files(&[
        (
            "Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nserde = \"1\"\nlocal = { path = \"vendor/local\" }\n",
            ),
        ),
        ("vendor/local/Cargo.toml", manifest("local", "")),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["local", "serde"]),
                member("local", &[]),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ]);
    let found = judge(&base(), &head);
    assert!(found.has(check::PATH), "{:?}", found.findings);
}

#[test]
fn negative_nt_sup_03_a_lockfile_package_with_no_source_and_no_manifest_fails() {
    // A package with no source looks like a path dependency. No manifest describes it.
    let head = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde", "ghost"]),
            member("ghost", &[]),
            reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
            reg("serde_derive", "1.0.100", 'b'),
        ]),
    );
    let found = judge(&base(), &head);
    assert!(found.has(check::PATH_UNEXPLAINED), "{:?}", found.findings);
}

#[test]
fn negative_nt_sup_03_a_patch_section_fails() {
    let head = with(
        base(),
        "Cargo.toml",
        &manifest(
            "app",
            "[dependencies]\nserde = \"1\"\n\n[patch.crates-io]\nserde = { git = \"https://attacker.test/serde\" }\n",
        ),
    );
    let found = judge(&base(), &head);
    assert!(found.has(check::PATCH), "{:?}", found.findings);
}

#[test]
fn negative_nt_sup_03_a_replace_section_fails() {
    let head = with(
        base(),
        "Cargo.toml",
        &manifest(
            "app",
            "[dependencies]\nserde = \"1\"\n\n[replace]\n\"serde:1.0.100\" = { path = \"evil\" }\n",
        ),
    );
    assert!(judge(&base(), &head).has(check::PATCH));
}

#[test]
fn negative_nt_sup_03_an_alternate_registry_in_the_build_configuration_fails() {
    let config = "[registries.corp]\nindex = \"sparse+https://attacker.test/index/\"\n\n[source.crates-io]\nreplace-with = \"corp\"\n";
    let head = with(base(), ".cargo/config.toml", config);
    let found = judge(&base(), &head);
    let redirects = found
        .findings
        .iter()
        .filter(|f| f.check == check::REGISTRY_REDIRECT)
        .count();
    assert_eq!(redirects, 2, "{:?}", found.findings);
    assert!(
        found
            .findings
            .iter()
            .all(|f| !f.message.contains("attacker.test")),
        "the value of a configuration key is never repeated: {:?}",
        found.findings
    );
}

#[test]
fn negative_nt_sup_03_an_alternate_registry_in_a_dependency_fails() {
    let head = with(
        base(),
        "Cargo.toml",
        &manifest(
            "app",
            "[dependencies]\nserde = \"1\"\ncorp-lib = { version = \"1\", registry = \"corp\" }\n",
        ),
    );
    assert!(judge(&base(), &head).has(check::ALTERNATE_REGISTRY));
}

#[test]
fn negative_nt_sup_03_the_hostile_fixture_build_configuration_fails() {
    // The stored copy of the file of FX-REPO-HOSTILE: a rustc wrapper, an environment, a runner
    // and a registry. Read as text; nothing of it runs.
    let hostile = include_str!(
        "../../../../fixtures/repos/security/hostile/files/dot-cargo/config.toml.fixture"
    );
    let head = with(base(), ".cargo/config.toml", hostile);
    let found = judge(&base(), &head);
    let keys: Vec<&str> = found
        .findings
        .iter()
        .filter(|f| f.is_violation())
        .map(|f| f.check)
        .collect();
    assert!(keys.contains(&check::REGISTRY_REDIRECT), "{keys:?}");
    assert!(keys.contains(&check::BUILD_CONFIG), "{keys:?}");
}

#[test]
fn a_build_configuration_that_was_already_at_the_base_commit_is_not_new() {
    let config = "[build]\nrustc-wrapper = \"/opt/sccache\"\n";
    let both = with(base(), ".cargo/config.toml", config);
    let found = judge(&both, &both);
    assert!(violations(&found).is_empty(), "{:?}", found.findings);
}

#[test]
fn a_harmless_build_configuration_is_allowed() {
    let head = with(
        base(),
        ".cargo/config.toml",
        "[term]\ncolor = \"never\"\n\n[build]\njobs = 2\n",
    );
    assert!(violations(&judge(&base(), &head)).is_empty());
}

#[test]
fn a_key_that_is_not_known_to_be_harmless_is_not_trusted() {
    let head = with(base(), ".cargo/config.toml", "[brand-new-table]\nkey = 1\n");
    assert!(judge(&base(), &head).has(check::BUILD_CONFIG));
}

#[test]
fn a_checksum_that_changes_with_no_change_of_version_is_caught() {
    let head = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde"]),
            reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
            reg("serde_derive", "1.0.100", '9'),
        ]),
    );
    let found = judge(&base(), &head);
    assert!(found.has(check::CHECKSUM_CHANGED));
    let message = &found
        .findings
        .iter()
        .find(|f| f.check == check::CHECKSUM_CHANGED)
        .expect("a finding")
        .message;
    assert!(message.contains("serde_derive"), "{message}");
    assert!(
        !message.contains(&sum('9')),
        "a checksum is not repeated in a sentence"
    );
}

#[test]
fn a_registry_package_without_a_valid_checksum_is_caught() {
    let head = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde"]),
            reg("serde", "1.0.101", 'a')
                .without_checksum()
                .with_deps(&["serde_derive"]),
            reg("serde_derive", "1.0.100", 'b'),
        ]),
    );
    assert!(judge(&base(), &head).has(check::CHECKSUM_MISSING));
}

#[test]
fn a_downgrade_is_caught() {
    let head = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde"]),
            reg("serde", "1.0.90", 'c').with_deps(&["serde_derive"]),
            reg("serde_derive", "1.0.100", 'b'),
        ]),
    );
    assert!(judge(&base(), &head).has(check::DOWNGRADE));
}

#[test]
fn a_lockfile_edited_without_a_manifest_change_is_caught() {
    // A package appears in the lockfile that nothing in any manifest asked for.
    let head = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde"]),
            reg("serde", "1.0.100", 'a').with_deps(&["serde_derive", "extra"]),
            reg("serde_derive", "1.0.100", 'b'),
            reg("extra", "0.1.0", 'c'),
        ]),
    );
    let found = judge(&base(), &head);
    assert!(found.has(check::LOCKFILE_ONLY), "{:?}", found.findings);
}

#[test]
fn a_plain_update_of_the_lockfile_is_a_warning_and_not_a_failure() {
    let head = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde"]),
            reg("serde", "1.0.101", 'c').with_deps(&["serde_derive"]),
            reg("serde_derive", "1.0.100", 'b'),
        ]),
    );
    let found = judge(&base(), &head);
    assert!(violations(&found).is_empty(), "{:?}", found.findings);
    assert_eq!(warnings(&found), vec![check::UPDATE_ONLY]);
}

#[test]
fn a_manifest_dependency_missing_from_the_lockfile_is_caught() {
    let head = with(
        base(),
        "Cargo.toml",
        &manifest("app", "[dependencies]\nserde = \"1\"\nrand = \"0.8\"\n"),
    );
    assert!(judge(&base(), &head).has(check::LOCKFILE_STALE));
}

#[test]
fn removing_the_lockfile_is_caught() {
    let head = files(&[(
        "Cargo.toml",
        manifest("app", "[dependencies]\nserde = \"1\"\n"),
    )]);
    let found = judge(&base(), &head);
    assert!(found.has(check::LOCKFILE_REMOVED), "{:?}", found.findings);
    assert!(found.has(check::LOCKFILE_MISSING));
}

#[test]
fn a_new_build_script_or_procedural_macro_is_flagged_for_review() {
    let head = with(
        base(),
        "Cargo.toml",
        &manifest(
            "app",
            "build = \"build.rs\"\n\n[dependencies]\nserde = \"1\"\n\n[lib]\nproc-macro = true\n",
        ),
    );
    let found = judge(&base(), &head);
    assert!(found.has(check::BUILD_CODE), "{:?}", found.findings);
    assert!(
        violations(&found).is_empty(),
        "a flag for review is not a failure"
    );
}

#[test]
fn a_dependency_file_that_cannot_be_read_fails_and_one_of_the_base_blocks() {
    let broken = with(base(), "Cargo.lock", "[[package]\nname = ");
    let found = judge(&base(), &broken);
    assert!(found.has(check::UNREADABLE), "{:?}", found.findings);

    let popular = PopularNames::bundled().expect("the bundled list");
    let cx = Context {
        internal_names: &[],
        popular: &popular,
    };
    let refused = inspect(&CargoFormat, &side(&broken), &side(&base()), &cx);
    assert!(
        refused.is_err(),
        "a broken file at the base commit is not a finding about the change"
    );
}

#[test]
fn an_old_lockfile_layout_is_unreadable_and_never_silently_passed() {
    let head = with(
        base(),
        "Cargo.lock",
        "[metadata]\n\"checksum serde 1.0.100 (x)\" = \"abc\"\n",
    );
    assert!(judge(&base(), &head).has(check::UNREADABLE));
}

#[test]
fn a_transitive_package_with_an_internal_name_from_the_public_registry_is_a_confusion() {
    let head = files(&[
        (
            "Cargo.toml",
            manifest("app", "[dependencies]\nserde = \"1\"\nrand = \"0.8\"\n"),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["rand", "serde"]),
                reg("rand", "0.8.5", 'c').with_deps(&["acme-billing-core"]),
                reg("acme-billing-core", "9.9.9", 'd'),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ]);
    let found = judge_with(&base(), &head, &["acme_billing_core".to_owned()]);
    assert!(found.has(check::CONFUSION), "{:?}", found.findings);
}

#[test]
fn a_transitive_package_one_edit_from_a_popular_name_is_a_warning() {
    let head = files(&[
        (
            "Cargo.toml",
            manifest("app", "[dependencies]\nserde = \"1\"\nrand = \"0.8\"\n"),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["rand", "serde"]),
                reg("rand", "0.8.5", 'c').with_deps(&["reqwset"]),
                reg("reqwset", "0.1.0", 'd'),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ]);
    let found = judge(&base(), &head);
    assert!(
        warnings(&found).contains(&check::SUSPECT_NAME),
        "{:?}",
        found.findings
    );
}

#[test]
fn a_finding_never_repeats_a_credential_from_a_source_address() {
    // The address is put together here, so that no file holds a URL with a password.
    let pass = ["pass", "word-1"].concat();
    let credentials = format!("user:{pass}");
    let query = ["to", "ken=abc"].concat();
    let address = format!("git+https://{credentials}@attacker.test:9999/x?{query}#c");
    let head = with(
        base(),
        "Cargo.lock",
        &lock(&[
            member("app", &["serde"]),
            Pkg {
                name: "serde",
                version: "1.0.100",
                source: Some(address.clone()),
                checksum: None,
                deps: vec!["serde_derive"],
            },
            reg("serde_derive", "1.0.100", 'b'),
        ]),
    );
    let found = judge(&base(), &head);
    let text: String = found
        .findings
        .iter()
        .map(|f: &Finding| f.message.clone())
        .collect();
    assert!(text.contains("attacker.test"));
    for secret in [pass.as_str(), query.as_str(), "9999", "user:"] {
        assert!(!text.contains(secret), "{secret} leaked into {text}");
    }
    assert!(CRATES_IO.starts_with("registry+"));
}
