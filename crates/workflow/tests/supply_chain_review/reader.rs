//! Attack: a manifest that cargo reads one way and the hand-written reader reads another.
//!
//! The reader (`toml.rs`, `cargo.rs`) is written to refuse what it does not know. The question is
//! whether there is a manifest that **cargo accepts** and the reader **accepts but reads
//! differently**, so that a dependency source (`git`, `path`, another registry) cargo sees is not
//! the one the reader reports.
//!
//! Method. 86 crafted manifests were written to a scratch directory outside the repository, and
//! `cargo metadata --no-deps --offline --format-version 1` (cargo 1.98.0, which parses manifests
//! and runs nothing) was asked for the dependencies of each. The same manifests were read with
//! `CargoFormat::parse_manifest`. The table below is the record of the cargo side for the cases
//! that matter, so that this test needs no cargo at run time. To refresh it, repeat the method
//! with a newer cargo.
//!
//! Result. For every manifest that both cargo and the reader accepted, the set of
//! (package name, source kind) was **the same**. The reader refused three manifests that cargo
//! 1.98.0 accepts, all of them TOML 1.1 syntax; that costs a false rejection, not a bypass.
//! The differences that do exist are about build code and are listed as SC-9 below.

use std::collections::{BTreeMap, BTreeSet};

use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::findings::check;
use factory_workflow::gates::supply_chain::model::{
    DeclaredSource, DependencyFormat, Manifest, normalize,
};

use crate::files::{base, judge, with};

const HEADER: &str = "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";

fn h(body: &str) -> String {
    format!("{HEADER}{body}")
}

fn kind(source: DeclaredSource) -> &'static str {
    match source {
        DeclaredSource::Registry => "registry",
        DeclaredSource::AlternateRegistry => "altreg",
        DeclaredSource::Path => "path",
        DeclaredSource::Git => "git",
        DeclaredSource::Workspace => "workspace",
    }
}

/// What the reader reports for a manifest: (normalized package name, source kind), with a
/// dependency inherited from the workspace table resolved through that table.
fn reader_view(manifest: &Manifest) -> BTreeSet<(String, &'static str)> {
    let workspace: BTreeMap<&str, (&str, DeclaredSource)> = manifest
        .workspace_declared
        .iter()
        .map(|d| (d.key.as_str(), (d.name.as_str(), d.source)))
        .collect();
    manifest
        .declared
        .iter()
        .map(|d| {
            let (name, source) = if d.source == DeclaredSource::Workspace {
                workspace
                    .get(d.key.as_str())
                    .copied()
                    .unwrap_or((d.key.as_str(), DeclaredSource::Workspace))
            } else {
                (d.name.as_str(), d.source)
            };
            (normalize(name), kind(source))
        })
        .collect()
}

/// One manifest and what cargo 1.98.0 said about its dependencies.
struct Case {
    id: &'static str,
    text: String,
    cargo: &'static [(&'static str, &'static str)],
}

const REGISTRY: &[(&str, &str)] = &[("evil", "registry")];
const GIT: &[(&str, &str)] = &[("evil", "git")];
const PATH: &[(&str, &str)] = &[("evil", "path")];
const ALTERNATE: &[(&str, &str)] = &[("evil", "altreg")];

fn cases() -> Vec<Case> {
    let case = |id, text: String, cargo| Case { id, text, cargo };
    vec![
        case(
            "rename",
            h("[dependencies]\nfoo = { package = \"evil\", version = \"1\" }\n"),
            REGISTRY,
        ),
        case(
            "target_cfg",
            h("[target.'cfg(unix)'.dependencies]\nevil = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "target_double_quoted_build",
            h("[target.\"cfg(unix)\".build-dependencies]\nevil = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "dev_underscore",
            h("[dev_dependencies]\nevil = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "build_underscore",
            h("[build_dependencies]\nevil = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "header_git",
            h("[dependencies.evil]\ngit = \"https://example.test/evil\"\n"),
            GIT,
        ),
        case(
            "dotted_git",
            h("[dependencies]\nevil.git = \"https://example.test/evil\"\n"),
            GIT,
        ),
        case(
            "root_dotted",
            format!("dependencies.evil = \"1\"\n{HEADER}"),
            REGISTRY,
        ),
        case(
            "root_inline_table",
            format!("dependencies = {{ evil = \"1\" }}\n{HEADER}"),
            REGISTRY,
        ),
        case(
            "root_target_dotted_git",
            format!(
                "target.'cfg(unix)'.dependencies.evil = {{ git = \"https://example.test/e\" }}\n{HEADER}"
            ),
            GIT,
        ),
        case(
            "quoted_table_name",
            h("[\"dependencies\"]\nevil = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "unicode_escape_in_key",
            h("[dependencies]\n\"ev\\u0069l\" = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "unicode_escape_in_path_key",
            h("[dependencies]\nevil = { \"pa\\u0074h\" = \"../x\" }\n"),
            PATH,
        ),
        case(
            "crlf",
            h("[dependencies]\nevil = \"1\"\n").replace('\n', "\r\n"),
            REGISTRY,
        ),
        case(
            "byte_order_mark",
            format!("\u{feff}{}", h("[dependencies]\nevil = \"1\"\n")),
            REGISTRY,
        ),
        case(
            "spaced_dotted_header",
            h("[ dependencies . evil ]\nversion = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "arrays_of_tables",
            h(
                "[[bin]]\nname = \"a\"\npath = \"src/a.rs\"\n[[bin]]\nname = \"b\"\npath = \"src/b.rs\"\n[dependencies]\nevil = \"1\"\n",
            ),
            REGISTRY,
        ),
        case(
            "workspace_inherit",
            h(
                "[dependencies]\nevil = { workspace = true }\n[workspace]\n[workspace.dependencies]\nevil = \"1\"\n",
            ),
            REGISTRY,
        ),
        case(
            "workspace_inherit_dotted",
            h(
                "[dependencies]\nevil.workspace = true\n[workspace]\n[workspace.dependencies]\nevil = \"1\"\n",
            ),
            REGISTRY,
        ),
        case(
            "workspace_rename",
            h(
                "[dependencies]\nfoo = { workspace = true }\n[workspace]\n[workspace.dependencies]\nfoo = { package = \"evil\", version = \"1\" }\n",
            ),
            REGISTRY,
        ),
        case(
            "git_with_rename",
            h("[dependencies]\nfoo = { package = \"evil\", git = \"https://example.test/e\" }\n"),
            GIT,
        ),
        case(
            "path_with_version",
            h("[dependencies]\nevil = { version = \"1\", path = \"../e\" }\n"),
            PATH,
        ),
        case(
            "dev_git_for_a_triple",
            h(
                "[target.x86_64-unknown-linux-gnu.dev-dependencies]\nevil = { git = \"https://example.test/e\" }\n",
            ),
            GIT,
        ),
        case(
            "target_with_dots_in_the_name",
            h("[target.\"a.b\".dependencies]\nevil = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "optional",
            h(
                "[dependencies]\nevil = { version = \"1\", optional = true }\n[features]\nx = [\"dep:evil\"]\n",
            ),
            REGISTRY,
        ),
        case(
            "registry_index",
            h(
                "[dependencies]\nevil = { version = \"1\", registry-index = \"https://example.test/idx\" }\n",
            ),
            ALTERNATE,
        ),
        case(
            "registry_named_crates_io",
            h("[dependencies]\nevil = { version = \"1\", registry = \"crates-io\" }\n"),
            ALTERNATE,
        ),
        case(
            "tabs_around_the_equals_sign",
            h("[dependencies]\n\tevil\t=\t\"1\"\n"),
            REGISTRY,
        ),
        case(
            "comment_that_mentions_git",
            h("[dependencies]\nevil = \"1\" # git = \"x\"\n"),
            REGISTRY,
        ),
        case(
            "literal_string",
            h("[dependencies]\nevil = '1'\n"),
            REGISTRY,
        ),
        case(
            "multi_line_string",
            h("[dependencies]\nevil = \"\"\"1\"\"\"\n"),
            REGISTRY,
        ),
        case(
            "multi_line_string_with_a_break",
            h("[dependencies]\nevil = \"\"\"\n1\"\"\"\n"),
            REGISTRY,
        ),
        case(
            "line_ending_backslash",
            h("[dependencies]\nevil = \"\"\"\\\n   1\"\"\"\n"),
            REGISTRY,
        ),
        case(
            "spaced_table_header",
            h("[ dependencies ]\nevil = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "indented_key",
            h("[dependencies]\n evil = \"1\"\n"),
            REGISTRY,
        ),
        case(
            "wildcard_requirement",
            h("[dependencies]\nevil = \"*\"\n"),
            REGISTRY,
        ),
        case(
            "a_dependencies_key_inside_package_is_not_a_dependency",
            h("dependencies = { a = \"1\" }\n[dependencies.b]\nversion = \"1\"\n"),
            &[("b", "registry")],
        ),
    ]
}

#[test]
fn every_manifest_that_both_cargo_and_the_reader_accept_is_read_the_same_way() {
    let mut differences = Vec::new();
    let mut compared = 0_usize;
    for case in cases() {
        let Ok(manifest) = CargoFormat.parse_manifest(&case.text) else {
            differences.push(format!(
                "{}: the reader refused a manifest cargo accepts",
                case.id
            ));
            continue;
        };
        compared += 1;
        let reader = reader_view(&manifest);
        let cargo: BTreeSet<(String, &str)> = case
            .cargo
            .iter()
            .map(|(name, kind)| (normalize(name), *kind))
            .collect();
        if reader != cargo {
            differences.push(format!(
                "{}: cargo reads {cargo:?} and the reader reads {reader:?}",
                case.id
            ));
        }
    }
    assert!(differences.is_empty(), "{differences:#?}");
    assert!(compared >= 35, "only {compared} manifests were compared");
}

/// TOML 1.1 syntax that cargo 1.98.0 accepts and the reader does not know. The reader refuses it,
/// the gate fails with `unreadable-dependency-file`, and nothing is read half way.
#[test]
fn toml_1_1_syntax_that_cargo_accepts_is_refused_and_not_misread() {
    let accepted_by_cargo = [
        // A table spread over lines, with a git source on the second line.
        h("[dependencies]\nevil = {\n  version = \"1\",\n  git = \"https://example.test/e\",\n}\n"),
        // A trailing comma in an inline table.
        h("[dependencies]\nevil = { version = \"1\", }\n"),
        // A `\x` escape in a key.
        h("[dependencies]\n\"ev\\x69l\" = \"1\"\n"),
    ];
    for text in accepted_by_cargo {
        assert!(CargoFormat.parse_manifest(&text).is_err(), "{text}");
        let head = with(base(), "Cargo.toml", &text);
        let integrity = judge(&base(), &head);
        assert!(
            integrity.has(check::UNREADABLE),
            "{text}: {:?}",
            integrity.findings
        );
    }
}

#[test]
fn a_patch_or_replace_section_is_seen_in_every_spelling_cargo_accepts() {
    let patched = [
        h(
            "[dependencies]\nserde = \"1\"\n[patch.crates-io]\nserde = { git = \"https://example.test/serde\" }\n",
        ),
        h(
            "[patch.\"https://github.com/rust-lang/crates.io-index\"]\nserde = { path = \"../s\" }\n",
        ),
        h(
            "[dependencies]\nserde = \"1\"\n[replace]\n\"serde:1.0.0\" = { git = \"https://example.test/serde\" }\n",
        ),
        format!("patch.crates-io.serde = {{ path = \"../s\" }}\n{HEADER}"),
    ];
    for text in patched {
        let manifest = CargoFormat.parse_manifest(&text).expect("a manifest");
        assert!(!manifest.patches.is_empty(), "{text}");
        let head = with(base(), "Cargo.toml", &text);
        let integrity = judge(&base(), &head);
        assert!(
            integrity.has(check::PATCH),
            "{text}: {:?}",
            integrity.findings
        );
    }
}

// ---------------------------------------------------------------------------------------------
// SC-9: build code that cargo sees and the reader does not (a warning, not a block)
// ---------------------------------------------------------------------------------------------

/// Cargo 1.98.0 still accepts `[project]` as an alias of `[package]`. With `[project] build =
/// "x.rs"` cargo lists a `custom-build` target (observed with `cargo metadata --no-deps`); the
/// reader reads `package` only, so the manifest has no name and no build script.
#[test]
fn sc9_the_project_alias_of_the_package_table_is_read() {
    let text = "[project]\nname = \"app\"\nversion = \"0.1.0\"\nbuild = \"x.rs\"\n";
    let manifest = CargoFormat.parse_manifest(text).expect("a manifest");
    assert_eq!(manifest.name.as_deref(), Some("app"));
    assert!(manifest.build_script);
}

/// `[lib] crate-type = ["proc-macro"]` builds a procedural macro (observed: cargo lists a
/// `proc-macro` target). The reader looks for `proc-macro = true` only.
#[test]
fn sc9_a_proc_macro_declared_by_crate_type_is_seen() {
    let text = h("[lib]\ncrate-type = [\"proc-macro\"]\n");
    let manifest = CargoFormat.parse_manifest(&text).expect("a manifest");
    assert!(manifest.proc_macro);
}

/// A `build.rs` next to a manifest that names no `build` key is a build script all the same: cargo
/// finds it by its name. The manifest cannot say so, so the gate reads the presence of the file.
#[test]
fn sc9_a_plain_build_rs_next_to_a_manifest_is_build_code() {
    let head = with(base(), "build.rs", "fn main() {}\n");
    let integrity = judge(&base(), &head);
    assert!(integrity.has(check::BUILD_CODE), "{:?}", integrity.findings);
    assert!(!integrity.has_violation(), "it is a warning, not a block");
}

/// The name is matched without regard to case, in the directory of the manifest only, and `build
/// = false` turns the script off.
#[test]
fn sc9_the_plain_build_script_rules_follow_cargo() {
    let in_other_dir = with(base(), "tools/build.rs", "fn main() {}\n");
    assert!(!judge(&base(), &in_other_dir).has(check::BUILD_CODE));

    let upper = with(base(), "BUILD.RS", "fn main() {}\n");
    assert!(judge(&base(), &upper).has(check::BUILD_CODE));

    let off = with(
        with(base(), "build.rs", "fn main() {}\n"),
        "Cargo.toml",
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nbuild = false\n\n[dependencies]\nserde = \"1\"\n",
    );
    assert!(!judge(&base(), &off).has(check::BUILD_CODE));
}

/// A build script that the base commit already had is not new.
#[test]
fn sc9_a_build_script_the_base_commit_already_had_is_not_reported_again() {
    let with_script = with(base(), "build.rs", "fn main() {}\n");
    let changed = with(
        with_script.clone(),
        "build.rs",
        "fn main() { /* more */ }\n",
    );
    assert!(!judge(&with_script, &changed).has(check::BUILD_CODE));
}
