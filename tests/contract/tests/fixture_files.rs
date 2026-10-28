//! The file checks, on the real fixture (they must hold) and on copies with one deliberate defect
//! each (the matching check must fail). A check that never fails would pass the first group and
//! be caught by the second.

use std::fs;
use std::path::Path;

use fixture_contract::workdir::{TempDir, copy_fixture};
use fixture_contract::{checks, fixture_dir};

fn copy(label: &str) -> TempDir {
    copy_fixture(&fixture_dir(), label).expect("the fixture copies")
}

fn edit(dir: &Path, file: &str, change: impl FnOnce(String) -> String) {
    let path = dir.join(file);
    let text = fs::read_to_string(&path).expect("the file exists");
    fs::write(path, change(text)).expect("the file is written");
}

fn says(findings: &[fixture_contract::Finding], needle: &str) -> bool {
    findings
        .iter()
        .any(|finding| finding.detail.contains(needle))
}

// ---- the real fixture ----------------------------------------------------------------------

#[test]
fn the_real_fixture_passes_every_file_check() {
    let findings = checks::all_static(&fixture_dir());
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn the_fixture_is_not_part_of_the_factory_workspace() {
    // The root manifest lists its members by name. The fixture has its own [workspace] table, and
    // no member glob of the root reaches `fixtures/`.
    let root = fixture_contract::repository_root().join("Cargo.toml");
    let text = fs::read_to_string(root).expect("the root manifest");
    let members_line = text
        .lines()
        .find(|line| line.trim_start().starts_with("members"))
        .expect("a members line");
    assert!(!members_line.contains("fixtures"), "{members_line}");
    assert!(!text.contains("word-count"));
}

// ---- layout ----------------------------------------------------------------------------------

#[test]
fn a_missing_codeowners_file_is_a_layout_finding() {
    let dir = copy("no-codeowners");
    fs::remove_file(dir.path().join("CODEOWNERS")).expect("removed");
    assert!(says(&checks::layout(dir.path()), "CODEOWNERS is missing"));
}

#[test]
fn a_build_script_is_a_layout_finding() {
    let dir = copy("build-script");
    fs::write(dir.path().join("build.rs"), "fn main() {}\n").expect("written");
    assert!(says(&checks::layout(dir.path()), "build.rs must not exist"));
}

#[test]
fn a_cargo_config_directory_is_a_layout_finding() {
    let dir = copy("cargo-config");
    fs::create_dir_all(dir.path().join(".cargo")).expect("made");
    fs::write(dir.path().join(".cargo/config.toml"), "[build]\n").expect("written");
    assert!(says(&checks::layout(dir.path()), ".cargo/config.toml"));
}

// ---- dependencies ----------------------------------------------------------------------------

#[test]
fn a_dependency_is_a_finding() {
    let dir = copy("dependency");
    edit(dir.path(), "Cargo.toml", |text| {
        text.replace("[dependencies]\n", "[dependencies]\nserde = \"1\"\n")
    });
    assert!(says(
        &checks::no_dependencies(dir.path()),
        "lists a dependency under [dependencies]"
    ));
}

#[test]
fn a_dev_dependency_is_a_finding() {
    let dir = copy("dev-dependency");
    edit(dir.path(), "Cargo.toml", |text| {
        format!("{text}\n[dev-dependencies]\ntempfile = \"3\"\n")
    });
    assert!(says(
        &checks::no_dependencies(dir.path()),
        "dev-dependencies"
    ));
}

#[test]
fn a_missing_workspace_table_is_a_finding() {
    let dir = copy("no-workspace");
    edit(dir.path(), "Cargo.toml", |text| {
        text.replace("[workspace]\n", "")
    });
    assert!(says(
        &checks::no_dependencies(dir.path()),
        "no [workspace] table"
    ));
}

#[test]
fn a_registry_package_in_the_lock_file_is_a_finding() {
    let dir = copy("lock");
    edit(dir.path(), "Cargo.lock", |text| {
        format!(
            "{text}\n[[package]]\nname = \"other\"\nversion = \"1.0.0\"\nsource = \"registry+https://example.invalid/index\"\n"
        )
    });
    let findings = checks::no_dependencies(dir.path());
    assert!(says(&findings, "lists 2 packages"));
    assert!(says(&findings, "registry or a repository"));
}

// ---- manifest --------------------------------------------------------------------------------

#[test]
fn a_manifest_that_does_not_protect_itself_is_refused_by_the_loader() {
    let dir = copy("manifest-unprotected");
    edit(dir.path(), ".factory/project.yaml", |text| {
        text.replace("  - \".factory/**\"\n", "")
    });
    let findings = checks::manifest(dir.path());
    assert!(
        says(&findings, "the loader refused the manifest"),
        "{findings:#?}"
    );
    assert!(says(&findings, "protected_paths"), "{findings:#?}");
}

#[test]
fn a_gate_run_through_a_shell_is_refused_by_the_loader() {
    let dir = copy("manifest-shell");
    edit(dir.path(), ".factory/project.yaml", |text| {
        text.replace("[cargo, build, --locked]", "[sh, -c, cargo build]")
    });
    let findings = checks::manifest(dir.path());
    assert!(
        says(&findings, "the loader refused the manifest"),
        "{findings:#?}"
    );
    assert!(says(&findings, "gates[2].argv"), "{findings:#?}");
}

#[test]
fn a_manifest_without_a_protected_golden_directory_is_a_finding() {
    let dir = copy("manifest-golden");
    edit(dir.path(), ".factory/project.yaml", |text| {
        text.replace("  - \"tests/golden/**\"\n", "")
    });
    assert!(says(
        &checks::manifest(dir.path()),
        "tests/golden/** is not a protected path"
    ));
}

#[test]
fn a_mandatory_lint_gate_is_a_finding() {
    let dir = copy("manifest-lint");
    edit(dir.path(), ".factory/project.yaml", |text| {
        text.replace(
            "    timeout_seconds: 600\n    mandatory: false",
            "    timeout_seconds: 600\n    mandatory: true",
        )
    });
    assert!(says(
        &checks::manifest(dir.path()),
        "gate lint must have mandatory = false"
    ));
}

#[test]
fn a_manifest_that_names_another_project_is_a_finding() {
    let dir = copy("manifest-name");
    edit(dir.path(), ".factory/project.yaml", |text| {
        text.replace("name: word-count", "name: other-tool")
    });
    assert!(says(
        &checks::manifest(dir.path()),
        "project.name is other-tool"
    ));
}

#[test]
fn a_required_document_that_does_not_exist_is_a_finding() {
    let dir = copy("manifest-document");
    fs::remove_file(dir.path().join("README.md")).expect("removed");
    assert!(says(
        &checks::manifest(dir.path()),
        "the required document README.md does not exist"
    ));
}

// ---- CODEOWNERS ------------------------------------------------------------------------------

#[test]
fn codeowners_without_the_catch_all_rule_is_a_finding() {
    let dir = copy("codeowners-star");
    edit(dir.path(), "CODEOWNERS", |text| {
        text.replace("* @example-org/maintainers\n", "")
    });
    assert!(says(&checks::codeowners(dir.path()), "no rule for *"));
}

#[test]
fn a_codeowners_rule_without_an_owner_is_a_finding() {
    let dir = copy("codeowners-owner");
    edit(dir.path(), "CODEOWNERS", |text| format!("{text}/docs/\n"));
    assert!(says(&checks::codeowners(dir.path()), "names no owner"));
}

// ---- secrets ---------------------------------------------------------------------------------

#[test]
fn a_token_shaped_string_is_a_finding() {
    let dir = copy("secret-token");
    // Built at run time, so this file holds no secret-shaped literal.
    let token = format!("{}{}_{}", "gh", "p", "A".repeat(36));
    edit(dir.path(), "README.md", |text| {
        format!("{text}\nToken: {token}\n")
    });
    assert!(says(&checks::no_secrets(dir.path()), "github-token"));
}

#[test]
fn a_private_key_header_is_a_finding() {
    let dir = copy("secret-key");
    let header = format!("{}{} PRIVATE KEY{}", "-----BEGIN ", "RSA", "-----");
    fs::write(dir.path().join("deploy.txt"), format!("{header}\n")).expect("written");
    assert!(says(&checks::no_secrets(dir.path()), "private-key"));
}

#[test]
fn an_assigned_credential_is_a_finding() {
    let dir = copy("secret-assigned");
    let line = format!("api_key = \"{}\"\n", "x9".repeat(12));
    edit(dir.path(), "src/main.rs", |text| {
        format!("{text}\n// {line}")
    });
    assert!(says(&checks::no_secrets(dir.path()), "assigned-credential"));
}

// ---- README ----------------------------------------------------------------------------------

const HELP: &str = "Usage: word-count [FILE]\n\nOptions:\n  -h, --help     Show this help and exit.\n  -V, --version  Show the version and exit.\n";

fn real_outputs() -> Vec<String> {
    vec![
        "      3       7      31 notes.txt".to_owned(),
        "      1       3      14".to_owned(),
    ]
}

#[test]
fn the_readme_matches_the_help_and_the_outputs_of_the_real_fixture() {
    let findings = checks::readme_matches_reality(&fixture_dir(), HELP, &real_outputs());
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn a_readme_that_documents_an_option_the_tool_lacks_is_a_finding() {
    let dir = copy("readme-option");
    edit(dir.path(), "README.md", |text| {
        text.replace(
            "| `-V`, `--version` | Show the version and exit. |",
            "| `-V`, `--version` | Show the version and exit. |\n| `--json` | Print JSON. |",
        )
    });
    let findings = checks::readme_matches_reality(dir.path(), HELP, &real_outputs());
    assert!(says(
        &findings,
        "documents --json, but the tool does not have it"
    ));
}

#[test]
fn a_readme_that_forgets_an_option_is_a_finding() {
    let dir = copy("readme-forgets");
    edit(dir.path(), "README.md", |text| {
        text.replace("| `-V`, `--version` | Show the version and exit. |\n", "")
    });
    let findings = checks::readme_matches_reality(dir.path(), HELP, &real_outputs());
    assert!(says(
        &findings,
        "the tool has --version, but the README does not document it"
    ));
}

#[test]
fn a_readme_example_output_the_tool_does_not_print_is_a_finding() {
    let dir = copy("readme-output");
    edit(dir.path(), "README.md", |text| {
        text.replace(
            "      3       7      31 notes.txt",
            "      4       7      31 notes.txt",
        )
    });
    let findings = checks::readme_matches_reality(dir.path(), HELP, &real_outputs());
    assert!(says(&findings, "which the tool does not print"));
}

#[test]
fn a_readme_command_no_gate_runs_is_a_finding() {
    let dir = copy("readme-cargo");
    edit(dir.path(), "README.md", |text| {
        text.replace("cargo fmt --check\n", "cargo publish\n")
    });
    let findings = checks::readme_matches_reality(dir.path(), HELP, &real_outputs());
    assert!(says(&findings, "cargo publish"));
}

// ---- the open gap ----------------------------------------------------------------------------

#[test]
fn a_fixture_that_already_has_the_planned_files_has_no_open_gap() {
    let dir = copy("gap-files");
    fs::write(dir.path().join("src/output.rs"), "// JSON output\n").expect("written");
    assert!(says(&checks::gap_files(dir.path()), "src/output.rs exists"));
}

#[test]
fn a_readme_that_mentions_json_has_no_open_gap() {
    let dir = copy("gap-readme");
    edit(dir.path(), "README.md", |text| {
        format!("{text}\nThe JSON option exists.\n")
    });
    assert!(says(
        &checks::gap_files(dir.path()),
        "README.md already mentions JSON"
    ));
}
