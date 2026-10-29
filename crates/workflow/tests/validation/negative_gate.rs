//! The negative tests of the gate group (`docs/security/negative-test-catalog.md`, section 7)
//! that this package owns: NT-GATE-01 to 07 and 10, and the tamper tests of the work package.
//!
//! In every test where the change is refused by a host-side rule, the sandbox is never created
//! and no command is ever run: the protected-path check comes before any gate.

use std::sync::Arc;

use factory_domain::contracts::gate_report::{BlockedCode, DefinitionSource};
use factory_domain::policy::paths::PathPolicy;
use factory_domain::vocabulary::GateOutcome;
use factory_ports::paths::CommitSha;
use factory_ports::sandbox::{ImageDigest, SandboxError};
use factory_ports::workspace::ChangeKind;
use factory_workflow::gates::command::TrustedGates;
use factory_workflow::gates::framework::{BlockCause, Resolution, resolve};
use factory_workflow::gates::scope::{self, Facts, FileChange, patch};
use factory_workflow::stages::validation::{JsonManifestReader, ManifestReader, ValidationHandler};

use crate::cargo::{TestRun, libtest};
use crate::gates::{
    base_run, gate, head_run, it_with_one_more, manifest_with, passing_world, run_of,
};
use crate::world::{MANIFEST, Ran, World, base_files, with};

/// A path and its new text, or `None` for a deleted path.
type Change<'a> = (&'a str, Option<&'a str>);

/// A fixture project, a change to it, and a run of the stage over it.
async fn run_change(changes: &[(&str, Option<&str>)], head: TestRun) -> (World, Ran) {
    let w = World::new();
    let (base, head_commit) = w.project(changes).await;
    w.cargo.queue_test_run(head);
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head_commit).await;
    (w, ran)
}

fn nothing_ran(w: &World, ran: &Ran) {
    assert_eq!(w.sandbox.created(), 0, "no sandbox was made");
    assert!(
        w.cargo.calls().is_empty(),
        "no command ran: {:?}",
        w.cargo.calls()
    );
    assert!(ran.decision.policy_violation);
    assert_eq!(
        ran.resolution,
        Resolution::Blocked(BlockCause::PolicyViolation)
    );
}

fn messages(ran: &Ran, gate: &str) -> String {
    ran.report(gate)
        .failures
        .iter()
        .flatten()
        .map(|failure| failure.message.as_str().to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

fn it_edit(from: &str, to: &str) -> String {
    let text = base_files()
        .into_iter()
        .find(|(path, _)| path == "tests/it.rs")
        .map(|(_, text)| text)
        .expect("the file exists");
    assert!(text.contains(from), "the fixture holds {from:?}");
    text.replace(from, to)
}

// -------------------------------------------------------------------------------------------
// NT-GATE-01: test code is additions-only
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_gate_01_a_new_test_file_and_an_appended_test_pass_the_path_rule() {
    let extra = "#[test]\nfn fr_005_new_file() {}\n";
    let head = libtest(
        &[
            (
                "unittests src/lib.rs",
                &[("tests::unit_counts_words", "ok")],
            ),
            ("tests/extra.rs", &[("fr_005_new_file", "ok")]),
            (
                "tests/it.rs",
                &[
                    ("fr_001_counts_a_line", "ok"),
                    ("fr_002_counts_one_word", "ok"),
                    ("fr_003_counts_nothing", "ok"),
                ],
            ),
            ("doc-tests word_count", &[]),
        ],
        0,
    );
    let (_, ran) = run_change(&[("tests/extra.rs", Some(extra))], head).await;
    assert_eq!(
        ran.outcome("protected-paths-unchanged"),
        GateOutcome::Passed
    );
    assert_eq!(ran.outcome("test-file-protection"), GateOutcome::Passed);
    assert_eq!(ran.resolution, Resolution::Pass);

    let more = it_with_one_more();
    let (_, ran) = run_change(&[("tests/it.rs", Some(&more))], head_run()).await;
    assert_eq!(ran.outcome("test-file-protection"), GateOutcome::Passed);
    assert_eq!(ran.resolution, Resolution::Pass);
}

#[tokio::test]
async fn negative_nt_gate_01_a_changed_removed_deleted_or_renamed_test_is_blocked_by_its_group() {
    let changed = it_edit(
        "assert_eq!(count(\"one two\"), 2);",
        "assert_eq!(count(\"one two\"), 3);",
    );
    let removed = it_edit("    assert_eq!(count(\"\"), 0);\n", "");
    let renamed = base_files()
        .into_iter()
        .find(|(path, _)| path == "tests/it.rs")
        .map(|(_, text)| text)
        .expect("the file exists");
    let cases: [(&str, Vec<Change<'_>>); 4] = [
        (
            "an assertion line is changed",
            vec![("tests/it.rs", Some(&changed))],
        ),
        (
            "an assertion line is removed",
            vec![("tests/it.rs", Some(&removed))],
        ),
        ("a test file is deleted", vec![("tests/it.rs", None)]),
        (
            "a test file is renamed",
            vec![("tests/it.rs", None), ("tests/renamed.rs", Some(&renamed))],
        ),
    ];
    for (what, changes) in cases {
        let (w, ran) = run_change(&changes, head_run()).await;
        assert_eq!(
            ran.outcome("test-file-protection"),
            GateOutcome::Failed,
            "{what}"
        );
        assert!(
            ran.failure_checks("test-file-protection")
                .contains(&"test-code-not-additions-only".to_owned()),
            "{what}"
        );
        assert!(
            messages(&ran, "test-file-protection").contains("protected_paths.groups:test_code"),
            "{what}: the decision names the group"
        );
        nothing_ran(&w, &ran);
    }
}

// -------------------------------------------------------------------------------------------
// NT-GATE-02: removed, ignored or skipped tests
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_gate_02_a_test_removed_or_ignored_inside_a_source_file_is_found_at_the_source()
{
    let without_test =
        "pub fn count(text: &str) -> usize {\n    text.split_whitespace().count()\n}\n";
    let ignored = crate::world::LIB.replace("    #[test]\n", "    #[test]\n    #[ignore]\n");
    for (what, lib, expected) in [
        (
            "a test function is removed",
            without_test.to_owned(),
            "test-removed",
        ),
        ("a test is marked ignored", ignored, "test-ignored"),
    ] {
        let (w, ran) = run_change(&[("src/lib.rs", Some(&lib))], head_run()).await;
        assert_eq!(
            ran.outcome("test-file-protection"),
            GateOutcome::Failed,
            "{what}"
        );
        assert!(
            ran.failure_checks("test-file-protection")
                .contains(&expected.to_owned()),
            "{what}: {:?}",
            ran.failure_checks("test-file-protection")
        );
        nothing_ran(&w, &ran);
    }
}

#[tokio::test]
async fn negative_nt_gate_02_skip_xfail_and_focus_markers_in_new_files_are_found() {
    let cases = [
        (
            "tests/test_skip.py",
            "import pytest\n\n@pytest.mark.skip(reason='later')\ndef test_a():\n    pass\n",
            "test-skipped",
        ),
        (
            "tests/test_xfail.py",
            "import pytest\n\n@pytest.mark.xfail\ndef test_a():\n    assert False\n",
            "test-skipped",
        ),
        (
            "tests/skip.test.js",
            "test.skip('a', () => {});\n",
            "test-skipped",
        ),
        (
            "tests/only.test.js",
            "it.only('a', () => {});\n",
            "test-focused",
        ),
    ];
    for (path, text, expected) in cases {
        let (w, ran) = run_change(&[(path, Some(text))], head_run()).await;
        assert_eq!(
            ran.outcome("test-file-protection"),
            GateOutcome::Failed,
            "{path}"
        );
        assert!(
            ran.failure_checks("test-file-protection")
                .contains(&expected.to_owned()),
            "{path}"
        );
        nothing_ran(&w, &ran);
    }
}

#[tokio::test]
async fn negative_nt_gate_02_a_test_missing_from_the_run_of_the_candidate_is_found_by_the_baseline()
{
    // No marker anywhere: the test is gone from the run only. The baseline run on the base commit
    // is what shows it.
    let lib = crate::world::LIB.replace("#[cfg(test)]", "#[cfg(any())]");
    let head = libtest(
        &[
            ("unittests src/lib.rs", &[]),
            (
                "tests/it.rs",
                &[
                    ("fr_001_counts_a_line", "ok"),
                    ("fr_002_counts_one_word", "ok"),
                    ("fr_003_counts_nothing", "ok"),
                ],
            ),
            ("doc-tests word_count", &[]),
        ],
        0,
    );
    let (_, ran) = run_change(&[("src/lib.rs", Some(&lib))], head).await;
    assert_eq!(ran.outcome("test-file-protection"), GateOutcome::Failed);
    let text = messages(&ran, "test-file-protection");
    assert!(text.contains("tests::unit_counts_words"), "{text}");
    assert!(
        ran.failure_checks("test-file-protection")
            .contains(&"test-removed".to_owned())
    );
    // A report that shows a regression cannot be PASSED.
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Failed);
    assert_eq!(
        ran.report("unit-tests").baseline_comparison.delta,
        factory_domain::contracts::gate_report::BaselineDelta::Regressed
    );
    assert_eq!(
        ran.resolution,
        Resolution::Blocked(BlockCause::PolicyViolation)
    );
}

#[tokio::test]
async fn negative_nt_gate_02_a_test_that_passed_before_and_is_ignored_now_is_found_by_the_baseline()
{
    // The test is ignored by a means no marker rule reads. The run is what shows it.
    let head = run_of(
        &[
            ("fr_001_counts_a_line", "ok"),
            ("fr_002_counts_one_word", "ignored"),
            ("fr_003_counts_nothing", "ok"),
        ],
        0,
    );
    let (_, ran) = run_change(
        &[("README.md", Some("# Word count\n\nMore words.\n"))],
        head,
    )
    .await;
    assert_eq!(ran.outcome("test-file-protection"), GateOutcome::Failed);
    assert!(
        ran.failure_checks("test-file-protection")
            .contains(&"test-ignored".to_owned())
    );
}

// -------------------------------------------------------------------------------------------
// NT-GATE-03: CI, gate and instruction file edits
// -------------------------------------------------------------------------------------------

const GATE_AND_CI_FILES: [&str; 17] = [
    ".github/workflows/ci.yml",
    "scripts/ci.sh",
    "scripts/ci/check.sh",
    "scripts/gates/run.sh",
    "deny.toml",
    ".gitleaks.toml",
    ".cargo/config.toml",
    "Makefile",
    ".pre-commit-config.yaml",
    "AGENTS.md",
    "CLAUDE.md",
    ".claude/settings.json",
    "rust-toolchain.toml",
    ".factory/project.json",
    ".gitlab-ci.yml",
    "CODEOWNERS",
    "rustfmt.toml",
];

#[tokio::test]
async fn negative_nt_gate_03_each_ci_gate_and_instruction_file_edit_fails_before_any_gate_runs() {
    for path in GATE_AND_CI_FILES {
        let (w, ran) = run_change(&[(path, Some("changed by the builder\n"))], head_run()).await;
        assert_eq!(
            ran.outcome("protected-paths-unchanged"),
            GateOutcome::Failed,
            "{path}"
        );
        assert!(
            ran.failure_checks("protected-paths-unchanged")
                .contains(&"protected-path-changed".to_owned()),
            "{path}"
        );
        nothing_ran(&w, &ran);
        // Every command gate says it did not run, and BLOCKED is not a pass.
        for command in ["format", "lint", "build", "unit-tests"] {
            // The configuration of a lint or format tool is also a lint relaxation (AUT-4), which
            // the host reads before any command runs and reports on the lint gate itself. So is a
            // cargo configuration that changed and cannot be read as TOML (RR-13): the host cannot
            // tell that it sets no flags.
            let tool_configuration = path.ends_with("clippy.toml")
                || path.ends_with("rustfmt.toml")
                || path == ".cargo/config.toml";
            let expected = if command == "lint" && tool_configuration {
                GateOutcome::Failed
            } else {
                GateOutcome::Blocked
            };
            assert_eq!(ran.outcome(command), expected, "{path}: {command}");
        }
    }
}

#[tokio::test]
async fn negative_nt_gate_03_deleting_a_protected_file_is_refused_too() {
    let (w, ran) = run_change(&[(".github/workflows/ci.yml", None)], head_run()).await;
    assert_eq!(
        ran.outcome("protected-paths-unchanged"),
        GateOutcome::Failed
    );
    nothing_ran(&w, &ran);
}

// -------------------------------------------------------------------------------------------
// AUT-4: lint_relaxation
// -------------------------------------------------------------------------------------------

/// A crate-level `allow` outranks the `-D warnings` of the lint command, so the lint command can
/// exit 0 for code with warnings. The host reads the attribute before any command runs, fails the
/// lint gate, and no sandbox is made.
#[tokio::test]
async fn aut_4_a_crate_level_allow_attribute_fails_the_lint_gate_before_any_command_runs() {
    let lib = base_files()
        .into_iter()
        .find(|(path, _)| path == "src/lib.rs")
        .map(|(_, text)| text)
        .expect("the fixture holds a library");
    for attribute in [
        "#![allow(warnings)]",
        "#![allow(clippy::all)]",
        "#![allow(unused)]",
        "#![expect(dead_code)]",
    ] {
        let changed = format!("{attribute}\n{lib}");
        let (w, ran) = run_change(&[("src/lib.rs", Some(&changed))], head_run()).await;
        assert_eq!(ran.outcome("lint"), GateOutcome::Failed, "{attribute}");
        assert!(
            ran.failure_checks("lint")
                .contains(&"lint-relaxed".to_owned()),
            "{attribute}"
        );
        assert_eq!(w.sandbox.created(), 0, "{attribute}: no sandbox was made");
        assert!(w.cargo.calls().is_empty(), "{attribute}: no command ran");
        assert_ne!(
            ran.resolution,
            Resolution::Pass,
            "{attribute}: the stage does not pass"
        );
    }
}

#[tokio::test]
async fn aut_4_a_lowered_lint_level_in_the_manifest_fails_the_lint_gate() {
    let manifest = "[package]\nname = \"word-count\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[lints.rust]\nunused = \"allow\"\n";
    let (w, ran) = run_change(&[("Cargo.toml", Some(manifest))], head_run()).await;
    assert_eq!(ran.outcome("lint"), GateOutcome::Failed);
    // A hit is a failure a person decides about (`blocks_until: human_approval`), not a
    // protected-path violation.
    assert!(!ran.decision.policy_violation);
    assert_eq!(w.sandbox.created(), 0, "no sandbox was made");
    assert!(w.cargo.calls().is_empty(), "no command ran");
}

#[tokio::test]
async fn aut_4_an_ordinary_change_still_passes_the_lint_gate() {
    let lib = base_files()
        .into_iter()
        .find(|(path, _)| path == "src/lib.rs")
        .map(|(_, text)| text)
        .expect("the fixture holds a library");
    let changed = format!("{lib}\npub fn extra() {{}}\n");
    let (_w, ran) = run_change(&[("src/lib.rs", Some(&changed))], head_run()).await;
    assert_eq!(ran.outcome("lint"), GateOutcome::Passed);
}

#[tokio::test]
async fn negative_nt_gate_03_a_held_out_test_a_fixture_and_the_project_policy_cannot_be_edited() {
    // A held-out test is hidden: no change may name it.
    let (w, ran) = run_change(
        &[("tests/holdout/case.rs", Some("// edited\n"))],
        head_run(),
    )
    .await;
    assert_eq!(
        ran.outcome("protected-paths-unchanged"),
        GateOutcome::Failed
    );
    assert!(
        ran.failure_checks("protected-paths-unchanged")
            .contains(&"hidden-path".to_owned())
    );
    nothing_ran(&w, &ran);
    // A new fixture file may be added; an existing one may not be edited. The fixture is in the
    // base for this case.
    let w = World::new();
    let base = w
        .push(&with(&[("tests/fixtures/sample.txt", Some("one\n"))]))
        .await;
    let head = w
        .push(&with(&[("tests/fixtures/sample.txt", Some("two\n"))]))
        .await;
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("test-file-protection"), GateOutcome::Failed);
    assert!(
        ran.failure_checks("test-file-protection")
            .contains(&"append-only-path-changed".to_owned())
    );
    nothing_ran(&w, &ran);
}

// -------------------------------------------------------------------------------------------
// NT-GATE-04: path normalization and rename tricks (table-driven, on the trusted diff)
// -------------------------------------------------------------------------------------------

fn change(path: &str, kind: ChangeKind, before: Option<&str>, after: Option<&str>) -> FileChange {
    FileChange {
        path: path.to_owned(),
        kind,
        before: before.map(|text| text.as_bytes().to_vec()),
        after: after.map(|text| text.as_bytes().to_vec()),
        readable: true,
    }
}

fn refusals(
    policy: &PathPolicy,
    files: &[FileChange],
    patch_text: &str,
) -> scope::protected::Refusals {
    let facts: Facts = patch::parse(patch_text.as_bytes());
    scope::protected::check(policy, &scope::entries(files, &facts))
}

#[test]
fn negative_nt_gate_04_every_path_trick_is_refused_with_its_group_and_the_controls_are_not() {
    let world = World::new();
    let policy = &world.policy.paths;
    let ci = ".github/workflows/ci.yml";
    let attacks: Vec<(&str, Vec<FileChange>, &str)> = vec![
        (
            "rename to a free path (a delete and an add)",
            vec![
                change(ci, ChangeKind::Deleted, Some("name: ci\n"), None),
                change("docs/ci.yml", ChangeKind::Added, None, Some("name: ci\n")),
            ],
            "",
        ),
        (
            "case variant",
            vec![change(
                ".GitHub/Workflows/ci.yml",
                ChangeKind::Added,
                None,
                Some("x\n"),
            )],
            "",
        ),
        (
            "a character git ignores inside the name",
            vec![change(
                ".git\u{200b}hub/workflows/ci.yml",
                ChangeKind::Added,
                None,
                Some("x\n"),
            )],
            "",
        ),
        (
            "a fullwidth full stop",
            vec![change(
                "\u{ff0e}github/workflows/ci.yml",
                ChangeKind::Added,
                None,
                Some("x\n"),
            )],
            "",
        ),
        (
            "a trailing dot on a component",
            vec![change(
                ".github./workflows/ci.yml",
                ChangeKind::Added,
                None,
                Some("x\n"),
            )],
            "",
        ),
        (
            "a trailing space on a component",
            vec![change(
                ".github /workflows/ci.yml",
                ChangeKind::Added,
                None,
                Some("x\n"),
            )],
            "",
        ),
        (
            "dot segments and a doubled slash",
            vec![change(
                "./.github//workflows/../workflows/ci.yml",
                ChangeKind::Added,
                None,
                Some("x\n"),
            )],
            "",
        ),
        (
            "the git directory in capitals",
            vec![change(".GIT/config", ChangeKind::Added, None, Some("x\n"))],
            "",
        ),
        (
            "a nested git directory",
            vec![change(
                "sub/.git/hooks/post-commit",
                ChangeKind::Added,
                None,
                Some("x\n"),
            )],
            "",
        ),
        (
            "the workflows directory replaced by a symbolic link",
            vec![change(
                ".github/workflows",
                ChangeKind::Added,
                None,
                Some("../docs"),
            )],
            "diff --git a/.github/workflows b/.github/workflows\nnew file mode 120000\n--- /dev/null\n+++ b/.github/workflows\n@@ -0,0 +1 @@\n+../docs\n",
        ),
        (
            "execute permission on a protected script",
            vec![change(
                "scripts/ci.sh",
                ChangeKind::Modified,
                Some("echo\n"),
                Some("echo\n"),
            )],
            "diff --git a/scripts/ci.sh b/scripts/ci.sh\nold mode 100644\nnew mode 100755\n",
        ),
        (
            "a protected file that became a symbolic link",
            vec![change(
                "deny.toml",
                ChangeKind::Modified,
                Some("x\n"),
                Some("../x"),
            )],
            "diff --git a/deny.toml b/deny.toml\nold mode 100644\nnew mode 120000\n--- a/deny.toml\n+++ b/deny.toml\n@@ -1 +1 @@\n-x\n+../x\n",
        ),
        (
            "a file that is a submodule",
            vec![change("vendor/x", ChangeKind::Added, None, Some(""))],
            "diff --git a/vendor/x b/vendor/x\nnew file mode 160000\n",
        ),
        (
            "a link that points out of the workspace",
            vec![change(
                "docs/link",
                ChangeKind::Added,
                None,
                Some("../../etc/passwd"),
            )],
            "diff --git a/docs/link b/docs/link\nnew file mode 120000\n--- /dev/null\n+++ b/docs/link\n@@ -0,0 +1 @@\n+../../etc/passwd\n",
        ),
    ];
    for (what, files, patch_text) in attacks {
        let found = refusals(policy, &files, patch_text);
        let all = found.protected.len() + found.tests.len();
        assert!(all > 0, "{what} must be refused");
    }
    let controls = [
        change(
            ".github-docs/readme.md",
            ChangeKind::Added,
            None,
            Some("x\n"),
        ),
        change("src/github.rs", ChangeKind::Added, None, Some("x\n")),
        change("docs/ci-notes.md", ChangeKind::Added, None, Some("x\n")),
    ];
    let found = refusals(policy, &controls, "");
    assert!(
        found.protected.is_empty() && found.tests.is_empty(),
        "{found:?}"
    );
}

#[tokio::test]
async fn negative_nt_gate_04_the_tricks_that_a_repository_can_hold_fail_the_whole_stage() {
    // A zero width character in the name of a protected directory cannot be a path at all: since
    // SBX-2 (`paths::hides_text`) `RepoPath` refuses it, so it never reaches a gate, and the
    // fixture below could not build it. The trick that is left is the ones the type allows.
    for hidden in [
        ".git\u{200b}hub/workflows/ci.yml",
        ".github/workflows/ci\u{202e}.yml",
    ] {
        assert_eq!(
            factory_ports::paths::RepoPath::new(hidden),
            Err(factory_ports::paths::NameError::HiddenCharacter),
            "{hidden:?}"
        );
    }
    for path in [".GitHub/Workflows/ci.yml", ".github./workflows/ci.yml"] {
        let (w, ran) = run_change(&[(path, Some("x\n"))], head_run()).await;
        assert_eq!(
            ran.outcome("protected-paths-unchanged"),
            GateOutcome::Failed,
            "{path:?}"
        );
        nothing_ran(&w, &ran);
    }
    for control in [".github-docs/readme.md", "src/github.rs"] {
        let (_, ran) = run_change(&[(control, Some("x\n"))], head_run()).await;
        assert_eq!(
            ran.outcome("protected-paths-unchanged"),
            GateOutcome::Passed,
            "{control}"
        );
    }
}

// -------------------------------------------------------------------------------------------
// NT-GATE-05: builder-supplied gates are ignored
// -------------------------------------------------------------------------------------------

fn expected_definitions(w: &World) -> TrustedGates {
    let manifest = JsonManifestReader
        .read(MANIFEST.as_bytes())
        .expect("the manifest is valid");
    let any_commit = CommitSha::parse(&"a".repeat(40)).expect("a sha");
    TrustedGates::resolve(&manifest, any_commit, &w.policy.commands)
}

#[tokio::test]
async fn negative_nt_gate_05_the_builders_gate_files_do_not_change_what_runs() {
    // Files that a builder might add to steer the gates, in places the policy does not protect.
    let steering = [
        ("gates.json", Some("{\"unit-tests\": [\"true\"]}\n")),
        ("tools/run_tests.sh", Some("#!/bin/sh\nexit 0\n")),
        (
            "report.json",
            Some("{\"outcome\": \"PASSED\", \"tests\": 99}\n"),
        ),
    ];
    let (w, base, head) = {
        let w = World::new();
        let more = it_with_one_more();
        let mut changes = steering.to_vec();
        changes.push(("tests/it.rs", Some(&more)));
        let (base, head) = w.project(&changes).await;
        w.cargo.queue_test_run(head_run());
        w.cargo.queue_test_run(base_run());
        (w, base, head)
    };
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.resolution, Resolution::Pass);
    assert_eq!(
        w.cargo.last("test").expect("the tests ran"),
        ["cargo", "test", "--offline", "--locked"],
        "the command is the base manifest's"
    );
    let expected = expected_definitions(&w);
    for report in &ran.decision.reports {
        let trusted = &report.metadata.trusted_definition;
        assert_eq!(trusted.source, DefinitionSource::ProtectedBaseBranch);
        assert_eq!(trusted.commit_sha.as_str(), base.as_str());
        assert_eq!(&trusted.definition_sha256, expected.hash());
    }
    assert!(
        !ran.evidence.to_string().contains("tests\\\": 99"),
        "the builder's report is not in the evidence"
    );
}

#[tokio::test]
async fn negative_nt_gate_05_an_edit_of_the_gate_definitions_fails_the_protected_path_gate() {
    let weakened = manifest_with(serde_json::json!([
        gate("build", &["cargo", "build"]),
        gate("unit-tests", &["true"]),
    ]));
    let (w, ran) = run_change(&[(".factory/project.json", Some(&weakened))], head_run()).await;
    assert_eq!(
        ran.outcome("protected-paths-unchanged"),
        GateOutcome::Failed
    );
    nothing_ran(&w, &ran);
    // The definitions the reports name are still the base commit's.
    let trusted = &ran.report("build").metadata.trusted_definition;
    assert_eq!(&trusted.definition_sha256, expected_definitions(&w).hash());
}

#[tokio::test]
async fn negative_nt_gate_05_a_test_target_without_the_harness_is_found() {
    let manifest = "[package]\nname = \"word-count\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[[test]]\nname = \"empty\"\npath = \"tests/empty.rs\"\nharness = false\n";
    let (w, ran) = run_change(
        &[
            ("Cargo.toml", Some(manifest)),
            ("tests/empty.rs", Some("fn main() {}\n")),
        ],
        head_run(),
    )
    .await;
    assert_eq!(ran.outcome("test-file-protection"), GateOutcome::Failed);
    assert!(
        ran.failure_checks("test-file-protection")
            .contains(&"test-harness-disabled".to_owned())
    );
    nothing_ran(&w, &ran);
}

// -------------------------------------------------------------------------------------------
// NT-GATE-06: fabricated evidence
// -------------------------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_gate_06_a_forged_report_does_not_hide_a_failing_test() {
    let w = World::new();
    let more = it_with_one_more();
    // The builder commits a report that says everything passed, and prints a forged summary.
    let (base, head) = w
        .project(&[
            ("tests/it.rs", Some(&more)),
            (
                "out/report.json",
                Some("{\"outcome\": \"PASSED\", \"passed\": 99}\n"),
            ),
        ])
        .await;
    let failing = [
        ("fr_001_counts_a_line", "ok"),
        ("fr_002_counts_one_word", "ok"),
        ("fr_003_counts_nothing", "ok"),
        ("fr_004_counts_a_tab", "FAILED"),
    ];
    let mut run = run_of(&failing, 101);
    run.stdout
        .push_str("test result: ok. 99 passed; 0 failed; 0 ignored\n");
    w.cargo.queue_test_run(run);
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Failed);
    let command = ran.report("unit-tests").commands.last().expect("a command");
    assert_eq!(command.exit_code, Some(101), "the supervisor's exit code");
    assert!(!matches!(ran.resolution, Resolution::Pass));
    assert!(!ran.evidence.to_string().contains("99 passed"));
}

#[tokio::test]
async fn negative_nt_gate_06_a_forged_summary_with_exit_code_zero_is_not_accepted() {
    let w = World::new();
    let (base, head) = w
        .project(&[("src/lib.rs", Some(&format!("{}\n", crate::world::LIB)))])
        .await;
    // Exit code 0 and a summary that claims 99 tests, with no test line behind it.
    let forged = TestRun {
        stdout:
            "\nrunning 99 tests\n\ntest result: ok. 99 passed; 0 failed; 0 ignored; 0 measured\n"
                .to_owned(),
        stderr: "     Running tests/it.rs (/out/x)\n".to_owned(),
        exit: 0,
    };
    w.cargo.queue_test_run(forged);
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Blocked);
    assert!(!matches!(ran.resolution, Resolution::Pass));
}

// -------------------------------------------------------------------------------------------
// NT-GATE-07: missing evidence is BLOCKED
// -------------------------------------------------------------------------------------------

async fn blocked_by(test: TestRun) -> Ran {
    let w = World::new();
    let more = it_with_one_more();
    let (base, head) = w.project(&[("tests/it.rs", Some(&more))]).await;
    w.cargo.queue_test_run(test);
    w.cargo.queue_test_run(base_run());
    w.run(&base, &head).await
}

#[tokio::test]
async fn negative_nt_gate_07_a_test_command_that_is_not_found_is_blocked() {
    let ran = blocked_by(TestRun {
        stdout: String::new(),
        stderr: "cargo: not found\n".to_owned(),
        exit: 127,
    })
    .await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Blocked);
    assert_eq!(
        ran.report("unit-tests")
            .blocked_reason
            .as_ref()
            .map(|r| r.code),
        Some(BlockedCode::ToolUnavailable)
    );
    assert!(matches!(
        ran.resolution,
        Resolution::Blocked(BlockCause::GateBlocked(_))
    ));
}

#[tokio::test]
async fn negative_nt_gate_07_a_scanner_missing_from_the_image_is_blocked() {
    let (w, base, head) = passing_world().await;
    w.cargo.lacks("clippy");
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("lint"), GateOutcome::Blocked);
    assert!(matches!(
        ran.resolution,
        Resolution::Blocked(BlockCause::GateBlocked(_))
    ));
}

#[tokio::test]
async fn negative_nt_gate_07_tests_that_collect_zero_tests_are_blocked() {
    let none = libtest(&[("unittests src/lib.rs", &[]), ("tests/it.rs", &[])], 0);
    let ran = blocked_by(none).await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Blocked);
    // Only ignored tests show nothing either.
    let ignored = libtest(
        &[("tests/it.rs", &[("fr_001_counts_a_line", "ignored")])],
        0,
    );
    let ran = blocked_by(ignored).await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Blocked);
}

#[tokio::test]
async fn negative_nt_gate_07_a_gate_that_times_out_is_blocked_and_so_is_one_that_is_killed() {
    for what in ["timeout", "signal", "memory"] {
        let (w, base, head) = passing_world().await;
        w.sandbox.set(Arc::new(move |argv: &[String], mut result| {
            if argv.get(1).map(String::as_str) == Some("build") {
                result.exit_code = None;
                match what {
                    "timeout" => result.timed_out = true,
                    "signal" => result.signal = Some(9),
                    _ => result.oom_killed = true,
                }
            }
            result
        }));
        let ran = w.run(&base, &head).await;
        assert_eq!(ran.outcome("build"), GateOutcome::Blocked, "{what}");
        let command = ran.report("build").commands.last().expect("a command");
        assert_eq!(
            command.exit_code,
            Some(137),
            "{what}: a killed process reads as 128 + 9"
        );
        assert_eq!(command.timed_out, what == "timeout", "{what}");
        assert!(
            matches!(
                ran.resolution,
                Resolution::Blocked(BlockCause::GateBlocked(_))
            ),
            "{what}"
        );
    }
}

#[tokio::test]
async fn negative_nt_gate_07_a_cut_test_output_is_blocked() {
    let (w, base, head) = passing_world().await;
    w.sandbox.set(Arc::new(|argv: &[String], mut result| {
        if argv.get(1).map(String::as_str) == Some("test") {
            result.stdout_truncated = true;
        }
        result
    }));
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Blocked);
}

#[tokio::test]
async fn negative_nt_gate_07_a_daemon_that_is_down_blocks_the_stage_run_and_nothing_runs() {
    for (error, cause) in [
        (
            SandboxError::DaemonUnavailable,
            factory_domain::machines::guards::EnvironmentCause::DaemonUnavailable,
        ),
        (
            SandboxError::ImageUnavailable,
            factory_domain::machines::guards::EnvironmentCause::ImageUnavailable,
        ),
    ] {
        let (w, base, head) = passing_world().await;
        w.sandbox.refuse_with(error);
        let handler = w.handler();
        let upstream = w.upstream(&base, &head).await;
        let contract = w
            .resolve_contract(&handler, &upstream, &w.policy_hash)
            .expect("a contract");
        let result = w.execute(&handler, &contract, &upstream).await;
        let error = result.expect_err("the stage cannot run");
        assert_eq!(error.environment(), Some(cause));
        assert!(
            w.cargo.calls().is_empty(),
            "nothing ran, on the host or anywhere else"
        );
    }
}

#[tokio::test]
async fn negative_nt_gate_07_a_gate_without_a_report_blocks_whatever_the_rest_says() {
    let (w, base, head) = passing_world().await;
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.resolution, Resolution::Pass);
    for missing in ["build", "unit-tests", "secret-scan", "acceptance-evidence"] {
        let mut decision = ran.decision.clone();
        decision
            .reports
            .retain(|report| report.metadata.gate_id.as_str() != missing);
        assert!(
            matches!(
                resolve(&ran.contract, &decision),
                Resolution::Blocked(BlockCause::MissingGate(_))
            ),
            "{missing}"
        );
    }
    let mut empty = ran.decision.clone();
    empty.reports.clear();
    assert!(matches!(
        resolve(&ran.contract, &empty),
        Resolution::Blocked(_)
    ));
}

// -------------------------------------------------------------------------------------------
// NT-GATE-10: evidence binding and flaky retries
// -------------------------------------------------------------------------------------------

fn failing_head() -> TestRun {
    run_of(
        &[
            ("fr_001_counts_a_line", "ok"),
            ("fr_002_counts_one_word", "FAILED"),
            ("fr_003_counts_nothing", "ok"),
            ("fr_004_counts_a_tab", "ok"),
        ],
        101,
    )
}

#[tokio::test]
async fn negative_nt_gate_10_evidence_for_one_commit_does_not_count_for_another() {
    let w = World::new();
    let more = it_with_one_more();
    let (base, a) = w.project(&[("tests/it.rs", Some(&more))]).await;
    let other = format!("{more}\n// a later push\n");
    let b = w.push(&with(&[("tests/it.rs", Some(&other))])).await;
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());

    let handler = w.handler();
    let for_a = w.upstream(&base, &a).await;
    let contract_a = w
        .resolve_contract(&handler, &for_a, &w.policy_hash)
        .expect("a contract");
    let outputs = w
        .execute(&handler, &contract_a, &for_a)
        .await
        .expect("execute works");

    // The evidence was recorded for A; the run is now about B.
    let for_b = w.upstream(&base, &b).await;
    let contract_b = w
        .resolve_contract(&handler, &for_b, &w.policy_hash)
        .expect("a contract");
    let ran = w
        .evaluate(&handler, &contract_b, &outputs, &for_b)
        .await
        .expect("evaluate works");
    assert_eq!(ran.outcome("evidence-binding"), GateOutcome::Failed);
    let checks = ran.failure_checks("evidence-binding");
    assert!(
        checks.contains(&"evidence-for-another-commit".to_owned()),
        "{checks:?}"
    );
    assert!(ran.decision.policy_violation);
    assert_eq!(
        ran.resolution,
        Resolution::Blocked(BlockCause::PolicyViolation)
    );

    // Evaluated against its own commit, the same evidence counts.
    let ran = w
        .evaluate(&handler, &contract_a, &outputs, &for_a)
        .await
        .expect("evaluate works");
    assert_eq!(ran.outcome("evidence-binding"), GateOutcome::Passed);
    assert_eq!(ran.resolution, Resolution::Pass);
}

#[tokio::test]
async fn negative_nt_gate_10_a_changed_policy_or_image_makes_the_evidence_stale() {
    let (w, base, head) = passing_world().await;
    let handler = w.handler();
    let upstream = w.upstream(&base, &head).await;
    let contract = w
        .resolve_contract(&handler, &upstream, &w.policy_hash)
        .expect("a contract");
    let outputs = w
        .execute(&handler, &contract, &upstream)
        .await
        .expect("execute works");

    // The policy bundle changed after the evidence was made.
    let new_policy = factory_domain::values::Sha256Digest::of(b"policy bundle two");
    let changed = w
        .resolve_contract(&handler, &upstream, &new_policy)
        .expect("a contract");
    let ran = w
        .evaluate(&handler, &changed, &outputs, &upstream)
        .await
        .expect("evaluate works");
    assert!(
        ran.failure_checks("evidence-binding")
            .contains(&"evidence-for-another-policy".to_owned())
    );
    assert_eq!(
        ran.resolution,
        Resolution::Blocked(BlockCause::PolicyViolation)
    );

    // The verify image changed.
    let mut cfg = w.config();
    cfg.sandbox.image = ImageDigest::parse(&format!(
        "registry.local/factory/sandbox@sha256:{}",
        "b".repeat(64)
    ))
    .expect("a digest");
    let other_image = ValidationHandler::new(Arc::new(cfg));
    let ran = w
        .evaluate(&other_image, &contract, &outputs, &upstream)
        .await
        .expect("evaluate works");
    assert!(
        ran.failure_checks("evidence-binding")
            .contains(&"evidence-for-another-image".to_owned())
    );
}

#[tokio::test]
async fn negative_nt_gate_10_a_test_that_fails_once_and_is_not_in_the_flaky_registry_is_failed() {
    let w = World::new();
    let more = it_with_one_more();
    let (base, head) = w.project(&[("tests/it.rs", Some(&more))]).await;
    w.cargo.queue_test_run(failing_head());
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Failed);
    assert_eq!(
        w.cargo.ran("test"),
        2,
        "the head run once and the baseline once: no retry"
    );
}

#[tokio::test]
async fn negative_nt_gate_10_a_registry_flake_gets_one_recorded_retry_and_no_more() {
    let more = it_with_one_more();
    let id = "tests/it.rs::fr_002_counts_one_word".to_owned();

    // Fails once, passes on the retry: passed, with the retry on the record.
    let w = World::new();
    let (base, head) = w.project(&[("tests/it.rs", Some(&more))]).await;
    w.cargo.queue_test_run(failing_head());
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let mut cfg = w.config();
    cfg.flaky_registry.insert(id.clone());
    let handler = ValidationHandler::new(Arc::new(cfg));
    let upstream = w.upstream(&base, &head).await;
    let contract = w
        .resolve_contract(&handler, &upstream, &w.policy_hash)
        .expect("a contract");
    let outputs = w
        .execute(&handler, &contract, &upstream)
        .await
        .expect("execute works");
    let ran = w
        .evaluate(&handler, &contract, &outputs, &upstream)
        .await
        .expect("evaluate works");
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Passed);
    let warnings: Vec<_> = ran
        .report("unit-tests")
        .warnings
        .iter()
        .flatten()
        .map(|w| w.check_id.as_str().to_owned())
        .collect();
    assert_eq!(warnings, ["flaky-retry"]);
    assert_eq!(
        w.cargo.ran("test"),
        3,
        "head, its one retry, and the baseline"
    );

    // Fails twice: failed, after exactly one retry.
    let w = World::new();
    let (base, head) = w.project(&[("tests/it.rs", Some(&more))]).await;
    w.cargo.queue_test_run(failing_head());
    w.cargo.queue_test_run(failing_head());
    w.cargo.queue_test_run(base_run());
    let mut cfg = w.config();
    cfg.flaky_registry.insert(id);
    let handler = ValidationHandler::new(Arc::new(cfg));
    let upstream = w.upstream(&base, &head).await;
    let contract = w
        .resolve_contract(&handler, &upstream, &w.policy_hash)
        .expect("a contract");
    let outputs = w
        .execute(&handler, &contract, &upstream)
        .await
        .expect("execute works");
    let ran = w
        .evaluate(&handler, &contract, &outputs, &upstream)
        .await
        .expect("evaluate works");
    assert_eq!(ran.outcome("unit-tests"), GateOutcome::Failed);
    assert_eq!(w.cargo.ran("test"), 3, "at most one retry");
}

// -------------------------------------------------------------------------------------------
// AUT-5: build code of the project's own waits for a security approver
// -------------------------------------------------------------------------------------------

const BUILD_SCRIPT: &str = "fn main() {\n    println!(\"cargo:rerun-if-changed=build.rs\");\n}\n";

/// The build gate of a change that adds build code is BLOCKED, with the code of a decision that is
/// missing, before any command runs: a command that built the change would run the build script.
fn assert_build_code_waits(w: &World, ran: &Ran, what: &str) {
    assert_eq!(ran.outcome("build"), GateOutcome::Blocked, "{what}");
    let blocked = ran
        .report("build")
        .blocked_reason
        .as_ref()
        .unwrap_or_else(|| panic!("{what}: a blocked report names its reason"));
    assert_eq!(blocked.code, BlockedCode::PolicyUnresolvable, "{what}");
    assert!(
        blocked
            .missing
            .iter()
            .any(|text| text.as_str().contains("approve_build_code")),
        "{what}: {blocked:?}"
    );
    assert_eq!(w.sandbox.created(), 0, "{what}: no sandbox was made");
    assert!(
        w.cargo.calls().is_empty(),
        "{what}: no command ran: {:?}",
        w.cargo.calls()
    );
    assert_ne!(ran.resolution, Resolution::Pass, "{what}");
    assert!(
        matches!(
            ran.resolution,
            Resolution::Blocked(BlockCause::GateBlocked(_))
        ),
        "{what}: {:?}",
        ran.resolution
    );
}

#[tokio::test]
async fn aut_5_a_new_build_script_blocks_the_build_gate_before_any_command_runs() {
    for path in ["build.rs", "tools/gen/build.rs", "BUILD.RS"] {
        let (w, ran) = run_change(&[(path, Some(BUILD_SCRIPT))], head_run()).await;
        assert_build_code_waits(&w, &ran, path);
    }
}

#[tokio::test]
async fn aut_5_an_existing_build_script_that_is_edited_blocks_the_build_gate_too() {
    let w = World::new();
    let base = w.push(&with(&[("build.rs", Some(BUILD_SCRIPT))])).await;
    let edited =
        format!("{BUILD_SCRIPT}fn extra() {{ let _ = std::process::Command::new(\"sh\"); }}\n");
    let head = w.push(&with(&[("build.rs", Some(&edited))])).await;
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_build_code_waits(&w, &ran, "an edited build.rs");
}

/// A decision of a person on `path`, as the ledger would hold it after the engine recorded it.
fn decided(
    w: &World,
    designation: factory_domain::policy::decision::Designation,
    path: &str,
    content: &str,
) -> factory_workflow::gates::scope::own_build_code::ProjectBuildCodeApproval {
    use factory_workflow::gates::scope::own_build_code::{BuildScript, ProjectBuildCodeApproval};
    use factory_workflow::gates::supply_chain::approval::DecisionScope;
    ProjectBuildCodeApproval {
        script: BuildScript {
            path: path.to_owned(),
            sha256: factory_domain::values::Sha256Digest::of(content.as_bytes()),
        },
        approver: factory_domain::policy::decision::GithubUserId::new(1004).expect("an id"),
        designation,
        allowlist_version: "sha256:allowlist".to_owned(),
        policy_hash: w.policy_hash.clone(),
        scope: DecisionScope {
            tenant: w.tenant,
            job: w.job,
        },
        reason: "Read the script; it only prints cargo directives.".to_owned(),
        decided_at: factory_domain::values::Timestamp::parse("2026-10-29T12:00:00Z")
            .expect("a time"),
    }
}

/// What the stage shows the person: the files that wait and the files decided on, each with the
/// hash of its content.
fn listing(ran: &Ran, list: &str) -> Vec<String> {
    ran.evidence["project_build_code"][list]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    format!(
                        "{} {}",
                        entry["path"].as_str().unwrap_or_default(),
                        entry["sha256"].as_str().unwrap_or_default()
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn aut_5_the_evidence_lists_the_file_and_the_hash_of_its_content_for_the_person() {
    let (_, ran) = run_change(&[("build.rs", Some(BUILD_SCRIPT))], head_run()).await;
    let hash = factory_domain::values::Sha256Digest::of(BUILD_SCRIPT.as_bytes());
    assert_eq!(
        listing(&ran, "awaiting"),
        [format!("build.rs {}", hash.as_str())]
    );
    assert!(listing(&ran, "decided").is_empty());
}

#[tokio::test]
async fn aut_5_a_security_approvers_decision_on_exactly_this_content_lets_the_build_gate_run() {
    use factory_domain::policy::decision::Designation;
    let w = World::new();
    let (base, head) = w.project(&[("build.rs", Some(BUILD_SCRIPT))]).await;
    w.approvals.record_build_code(decided(
        &w,
        Designation::SecurityApprover,
        "build.rs",
        BUILD_SCRIPT,
    ));
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    // The host rule passes, so the commands run in the sandbox as for any other change.
    assert_ne!(
        ran.outcome("build"),
        GateOutcome::Blocked,
        "{:?}",
        ran.report("build")
    );
    assert!(w.sandbox.created() >= 1, "the commands ran");
    assert!(listing(&ran, "awaiting").is_empty());
    assert_eq!(listing(&ran, "decided").len(), 1);
}

#[tokio::test]
async fn aut_5_a_decision_does_not_cover_a_script_that_changed_or_moved_or_was_made_by_an_approver()
{
    use factory_domain::policy::decision::Designation;
    // The reviewer read BUILD_SCRIPT. The change now carries an edited script: a new decision is
    // needed, and the gate waits again before any command runs.
    let w = World::new();
    let edited =
        format!("{BUILD_SCRIPT}fn extra() {{ let _ = std::process::Command::new(\"sh\"); }}\n");
    let (base, head) = w.project(&[("build.rs", Some(&edited))]).await;
    w.approvals.record_build_code(decided(
        &w,
        Designation::SecurityApprover,
        "build.rs",
        BUILD_SCRIPT,
    ));
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_build_code_waits(&w, &ran, "a script edited after the decision");
    assert_eq!(listing(&ran, "awaiting").len(), 1);

    // The same text at another path is another file.
    let w = World::new();
    let (base, head) = w.project(&[("tools/build.rs", Some(BUILD_SCRIPT))]).await;
    w.approvals.record_build_code(decided(
        &w,
        Designation::SecurityApprover,
        "build.rs",
        BUILD_SCRIPT,
    ));
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_build_code_waits(&w, &ran, "the same text at another path");

    // A decision of an ordinary approver is not the decision the action row names.
    let w = World::new();
    let (base, head) = w.project(&[("build.rs", Some(BUILD_SCRIPT))]).await;
    w.approvals
        .record_build_code(decided(&w, Designation::Approver, "build.rs", BUILD_SCRIPT));
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_build_code_waits(&w, &ran, "an approver's decision");

    // A decision taken under another policy bundle does not carry over.
    let w = World::new();
    let (base, head) = w.project(&[("build.rs", Some(BUILD_SCRIPT))]).await;
    let mut other = decided(&w, Designation::SecurityApprover, "build.rs", BUILD_SCRIPT);
    other.policy_hash = factory_domain::values::Sha256Digest::of(b"another policy bundle");
    w.approvals.record_build_code(other);
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_build_code_waits(&w, &ran, "a decision under another policy");
}

#[tokio::test]
async fn aut_5_a_build_script_moved_into_place_or_into_a_subdirectory_blocks_the_build_gate() {
    for (from, to) in [
        ("scripts/gen.rs", "build.rs"),
        ("build.rs", "crates/inner/build.rs"),
    ] {
        let w = World::new();
        let base = w.push(&with(&[(from, Some(BUILD_SCRIPT))])).await;
        let head = w
            .push(&with(&[(from, None), (to, Some(BUILD_SCRIPT))]))
            .await;
        w.cargo.queue_test_run(head_run());
        w.cargo.queue_test_run(base_run());
        let ran = w.run(&base, &head).await;
        assert_build_code_waits(&w, &ran, &format!("{from} moved to {to}"));
    }
}

#[tokio::test]
async fn aut_5_a_build_script_inside_a_vendored_dependency_is_build_code_too() {
    for path in [
        "vendor/some-crate/build.rs",
        "third_party/deps/other/build.rs",
    ] {
        let (w, ran) = run_change(&[(path, Some(BUILD_SCRIPT))], head_run()).await;
        assert_build_code_waits(&w, &ran, path);
    }
}

#[tokio::test]
async fn aut_5_a_build_key_a_procedural_macro_and_build_dependencies_in_a_manifest_block_the_build_gate()
 {
    let base = base_files()
        .into_iter()
        .find(|(path, _)| path == "Cargo.toml")
        .map(|(_, text)| text)
        .expect("the fixture holds a manifest");
    for (what, addition) in [
        ("a build key", "\n[package.metadata.x]\n"),
        ("build dependencies", "\n[build-dependencies]\ncc = \"1\"\n"),
        ("a procedural macro", "\n[lib]\nproc-macro = true\n"),
    ] {
        let changed = if what == "a build key" {
            base.replace("[package]\n", "[package]\nbuild = \"gen.rs\"\n")
        } else {
            format!("{base}{addition}")
        };
        let (w, ran) = run_change(&[("Cargo.toml", Some(&changed))], head_run()).await;
        assert_build_code_waits(&w, &ran, what);
    }
}

#[tokio::test]
async fn aut_5_an_ordinary_change_and_the_removal_of_a_build_script_do_not_block_the_build_gate() {
    let lib = base_files()
        .into_iter()
        .find(|(path, _)| path == "src/lib.rs")
        .map(|(_, text)| text)
        .expect("the fixture holds a library");
    let changed = format!("{lib}\npub fn extra() {{}}\n");
    let (_w, ran) = run_change(&[("src/lib.rs", Some(&changed))], head_run()).await;
    assert_eq!(ran.outcome("build"), GateOutcome::Passed);
    // Removing a build script adds no code.
    let w = World::new();
    let base = w.push(&with(&[("build.rs", Some(BUILD_SCRIPT))])).await;
    let head = w.push(&with(&[("build.rs", None)])).await;
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("build"), GateOutcome::Passed);
}
