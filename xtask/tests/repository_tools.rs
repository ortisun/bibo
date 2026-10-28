//! The commands that check the repository outside the Cargo graph: `check-links` (relative links
//! in Markdown), `check-invariants` (the invariant register of the state machine file, review
//! finding F-24) and `check-generated` (files that a script generates).
//!
//! Each test writes a small repository into a temporary directory and runs the real binary.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

struct Repo {
    dir: PathBuf,
}

struct Result {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Repo {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "xtask-tools-{}-{}-{label}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create the repository");
        Self { dir }
    }

    fn file(&self, relative: &str, content: &str) -> &Self {
        let path = self.dir.join(relative);
        fs::create_dir_all(path.parent().unwrap()).expect("create directories");
        fs::write(path, content).expect("write a file");
        self
    }

    fn run(&self, command: &str, extra: &[&str]) -> Result {
        let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .arg(command)
            .arg("--root")
            .arg(&self.dir)
            .args(extra)
            .output()
            .expect("run xtask");
        Result {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Result {
    fn report(&self) -> String {
        format!("exit {:?}\n{}\n{}", self.code, self.stdout, self.stderr)
    }

    fn passes(&self) {
        assert_eq!(self.code, Some(0), "{}", self.report());
    }

    fn finds(&self, text: &str) {
        assert_eq!(self.code, Some(1), "{}", self.report());
        assert!(
            self.stderr.contains(text),
            "expected {text:?}:\n{}",
            self.report()
        );
    }
}

mod check_links {
    use super::*;

    fn repo() -> Repo {
        let repo = Repo::new("links");
        repo.file(
            "README.md",
            "# Title\n\n## A section\n\nSee [guide](docs/guide.md) and [section](#a-section).\n",
        )
        .file(
            "docs/guide.md",
            "# Guide\n\n## Setup steps\n\nBack to [home](../README.md#title).\n",
        );
        repo
    }

    #[test]
    fn a_repository_whose_links_resolve_passes() {
        repo().run("check-links", &[]).passes();
    }

    #[test]
    fn a_link_to_a_file_that_does_not_exist_fails_and_names_the_line() {
        let repo = repo();
        repo.file("docs/other.md", "one\n\nSee [gone](missing/file.md).\n");
        repo.run("check-links", &[]).finds(
            "error[LINK]: docs/other.md:3: the link target \"missing/file.md\" does not exist",
        );
    }

    #[test]
    fn a_link_to_a_heading_that_does_not_exist_fails() {
        let repo = repo();
        repo.file("docs/other.md", "[x](guide.md#no-such-heading)\n");
        repo.run("check-links", &[])
            .finds("points at a heading that does not exist");
    }

    #[test]
    fn a_link_to_a_heading_that_exists_passes() {
        let repo = repo();
        repo.file(
            "docs/other.md",
            "[x](guide.md#setup-steps) [y](guide.md#Setup-Steps)\n",
        );
        repo.run("check-links", &[]).passes();
    }

    #[test]
    fn a_same_file_anchor_that_does_not_exist_fails() {
        let repo = repo();
        repo.file("docs/other.md", "# Real\n\n[x](#fake)\n");
        repo.run("check-links", &[]).finds("\"#fake\"");
    }

    #[test]
    fn urls_mail_links_and_line_anchors_on_other_files_are_not_checked() {
        let repo = repo();
        repo.file(
            "docs/other.md",
            "[a](https://example.invalid/x) [b](mailto:a@b.invalid) [c](../crates/x/src/lib.rs#L10)\n",
        )
        .file("crates/x/src/lib.rs", "");
        repo.run("check-links", &[]).passes();
    }

    #[test]
    fn links_inside_code_and_comments_are_not_checked() {
        let repo = repo();
        repo.file(
            "docs/other.md",
            "`[a](missing.md)`\n```\n[b](missing.md)\n```\n<!-- [c](missing.md) -->\n",
        );
        repo.run("check-links", &[]).passes();
    }

    #[test]
    fn a_reference_definition_and_an_undefined_reference_are_checked() {
        let repo = repo();
        repo.file("docs/a.md", "[x][ok] and [y][lost]\n\n[ok]: guide.md\n");
        repo.run("check-links", &[])
            .finds("the reference [lost] has no definition");
        let repo = Repo::new("links-definition");
        repo.file("docs/a.md", "[x][gone]\n\n[gone]: nothing.md\n");
        repo.run("check-links", &[]).finds("nothing.md");
    }

    #[test]
    fn an_html_href_and_an_image_are_checked() {
        let repo = repo();
        repo.file(
            "docs/a.md",
            "<a href=\"gone.md\">x</a> ![pic](pics/none.png)\n",
        );
        let run = repo.run("check-links", &[]);
        run.finds("gone.md");
        assert!(run.stderr.contains("pics/none.png"), "{}", run.report());
    }

    #[test]
    fn a_path_from_the_repository_root_and_a_directory_resolve() {
        let repo = repo();
        repo.file("docs/a.md", "[a](/docs/guide.md) [b](../docs/) [c](.)\n");
        repo.run("check-links", &[]).passes();
    }

    #[test]
    fn a_percent_escaped_path_resolves() {
        let repo = repo();
        repo.file("docs/with space.md", "# x\n")
            .file("docs/a.md", "[a](with%20space.md)\n");
        repo.run("check-links", &[]).passes();
    }

    #[test]
    fn nested_checkouts_build_output_and_node_modules_are_skipped() {
        let repo = repo();
        repo.file("worktrees/x/.git", "gitdir: /elsewhere\n")
            .file("worktrees/x/doc.md", "[a](missing.md)\n")
            .file("target/doc.md", "[a](missing.md)\n")
            .file("node_modules/pkg/README.md", "[a](missing.md)\n");
        repo.run("check-links", &[]).passes();
    }

    #[test]
    fn a_duplicate_heading_gets_a_numbered_anchor() {
        let repo = repo();
        repo.file(
            "docs/a.md",
            "# Notes\n\n# Notes\n\n[a](#notes) [b](#notes-1) [c](#notes-2)\n",
        );
        repo.run("check-links", &[]).finds("\"#notes-2\"");
    }

    #[test]
    fn the_real_repository_is_checked_without_a_crash() {
        // The result depends on the documents; the command must run to the end. A dead link
        // found here is a real finding to fix in the document, not a test failure.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .arg("check-links")
            .arg("--root")
            .arg(&root)
            .output()
            .expect("run xtask");
        assert!(matches!(output.status.code(), Some(0 | 1)), "{output:?}");
    }
}

mod invariant_register {
    use super::*;

    const REGISTER: &str =
        "{\"invariants\": [{\"id\": \"INV-01\"}, {\"id\": \"INV-02\"}, {\"id\": \"INV-03\"}]}";

    fn repo(files: &[(&str, &str)]) -> Repo {
        let repo = Repo::new("invariants");
        repo.file("docs/architecture/state-machine.json", REGISTER);
        for (path, content) in files {
            repo.file(path, content);
        }
        repo
    }

    fn run(repo: &Repo) -> Result {
        let register = repo.dir.join("docs/architecture/state-machine.json");
        repo.run(
            "check-invariants",
            &["--register", register.to_str().unwrap()],
        )
    }

    #[test]
    fn every_invariant_named_by_a_test_or_a_marker_passes() {
        let repo = repo(&[
            (
                "crates/domain/tests/a.rs",
                "#[test]\nfn inv_01_only_the_engine_writes() {}\n// INV-02\n#[test]\nfn x() {}\n",
            ),
            (
                "crates/ports/src/lib.rs",
                "/// The store keeps INV-03 by compare-and-swap.\npub fn y() {}\n",
            ),
        ]);
        run(&repo).passes();
    }

    #[test]
    fn an_invariant_that_no_test_names_fails_and_the_message_lists_every_missing_id() {
        let repo = repo(&[("crates/domain/tests/a.rs", "// INV-02\n")]);
        let result = run(&repo);
        result.finds("error[INV-01]");
        assert!(
            result.stderr.contains("error[INV-03]"),
            "{}",
            result.report()
        );
        assert!(
            !result.stderr.contains("error[INV-02]"),
            "{}",
            result.report()
        );
        assert!(
            result.stderr.contains("2 of 3 invariants"),
            "{}",
            result.report()
        );
    }

    #[test]
    fn a_string_a_plain_function_and_a_cfg_test_function_do_not_count() {
        let repo = repo(&[(
            "crates/domain/src/lib.rs",
            "const A: &str = \"INV-01\";\nfn inv_02_helper() {}\n#[cfg(test)]\nfn inv_03_not_a_test() {}\n",
        )]);
        let result = run(&repo);
        result.finds("error[INV-01]");
        assert!(
            result.stderr.contains("3 of 3 invariants"),
            "{}",
            result.report()
        );
    }

    #[test]
    fn a_longer_number_does_not_name_a_shorter_one() {
        let repo = repo(&[(
            "crates/domain/src/lib.rs",
            "// INV-011 and INV-021 and INV-031\n",
        )]);
        run(&repo).finds("3 of 3");
    }

    #[test]
    fn an_async_test_counts() {
        let repo = repo(&[(
            "crates/workflow/tests/e.rs",
            "// INV-01 INV-02\n#[tokio::test(flavor = \"current_thread\")]\nasync fn inv_03_x() {}\n",
        )]);
        run(&repo).passes();
    }

    #[test]
    fn files_outside_crates_do_not_count() {
        let repo = repo(&[("docs/note.rs", "// INV-01 INV-02 INV-03\n")]);
        run(&repo).finds("3 of 3");
    }

    #[test]
    fn a_register_that_is_not_readable_is_an_error_not_a_pass() {
        let repo = Repo::new("invariants-broken");
        repo.file("docs/architecture/state-machine.json", "{}");
        let register = repo.dir.join("docs/architecture/state-machine.json");
        let result = repo.run(
            "check-invariants",
            &["--register", register.to_str().unwrap()],
        );
        assert_eq!(result.code, Some(2), "{}", result.report());
        assert!(result.stderr.contains("invariants"), "{}", result.report());
    }

    #[test]
    fn the_real_register_lists_eleven_invariants() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/architecture/state-machine.json");
        let ids = xtask::invariants::register_ids(&fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(ids.len(), 11);
        assert_eq!(ids[0], "INV-01");
    }
}

mod generated_artifacts {
    use super::*;
    use serde_json::json;

    /// A rules file whose generated artifacts are the given commands. It is the real rules file
    /// with that one list replaced.
    fn rules_with(repo: &Repo, commands: &[(&str, &[&str])]) -> PathBuf {
        let text = fs::read_to_string(common::real_rules_path()).unwrap();
        let mut doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        doc["source_scans"]["generated_artifacts"] = commands
            .iter()
            .map(|(name, check)| json!({"name": name, "check": check, "regenerate": "run the generator"}))
            .collect();
        let path = repo.dir.join("rules.json");
        fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
        path
    }

    #[test]
    fn current_artifacts_pass() {
        let repo = Repo::new("generated-ok");
        let rules = rules_with(&repo, &[("index", &["true"]), ("fixture", &["true"])]);
        let result = repo.run("check-generated", &["--rules", rules.to_str().unwrap()]);
        result.passes();
        assert!(
            result.stdout.contains("current: index"),
            "{}",
            result.report()
        );
    }

    #[test]
    fn a_stale_artifact_fails_and_says_how_to_regenerate_it() {
        let repo = Repo::new("generated-stale");
        let rules = rules_with(&repo, &[("index", &["true"]), ("fixture", &["false"])]);
        let result = repo.run("check-generated", &["--rules", rules.to_str().unwrap()]);
        result.finds("error[GENERATED]");
        assert!(
            result.stderr.contains("fixture is stale"),
            "{}",
            result.report()
        );
        assert!(
            result.stderr.contains("run the generator"),
            "{}",
            result.report()
        );
    }

    #[test]
    fn a_command_that_cannot_start_is_blocked_and_never_a_pass() {
        let repo = Repo::new("generated-blocked");
        let rules = rules_with(&repo, &[("index", &["no-such-program-xtask-test"])]);
        let result = repo.run("check-generated", &["--rules", rules.to_str().unwrap()]);
        assert_eq!(result.code, Some(2), "{}", result.report());
        assert!(result.stderr.contains("BLOCKED"), "{}", result.report());
    }

    #[test]
    fn the_real_rules_file_lists_the_example_index_and_the_ledger_oracle() {
        let rules = common::real_rules();
        let checks: Vec<String> = rules
            .source_scans
            .generated_artifacts
            .iter()
            .map(|a| a.check.join(" "))
            .collect();
        assert!(
            checks
                .iter()
                .any(|c| c.contains("gen_example_index.py --check")),
            "{checks:?}"
        );
        assert!(
            checks
                .iter()
                .any(|c| c.contains("ledger_chain_oracle.py --check")),
            "{checks:?}"
        );
        assert!(
            rules
                .source_scans
                .generated_artifacts
                .iter()
                .all(|a| a.check[..2] == ["python3", "-I"])
        );
    }
}
