//! The impact policy, the plan and the checks of the gate, tested without an engine. The names of
//! the modules are the names of the done criteria of the work package.

use std::collections::{BTreeMap, BTreeSet};

use factory_ports::sandbox::ExecResult;
use factory_workflow::gates::docs::check::{self, DiagramRun, Inputs, Observations, Observed, Ran};
use factory_workflow::gates::docs::claims::Example;
use factory_workflow::gates::docs::plan::{self, ChangedFile, Facts, Kind, derive};
use factory_workflow::gates::docs::{Binding, DocPlan, Verdict};
use serde_json::json;

fn binding() -> Binding {
    Binding {
        base_commit: "a".repeat(40),
        code_head: "b".repeat(40),
        specification_sha256: format!("sha256:{}", "c".repeat(64)),
    }
}

fn changed(path: &str, kind: Kind, added: &[&str], removed: &[&str]) -> ChangedFile {
    ChangedFile {
        path: path.to_owned(),
        kind,
        added: added.iter().map(|s| (*s).to_owned()).collect(),
        removed: removed.iter().map(|s| (*s).to_owned()).collect(),
    }
}

fn facts(files: Vec<ChangedFile>) -> Facts {
    Facts {
        changed: files,
        existing_pages: ["README.md".to_owned()].into(),
        program: Some("word-count".to_owned()),
        profile: "rust-command-line-tool".to_owned(),
        ..Facts::default()
    }
}

fn new_flag() -> DocPlan {
    derive(
        &facts(vec![changed(
            "src/main.rs",
            Kind::Modified,
            &["a == \"--json\""],
            &[],
        )]),
        binding(),
    )
}

mod impact_policy {
    use super::*;

    #[test]
    fn a_new_command_line_flag_needs_usage_text_and_a_changelog_entry() {
        let plan = new_flag();
        let kinds: Vec<&str> = plan.items.iter().map(|i| i.kind.as_str()).collect();
        assert_eq!(kinds, ["usage", "changelog"]);
        assert_eq!(plan.items[0].terms, ["--json"]);
        assert_eq!(plan.items[1].page, "CHANGELOG.md");
        assert!(plan.not_applicable.is_none());
    }

    #[test]
    fn a_pure_refactor_is_not_applicable_with_the_rule_recorded() {
        let plan = derive(
            &facts(vec![changed(
                "src/output.rs",
                Kind::Modified,
                &["let a = 1;"],
                &["let a = 2;"],
            )]),
            binding(),
        );
        assert!(plan.items.is_empty());
        let rule = plan.not_applicable.expect("the rule is recorded");
        assert_eq!(rule.rule, "refactor-no-interface-change");
        assert!(!rule.reason.is_empty());
    }

    #[test]
    fn nothing_is_forced_on_a_change_that_touches_no_interface() {
        for files in [
            vec![changed("tests/a.rs", Kind::Added, &["fn t() {}"], &[])],
            vec![changed("src/lib.rs", Kind::Modified, &["x"], &["y"])],
            vec![changed("Cargo.lock", Kind::Modified, &["x"], &["y"])],
        ] {
            let plan = derive(&facts(files), binding());
            assert!(plan.items.is_empty());
            assert!(plan.not_applicable.is_some());
        }
    }

    #[test]
    fn a_breaking_change_adds_an_upgrade_note_and_marks_the_changelog() {
        let plan = derive(
            &facts(vec![changed(
                "src/main.rs",
                Kind::Modified,
                &[],
                &["a == \"--old\""],
            )]),
            binding(),
        );
        assert!(plan.breaking);
        assert!(plan.items.iter().any(|i| i.kind.as_str() == "upgrade"));
        let changelog = plan
            .items
            .iter()
            .find(|i| i.kind.as_str() == "changelog")
            .expect("an entry");
        assert!(changelog.acceptance.iter().any(|a| a.contains("breaking")));
    }

    #[test]
    fn an_existing_page_is_updated_before_a_new_one_is_written() {
        let mut with_usage = facts(vec![changed(
            "src/main.rs",
            Kind::Modified,
            &["a == \"--json\""],
            &[],
        )]);
        with_usage.existing_pages.insert("docs/usage.md".to_owned());
        let plan = derive(&with_usage, binding());
        assert_eq!(plan.items[0].page, "docs/usage.md");
    }

    #[test]
    fn a_domain_profile_adds_its_content_only_when_code_changed() {
        let mut trading = facts(vec![changed("src/lib.rs", Kind::Modified, &["x"], &["y"])]);
        trading.profile = "trading".to_owned();
        let plan = derive(&trading, binding());
        assert!(plan.items.iter().any(|i| i.kind.as_str() == "domain"));
    }
}

mod plan_matches_schema {
    use super::*;

    #[test]
    fn every_derived_plan_follows_the_schema() {
        let plans = [
            new_flag(),
            derive(
                &facts(vec![changed(
                    "src/main.rs",
                    Kind::Modified,
                    &[],
                    &["a == \"--old\""],
                )]),
                binding(),
            ),
            derive(
                &facts(vec![changed(
                    "src/output.rs",
                    Kind::Modified,
                    &["a"],
                    &["b"],
                )]),
                binding(),
            ),
            derive(
                &facts(vec![changed("docs/a.md", Kind::Modified, &["x"], &[])]),
                binding(),
            ),
        ];
        for plan in plans {
            plan::validate(&plan.to_json()).expect("the plan follows its schema");
            assert_eq!(
                DocPlan::from_json(&plan.to_json()).expect("it reads back"),
                plan
            );
        }
    }

    #[test]
    fn a_plan_that_breaks_the_schema_is_refused_at_the_field() {
        let good = new_flag().to_json();
        let mut cases = Vec::new();
        let mut no_items = good.clone();
        no_items.as_object_mut().expect("an object").remove("items");
        cases.push((no_items, "/items"));
        let mut unknown_kind = good.clone();
        unknown_kind["items"][0]["kind"] = json!("poem");
        cases.push((unknown_kind, "/items/0/kind"));
        let mut code_page = good.clone();
        code_page["items"][0]["page"] = json!("src/main.rs");
        cases.push((code_page, "/items/0/page"));
        let mut bad_commit = good.clone();
        bad_commit["code_head"] = json!("not-a-commit");
        cases.push((bad_commit, "/code_head"));
        let mut empty_and_applicable = good;
        empty_and_applicable["items"] = json!([]);
        cases.push((empty_and_applicable, "/applicable"));
        for (document, at) in cases {
            let error = plan::validate(&document).expect_err("the plan breaks the schema");
            assert_eq!(error.0, at);
        }
    }

    #[test]
    fn the_schema_file_and_the_validator_name_the_same_fields() {
        let schema: serde_json::Value = serde_json::from_str(plan::SCHEMA).expect("it parses");
        let required: Vec<&str> = schema["required"]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        for field in new_flag().to_json().as_object().expect("an object").keys() {
            if field != "not_applicable" {
                assert!(required.contains(&field.as_str()), "{field}");
            }
        }
        assert!(schema["properties"].get("not_applicable").is_some());
    }
}

// ---- the checks ---------------------------------------------------------------------------

struct World {
    plan: DocPlan,
    files: BTreeSet<String>,
    pages: BTreeMap<String, String>,
    changed: BTreeSet<String>,
    env: BTreeSet<String>,
    flags: BTreeSet<String>,
    head: String,
}

const README: &str = "# Word count\n\nAdd `--json` to print JSON.\n\n```console\n$ word-count --json notes.txt\n{\"lines\":1}\n```\n\nSee the [changelog](CHANGELOG.md#unreleased).\n";
const CHANGELOG: &str = "# Changelog\n\n## Unreleased\n\n- Added `--json`.\n";

fn world(readme: &str, changelog: Option<&str>) -> World {
    let mut pages: BTreeMap<String, String> = BTreeMap::new();
    pages.insert("README.md".to_owned(), readme.to_owned());
    if let Some(text) = changelog {
        pages.insert("CHANGELOG.md".to_owned(), text.to_owned());
    }
    World {
        plan: new_flag(),
        files: pages.keys().cloned().collect(),
        changed: pages.keys().cloned().collect(),
        pages,
        env: BTreeSet::new(),
        flags: BTreeSet::new(),
        head: "b".repeat(40),
    }
}

fn inputs(w: &World) -> Inputs<'_> {
    Inputs {
        plan: &w.plan,
        files: &w.files,
        pages: &w.pages,
        changed_docs: &w.changed,
        changelog_added: "- Added `--json`.\n",
        source_env: &w.env,
        source_flags: &w.flags,
        code_head_now: &w.head,
        written_over: &w.head,
        secret: &|_| Some(false),
    }
}

fn exec(code: i32) -> ExecResult {
    // The streams are artifact references; the checks read the text the stage already fetched.
    use factory_domain::contracts::ArtifactRef;
    use factory_domain::values::{MediaType, Sha256Digest, Timestamp};
    let reference = ArtifactRef {
        sha256: Sha256Digest::of(b""),
        media_type: MediaType::parse("text/plain").expect("a media type"),
        size_bytes: None,
    };
    let at = Timestamp::parse("2026-10-27T10:00:00Z").expect("a time");
    ExecResult {
        exit_code: Some(code),
        signal: None,
        timed_out: false,
        oom_killed: false,
        stdout: reference.clone(),
        stderr: reference,
        stdout_truncated: false,
        stderr_truncated: false,
        started_at: at,
        finished_at: at,
    }
}

fn ran(argv: &[&str], code: i32, stdout: &str) -> Ran {
    Ran {
        argv: argv.iter().map(|s| (*s).to_owned()).collect(),
        exec: exec(code),
        stdout: stdout.to_owned(),
        stderr: String::new(),
    }
}

const HELP: &str =
    "Usage: word-count [OPTIONS] FILE\n\n      --json   Print JSON\n  -h, --help   Print help\n";

/// The program built and ran: its help, and the examples of the page.
fn observed(w: &World, output: &str) -> Observations {
    let needs = check::needs(&inputs(w));
    Observations {
        sandbox_id: Some("sandbox-1".to_owned()),
        help: Observed::Seen(ran(&["word-count", "--help"], 0, HELP)),
        examples: if needs.examples.is_empty() {
            Observed::NotNeeded
        } else {
            Observed::Seen(
                needs
                    .examples
                    .iter()
                    .map(|e: &Example| (e.clone(), Some(ran(&["word-count"], 0, output))))
                    .collect(),
            )
        },
        diagrams: Observed::NotNeeded,
    }
}

fn verdict_of<'a>(results: &'a [check::CheckResult], gate: &str) -> &'a Verdict {
    &results
        .iter()
        .find(|r| r.gate == gate)
        .expect("a result")
        .verdict
}

mod gate_checks {
    use super::*;

    #[test]
    fn good_documents_pass_every_check_that_applies() {
        let w = world(README, Some(CHANGELOG));
        let results = check::run(&inputs(&w), &observed(&w, "{\"lines\":1}\n"));
        for result in &results {
            assert!(
                matches!(
                    result.verdict,
                    Verdict::Passed | Verdict::NotApplicable { .. }
                ),
                "{}: {:?}",
                result.gate,
                result.verdict
            );
        }
        assert_eq!(*verdict_of(&results, check::EXAMPLES), Verdict::Passed);
        assert_eq!(*verdict_of(&results, check::COMMANDS), Verdict::Passed);
    }

    #[test]
    fn a_broken_link_fails() {
        let w = world(
            &README.replace("CHANGELOG.md#unreleased", "docs/gone.md"),
            Some(CHANGELOG),
        );
        let results = check::run(&inputs(&w), &observed(&w, "{\"lines\":1}\n"));
        assert_eq!(*verdict_of(&results, check::LINKS), Verdict::Failed);
    }

    #[test]
    fn a_snippet_whose_output_differs_fails() {
        let w = world(README, Some(CHANGELOG));
        let results = check::run(&inputs(&w), &observed(&w, "{\"lines\":2}\n"));
        assert_eq!(*verdict_of(&results, check::EXAMPLES), Verdict::Failed);
    }

    #[test]
    fn a_command_that_does_not_exist_fails() {
        let w = world(
            &README.replace("Add `--json`", "Add `--json` or `--colour`"),
            Some(CHANGELOG),
        );
        let results = check::run(&inputs(&w), &observed(&w, "{\"lines\":1}\n"));
        assert_eq!(*verdict_of(&results, check::COMMANDS), Verdict::Failed);
    }

    #[test]
    fn a_bad_diagram_fails() {
        let w = world(
            &format!("{README}\n```mermaid\ngraph TD\n  A --> \n```\n"),
            Some(CHANGELOG),
        );
        let needs = check::needs(&inputs(&w));
        let mut seen = observed(&w, "{\"lines\":1}\n");
        seen.diagrams = Observed::Seen(
            needs
                .diagrams
                .iter()
                .map(|d| DiagramRun {
                    file: d.file.clone(),
                    line: d.line,
                    ran: ran(&["check-mermaid"], 1, ""),
                })
                .collect(),
        );
        let results = check::run(&inputs(&w), &seen);
        assert_eq!(*verdict_of(&results, check::DIAGRAMS), Verdict::Failed);
    }

    #[test]
    fn a_missing_required_page_fails() {
        let mut w = world(README, Some(CHANGELOG));
        w.files.remove("README.md");
        w.pages.remove("README.md");
        let results = check::run(&inputs(&w), &observed(&w, "{\"lines\":1}\n"));
        assert_eq!(*verdict_of(&results, check::PAGES), Verdict::Failed);
    }

    #[test]
    fn a_secret_in_the_text_fails_and_the_report_does_not_hold_it() {
        let w = world(README, Some(CHANGELOG));
        let mut input = inputs(&w);
        input.secret = &|_| Some(true);
        let results = check::run(&input, &observed(&w, "{\"lines\":1}\n"));
        assert_eq!(*verdict_of(&results, check::SECRETS), Verdict::Failed);
        let secrets = results
            .iter()
            .find(|r| r.gate == check::SECRETS)
            .expect("a result");
        assert!(
            secrets
                .findings
                .iter()
                .all(|f| !f.message.contains("{\"lines\""))
        );
    }

    #[test]
    fn a_missing_changelog_entry_fails() {
        let w = world(README, Some(CHANGELOG));
        let mut input = inputs(&w);
        input.changelog_added = "";
        let results = check::run(&input, &observed(&w, "{\"lines\":1}\n"));
        assert_eq!(*verdict_of(&results, check::CHANGELOG), Verdict::Failed);
    }

    #[test]
    fn documents_written_for_other_code_fail_the_binding() {
        let w = world(README, Some(CHANGELOG));
        let mut input = inputs(&w);
        let newer = "d".repeat(40);
        input.code_head_now = &newer;
        let results = check::run(&input, &observed(&w, "{\"lines\":1}\n"));
        assert_eq!(*verdict_of(&results, check::BINDING), Verdict::Failed);
    }
}

mod absence_is_never_a_pass {
    use super::*;

    const DIAGRAM: &str = "\n```mermaid\ngraph TD\n  A --> B\n```\n";

    #[test]
    fn diagrams_and_no_parser_is_blocked() {
        let w = world(&format!("{README}{DIAGRAM}"), Some(CHANGELOG));
        let mut seen = observed(&w, "{\"lines\":1}\n");
        seen.diagrams = Observed::Absent {
            missing: "the diagram parser".to_owned(),
        };
        let results = check::run(&inputs(&w), &seen);
        assert!(matches!(
            verdict_of(&results, check::DIAGRAMS),
            Verdict::Blocked { .. }
        ));
    }

    #[test]
    fn nothing_to_check_is_not_applicable_with_a_reason() {
        let w = world(README, Some(CHANGELOG));
        let results = check::run(&inputs(&w), &observed(&w, "{\"lines\":1}\n"));
        match verdict_of(&results, check::DIAGRAMS) {
            Verdict::NotApplicable { justification, .. } => assert!(!justification.is_empty()),
            other => panic!("expected not applicable, got {other:?}"),
        }
    }

    #[test]
    fn a_program_that_could_not_run_is_blocked_for_every_check_that_needs_it() {
        let w = world(README, Some(CHANGELOG));
        let mut seen = observed(&w, "x");
        seen.help = Observed::Absent {
            missing: "cargo".to_owned(),
        };
        seen.examples = Observed::Absent {
            missing: "cargo".to_owned(),
        };
        let results = check::run(&inputs(&w), &seen);
        assert!(matches!(
            verdict_of(&results, check::COMMANDS),
            Verdict::Blocked { .. }
        ));
        assert!(matches!(
            verdict_of(&results, check::EXAMPLES),
            Verdict::Blocked { .. }
        ));
    }

    #[test]
    fn a_scanner_that_could_not_run_is_blocked() {
        let w = world(README, Some(CHANGELOG));
        let mut input = inputs(&w);
        input.secret = &|_| None;
        let results = check::run(&input, &observed(&w, "{\"lines\":1}\n"));
        assert!(matches!(
            verdict_of(&results, check::SECRETS),
            Verdict::Blocked { .. }
        ));
    }

    /// Whatever a tool does not give, no check that needed it is `Passed`.
    #[test]
    fn no_missing_observation_turns_into_a_pass() {
        let w = world(&format!("{README}{DIAGRAM}"), Some(CHANGELOG));
        let absent = Observations {
            sandbox_id: None,
            help: Observed::Absent {
                missing: "x".to_owned(),
            },
            examples: Observed::Absent {
                missing: "x".to_owned(),
            },
            diagrams: Observed::Absent {
                missing: "x".to_owned(),
            },
        };
        let results = check::run(&inputs(&w), &absent);
        for gate in [check::COMMANDS, check::EXAMPLES, check::DIAGRAMS] {
            assert_ne!(*verdict_of(&results, gate), Verdict::Passed, "{gate}");
        }
        let never_ran = Observations::none();
        for result in check::run(&inputs(&w), &never_ran) {
            if matches!(result.gate, check::COMMANDS | check::DIAGRAMS) {
                assert_ne!(result.verdict, Verdict::Passed, "{}", result.gate);
            }
        }
    }
}

mod external_links_are_not_reported_valid {
    use super::*;

    #[test]
    fn they_are_counted_and_named_and_never_called_valid() {
        let page = format!(
            "{README}\nSee [the project](https://example.test/project) and [more](https://example.test/more).\n"
        );
        let w = world(&page, Some(CHANGELOG));
        let results = check::run(&inputs(&w), &observed(&w, "{\"lines\":1}\n"));
        let links = results
            .iter()
            .find(|r| r.gate == check::LINKS)
            .expect("a result");
        assert_eq!(links.verdict, Verdict::Passed);
        assert!(
            links.reason.contains("2 external link(s) were not checked"),
            "{}",
            links.reason
        );
        assert!(
            !links.reason.to_lowercase().contains("valid")
                || links.reason.contains("none is reported as valid")
        );
        assert!(
            links
                .evidence
                .contains(&"external_not_checked=https://example.test/project".to_owned())
        );
        assert_eq!(links.warnings.len(), 1);
    }

    #[test]
    fn a_page_with_only_external_links_has_nothing_the_gate_could_check() {
        let w = world(
            "# Tool\n\nSee [the project](https://example.test/project).\n",
            Some(CHANGELOG),
        );
        let results = check::run(&inputs(&w), &observed(&w, ""));
        match verdict_of(&results, check::LINKS) {
            Verdict::NotApplicable { justification, .. } => {
                assert!(justification.contains("1 external link(s) were not checked"));
            }
            other => panic!("expected not applicable, got {other:?}"),
        }
    }
}
