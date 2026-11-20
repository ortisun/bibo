//! The seven post-conditions of a skill run, each with a failing fixture, and the check that the
//! agent's own report is ignored. The Input line of the specification is not checked here: what
//! reached the arguments of the skill is checked by the stage, on the transcript.
//!
//! Done criterion: the seven post-conditions are checked after every skill and the agent's own
//! report is ignored.

mod support;

use factory_ports::spec::{SpecError, SpecOperation};
use factory_spec_adapter::integrity::FileView;
use factory_spec_adapter::invocation::Host;
use factory_spec_adapter::postcond::{RunFacts, check_changed_paths, evaluate};
use support::{FEATURE, Files, assemble, feature, path, provider};

/// The names of the post-conditions that fail for a set of files.
fn failing(op: SpecOperation, files: &Files, run_succeeded: bool) -> Vec<String> {
    let set = files.build();
    let facts = RunFacts {
        op,
        feature: &feature(),
        host: Host::ClaudeCode,
        view: FileView::new(&set.files),
        run_succeeded,
    };
    let mut names: Vec<String> = evaluate(&facts)
        .into_iter()
        .map(|c| c.name.as_str().to_owned())
        .collect();
    names.sort();
    names.dedup();
    names
}

fn without_request(files: &mut Files) {
    files.remove(support::REQUEST);
}

#[test]
fn post_conditions_all_hold_for_a_clean_run() {
    let mut files = Files::linked();
    without_request(&mut files);
    for op in [
        SpecOperation::Specify,
        SpecOperation::Clarify,
        SpecOperation::Checklist,
    ] {
        assert_eq!(failing(op, &files, true), Vec::<String>::new(), "{op:?}");
    }
}

#[test]
fn post_conditions_1_a_run_that_did_not_end_normally_fails() {
    let mut files = Files::linked();
    without_request(&mut files);
    assert_eq!(
        failing(SpecOperation::Specify, &files, false),
        ["run-succeeded"]
    );
}

#[test]
fn post_conditions_3_a_path_no_skill_of_the_stage_writes_fails() {
    let mut files = Files::linked();
    without_request(&mut files);
    files.set("src/main.rs", b"fn main() {}\n");
    assert_eq!(
        failing(SpecOperation::Specify, &files, true),
        ["unexpected-path"]
    );
    // The check over the list of changed paths measured by the host.
    let changed = [
        path(&format!("{FEATURE}/spec.md")),
        path(".github/workflows/ci.yml"),
    ];
    let found = check_changed_paths(SpecOperation::Clarify, &feature(), &changed);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].name.as_str(), "unexpected-path");
    // A skill may write only its own files: the checklist skill may not touch the specification.
    let found = check_changed_paths(
        SpecOperation::Checklist,
        &feature(),
        &[path(&format!("{FEATURE}/spec.md"))],
    );
    assert_eq!(found.len(), 1);
}

#[test]
fn post_conditions_3_the_request_file_left_in_the_commit_is_caught() {
    // The stage removes the request file before the audit. If it stays, it is an unexpected path.
    let mut files = Files::linked();
    files.set(support::REQUEST, b"hostile text");
    let set = files.build();
    let facts = RunFacts {
        op: SpecOperation::Specify,
        feature: &feature(),
        host: Host::ClaudeCode,
        view: FileView::new(&set.files),
        run_succeeded: true,
    };
    assert!(
        evaluate(&facts)
            .iter()
            .any(|c| c.name.as_str() == "unexpected-path")
    );
}

#[test]
fn post_conditions_4_a_feature_directory_without_a_specification_fails() {
    let mut files = Files::linked();
    without_request(&mut files);
    files.remove(&format!("{FEATURE}/spec.md"));
    assert!(
        failing(SpecOperation::Specify, &files, true).contains(&"feature-file-written".to_owned())
    );
}

#[test]
fn post_conditions_4_a_pointer_that_names_another_directory_fails() {
    let mut files = Files::linked();
    without_request(&mut files);
    files.set(
        ".specify/feature.json",
        br#"{"feature_directory":"specs/001-something-else"}"#,
    );
    assert_eq!(
        failing(SpecOperation::Specify, &files, true),
        ["feature-pointer-valid"]
    );
    files.set(".specify/feature.json", b"not json");
    assert_eq!(
        failing(SpecOperation::Specify, &files, true),
        ["feature-pointer-valid"]
    );
    files.set(
        ".specify/feature.json",
        format!(r#"{{"feature_directory":"{FEATURE}"}}"#).as_bytes(),
    );
    assert!(failing(SpecOperation::Specify, &files, true).is_empty());
}

#[test]
fn post_conditions_5_a_template_placeholder_fails() {
    for placeholder in [
        "[FEATURE NAME]",
        "$ARGUMENTS",
        "[###-feature-name]",
        "[DATE]",
        "[PRINCIPLE_1_NAME]",
    ] {
        let mut files = Files::linked();
        without_request(&mut files);
        files.edit_spec(|text| format!("{text}\n- Left over: {placeholder}\n"));
        assert_eq!(
            failing(SpecOperation::Specify, &files, true),
            ["no-template-placeholder"],
            "{placeholder}"
        );
    }
    // The constitution is judged too.
    let mut files = Files::linked();
    without_request(&mut files);
    files.set(
        ".specify/memory/constitution.md",
        b"# Constitution\n\n### [PRINCIPLE_1_NAME]\n",
    );
    assert_eq!(
        failing(SpecOperation::Specify, &files, true),
        ["no-template-placeholder"]
    );
}

#[test]
fn post_conditions_6_a_file_of_a_skill_the_factory_never_runs_fails() {
    for artifact in [
        "plan.md",
        "tasks.md",
        "research.md",
        "data-model.md",
        "quickstart.md",
        "contracts/api.yaml",
    ] {
        let mut files = Files::linked();
        without_request(&mut files);
        files.set(
            &format!("{FEATURE}/{artifact}"),
            b"# written by a denied skill\n",
        );
        assert_eq!(
            failing(SpecOperation::Specify, &files, true),
            ["no-forbidden-artifact"],
            "{artifact}"
        );
    }
}

#[test]
fn post_conditions_7_the_checklist_exists_and_no_custom_item_is_ticked_by_its_author() {
    let mut files = Files::linked();
    without_request(&mut files);
    files.remove(&format!("{FEATURE}/checklists/requirements.md"));
    assert_eq!(
        failing(SpecOperation::Specify, &files, true),
        ["checklist-present"]
    );

    let mut files = Files::linked();
    without_request(&mut files);
    files.remove(&format!("{FEATURE}/checklists/requirements-quality.md"));
    assert_eq!(
        failing(SpecOperation::Checklist, &files, true),
        ["checklist-present"]
    );

    let mut files = Files::linked();
    without_request(&mut files);
    let custom = format!("{FEATURE}/checklists/requirements-quality.md");
    let text = String::from_utf8(files.get(&custom).to_vec()).expect("text");
    files.set(
        &custom,
        text.replacen("- [ ] CHK001", "- [x] CHK001", 1).as_bytes(),
    );
    assert_eq!(
        failing(SpecOperation::Checklist, &files, true),
        ["custom-checklist-ticked"]
    );
}

#[test]
fn post_conditions_an_input_line_that_restates_the_request_is_not_a_failure() {
    // The Input line is text the model wrote. A real model read the request file and summarised
    // it there (run of 2026-11-15), which proves nothing about the arguments either way. What
    // reached the arguments is checked by the stage, on the invocation in the transcript.
    let mut files = Files::linked();
    files.edit_spec(|text| {
        text.lines()
            .map(|line| {
                if line.starts_with("**Input**:") {
                    "**Input**: User description: \"A new --json option on the word count tool. It prints the counts as one JSON object.\"".to_owned()
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    });
    let mut handed = files.clone();
    without_request(&mut handed);
    assert!(
        failing(SpecOperation::Checklist, &handed, true).is_empty(),
        "a summary on the Input line fails nothing"
    );
    assert!(
        assemble(&provider(), SpecOperation::Checklist, &files).is_ok(),
        "the specification assembles with the model's own Input line"
    );
}

#[test]
fn post_conditions_the_agents_report_cannot_change_the_result() {
    // `evaluate` and `assemble` take no report. Whatever the agent said, the files decide: a
    // specification with a leftover placeholder fails, and a clean one passes.
    let mut bad = Files::linked();
    bad.edit_spec(|text| format!("{text}\n- [FEATURE NAME]\n"));
    let result = assemble(&provider(), SpecOperation::Checklist, &bad);
    assert!(matches!(result, Err(SpecError::PostConditionFailed(_))));
    let good = Files::linked();
    assert!(assemble(&provider(), SpecOperation::Checklist, &good).is_ok());
}
