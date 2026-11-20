//! The parser and the assembly over the recorded real Spec Kit output (`--test golden`).
//!
//! The files under `tests/fixtures/recordings/` are real output of Spec Kit 1.1.2 with Claude Code
//! 2.1.311, labelled recordings. The tests say what the parser reads from them, what the contract
//! holds, and what happens when the recording is damaged.

mod support;

use factory_domain::contracts::{Contract, SpecificationContract};
use factory_domain::values::Sha256Digest;
use factory_ports::spec::{ParseReason, SpecError, SpecOperation, SpecOutcome};
use factory_spec_adapter::assemble::CHECKLIST_PREFIX;
use factory_spec_adapter::parse::{StoryPriority, parse_checklist, parse_spec};
use support::{FEATURE, Files, assemble, provider};

fn recorded_spec() -> String {
    String::from_utf8(
        Files::recorded()
            .get(&format!("{FEATURE}/spec.md"))
            .to_vec(),
    )
    .expect("the recording is text")
}

fn draft(files: &Files) -> SpecificationContract {
    match assemble(&provider(), SpecOperation::Checklist, files).expect("the files assemble") {
        SpecOutcome::Draft(draft) => draft.contract,
        SpecOutcome::NeedsHuman(questions) => {
            panic!("{} blocking question(s)", questions.len())
        }
    }
}

#[test]
fn the_recorded_specification_is_read_in_full() {
    let spec = parse_spec(&recorded_spec()).expect("the recording parses");
    assert_eq!(spec.title, "End-to-end minimum viable product");
    assert_eq!(spec.created, "2026-10-27");
    assert_eq!(spec.status, "Draft");
    assert_eq!(spec.stories.len(), 10);
    assert_eq!(spec.stories[0].priority, StoryPriority::P1);
    assert_eq!(spec.stories[2].priority, StoryPriority::P2);
    let scenarios: usize = spec.stories.iter().map(|s| s.scenarios.len()).sum();
    assert_eq!(scenarios, 40);
    assert_eq!(spec.requirements.len(), 40);
    assert_eq!(spec.success_criteria.len(), 13);
    assert_eq!(spec.clarifications.len(), 7);
    assert!(spec.markers.is_empty(), "the recording has no open marker");
    assert!(
        spec.edge_cases[0].contains("Out of scope"),
        "the first edge case is the scope boundary"
    );
    // Spec Kit does not promise the order of identifiers, so the parser keys on the identifier.
    let mut ids: Vec<&str> = spec.requirements.iter().map(|r| r.id.as_str()).collect();
    ids.sort_unstable();
    let expected: Vec<String> = (1..=40).map(|n| format!("FR-{n:03}")).collect();
    assert_eq!(ids, expected.iter().map(String::as_str).collect::<Vec<_>>());
}

#[test]
fn the_recorded_checklists_are_read_and_their_ticks_are_only_read() {
    let files = Files::recorded();
    let built_in = parse_checklist(
        std::str::from_utf8(files.get(&format!("{FEATURE}/checklists/requirements.md")))
            .expect("text"),
    );
    assert_eq!(built_in.len(), 16);
    assert!(
        built_in.iter().all(|item| item.ticked),
        "the specify skill ticked every item of its own checklist"
    );
    let custom = parse_checklist(
        std::str::from_utf8(files.get(&format!("{FEATURE}/checklists/requirements-quality.md")))
            .expect("text"),
    );
    assert_eq!(custom.len(), 36);
    assert!(custom.iter().all(|item| !item.ticked));
    assert_eq!(custom[0].id.as_deref(), Some("CHK001"));
}

#[test]
fn the_recording_as_written_has_no_link_between_requirements_and_scenarios() {
    // Spec Kit gives no link. Left as it is, the recording cannot become a contract, and the
    // adapter says so instead of inventing the links.
    let files = Files::recorded();
    let Err(SpecError::PostConditionFailed(found)) =
        assemble(&provider(), SpecOperation::Checklist, &files)
    else {
        panic!("the unlinked recording must not assemble");
    };
    let names: Vec<&str> = found.iter().map(|c| c.name.as_str()).collect();
    assert!(names.contains(&"requirement-without-scenario"), "{names:?}");
    assert!(names.contains(&"scenario-without-requirement"), "{names:?}");
    assert!(
        names.contains(&"more-failures"),
        "the list is capped: {names:?}"
    );
}

#[test]
fn the_recording_with_its_input_line_as_recorded_is_not_judged_by_that_line() {
    // The recorded Input line is a pasted description, not the fixed instruction. The line is text
    // the model wrote, so the adapter no longer reads it as evidence of the arguments; the stage
    // checks the invocation in the transcript instead. The recording still fails, for its links.
    let Err(SpecError::PostConditionFailed(found)) =
        assemble(&provider(), SpecOperation::Checklist, &Files::recorded())
    else {
        panic!("the unlinked recording must not assemble");
    };
    assert!(
        found
            .iter()
            .all(|c| c.name.as_str() != "skill-arguments-fixed"),
        "{found:?}"
    );
}

#[test]
fn the_traceable_recording_becomes_the_expected_contract() {
    let files = Files::linked();
    let contract = draft(&files);
    contract.validate().expect("the contract validates");
    SpecificationContract::from_json_value(contract.to_json_value().expect("json"))
        .expect("it round-trips");
    assert_eq!(contract.title.as_str(), "End-to-end minimum viable product");
    assert_eq!(contract.requirements.as_slice().len(), 40);
    assert_eq!(contract.acceptance_scenarios.as_slice().len(), 40);
    assert_eq!(contract.nonfunctional_requirements.len(), 13);
    assert_eq!(contract.risks.len(), 2);
    assert_eq!(contract.constraints.len(), 2);
    assert_eq!(contract.out_of_scope.len(), 1);
    assert_eq!(contract.metadata.commit_sha.as_str(), "a".repeat(40));
    // 7 answered clarifications, 16 built-in items and 36 custom items.
    assert_eq!(contract.open_questions.len(), 7 + 16 + 36);
    let first = &contract.requirements.as_slice()[0];
    assert_eq!(first.id.as_str(), "FR-001");
    assert_eq!(first.priority.as_str(), "P1");
}

#[test]
fn the_artifact_hashes_are_the_hashes_of_the_exact_bytes() {
    let files = Files::linked();
    let contract = draft(&files);
    let artifacts = contract.provenance.artifacts.as_slice();
    let roles: Vec<&str> = artifacts.iter().map(|a| a.role.as_str()).collect();
    assert_eq!(
        roles,
        [
            "specification",
            "requirements_checklist",
            "custom_checklist",
            "constitution"
        ]
    );
    for artifact in artifacts {
        assert_eq!(
            artifact.sha256,
            Sha256Digest::of(files.get(artifact.path.as_str())),
            "{}",
            artifact.path.as_str()
        );
    }
    // A single changed byte changes the hash.
    let mut edited = files.clone();
    edited.edit_spec(|text| text.replacen("MUST", "MUST ", 1));
    let other = draft(&edited);
    assert_ne!(
        other.provenance.artifacts.as_slice()[0].sha256,
        artifacts[0].sha256
    );
}

#[test]
fn every_checklist_item_is_an_open_question_whether_the_agent_ticked_it_or_not() {
    let contract = draft(&Files::linked());
    let items: Vec<_> = contract
        .open_questions
        .iter()
        .filter(|q| q.question.as_str().starts_with(CHECKLIST_PREFIX))
        .collect();
    assert_eq!(items.len(), 52);
    assert!(items.iter().all(|q| q.blocking && q.answer.is_none()));
}

#[test]
fn a_scenario_keeps_its_identifier_when_another_is_inserted_before_it() {
    let before = draft(&Files::linked());
    let mut edited = Files::linked();
    edited.edit_spec(|text| {
        text.replacen(
            "1. **Given** an authorized person has filed a clear issue",
            "1. **Given** a brand new opening situation, **When** the factory starts, **Then** it is ready. (FR-001)\n2. **Given** an authorized person has filed a clear issue",
            1,
        )
    });
    let after = draft(&edited);
    let ids = |c: &SpecificationContract| -> Vec<String> {
        c.acceptance_scenarios
            .as_slice()
            .iter()
            .map(|s| s.id.as_str().to_owned())
            .collect()
    };
    let (old, new) = (ids(&before), ids(&after));
    assert_eq!(new.len(), old.len() + 1);
    for id in &old {
        assert!(new.contains(id), "{id} survives the insertion");
    }
}

#[test]
fn assembling_twice_gives_the_same_contract() {
    let files = Files::linked();
    let first = draft(&files).to_json_value().expect("json");
    let second = draft(&files).to_json_value().expect("json");
    assert_eq!(first, second);
}

#[test]
fn a_marker_in_the_specification_sends_the_questions_to_a_person() {
    let mut files = Files::linked();
    files.edit_spec(|text| {
        text.replacen(
            "- **FR-001**: ",
            "- **FR-001**: [NEEDS CLARIFICATION: which file size limit applies?] ",
            1,
        )
    });
    match assemble(&provider(), SpecOperation::Checklist, &files).expect("assembles") {
        SpecOutcome::NeedsHuman(questions) => {
            assert_eq!(questions.len(), 1);
            assert_eq!(questions[0].id.as_str(), "Q-001");
            assert!(questions[0].blocking && questions[0].source_marker.is_some());
        }
        SpecOutcome::Draft(_) => panic!("a marker must stop the draft"),
    }
}

#[test]
fn a_damaged_recording_is_a_parse_error_and_never_a_guess() {
    type Damage = fn(String) -> String;
    let cases: [(&str, Damage, ParseReason); 6] = [
        (
            "a priority outside P1 to P3 is not read as a lower one",
            |t| t.replacen("(Priority: P1)", "(Priority: P4)", 1),
            ParseReason::BadId,
        ),
        (
            "a story without a priority",
            |t| t.replacen("(Priority: P1)", "", 1),
            ParseReason::SectionMissing,
        ),
        (
            "a missing required section",
            |t| t.replace("## Success Criteria", "## Outcomes"),
            ParseReason::SectionMissing,
        ),
        (
            "a requirement id out of shape",
            |t| t.replacen("**FR-001**", "**FR-1**", 1),
            ParseReason::BadId,
        ),
        (
            "a repeated requirement id",
            |t| t.replacen("**FR-002**", "**FR-001**", 1),
            ParseReason::BadId,
        ),
        (
            "a truncated file",
            |t| t.chars().take(t.len() / 2).collect(),
            ParseReason::SectionMissing,
        ),
    ];
    for (name, damage, reason) in cases {
        let mut files = Files::linked();
        files.edit_spec(damage);
        match assemble(&provider(), SpecOperation::Checklist, &files) {
            Err(SpecError::ParseError {
                path,
                reason: found,
            }) => {
                assert_eq!(path.as_str(), format!("{FEATURE}/spec.md"), "{name}");
                assert_eq!(found, reason, "{name}");
            }
            other => panic!("{name}: expected SPEC_PARSE_ERROR, got {other:?}"),
        }
    }
}

#[test]
fn a_specification_that_is_not_text_or_is_missing_is_a_parse_error() {
    let mut binary = Files::linked();
    binary.set(&format!("{FEATURE}/spec.md"), &[0xff, 0xfe, 0x00, 0x9f]);
    assert!(matches!(
        assemble(&provider(), SpecOperation::Checklist, &binary),
        Err(SpecError::ParseError {
            reason: ParseReason::NotText,
            ..
        })
    ));
    let mut missing = Files::linked();
    missing.remove(&format!("{FEATURE}/spec.md"));
    let result = assemble(&provider(), SpecOperation::Checklist, &missing);
    assert!(
        matches!(&result, Err(SpecError::PostConditionFailed(found))
            if found.iter().any(|c| c.name.as_str() == "feature-file-written")),
        "{result:?}"
    );
}
