//! The deterministic specification gate: each rule, with a passing contract and a failing fixture.
//!
//! The rules are pure, so these tests build typed contracts from the example document and break
//! one thing at a time.

use std::collections::BTreeMap;

use factory_domain::contracts::{Contract, SpecificationContract};
use factory_domain::policy::SecurityPolicy;
use factory_domain::values::Sha256Digest;
use factory_ports::spec::ParseReason;
use factory_workflow::gates::spec::checklist::{self, ChecklistInput, Waiver, parse_waivers};
use factory_workflow::gates::spec::profile::{ProfileEvidence, ProfileRules};
use factory_workflow::gates::spec::rules::{self, CHECKLIST_PREFIX, Limits};
use factory_workflow::gates::spec::{self, Family, family_of};
use serde_json::{Value, json};

const EXAMPLE: &str = include_str!(
    "../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
);
const SECURITY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");

/// The three recorded files of the example, with the hashes the tests use.
pub const SPEC_PATH: &str = "specs/word-count-json-output/spec.md";
pub const REQUIREMENTS_PATH: &str = "specs/word-count-json-output/checklists/requirements.md";
pub const CUSTOM_PATH: &str = "specs/word-count-json-output/checklists/requirements-quality.md";

pub fn sha(text: &str) -> String {
    Sha256Digest::of(text.as_bytes()).as_str().to_owned()
}

/// A draft the writer could have produced: no approval, three recorded files, the checklist items
/// as open questions.
pub fn draft_json() -> Value {
    let mut value: Value = serde_json::from_str(EXAMPLE).expect("the example is JSON");
    value["metadata"]["status"] = json!("draft");
    value["metadata"]
        .as_object_mut()
        .expect("object")
        .remove("approved_at");
    value["metadata"]
        .as_object_mut()
        .expect("object")
        .remove("approved_by");
    value["provenance"]["host_runtime"]["fidelity"] = json!("real");
    value["provenance"]["feature_directory"] = json!("specs/word-count-json-output");
    value["provenance"]["artifacts"] = json!([
        {"role": "specification", "path": SPEC_PATH, "sha256": sha("spec")},
        {"role": "requirements_checklist", "path": REQUIREMENTS_PATH, "sha256": sha("requirements")},
        {"role": "custom_checklist", "path": CUSTOM_PATH, "sha256": sha("custom")},
    ]);
    value["open_questions"] = json!([
        item(1, "CHK001", "Is every requirement testable?"),
        item(2, "CHK002", "Is the scope boundary stated?"),
    ]);
    value
}

pub fn item(number: u32, label: &str, text: &str) -> Value {
    json!({
        "id": format!("Q-{number:03}"),
        "question": format!("{CHECKLIST_PREFIX}{label} of requirements-quality.md: {text}"),
        "blocking": true,
        "status": "open",
    })
}

pub fn contract(value: Value) -> SpecificationContract {
    SpecificationContract::from_json_value(value).expect("the contract validates")
}

pub fn draft() -> SpecificationContract {
    contract(draft_json())
}

fn codes(found: &[spec::Finding]) -> Vec<&'static str> {
    let mut codes: Vec<&'static str> = found.iter().map(|f| f.code).collect();
    codes.sort_unstable();
    codes.dedup();
    codes
}

fn committed_all() -> BTreeMap<String, Sha256Digest> {
    [
        (SPEC_PATH, "spec"),
        (REQUIREMENTS_PATH, "requirements"),
        (CUSTOM_PATH, "custom"),
    ]
    .into_iter()
    .map(|(p, t)| (p.to_owned(), Sha256Digest::of(t.as_bytes())))
    .collect()
}

#[test]
fn a_sound_draft_passes_every_rule_but_the_checklist() {
    let c = draft();
    let limits = Limits::default();
    assert!(rules::structure(&c, &limits).is_empty());
    assert!(rules::identifiers(&c).is_empty());
    assert!(rules::requirement_keywords(&c).is_empty());
    assert!(rules::technology_names(&c, &limits).is_empty());
    assert!(rules::traceability(&c).is_empty());
    assert!(rules::clarity(&c, &Default::default()).is_empty());
    assert!(rules::contradictions(&c).is_empty());
    assert!(rules::safety(&c, &limits).is_empty());
    assert!(rules::authorization(&c).is_empty());
    assert!(rules::artifacts(&c, &committed_all(), &[]).is_empty());
}

#[test]
fn required_fields_a_missing_scope_boundary_risk_and_success_criterion_fail() {
    let mut value = draft_json();
    value["out_of_scope"] = json!([]);
    value["risks"] = json!([]);
    value["nonfunctional_requirements"] = json!([]);
    let found = rules::structure(&contract(value), &Limits::default());
    assert_eq!(
        codes(&found),
        ["no-measurable-criterion", "no-risks", "no-scope-boundary"]
    );
}

#[test]
fn required_sections_status_date_priorities_and_scenarios_fail_as_a_parse_failure() {
    // The adapter reads the files strictly. What it cannot read reaches the gate as a reason.
    for (reason, code) in [
        (ParseReason::Missing, "specification-file-missing"),
        (ParseReason::NotText, "specification-not-text"),
        (ParseReason::SectionMissing, "required-structure-missing"),
        (ParseReason::BadId, "identifier-malformed"),
        (ParseReason::TooLarge, "specification-too-large"),
    ] {
        assert_eq!(rules::parse_failure(SPEC_PATH, reason).code, code);
    }
}

#[test]
fn identifier_uniqueness_a_repeated_identifier_fails() {
    let mut value = draft_json();
    let mut second = value["requirements"][1].clone();
    second["id"] = json!("FR-001");
    value["requirements"][1] = second;
    let found = rules::identifiers(&contract(value));
    assert_eq!(codes(&found), ["duplicate-identifier"]);
    assert!(found[0].message.contains("FR-001"));
}

#[test]
fn requirement_keywords_a_requirement_without_one_fails() {
    let mut value = draft_json();
    value["requirements"][0]["statement"] =
        json!("When the flag is given, the tool prints the counts as one object.");
    value["requirements"][1]["statement"] =
        json!("When the flag is absent, the tool must keep its output unchanged.");
    let found = rules::requirement_keywords(&contract(value));
    assert_eq!(found.len(), 2, "lower case must does not count: {found:?}");
    assert_eq!(codes(&found), ["requirement-keyword-missing"]);
}

#[test]
fn remaining_markers_and_placeholders_fail_and_a_waived_question_does_not() {
    let mut value = draft_json();
    value["requirements"][0]["statement"] = json!(
        "The tool MUST print the counts [NEEDS CLARIFICATION: in which order?] as one object."
    );
    value["requirements"][1]["statement"] =
        json!("The tool MUST keep its output unchanged for [FEATURE NAME] and $ARGUMENTS.");
    value["open_questions"] = json!([{
        "id": "Q-001", "question": "Which order do the keys use?", "blocking": true, "status": "open"
    }]);
    let c = contract(value);
    let found = rules::clarity(&c, &Default::default());
    assert_eq!(
        codes(&found),
        [
            "blocking-question-open",
            "template-placeholder",
            "unresolved-marker"
        ]
    );
    // A person waived the open question with a reason. The marker and the placeholder stay.
    let waived = checklist::waived(&parse_waivers(
        "waive Q-001: the order is fixed by the tool",
    ));
    let found = rules::clarity(&c, &waived);
    assert_eq!(codes(&found), ["template-placeholder", "unresolved-marker"]);
    assert!(rules::has_placeholder("[PRINCIPLE_1_NAME]"));
    assert!(rules::has_placeholder("a [DATE] here"));
    assert!(!rules::has_placeholder("an [x] and a [Note] and [SQL]"));
}

#[test]
fn technology_names_a_requirement_that_names_a_technology_fails() {
    let mut value = draft_json();
    value["requirements"][0]["statement"] =
        json!("The tool MUST store the counts in PostgreSQL and print them.");
    value["nonfunctional_requirements"][0]["statement"] =
        json!("The tool produces output in under 2 seconds when it runs on Kubernetes.");
    let found = rules::technology_names(&contract(value), &Limits::default());
    assert_eq!(codes(&found), ["technology-named"]);
    assert_eq!(found.len(), 2);
}

#[test]
fn traceability_a_requirement_without_a_scenario_and_a_scenario_without_a_requirement_fail() {
    // FR-003 loses its scenario and AS-004 names no requirement of the specification.
    let mut value = draft_json();
    value["acceptance_scenarios"][3]["requirement_ids"] = json!(["FR-099"]);
    let found = rules::traceability(&contract(value));
    let all = codes(&found);
    assert!(all.contains(&"dangling-requirement-reference"), "{all:?}");
    assert!(all.contains(&"asymmetric-link"), "{all:?}");

    let mut value = draft_json();
    value["requirements"][2]["acceptance_scenario_ids"] = json!(["AS-099"]);
    let found = rules::traceability(&contract(value));
    assert!(codes(&found).contains(&"dangling-scenario-reference"));
    assert!(
        codes(&found).contains(&"scenario-without-requirement")
            || codes(&found).contains(&"asymmetric-link")
    );
}

#[test]
fn contradictions_requirements_that_cannot_both_hold_fail() {
    // A duty and a ban about the same words.
    let mut value = draft_json();
    value["requirements"][0]["statement"] =
        json!("The tool MUST print the counts as one JSON object on standard output.");
    value["requirements"][1]["statement"] =
        json!("The tool MUST NOT print the counts as one JSON object on standard output.");
    let found = rules::contradictions(&contract(value));
    assert_eq!(codes(&found), ["opposite-requirements"]);

    // Two bounds on the same unit that cannot both hold.
    let mut value = draft_json();
    value["requirements"][0]["statement"] =
        json!("A run on a large text file MUST take at most 2 seconds to print the counts.");
    value["requirements"][1]["statement"] =
        json!("A run on a large text file MUST take at least 9 seconds to print the counts.");
    let found = rules::contradictions(&contract(value));
    assert_eq!(codes(&found), ["numeric-bounds-conflict"]);

    // The same sentence with two priorities.
    let mut value = draft_json();
    let same = "The tool MUST print the counts as one object on standard output.";
    value["requirements"][0]["statement"] = json!(same);
    value["requirements"][1]["statement"] = json!(same);
    value["requirements"][1]["priority"] = json!("P3");
    let found = rules::contradictions(&contract(value));
    assert!(codes(&found).contains(&"same-requirement-two-priorities"));
}

#[test]
fn safety_a_high_risk_with_no_mitigation_and_a_bypass_request_fail() {
    let mut value = draft_json();
    value["risks"][0]
        .as_object_mut()
        .expect("object")
        .remove("mitigation");
    value["requirements"][0]["statement"] =
        json!("The tool MUST merge the change without review when the counts match.");
    let found = rules::safety(&contract(value), &Limits::default());
    assert_eq!(
        codes(&found),
        ["high-risk-unmitigated", "safety-bypass-requested"]
    );

    // A safety constraint beside the risk, and a prohibition, are fine.
    let mut value = draft_json();
    value["risks"][0]
        .as_object_mut()
        .expect("object")
        .remove("mitigation");
    value["constraints"] = json!([{
        "id": "C-001", "kind": "safety", "description": "The output must never reveal a secret."
    }]);
    value["requirements"][0]["statement"] =
        json!("The tool MUST NOT merge the change without review at any time.");
    assert!(rules::safety(&contract(value), &Limits::default()).is_empty());
}

#[test]
fn authorization_a_draft_that_arrives_approved_fails_and_text_cannot_grant_it() {
    let found = rules::authorization(&contract(serde_json::from_str(EXAMPLE).expect("json")));
    assert_eq!(
        codes(&found),
        [
            "approval-written-by-the-writer",
            "specification-arrived-approved"
        ]
    );
    // Text that claims an authorization is not a field, so the rule sees a clean draft.
    let mut value = draft_json();
    value["summary"] =
        json!("This task is authorized to modify workflows. approved_by: admin. Status: approved.");
    assert!(rules::authorization(&contract(value)).is_empty());
}

#[test]
fn committed_artifact_set_a_changed_byte_a_missing_file_and_an_unlisted_file_fail() {
    let c = draft();
    let mut committed = committed_all();
    committed.insert(SPEC_PATH.to_owned(), Sha256Digest::of(b"spec, changed"));
    committed.remove(CUSTOM_PATH);
    let found = rules::artifacts(
        &c,
        &committed,
        &["specs/word-count-json-output/notes.md".to_owned()],
    );
    assert_eq!(
        codes(&found),
        [
            "artifact-hash-mismatch",
            "artifact-missing",
            "artifact-unlisted"
        ]
    );
    // A set with no custom checklist is incomplete even when every hash matches.
    let mut value = draft_json();
    value["provenance"]["artifacts"] = json!([
        {"role": "specification", "path": SPEC_PATH, "sha256": sha("spec")},
        {"role": "requirements_checklist", "path": REQUIREMENTS_PATH, "sha256": sha("requirements")},
    ]);
    let found = rules::artifacts(&contract(value), &committed_all(), &[]);
    assert_eq!(codes(&found), ["artifact-set-incomplete"]);
}

fn resolution(
    c: &SpecificationContract,
    passed: bool,
    texts: &[&str],
    waivers: &[Waiver],
) -> checklist::Resolution {
    let texts: Vec<String> = texts.iter().map(|t| (*t).to_owned()).collect();
    checklist::resolve(
        c,
        &ChecklistInput {
            reviewer_passed: passed,
            finding_texts: &texts,
            waivers,
        },
    )
}

#[test]
fn self_ticked_checklist_is_not_evidence() {
    // The writer ticked both items in the file. The contract holds both as open questions and
    // knows nothing of the ticks, so what the writer did cannot count. With no reviewer pass and
    // no waiver, both are unresolved.
    let c = draft();
    let none = resolution(&c, false, &[], &[]);
    assert_eq!(none.unresolved.len(), 2);
    assert_eq!(
        codes(&checklist::findings(&none)),
        ["checklist-item-unresolved"]
    );
    // A reviewer that did not pass verifies nothing, even if its findings do not name the items.
    assert_eq!(
        resolution(&c, false, &["some other point"], &[])
            .unresolved
            .len(),
        2
    );
    // A reviewer that passed verifies the items its findings do not name.
    let passed = resolution(&c, true, &[], &[]);
    assert!(passed.unresolved.is_empty());
    assert_eq!(passed.verified.len(), 2);
    // A pass that names one item in a note leaves that item open.
    let named = resolution(
        &c,
        true,
        &["CHK002 is not stated anywhere in the text"],
        &[],
    );
    assert_eq!(named.unresolved.len(), 1);
    assert_eq!(named.unresolved[0].0, "Q-002");
}

#[test]
fn a_person_waives_an_item_only_with_a_reason() {
    let c = draft();
    let without_reason = parse_waivers("waive Q-001:\nwaive Q-002: ok");
    assert!(without_reason.is_empty());
    let with_reason = parse_waivers(
        "waive Q-001: the criteria are testable at architecture time\nwaive Q-002: the scope is stated in the edge cases",
    );
    let r = resolution(&c, false, &[], &with_reason);
    assert!(r.unresolved.is_empty());
    assert_eq!(r.waived.len(), 2);
    // A waiver for another question changes nothing here.
    let other = parse_waivers("waive Q-009: a reason that is long enough");
    assert_eq!(resolution(&c, false, &[], &other).unresolved.len(), 2);
}

#[test]
fn post_conditions_of_the_adapter_are_classed_and_an_unknown_one_blocks() {
    for name in [
        "forbidden-skill-invoked",
        "no-forbidden-artifact",
        "unexpected-path",
        "skill-arguments-fixed",
        "run-succeeded",
    ] {
        assert_eq!(family_of(name), Family::Profile, "{name}");
    }
    for name in [
        "feature-file-written",
        "no-template-placeholder",
        "checklist-present",
        "custom-checklist-ticked",
        "feature-pointer-valid",
    ] {
        assert_eq!(family_of(name), Family::Structure, "{name}");
    }
    for name in [
        "requirement-without-scenario",
        "scenario-without-requirement",
        "more-failures",
    ] {
        assert_eq!(family_of(name), Family::Traceability, "{name}");
    }
    // A check the table does not know fails closed.
    assert_eq!(family_of("a-check-added-later"), Family::Profile);
}

pub fn rules_from_policy() -> ProfileRules {
    let policy: SecurityPolicy = serde_json::from_str(SECURITY).expect("the policy");
    ProfileRules::from_policy(&policy, "SPECIFICATION").expect("the specification profile")
}

fn evidence<'a>(
    denials: &'a [(String, String)],
    transcripts: &'a [Vec<u8>],
    changed: &'a [String],
    committed: &'a [String],
) -> ProfileEvidence<'a> {
    ProfileEvidence {
        denials,
        transcripts,
        changed,
        committed,
    }
}

#[test]
fn stage_profile_check_a_clean_run_passes() {
    let rules = rules_from_policy();
    let changed = vec![
        "specs/a/spec.md".to_owned(),
        "specs/a/checklists/requirements.md".to_owned(),
        "specs/a/checklists/requirements-quality.md".to_owned(),
        ".specify/feature.json".to_owned(),
    ];
    let init = json!({"type": "system", "subtype": "init", "skills": ["speckit-specify", "speckit-clarify", "speckit-checklist", "speckit-constitution", "update-config"], "slash_commands": ["speckit-specify"]});
    let transcript = format!(
        "{init}\n{}\n",
        json!({"type": "result", "subtype": "success", "permission_denials": []})
    )
    .into_bytes();
    let found = rules.check(&evidence(&[], &[transcript], &changed, &changed));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn stage_profile_check_a_forbidden_artifact_after_the_run_fails() {
    let rules = rules_from_policy();
    for artifact in [
        "plan.md",
        "tasks.md",
        "research.md",
        "data-model.md",
        "quickstart.md",
        "contracts/api.yaml",
    ] {
        let committed = vec![format!("specs/a/{artifact}")];
        let found = rules.check(&evidence(&[], &[], &[], &committed));
        assert_eq!(codes(&found), ["forbidden_artifact_present"], "{artifact}");
    }
}

#[test]
fn stage_profile_check_a_denied_skill_in_the_event_stream_or_the_denials_fails() {
    let rules = rules_from_policy();
    let denial = vec![("Skill(speckit-implement)".to_owned(), "denied".to_owned())];
    assert_eq!(
        codes(&rules.check(&evidence(&denial, &[], &[], &[]))),
        ["forbidden_skill_invoked"]
    );
    // The skill is called through the Skill tool.
    let call = json!({"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "Skill", "input": {"skill": "speckit-plan"}}]}});
    let found = rules.check(&evidence(
        &[],
        &[format!("{call}\n").into_bytes()],
        &[],
        &[],
    ));
    assert_eq!(codes(&found), ["forbidden_skill_invoked"]);
    // The skill is typed as a command in a user message.
    let typed = json!({"type": "user", "message": {"content": [{"type": "text", "text": "$speckit-taskstoissues now"}]}});
    let found = rules.check(&evidence(
        &[],
        &[format!("{typed}\n").into_bytes()],
        &[],
        &[],
    ));
    assert_eq!(codes(&found), ["forbidden_skill_invoked"]);
    // The runtime reports the denial in its result event.
    let result = json!({"type": "result", "permission_denials": [{"tool_name": "Skill", "tool_input": {"skill": "speckit-converge"}}]});
    let found = rules.check(&evidence(
        &[],
        &[format!("{result}\n").into_bytes()],
        &[],
        &[],
    ));
    assert_eq!(codes(&found), ["forbidden_skill_invoked"]);
}

#[test]
fn stage_profile_check_a_fifth_skill_visible_fails_and_a_skill_file_read_does_not() {
    let rules = rules_from_policy();
    let init = json!({"type": "system", "subtype": "init", "skills": ["speckit-specify", "speckit-analyze"], "slash_commands": []});
    let found = rules.check(&evidence(
        &[],
        &[format!("{init}\n").into_bytes()],
        &[],
        &[],
    ));
    assert_eq!(codes(&found), ["skill_visible_outside_profile"]);
    // A tool result that holds the text of a skill, which names the next skill, is not a call.
    let read = json!({"type": "user", "message": {"content": [{"type": "tool_result", "content": "Ready for /speckit-plan after clarification"}]}});
    let found = rules.check(&evidence(
        &[],
        &[format!("{read}\n").into_bytes()],
        &[],
        &[],
    ));
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn stage_profile_check_a_write_outside_the_four_skills_fails() {
    let rules = rules_from_policy();
    let changed = vec![
        ".github/workflows/ci.yml".to_owned(),
        "src/main.rs".to_owned(),
    ];
    let found = rules.check(&evidence(&[], &[], &changed, &[]));
    assert_eq!(codes(&found), ["write_outside_profile"]);
    assert_eq!(found.len(), 2);
}

#[test]
fn stage_profile_check_cannot_be_waived() {
    let policy: SecurityPolicy = serde_json::from_str(SECURITY).expect("the policy");
    let text = SECURITY.to_owned();
    assert!(text.contains("stage_profile_check"));
    let nonwaivable = &policy.gate_integrity.nonwaivable_gates;
    assert!(
        nonwaivable.iter().any(|g| g == spec::STAGE_PROFILE),
        "{nonwaivable:?}"
    );
    assert_eq!(spec::STAGE_PROFILE, "stage_profile_check");
}
