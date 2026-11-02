//! `policies/issue-workflow.yaml` is read by the engine with the same strict contract as the other
//! policies, and what the engine reads is what the Python tool renders for the installer and the
//! Action (`onboarding/github/issue-workflow.json`). The two cannot disagree about a label.
//!
//! Each refusal case takes the real file, changes it in one way, writes it into a temporary
//! checkout and loads it. The unchanged text loads through the same helper first, so a failure is
//! about the change and not about the setup.

mod support;

use std::collections::BTreeSet;

use factory_contracts::policy::{
    ISSUE_WORKFLOW_FILE, PolicyError, PolicyErrorKind, PolicyLoader, ProtectedPolicySource,
};
use factory_domain::policy::issue_workflow::{STATUS_PREFIX, check_status_label_name};
use factory_domain::state::JobStatus;
use serde_json::Value;
use support::{TempDir, read_text, repo_root};

fn real() -> String {
    read_text(&repo_root().join(ISSUE_WORKFLOW_FILE))
}

fn rendered() -> Value {
    serde_json::from_str(&read_text(
        &repo_root().join("onboarding/github/issue-workflow.json"),
    ))
    .expect("the rendered policy is JSON")
}

fn state_machine() -> Value {
    serde_json::from_str(&read_text(
        &repo_root().join("docs/architecture/state-machine.json"),
    ))
    .expect("the state machine is JSON")
}

fn load_text(text: &str) -> Result<(), PolicyError> {
    let dir = TempDir::new("issue-workflow");
    dir.write(ISSUE_WORKFLOW_FILE, text);
    let source = ProtectedPolicySource::protected_default_branch(dir.path(), &[])
        .expect("the checkout exists");
    PolicyLoader::load_issue_workflow(&source).map(|_| ())
}

fn replace_once(text: &str, from: &str, to: &str) -> String {
    assert!(
        text.contains(from),
        "the policy file no longer contains `{from}`; update this negative test to the new text"
    );
    text.replacen(from, to, 1)
}

fn refused(text: &str) -> PolicyError {
    load_text(text).expect_err("the policy must be refused")
}

#[test]
fn the_real_file_loads_and_the_helper_is_sound() {
    load_text(&real()).expect("the real policy loads through the helper");
    let source = ProtectedPolicySource::protected_default_branch(&repo_root(), &[]).unwrap();
    let loaded = PolicyLoader::load_issue_workflow(&source).expect("the real policy loads");
    assert!(loaded.hash.as_str().starts_with("sha256:"));
}

#[test]
fn what_the_engine_reads_equals_what_the_tool_renders() {
    let source = ProtectedPolicySource::protected_default_branch(&repo_root(), &[]).unwrap();
    let policy = PolicyLoader::load_issue_workflow(&source)
        .expect("loads")
        .document;
    let json = rendered();

    // Every label of the rendering, with its color and description, in the order of the file.
    let mut expected: Vec<(String, String, String, String)> = vec![(
        policy.trigger.label.clone(),
        policy.trigger.color.clone(),
        policy.trigger.description.clone(),
        "trigger".to_owned(),
    )];
    for state in &policy.design_track.states {
        expected.push((
            format!("{}{}", policy.namespaces.design.prefix, state.name),
            state.color.clone(),
            state.description.clone(),
            "design".to_owned(),
        ));
    }
    for state in &policy.factory_track.states {
        expected.push((
            format!("{}{}", policy.namespaces.factory.prefix, state.name),
            state.color.clone(),
            state.description.clone(),
            "factory".to_owned(),
        ));
    }
    let rendered_labels: Vec<(String, String, String, String)> = json["labels"]
        .as_array()
        .expect("labels")
        .iter()
        .map(|l| {
            (
                l["name"].as_str().unwrap().to_owned(),
                l["color"].as_str().unwrap().to_owned(),
                l["description"].as_str().unwrap().to_owned(),
                l["kind"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(rendered_labels, expected);

    // The map from job state to label, the prefixes and the design track.
    let labels = policy.status_labels().expect("the real policy is sound");
    let rendered_map = json["factory"]["job_states"].as_object().expect("map");
    assert_eq!(rendered_map.len(), JobStatus::ALL.len());
    for status in JobStatus::ALL {
        assert_eq!(
            rendered_map[status.as_str()].as_str(),
            Some(labels.label_for(*status).as_str()),
            "{}",
            status.as_str()
        );
    }
    assert_eq!(json["factory"]["prefix"], policy.namespaces.factory.prefix);
    assert_eq!(json["design"]["prefix"], policy.namespaces.design.prefix);
    assert_eq!(json["trigger"], policy.trigger.label);
    assert_eq!(
        json["design"]["start_states"],
        serde_json::json!(policy.design_track.start_states)
    );
    let moves: Vec<Value> = policy
        .design_track
        .transitions
        .iter()
        .map(|m| serde_json::json!([m.from, m.to]))
        .collect();
    assert_eq!(json["design"]["transitions"], Value::Array(moves));
    assert_eq!(
        json["design"]["approved"],
        policy.intake_requirements.design_track_requires
    );
    let document = &policy.design_track.approval_requires.design_document;
    assert_eq!(json["design"]["document_field"], document.issue_body_field);
    assert_eq!(json["design"]["document_glob"], document.path_glob);
}

#[test]
fn every_job_state_of_the_state_machine_has_exactly_one_label_and_no_other_has() {
    let source = ProtectedPolicySource::protected_default_branch(&repo_root(), &[]).unwrap();
    let policy = PolicyLoader::load_issue_workflow(&source)
        .expect("loads")
        .document;
    let machine = state_machine();
    let machine_states: BTreeSet<String> = machine["machines"]["job"]["states"]
        .as_object()
        .expect("states")
        .keys()
        .cloned()
        .collect();
    let mapped: Vec<&str> = policy
        .factory_track
        .states
        .iter()
        .map(|s| s.job_state.as_str())
        .collect();
    assert_eq!(
        mapped.len(),
        machine_states.len(),
        "one label for each state, no more"
    );
    assert_eq!(
        mapped
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>(),
        machine_states,
        "the policy names exactly the job states of docs/architecture/state-machine.json"
    );
    // The typed list in the domain is the same list.
    assert_eq!(
        JobStatus::ALL
            .iter()
            .map(|s| s.as_str().to_owned())
            .collect::<BTreeSet<_>>(),
        machine_states
    );
    let labels = policy.status_labels().expect("sound");
    let names: BTreeSet<&str> = labels.iter().map(|l| l.as_str()).collect();
    assert_eq!(
        names.len(),
        machine_states.len(),
        "no two states share a label"
    );
    for label in labels.iter() {
        assert!(label.as_str().starts_with(STATUS_PREFIX));
        assert_eq!(check_status_label_name(label.as_str()), Ok(()));
    }
}

#[test]
fn a_policy_that_misses_a_job_state_is_refused() {
    let line = "    - { job_state: PAUSED,            name: paused,               color: \"d4c5f9\", description: \"An operator paused the work.\" }\n";
    let text = replace_once(&real(), line, "");
    let error = refused(&text);
    assert!(error.message.contains("PAUSED"), "{error}");
    assert_eq!(error.kind, PolicyErrorKind::Constraint);
    assert_eq!(error.key.as_deref(), Some("factory_track.states"));
}

#[test]
fn a_policy_that_names_a_state_the_engine_does_not_have_is_refused() {
    let text = replace_once(&real(), "job_state: PAUSED,", "job_state: SNOOZED,");
    let error = refused(&text);
    let said = format!("{error}");
    assert!(said.contains("SNOOZED"), "{said}");
    assert!(
        said.contains("PAUSED"),
        "the state left without a label is named too: {said}"
    );
}

#[test]
fn a_policy_that_maps_a_job_state_twice_is_refused() {
    let text = replace_once(&real(), "job_state: BLOCKED,", "job_state: PAUSED,");
    let error = refused(&text);
    assert!(format!("{error}").contains("mapped twice"), "{error}");
}

#[test]
fn a_trigger_label_inside_a_namespace_is_refused() {
    let text = replace_once(&real(), "  label: factory\n", "  label: \"factory: go\"\n");
    let error = refused(&text);
    assert!(
        format!("{error}").contains("outside both namespaces"),
        "{error}"
    );
    let text = replace_once(&real(), "  label: factory\n", "  label: \"design: go\"\n");
    assert!(format!("{}", refused(&text)).contains("outside both namespaces"));
}

#[test]
fn the_type_cannot_hold_the_trigger_label_a_design_label_or_a_label_with_no_name() {
    let source = ProtectedPolicySource::protected_default_branch(&repo_root(), &[]).unwrap();
    let policy = PolicyLoader::load_issue_workflow(&source)
        .expect("loads")
        .document;
    let labels = policy.status_labels().expect("sound");
    for label in labels.iter() {
        assert_ne!(label.as_str(), policy.trigger.label, "the trigger label");
        assert!(!label.as_str().starts_with("design: "), "{label}");
        assert!(label.as_str().len() > STATUS_PREFIX.len(), "{label}");
    }
    // The ways to try to make one are refused when the policy loads.
    let moved = replace_once(&real(), "prefix: \"factory: \"", "prefix: \"design: \"");
    assert!(
        format!("{}", refused(&moved)).contains("prefix"),
        "a namespace moved onto design:"
    );
    let nameless = replace_once(&real(), "name: paused,", "name: '',");
    assert!(
        format!("{}", refused(&nameless)).contains("not a status label"),
        "a state with no name"
    );
    let spaced = replace_once(&real(), "name: paused,", "name: ' paused',");
    assert!(
        refused(&spaced).message.len() > 10,
        "a space at the edge of the name"
    );
}

#[test]
fn a_label_over_the_length_limit_is_refused() {
    // 50 characters is the limit: "factory: " is 9, so a 42 character name is one too many.
    let long = "a".repeat(42);
    let text = replace_once(&real(), "name: paused,", &format!("name: {long},"));
    let error = refused(&text);
    assert!(
        format!("{error}").contains("1 to 50 printable ASCII"),
        "{error}"
    );
    // The longest allowed name loads, so the limit is exact.
    let edge = "a".repeat(41);
    load_text(&replace_once(
        &real(),
        "name: paused,",
        &format!("name: {edge},"),
    ))
    .expect("a name of exactly 50 characters with its prefix loads");
}

#[test]
fn a_description_over_the_limit_and_a_bad_color_are_refused() {
    let long = "x".repeat(101);
    let text = replace_once(&real(), "An operator paused the work.", &long);
    assert!(format!("{}", refused(&text)).contains("1 to 100 characters"));
    let text = replace_once(&real(), "color: \"d4c5f9\"", "color: \"D4C5F9\"");
    assert!(format!("{}", refused(&text)).contains("six lower-case hex digits"));
}

#[test]
fn the_schema_version_the_unknown_field_and_a_wrong_policy_are_refused_like_the_other_policies() {
    let text = replace_once(&real(), "schema_version: 1", "schema_version: 2");
    assert_eq!(refused(&text).kind, PolicyErrorKind::SchemaVersion);
    let text = replace_once(
        &real(),
        "  status: designed\n",
        "  status: designed\n  note: x\n",
    );
    assert_eq!(refused(&text).kind, PolicyErrorKind::Type);
    let text = replace_once(
        &real(),
        "intake_requirements:\n",
        "intake_requirements:\n  extra: true\n",
    );
    assert_eq!(refused(&text).kind, PolicyErrorKind::Type);
    let text = replace_once(&real(), "id: issue-workflow", "id: approval");
    assert_eq!(refused(&text).kind, PolicyErrorKind::WrongPolicy);
}

#[test]
fn the_hazards_the_yaml_subset_refuses_are_refused_here_too() {
    // A duplicate key and an anchor: the shared reader refuses both before any rule runs.
    let text = replace_once(
        &real(),
        "schema_version: 1\n",
        "schema_version: 1\nschema_version: 1\n",
    );
    assert!(matches!(refused(&text).kind, PolicyErrorKind::Yaml(_)));
    let text = replace_once(&real(), "trigger:\n", "x: &a 1\ntrigger:\n");
    assert!(matches!(refused(&text).kind, PolicyErrorKind::Yaml(_)));
}

#[test]
fn a_missing_file_is_an_error_and_there_is_no_default() {
    let dir = TempDir::new("issue-workflow-missing");
    let source = ProtectedPolicySource::protected_default_branch(dir.path(), &[]).unwrap();
    let error = PolicyLoader::load_issue_workflow(&source).expect_err("no file, no policy");
    assert_eq!(error.kind, PolicyErrorKind::Unavailable);
}
