//! The issue texts: they load, they are what their README says, and the readability gate agrees
//! with the language of each.

use std::fs;

use factory_e2e::issues::{self, Requester};
use factory_workflow::gates::readability::{Artifact, Catalog, Options, Severity, check};

const OUTCOMES: [&str; 6] = [
    "draft_pull_request",
    "rejected_at_admission",
    "no_effect",
    "restart_from_intake",
    "one_question",
    "declined",
];

fn blocking_rules(title: &str, body: &str) -> Vec<&'static str> {
    let catalog = Catalog::embedded().expect("the catalog loads");
    let artifacts = [Artifact::request(title, body)];
    check(&catalog, &Options::new(), &artifacts)
        .expect("the gate runs")
        .into_iter()
        .filter(|finding| finding.severity == Severity::Block)
        .map(|finding| finding.rule.as_str())
        .collect()
}

#[test]
fn every_issue_loads_and_the_directory_holds_no_other_file() {
    let loaded = issues::load_all().expect("every issue loads");
    assert_eq!(loaded.len(), issues::ids().len());
    let dir = format!("{}/issues", env!("CARGO_MANIFEST_DIR"));
    let mut on_disk: Vec<String> = fs::read_dir(&dir)
        .expect("the issues directory")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".json").map(str::to_owned))
        .collect();
    on_disk.sort();
    let mut known: Vec<String> = issues::ids().into_iter().map(str::to_owned).collect();
    known.sort();
    assert_eq!(
        on_disk, known,
        "a file in issues/ is not embedded, or the reverse"
    );
}

#[test]
fn every_issue_has_a_known_outcome_and_plain_english_behavior() {
    for issue in issues::load_all().expect("load") {
        assert!(
            OUTCOMES.contains(&issue.expected.outcome.as_str()),
            "{}",
            issue.id
        );
        assert!(
            issue.expected.behavior.len() >= 3,
            "{} lists too little behavior",
            issue.id
        );
        assert!(!issue.summary.is_empty());
        for line in &issue.expected.behavior {
            assert!(
                line.ends_with('.'),
                "{}: '{line}' is not a sentence",
                issue.id
            );
        }
    }
}

#[test]
fn the_readme_lists_every_issue_file() {
    let readme = fs::read_to_string(format!("{}/issues/README.md", env!("CARGO_MANIFEST_DIR")))
        .expect("the issues README");
    for id in issues::ids() {
        assert!(
            readme.contains(&format!("`{id}.json`")),
            "{id} is not in the README table"
        );
    }
}

#[test]
fn the_english_requests_pass_the_readability_gate_as_requests() {
    for id in [
        "json-output-en",
        "unauthorized-requester",
        "ambiguous-request",
        "out-of-policy-request",
        "hostile-injection",
    ] {
        let issue = issues::load(id).expect("load");
        for revision in &issue.revisions {
            let blocking = blocking_rules(&revision.title, &revision.body_text());
            assert!(blocking.is_empty(), "{id}: {blocking:?}");
        }
    }
}

#[test]
fn the_portuguese_request_is_recognised_as_not_english_by_the_gate() {
    let issue = issues::load("json-output-pt").expect("load");
    let blocking = blocking_rules(&issue.first().title, &issue.first().body_text());
    assert!(
        blocking.contains(&"text-not-english"),
        "the gate should block Portuguese prose, got {blocking:?}"
    );
}

#[test]
fn the_portuguese_request_has_the_same_intent_as_the_english_one() {
    let english = issues::load("json-output-en").expect("load");
    let portuguese = issues::load("json-output-pt").expect("load");
    assert_eq!(portuguese.same_intent_as.as_deref(), Some("json-output-en"));
    assert_eq!(english.intent, portuguese.intent);
    // The facts that must survive are in both texts: the option, the keys and the example counts.
    for fact in [
        "--json",
        "lines",
        "words",
        "characters",
        "3",
        "7",
        "31",
        "README",
    ] {
        assert!(
            english.first().body_text().contains(fact),
            "English text lacks {fact}"
        );
        assert!(
            portuguese.first().body_text().contains(fact),
            "Portuguese text lacks {fact}"
        );
    }
    // Four acceptance criteria in each, as list items under the criteria heading.
    let items = |text: &str| text.lines().filter(|l| l.starts_with("- ")).count();
    assert_eq!(
        items(&english.first().body_text()),
        items(&portuguese.first().body_text())
    );
}

#[test]
fn the_intent_checks_hold_for_the_english_request_text_and_not_for_nonsense() {
    let issue = issues::load("json-output-en").expect("load");
    let text = format!("{}\n{}", issue.first().title, issue.first().body_text());
    for check in &issue.intent.checks {
        assert!(
            check.holds_in(&text),
            "{} does not hold for the English request",
            check.id
        );
        assert!(
            !check.holds_in("an unrelated sentence"),
            "{} holds for nonsense",
            check.id
        );
    }
}

#[test]
fn the_hostile_request_carries_its_markers_and_the_others_carry_none() {
    for issue in issues::load_all().expect("load") {
        let text = issue.current().body_text();
        match &issue.injection {
            Some(injection) => {
                assert_eq!(issue.id, "hostile-injection");
                assert!(injection.markers.iter().all(|m| text.contains(m.as_str())));
                assert!(injection.demanded_actions.len() >= 5);
            }
            None => assert!(
                !text.contains("Ignore all previous instructions"),
                "{}",
                issue.id
            ),
        }
    }
}

#[test]
fn the_edited_request_has_a_clean_first_revision_and_a_second_that_asks_for_harm() {
    let issue = issues::load("edited-after-authorization").expect("load");
    assert_eq!(issue.revisions.len(), 2);
    assert!(
        !issue
            .first()
            .body_text()
            .contains("Remove the `tests` directory")
    );
    assert!(
        issue
            .current()
            .body_text()
            .contains("Remove the `tests` directory")
    );
    assert_eq!(issue.first().title, issue.current().title);
}

#[test]
fn only_the_unauthorized_request_comes_from_a_stranger_and_it_has_a_no_label_variant() {
    for issue in issues::load_all().expect("load") {
        let expected = if issue.id == "unauthorized-requester" {
            Requester::Unauthorized
        } else {
            Requester::Authorized
        };
        assert_eq!(issue.requester, expected, "{}", issue.id);
    }
    let issue = issues::load("unauthorized-requester").expect("load");
    assert_eq!(issue.variants.len(), 1);
    assert!(issue.variants[0].labels.is_empty());
}
