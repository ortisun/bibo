//! The labelled corpus, embedded at compile time, and a runner that compares the gate with it.
//!
//! The corpus is `fixtures/readability/cases/*.json`, owned by the documentation rubric package.
//! This file reads it and never changes it. A case says which rule ids its text breaks (`breaks`)
//! and what the verdict is. Only the deterministic rules are the gate's business, so the expected
//! set is `breaks` filtered to deterministic rules, and the expected verdict is derived from that
//! filtered set with the severities of the catalog (`fixtures/readability/README.md`, "How the
//! gate should use the corpus").
//!
//! The corpus is read with `include_str!` because the workflow crate may not read files. The list
//! of files is explicit. A new file in the directory is not seen here until it is added to
//! [`FILES`], and the check `the_corpus_has_every_file_and_a_plausible_number_of_cases` fails
//! when a file disappears or the corpus shrinks. `python3 -I fixtures/readability/check_corpus.py`
//! walks the directory and is the check that finds a file this list lacks.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use factory_workflow::gates::readability::{
    Artifact, Catalog, DocumentType, Finding, Options, RuleId, Severity, check,
};
use serde_json::Value;

/// Every file of `fixtures/readability/cases/`, by name.
pub const FILES: [(&str, &str); 9] = [
    (
        "adversarial",
        include_str!("../../../../fixtures/readability/cases/adversarial.json"),
    ),
    (
        "documentation",
        include_str!("../../../../fixtures/readability/cases/documentation.json"),
    ),
    (
        "identity",
        include_str!("../../../../fixtures/readability/cases/identity.json"),
    ),
    (
        "prompt-examples",
        include_str!("../../../../fixtures/readability/cases/prompt-examples.json"),
    ),
    (
        "pull-requests",
        include_str!("../../../../fixtures/readability/cases/pull-requests.json"),
    ),
    (
        "requests",
        include_str!("../../../../fixtures/readability/cases/requests.json"),
    ),
    (
        "tasks",
        include_str!("../../../../fixtures/readability/cases/tasks.json"),
    ),
    (
        "titles",
        include_str!("../../../../fixtures/readability/cases/titles.json"),
    ),
    (
        "translations",
        include_str!("../../../../fixtures/readability/cases/translations.json"),
    ),
];

/// One text to check, as the corpus describes it. An `identity_pair` gives one of these for each
/// version, and a `translation` gives the English rendering.
#[derive(Debug, Clone)]
pub struct Sample {
    pub id: String,
    pub file: &'static str,
    pub kind: String,
    pub title: String,
    pub body: String,
    pub doc_type: Option<DocumentType>,
    /// Every rule id in `breaks`, deterministic or not.
    pub breaks: BTreeSet<String>,
    pub verdict: String,
}

impl Sample {
    pub fn artifact(&self) -> Artifact<'_> {
        match self.kind.as_str() {
            "task" => Artifact::task(&self.title, &self.body),
            "pull_request" => Artifact::pull_request(&self.title, &self.body),
            "documentation" => Artifact::documentation(
                &self.title,
                self.doc_type.expect("a documentation case has a doc_type"),
                &self.body,
            ),
            "title" => Artifact::title(&self.title),
            // A request, and the English rendering of a translation.
            _ => Artifact::request(&self.title, &self.body),
        }
    }
}

fn text(value: &Value, key: &str) -> String {
    value[key].as_str().expect("a text field").to_owned()
}

fn lines(value: &Value) -> String {
    value["body"]
        .as_array()
        .map(|lines| {
            lines
                .iter()
                .map(|line| line.as_str().expect("a body line"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn rule_set(value: &Value) -> BTreeSet<String> {
    value["breaks"]
        .as_array()
        .expect("breaks is a list")
        .iter()
        .map(|rule| rule.as_str().expect("a rule id").to_owned())
        .collect()
}

/// Every sample of the corpus.
pub fn samples() -> Vec<Sample> {
    let mut out = Vec::new();
    for (file, json) in FILES {
        let doc: Value = serde_json::from_str(json).expect("a case file is JSON");
        for case in doc["cases"].as_array().expect("a list of cases") {
            let id = text(case, "id");
            let kind = text(case, "kind");
            let input = &case["input"];
            match kind.as_str() {
                "identity_pair" => {
                    for version in input["versions"].as_array().expect("versions") {
                        out.push(Sample {
                            id: format!("{id} [{}]", text(version, "label")),
                            file,
                            kind: "title".to_owned(),
                            title: text(version, "title"),
                            body: String::new(),
                            doc_type: None,
                            breaks: rule_set(version),
                            verdict: text(version, "verdict"),
                        });
                    }
                }
                "translation" => out.push(Sample {
                    id,
                    file,
                    kind: "request".to_owned(),
                    title: text(&input["rendering"], "title"),
                    body: lines(&input["rendering"]),
                    doc_type: None,
                    breaks: rule_set(case),
                    verdict: text(case, "verdict"),
                }),
                _ => out.push(Sample {
                    id,
                    file,
                    title: text(input, "title"),
                    body: lines(input),
                    doc_type: input["doc_type"]
                        .as_str()
                        .map(|name| DocumentType::parse(name).expect("a known document type")),
                    kind,
                    breaks: rule_set(case),
                    verdict: text(case, "verdict"),
                }),
            }
        }
    }
    out
}

/// The verdict of a set of severities: `block` if any blocks, else `warn` if any warns, else `pass`.
pub fn verdict_of(severities: impl IntoIterator<Item = Severity>) -> &'static str {
    let mut verdict = "pass";
    for severity in severities {
        match severity {
            Severity::Block => return "block",
            Severity::Warn => verdict = "warn",
        }
    }
    verdict
}

/// One case where the gate and the label differ.
#[derive(Debug)]
pub struct Disagreement {
    pub id: String,
    pub file: &'static str,
    pub expected: BTreeSet<String>,
    pub actual: BTreeSet<String>,
    pub expected_verdict: &'static str,
    pub actual_verdict: &'static str,
}

/// The result of one run of the corpus.
#[derive(Debug, Default)]
pub struct Outcome {
    pub cases: usize,
    pub matched: usize,
    pub disagreements: Vec<Disagreement>,
}

impl Outcome {
    /// A report that names every failing case, for the message of a failed assertion.
    pub fn describe(&self) -> String {
        let mut out = format!(
            "{} of {} cases disagree with their labels:\n",
            self.disagreements.len(),
            self.cases
        );
        for d in &self.disagreements {
            let _ = writeln!(
                out,
                "  {} ({}): expected {:?} / {}, gate reported {:?} / {}",
                d.id, d.file, d.expected, d.expected_verdict, d.actual, d.actual_verdict
            );
        }
        out
    }
}

/// Runs the corpus through the gate.
///
/// `scope` picks the rules under test. `hide` drops the findings of a rule after the gate ran,
/// which is how a test shows that the corpus notices a rule that stopped working.
pub fn run_with(
    catalog: &Catalog,
    options: &Options,
    scope: impl Fn(RuleId) -> bool,
    hide: impl Fn(RuleId) -> bool,
) -> Outcome {
    let mut outcome = Outcome::default();
    for sample in samples() {
        let artifacts = [sample.artifact()];
        let findings: Vec<Finding> = check(catalog, options, &artifacts)
            .expect("a corpus case is far below the size limit")
            .into_iter()
            .filter(|f| scope(f.rule) && !hide(f.rule))
            .collect();
        let actual: BTreeSet<String> = findings
            .iter()
            .map(|f| f.rule.as_str().to_owned())
            .collect();
        let expected_rules: Vec<RuleId> = sample
            .breaks
            .iter()
            .filter_map(|id| RuleId::parse(id))
            .filter(|rule| scope(*rule))
            .collect();
        let expected: BTreeSet<String> = expected_rules
            .iter()
            .map(|rule| rule.as_str().to_owned())
            .collect();
        let expected_verdict =
            verdict_of(expected_rules.iter().map(|rule| catalog.severity(*rule)));
        let actual_verdict = verdict_of(findings.iter().map(|f| f.severity));
        outcome.cases += 1;
        if expected == actual && expected_verdict == actual_verdict {
            outcome.matched += 1;
        } else {
            outcome.disagreements.push(Disagreement {
                id: sample.id.clone(),
                file: sample.file,
                expected,
                actual,
                expected_verdict,
                actual_verdict,
            });
        }
    }
    outcome
}

/// Runs the corpus with every rule on and none hidden.
pub fn run(scope: impl Fn(RuleId) -> bool) -> Outcome {
    let catalog = Catalog::embedded().expect("the embedded catalog loads");
    run_with(&catalog, &Options::new(), scope, |_| false)
}
