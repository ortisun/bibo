//! The test gate, the baseline comparison and the acceptance evidence gate over a project whose
//! tests are not Rust: the manifest names a JUnit XML report file, and the stage reads it back
//! from the sandbox after the test command.
//!
//! The test runner here is a scripted `pytest` in the fake sandbox. The reports it "writes" are
//! built by this file in the shape pytest writes them. They were not recorded from pytest.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::vocabulary::GateOutcome;
use factory_ports::paths::CommitSha;
use factory_testkit::sandbox::ProgramOutput;
use factory_workflow::gates::framework::Resolution;
use serde_json::json;

use crate::gates::{gate, manifest_with};
use crate::world::{Ran, World, with};

const TESTS: &str = "unit-tests";
const ACCEPTANCE: &str = "acceptance-evidence";
const PROTECTION: &str = "test-file-protection";
const REPORT_FILE: &str = "/out/test-report.xml";

/// One run of the scripted pytest: its exit code and the report file it leaves, if any.
#[derive(Clone)]
struct PytestRun {
    exit: i32,
    report: Option<String>,
}

/// A scripted `pytest`, `python` and `cat` for the fake verify image.
#[derive(Default)]
struct Script {
    runs: Mutex<VecDeque<PytestRun>>,
    /// What is in the report file now: what the most recent pytest run left.
    file: Mutex<Option<String>>,
    calls: Mutex<Vec<Vec<String>>>,
}

fn said(text: &str) -> ProgramOutput {
    ProgramOutput {
        exit_code: Some(0),
        stdout: text.as_bytes().to_vec(),
        stderr: Vec::new(),
    }
}

impl Script {
    fn install(world: &World, runs: &[PytestRun]) -> Arc<Self> {
        let script = Arc::new(Self::default());
        script
            .runs
            .lock()
            .expect("the lock is never poisoned")
            .extend(runs.iter().cloned());
        let pytest = Arc::clone(&script);
        world.sandbox.add_program("pytest", move |argv, _| {
            if argv.iter().any(|word| word == "--version") {
                return said("pytest 8.3.3\n");
            }
            pytest.record(argv);
            let run = pytest
                .runs
                .lock()
                .expect("the lock is never poisoned")
                .pop_front()
                .unwrap_or(PytestRun {
                    exit: 4,
                    report: None,
                });
            *pytest.file.lock().expect("the lock is never poisoned") = run.report;
            ProgramOutput {
                exit_code: Some(run.exit),
                stdout: b"collected some items\n".to_vec(),
                stderr: Vec::new(),
            }
        });
        world.sandbox.add_program("python", |argv, _| {
            if argv.iter().any(|word| word == "--version") {
                said("Python 3.13.0\n")
            } else {
                said("")
            }
        });
        let cat = Arc::clone(&script);
        world.sandbox.add_program("cat", move |argv, _| {
            cat.record(argv);
            let file = cat.file.lock().expect("the lock is never poisoned").clone();
            match (argv.get(1).map(String::as_str), file) {
                (Some(REPORT_FILE), Some(text)) => said(&text),
                _ => ProgramOutput {
                    exit_code: Some(1),
                    stdout: Vec::new(),
                    stderr: b"cat: No such file or directory\n".to_vec(),
                },
            }
        });
        script
    }

    fn record(&self, argv: &[String]) {
        self.calls
            .lock()
            .expect("the lock is never poisoned")
            .push(argv.to_vec());
    }

    fn calls(&self) -> Vec<Vec<String>> {
        self.calls
            .lock()
            .expect("the lock is never poisoned")
            .clone()
    }
}

/// A JUnit report in the shape pytest writes: one suite, the class name is the module. Each
/// test ends as `ok`, `FAILED` or `ignored`, the words the Rust fixtures of this suite use.
fn junit(tests: &[(&str, &str)]) -> String {
    let count = |status: &str| tests.iter().filter(|(_, s)| *s == status).count();
    let mut cases = String::new();
    for (name, status) in tests {
        let child = match *status {
            "FAILED" => "<failure message=\"assert 1 == 0\">E   assert 1 == 0</failure>",
            "ignored" => "<skipped type=\"pytest.skip\" message=\"not now\">not now</skipped>",
            _ => "",
        };
        cases.push_str(&format!(
            "<testcase classname=\"tests.test_wc\" name=\"{name}\" time=\"0.001\">{child}</testcase>"
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><testsuites><testsuite name=\"pytest\" errors=\"0\" failures=\"{}\" skipped=\"{}\" tests=\"{}\" time=\"0.05\" hostname=\"verify\">{cases}</testsuite></testsuites>\n",
        count("FAILED"),
        count("ignored"),
        tests.len(),
    )
}

const BASE_TESTS: [(&str, &str); 2] = [("test_counts_a_line", "ok"), ("test_counts_nothing", "ok")];

/// The tests of the base commit and one new test for each requirement of the specification.
const HEAD_TESTS: [(&str, &str); 5] = [
    ("test_counts_a_line", "ok"),
    ("test_counts_nothing", "ok"),
    ("test_fr_001_counts_a_tab", "ok"),
    ("test_fr_002_counts_a_line_break", "ok"),
    ("test_fr_003_counts_repeated_spaces", "ok"),
];

fn passing(tests: &[(&str, &str)]) -> PytestRun {
    PytestRun {
        exit: 0,
        report: Some(junit(tests)),
    }
}

/// A Python project: the manifest at the base commit names pytest and its JUnit report file.
async fn project(world: &World) -> (CommitSha, CommitSha) {
    let mut tests = gate(TESTS, &["pytest", "--junitxml=/out/test-report.xml"]);
    tests["test_report"] = json!({ "format": "junit-xml", "path": "test-report.xml" });
    let manifest = manifest_with(json!([
        gate("build", &["python", "-m", "compileall", "src"]),
        tests
    ]));
    let base_files = with(&[
        (".factory/project.json", Some(&manifest)),
        (
            "tests/test_wc.py",
            Some("def test_counts_a_line():\n    assert True\n"),
        ),
    ]);
    let mut head_files = base_files.clone();
    head_files.retain(|(path, _)| path != "tests/test_wc.py");
    head_files.push((
        "tests/test_wc.py".to_owned(),
        "def test_counts_a_line():\n    assert True\n\n\ndef test_fr_001_counts_a_tab():\n    assert True\n".to_owned(),
    ));
    let base = world.push(&base_files).await;
    let head = world.push(&head_files).await;
    (base, head)
}

/// Runs the stage. The first scripted run is the candidate's, the second the base commit's.
async fn run_with(runs: &[PytestRun]) -> (Ran, Arc<Script>) {
    let world = World::new();
    let script = Script::install(&world, runs);
    let (base, head) = project(&world).await;
    let ran = world.run(&base, &head).await;
    (ran, script)
}

fn blocked_reason(ran: &Ran, gate: &str) -> (BlockedCode, String, String) {
    let report = ran.report(gate);
    let reason = report.blocked_reason.as_ref().expect("a blocked reason");
    (
        reason.code,
        reason
            .missing
            .iter()
            .map(|missing| missing.as_str().to_owned())
            .collect::<Vec<_>>()
            .join(", "),
        report.reason.as_str().to_owned(),
    )
}

#[tokio::test]
async fn a_python_project_passes_the_test_gate_and_the_acceptance_gate_on_its_junit_report() {
    let (ran, script) = run_with(&[passing(&HEAD_TESTS), passing(&BASE_TESTS)]).await;
    assert_eq!(ran.outcome(TESTS), GateOutcome::Passed);
    assert_eq!(ran.outcome(PROTECTION), GateOutcome::Passed);
    assert_eq!(ran.outcome(ACCEPTANCE), GateOutcome::Passed);
    assert_eq!(ran.outcome("build"), GateOutcome::Passed);
    assert_eq!(ran.resolution, Resolution::Pass);
    assert_eq!(ran.problem, None, "the engine accepts the evidence");

    // The report file was read back once after each test run, by a command the supervisor ran,
    // and that command is in the gate report next to the test command.
    let reads: Vec<Vec<String>> = script
        .calls()
        .into_iter()
        .filter(|call| call[0] == "cat")
        .collect();
    assert_eq!(reads, [["cat", REPORT_FILE], ["cat", REPORT_FILE]]);
    let commands: Vec<Vec<String>> = ran
        .report(TESTS)
        .commands
        .iter()
        .map(|command| command.argv.as_slice().to_vec())
        .collect();
    assert!(commands.contains(&vec!["cat".to_owned(), REPORT_FILE.to_owned()]));
    assert!(
        commands
            .iter()
            .any(|argv| argv[0] == "pytest" && argv.len() > 1 && argv[1] != "--version")
    );

    // The covering tests are named as the JUnit report names them: class name and name.
    let notes = ran
        .report(ACCEPTANCE)
        .baseline_comparison
        .notes
        .as_ref()
        .expect("the notes of the comparison")
        .as_str()
        .to_owned();
    for (requirement, test) in [
        ("FR-001", "tests.test_wc::test_fr_001_counts_a_tab"),
        ("FR-002", "tests.test_wc::test_fr_002_counts_a_line_break"),
        (
            "FR-003",
            "tests.test_wc::test_fr_003_counts_repeated_spaces",
        ),
    ] {
        let line = notes
            .lines()
            .find(|line| line.starts_with(requirement))
            .unwrap_or_else(|| panic!("a line for {requirement} in {notes:?}"));
        assert!(line.contains(test), "{line}");
        assert!(line.contains("new test"), "{line}");
    }
}

#[tokio::test]
async fn exit_code_zero_without_the_report_file_is_blocked_and_never_passed() {
    let no_report = PytestRun {
        exit: 0,
        report: None,
    };
    let (ran, _) = run_with(&[no_report, passing(&BASE_TESTS)]).await;
    assert_eq!(ran.outcome(TESTS), GateOutcome::Blocked);
    let (code, missing, reason) = blocked_reason(&ran, TESTS);
    assert_eq!(code, BlockedCode::ToolProbeFailed);
    assert_eq!(missing, "the test report file");
    assert!(reason.contains("could not be read"), "{reason}");
    assert_eq!(ran.outcome(ACCEPTANCE), GateOutcome::Blocked);
    assert!(!matches!(ran.resolution, Resolution::Pass));
}

#[tokio::test]
async fn a_report_that_cannot_be_trusted_blocks_the_gate_with_the_reason() {
    let whole = junit(&HEAD_TESTS);
    let cases: [(&str, String); 5] = [
        ("is empty", String::new()),
        ("ends before", whole[..whole.len() - 30].to_owned()),
        ("totals", whole.replace("tests=\"5\"", "tests=\"6\"")),
        ("not well-formed", format!("{whole}trailing text")),
        (
            "document type",
            whole.replace(
                "<testsuites>",
                "<!DOCTYPE x [<!ENTITY a \"b\">]><testsuites>",
            ),
        ),
    ];
    for (part_of_reason, report) in cases {
        let bad = PytestRun {
            exit: 0,
            report: Some(report),
        };
        let (ran, _) = run_with(&[bad, passing(&BASE_TESTS)]).await;
        assert_eq!(ran.outcome(TESTS), GateOutcome::Blocked, "{part_of_reason}");
        let (_, missing, reason) = blocked_reason(&ran, TESTS);
        assert_eq!(missing, "a test report that can be trusted");
        assert!(reason.contains(part_of_reason), "{reason}");
        assert_eq!(ran.outcome(ACCEPTANCE), GateOutcome::Blocked);
        assert!(!matches!(ran.resolution, Resolution::Pass));
    }
}

#[tokio::test]
async fn a_report_with_no_test_that_ran_is_blocked() {
    for tests in [&[][..], &[("test_counts_a_line", "ignored")][..]] {
        let (ran, _) = run_with(&[passing(tests), passing(&BASE_TESTS)]).await;
        assert_eq!(ran.outcome(TESTS), GateOutcome::Blocked);
        let (_, missing, _) = blocked_reason(&ran, TESTS);
        assert_eq!(missing, "at least one test that ran");
    }
}

#[tokio::test]
async fn a_failed_test_fails_the_gate_and_the_report_names_it() {
    let mut tests = HEAD_TESTS.to_vec();
    tests[3].1 = "FAILED";
    let failing = PytestRun {
        exit: 1,
        report: Some(junit(&tests)),
    };
    let (ran, _) = run_with(&[failing, passing(&BASE_TESTS)]).await;
    assert_eq!(ran.outcome(TESTS), GateOutcome::Failed);
    let messages: Vec<String> = ran
        .report(TESTS)
        .failures
        .iter()
        .flatten()
        .map(|failure| failure.message.as_str().to_owned())
        .collect();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("tests.test_wc::test_fr_002_counts_a_line_break")),
        "{messages:?}"
    );
    assert!(matches!(ran.resolution, Resolution::Failed { .. }));
}

#[tokio::test]
async fn exit_code_zero_with_a_failed_test_in_the_report_is_blocked() {
    let mut tests = HEAD_TESTS.to_vec();
    tests[0].1 = "FAILED";
    let (ran, _) = run_with(&[passing(&tests), passing(&BASE_TESTS)]).await;
    assert_eq!(ran.outcome(TESTS), GateOutcome::Blocked);
    let (_, missing, _) = blocked_reason(&ran, TESTS);
    assert_eq!(missing, "test output that matches the exit code");
}

#[tokio::test]
async fn a_test_of_the_base_commit_that_is_gone_or_skipped_now_fails_test_protection() {
    // `test_counts_nothing` passed on the base commit and is not in the candidate's report.
    let removed: Vec<(&str, &str)> = HEAD_TESTS
        .iter()
        .copied()
        .filter(|(name, _)| *name != "test_counts_nothing")
        .collect();
    let (ran, _) = run_with(&[passing(&removed), passing(&BASE_TESTS)]).await;
    assert_eq!(ran.outcome(PROTECTION), GateOutcome::Failed);
    assert!(
        ran.failure_checks(PROTECTION)
            .contains(&"test-removed".to_owned())
    );

    let mut skipped = HEAD_TESTS.to_vec();
    skipped[1].1 = "ignored";
    let (ran, _) = run_with(&[passing(&skipped), passing(&BASE_TESTS)]).await;
    assert_eq!(ran.outcome(PROTECTION), GateOutcome::Failed);
    assert!(
        ran.failure_checks(PROTECTION)
            .contains(&"test-ignored".to_owned())
    );
}

#[tokio::test]
async fn a_test_that_already_passed_on_the_base_commit_does_not_cover_its_requirement() {
    let mut base = BASE_TESTS.to_vec();
    base.push(("test_fr_001_counts_a_tab", "ok"));
    let (ran, _) = run_with(&[passing(&HEAD_TESTS), passing(&base)]).await;
    assert_eq!(ran.outcome(TESTS), GateOutcome::Passed);
    assert_eq!(ran.outcome(ACCEPTANCE), GateOutcome::Failed);
    assert_eq!(
        ran.failure_checks(ACCEPTANCE),
        ["requirement-covered-only-by-old-tests"]
    );
}

#[tokio::test]
async fn without_a_report_of_the_base_commit_the_acceptance_gate_is_blocked() {
    let no_report = PytestRun {
        exit: 0,
        report: None,
    };
    let (ran, _) = run_with(&[passing(&HEAD_TESTS), no_report]).await;
    assert_eq!(ran.outcome(TESTS), GateOutcome::Passed);
    assert_eq!(ran.outcome(ACCEPTANCE), GateOutcome::Blocked);
    assert!(!matches!(ran.resolution, Resolution::Pass));
}

#[tokio::test]
async fn a_tap_report_on_standard_output_is_read_without_a_second_command() {
    let world = World::new();
    let script = Script::install(&world, &[]);
    let outputs = Arc::new(Mutex::new(VecDeque::from([
        "TAP version 13\n1..3\nok 1 - counts a line\nok 2 - fr_001 counts a tab\nok 3 - fr_002 and fr_003 count breaks and spaces\n",
        "TAP version 13\n1..1\nok 1 - counts a line\n",
    ])));
    world.sandbox.add_program("npm", move |argv, _| {
        if argv.iter().any(|word| word == "--version") {
            return said("10.9.0\n");
        }
        let next = outputs
            .lock()
            .expect("the lock is never poisoned")
            .pop_front()
            .unwrap_or_default();
        said(next)
    });
    let mut tests = gate(TESTS, &["npm", "test"]);
    tests["test_report"] = json!({ "format": "tap" });
    let manifest = manifest_with(json!([
        gate("build", &["python", "-m", "compileall", "src"]),
        tests
    ]));
    let base_files = with(&[(".factory/project.json", Some(&manifest))]);
    let mut head_files = base_files.clone();
    head_files.push((
        "test/count.test.js".to_owned(),
        "// a new test\n".to_owned(),
    ));
    let base = world.push(&base_files).await;
    let head = world.push(&head_files).await;
    let ran = world.run(&base, &head).await;
    assert_eq!(ran.outcome(TESTS), GateOutcome::Passed);
    assert_eq!(ran.outcome(ACCEPTANCE), GateOutcome::Passed);
    assert_eq!(ran.resolution, Resolution::Pass);
    assert!(
        !script.calls().iter().any(|call| call[0] == "cat"),
        "nothing is read back when the report is the standard output"
    );
}
