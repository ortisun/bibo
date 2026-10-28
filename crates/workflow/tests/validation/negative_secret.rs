//! NT-SEC-05: secrets in the diff are blocked before anything is committed or sent.
//!
//! The secrets here are built at run time, so that no secret-shaped literal sits in the source.

use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::framework::{BlockCause, Resolution};

use crate::gates::{base_run, head_run};
use crate::world::{LIB, Ran, World, base_files, with};

fn token() -> String {
    format!("{}{}", "ghp_", "a1B2c3".repeat(6))
}

fn private_key() -> String {
    format!(
        "-----BEGIN {} KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END {} KEY-----\n",
        "PRIVATE", "PRIVATE"
    )
}

async fn run_change(changes: &[(&str, Option<&str>)]) -> (World, Ran) {
    let w = World::new();
    let (base, head) = w.project(changes).await;
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    (w, ran)
}

fn nothing_ran(w: &World, ran: &Ran) {
    assert_eq!(w.sandbox.created(), 0, "no sandbox was made");
    assert!(w.cargo.calls().is_empty(), "no command ran");
    assert!(ran.decision.policy_violation);
    assert_eq!(
        ran.resolution,
        Resolution::Blocked(BlockCause::PolicyViolation)
    );
}

#[tokio::test]
async fn negative_nt_sec_05_a_token_in_source_blocks_the_change_and_its_text_is_never_kept() {
    let source = format!("{LIB}\nconst TOKEN: &str = \"{}\";\n", token());
    let (w, ran) = run_change(&[("src/lib.rs", Some(&source))]).await;
    assert_eq!(ran.outcome("secret-scan"), GateOutcome::Failed);
    assert_eq!(ran.failure_checks("secret-scan"), ["secret-in-diff"]);
    let failure = ran
        .report("secret-scan")
        .failures
        .iter()
        .flatten()
        .next()
        .expect("a failure");
    assert_eq!(
        failure.location.as_ref().map(|at| at.path.as_str()),
        Some("src/lib.rs")
    );
    nothing_ran(&w, &ran);
    // The finding names the path, never the value, in every document the stage wrote.
    let everything = ran.evidence.to_string();
    assert!(!everything.contains(&token()));
    assert!(!everything.contains("a1B2c3a1B2c3"));
}

#[tokio::test]
async fn negative_nt_sec_05_a_private_key_in_documentation_blocks_the_change() {
    let readme = format!("# Word count\n\n{}", private_key());
    let (w, ran) = run_change(&[("README.md", Some(&readme))]).await;
    assert_eq!(ran.outcome("secret-scan"), GateOutcome::Failed);
    assert!(!ran.evidence.to_string().contains("MIIEvQIBADANBg"));
    nothing_ran(&w, &ran);
}

#[tokio::test]
async fn negative_nt_sec_05_secret_bearing_files_are_hidden_paths_that_no_change_may_add() {
    for path in [".env", "keys/id_rsa", "deploy/.env.production"] {
        let (w, ran) = run_change(&[(path, Some("KEY=value\n"))]).await;
        assert_eq!(
            ran.outcome("protected-paths-unchanged"),
            GateOutcome::Failed,
            "{path}"
        );
        assert!(
            ran.failure_checks("protected-paths-unchanged")
                .contains(&"hidden-path".to_owned()),
            "{path}"
        );
        nothing_ran(&w, &ran);
    }
}

#[tokio::test]
async fn negative_nt_sec_05_only_the_lines_the_change_adds_are_scanned() {
    // A line that was already in the base commit is not this change's secret.
    let w = World::new();
    let old = format!("# Word count\n{}\n", token());
    let base = w.push(&with(&[("README.md", Some(&old))])).await;
    let new = format!("{old}\nA new sentence.\n");
    let head = w.push(&with(&[("README.md", Some(&new))])).await;
    w.cargo.queue_test_run(head_run());
    w.cargo.queue_test_run(base_run());
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("secret-scan"), GateOutcome::Passed);
    // The same line added a second time is new.
    let twice = format!("{old}{}\n", token());
    let head = w.push(&with(&[("README.md", Some(&twice))])).await;
    let ran = w.run(&base, &head).await;
    assert_eq!(ran.outcome("secret-scan"), GateOutcome::Failed);
}

#[tokio::test]
async fn negative_nt_sec_05_a_file_that_cannot_be_scanned_in_full_is_not_a_clean_file() {
    let big = "x\n".repeat(600_000);
    let (w, ran) = run_change(&[("docs/big.txt", Some(&big))]).await;
    assert_eq!(ran.outcome("secret-scan"), GateOutcome::Blocked);
    assert_eq!(ran.outcome("test-file-protection"), GateOutcome::Blocked);
    assert_eq!(w.sandbox.created(), 0);
    assert!(w.cargo.calls().is_empty());
    assert!(matches!(ran.resolution, Resolution::Blocked(_)));
    let _ = base_files();
}
