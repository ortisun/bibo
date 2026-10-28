//! `probe`: the checks that can run in process, and the `BLOCKED:` lines for the ones that cannot.
//!
//! The command starts no process (DEP-10), so it cannot read a runtime's capability record itself.
//! It says so for each runtime and for each adapter the composition cannot assemble, and exits 3.

use std::path::PathBuf;

use factory_cli::{Exit, run};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn probe(args: &[&str]) -> (Exit, String, String) {
    let args: Vec<String> = std::iter::once("probe".to_owned())
        .chain(args.iter().map(|word| (*word).to_owned()))
        .collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit = run(&args, &|_| None, &mut out, &mut err);
    (
        exit,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

#[test]
fn probe_prints_the_checks_and_exits_3_with_blocked_lines() {
    let checkout = root();
    let catalog = root().join("infra/sandbox-images/images.json");
    let (exit, out, err) = probe(&[
        "--protected-checkout",
        checkout.to_str().expect("utf-8"),
        "--images-catalog",
        catalog.to_str().expect("utf-8"),
    ]);
    assert_eq!(exit.code(), 3, "stdout: {out}\nstderr: {err}");
    // What could run, passed.
    assert!(out.contains("OK: policy: loaded"), "{out}");
    assert!(out.contains("OK: redactor"), "{out}");
    // What could not run is named, one line each, and is not a pass.
    for runtime in ["claude", "codex"] {
        assert!(
            err.contains(&format!("BLOCKED: runtime {runtime}:")),
            "{err}"
        );
    }
    for adapter in [
        "agent runtime",
        "model router",
        "issue source",
        "change host",
    ] {
        assert!(err.contains(&format!("BLOCKED: {adapter}:")), "{err}");
    }
    assert!(err.contains("BLOCKED: DeliverySources::tree_of"), "{err}");
    assert!(err.contains("BLOCKED is not a pass"), "{err}");
    assert!(!err.contains("FAILED"), "{err}");
}

#[test]
fn probe_without_a_catalog_says_it_could_not_check_the_images() {
    let checkout = root();
    let (exit, _, err) = probe(&["--protected-checkout", checkout.to_str().expect("utf-8")]);
    assert_eq!(exit.code(), 3);
    assert!(err.contains("BLOCKED: sandbox images:"), "{err}");
}

#[test]
fn probe_fails_loudly_on_a_checkout_without_a_policy() {
    let empty = std::env::temp_dir().join(format!("factory-cli-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).expect("dir");
    let (exit, out, err) = probe(&["--protected-checkout", empty.to_str().expect("utf-8")]);
    assert_eq!(exit.code(), 1);
    assert!(err.contains("FAILED: policy:"), "{err}");
    assert!(!out.contains("OK: policy"));
    let _ = std::fs::remove_dir_all(empty);
}

#[test]
fn probe_refuses_an_unknown_profile_and_a_missing_checkout_argument() {
    assert_eq!(probe(&[]).0.code(), 1);
    assert_eq!(
        probe(&["--protected-checkout", "/x", "--profile", "staging"])
            .0
            .code(),
        1
    );
    assert_eq!(
        probe(&["--protected-checkout", "/x", "--shell", "sh"])
            .0
            .code(),
        1
    );
}
