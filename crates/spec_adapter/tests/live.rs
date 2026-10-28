//! The live run of the specification skills on the fixture issue (`FACTORY_LIVE=1`).
//!
//! It needs the installed Spec Kit, a real agent tool in a sandbox image and a model credential.
//! None of them is available to the test suite, and the suite never calls a model. Without
//! `FACTORY_LIVE` the test does nothing. With it set and a prerequisite missing, the test fails
//! with a message that starts `BLOCKED:` so that a missing prerequisite is never read as a pass.
//!
//! The inner crates may not read the process environment (rule DEP-05), so the variables are
//! read when the test is compiled, with `option_env!`. Cargo recompiles the test when they change.
//!
//! What a live run must prove, and the spike questions it answers, are listed in the final report
//! of work package `s1-spec-adapter-and-stage`.

#[test]
fn live_run_on_the_fixture_issue_or_blocked() {
    if option_env!("FACTORY_LIVE").is_none() {
        return;
    }
    let prerequisites = [
        (
            option_env!("FACTORY_LIVE_SANDBOX_IMAGE"),
            "the agent sandbox image",
        ),
        (
            option_env!("FACTORY_LIVE_MODEL_ENDPOINT"),
            "the model broker endpoint",
        ),
        (
            option_env!("FACTORY_LIVE_SPECKIT"),
            "the installed Spec Kit",
        ),
    ];
    let missing: Vec<&str> = prerequisites
        .into_iter()
        .filter(|(value, _)| value.is_none())
        .map(|(_, what)| what)
        .collect();
    assert!(
        missing.is_empty(),
        "BLOCKED: the live run needs {}, and none is set. No model was called.",
        missing.join(", ")
    );
    // The composition root that wires the real sandbox, runtime and broker is outside this
    // crate. Reaching this line means the prerequisites exist, and the run belongs to the
    // end-to-end harness.
    panic!("BLOCKED: the live run is driven by the end-to-end harness, which owns the wiring");
}
