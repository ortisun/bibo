//! The live smoke test (work package done criterion 8): one minimal turn of each tool through the
//! model broker, with a real provider key behind it, recording evidence of fidelity `real`.
//!
//! **It reports BLOCKED, not PASSED, when it cannot run.** Run with `FACTORY_LIVE=1`. It needs all of:
//!
//! 1. an Anthropic key and an OpenAI key, each made for the factory with a hard provider-side spend
//!    limit, held by the model broker (`s1-egress-and-broker`) and never by this test;
//! 2. the broker running, and its address in `FACTORY_LIVE_BROKER_URL`;
//! 3. a job token the broker issued for this smoke test, in a file named by
//!    `FACTORY_LIVE_TOKEN_FILE`, with a small ceiling and the two models in its allowed list;
//! 4. the pinned agent image on the host, and a sandbox provider that can put the broker on the
//!    job network (the sidecar image is still a skeleton).
//!
//! A subscription login (a claude.ai or ChatGPT login) does not count. This test never looks for one:
//! it reads no file under a home directory and no key from the environment, and the adapters it
//! drives deliver the token only through the file named above.
//!
//! Without `FACTORY_LIVE=1` the test only says that no live run was requested. That is not evidence
//! of anything, and the line it prints says so.

mod support;

use factory_testkit::fx::docker::blocked;

/// What a live run needs and this machine does not have, in the order a human would supply it.
fn what_is_missing() -> Vec<&'static str> {
    let mut missing = Vec::new();
    for (name, why) in [
        (
            "FACTORY_LIVE_BROKER_URL",
            "the address of a running model broker (work package s1-egress-and-broker does not exist yet)",
        ),
        (
            "FACTORY_LIVE_TOKEN_FILE",
            "a job token file issued by that broker, with a small cost ceiling",
        ),
    ] {
        if std::env::var_os(name).is_none() {
            missing.push(why);
        }
    }
    // The egress sidecar image is a skeleton in infra/sandbox-images/images.json, so no sandbox
    // provider can put a broker on the job network yet. When the image is ready this entry goes.
    if support::IMAGES_JSON.contains("\"status\": \"awaiting-binary\"") {
        missing.push(
            "a ready egress sidecar image (the one in images.json is a skeleton), so that a sandbox can reach the broker",
        );
    }
    missing.push(
        "an Anthropic key and an OpenAI key with provider-side spend limits, loaded into the broker by a person",
    );
    missing
}

#[test]
fn live_smoke_reports_blocked_and_never_passed_without_a_broker_and_provider_keys() {
    if std::env::var("FACTORY_LIVE").as_deref() != Ok("1") {
        println!(
            "NOT REQUESTED: no live run was made and this line is not evidence of a working provider; set FACTORY_LIVE=1 to ask for one"
        );
        return;
    }
    let missing = what_is_missing();
    blocked(&format!(
        "the live smoke test cannot run: {}",
        missing.join("; ")
    ));
}
