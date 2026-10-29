//! The `Scrub` seam over the factory's one redactor.
//!
//! What a redactor finds, and in which encodings, is tested where the redactor lives, in
//! `crates/domain/tests/redaction.rs`. These tests cover only the seam: that the redactor is the
//! one that runs, that its markers come through, that text without a secret is not copied, and that
//! a redactor that fails makes the seam fail instead of passing the text on.
//!
//! Every sample is assembled at run time from short pieces, so no string in this file looks like a
//! real credential to a repository secret scan.

mod common;

use common::{policy_patterns, policy_redactor};
use factory_domain::redaction::{Limits, Redactor};
use factory_observability::redact::{PLACEHOLDER_PREFIX, RedactorScrubber, Scrub, ScrubError};
use std::borrow::Cow;
use std::sync::Arc;

fn rep(c: char, n: usize) -> String {
    c.to_string().repeat(n)
}

fn scrubber() -> RedactorScrubber {
    RedactorScrubber::new(policy_redactor())
}

fn scrub(text: &str) -> String {
    scrubber()
        .scrub(text)
        .expect("the policy redactor does not fail on small input")
        .into_owned()
}

#[test]
fn a_policy_pattern_is_replaced_by_a_marker_that_names_it() {
    let token = format!("ghp_{}", rep('a', 36));
    assert_eq!(
        scrub(&format!("before {token} after")),
        "before [REDACTED:github_token_classic] after"
    );
    let header = format!("Authorization: Bearer {}", rep('p', 24));
    assert_eq!(scrub(&header), "[REDACTED:authorization_header]");
    let url = format!("{}://svc:{}@db.internal:5432", "postgres", "hunter22");
    assert_eq!(scrub(&url), "[REDACTED:url_with_credentials]");
    assert!(scrub(&token).starts_with(PLACEHOLDER_PREFIX));
}

#[test]
fn a_registered_value_is_replaced_by_its_label() {
    let redactor = policy_redactor();
    let value = ["not", "a", "pattern", "7Hq2"].join("-");
    redactor
        .register("webhook_secret", value.as_bytes())
        .expect("registers");
    let seam = RedactorScrubber::new(Arc::clone(&redactor));
    assert_eq!(
        seam.scrub(&format!("seen {value} here")).expect("scrubs"),
        "seen [REDACTED:webhook_secret] here"
    );
}

#[test]
fn a_value_registered_after_the_seam_was_built_is_found() {
    // The composition root builds the seam once, and the broker registers each job token later.
    let redactor = policy_redactor();
    let seam = RedactorScrubber::new(Arc::clone(&redactor));
    let value = ["late", "value", "Zk93", "wQ"].join("-");
    assert_eq!(seam.scrub(&value).expect("scrubs"), value.as_str());
    redactor
        .register("job_tokens", value.as_bytes())
        .expect("registers");
    assert_eq!(seam.scrub(&value).expect("scrubs"), "[REDACTED:job_tokens]");
}

#[test]
fn text_without_a_secret_is_returned_unchanged_and_without_a_copy() {
    let harmless = [
        "",
        "stage run 3 of 5 finished",
        "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77",
        "crates/workflow/src/engine.rs:120",
        "sk-short",
        "ghp_tooshort",
        "unicode: caf\u{e9} \u{1f980} \u{4e2d}\u{6587}",
        "factory.stage_run INTAKE",
    ];
    let seam = scrubber();
    for text in harmless {
        let output = seam.scrub(text).expect("no failure");
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "harmless text was copied or changed: {text:?} -> {output:?}"
        );
        assert_eq!(output, text);
    }
}

#[test]
fn a_secret_inside_a_json_line_is_removed_and_the_line_stays_well_formed() {
    let secret = format!("ghp_{}", rep('a', 36));
    let line = format!(r#"{{"level":"INFO","fields":{{"message":"got {secret} here"}}}}"#);
    let output = scrub(&line);
    assert_eq!(
        output,
        r#"{"level":"INFO","fields":{"message":"got [REDACTED:github_token_classic] here"}}"#
    );
    assert!(common::is_valid_json(&output));
}

#[test]
fn multi_byte_text_around_a_secret_does_not_break_the_cut() {
    let secret = format!("npm_{}", rep('j', 36));
    let output = scrub(&format!("caf\u{e9} {secret} \u{1f980}\u{1f980}"));
    assert_eq!(output, "caf\u{e9} [REDACTED:npm_token] \u{1f980}\u{1f980}");
}

#[test]
fn a_redactor_that_fails_makes_the_seam_fail() {
    let redactor = Redactor::builder()
        .patterns(policy_patterns())
        .limits(Limits {
            max_input_bytes: 16,
            ..Limits::default()
        })
        .build()
        .expect("builds");
    let seam = RedactorScrubber::new(Arc::new(redactor));
    let oversized = rep('x', 64);
    let result = seam.scrub(&oversized);
    assert_eq!(
        result,
        Err(ScrubError::Unavailable),
        "the text must not come back"
    );
    // Small input still works, so the failure is about the input and not the seam.
    assert!(seam.scrub("short").is_ok());
}

#[test]
fn the_debug_form_of_the_seam_shows_no_registered_value() {
    let redactor = policy_redactor();
    let value = ["debug", "form", "Pq81", "Lm"].join("-");
    redactor
        .register("broker_keys", value.as_bytes())
        .expect("registers");
    let seam = RedactorScrubber::new(redactor);
    let shown = format!("{seam:?}");
    assert!(!shown.contains(&value), "{shown}");
}

#[test]
fn scrubbing_twice_gives_the_same_result_as_scrubbing_once() {
    let token = format!("sfjt_{}", rep('r', 40));
    let once = scrub(&format!("x {token} y"));
    assert_eq!(scrub(&once), once);
}

#[test]
fn odd_input_never_panics() {
    let pieces = [
        "-----BEGIN ",
        "-----",
        "ghp_",
        "sk-",
        "eyJ",
        ".",
        "://",
        "@",
        ":",
        "=",
        "\"",
        "'",
        "\\",
        "password",
        "Authorization",
        "aws_secret",
        "\u{0}",
        "\u{e9}",
        "\u{1f980}",
        " ",
        "\n",
        "A",
        "9",
        "_",
        "-",
    ];
    // A fixed pseudo-random walk over the pieces, so the test is the same on every run.
    let seam = scrubber();
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    for _ in 0..1000 {
        let mut text = String::new();
        for _ in 0..12 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            text.push_str(pieces[(state % pieces.len() as u64) as usize]);
        }
        // Only that it returns, with a result of either kind.
        let _ = seam.scrub(&text);
    }
}
