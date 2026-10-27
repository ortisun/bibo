//! The scrubber removes the secret patterns that `policies/security.yaml` lists.
//!
//! Every sample is assembled at run time from short pieces, so no string in this file looks like a
//! real credential to a repository secret scan. The pieces keep the real format of each token.

use factory_observability::redact::{PolicyPatternScrubber, Scrub};

const POLICY: &str = include_str!("../../../policies/security.yaml");

fn rep(c: char, n: usize) -> String {
    c.to_string().repeat(n)
}

/// One fake secret per pattern id in the security policy, in the policy's order.
fn samples() -> Vec<(&'static str, String)> {
    vec![
        ("github_token_classic", format!("ghp_{}", rep('a', 36))),
        ("github_token_prefixed", format!("ghs_{}", rep('b', 40))),
        (
            "github_fine_grained",
            format!("github_pat_{}", rep('c', 30)),
        ),
        (
            "private_key_block",
            format!(
                "-----BEGIN {} KEY-----\n{}\n-----END {} KEY-----",
                "RSA PRIVATE",
                rep('d', 64),
                "RSA PRIVATE"
            ),
        ),
        ("anthropic_api_key", format!("sk-ant-{}", rep('e', 30))),
        ("openai_api_key", format!("sk-proj-{}", rep('f', 40))),
        ("aws_access_key_id", format!("AKIA{}", rep('Q', 16))),
        (
            "aws_secret_access_key",
            format!("aws_secret_access_key = {}", rep('g', 40)),
        ),
        ("gcp_api_key", format!("AIza{}", rep('h', 35))),
        ("slack_token", format!("xoxb-{}", rep('1', 12))),
        ("stripe_live_key", format!("sk_live_{}", rep('i', 24))),
        ("npm_token", format!("npm_{}", rep('j', 36))),
        ("pypi_token", format!("pypi-AgE{}", rep('k', 60))),
        ("crates_io_token", format!("cio{}", rep('l', 32))),
        (
            "jwt",
            format!("eyJ{}.eyJ{}.{}", rep('m', 12), rep('n', 12), rep('o', 12)),
        ),
        (
            "authorization_header",
            format!("Authorization: Bearer {}", rep('p', 24)),
        ),
        (
            "url_with_credentials",
            format!("{}://svc:{}@db.internal:5432", "postgres", "hunter22"),
        ),
        ("factory_job_token", format!("sfjt_{}", rep('r', 40))),
        (
            "nats_credentials",
            format!(
                "-----BEGIN NATS USER NKEY SEED-----\n{}\n------END NATS USER NKEY SEED------",
                rep('s', 40)
            ),
        ),
        ("generic_assignment", format!("password={}", rep('t', 16))),
    ]
}

fn scrub(text: &str) -> String {
    PolicyPatternScrubber::new()
        .scrub(text)
        .expect("the pattern scrubber does not fail")
        .into_owned()
}

fn policy_pattern_ids() -> Vec<String> {
    let block = POLICY
        .split("\nsecrets:\n")
        .nth(1)
        .expect("security.yaml has a secrets section")
        .split("entropy_heuristic:")
        .next()
        .expect("the patterns end at the entropy heuristic");
    block
        .lines()
        .filter(|line| line.contains("{ id: ") && line.contains("regex:"))
        .map(|line| {
            let after = line.split("{ id: ").nth(1).expect("an id follows");
            after
                .split(',')
                .next()
                .expect("a comma ends the id")
                .trim()
                .to_string()
        })
        .collect()
}

#[test]
fn the_scrubber_has_one_rule_for_every_pattern_in_the_security_policy() {
    let from_policy = policy_pattern_ids();
    assert!(
        from_policy.len() >= 20,
        "found only {} pattern ids in the policy; the test reader is broken",
        from_policy.len()
    );
    let from_code: Vec<String> = PolicyPatternScrubber::rule_ids()
        .iter()
        .map(|id| id.to_string())
        .collect();
    assert_eq!(
        from_code, from_policy,
        "the scrubber and policies/security.yaml list different patterns, or in a different order"
    );
}

#[test]
fn the_samples_cover_every_pattern_in_the_security_policy() {
    let from_samples: Vec<String> = samples().iter().map(|(id, _)| id.to_string()).collect();
    assert_eq!(from_samples, policy_pattern_ids());
}

#[test]
fn each_pattern_is_replaced_by_a_placeholder_that_names_it() {
    for (id, secret) in samples() {
        let input = format!("before {secret} after");
        let output = scrub(&input);
        assert_eq!(
            output,
            format!("before [REDACTED:{id}] after"),
            "pattern {id} was not replaced as expected"
        );
        assert!(
            !output.contains(&secret[secret.len() / 2..]),
            "pattern {id} leaked"
        );
    }
}

#[test]
fn a_secret_at_the_start_or_end_of_the_value_is_found() {
    for (id, secret) in samples() {
        assert_eq!(scrub(&secret), format!("[REDACTED:{id}]"), "alone: {id}");
        assert_eq!(
            scrub(&format!("{secret} tail")),
            format!("[REDACTED:{id}] tail"),
            "at the start: {id}"
        );
    }
}

#[test]
fn several_secrets_in_one_value_are_all_replaced() {
    let a = format!("ghp_{}", rep('a', 36));
    let b = format!("AKIA{}", rep('Q', 16));
    let output = scrub(&format!("first {a} second {b} end"));
    assert_eq!(
        output,
        "first [REDACTED:github_token_classic] second [REDACTED:aws_access_key_id] end"
    );
}

#[test]
fn a_private_key_is_removed_through_its_end_line_or_to_the_end_of_the_value() {
    let header = format!("-----BEGIN {} KEY-----", "PRIVATE");
    let body = rep('z', 80);
    assert_eq!(
        scrub(&format!("{header}\n{body}")),
        "[REDACTED:private_key_block]",
        "a key with no end line must still lose its body"
    );
    assert_eq!(
        scrub(&format!(
            "{header}{body}-----END {} KEY----- tail",
            "PRIVATE"
        )),
        "[REDACTED:private_key_block] tail"
    );
}

#[test]
fn text_without_secrets_is_returned_unchanged_and_without_a_copy() {
    let harmless = [
        "",
        "stage run 3 of 5 finished",
        "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "crates/workflow/src/engine.rs:120",
        "github_pat is the name of a token kind, not a token",
        "sk-short",
        "ghp_tooshort",
        "token_count=123456789012345",
        "unicode: caf\u{e9} \u{1f980} \u{4e2d}\u{6587}",
        "AKIA is a prefix",
        "factory.stage_run INTAKE",
    ];
    let scrubber = PolicyPatternScrubber::new();
    for text in harmless {
        let output = scrubber.scrub(text).expect("no failure");
        assert!(
            matches!(output, std::borrow::Cow::Borrowed(_)),
            "harmless text was copied or changed: {text:?} -> {output:?}"
        );
        assert_eq!(output, text);
    }
}

#[test]
fn scrubbing_twice_gives_the_same_result_as_scrubbing_once() {
    for (id, secret) in samples() {
        let once = scrub(&format!("x {secret} y"));
        assert_eq!(scrub(&once), once, "pattern {id} is not stable");
    }
}

#[test]
fn matching_is_case_insensitive_where_the_policy_asks_for_it() {
    let header = format!("authorization: bearer {}", rep('p', 24));
    assert_eq!(scrub(&header), "[REDACTED:authorization_header]");
    let assign = format!("API_KEY: \"{}\"", rep('t', 16));
    assert_eq!(scrub(&assign), "[REDACTED:generic_assignment]\"");
}

#[test]
fn a_short_assignment_value_is_not_treated_as_a_secret() {
    assert_eq!(scrub("password=short"), "password=short");
    assert_eq!(scrub("token: abc"), "token: abc");
}

#[test]
fn a_secret_inside_a_json_line_is_removed_and_the_line_stays_well_formed() {
    let secret = format!("ghp_{}", rep('a', 36));
    let line = format!(r#"{{"level":"INFO","fields":{{"message":"got {secret} here"}}}}"#);
    assert_eq!(
        scrub(&line),
        r#"{"level":"INFO","fields":{"message":"got [REDACTED:github_token_classic] here"}}"#
    );
}

#[test]
fn multi_byte_text_around_a_secret_does_not_break_the_cut() {
    let secret = format!("npm_{}", rep('j', 36));
    let output = scrub(&format!("caf\u{e9} {secret} \u{1f980}\u{1f980}"));
    assert_eq!(output, "caf\u{e9} [REDACTED:npm_token] \u{1f980}\u{1f980}");
    let url = format!("{}://u\u{e9}:p\u{e9}ss@h\u{e9}st\u{4e2d}", "https");
    assert_eq!(scrub(&url), "[REDACTED:url_with_credentials]");
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
    let mut state: u64 = 0x2545_f491_4f6c_dd1d;
    for _ in 0..3000 {
        let mut text = String::new();
        for _ in 0..12 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            text.push_str(pieces[(state % pieces.len() as u64) as usize]);
        }
        // Only that it returns. Every cut must land on a character boundary.
        let _ = scrub(&text);
    }
}
