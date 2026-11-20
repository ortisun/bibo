//! The canary sweeper of the test kit (FX-CANARY) as an independent judge of the secret redactor
//! of `factory-domain` (work package `s1-redaction`).
//!
//! The redactor and the sweeper are written separately and share no encoder, no reader of escape
//! sequences and no list of invisible characters. A canary is made when a test runs, in a real
//! format, and put through the redactor in every spelling the sweeper knows. The sweeper then
//! looks at what came out, in its raw and its stripped view and across chunk boundaries, and must
//! find nothing, not even the marker fragment `CANARY`.
//!
//! This file lives in the test kit because the dependency rules (`crates/domain` may not
//! dev-depend on the test kit) keep the domain crate's own tests from using the sweeper. The
//! domain crate's tests carry a second, separate leak check of their own.

use factory_domain::redaction::{
    Encoding, EntropySpec, PatternAction, PatternSpec, Redactor, RedactorBuilder,
};
use factory_testkit::fx::canary::{Canary, CanaryKind, CanarySet, Form, Sweeper};
use factory_testkit::fx::rng::FxRng;

const POLICY: &str = include_str!("../../../policies/security.yaml");

// ---- The policy patterns, read as text -------------------------------------------------------

fn single_quoted(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
                out.push('\'');
            } else {
                return out;
            }
        } else {
            out.push(c);
        }
    }
    panic!("a quoted scalar in the policy does not end");
}

fn policy_patterns() -> Vec<PatternSpec> {
    let secrets = POLICY
        .split("\nsecrets:\n")
        .nth(1)
        .expect("the policy has a secrets section");
    let block = secrets
        .split("  patterns:\n")
        .nth(1)
        .and_then(|rest| rest.split("  entropy_heuristic:").next())
        .expect("the secrets section lists patterns");
    block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("- { id: "))
        .map(|line| {
            let id = line
                .split("id: ")
                .nth(1)
                .and_then(|rest| rest.split(',').next())
                .expect("an id")
                .trim();
            let regex = single_quoted(line.split("regex: '").nth(1).expect("a regex"));
            let action = match line
                .rsplit("action: ")
                .next()
                .and_then(|rest| rest.split([',', ' ', '}']).next())
            {
                Some("block") => PatternAction::Block,
                _ => PatternAction::Flag,
            };
            PatternSpec::new(id, regex, action)
        })
        .collect()
}

fn builder() -> RedactorBuilder {
    Redactor::builder()
        .patterns(policy_patterns())
        .entropy(EntropySpec {
            min_length: 32,
            min_bits_per_char: 4.2,
            action: PatternAction::Flag,
        })
}

/// A redactor with the patterns of the policy and every canary registered.
fn redactor_for(canaries: &CanarySet) -> Redactor {
    let r = builder().build().expect("the policy patterns compile");
    for canary in canaries.iter() {
        r.register(canary.label(), canary.value())
            .expect("a canary can be registered");
    }
    r
}

/// A sweeper for the canaries. It also reports the bare marker `CANARY`, so a half-redacted
/// canary that leaves its first letters behind is a hit as well.
fn sweeper_for(canaries: &CanarySet) -> Sweeper {
    Sweeper::new(canaries)
}

fn redact_in_chunks(r: &Redactor, input: &[u8], size: usize) -> Vec<u8> {
    let mut stream = r.stream();
    let mut out = Vec::new();
    for chunk in input.chunks(size) {
        stream.push(chunk, &mut out).expect("the stream takes it");
    }
    stream.finish(&mut out).expect("the stream ends");
    out
}

/// Puts `separator` between the bytes of `text`.
fn interleave(text: &[u8], separator: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in text {
        out.push(*byte);
        out.extend_from_slice(separator);
    }
    out
}

// ---- The checks ------------------------------------------------------------------------------

#[test]
fn the_sweeper_finds_nothing_after_every_canary_in_every_form_is_redacted() {
    for seed in [1u64, 2, 3] {
        let canaries = CanarySet::generate_with(&mut FxRng::from_seed(seed));
        let r = redactor_for(&canaries);
        let sweeper = sweeper_for(&canaries);
        for canary in canaries.iter() {
            for form in Form::ALL {
                let Some(bytes) = form.encode(canary.value()) else {
                    continue;
                };
                let mut input = b"line before ".to_vec();
                input.extend_from_slice(&bytes);
                input.extend_from_slice(b" line after\n");

                let whole = r
                    .redact(&input)
                    .expect("redaction works")
                    .output
                    .into_owned();
                let hits = sweeper.scan("redacted output", &whole);
                assert!(
                    hits.is_empty(),
                    "seed {seed}: {} in form {form}: {:?}",
                    canary.label(),
                    hits.iter().map(ToString::to_string).collect::<Vec<_>>()
                );

                // The same through a stream, cut at awkward sizes, and swept across the cuts.
                for size in [1usize, 7, 64, 4093] {
                    let streamed = redact_in_chunks(&r, &input, size);
                    assert_eq!(
                        streamed,
                        whole,
                        "{} in form {form}, chunks of {size}",
                        canary.label()
                    );
                    let chunks: Vec<&[u8]> = streamed.chunks(size).collect();
                    let hits = sweeper.scan_chunks("streamed output", chunks);
                    assert!(
                        hits.is_empty(),
                        "{} in form {form}, chunks of {size}",
                        canary.label()
                    );
                }
            }
        }
    }
}

#[test]
fn the_sweeper_finds_nothing_when_the_forms_are_hidden_behind_colour_codes_and_invisible_text() {
    let canaries = CanarySet::generate_with(&mut FxRng::from_seed(11));
    let r = redactor_for(&canaries);
    let sweeper = sweeper_for(&canaries);
    let noises: [&[u8]; 4] = [
        b"\x1b[31m",
        b"\x1b[0m",
        "\u{200b}".as_bytes(),
        "\u{2060}".as_bytes(),
    ];
    for canary in canaries.iter() {
        for form in Form::ALL {
            let Some(bytes) = form.encode(canary.value()) else {
                continue;
            };
            for noise in noises {
                let mut input = b"x ".to_vec();
                input.extend_from_slice(&interleave(&bytes, noise));
                input.extend_from_slice(b" y");
                let out = r
                    .redact(&input)
                    .expect("redaction works")
                    .output
                    .into_owned();
                let hits = sweeper.scan("redacted output", &out);
                assert!(
                    hits.is_empty(),
                    "{} in form {form} with {noise:?}: {:?}",
                    canary.label(),
                    hits.iter().map(ToString::to_string).collect::<Vec<_>>()
                );
            }
        }
    }
}

#[test]
fn the_patterns_alone_catch_the_canaries_that_have_a_vendor_format() {
    let canaries = CanarySet::generate_with(&mut FxRng::from_seed(21));
    // Nothing is registered. Only the policy patterns work.
    let r = builder().build().expect("the policy patterns compile");
    let sweeper = sweeper_for(&canaries);
    let shaped = [
        CanaryKind::GithubInstallationToken,
        CanaryKind::AppPrivateKey,
        CanaryKind::ModelApiKey,
        CanaryKind::JobToken,
    ];
    for kind in shaped {
        let canary = canaries.get(kind);
        let input = format!("value {} end", canary.value());
        let out = r
            .redact(input.as_bytes())
            .expect("redaction works")
            .output
            .into_owned();
        let hits = sweeper.scan("pattern-only output", &out);
        assert!(hits.is_empty(), "{kind:?}: {hits:?}");
    }
}

/// Measures how fast the redactor reads a large log. Run it in a release build:
/// `cargo test --release -p factory-testkit --test redaction_oracle throughput -- --ignored --nocapture`.
/// The domain crate may not read a clock, so the measurement is made here. The floor it asserts
/// is low on purpose; the printed numbers are the point.
#[test]
#[ignore = "a speed measurement; run it in a release build"]
fn throughput_of_a_large_log_with_secrets_and_colour_codes_in_it() {
    let canaries = CanarySet::generate_with(&mut FxRng::from_seed(61));
    let r = redactor_for(&canaries);
    let secret = canaries
        .get(CanaryKind::DatabasePassword)
        .value()
        .to_owned();
    let token = canaries.get(CanaryKind::JobToken).value().to_owned();
    let line = "2026-10-27T12:00:00Z INFO worker claimed job 0192f3a4 stage=IMPLEMENTATION attempt=2 path=/workspace/src/lib.rs\n";
    let mut text = String::new();
    let mut n = 0u32;
    while text.len() < 64 << 20 {
        text.push_str(line);
        n += 1;
        if n.is_multiple_of(50) {
            text.push_str(&format!("password {secret} and {token}\n"));
        }
        if n.is_multiple_of(40) {
            text.push_str("\u{1b}[32mok\u{1b}[0m \u{200b}progress\n");
        }
    }
    let start = std::time::Instant::now();
    let mut stream = r.stream();
    let mut out = Vec::new();
    let mut written = 0usize;
    for chunk in text.as_bytes().chunks(65_536) {
        stream.push(chunk, &mut out).expect("the stream takes it");
        written += out.len();
        out.clear();
    }
    let report = stream.finish(&mut out).expect("the stream ends");
    let seconds = start.elapsed().as_secs_f64();
    let mb = text.len() as f64 / 1e6;
    println!(
        "{mb:.0} MB through a stream in {seconds:.2} s = {:.1} MB/s; {} replacements; {} bytes out",
        mb / seconds,
        report.replacements(),
        written + out.len()
    );
    assert!(mb / seconds > 2.0, "slower than 2 MB/s");

    let start = std::time::Instant::now();
    assert!(r.contains_secret(text.as_bytes()).expect("the check works"));
    println!(
        "contains_secret stops at the first secret in {:.4} s",
        start.elapsed().as_secs_f64()
    );
    let clean = text.replace(&secret, "x").replace(&token, "y");
    let start = std::time::Instant::now();
    assert!(
        !r.contains_secret(clean.as_bytes())
            .expect("the check works")
    );
    println!(
        "{:.0} MB with no secret scanned in {:.2} s",
        clean.len() as f64 / 1e6,
        start.elapsed().as_secs_f64()
    );
}

// ---- Control off: the judge can fail -----------------------------------------------------------

#[test]
fn control_off_a_redactor_with_no_registry_leaves_what_has_no_vendor_format() {
    let canaries = CanarySet::generate_with(&mut FxRng::from_seed(31));
    let r = builder().build().expect("the policy patterns compile");
    let sweeper = sweeper_for(&canaries);
    // A hex webhook secret, a password, a holdout string and another tenant's string have no
    // format the patterns know. Without the registry they come through, and the sweeper says so.
    for kind in [
        CanaryKind::WebhookSecret,
        CanaryKind::DatabasePassword,
        CanaryKind::HoldoutString,
        CanaryKind::SecondTenantString,
    ] {
        let canary = canaries.get(kind);
        let input = format!("value {} end", canary.value());
        let out = r
            .redact(input.as_bytes())
            .expect("redaction works")
            .output
            .into_owned();
        assert!(
            !sweeper.scan("unregistered output", &out).is_empty(),
            "{kind:?} should have come through"
        );
    }
}

#[test]
fn control_off_a_redactor_that_lacks_an_encoding_lets_that_spelling_through() {
    let without_hex: Vec<Encoding> = Encoding::ALL
        .into_iter()
        .filter(|e| !matches!(e, Encoding::HexLower | Encoding::HexUpper))
        .collect();
    let r = builder()
        .encodings(&without_hex)
        .build()
        .expect("the policy patterns compile");
    let canary = Canary::custom("job_secret", "Plain-Looking-Secret-Value-2026");
    r.register(canary.label(), canary.value())
        .expect("registered");
    let set = CanarySet::generate_with(&mut FxRng::from_seed(41)).with(canary.clone());
    let sweeper = sweeper_for(&set);
    // The registered value is a plain string, so no vendor pattern helps and only the registry
    // and its encodings decide.
    let hex = Form::HexLower.encode(canary.value()).expect("hex form");
    let raw = Form::Raw.encode(canary.value()).expect("raw form");
    let out_hex = r.redact(&hex).expect("redaction works").output.into_owned();
    let out_raw = r.redact(&raw).expect("redaction works").output.into_owned();
    assert!(
        !sweeper.scan("hex", &out_hex).is_empty(),
        "the hex spelling should come through"
    );
    assert!(
        sweeper.scan("raw", &out_raw).is_empty(),
        "the raw spelling is still caught"
    );
}

#[test]
fn control_off_a_naive_per_chunk_redactor_leaks_a_secret_cut_in_two() {
    let canaries = CanarySet::generate_with(&mut FxRng::from_seed(51));
    let r = redactor_for(&canaries);
    let sweeper = sweeper_for(&canaries);
    let canary = canaries.get(CanaryKind::DatabasePassword);
    let input = format!("value {} end", canary.value());
    let (first, second) = input.as_bytes().split_at(input.len() / 2);
    let mut naive = r
        .redact(first)
        .expect("redaction works")
        .output
        .into_owned();
    naive.extend_from_slice(r.redact(second).expect("redaction works").output.as_ref());
    assert!(
        !sweeper.scan("naive output", &naive).is_empty(),
        "a redactor with no memory between chunks should leak"
    );
    let streamed = redact_in_chunks(&r, input.as_bytes(), first.len());
    assert!(sweeper.scan("stream output", &streamed).is_empty());
}
