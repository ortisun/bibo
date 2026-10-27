//! Behaviour of the secret redactor, from the outside.
//!
//! The patterns come from `policies/security.yaml`, read here with `include_str!` and a small
//! text reader, so the tests and the redactor share one source and neither holds a copy.
//!
//! Every secret and every token is built when a test runs, from short pieces and a deterministic
//! random source. No line in this file looks like a credential to a repository secret scan, and
//! none is a real one.
//!
//! The leak checks do not reuse the encoders of the code under test. They go the other way: they
//! take the output and decode it in every way a reader could (remove escape sequences and invisible
//! characters, undo percent-encoding and JSON escapes, decode runs of hexadecimal and of base64 at
//! every alignment) and look for the secret in each result.

use std::borrow::Cow;
use std::sync::Arc;

use factory_domain::redaction::{
    BuildError, Encoding, EntropySpec, FindingSource, FlagHandling, Limits, PatternAction,
    PatternSpec, RedactStream, RedactionError, Redactor, RedactorBuilder, Registered,
    RegistryError, Report,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

const POLICY: &str = include_str!("../../../policies/security.yaml");

// ---- The policy, read as text ------------------------------------------------------------

struct Policy {
    patterns: Vec<PatternSpec>,
    entropy: EntropySpec,
    min_len: usize,
    encodings: Vec<Encoding>,
}

/// The text of a YAML single-quoted scalar, starting just after the opening quote. A doubled
/// quote stands for one quote.
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

fn pattern_from_line(line: &str) -> PatternSpec {
    let id = line
        .split("id: ")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .expect("the line has an id")
        .trim();
    let regex = single_quoted(line.split("regex: '").nth(1).expect("the line has a regex"));
    let action = line
        .rsplit("action: ")
        .next()
        .and_then(|rest| rest.split([',', ' ', '}']).next())
        .expect("the line has an action");
    let action = match action {
        "block" => PatternAction::Block,
        "flag" => PatternAction::Flag,
        other => panic!("unknown action {other}"),
    };
    PatternSpec::new(id, regex, action)
}

fn value_of<'a>(block: &'a str, key: &str) -> &'a str {
    block
        .lines()
        .find_map(|line| line.trim().strip_prefix(key))
        .unwrap_or_else(|| panic!("the policy has no {key}"))
        .split('#')
        .next()
        .expect("split always gives one piece")
        .trim()
}

fn policy() -> Policy {
    let secrets = POLICY
        .split("\nsecrets:\n")
        .nth(1)
        .expect("the policy has a secrets section");
    let patterns_block = secrets
        .split("  patterns:\n")
        .nth(1)
        .and_then(|rest| rest.split("  entropy_heuristic:").next())
        .expect("the secrets section lists patterns");
    let patterns: Vec<PatternSpec> = patterns_block
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("- { id: "))
        .map(pattern_from_line)
        .collect();
    assert!(
        patterns.len() >= 20,
        "the policy reader found too few patterns"
    );

    let entropy_block = secrets
        .split("  entropy_heuristic:\n")
        .nth(1)
        .and_then(|rest| rest.split("  exact_values:").next())
        .expect("the secrets section has the entropy heuristic");
    let entropy = EntropySpec {
        min_length: value_of(entropy_block, "min_length:")
            .parse()
            .expect("a number"),
        min_bits_per_char: value_of(entropy_block, "min_shannon_bits_per_char:")
            .parse()
            .expect("a number"),
        action: match value_of(entropy_block, "action:") {
            "flag" => PatternAction::Flag,
            "block" => PatternAction::Block,
            other => panic!("unknown action {other}"),
        },
    };

    let exact_block = secrets
        .split("  exact_values:\n")
        .nth(1)
        .and_then(|rest| rest.split("  sinks:").next())
        .expect("the secrets section has exact values");
    let encodings = value_of(exact_block, "encodings:")
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|name| {
            Encoding::from_policy_name(name.trim())
                .unwrap_or_else(|| panic!("unknown encoding {name}"))
        })
        .collect();
    Policy {
        patterns,
        entropy,
        min_len: value_of(exact_block, "min_length:")
            .parse()
            .expect("a number"),
        encodings,
    }
}

fn builder() -> RedactorBuilder {
    let p = policy();
    Redactor::builder()
        .patterns(p.patterns)
        .entropy(p.entropy)
        .exact_value_min_len(p.min_len)
        .encodings(&p.encodings)
}

fn redactor() -> Redactor {
    builder().build().expect("the policy patterns compile")
}

fn redactor_with(secrets: &[(&str, &str)]) -> Redactor {
    let r = redactor();
    for (label, value) in secrets {
        assert!(matches!(
            r.register(label, value).expect("registered"),
            Registered::Added(_)
        ));
    }
    r
}

// ---- Run-time secrets --------------------------------------------------------------------

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn string(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| char::from(alphabet[self.below(alphabet.len())]))
            .collect()
    }
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Punctuation that every encoding treats differently.
const AWKWARD: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#%&*+=/?:;\"\\<>~ ";

/// A fake secret with punctuation inside and plain letters at both ends.
fn fake_secret(rng: &mut Rng, len: usize) -> String {
    let middle = rng.string(AWKWARD, len - 2);
    format!("{}{}{}", rng.string(ALNUM, 1), middle, rng.string(ALNUM, 1))
}

/// A twelve byte secret, made from pieces so that no literal here looks like one to a scan.
fn short_secret() -> String {
    ["kJ4m", "P9xQ", "2vL7"].concat()
}

fn rep(c: char, n: usize) -> String {
    c.to_string().repeat(n)
}

// ---- The independent leak check ----------------------------------------------------------

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Removes escape sequences and invisible characters, written independently of the code under
/// test: it reads text, not bytes, and knows the sequences by their first two characters.
fn strip_noise(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.next() {
                Some('[') => {
                    for n in chars.by_ref() {
                        if ('@'..='~').contains(&n) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    while let Some(n) = chars.next() {
                        if n == '\u{7}' || (n == '\u{1b}' && chars.peek() == Some(&'\\')) {
                            if n == '\u{1b}' {
                                chars.next();
                            }
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\u{200b}'..='\u{200f}'
            | '\u{2060}'..='\u{2064}'
            | '\u{feff}'
            | '\u{ad}'
            | '\u{202a}'..='\u{202e}' => {}
            c => out.push(c),
        }
    }
    out.into_bytes()
}

fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2]))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
        } else {
            out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
            i += 1;
        }
    }
    out
}

fn json_unescape(bytes: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('u') => {
                let digits: String = chars.by_ref().take(4).collect();
                if let Some(ch) = u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(ch);
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out.into_bytes()
}

/// Decodes every run of hexadecimal digits, from either alignment.
fn hex_decodes(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    for run in bytes.split(|b| !b.is_ascii_hexdigit()) {
        for skip in 0..2 {
            let digits = run.get(skip..).unwrap_or(&[]);
            let decoded: Vec<u8> = digits
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[high, low]| {
                    let h = char::from(*high).to_digit(16).unwrap();
                    let l = char::from(*low).to_digit(16).unwrap();
                    (h * 16 + l) as u8
                })
                .collect();
            found.push(decoded);
        }
    }
    found
}

/// Decodes every run of base64 letters from each of the four possible alignments, accepting both
/// alphabets at once.
fn base64_decodes(bytes: &[u8]) -> Vec<Vec<u8>> {
    let value = |b: u8| match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    };
    let mut found = Vec::new();
    for run in bytes.split(|b| value(*b).is_none()) {
        for skip in 0..4 {
            let mut bits = 0u32;
            let mut have = 0;
            let mut decoded = Vec::new();
            for &b in run.get(skip..).unwrap_or(&[]) {
                bits = (bits << 6) | u32::from(value(b).unwrap());
                have += 6;
                if have >= 8 {
                    have -= 8;
                    decoded.push((bits >> have) as u8);
                    bits &= (1 << have) - 1;
                }
            }
            found.push(decoded);
        }
    }
    found
}

fn every_view(output: &[u8]) -> Vec<Vec<u8>> {
    let mut views = Vec::new();
    for base in [output.to_vec(), strip_noise(output)] {
        views.push(percent_decode(&base));
        views.push(json_unescape(&base));
        views.extend(hex_decodes(&base));
        views.extend(base64_decodes(&base));
        views.push(base);
    }
    views
}

/// Fails when any ten byte stretch of `secret` appears in any decoding of `output`. Ten bytes,
/// and not the whole secret, so that a partial leak is a failure too.
fn assert_no_leak(output: &[u8], secret: &str, context: &str) {
    if let Some(view) = find_leak(output, secret) {
        panic!(
            "{context}: a stretch of the secret survived (view {view}) in {:?}",
            String::from_utf8_lossy(output)
        );
    }
}

/// The number of the first decoding of `output` that holds a ten byte stretch of `secret`.
fn find_leak(output: &[u8], secret: &str) -> Option<usize> {
    let window = 10.min(secret.len());
    let views = every_view(output);
    for piece in secret.as_bytes().windows(window) {
        for (n, view) in views.iter().enumerate() {
            if contains(view, piece) {
                return Some(n);
            }
        }
    }
    None
}

// ---- Independent encoders for the leaks ---------------------------------------------------

fn base64(bytes: &[u8], url: bool, pad: bool) -> String {
    let alphabet: &[u8] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut bits: String = bytes.iter().map(|b| format!("{b:08b}")).collect();
    while !bits.len().is_multiple_of(6) {
        bits.push('0');
    }
    let mut out: String = bits
        .as_bytes()
        .chunks(6)
        .map(|six| {
            let n = usize::from_str_radix(std::str::from_utf8(six).unwrap(), 2).unwrap();
            char::from(alphabet[n])
        })
        .collect();
    while pad && !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

fn hex(bytes: &[u8], upper: bool) -> String {
    bytes
        .iter()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
}

fn percent(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn json(text: &str) -> String {
    let quoted = serde_json::to_string(text).unwrap();
    quoted[1..quoted.len() - 1].to_owned()
}

/// Every spelling of `secret` that the tests plant, with a name for failure messages.
fn leaks_of(secret: &str) -> Vec<(String, String)> {
    let bytes = secret.as_bytes();
    let mut forms = vec![
        ("raw".to_owned(), secret.to_owned()),
        ("base64".to_owned(), base64(bytes, false, true)),
        ("base64 no padding".to_owned(), base64(bytes, false, false)),
        ("base64url".to_owned(), base64(bytes, true, true)),
        (
            "base64url no padding".to_owned(),
            base64(bytes, true, false),
        ),
        ("hex".to_owned(), hex(bytes, false)),
        ("HEX".to_owned(), hex(bytes, true)),
        ("percent".to_owned(), percent(bytes)),
        ("json".to_owned(), json(secret)),
    ];
    // The secret inside a longer base64 message, at each of the three alignments.
    for (prefix, name) in [
        ("", "0"),
        ("u", "1"),
        ("us", "2"),
        ("use", "0 again"),
        ("user:", "2 basic"),
    ] {
        for url in [false, true] {
            let mut message = prefix.as_bytes().to_vec();
            message.extend_from_slice(bytes);
            message.extend_from_slice(b"-trailing text");
            forms.push((
                format!(
                    "base64{} inside, offset {name}",
                    if url { "url" } else { "" }
                ),
                base64(&message, url, true),
            ));
        }
    }
    forms
}

// ---- Helpers for running the redactor ------------------------------------------------------

fn redact(r: &Redactor, input: &[u8]) -> Vec<u8> {
    r.redact(input)
        .expect("redaction works")
        .output
        .into_owned()
}

fn redact_text(r: &Redactor, input: &str) -> String {
    String::from_utf8(redact(r, input.as_bytes())).expect("the output is text")
}

/// Pushes the input through a stream in chunks of the given sizes (cycled).
fn stream_with(r: &Redactor, input: &[u8], sizes: &[usize]) -> (Vec<u8>, Report) {
    let mut stream = r.stream();
    let mut out = Vec::new();
    let mut rest = input;
    let mut i = 0;
    while !rest.is_empty() {
        let n = sizes[i % sizes.len()].max(1).min(rest.len());
        stream
            .push(&rest[..n], &mut out)
            .expect("the stream accepts the chunk");
        rest = &rest[n..];
        i += 1;
    }
    let report = stream.finish(&mut out).expect("the stream finishes");
    (out, report)
}

// ===== Patterns =====================================================================================

/// A positive sample and some near misses for every pattern of the policy, in the order of the
/// policy. Built from pieces so that no literal here looks like a credential.
struct Sample {
    id: &'static str,
    positive: String,
    negatives: Vec<String>,
}

fn samples() -> Vec<Sample> {
    let pem = |label: &str, body: char| {
        format!(
            "-----BEGIN {label}-----\n{}\n{}\n-----END {label}-----",
            rep(body, 64),
            rep(body, 32)
        )
    };
    let s = |id, positive: String, negatives: Vec<String>| Sample {
        id,
        positive,
        negatives,
    };
    vec![
        s(
            "github_token_classic",
            format!("ghp_{}", rep('a', 36)),
            vec![
                format!("ghp_{}", rep('a', 35)),
                format!("ghp-{}", rep('a', 36)),
                format!("x{}ghp_{}", "x", rep('a', 36)),
            ],
        ),
        s(
            "github_token_prefixed",
            format!("ghs_{}", rep('b', 40)),
            vec![
                format!("ghx_{}", rep('b', 40)),
                format!("ghs_{}", rep('b', 35)),
            ],
        ),
        s(
            "github_fine_grained",
            format!("github_pat_{}", rep('c', 30)),
            vec![format!("github_pat_{}", rep('c', 10))],
        ),
        s(
            "private_key_block",
            pem("RSA PRIVATE KEY", 'd'),
            vec![pem("PUBLIC KEY", 'd'), pem("CERTIFICATE", 'd')],
        ),
        s(
            "anthropic_api_key",
            format!("sk-ant-{}", rep('e', 30)),
            vec![format!("sk-ant-{}", rep('e', 5))],
        ),
        s(
            "openai_api_key",
            format!("sk-proj-{}", rep('f', 40)),
            vec![
                format!("sk-{}", rep('f', 10)),
                format!("task-{}", rep('f', 40)),
            ],
        ),
        s(
            "aws_access_key_id",
            format!("AKIA{}", rep('Q', 16)),
            vec![
                format!("AKIA{}", rep('Q', 15)),
                format!("akia{}", rep('q', 16)),
            ],
        ),
        s(
            "aws_secret_access_key",
            format!("aws_secret_access_key = {}", rep('g', 40)),
            vec![format!("aws_secret_access_key = {}", rep('g', 10))],
        ),
        s(
            "gcp_api_key",
            format!("AIza{}", rep('h', 35)),
            vec![format!("AIza{}", rep('h', 10))],
        ),
        s(
            "slack_token",
            format!("xoxb-{}", rep('1', 12)),
            vec![
                format!("xoxz-{}", rep('1', 12)),
                format!("xoxb-{}", rep('1', 3)),
            ],
        ),
        s(
            "stripe_live_key",
            format!("sk_live_{}", rep('i', 24)),
            vec![
                format!("sk_test_{}", rep('i', 24)),
                format!("sk_live_{}", rep('i', 5)),
            ],
        ),
        s(
            "npm_token",
            format!("npm_{}", rep('j', 36)),
            vec![format!("npm_{}", rep('j', 10))],
        ),
        s(
            "pypi_token",
            format!("pypi-AgE{}", rep('k', 60)),
            vec![format!("pypi-AgE{}", rep('k', 10))],
        ),
        s(
            "crates_io_token",
            format!("cio{}", rep('l', 32)),
            vec![format!("cio{}", rep('l', 10))],
        ),
        s(
            "jwt",
            format!("eyJ{}.eyJ{}.{}", rep('m', 12), rep('n', 12), rep('o', 12)),
            vec![
                format!("eyJ{}.eyJ{}", rep('m', 12), rep('n', 12)),
                "eyJ.eyJ.x".to_owned(),
            ],
        ),
        s(
            "authorization_header",
            format!("Authorization: Bearer {}", rep('p', 24)),
            vec![format!("Authorization: Bearer {}", rep('p', 5))],
        ),
        s(
            "url_with_credentials",
            format!("{}://svc:{}@db.internal:5432", "postgres", "hunter22"),
            vec![
                format!("{}://db.internal:5432/path", "postgres"),
                format!("{}://example.test/a:b@c", "https"),
            ],
        ),
        s(
            "factory_job_token",
            format!("sfjt_{}", rep('r', 40)),
            vec![format!("sfjt_{}", rep('r', 10))],
        ),
        s(
            "nats_credentials",
            pem("NATS USER NKEY SEED", 's'),
            vec![pem("NATS UNKNOWN THING", 's')],
        ),
        s(
            "generic_assignment",
            format!("password={}", rep('t', 16)),
            vec![
                "password=short".to_owned(),
                "the password was reset yesterday".to_owned(),
                format!("token_count={}", rep('9', 16)),
            ],
        ),
    ]
}

#[test]
fn patterns_the_samples_cover_every_pattern_of_the_policy_in_order() {
    let from_policy: Vec<String> = policy().patterns.iter().map(|p| p.id.clone()).collect();
    let from_samples: Vec<&str> = samples().iter().map(|s| s.id).collect();
    assert_eq!(from_samples, from_policy);
}

#[test]
fn patterns_all_compile_in_the_regex_dialect() {
    let r = redactor();
    assert_eq!(r.pattern_ids().len(), policy().patterns.len());
}

/// Judges a redactor by the positive samples: what the samples of each pattern do to it.
fn positive_failures(r: &Redactor) -> Vec<String> {
    let actions: std::collections::HashMap<String, PatternAction> = policy()
        .patterns
        .into_iter()
        .map(|p| (p.id, p.action))
        .collect();
    let mut failures = Vec::new();
    for sample in samples() {
        let input = format!("before {} after", sample.positive);
        let out = match r.redact(input.as_bytes()) {
            Ok(out) => out,
            Err(e) => {
                failures.push(format!("{}: {e}", sample.id));
                continue;
            }
        };
        let text = String::from_utf8_lossy(&out.output).into_owned();
        match actions[sample.id] {
            PatternAction::Block => {
                if text != format!("before [REDACTED:{}] after", sample.id) {
                    failures.push(format!("{}: the sample came out as {text:?}", sample.id));
                } else if !out.report.has_blocking() || !out.report.ids().any(|i| i == sample.id) {
                    failures.push(format!("{}: the report does not name it", sample.id));
                } else {
                    let finding = &out.report.findings()[0];
                    if (finding.start, finding.end) != (7, 7 + sample.positive.len() as u64) {
                        failures.push(format!("{}: wrong offsets", sample.id));
                    }
                }
            }
            PatternAction::Flag => {
                let flagged = out.report.has_flagged() && !out.report.has_blocking();
                if text != input || !flagged || !out.report.ids().any(|i| i == sample.id) {
                    failures.push(format!(
                        "{}: a flag must leave the text and say so",
                        sample.id
                    ));
                }
            }
        }
    }
    failures
}

/// Judges a redactor by the near misses: none of them may be touched or counted as a secret.
fn negative_failures(r: &Redactor) -> Vec<String> {
    let mut failures = Vec::new();
    for sample in samples() {
        for negative in &sample.negatives {
            let input = format!("before {negative} after");
            let out = r.redact(input.as_bytes()).unwrap();
            if String::from_utf8_lossy(&out.output) != input
                || out.report.has_blocking()
                || r.contains_secret(input.as_bytes()).unwrap()
            {
                failures.push(format!(
                    "{}: {negative:?} was taken for a secret",
                    sample.id
                ));
            }
        }
    }
    failures
}

#[test]
fn patterns_redact_their_positive_samples() {
    assert_eq!(positive_failures(&redactor()), Vec::<String>::new());
}

#[test]
fn patterns_ignore_their_negative_samples() {
    assert_eq!(negative_failures(&redactor()), Vec::<String>::new());
}

#[test]
fn patterns_match_at_the_start_and_the_end_of_the_input() {
    let r = redactor();
    for sample in samples().iter().filter(|s| s.id != "generic_assignment") {
        assert_eq!(
            redact_text(&r, &sample.positive),
            format!("[REDACTED:{}]", sample.id),
            "pattern {}",
            sample.id
        );
    }
}

#[test]
fn patterns_that_the_policy_marks_flag_are_never_blocking() {
    let r = redactor();
    let input = format!("password={}", rep('t', 16));
    assert!(!r.contains_secret(input.as_bytes()).unwrap());
    let report = r.scan(input.as_bytes()).unwrap();
    assert!(report.has_flagged() && !report.has_blocking());
}

#[test]
fn patterns_report_the_label_of_the_earliest_longest_match_when_two_patterns_overlap() {
    let r = redactor();
    // The same bytes match the Anthropic and the OpenAI pattern. The Anthropic pattern comes
    // first in the policy, so the marker names it, and the report still lists both.
    let token = format!("sk-ant-{}", rep('e', 30));
    let out = r.redact(token.as_bytes()).unwrap();
    assert_eq!(out.output.as_ref(), b"[REDACTED:anthropic_api_key]");
    let ids: Vec<&str> = out.report.ids().collect();
    assert!(
        ids.contains(&"anthropic_api_key") && ids.contains(&"openai_api_key"),
        "{ids:?}"
    );
}

// ===== NT-SEC-02: redaction evasion ==================================================================

/// Puts `separator` between every pair of characters of `text`.
fn interleave(text: &str, separator: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        out.push(c);
        out.push_str(separator);
    }
    out
}

fn a_registered_secret_and_a_pattern_token() -> (Redactor, String, String) {
    let mut rng = Rng::new(0x5eed_0001);
    let secret = fake_secret(&mut rng, 36);
    let token = format!("ghp_{}", rng.string(ALNUM, 36));
    let r = redactor_with(&[("webhook_secret", &secret)]);
    (r, secret, token)
}

#[test]
fn negative_nt_sec_02_a_token_split_over_two_writes_is_redacted() {
    let (r, secret, token) = a_registered_secret_and_a_pattern_token();
    for (what, value) in [("registered secret", &secret), ("pattern token", &token)] {
        let line = format!("value: {value} end");
        let reference = redact(&r, line.as_bytes());
        assert_no_leak(&reference, value, what);
        // Every position at which the text can be cut in two.
        for cut in 0..=line.len() {
            let (first, second) = line.as_bytes().split_at(cut);
            let mut stream = r.stream();
            let mut out = Vec::new();
            stream.push(first, &mut out).unwrap();
            stream.push(second, &mut out).unwrap();
            stream.finish(&mut out).unwrap();
            assert_eq!(out, reference, "{what}, cut at {cut}");
        }
    }
}

#[test]
fn negative_nt_sec_02_terminal_codes_between_the_characters_do_not_hide_a_token() {
    let (r, secret, token) = a_registered_secret_and_a_pattern_token();
    for (what, value) in [("registered secret", &secret), ("pattern token", &token)] {
        for code in [
            "\u{1b}[31m",
            "\u{1b}[0m",
            "\u{1b}[38;2;1;2;3m",
            "\u{1b}]0;title\u{7}",
            "\u{1b}]8;;x\u{1b}\\",
        ] {
            let input = format!("value: {} end", interleave(value, code));
            let out = redact(&r, input.as_bytes());
            assert_no_leak(&out, value, &format!("{what} with {code:?}"));
            assert!(
                String::from_utf8_lossy(&out).contains("[REDACTED:"),
                "{what} with {code:?}: no marker in {:?}",
                String::from_utf8_lossy(&out)
            );
        }
    }
}

#[test]
fn negative_nt_sec_02_a_coloured_token_is_redacted() {
    let (r, _, token) = a_registered_secret_and_a_pattern_token();
    // The colour code ends in a letter that sits right before the token, so the raw bytes have
    // no word boundary before it. A reader sees a clean token after the space.
    let input = format!("key: \u{1b}[31m{token}\u{1b}[0m done");
    let out = redact(&r, input.as_bytes());
    assert_no_leak(&out, &token, "coloured token");
}

#[test]
fn negative_nt_sec_02_zero_width_characters_between_the_characters_do_not_hide_a_token() {
    let (r, secret, token) = a_registered_secret_and_a_pattern_token();
    for (what, value) in [("registered secret", &secret), ("pattern token", &token)] {
        for invisible in [
            "\u{200b}",
            "\u{200c}",
            "\u{200d}",
            "\u{2060}",
            "\u{feff}",
            "\u{ad}",
            "\u{202e}",
            "\u{fe0f}",
            "\u{e0041}",
        ] {
            let input = format!("value: {} end", interleave(value, invisible));
            let out = redact(&r, input.as_bytes());
            assert_no_leak(&out, value, &format!("{what} with {invisible:?}"));
        }
    }
}

#[test]
fn negative_nt_sec_02_every_encoding_of_a_registered_secret_is_redacted() {
    let mut rng = Rng::new(0x5eed_0002);
    for round in 0..6 {
        let secret = fake_secret(&mut rng, 20 + round * 7);
        let r = redactor_with(&[("database_password", &secret)]);
        for (name, leak) in leaks_of(&secret) {
            let input = format!("log: {leak} end");
            let out = redact(&r, input.as_bytes());
            assert_no_leak(&out, &secret, &format!("secret {round}, {name}"));
        }
    }
}

#[test]
fn negative_nt_sec_02_encodings_mixed_with_invisible_characters_are_redacted() {
    let mut rng = Rng::new(0x5eed_0003);
    let secret = fake_secret(&mut rng, 30);
    let r = redactor_with(&[("database_password", &secret)]);
    for (name, leak) in leaks_of(&secret) {
        let input = format!("log: {} end", interleave(&leak, "\u{200b}"));
        let out = redact(&r, input.as_bytes());
        assert_no_leak(&out, &secret, &format!("{name} with zero-width spaces"));
        let input = format!("log: {} end", interleave(&leak, "\u{1b}[0m"));
        let out = redact(&r, input.as_bytes());
        assert_no_leak(&out, &secret, &format!("{name} with colour codes"));
    }
}

#[test]
fn negative_nt_sec_02_an_unknown_random_string_is_flagged_and_not_blocked() {
    let r = redactor();
    let mut rng = Rng::new(0x5eed_0004);
    let random = rng.string(ALNUM, 40);
    let input = format!("value {random} end");
    let out = r.redact(input.as_bytes()).unwrap();
    assert_eq!(
        out.output.as_ref(),
        input.as_bytes(),
        "a flag leaves the text alone"
    );
    assert!(out.report.has_flagged() && !out.report.has_blocking());
    assert!(
        out.report
            .findings()
            .iter()
            .any(|f| f.source == FindingSource::Entropy)
    );
    assert!(!r.contains_secret(input.as_bytes()).unwrap());
}

#[test]
fn negative_nt_sec_02_ordinary_text_with_the_word_password_is_untouched() {
    let r = redactor();
    for text in [
        "Please reset your password before Friday.",
        "the password field is required",
        "password: ***",
        "password=",
        "a token of appreciation",
        "secret santa lists: alice, bob and carol exchange gifts on the 24th",
    ] {
        let out = r.redact(text.as_bytes()).unwrap();
        assert_eq!(out.output.as_ref(), text.as_bytes());
        assert!(out.report.is_clean(), "{text:?}: {:?}", out.report);
    }
}

// ===== The exact-value registry ======================================================================

#[test]
fn registry_a_value_shorter_than_the_minimum_is_not_registered() {
    let r = redactor();
    assert_eq!(r.register("x", "1234567").unwrap(), Registered::TooShort);
    assert!(matches!(
        r.register("x", "12345678").unwrap(),
        Registered::Added(_)
    ));
    assert_eq!(r.registered_count(), 1);
    assert_eq!(redact_text(&r, "a 1234567 b"), "a 1234567 b");
}

#[test]
fn registry_a_forgotten_value_is_no_longer_redacted() {
    let r = redactor();
    let mut rng = Rng::new(0x5eed_0005);
    let secret = fake_secret(&mut rng, 24);
    let Registered::Added(handle) = r.register("job_token", &secret).unwrap() else {
        panic!("registered");
    };
    assert_eq!(
        redact_text(&r, &format!("[{secret}]")),
        "[[REDACTED:job_token]]"
    );
    assert!(r.forget(handle));
    assert!(!r.forget(handle), "a handle works once");
    assert_eq!(r.registered_count(), 0);
    assert_eq!(
        redact_text(&r, &format!("[{secret}]")),
        format!("[{secret}]")
    );
}

#[test]
fn registry_registering_the_same_value_twice_gives_one_entry() {
    let r = redactor();
    let a = r.register("job_token", "abcdefghijkl").unwrap();
    let b = r.register("job_token", "abcdefghijkl").unwrap();
    assert_eq!(a, b);
    assert_eq!(r.registered_count(), 1);
}

#[test]
fn registry_a_label_must_be_usable_inside_a_marker() {
    let r = redactor();
    for bad in [
        "",
        "has space",
        "has]bracket",
        "[REDACTED:x",
        "a/b",
        "line\nbreak",
        &"a".repeat(65),
    ] {
        assert_eq!(
            r.register(bad, "abcdefghijkl"),
            Err(RegistryError::InvalidLabel {
                label: bad.to_owned()
            })
        );
    }
    assert!(r.register("ok_label-1.x", "abcdefghijkl").is_ok());
}

#[test]
fn registry_limits_are_enforced_and_say_so() {
    let r = builder()
        .limits(Limits {
            max_registry_values: 2,
            max_value_len: 16,
            ..Limits::default()
        })
        .build()
        .unwrap();
    assert_eq!(
        r.register("a", "x".repeat(17)),
        Err(RegistryError::ValueTooLong { max: 16 })
    );
    r.register("a", "1111111111").unwrap();
    r.register("a", "2222222222").unwrap();
    assert_eq!(
        r.register("a", "3333333333"),
        Err(RegistryError::TooManyValues { max: 2 })
    );
}

#[test]
fn registry_a_multi_line_secret_is_redacted_one_line_at_a_time_too() {
    let mut rng = Rng::new(0x5eed_0006);
    let lines: Vec<String> = (0..4).map(|_| rng.string(ALNUM, 40)).collect();
    let key = format!("{}\n", lines.join("\n"));
    let r = redactor_with(&[("app_private_key", &key)]);
    for line in &lines {
        let out = redact_text(&r, &format!("log: {line} end"));
        assert_no_leak(out.as_bytes(), line, "one line of a key");
    }
    // The value with its trailing newline trimmed is found as well.
    let out = redact_text(&r, &format!("log: {} end", key.trim_end()));
    assert_eq!(out, "log: [REDACTED:app_private_key] end");
}

#[test]
fn registry_a_secret_is_found_anywhere_in_a_word_with_no_boundary_needed() {
    let value = short_secret();
    let r = redactor_with(&[("webhook_secret", &value)]);
    assert_eq!(
        redact_text(&r, &format!("prefix{value}suffix")),
        "prefix[REDACTED:webhook_secret]suffix"
    );
}

#[test]
fn registry_two_secrets_that_share_text_are_both_redacted() {
    let r = redactor_with(&[("a", "sharedprefix-AAAA-1"), ("b", "AAAA-1-sharedsuffix")]);
    let out = redact_text(&r, "x sharedprefix-AAAA-1-sharedsuffix y");
    assert_eq!(out, "x [REDACTED:a] y");
    assert!(!out.contains("sharedsuffix"));
}

// ===== Overlap and merging ===========================================================================

#[test]
fn overlapping_matches_become_one_marker_that_covers_all_of_them() {
    let mut rng = Rng::new(0x5eed_0007);
    let secret = format!("ghp_{}", rng.string(ALNUM, 36));
    let r = redactor_with(&[("job_token", &secret[2..30])]);
    // The registered text sits inside a token that a pattern also matches.
    let out = redact_text(&r, &format!("t={secret}!"));
    assert_eq!(out, "t=[REDACTED:github_token_classic]!");
}

#[test]
fn matches_that_only_touch_stay_separate() {
    let r = redactor_with(&[("a", "AAAAAAAAAA1"), ("b", "BBBBBBBBBB2")]);
    assert_eq!(
        redact_text(&r, "AAAAAAAAAA1BBBBBBBBBB2"),
        "[REDACTED:a][REDACTED:b]"
    );
}

#[test]
fn the_marker_names_the_earliest_longest_match_whatever_order_they_were_found_in() {
    let r = redactor_with(&[("inner", "KKKKKKKK9999"), ("outer", "xx-KKKKKKKK9999-yy")]);
    assert_eq!(
        redact_text(&r, "<xx-KKKKKKKK9999-yy>"),
        "<[REDACTED:outer]>"
    );
}

#[test]
fn the_report_lists_each_finding_once_with_its_offsets() {
    let r = redactor_with(&[("job_token", "abcdefghijkl")]);
    let out = r.redact(b"..abcdefghijkl..abcdefghijkl").unwrap();
    let spans: Vec<(u64, u64)> = out
        .report
        .findings()
        .iter()
        .map(|f| (f.start, f.end))
        .collect();
    assert_eq!(spans, vec![(2, 14), (16, 28)]);
    assert_eq!(out.report.replacements(), 2);
}

// ===== Streaming =====================================================================================

fn a_text_with_secrets() -> (Redactor, Vec<u8>) {
    let mut rng = Rng::new(0x5eed_0008);
    let secret = fake_secret(&mut rng, 32);
    let token = format!("ghp_{}", rng.string(ALNUM, 36));
    let r = redactor_with(&[("webhook_secret", &secret)]);
    let text = format!(
        "start {secret} then {token} and \u{1b}[31m{}\u{1b}[0m plus {} and {} end\n{}",
        interleave(&token, "\u{200b}"),
        base64(secret.as_bytes(), true, false),
        hex(secret.as_bytes(), true),
        "plain filler text. ".repeat(40)
    );
    (r, text.into_bytes())
}

#[test]
fn streaming_every_way_of_cutting_the_input_in_two_gives_the_one_shot_result() {
    let (r, text) = a_text_with_secrets();
    let reference = r.redact(&text).unwrap();
    for cut in 0..=text.len() {
        let (first, second) = text.split_at(cut);
        let mut stream = r.stream();
        let mut out = Vec::new();
        stream.push(first, &mut out).unwrap();
        stream.push(second, &mut out).unwrap();
        let report = stream.finish(&mut out).unwrap();
        assert_eq!(out, reference.output.as_ref(), "cut at {cut}");
        assert_eq!(report, reference.report, "cut at {cut}");
    }
}

#[test]
fn streaming_one_byte_at_a_time_gives_the_one_shot_result() {
    let (r, text) = a_text_with_secrets();
    let reference = r.redact(&text).unwrap();
    let (out, report) = stream_with(&r, &text, &[1]);
    assert_eq!(out, reference.output.as_ref());
    assert_eq!(report, reference.report);
}

#[test]
fn streaming_a_secret_at_every_distance_from_a_block_boundary_is_redacted() {
    let mut rng = Rng::new(0x5eed_0009);
    let secret = fake_secret(&mut rng, 40);
    let token = format!("sfjt_{}", rng.string(ALNUM, 40));
    let r = redactor_with(&[("webhook_secret", &secret)]);
    // The secret is 40 bytes long, so these offsets put a block boundary at every position
    // inside it, and one byte before and after. The text after the value is long enough that the
    // block holding the boundary is searched with a look-ahead and is not the last one: only
    // then can a match straddle a boundary.
    for boundary in [4096usize, 8192] {
        for offset in boundary - 45..boundary + 3 {
            for value in [&secret, &token] {
                let text = format!("{}{value}{}", rep('.', offset), rep('.', 9_000));
                let reference = redact(&r, text.as_bytes());
                // The value is written as it is here, so the first, middle and last ten bytes
                // are a cheap and complete check; the full decoding check is slow for 8 KB.
                for piece in [&value[..10], &value[15..25], &value[value.len() - 10..]] {
                    assert!(
                        !contains(&reference, piece.as_bytes()),
                        "offset {offset}: a piece of the value survived"
                    );
                }
                let (chunked, _) = stream_with(&r, text.as_bytes(), &[1000, 4093, 17]);
                assert_eq!(chunked, reference, "offset {offset}");
            }
        }
    }
}

#[test]
fn streaming_a_token_longer_than_the_look_ahead_is_redacted_to_its_end() {
    let r = redactor();
    for len in [3_000usize, 5_000, 9_000, 30_000] {
        let token = format!("sk-{}", rep('a', len));
        let text = format!("before {token} after");
        let out = redact_text(&r, &text);
        assert_eq!(
            out, "before [REDACTED:openai_api_key] after",
            "length {len}"
        );
        let (chunked, _) = stream_with(&r, text.as_bytes(), &[777]);
        assert_eq!(String::from_utf8(chunked).unwrap(), out, "length {len}");
    }
}

#[test]
fn streaming_a_key_block_with_no_end_line_is_redacted_to_the_end_of_the_input() {
    let r = redactor();
    let text = format!(
        "start\n-----BEGIN {} KEY-----\n{}\nno end line here",
        "PRIVATE",
        rep('x', 20_000)
    );
    assert_eq!(
        redact_text(&r, &text),
        "start\n[REDACTED:private_key_block]"
    );
}

#[test]
fn streaming_a_key_block_with_an_end_line_stops_at_the_end_line() {
    let r = redactor();
    let text = format!(
        "a\n-----BEGIN {0} KEY-----\n{1}\n-----END {0} KEY-----\nb",
        "RSA PRIVATE",
        rep('x', 7_000)
    );
    assert_eq!(redact_text(&r, &text), "a\n[REDACTED:private_key_block]\nb");
    // A footer written with a longer run of dashes is swallowed whole.
    let odd = format!(
        "a\n-----BEGIN {0} KEY-----\n{1}\n------END {0} KEY------\nb",
        "PRIVATE",
        rep('x', 50)
    );
    assert_eq!(redact_text(&r, &odd), "a\n[REDACTED:private_key_block]\nb");
}

#[test]
fn streaming_holds_back_only_a_bounded_amount_of_ordinary_text() {
    let r = redactor();
    let mut stream = r.stream();
    let mut out = Vec::new();
    let line = "2026-10-27 INFO worker claimed job 0192f3a4 stage=IMPLEMENTATION attempt=2\n";
    let mut most = 0;
    let mut pushed = 0usize;
    while pushed < 6 << 20 {
        stream.push(line.as_bytes(), &mut out).unwrap();
        pushed += line.len();
        most = most.max(stream.pending_bytes());
        if out.len() > 1 << 20 {
            out.clear();
        }
    }
    assert!(most < 32 * 1024, "the stream held back {most} bytes");
}

#[test]
fn streaming_a_token_that_never_ends_fails_closed_at_the_pending_limit() {
    let r = builder()
        .limits(Limits {
            max_pending_bytes: 64 * 1024,
            ..Limits::default()
        })
        .build()
        .unwrap();
    let mut stream = r.stream();
    let mut out = Vec::new();
    stream.push(b"sk-", &mut out).unwrap();
    let mut failure = None;
    for _ in 0..200 {
        if let Err(e) = stream.push(&vec![b'a'; 4096], &mut out) {
            failure = Some(e);
            break;
        }
    }
    assert_eq!(
        failure,
        Some(RedactionError::PendingTooLarge { max: 64 * 1024 })
    );
    assert_eq!(
        stream.push(b"more", &mut out),
        Err(RedactionError::StreamFailed)
    );
    assert!(
        !out.windows(3).any(|w| w == b"sk-"),
        "the start of the token must not have been written"
    );
}

#[test]
fn streaming_a_flood_of_invisible_characters_fails_closed_and_does_not_grow_without_bound() {
    let r = builder()
        .limits(Limits {
            max_pending_bytes: 64 * 1024,
            ..Limits::default()
        })
        .build()
        .unwrap();
    let mut stream = r.stream();
    let mut out = Vec::new();
    let mut failed = false;
    stream.push(b"ghp_", &mut out).unwrap();
    for _ in 0..200 {
        // Zero-width spaces between the letters of a token never let the stream decide.
        if stream
            .push("\u{200b}".repeat(2000).as_bytes(), &mut out)
            .is_err()
        {
            failed = true;
            break;
        }
        assert!(stream.pending_bytes() <= 64 * 1024 + 8192);
    }
    assert!(failed, "the flood must be refused");
}

#[test]
fn streaming_a_large_clean_input_passes_through_unchanged() {
    let r = redactor();
    let text = "A line of ordinary build output, with numbers 12345 and paths /usr/lib/x.\n"
        .repeat(60_000);
    let (out, report) = stream_with(&r, text.as_bytes(), &[65_536]);
    assert_eq!(out, text.as_bytes());
    assert!(report.is_clean());
    assert_eq!(
        r.redact(text.as_bytes()).unwrap().output,
        Cow::Borrowed(text.as_bytes())
    );
}

#[test]
fn one_shot_input_over_the_limit_is_refused_and_a_stream_takes_it() {
    let r = builder()
        .limits(Limits {
            max_input_bytes: 1000,
            ..Limits::default()
        })
        .build()
        .unwrap();
    let big = vec![b'x'; 1001];
    assert_eq!(
        r.redact(&big),
        Err(RedactionError::InputTooLarge { max: 1000 })
    );
    assert_eq!(
        r.scan(&big),
        Err(RedactionError::InputTooLarge { max: 1000 })
    );
    assert_eq!(
        r.contains_secret(&big),
        Err(RedactionError::InputTooLarge { max: 1000 })
    );
    let (out, _) = stream_with(&r, &big, &[100]);
    assert_eq!(out, big);
}

// ===== The check path ================================================================================

#[test]
fn contains_secret_is_true_for_registered_values_and_blocking_patterns_only() {
    let mut rng = Rng::new(0x5eed_000a);
    let secret = fake_secret(&mut rng, 30);
    let r = redactor_with(&[("webhook_secret", &secret)]);
    assert!(
        r.contains_secret(format!("x {secret} y").as_bytes())
            .unwrap()
    );
    assert!(
        r.contains_secret(format!("x {} y", base64(secret.as_bytes(), false, true)).as_bytes())
            .unwrap()
    );
    assert!(
        r.contains_secret(format!("x ghp_{} y", rng.string(ALNUM, 36)).as_bytes())
            .unwrap()
    );
    assert!(!r.contains_secret(b"nothing to see here").unwrap());
    assert!(!r.contains_secret(b"").unwrap());
    assert!(
        !r.contains_secret(format!("password={}", rep('t', 16)).as_bytes())
            .unwrap()
    );
}

#[test]
fn a_scan_stream_finds_a_secret_split_across_chunks_and_keeps_no_text() {
    let mut rng = Rng::new(0x5eed_000b);
    let secret = fake_secret(&mut rng, 30);
    let r = redactor_with(&[("webhook_secret", &secret)]);
    let text = format!("{}{secret}{}", rep('.', 9000), rep('.', 9000));
    let mut scan = r.scan_stream();
    assert!(!scan.has_blocking());
    for chunk in text.as_bytes().chunks(997) {
        scan.push(chunk).unwrap();
    }
    assert!(scan.has_blocking());
    let report = scan.finish().unwrap();
    assert!(report.has_blocking());
    assert_eq!(report, r.scan(text.as_bytes()).unwrap());
}

// ===== Robustness ====================================================================================

#[test]
fn invalid_utf8_around_and_inside_a_secret_is_preserved_except_for_the_secret() {
    let value = short_secret();
    let r = redactor_with(&[("webhook_secret", &value)]);
    let mut input = vec![0xff, 0xfe, 0x80];
    input.extend_from_slice(value.as_bytes());
    input.extend_from_slice(&[0xc3, 0x28, 0xe2, 0x80]);
    let mut expected = vec![0xff, 0xfe, 0x80];
    expected.extend_from_slice(b"[REDACTED:webhook_secret]");
    expected.extend_from_slice(&[0xc3, 0x28, 0xe2, 0x80]);
    assert_eq!(redact(&r, &input), expected);
}

#[test]
fn every_byte_value_is_handled() {
    let value = short_secret();
    let r = redactor_with(&[("webhook_secret", &value)]);
    let all: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
    let out = r.redact(&all).unwrap();
    assert_eq!(out.output.as_ref(), all.as_slice());
    assert!(out.report.is_clean());
}

#[test]
fn empty_input_is_clean() {
    let r = redactor();
    let out = r.redact(b"").unwrap();
    assert_eq!(out.output.as_ref(), b"");
    assert!(out.report.is_clean());
    let (streamed, report) = stream_with(&r, b"", &[1]);
    assert!(streamed.is_empty() && report.is_clean());
}

#[test]
fn redact_str_borrows_clean_text_and_always_returns_valid_text() {
    let mut rng = Rng::new(0x5eed_000c);
    let secret = fake_secret(&mut rng, 30);
    let r = redactor_with(&[("webhook_secret", &secret)]);
    let clean = "nothing secret in this line, only text and a symbol: \u{1f600}";
    let out = r.redact_str(clean).unwrap();
    assert!(matches!(out.output, Cow::Borrowed(_)));
    let dirty = format!("\u{e9}{secret}\u{1f600}");
    let out = r.redact_str(&dirty).unwrap();
    assert_eq!(out.output, "\u{e9}[REDACTED:webhook_secret]\u{1f600}");
}

#[test]
fn no_marker_matches_a_pattern_again() {
    let r = redactor();
    for sample in samples() {
        let once = redact(&r, sample.positive.as_bytes());
        let twice = redact(&r, &once);
        assert_eq!(once, twice, "pattern {}", sample.id);
        assert!(!r.contains_secret(&once).unwrap(), "pattern {}", sample.id);
    }
}

#[test]
fn redacting_flagged_matches_too_is_a_choice_and_changes_only_flags() {
    let strict = builder().flagged(FlagHandling::Redact).build().unwrap();
    let relaxed = redactor();
    let input = format!("password={} ok", rep('t', 16));
    assert_eq!(
        redact_text(&strict, &input),
        "[REDACTED:generic_assignment] ok"
    );
    assert_eq!(redact_text(&relaxed, &input), input);
    // Idempotent in this mode too.
    let once = redact(&strict, input.as_bytes());
    assert_eq!(redact(&strict, &once), once);
    // A secret with a flag around it is still one marker.
    let both = format!("password=ghp_{} ok", rep('z', 36));
    assert_eq!(
        redact_text(&strict, &both),
        "[REDACTED:generic_assignment] ok"
    );
}

// ===== Control-off checks ============================================================================
//
// Each check weakens the redactor on purpose and shows that the tests above notice. A test that
// still passed with its control switched off would prove nothing.

fn redactor_with_pattern(id: &str, regex: &str) -> Redactor {
    let mut p = policy();
    let spec = p
        .patterns
        .iter_mut()
        .find(|spec| spec.id == id)
        .expect("the policy has the pattern");
    spec.regex = regex.to_owned();
    Redactor::builder()
        .patterns(p.patterns)
        .entropy(p.entropy)
        .exact_value_min_len(p.min_len)
        .encodings(&p.encodings)
        .build()
        .expect("the changed pattern compiles")
}

#[test]
fn control_off_a_pattern_that_is_too_narrow_fails_its_positive_sample() {
    let r = redactor_with_pattern("github_token_classic", r"\bghp_[A-Za-z0-9]{40}\b");
    let failures = positive_failures(&r);
    assert!(
        failures
            .iter()
            .any(|f| f.starts_with("github_token_classic")),
        "{failures:?}"
    );
}

#[test]
fn control_off_a_pattern_that_is_too_greedy_fails_its_positive_sample() {
    let r = redactor_with_pattern("github_token_classic", r"\bghp_[A-Za-z0-9]{36}\b.*");
    let failures = positive_failures(&r);
    assert!(
        failures
            .iter()
            .any(|f| f.starts_with("github_token_classic")),
        "{failures:?}"
    );
}

#[test]
fn control_off_a_pattern_without_its_word_boundary_fails_its_negative_sample() {
    let r = redactor_with_pattern("github_token_classic", r"ghp_[A-Za-z0-9]{36}");
    let failures = negative_failures(&r);
    assert!(
        failures
            .iter()
            .any(|f| f.starts_with("github_token_classic")),
        "{failures:?}"
    );
}

#[test]
fn control_off_a_pattern_with_a_ceiling_leaves_the_tail_of_a_long_token() {
    let r = redactor_with_pattern(
        "openai_api_key",
        r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,64}\b",
    );
    let text = format!("before sk-{} after", rep('a', 3_000));
    let out = redact_text(&r, &text);
    assert_ne!(out, "before [REDACTED:openai_api_key] after");
    assert!(
        out.contains("aaaaaaaaaaaaaaaa"),
        "the tail must still be there"
    );
    // The real redactor covers it.
    assert_eq!(
        redact_text(&redactor(), &text),
        "before [REDACTED:openai_api_key] after"
    );
}

#[test]
fn control_off_a_redactor_that_skips_the_registry_leaks_every_encoding() {
    let mut rng = Rng::new(0x5eed_0020);
    let secret = fake_secret(&mut rng, 30);
    let unregistered = redactor();
    for (name, leak) in leaks_of(&secret) {
        let out = redact(&unregistered, format!("log: {leak} end").as_bytes());
        assert!(
            find_leak(&out, &secret).is_some(),
            "{name}: the leak check missed a secret that nothing removed"
        );
    }
}

#[test]
fn control_off_dropping_an_encoding_lets_its_spellings_through() {
    use Encoding::{
        Base64NoPad, Base64Std, Base64Url, HexLower, HexUpper, JsonEscaped, Raw, UrlPercent,
    };
    let mut rng = Rng::new(0x5eed_0021);
    let secret = fake_secret(&mut rng, 30);
    let full = redactor_with(&[("job_token", &secret)]);
    type Affected = fn(&str) -> bool;
    let cases: [(&[Encoding], Affected); 6] = [
        (&[Raw], |name| name == "raw"),
        (&[HexLower], |name| name == "hex"),
        (&[HexUpper], |name| name == "HEX"),
        (&[UrlPercent], |name| name == "percent"),
        (&[JsonEscaped], |name| name == "json"),
        (&[Base64Std, Base64Url, Base64NoPad], |name| {
            name.starts_with("base64")
        }),
    ];
    for (dropped, is_affected) in cases {
        let kept: Vec<Encoding> = policy()
            .encodings
            .into_iter()
            .filter(|e| !dropped.contains(e))
            .collect();
        let weakened = builder().encodings(&kept).build().unwrap();
        weakened.register("job_token", &secret).unwrap();
        let mut leaked = 0;
        for (name, leak) in leaks_of(&secret)
            .into_iter()
            .filter(|(n, _)| is_affected(n))
        {
            let input = format!("log: {leak} end");
            // With the encoding, nothing survives.
            assert_no_leak(&redact(&full, input.as_bytes()), &secret, &name);
            // Without it, the leak check sees the spelling come through.
            if find_leak(&redact(&weakened, input.as_bytes()), &secret).is_some() {
                leaked += 1;
            }
        }
        assert!(leaked > 0, "dropping {dropped:?} let nothing through");
    }
}

#[test]
fn control_off_redacting_each_chunk_alone_would_miss_a_secret_cut_by_a_chunk_boundary() {
    let (r, secret, token) = a_registered_secret_and_a_pattern_token();
    for value in [&secret, &token] {
        let line = format!("v: {value} end");
        let (first, second) = line.split_at(line.len() / 2);
        // A redactor with no memory between chunks.
        let mut naive = redact(&r, first.as_bytes());
        naive.extend(redact(&r, second.as_bytes()));
        assert!(
            find_leak(&naive, value).is_some(),
            "the cut must hide the value"
        );
        // The stream, given the same two chunks, does not leak.
        let (streamed, _) = stream_with(&r, line.as_bytes(), &[first.len(), second.len()]);
        assert_no_leak(&streamed, value, "stream");
    }
}

// ===== Properties ====================================================================================

/// 96 cases by default, which keeps the suite fast. `PROPTEST_CASES=5000` runs a long search.
fn runner() -> TestRunner {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|n| n.parse().ok())
        .unwrap_or(96);
    TestRunner::new(Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    })
}

/// Pieces of text that stress the redactor: words, a registered secret, a pattern token, escape
/// sequences, invisible characters, line breaks and arbitrary bytes.
///
/// With `glue` the pieces are joined as they are, so a token can sit right behind a word. Without
/// it a space separates them.
fn pieces(secret: &str, token: &str, glue: bool) -> impl Strategy<Value = Vec<u8>> {
    let secret = secret.as_bytes().to_vec();
    let token = token.as_bytes().to_vec();
    let secret_b64 = base64(&secret, false, true).into_bytes();
    let piece = prop_oneof![
        3 => "[a-z ]{0,24}".prop_map(String::into_bytes),
        2 => Just(secret),
        2 => Just(token),
        1 => Just(secret_b64),
        1 => Just(b"\x1b[31m".to_vec()),
        1 => Just(b"\x1b]0;t\x07".to_vec()),
        1 => Just("\u{200b}".as_bytes().to_vec()),
        1 => Just(b"\n".to_vec()),
        1 => proptest::collection::vec(any::<u8>(), 0..6),
    ];
    proptest::collection::vec(piece, 0..14).prop_map(move |parts| {
        if glue {
            parts.concat()
        } else {
            parts.join(&b' ')
        }
    })
}

fn property_redactor() -> (Redactor, String, String) {
    let mut rng = Rng::new(0x5eed_00ff);
    let secret = fake_secret(&mut rng, 28);
    let token = format!("sfjt_{}", rng.string(ALNUM, 40));
    let r = redactor_with(&[("webhook_secret", &secret)]);
    (r, secret, token)
}

#[test]
fn property_chunking_never_changes_the_result() {
    let (r, secret, token) = property_redactor();
    let sizes = proptest::collection::vec(1usize..40, 1..6);
    runner()
        .run(&(pieces(&secret, &token, true), sizes), |(input, sizes)| {
            let whole = r.redact(&input).unwrap();
            let (out, report) = stream_with(&r, &input, &sizes);
            prop_assert_eq!(&out[..], whole.output.as_ref());
            prop_assert_eq!(report, whole.report);
            Ok(())
        })
        .unwrap();
}

#[test]
fn property_redacting_twice_changes_nothing_more() {
    // The pieces are separated here. A pattern written with a word boundary does not match a
    // token glued to a word, but it does once a marker has taken the word's place, so for glued
    // pieces a second pass can find one more token. `known_limit_*` below shows that case.
    let (r, secret, token) = property_redactor();
    runner()
        .run(&pieces(&secret, &token, false), |input| {
            let once = redact(&r, &input);
            let twice = redact(&r, &once);
            prop_assert_eq!(once, twice);
            Ok(())
        })
        .unwrap();
}

#[test]
fn property_no_registered_secret_survives_in_any_encoding_or_disguise() {
    let mut rng = Rng::new(0x5eed_00fe);
    let secret = fake_secret(&mut rng, 28);
    let r = redactor_with(&[("webhook_secret", &secret)]);
    let leaks = leaks_of(&secret);
    let noise = ["", "\u{200b}", "\u{1b}[31m", "\u{2060}", "\u{1b}]0;x\u{7}"];
    runner()
        .run(
            &(
                0..leaks.len(),
                0..noise.len(),
                "[a-z ]{0,30}",
                "[a-z ]{0,30}",
                1usize..64,
            ),
            |(which, with_noise, before, after, chunk)| {
                let (name, leak) = &leaks[which];
                let planted = if noise[with_noise].is_empty() {
                    leak.clone()
                } else {
                    interleave(leak, noise[with_noise])
                };
                let input = format!("{before}{planted}{after}");
                let whole = redact(&r, input.as_bytes());
                assert_no_leak(&whole, &secret, name);
                let (streamed, _) = stream_with(&r, input.as_bytes(), &[chunk]);
                prop_assert_eq!(streamed, whole);
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn property_text_with_no_secret_in_it_is_returned_unchanged() {
    let (r, _, _) = property_redactor();
    runner()
        .run(
            &proptest::collection::vec("[a-zA-Z .,;:!?'\\-]{0,40}|[0-9]{1,6}|\n|\t", 0..30),
            |parts| {
                let input = parts.concat();
                let out = r.redact(input.as_bytes()).unwrap();
                prop_assert_eq!(out.output.as_ref(), input.as_bytes());
                prop_assert!(!out.report.has_blocking());
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn property_long_tokens_and_key_blocks_are_covered_to_the_end_whatever_the_chunking() {
    // Tokens and key blocks of up to several blocks long, with noise, white space and words
    // around them. The body of a token is the letter Q and the body of a key is the letter P,
    // and no other piece has those letters, so a tail left behind is easy to see.
    let (r, secret, _) = property_redactor();
    let long_token = (0usize..7000).prop_map(|n| format!("sk-{}", "Q".repeat(n + 40)).into_bytes());
    let key_body = (0usize..7000).prop_map(|n| "P".repeat(n + 1));
    let key = (key_body, any::<bool>()).prop_map(|(body, footer)| {
        let mut block = format!("-----BEGIN {} KEY-----\n{body}\n", "RSA PRIVATE").into_bytes();
        if footer {
            block.extend_from_slice(format!("-----END {} KEY-----", "RSA PRIVATE").as_bytes());
        }
        block
    });
    let piece = prop_oneof![
        3 => "[a-z ]{0,400}".prop_map(String::into_bytes),
        3 => long_token,
        2 => key,
        1 => Just(secret.clone().into_bytes()),
        1 => Just(b"\x1b[31m".to_vec()),
        1 => Just("\u{200b}".as_bytes().to_vec()),
        1 => Just(b"\n".to_vec()),
    ];
    let input = proptest::collection::vec(piece, 1..8).prop_map(|parts| parts.join(&b' '));
    let sizes = proptest::collection::vec(1usize..9000, 1..5);
    runner()
        .run(&(input, sizes), |(input, sizes)| {
            let whole = r.redact(&input).unwrap();
            let (out, report) = stream_with(&r, &input, &sizes);
            prop_assert_eq!(&out[..], whole.output.as_ref());
            prop_assert_eq!(report, whole.report);
            prop_assert!(
                !contains(&out, b"QQQQQQQQQQ"),
                "the tail of a token was left"
            );
            prop_assert!(!contains(&out, b"PPPPPPPPPP"), "the body of a key was left");
            prop_assert!(!contains(&out, secret.as_bytes()));
            Ok(())
        })
        .unwrap();
}

#[test]
fn property_arbitrary_bytes_never_panic_and_never_depend_on_the_chunking() {
    let (r, _, _) = property_redactor();
    runner()
        .run(
            &(proptest::collection::vec(any::<u8>(), 0..3000), 1usize..500),
            |(input, chunk)| {
                let whole = r.redact(&input).unwrap();
                let (out, report) = stream_with(&r, &input, &[chunk]);
                prop_assert_eq!(&out[..], whole.output.as_ref());
                prop_assert_eq!(report, whole.report);
                let _ = r.contains_secret(&input).unwrap();
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn known_limit_a_pattern_token_glued_to_a_word_has_no_word_boundary_in_front_of_it() {
    // The policy writes its token patterns with a word boundary in front. A token right behind a
    // letter, digit or underscore has none, so no pattern matches it. A registered value is found
    // anywhere, which is why the factory's own secrets are registered. After a replacement the
    // marker gives the next text a boundary, so a second pass finds a token the first one could
    // not.
    let mut rng = Rng::new(0x5eed_0010);
    let secret = fake_secret(&mut rng, 24);
    let token = format!("sfjt_{}", rng.string(ALNUM, 40));
    let r = redactor_with(&[("webhook_secret", &secret)]);
    assert!(!r.contains_secret(format!("x{token}").as_bytes()).unwrap());
    let once = redact_text(&r, &format!("{secret}{token}"));
    assert_eq!(once, format!("[REDACTED:webhook_secret]{token}"));
    assert_eq!(
        redact_text(&r, &once),
        "[REDACTED:webhook_secret][REDACTED:factory_job_token]"
    );
}

// ===== Building and sharing ==========================================================================

#[test]
fn redactor_is_built_from_the_policy_and_is_shareable() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<Redactor>();
    assert_send_sync::<Arc<Redactor>>();
    fn assert_send<T: Send + 'static>() {}
    assert_send::<RedactStream>();

    // Built from the policy's own list, in the policy's own order, without reading a file.
    let from_policy = policy();
    let r = redactor();
    let ids: Vec<String> = from_policy.patterns.iter().map(|p| p.id.clone()).collect();
    assert_eq!(r.pattern_ids(), ids);

    // Shared between threads: several threads redact while another registers secrets.
    let r = Arc::new(r);
    let mut handles = Vec::new();
    for n in 0..4u64 {
        let r = Arc::clone(&r);
        handles.push(std::thread::spawn(move || {
            let mut rng = Rng::new(0x7000 + n);
            for _ in 0..50 {
                let token = format!("ghp_{}", rng.string(ALNUM, 36));
                let line = format!("x {token} y");
                let out = r.redact(line.as_bytes()).unwrap();
                assert_eq!(out.output.as_ref(), b"x [REDACTED:github_token_classic] y");
            }
        }));
    }
    let registrar = {
        let r = Arc::clone(&r);
        std::thread::spawn(move || {
            for n in 0..20 {
                r.register("job_token", format!("registered-value-{n:04}"))
                    .unwrap();
            }
        })
    };
    for h in handles {
        h.join().unwrap();
    }
    registrar.join().unwrap();
    assert_eq!(r.registered_count(), 20);
    assert_eq!(
        redact_text(&r, "a registered-value-0007 b"),
        "a [REDACTED:job_token] b"
    );
}

#[test]
fn redactor_has_no_pattern_of_its_own() {
    // Built from an empty list it finds nothing a pattern would find.
    let empty = Redactor::builder().build().unwrap();
    for sample in samples() {
        assert_eq!(
            redact(&empty, sample.positive.as_bytes()),
            sample.positive.as_bytes(),
            "pattern {}",
            sample.id
        );
    }
    // Built from a different list it follows that list.
    let custom = Redactor::builder()
        .pattern("only_this", "ZZ[0-9]{4}", PatternAction::Block)
        .build()
        .unwrap();
    assert_eq!(
        redact_text(&custom, "a ZZ1234 b ghp_x"),
        "a [REDACTED:only_this] b ghp_x"
    );
    assert_eq!(custom.pattern_ids(), vec!["only_this".to_owned()]);
}

#[test]
fn redactor_source_holds_no_copy_of_the_policy_patterns() {
    // The sources of the module, read at compile time. No pattern of the policy appears in them.
    let sources = [
        include_str!("../src/redaction/mod.rs"),
        include_str!("../src/redaction/automaton.rs"),
        include_str!("../src/redaction/config.rs"),
        include_str!("../src/redaction/encodings.rs"),
        include_str!("../src/redaction/error.rs"),
        include_str!("../src/redaction/redactor.rs"),
        include_str!("../src/redaction/report.rs"),
        include_str!("../src/redaction/terminal.rs"),
    ];
    for pattern in policy().patterns {
        for source in sources {
            assert!(
                !source.contains(&pattern.regex),
                "the source copies the pattern {}",
                pattern.id
            );
        }
    }
}

#[test]
fn building_rejects_what_cannot_work() {
    let build = |id: &str, regex: &str| {
        Redactor::builder()
            .pattern(id, regex, PatternAction::Block)
            .build()
            .err()
    };
    assert!(matches!(
        build("ok", "(unclosed"),
        Some(BuildError::InvalidPattern { .. })
    ));
    assert!(matches!(
        build("ok", "a*"),
        Some(BuildError::EmptyMatch { .. })
    ));
    assert!(matches!(
        build("bad id", "x"),
        Some(BuildError::InvalidId { .. })
    ));
    assert!(matches!(build("", "x"), Some(BuildError::InvalidId { .. })));
    assert!(matches!(
        Redactor::builder()
            .pattern("a", "x", PatternAction::Block)
            .pattern("a", "y", PatternAction::Block)
            .build()
            .err(),
        Some(BuildError::DuplicateId { .. })
    ));
    assert!(matches!(
        Redactor::builder()
            .entropy(EntropySpec {
                min_length: 0,
                min_bits_per_char: 4.0,
                action: PatternAction::Flag
            })
            .build()
            .err(),
        Some(BuildError::InvalidEntropy { .. })
    ));
}

#[test]
fn an_error_never_repeats_a_secret() {
    let r = redactor();
    let secret = "S3cr3t-V4lue-that-is-way-too-long".repeat(200);
    let err = r.register("x", &secret).unwrap_err();
    assert!(!err.to_string().contains("S3cr3t"));
    let err = r
        .register("bad label with S3cr3t", "abcdefghijkl")
        .unwrap_err();
    // The label is not a secret, so it may be shown, but the value never is.
    assert!(!err.to_string().contains("abcdefghijkl"));
}
