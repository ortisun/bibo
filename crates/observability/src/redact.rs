//! Removal of secrets from text that is about to leave the process as telemetry.
//!
//! `policies/security.yaml` lists the secret patterns under `secrets.patterns` and says that logs
//! and traces redact a match instead of blocking. [`PolicyPatternScrubber`] does that with one
//! hand-written rule per listed pattern, in the same order. It does not use the `regex` crate,
//! because the dependency rules do not allow it in this crate.
//!
//! This is a baseline. The security documents call for one `Redactor` with one implementation, to
//! be built in `domain::redaction` by work package `s1-redaction`, with an exact-value registry
//! and a sliding window for split secrets. Everything in this crate that scrubs goes through the
//! [`Scrub`] trait, so the composition root can hand in that redactor when it exists. Until then a
//! test reads the policy file and fails if this list and the policy disagree.
//!
//! Each rule is at least as strict as the pattern it mirrors: where the pattern asks for "at least
//! N characters then a word boundary", the rule takes the whole run of token characters, so a
//! longer token is removed in full and not left half visible.
//!
//! What this scrubber does not do: it does not apply the entropy heuristic, which the policy only
//! flags, and it does not know the exact values of the factory's own secrets.

use std::borrow::Cow;

/// The text that replaces a match is `[REDACTED:<pattern id>]`.
pub const PLACEHOLDER_PREFIX: &str = "[REDACTED:";

/// Why a scrubber could not do its job.
///
/// A caller must treat this as "drop the value". It must never pass the original text on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrubError {
    /// The redactor behind the scrubber is not available.
    Unavailable,
}

impl std::fmt::Display for ScrubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScrubError::Unavailable => f.write_str("the redactor is not available"),
        }
    }
}

impl std::error::Error for ScrubError {}

/// Something that removes secrets from text.
///
/// The telemetry pipeline depends on this trait and not on a particular redactor.
pub trait Scrub: Send + Sync + std::fmt::Debug {
    /// The text with every secret replaced. Returns the input itself, without a copy, when it
    /// holds nothing to remove.
    fn scrub<'a>(&self, text: &'a str) -> Result<Cow<'a, str>, ScrubError>;
}

/// A rule finds a secret that starts at a given byte and returns the byte after its end.
type Matcher = fn(&[u8], usize) -> Option<usize>;

struct Rule {
    id: &'static str,
    /// True when the policy pattern starts with a word boundary, so a match must not begin in the
    /// middle of a word.
    boundary_before: bool,
    matches: Matcher,
}

/// Scrubs the secret patterns in `policies/security.yaml`. See the module documentation.
#[derive(Debug, Clone, Default)]
pub struct PolicyPatternScrubber {
    _private: (),
}

impl PolicyPatternScrubber {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// The pattern ids this scrubber covers, in the order the policy lists them.
    pub fn rule_ids() -> Vec<&'static str> {
        RULES.iter().map(|rule| rule.id).collect()
    }
}

impl Scrub for PolicyPatternScrubber {
    fn scrub<'a>(&self, text: &'a str) -> Result<Cow<'a, str>, ScrubError> {
        let bytes = text.as_bytes();
        let mut output: Option<String> = None;
        let mut copied_to = 0;
        let mut i = 0;
        while i < bytes.len() {
            match first_match(bytes, i) {
                Some((id, end)) if end > i => {
                    let out = output.get_or_insert_with(|| String::with_capacity(text.len()));
                    out.push_str(&text[copied_to..i]);
                    out.push_str(PLACEHOLDER_PREFIX);
                    out.push_str(id);
                    out.push(']');
                    i = end;
                    copied_to = end;
                }
                _ => i += 1,
            }
        }
        Ok(match output {
            None => Cow::Borrowed(text),
            Some(mut out) => {
                out.push_str(&text[copied_to..]);
                Cow::Owned(out)
            }
        })
    }
}

fn first_match(bytes: &[u8], at: usize) -> Option<(&'static str, usize)> {
    let preceded_by_word = at > 0 && is_word(bytes[at - 1]);
    RULES.iter().find_map(|rule| {
        if rule.boundary_before && preceded_by_word {
            return None;
        }
        (rule.matches)(bytes, at).map(|end| (rule.id, end))
    })
}

// ---- Character classes -------------------------------------------------------------------

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn alnum_underscore(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn alnum_dash(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
}

fn alnum_dash_underscore(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn upper_alnum(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}

fn base64_like(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'+' | b'=')
}

fn header_value(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
}

fn is_space(b: u8) -> bool {
    b.is_ascii_whitespace()
}

fn is_quote(b: u8) -> bool {
    b == b'"' || b == b'\''
}

// ---- Building blocks ---------------------------------------------------------------------

/// The end of the run of bytes, starting at `from`, that satisfy `class`.
fn run(bytes: &[u8], from: usize, class: fn(u8) -> bool) -> usize {
    let mut end = from;
    while end < bytes.len() && class(bytes[end]) {
        end += 1;
    }
    end
}

fn starts_with_ci(bytes: &[u8], at: usize, needle: &[u8]) -> bool {
    bytes.len() >= at + needle.len() && bytes[at..at + needle.len()].eq_ignore_ascii_case(needle)
}

fn starts_with(bytes: &[u8], at: usize, needle: &[u8]) -> bool {
    bytes.len() >= at + needle.len() && &bytes[at..at + needle.len()] == needle
}

/// One of the `prefixes`, then at least `min` bytes of `class`, taking the whole run.
fn prefixed_token(
    bytes: &[u8],
    at: usize,
    prefixes: &[&[u8]],
    class: fn(u8) -> bool,
    min: usize,
) -> Option<usize> {
    prefixes.iter().find_map(|prefix| {
        if !starts_with(bytes, at, prefix) {
            return None;
        }
        let body = at + prefix.len();
        let end = run(bytes, body, class);
        (end - body >= min).then_some(end)
    })
}

/// A block such as a private key: from its header through its end line, or to the end of the
/// value when there is no end line. A key body is not covered by the policy's header pattern, so
/// leaving it would leak the key.
fn armored_block(bytes: &[u8], at: usize, label_ok: fn(&[u8]) -> bool) -> Option<usize> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const DASHES: &[u8] = b"-----";
    const END: &[u8] = b"-----END ";
    if !starts_with(bytes, at, BEGIN) {
        return None;
    }
    let label_start = at + BEGIN.len();
    let label_end = find(bytes, label_start, DASHES)?;
    if !label_ok(&bytes[label_start..label_end]) {
        return None;
    }
    let header_end = label_end + DASHES.len();
    let Some(footer) = find(bytes, header_end, END) else {
        return Some(bytes.len());
    };
    let Some(footer_dashes) = find(bytes, footer + END.len(), DASHES) else {
        return Some(bytes.len());
    };
    Some(run(bytes, footer_dashes, |b| b == b'-'))
}

fn find(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if from > bytes.len() {
        return None;
    }
    bytes[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

// ---- The rules, in the order of policies/security.yaml -----------------------------------

const RULES: &[Rule] = &[
    Rule {
        id: "github_token_classic",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"ghp_"], alnum, 36),
    },
    Rule {
        id: "github_token_prefixed",
        boundary_before: true,
        matches: |b, i| {
            prefixed_token(
                b,
                i,
                &[b"ghp_", b"gho_", b"ghu_", b"ghs_", b"ghr_"],
                alnum,
                36,
            )
        },
    },
    Rule {
        id: "github_fine_grained",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"github_pat_"], alnum_underscore, 22),
    },
    Rule {
        id: "private_key_block",
        boundary_before: false,
        matches: |b, i| armored_block(b, i, private_key_label),
    },
    Rule {
        id: "anthropic_api_key",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"sk-ant-"], alnum_dash_underscore, 20),
    },
    Rule {
        id: "openai_api_key",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"sk-"], alnum_dash_underscore, 32),
    },
    Rule {
        id: "aws_access_key_id",
        boundary_before: true,
        matches: |b, i| {
            prefixed_token(
                b,
                i,
                &[
                    b"AKIA", b"ASIA", b"AGPA", b"AIDA", b"AROA", b"ANPA", b"ANVA",
                ],
                upper_alnum,
                16,
            )
        },
    },
    Rule {
        id: "aws_secret_access_key",
        boundary_before: false,
        matches: aws_secret_access_key,
    },
    Rule {
        id: "gcp_api_key",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"AIza"], alnum_dash_underscore, 35),
    },
    Rule {
        id: "slack_token",
        boundary_before: true,
        matches: |b, i| {
            prefixed_token(
                b,
                i,
                &[b"xoxa-", b"xoxb-", b"xoxp-", b"xoxr-", b"xoxs-"],
                alnum_dash,
                10,
            )
        },
    },
    Rule {
        id: "stripe_live_key",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"rk_live_", b"sk_live_"], alnum, 20),
    },
    Rule {
        id: "npm_token",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"npm_"], alnum, 36),
    },
    Rule {
        id: "pypi_token",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"pypi-AgE"], alnum_dash_underscore, 50),
    },
    Rule {
        id: "crates_io_token",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"cio"], alnum, 32),
    },
    Rule {
        id: "jwt",
        boundary_before: true,
        matches: jwt,
    },
    Rule {
        id: "authorization_header",
        boundary_before: true,
        matches: authorization_header,
    },
    Rule {
        id: "url_with_credentials",
        boundary_before: true,
        matches: url_with_credentials,
    },
    Rule {
        id: "factory_job_token",
        boundary_before: true,
        matches: |b, i| prefixed_token(b, i, &[b"sfjt_"], alnum_dash_underscore, 32),
    },
    Rule {
        id: "nats_credentials",
        boundary_before: false,
        matches: |b, i| armored_block(b, i, nats_label),
    },
    Rule {
        id: "generic_assignment",
        boundary_before: true,
        matches: generic_assignment,
    },
];

/// `PRIVATE KEY` or `PRIVATE KEY BLOCK`, optionally after one or more upper case words.
fn private_key_label(label: &[u8]) -> bool {
    let words_ok = label
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ');
    words_ok && (label.ends_with(b"PRIVATE KEY") || label.ends_with(b"PRIVATE KEY BLOCK"))
}

fn nats_label(label: &[u8]) -> bool {
    matches!(
        label,
        b"USER JWT" | b"NATS USER JWT" | b"USER NKEY SEED" | b"NATS USER NKEY SEED"
    )
}

/// `aws_?secret_?access_?key`, then separators, then 40 base64 characters.
fn aws_secret_access_key(bytes: &[u8], at: usize) -> Option<usize> {
    let mut i = at;
    for (part, optional_underscore) in [
        (&b"aws"[..], true),
        (&b"secret"[..], true),
        (&b"access"[..], true),
        (&b"key"[..], false),
    ] {
        if !starts_with_ci(bytes, i, part) {
            return None;
        }
        i += part.len();
        if optional_underscore && bytes.get(i) == Some(&b'_') {
            i += 1;
        }
    }
    let separators_end = run(bytes, i, |b| {
        is_quote(b) || is_space(b) || b == b':' || b == b'='
    });
    if separators_end == i {
        return None;
    }
    let end = run(bytes, separators_end, base64_like);
    (end - separators_end >= 40).then_some(end)
}

/// `eyJ<8+>.eyJ<8+>.<8+>`, the shape of a JSON Web Token.
fn jwt(bytes: &[u8], at: usize) -> Option<usize> {
    let mut i = at;
    for (segment, needs_header) in [(0, true), (1, true), (2, false)] {
        if needs_header {
            if !starts_with(bytes, i, b"eyJ") {
                return None;
            }
            i += 3;
        }
        let end = run(bytes, i, alnum_dash_underscore);
        if end - i < 8 {
            return None;
        }
        i = end;
        if segment < 2 {
            if bytes.get(i) != Some(&b'.') {
                return None;
            }
            i += 1;
        }
    }
    Some(i)
}

/// `Authorization:` followed by `Bearer`, `Token` or `Basic` and a credential of 16 characters or
/// more, in any letter case.
fn authorization_header(bytes: &[u8], at: usize) -> Option<usize> {
    if !starts_with_ci(bytes, at, b"authorization:") {
        return None;
    }
    let mut i = run(bytes, at + b"authorization:".len(), is_space);
    let scheme = [&b"bearer"[..], &b"token"[..], &b"basic"[..]]
        .into_iter()
        .find(|scheme| starts_with_ci(bytes, i, scheme))?;
    i += scheme.len();
    let value_start = run(bytes, i, is_space);
    if value_start == i {
        return None;
    }
    let end = run(bytes, value_start, header_value);
    (end - value_start >= 16).then_some(end)
}

/// `scheme://user:password@host`, where the password has at least three characters.
fn url_with_credentials(bytes: &[u8], at: usize) -> Option<usize> {
    if !bytes.get(at)?.is_ascii_alphabetic() {
        return None;
    }
    let scheme_end = run(bytes, at, |b| {
        b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')
    });
    if !starts_with(bytes, scheme_end, b"://") {
        return None;
    }
    let user_start = scheme_end + 3;
    let user_end = run(bytes, user_start, |b| {
        !is_space(b) && !matches!(b, b':' | b'/' | b'@')
    });
    if user_end == user_start || bytes.get(user_end) != Some(&b':') {
        return None;
    }
    let password_start = user_end + 1;
    let password_end = run(bytes, password_start, |b| {
        !is_space(b) && !matches!(b, b'@' | b'/')
    });
    if password_end - password_start < 3 || bytes.get(password_end) != Some(&b'@') {
        return None;
    }
    let host_start = password_end + 1;
    let host_end = run(bytes, host_start, |b| !is_space(b) && b != b'/');
    (host_end > host_start).then_some(host_end)
}

/// A keyword such as `password` or `api_key`, then `:` or `=`, then a value of 12 characters or
/// more. The keyword must end at a word boundary, so `token_count=...` is left alone.
fn generic_assignment(bytes: &[u8], at: usize) -> Option<usize> {
    let keyword_end = [
        &b"password"[..],
        &b"passwd"[..],
        &b"secret"[..],
        &b"token"[..],
    ]
    .into_iter()
    .find(|word| starts_with_ci(bytes, at, word))
    .map(|word| at + word.len())
    .or_else(|| key_with_optional_separator(bytes, at, b"api"))
    .or_else(|| key_with_optional_separator(bytes, at, b"access"))?;
    if keyword_end < bytes.len() && is_word(bytes[keyword_end]) {
        return None;
    }
    let mut i = keyword_end;
    if bytes.get(i).is_some_and(|&b| is_quote(b)) {
        i += 1; // a quoted key, as in a JSON field name
    }
    i = run(bytes, i, is_space);
    if !matches!(bytes.get(i), Some(b':') | Some(b'=')) {
        return None;
    }
    i = run(bytes, i + 1, is_space);
    if bytes.get(i).is_some_and(|&b| is_quote(b)) {
        i += 1;
    }
    let end = run(bytes, i, |b| !is_space(b) && !is_quote(b));
    (end - i >= 12).then_some(end)
}

/// `<word>key` or `<word>_key` or `<word>-key`, in any letter case.
fn key_with_optional_separator(bytes: &[u8], at: usize, word: &[u8]) -> Option<usize> {
    if !starts_with_ci(bytes, at, word) {
        return None;
    }
    let mut i = at + word.len();
    if matches!(bytes.get(i), Some(b'_') | Some(b'-')) {
        i += 1;
    }
    starts_with_ci(bytes, i, b"key").then_some(i + 3)
}
