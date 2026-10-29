//! The URL and token patterns of `policies/security.yaml` against shapes that a review of the first
//! fix found (RR-1 to RR-4): a host in another script, an at sign written as an escape, a data source
//! name with no scheme, and a token glued to a word.
//!
//! The generator here is a grammar and not a list: a URL or a data source name is built from
//! independent choices (scheme, user, the spelling of the at sign, the host, the wrapper around the
//! text, the word it is glued to), and the property is that no stretch of the password survives. It is
//! not the generator of `redaction.rs`, which writes lines of text and checks that nothing but the URL
//! is eaten; the two overlap on purpose and share no code.
//!
//! No line of this file looks like a credential to a secret scan: every password and every token is
//! assembled when a test runs, from characters a generator draws.

use factory_domain::redaction::{PatternAction, PatternSpec, Redactor};
use proptest::prelude::*;

const POLICY: &str = include_str!("../../../policies/security.yaml");

/// The text of a YAML single-quoted scalar, starting just after the opening quote.
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

/// A redactor made of the block patterns of the policy and nothing else.
fn redactor() -> Redactor {
    let block = POLICY
        .split("\nsecrets:\n")
        .nth(1)
        .and_then(|secrets| secrets.split("  patterns:\n").nth(1))
        .and_then(|rest| rest.split("  entropy_heuristic:").next())
        .expect("the policy lists patterns");
    let patterns: Vec<PatternSpec> = block
        .lines()
        .filter(|line| line.trim_start().starts_with("- { id:"))
        .map(|line| {
            let id = line
                .split("id: ")
                .nth(1)
                .and_then(|rest| rest.split(',').next())
                .expect("an id")
                .trim();
            let regex = single_quoted(line.split("regex: '").nth(1).expect("a regex"));
            let action = if line.contains("action: block") {
                PatternAction::Block
            } else {
                PatternAction::Flag
            };
            PatternSpec::new(id, regex, action)
        })
        .collect();
    Redactor::builder()
        .patterns(patterns)
        .build()
        .expect("the patterns compile")
}

fn redact(redactor: &Redactor, text: &str) -> String {
    redactor
        .redact_str(text)
        .expect("redacts")
        .output
        .into_owned()
}

// ------------------------------------------------------------------------------------------
// The grammar
// ------------------------------------------------------------------------------------------

fn alphanumeric(length: std::ops::RangeInclusive<usize>) -> impl Strategy<Value = String> {
    proptest::collection::vec(
        prop::sample::select(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                .chars()
                .collect::<Vec<char>>(),
        ),
        length,
    )
    .prop_map(|chars| chars.into_iter().collect())
}

/// A password: twelve to twenty characters, at least one of which comes from outside the letters, so
/// it is not a word. A leak is any stretch of ten of them in the output.
fn password() -> impl Strategy<Value = String> {
    (
        alphanumeric(8..=14),
        prop::sample::select(vec!["-", "_", ".", "~", "!", "*", "+", "="]),
        alphanumeric(3..=6),
    )
        .prop_map(|(head, mark, tail)| format!("Zq{head}{mark}{tail}"))
}

fn scheme() -> impl Strategy<Value = String> {
    prop_oneof![
        prop::sample::select(vec![
            "http",
            "https",
            "HTTPS",
            "ftp",
            "ssh",
            "redis",
            "rediss",
            "amqp",
            "mongodb+srv",
            "postgres",
            "postgresql",
            "Postgres",
            "mysql",
            "git+https",
        ])
        .prop_map(str::to_owned),
        "[a-z][a-z0-9+.-]{1,10}",
    ]
}

fn user() -> impl Strategy<Value = String> {
    prop_oneof![
        1 => Just(String::new()),
        4 => alphanumeric(1..=12),
        1 => alphanumeric(2..=6).prop_map(|name| format!("{name}.{name}")),
    ]
}

/// The host: an ASCII name, an address, a name in another script, with or without a port.
fn host() -> impl Strategy<Value = String> {
    let name = prop_oneof![
        3 => "[a-z][a-z0-9-]{0,10}(\\.[a-z]{2,6}){1,2}",
        1 => Just("localhost".to_owned()),
        1 => Just("10.0.4.7".to_owned()),
        1 => Just("[::1]".to_owned()),
        1 => Just("[fe80::1%25eth0]".to_owned()),
        // Names in other scripts and with an umlaut or a tilde as their first letter.
        1 => Just("\u{4f8b}\u{3048}.jp".to_owned()),
        1 => Just("\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}".to_owned()),
        1 => Just("\u{fc}nchen.example".to_owned()),
        1 => Just("\u{627}\u{62e}\u{62a}\u{628}\u{627}\u{631}.example".to_owned()),
        1 => Just("db.\u{3b1}\u{3b2}\u{3b3}.example".to_owned()),
    ];
    let port = prop_oneof![
        2 => Just(String::new()),
        1 => (1u16..65535).prop_map(|n| format!(":{n}")),
    ];
    let path = prop_oneof![
        2 => Just(String::new()),
        1 => alphanumeric(1..=8).prop_map(|s| format!("/{s}")),
        1 => alphanumeric(1..=5).prop_map(|s| format!("/{s}?a=1&b=2")),
    ];
    (name, port, path).prop_map(|(name, port, path)| format!("{name}{port}{path}"))
}

/// How the at sign that ends the user information is written.
fn at_sign() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec!["@", "@", "@", "%40", "\\u0040", "\\x40", "\\u{40}"])
}

/// What the text is wrapped in, and what stands in front of it.
fn wrap(kind: u8, text: &str) -> String {
    match kind % 9 {
        0 => text.to_owned(),
        1 => format!("{{\"url\":\"{text}\"}}"),
        2 => format!("<{text}>"),
        3 => format!("[link]({text})"),
        4 => format!("url={text} attempt=3"),
        5 => format!("connect to \"{text}\" failed"),
        6 => format!("'{text}'"),
        7 => format!("export DATABASE_URL={text}"),
        _ => format!("({text}), retrying"),
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 400,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// A URL with a password, in any scheme, any spelling of the at sign, any host and any wrapper,
    /// keeps no stretch of the password.
    #[test]
    fn a_url_with_a_password_keeps_none_of_it(
        scheme in scheme(),
        user in user(),
        password in password(),
        at in at_sign(),
        host in host(),
        wrapper in 0u8..9,
    ) {
        let text = wrap(wrapper, &format!("{scheme}://{user}:{password}{at}{host}"));
        let out = redact(&redactor(), &text);
        prop_assert!(
            !has_stretch(&out, &password),
            "a stretch of the password survived: {text:?} -> {out:?}"
        );
    }

    /// A data source name with no scheme, in the forms of the Go MySQL driver and of a driver that
    /// takes a host and a port or a host and a database, keeps none of the password.
    #[test]
    fn a_scheme_less_data_source_name_keeps_none_of_its_password(
        user in alphanumeric(1..=10),
        password in password(),
        at in at_sign(),
        form in 0u8..4,
        host in "[a-z][a-z0-9-]{0,8}(\\.[a-z]{2,5}){0,2}",
        port in 1u16..65535,
        database in alphanumeric(1..=8),
        wrapper in 0u8..9,
    ) {
        let address = match form {
            0 => format!("tcp({host}:{port})/{database}?parseTime=true"),
            1 => format!("unix(/var/run/{database}.sock)/{database}"),
            2 => format!("{host}:{port}/{database}"),
            _ => format!("{host}/{database}"),
        };
        let text = wrap(wrapper, &format!("{user}:{password}{at}{address}"));
        let out = redact(&redactor(), &text);
        prop_assert!(
            !has_stretch(&out, &password),
            "a stretch of the password survived: {text:?} -> {out:?}"
        );
    }

    /// A token behind any run of word characters, hyphens and underscores is still a token.
    #[test]
    fn a_token_glued_to_a_word_is_redacted(
        kind in 0usize..8,
        body in alphanumeric(60..=60),
        glue in "[A-Za-z0-9_-]{0,12}",
        after in prop::sample::select(vec!["", " ", "\n", ",", "\"", ")", ";"]),
    ) {
        // (prefix, characters of the body that make the token)
        let shapes: [(&str, usize); 8] = [
            ("sfat_", 43),
            ("sfjt_", 40),
            ("ghp_", 36),
            ("github_pat_", 30),
            ("AKIA", 16),
            ("AIza", 35),
            ("sk-ant-", 30),
            ("xoxb-", 24),
        ];
        let (prefix, length) = shapes[kind];
        let secret = &body[..length];
        // The prefixes of the AWS and the Google keys take capital letters and digits only.
        let secret: String = if prefix == "AKIA" {
            secret.to_ascii_uppercase()
        } else {
            secret.to_owned()
        };
        let text = format!("{glue}{prefix}{secret}{after}");
        let out = redact(&redactor(), &text);
        prop_assert!(
            !out.contains(&secret[2..]),
            "the token survived: {text:?} -> {out:?}"
        );
    }
}

/// True when any stretch of ten characters of `secret` is in `output`.
fn has_stretch(output: &str, secret: &str) -> bool {
    let chars: Vec<char> = secret.chars().collect();
    chars
        .windows(10.min(chars.len()))
        .any(|stretch| output.contains(&stretch.iter().collect::<String>()))
}

#[test]
fn the_properties_run_over_the_shapes_the_review_named() {
    // The same property, once, over the exact shapes of RR-1 to RR-4, so that a regression names
    // itself without a shrunk counter-example.
    let r = redactor();
    let secret = &["Zq", "7fK3", "mP9x", "Lw"].concat();
    let (sep, colon) = ("://", ":");
    for text in [
        format!("https{sep}admin{colon}{secret}@\u{4f8b}\u{3048}.jp/x"),
        format!("postgres{sep}app{colon}{secret}@\u{fc}nchen.example:5432/db"),
        format!("{{\"url\":\"https{sep}svc{colon}{secret}\\u0040db.example/x\"}}"),
        format!("url: \"https{sep}svc{colon}{secret}\\x40db.example/x\""),
        format!("https{sep}svc{colon}{secret}%40db.example/x"),
        format!("svc{colon}{secret}@tcp(db.example:3306)/app?parseTime=true"),
        format!("app{colon}{secret}@db.example:5432/app"),
        format!("HTTPS{sep}svc{colon}{secret}@db.example/x"),
    ] {
        let out = redact(&r, &text);
        assert!(!out.contains(secret.as_str()), "{text:?} -> {out:?}");
    }
}

#[test]
fn text_that_only_looks_like_a_data_source_name_is_left_alone() {
    let r = redactor();
    for text in [
        "mail to support@example.com about it",
        "contact:jane@example.com",
        "see https://example.com/docs and http://localhost:8080/health",
        "postgres://db.example:5432/app",
        "git clone git@github.com:org/repo.git",
        "the time is 12:30:45 and the port is 8080",
        "ratio 3:4@home",
        "ssh://git@github.com/org/repo.git",
    ] {
        assert_eq!(redact(&r, text), text, "{text}");
    }
}
