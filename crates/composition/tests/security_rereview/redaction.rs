//! The URL-credential pattern and the API-token pattern of `policies/security.yaml`, attacked with
//! shapes other than the ones the fix author generated.

use factory_composition::redaction::redactor_from_policy;
use factory_composition::startup::load_policy;
use factory_domain::redaction::Redactor;

use crate::repository_root;

fn policy_redactor() -> Redactor {
    let policies = load_policy(&repository_root(), &[]).expect("the real policies load");
    redactor_from_policy(&policies.security).expect("the redactor builds")
}

/// A fresh random identifier. The `uuid` crate has no generator feature in this crate, so the
/// system's own source is used, as the other tests of this crate do.
fn fresh() -> uuid::Uuid {
    let ids = factory_composition::system::RandomIds::new().expect("the random source opens");
    factory_ports::clock::IdGenerator::new_uuid(&ids)
}

/// A twelve character marker, built at run time, that is not a word and not a real credential.
fn marker() -> String {
    let id = fresh().simple().to_string();
    format!("Zq{}", &id[..10])
}

/// True when `marker` is still readable in the redacted text.
fn survives(redactor: &Redactor, text: &str, marker: &str) -> bool {
    redactor
        .redact_str(text)
        .expect("redacts")
        .output
        .contains(marker)
}

fn url(scheme: &str, user: &str, password: &str, host: &str) -> String {
    let (sep, colon, at) = ("://", ":", "@");
    format!("{scheme}{sep}{user}{colon}{password}{at}{host}")
}

/// Every shape in `shapes` is a URL a parser would read as having this password. Returns the names of
/// the shapes whose password is still in the output.
fn leaks(shapes: &[(&str, String)], marker: &str) -> Vec<String> {
    let redactor = policy_redactor();
    shapes
        .iter()
        .filter(|(_, text)| survives(&redactor, text, marker))
        .map(|(name, _)| (*name).to_owned())
        .collect()
}

/// A token body of 43 URL-safe characters, built at run time.
fn token_body() -> String {
    fresh()
        .simple()
        .to_string()
        .chars()
        .chain(fresh().simple().to_string().chars())
        .take(43)
        .collect()
}

/// Control group: ordinary and unusual shapes that the fix does handle.
#[test]
fn held_ordinary_and_unusual_url_shapes_lose_their_password() {
    let m = marker();
    let at = "@";
    let shapes = vec![
        ("plain", url("https", "svc", &m, "db.example/x")),
        (
            "scheme with a plus",
            url("postgres+tls", "svc", &m, "db.example:5432/x"),
        ),
        ("upper-case scheme", url("HTTPS", "svc", &m, "db.example/x")),
        ("ipv6 host", url("redis", "", &m, "[::1]:6379/0")),
        (
            "ipv6 host with a zone",
            url("redis", "svc", &m, "[fe80::1%25eth0]:6379/0"),
        ),
        (
            "at sign inside the password",
            url("https", "svc", &format!("ab{at}{m}"), "db.example/x"),
        ),
        (
            "percent-encoded at sign",
            url("https", "svc", &format!("{m}%40x"), "db.example/x"),
        ),
        (
            "percent-encoded host",
            url("https", "svc", &m, "%64b.example/x"),
        ),
        (
            "password then a query with an at sign",
            url("https", "svc", &m, "db.example/x?a=b@c"),
        ),
        (
            "in a JSON string",
            format!("{{\"u\":\"{}\"}}", url("https", "svc", &m, "db.example/x")),
        ),
        (
            "in angle brackets",
            format!("<{}>", url("https", "svc", &m, "db.example")),
        ),
        (
            "in a markdown link",
            format!("[x]({})", url("https", "svc", &m, "db.example")),
        ),
    ];
    let missed = leaks(&shapes, &m);
    assert!(missed.is_empty(), "a password survived in: {missed:?}");
}

/// RR-1 (fixed). The host part of the pattern accepts ASCII characters only (`[a-z0-9._~%:-]`), so a URL whose
/// host begins with a letter of another script (an internationalised domain name, which every URL
/// library accepts) is not recognised and its password is printed. The case-insensitive flag does not
/// help; the host class has no Unicode letter in it.
#[test]
fn rr_1_a_url_whose_host_is_an_internationalised_name_keeps_no_password() {
    let m = marker();
    let shapes = vec![
        (
            "japanese host",
            url("https", "admin", &m, "\u{4f8b}\u{3048}.jp/x"),
        ),
        (
            "german host starting with an umlaut",
            url("postgres", "app", &m, "\u{fc}nchen.example:5432/db"),
        ),
        (
            "cyrillic host",
            url(
                "https",
                "admin",
                &m,
                "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.\u{440}\u{444}/",
            ),
        ),
    ];
    let missed = leaks(&shapes, &m);
    assert!(
        missed.is_empty(),
        "the password is still readable in: {missed:?}"
    );
}

/// RR-2 (fixed). The pattern looked for a literal at sign. A JSON writer, a YAML double-quoted string or a
/// source literal may write it as `@` or `\x40`; the same bytes decode to a URL with a password
/// at the first consumer. The registered-secret path covers the encodings of a *known* secret
/// (`json_escaped`), but this pattern is the net for a secret nobody registered.
#[test]
fn rr_2_a_url_whose_at_sign_is_written_as_an_escape_keeps_no_password() {
    let m = marker();
    // Joined from pieces, so that no line of this file is itself a URL with a password (the
    // repository's secret scan decodes the first escape and would flag it).
    let (sep, colon) = ("://", ":");
    let (unicode_escape, hex_escape) = ("\\u0040", "\\x40");
    let shapes = vec![
        (
            "json unicode escape",
            format!("{{\"url\":\"https{sep}svc{colon}{m}{unicode_escape}db.example/x\"}}"),
        ),
        (
            "hex escape in a yaml or source string",
            format!("url: \"https{sep}svc{colon}{m}{hex_escape}db.example/x\""),
        ),
    ];
    let missed = leaks(&shapes, &m);
    assert!(
        missed.is_empty(),
        "the password is still readable in: {missed:?}"
    );
}

/// RR-3 (fixed). A data source name with no scheme (`user:password@tcp(host:3306)/db`, the form of the Go
/// MySQL driver and of several others) is not a URL, and the pattern starts at `scheme://`, so the
/// password is printed.
#[test]
fn rr_3_a_scheme_less_data_source_name_keeps_no_password() {
    let m = marker();
    let (colon, at) = (":", "@");
    let shapes = vec![(
        "go mysql dsn",
        format!("svc{colon}{m}{at}tcp(db.example:3306)/app?parseTime=true"),
    )];
    let missed = leaks(&shapes, &m);
    assert!(
        missed.is_empty(),
        "the password is still readable in: {missed:?}"
    );
}

/// RR-4 (fixed). The API token pattern begins with `\b`, so a token glued to a word character (a variable
/// name ending in an underscore, a digit, a letter) has no boundary in front of it and is not
/// matched. The job-token pattern shares the shape.
#[test]
fn rr_4_an_api_token_glued_to_a_word_character_is_recognised() {
    let redactor = policy_redactor();
    let token = format!("sfat{}{}", '_', token_body());
    let mut missed = Vec::new();
    for (name, text) in [
        ("after a letter", format!("x{token}")),
        ("after an underscore", format!("API_TOKEN_{token}")),
        ("after a digit", format!("1{token}")),
    ] {
        if !redactor.contains_secret(text.as_bytes()).expect("scans") {
            missed.push(name);
        }
    }
    assert!(missed.is_empty(), "not recognised: {missed:?}");
}

/// A token at a normal boundary is recognised, so RR-4 is about the boundary and nothing else.
#[test]
fn held_an_api_token_at_a_boundary_is_recognised() {
    let redactor = policy_redactor();
    let token = format!("sfat{}{}", '_', token_body());
    for text in [
        token.clone(),
        format!("credential={token}"),
        format!("{{\"t\":\"{token}\"}}"),
        format!("Bearer {token}"),
        format!("({token})"),
        format!("{token}-and-more"),
    ] {
        assert!(
            redactor.contains_secret(text.as_bytes()).expect("scans"),
            "{text}"
        );
    }
}
