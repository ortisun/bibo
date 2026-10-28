//! Egress: hosts, ports, methods and resolved addresses.

use std::net::IpAddr;
use std::sync::LazyLock;

use factory_domain::policy::SandboxProfileKind;
use factory_domain::policy::egress::{
    EgressDenial, EgressPolicy, EgressProfileId, EgressVerdict, HostRefusal, normalize_host,
};
use proptest::prelude::*;

use crate::support::{security, security_from, security_json};

fn policy() -> &'static EgressPolicy {
    static POLICY: LazyLock<EgressPolicy> =
        LazyLock::new(|| EgressPolicy::from_policy(&security()).expect("the real policy builds"));
    &POLICY
}

fn denial(verdict: &EgressVerdict) -> Option<EgressDenial> {
    match verdict {
        EgressVerdict::Denied { reason, .. } => Some(*reason),
        EgressVerdict::Allowed { .. } => None,
    }
}

#[test]
fn the_sandbox_profiles_use_the_egress_profiles_the_policy_names() {
    assert_eq!(
        policy().profile_of(SandboxProfileKind::Agent),
        EgressProfileId::Agent
    );
    assert_eq!(
        policy().profile_of(SandboxProfileKind::FetchDeps),
        EgressProfileId::FetchDeps
    );
    assert_eq!(
        policy().profile_of(SandboxProfileKind::Verify),
        EgressProfileId::None
    );
}

#[test]
fn hosts_ports_and_methods_are_checked_against_the_profile_entry() {
    use EgressProfileId::{Agent, FetchDeps, None as Nothing};
    let table = [
        (FetchDeps, "index.crates.io", 443, "GET", None),
        (FetchDeps, "INDEX.CRATES.IO.", 443, "HEAD", None),
        (FetchDeps, "registry.npmjs.org", 443, "GET", None),
        (FetchDeps, "proxy.golang.org", 443, "GET", None),
        (
            FetchDeps,
            "index.crates.io",
            443,
            "POST",
            Some(EgressDenial::MethodNotAllowed),
        ),
        (
            FetchDeps,
            "index.crates.io",
            443,
            "get",
            Some(EgressDenial::MethodNotAllowed),
        ),
        (
            FetchDeps,
            "index.crates.io",
            80,
            "GET",
            Some(EgressDenial::PortNotAllowed),
        ),
        (
            FetchDeps,
            "index.crates.io",
            8443,
            "GET",
            Some(EgressDenial::PortNotAllowed),
        ),
        (
            FetchDeps,
            "evil.example",
            443,
            "GET",
            Some(EgressDenial::HostNotAllowed),
        ),
        (
            FetchDeps,
            "index.crates.io.evil.example",
            443,
            "GET",
            Some(EgressDenial::HostNotAllowed),
        ),
        (
            FetchDeps,
            "crates.io",
            443,
            "GET",
            Some(EgressDenial::HostNotAllowed),
        ),
        (
            FetchDeps,
            "sub.index.crates.io",
            443,
            "GET",
            Some(EgressDenial::HostNotAllowed),
        ),
        // The profile decides: a registry is not reachable from the agent profile.
        (
            Agent,
            "index.crates.io",
            443,
            "GET",
            Some(EgressDenial::HostNotAllowed),
        ),
        (Agent, "model-broker.sandbox.internal", 8443, "POST", None),
        (
            Agent,
            "model-broker.sandbox.internal",
            8443,
            "GET",
            Some(EgressDenial::MethodNotAllowed),
        ),
        (
            Agent,
            "model-broker.sandbox.internal",
            443,
            "POST",
            Some(EgressDenial::PortNotAllowed),
        ),
        (
            Agent,
            "api.anthropic.com",
            443,
            "POST",
            Some(EgressDenial::HostNotAllowed),
        ),
        // Never allowed, in every profile.
        (
            FetchDeps,
            "github.com",
            443,
            "GET",
            Some(EgressDenial::NeverAllowed),
        ),
        (
            Agent,
            "API.GITHUB.COM",
            443,
            "POST",
            Some(EgressDenial::NeverAllowed),
        ),
        (
            Nothing,
            "pastebin.com",
            443,
            "GET",
            Some(EgressDenial::NeverAllowed),
        ),
        (
            Nothing,
            "transfer.sh.",
            443,
            "PUT",
            Some(EgressDenial::NeverAllowed),
        ),
        // The `none` profile reaches nothing.
        (
            Nothing,
            "index.crates.io",
            443,
            "GET",
            Some(EgressDenial::HostNotAllowed),
        ),
    ];
    for (profile, host, port, method, expected) in table {
        let verdict = policy().check(profile, host, port, method);
        assert_eq!(
            denial(&verdict),
            expected,
            "{profile:?} {host} {port} {method}: {verdict:?}"
        );
    }
}

#[test]
fn a_host_that_is_not_a_plain_dns_name_is_refused() {
    use HostRefusal::{Character, IpAddress, Label, Length};
    let too_long = "a".repeat(254);
    let long_label = format!("{}.io", "a".repeat(64));
    let table = [
        ("", Length),
        (too_long.as_str(), Length),
        ("*.crates.io", Character),
        ("index.crates.io:443", Character),
        ("user@index.crates.io", Character),
        ("[::1]", Character),
        ("index.crates.io/path", Character),
        ("index.crates.io ", Character),
        ("ind\u{435}x.crates.io", Character),
        ("index.cr\u{2024}tes.io", Character),
        ("index..crates.io", Label),
        ("-index.crates.io", Label),
        ("index-.crates.io", Label),
        ("index.crates.io..", Label),
        (long_label.as_str(), Label),
        ("127.0.0.1", IpAddress),
        ("2130706433", IpAddress),
        ("0x7f.1", IpAddress),
        ("127.1", IpAddress),
        ("10.0.0.1.", IpAddress),
    ];
    for (host, refusal) in table {
        assert_eq!(normalize_host(host), Err(refusal), "{host:?}");
        let verdict = policy().check(EgressProfileId::FetchDeps, host, 443, "GET");
        assert_eq!(
            denial(&verdict),
            Some(EgressDenial::MalformedHost(refusal)),
            "{host:?}"
        );
    }
}

#[test]
fn a_resolved_address_in_a_refused_range_is_never_connected_to() {
    let refused = [
        "127.0.0.1",
        "127.255.255.254",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "100.127.255.255",
        "0.0.0.0",
        "0.1.2.3",
        "224.0.0.1",
        "255.255.255.255",
        "240.0.0.1",
        "::1",
        "::",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "::127.0.0.1",
        "64:ff9b::7f00:1",
        "2002:7f00:1::",
        "2002:a9fe:a9fe::1",
    ];
    for text in refused {
        let ip: IpAddr = text.parse().expect("address");
        assert_eq!(
            denial(&policy().check_address(ip)),
            Some(EgressDenial::AddressRefused),
            "{text}"
        );
    }
    for text in [
        "8.8.8.8",
        "140.82.112.3",
        "151.101.1.1",
        "172.32.0.1",
        "100.128.0.1",
        "2606:4700::1",
        "2a00:1450::1",
    ] {
        let ip: IpAddr = text.parse().expect("address");
        assert!(policy().check_address(ip).is_allowed(), "{text}");
    }
}

#[test]
fn an_allow_entry_for_a_never_allowed_host_or_a_wildcard_does_not_build() {
    let mut json = security_json();
    json["egress"]["profiles"]["fetch_deps"]["allow"][0]["host"] = "github.com".into();
    assert!(EgressPolicy::from_policy(&security_from(json)).is_err());
    let mut json = security_json();
    json["egress"]["profiles"]["fetch_deps"]["allow"][0]["host"] = "*.crates.io".into();
    assert!(EgressPolicy::from_policy(&security_from(json)).is_err());
    let mut json = security_json();
    json["egress"]["allow_wildcards"] = true.into();
    assert!(EgressPolicy::from_policy(&security_from(json)).is_err());
    let mut json = security_json();
    json["egress"]["profiles"]["none"]["allow"] = serde_json::json!([{
        "id": "x", "host": "example.org", "ports": [443], "methods": ["GET"],
        "justification": "x", "review_by": "2027-01-01"
    }]);
    assert!(EgressPolicy::from_policy(&security_from(json)).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 600, ..ProptestConfig::default() })]

    #[test]
    fn host_normalization_is_total_and_its_output_is_a_plain_lowercase_name(host in "\\PC{0,80}|[a-zA-Z0-9.:@*\\[\\]/ -]{0,60}") {
        if let Ok(name) = normalize_host(&host) {
            prop_assert!(name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'));
            prop_assert!(!name.starts_with('.') && !name.ends_with('.') && !name.contains(".."));
            prop_assert_eq!(normalize_host(&name), Ok(name.clone()));
            prop_assert!(name.parse::<IpAddr>().is_err());
        }
    }

    #[test]
    fn nothing_but_a_listed_entry_is_ever_allowed(
        host in "[a-z0-9.-]{1,40}",
        port in any::<u16>(),
        method in "[A-Z]{2,7}",
        profile in prop::sample::select(vec![EgressProfileId::None, EgressProfileId::FetchDeps, EgressProfileId::Agent]),
    ) {
        let verdict = policy().check(profile, &host, port, &method);
        if verdict.is_allowed() {
            let listed = [
                "index.crates.io", "static.crates.io", "registry.npmjs.org", "pypi.org",
                "files.pythonhosted.org", "proxy.golang.org", "sum.golang.org",
                "model-broker.sandbox.internal",
            ];
            prop_assert!(listed.contains(&normalize_host(&host).expect("allowed hosts normalize").as_str()));
            prop_assert!(profile != EgressProfileId::None);
        }
    }

    #[test]
    fn address_checks_are_total_and_refuse_every_private_v4(a in any::<u8>(), b in any::<u8>(), c in any::<u8>(), d in any::<u8>()) {
        let ip = IpAddr::from([a, b, c, d]);
        let private = a == 10 || a == 127 || a == 0 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
            || (a == 169 && b == 254) || (a == 100 && (64..=127).contains(&b)) || a >= 224;
        if private {
            prop_assert!(!policy().check_address(ip).is_allowed());
            // The same address wrapped as IPv4-mapped IPv6 is refused too.
            let mapped = IpAddr::V6(std::net::Ipv4Addr::new(a, b, c, d).to_ipv6_mapped());
            prop_assert!(!policy().check_address(mapped).is_allowed());
        }
    }
}
