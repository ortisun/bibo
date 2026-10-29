//! What the relay may connect to: the exact-host allowlist, the ranges it refuses after
//! resolution, and the reading of a `CONNECT` target.
//!
//! `docs/security/sandbox-policy.md` section 5.2: exact hostnames only (no wildcards, no suffix
//! matching, no IP literals), the relay resolves the name itself and refuses a private, loopback,
//! link-local, metadata or other internal address, and it connects to the address it checked.
//! Everything in this file is a function of its arguments; the network side is in `engine`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An address range, such as `10.0.0.0/8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Reads `address/prefix`. An address without a prefix is a single host.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max)?,
            None => max,
        };
        Some(Self { addr, prefix })
    }

    /// True when `ip` is inside the range. An address of the other family is never inside.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(range), IpAddr::V4(ip)) => {
                prefix_matches(&range.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(range), IpAddr::V6(ip)) => {
                prefix_matches(&range.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_matches(range: &[u8], ip: &[u8], prefix: u8) -> bool {
    let whole = usize::from(prefix / 8);
    let rest = prefix % 8;
    if range[..whole] != ip[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xff_u8 << (8 - rest);
    (range[whole] & mask) == (ip[whole] & mask)
}

/// The ranges the relay refuses after it resolved a name: `egress.proxy_rules.
/// reject_resolved_ip_ranges` of `policies/security.yaml`, and a few more that no registry or
/// model API lives in (this-network, multicast, reserved, the benchmarking range, the NAT64 and
/// transition prefixes).
///
/// 198.18.0.0/15 (RFC 2544) is the pool several VPN and proxy clients use for fake addresses on a
/// developer machine, so an answer in it can reach a local service. The sandbox suites make their
/// own Docker networks in the same range; those are networks of the test host, not targets of the
/// relay, which never connects to a network address of a job.
pub const DEFAULT_DENY_RANGES: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    // Beyond the policy list.
    "0.0.0.0/8",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "198.18.0.0/15",
    "::/128",
    "ff00::/8",
    "64:ff9b::/96",
    // NAT64 for local use (RFC 8215), 6to4 (RFC 3056) and Teredo (RFC 4380) carry an IPv4 address
    // inside an IPv6 one that a transition mechanism on the path may deliver to a private host.
    "64:ff9b:1::/48",
    "2002::/16",
    "2001::/32",
];

/// The hosts that no sandbox may reach, whatever else is configured
/// (`egress.never_allow_from_sandbox`).
pub const NEVER_ALLOWED_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "gist.github.com",
    "raw.githubusercontent.com",
    "pastebin.com",
    "transfer.sh",
];

/// The default ranges, parsed.
#[must_use]
pub fn default_deny_ranges() -> Vec<Cidr> {
    DEFAULT_DENY_RANGES
        .iter()
        .filter_map(|text| Cidr::parse(text))
        .collect()
}

/// The IPv4 addresses an IPv6 address stands for, in every form that embeds one:
///
/// * IPv4-mapped, `::ffff:a.b.c.d`;
/// * IPv4-compatible, `::a.b.c.d` (deprecated, but still delivered by some stacks);
/// * IPv4-translated, `::ffff:0:a.b.c.d` (SIIT);
/// * the well-known NAT64 prefix, `64:ff9b::a.b.c.d`;
/// * 6to4, `2002:AABB:CCDD::`, where the address is in bits 16 to 47.
///
/// The prefixes that carry one at another position (NAT64 for local use, Teredo) are refused whole
/// by [`DEFAULT_DENY_RANGES`].
#[must_use]
pub fn embedded_ipv4(address: &Ipv6Addr) -> Vec<Ipv4Addr> {
    let s = address.segments();
    let o = address.octets();
    let last = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    let mut found = Vec::new();
    if let Some(mapped) = address.to_ipv4_mapped() {
        found.push(mapped);
    }
    if s[..6].iter().all(|part| *part == 0) {
        found.push(last);
    }
    if s[..4].iter().all(|part| *part == 0) && s[4] == 0xffff && s[5] == 0 {
        found.push(last);
    }
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2..6].iter().all(|part| *part == 0) {
        found.push(last);
    }
    if s[0] == 0x2002 {
        found.push(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    found
}

/// True when `ip` is in any range, or when it is an IPv6 address that embeds an IPv4 address (see
/// [`embedded_ipv4`]) that is. `::ffff:127.0.0.1`, `::127.0.0.1` and `64:ff9b::7f00:1` are all
/// loopback.
#[must_use]
pub fn is_denied(ranges: &[Cidr], ip: IpAddr) -> bool {
    let embedded: Vec<IpAddr> = match ip {
        IpAddr::V6(v6) => embedded_ipv4(&v6).into_iter().map(IpAddr::V4).collect(),
        IpAddr::V4(_) => Vec::new(),
    };
    ranges.iter().any(|range| range.contains(ip))
        || embedded
            .iter()
            .any(|inner| ranges.iter().any(|range| range.contains(*inner)))
}

/// One host the relay may connect to, and the ports on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRule {
    /// The host, in lower case, with no trailing dot.
    pub host: String,
    /// The ports.
    pub ports: Vec<u16>,
}

impl HostRule {
    /// Reads `host:port`. The host goes through the same checks as a request target, so a rule
    /// cannot name an IP literal or a name that is not a plain host name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let target = parse_target(text).ok()?;
        Some(Self {
            host: target.host,
            ports: vec![target.port],
        })
    }
}

/// Why a target was refused. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Denial {
    /// The target is not `host:port`, or holds a character a host name cannot hold.
    #[error("malformed")]
    Malformed,
    /// The target carries a user name or a password (`name@host`).
    #[error("userinfo")]
    Userinfo,
    /// The host is an IP address in some spelling.
    #[error("ip_literal")]
    IpLiteral,
    /// The host is not on the list.
    #[error("not_allowlisted")]
    NotAllowlisted,
    /// The host is on the list, but not at this port.
    #[error("port_not_allowed")]
    PortNotAllowed,
    /// The host is one that no sandbox may reach.
    #[error("never_allowed")]
    NeverAllowed,
    /// The name did not resolve.
    #[error("resolve_failed")]
    ResolveFailed,
    /// The name resolved to an address in a refused range.
    #[error("resolved_to_denied_range")]
    ResolvedToDeniedRange,
    /// The method is not CONNECT.
    #[error("method_not_allowed")]
    MethodNotAllowed,
    /// The relay could not connect to the address it checked.
    #[error("upstream_unreachable")]
    UpstreamUnreachable,
    /// The relay is serving as many connections as it may.
    #[error("too_many_connections")]
    TooManyConnections,
    /// The job has moved all the bytes it may.
    #[error("quota_exhausted")]
    QuotaExhausted,
}

impl Denial {
    /// The name used in the decision log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Userinfo => "userinfo",
            Self::IpLiteral => "ip_literal",
            Self::NotAllowlisted => "not_allowlisted",
            Self::PortNotAllowed => "port_not_allowed",
            Self::NeverAllowed => "never_allowed",
            Self::ResolveFailed => "resolve_failed",
            Self::ResolvedToDeniedRange => "resolved_to_denied_range",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::UpstreamUnreachable => "upstream_unreachable",
            Self::TooManyConnections => "too_many_connections",
            Self::QuotaExhausted => "quota_exhausted",
        }
    }

    /// The status the client gets. A refusal of policy is 403; a name or a connection that failed
    /// is 502; a wrong method is 405.
    #[must_use]
    pub fn status(self) -> u16 {
        match self {
            Self::ResolveFailed | Self::UpstreamUnreachable => 502,
            Self::MethodNotAllowed => 405,
            Self::TooManyConnections => 503,
            _ => 403,
        }
    }
}

/// A `CONNECT` target that is well formed: a host name in the one spelling the relay compares
/// (lower case, no trailing dot) and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The normalised host name.
    pub host: String,
    /// The port.
    pub port: u16,
}

/// Reads the authority of a `CONNECT` request.
///
/// # Errors
/// [`Denial`]: `Userinfo` for `name@host`, `IpLiteral` for an address in any spelling, and
/// `Malformed` for anything else that is not a plain `host:port`.
pub fn parse_target(text: &str) -> Result<Target, Denial> {
    if text.is_empty() || text.len() > 300 {
        return Err(Denial::Malformed);
    }
    if text.contains('@') {
        return Err(Denial::Userinfo);
    }
    if text.starts_with('[') {
        // A bracketed IPv6 literal.
        return Err(Denial::IpLiteral);
    }
    if !text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b':')
    {
        return Err(Denial::Malformed);
    }
    let (host, port) = text.rsplit_once(':').ok_or(Denial::Malformed)?;
    if host.contains(':') {
        // An unbracketed IPv6 address.
        return Err(Denial::IpLiteral);
    }
    let port: u16 =
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Denial::Malformed);
        } else {
            port.parse().map_err(|_| Denial::Malformed)?
        };
    if port == 0 {
        return Err(Denial::Malformed);
    }
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if host.is_empty() || host.len() > 253 {
        return Err(Denial::Malformed);
    }
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err(Denial::Malformed);
        }
    }
    if looks_like_an_address(host, &labels) {
        return Err(Denial::IpLiteral);
    }
    Ok(Target {
        host: host.to_owned(),
        port,
    })
}

/// True for dotted quads, and for the spellings a resolver would also turn into an address: a
/// single decimal number (`2130706433`), a hexadecimal part (`0x7f.1`) and any name whose last
/// label is all digits (`1.2.3.4` and `1.2.4`).
fn looks_like_an_address(host: &str, labels: &[&str]) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() || host.parse::<Ipv6Addr>().is_ok() {
        return true;
    }
    let last = labels.last().copied().unwrap_or("");
    last.bytes().all(|b| b.is_ascii_digit()) || labels.iter().any(|l| l.starts_with("0x"))
}

/// The allowlist and the ranges, together.
#[derive(Debug, Clone)]
pub struct HostPolicy {
    allow: Vec<HostRule>,
    deny_ranges: Vec<Cidr>,
}

impl HostPolicy {
    /// A policy over these rules and these refused ranges.
    #[must_use]
    pub fn new(allow: Vec<HostRule>, deny_ranges: Vec<Cidr>) -> Self {
        Self { allow, deny_ranges }
    }

    /// The refused ranges.
    #[must_use]
    pub fn deny_ranges(&self) -> &[Cidr] {
        &self.deny_ranges
    }

    /// Checks a `CONNECT` target against the list, before any name is resolved.
    ///
    /// # Errors
    /// [`Denial`].
    pub fn check_target(&self, text: &str) -> Result<Target, Denial> {
        let target = parse_target(text)?;
        if NEVER_ALLOWED_HOSTS.contains(&target.host.as_str()) {
            return Err(Denial::NeverAllowed);
        }
        let rule = self
            .allow
            .iter()
            .find(|rule| rule.host == target.host)
            .ok_or(Denial::NotAllowlisted)?;
        if !rule.ports.contains(&target.port) {
            return Err(Denial::PortNotAllowed);
        }
        Ok(target)
    }

    /// Checks what a name resolved to. Every address must be allowed: one refused address in the
    /// answer refuses the name, so an answer that mixes a public and an internal address is not
    /// a way in. Returns the address to connect to, which is the first one.
    ///
    /// # Errors
    /// [`Denial::ResolveFailed`] for an empty answer and [`Denial::ResolvedToDeniedRange`].
    pub fn check_resolved(&self, answers: &[IpAddr]) -> Result<IpAddr, Denial> {
        let first = *answers.first().ok_or(Denial::ResolveFailed)?;
        if answers.iter().any(|ip| is_denied(&self.deny_ranges, *ip)) {
            return Err(Denial::ResolvedToDeniedRange);
        }
        Ok(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HostPolicy {
        HostPolicy::new(
            vec![
                HostRule::parse("registry.test:443").expect("a rule"),
                HostRule::parse("static.registry.test:443").expect("a rule"),
            ],
            default_deny_ranges(),
        )
    }

    #[test]
    fn the_allowed_host_in_its_plain_and_its_normalised_spellings_passes() {
        for text in [
            "registry.test:443",
            "REGISTRY.test:443",
            "Registry.TEST.:443",
            "registry.test.:443",
        ] {
            let target = policy().check_target(text).expect(text);
            assert_eq!(target.host, "registry.test");
            assert_eq!(target.port, 443);
        }
    }

    #[test]
    fn lookalikes_userinfo_literals_ports_and_malformed_targets_are_refused_with_a_reason() {
        let cases: &[(&str, Denial)] = &[
            ("evil.test:443", Denial::NotAllowlisted),
            ("registry.test.evil.test:443", Denial::NotAllowlisted),
            ("xregistry.test:443", Denial::NotAllowlisted),
            ("evil-registry.test:443", Denial::NotAllowlisted),
            ("sub.registry.test:443", Denial::NotAllowlisted),
            ("registry.test@evil.test:443", Denial::Userinfo),
            ("user:pw@registry.test:443", Denial::Userinfo),
            ("registry.test:443@evil.test:443", Denial::Userinfo),
            ("192.0.2.10:443", Denial::IpLiteral),
            ("127.0.0.1:443", Denial::IpLiteral),
            ("2130706433:443", Denial::IpLiteral),
            ("0x7f.1:443", Denial::IpLiteral),
            ("1.2.4:443", Denial::IpLiteral),
            ("[::1]:443", Denial::IpLiteral),
            ("::1:443", Denial::IpLiteral),
            ("registry.test:22", Denial::PortNotAllowed),
            ("registry.test:8443", Denial::PortNotAllowed),
            ("registry.test", Denial::Malformed),
            ("registry.test:", Denial::Malformed),
            ("registry.test:0", Denial::Malformed),
            ("registry.test:99999", Denial::Malformed),
            ("registry.test:44a", Denial::Malformed),
            ("registry..test:443", Denial::Malformed),
            ("registry.test..:443", Denial::Malformed),
            (".registry.test:443", Denial::Malformed),
            ("-registry.test:443", Denial::Malformed),
            ("registry.test/x:443", Denial::Malformed),
            ("registry.test%2e:443", Denial::Malformed),
            ("registry.test :443", Denial::Malformed),
            ("registry.tést:443", Denial::Malformed),
            (":443", Denial::Malformed),
            ("", Denial::Malformed),
            ("github.com:443", Denial::NeverAllowed),
            ("API.GitHub.com.:443", Denial::NeverAllowed),
            ("pastebin.com:443", Denial::NeverAllowed),
        ];
        for (text, expected) in cases {
            assert_eq!(
                policy().check_target(text).unwrap_err(),
                *expected,
                "target {text:?}"
            );
        }
    }

    #[test]
    fn a_never_allowed_host_stays_refused_even_when_the_list_names_it() {
        let policy = HostPolicy::new(
            vec![HostRule::parse("github.com:443").expect("a rule")],
            default_deny_ranges(),
        );
        assert_eq!(
            policy.check_target("github.com:443").unwrap_err(),
            Denial::NeverAllowed
        );
    }

    #[test]
    fn a_rule_cannot_name_an_address() {
        assert_eq!(HostRule::parse("10.0.0.5:443"), None);
        assert_eq!(HostRule::parse("registry.test"), None);
    }

    #[test]
    fn private_loopback_link_local_metadata_and_shared_ranges_are_refused_after_resolution() {
        let denied = [
            "127.0.0.1",
            "127.255.255.255",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.5",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            // The benchmarking range and the forms that carry a private IPv4 address inside an
            // IPv6 one (finding EGR-3).
            "198.18.0.1",
            "198.19.255.254",
            "::7f00:1",
            "::a00:1",
            "::c0a8:101",
            "::ffff:0:7f00:1",
            "64:ff9b:1::1",
            "64:ff9b:1:ffff::1",
            "2002:7f00:1::",
            "2002:a00:1::1",
            "2002:c0a8:101::",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
        ];
        let allowed = [
            "198.17.255.255",
            "198.20.0.0",
            "192.0.2.10",
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "2001:db8::1",
        ];
        let ranges = default_deny_ranges();
        for text in denied {
            let ip: IpAddr = text.parse().expect("an address");
            assert!(is_denied(&ranges, ip), "{text} must be refused");
        }
        for text in allowed {
            let ip: IpAddr = text.parse().expect("an address");
            assert!(!is_denied(&ranges, ip), "{text} must pass");
        }
    }

    #[test]
    fn one_refused_address_in_an_answer_refuses_the_name() {
        let public: IpAddr = "192.0.2.10".parse().expect("an address");
        let private: IpAddr = "10.0.0.5".parse().expect("an address");
        assert_eq!(policy().check_resolved(&[public]), Ok(public));
        assert_eq!(
            policy().check_resolved(&[public, private]),
            Err(Denial::ResolvedToDeniedRange)
        );
        assert_eq!(
            policy().check_resolved(&[private, public]),
            Err(Denial::ResolvedToDeniedRange)
        );
        assert_eq!(policy().check_resolved(&[]), Err(Denial::ResolveFailed));
    }

    #[test]
    fn cidr_arithmetic_handles_prefixes_that_are_not_whole_bytes() {
        let range = Cidr::parse("172.16.0.0/12").expect("a range");
        assert!(range.contains("172.16.0.0".parse().expect("ip")));
        assert!(range.contains("172.31.255.255".parse().expect("ip")));
        assert!(!range.contains("172.32.0.0".parse().expect("ip")));
        assert!(!range.contains("172.15.255.255".parse().expect("ip")));
        assert_eq!(Cidr::parse("10.0.0.0/33"), None);
        assert_eq!(Cidr::parse("nonsense"), None);
        let host = Cidr::parse("10.1.2.3").expect("a host");
        assert!(host.contains("10.1.2.3".parse().expect("ip")));
        assert!(!host.contains("10.1.2.4".parse().expect("ip")));
    }
}
