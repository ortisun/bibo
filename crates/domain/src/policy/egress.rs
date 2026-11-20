//! Network egress (`egress` of `policies/security.yaml`).
//!
//! A sandbox profile has an egress profile (`none`, `fetch_deps`, `agent` or `troubleshooter`),
//! and the egress
//! profile lists the hosts, ports and methods that may be reached. Everything else is refused
//! (`default_action: deny`). [`EgressPolicy::check`] decides one request on the text the proxy
//! sees; [`EgressPolicy::check_address`] decides the address the proxy resolved the host to, which
//! is the DNS-rebinding and internal-pivot defense and must be asked of the pinned address, never
//! of an earlier answer.
//!
//! * **The host is compared exactly** after lower-casing and removing one trailing dot. There are
//!   no wildcards (`allow_wildcards: false`). A host that is not a plain DNS name is refused: an
//!   IP address in any notation, a port, user information, a bracket, a non-ASCII character
//!   (write an internationalized name as punycode), an empty or over-long label.
//! * **The never-allowed list wins** over any allow entry, and the engine will not build from a
//!   policy that lists one host in both.
//! * **Ports and methods** must be on the entry that matched the host. Methods are case
//!   sensitive.
//! * **Addresses** in the ranges of `reject_resolved_ip_ranges` are refused, and so are
//!   the unspecified, loopback, multicast and broadcast addresses, `0.0.0.0/8`, the IPv4-mapped
//!   and IPv4-compatible forms of any refused IPv4 address, and the 6to4 and NAT64 forms that
//!   carry one.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::security::SecurityPolicy;
use super::{BuildError, RuleRef, SandboxProfileKind};

/// An egress profile (`egress.profiles`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EgressProfileId {
    /// No network.
    None,
    /// Package registries, for the dependency fetch.
    FetchDeps,
    /// The model broker only.
    Agent,
    /// The model broker and the MCP gateway (ADR 0021). Only the `troubleshooter` sandbox profile
    /// may use it.
    Troubleshooter,
}

/// The id of the one egress entry that reaches the troubleshooter's MCP gateway. It may appear in
/// the `troubleshooter` egress profile and in no other (ADR 0021, Decision 5).
pub const MCP_GATEWAY_ENTRY: &str = "mcp_gateway";

impl EgressProfileId {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "none" => Some(Self::None),
            "fetch_deps" => Some(Self::FetchDeps),
            "agent" => Some(Self::Agent),
            "troubleshooter" => Some(Self::Troubleshooter),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FetchDeps => "fetch_deps",
            Self::Agent => "agent",
            Self::Troubleshooter => "troubleshooter",
        }
    }
}

/// Why a host was not accepted as a plain DNS name. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostRefusal {
    /// The host is empty or longer than 253 bytes.
    #[error("the host is empty or too long")]
    Length,
    /// A label is empty, longer than 63 bytes, or begins or ends with `-`.
    #[error("the host has an invalid label")]
    Label,
    /// A character outside letters, digits, `-` and `.`: a port, user information, a bracket, a
    /// wildcard, a space, or a non-ASCII character.
    #[error("the host has a character that is not allowed in a plain DNS name")]
    Character,
    /// The host is an IP address in some notation.
    #[error("the host is an IP address")]
    IpAddress,
}

/// Why an egress request was refused. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EgressDenial {
    /// The host is not a plain DNS name.
    #[error("the host is not a plain DNS name")]
    MalformedHost(HostRefusal),
    /// The host is on the never-allowed list.
    #[error("the host may never be reached from a sandbox")]
    NeverAllowed,
    /// The profile has no entry for the host.
    #[error("the profile has no entry for the host")]
    HostNotAllowed,
    /// The entry does not list the port.
    #[error("the entry does not list the port")]
    PortNotAllowed,
    /// The entry does not list the method.
    #[error("the entry does not list the method")]
    MethodNotAllowed,
    /// The resolved address is in a refused range.
    #[error("the resolved address is in a refused range")]
    AddressRefused,
}

/// The answer for one egress request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressVerdict {
    /// The request may go out.
    Allowed {
        /// The entry that allowed it, such as `egress.profiles.fetch_deps:crates_index`.
        rule: RuleRef,
    },
    /// Refused.
    Denied {
        /// Why.
        reason: EgressDenial,
        /// The list or entry behind it.
        rule: RuleRef,
    },
}

impl EgressVerdict {
    /// True when the request may go out.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }
}

/// Writes a host as the comparison form, or says why it is not a plain DNS name.
///
/// # Errors
/// The [`HostRefusal`] for the first rule the text breaks.
pub fn normalize_host(host: &str) -> Result<String, HostRefusal> {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(HostRefusal::Length);
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(HostRefusal::Character);
    }
    let lowered = trimmed.to_ascii_lowercase();
    let mut last = "";
    for label in lowered.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return Err(HostRefusal::Label);
        }
        last = label;
    }
    // `2130706433`, `0x7f.1`, `127.1` and `127.0.0.1` are all IPv4 addresses to a resolver.
    if last.bytes().all(|b| b.is_ascii_digit()) || last.starts_with("0x") {
        return Err(HostRefusal::IpAddress);
    }
    Ok(lowered)
}

#[derive(Debug)]
struct Allow {
    id: String,
    host: String,
    ports: BTreeSet<u16>,
    methods: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = text.split_once('/')?;
        let addr: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        fn leading_equal(a: &[u8], b: &[u8], bits: u8) -> bool {
            let whole = usize::from(bits / 8);
            let rest = bits % 8;
            if a.get(..whole) != b.get(..whole) {
                return false;
            }
            if rest == 0 {
                return true;
            }
            let mask = 0xffu8 << (8 - rest);
            match (a.get(whole), b.get(whole)) {
                (Some(x), Some(y)) => x & mask == y & mask,
                _ => false,
            }
        }
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                leading_equal(&net.octets(), &candidate.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                leading_equal(&net.octets(), &candidate.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// Ranges refused whatever the policy lists, because a sandbox has no business there.
const BUILTIN_REFUSED: [&str; 12] = [
    "0.0.0.0/8",
    "127.0.0.0/8",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "ff00::/8",
    "::/96",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "2002::/16",
    "fe80::/10",
];

/// The egress rules of one security policy.
#[derive(Debug)]
pub struct EgressPolicy {
    profiles: BTreeMap<EgressProfileId, Vec<Allow>>,
    never_allowed: BTreeSet<String>,
    refused_ranges: Vec<Cidr>,
    sandbox_to_egress: BTreeMap<SandboxProfileKind, EgressProfileId>,
    max_bytes_per_job: u64,
}

fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = ip.octets();
    let low = |from: usize| Ipv4Addr::new(o[from], o[from + 1], o[from + 2], o[from + 3]);
    // IPv4-mapped, IPv4-compatible, NAT64 and 6to4.
    if o[..10].iter().all(|b| *b == 0) && o[10] == 0xff && o[11] == 0xff {
        return Some(low(12));
    }
    if o[..12].iter().all(|b| *b == 0) {
        return Some(low(12));
    }
    if o[..4] == [0x00, 0x64, 0xff, 0x9b] && o[4..12].iter().all(|b| *b == 0) {
        return Some(low(12));
    }
    if o[0] == 0x20 && o[1] == 0x02 {
        return Some(low(2));
    }
    None
}

impl EgressPolicy {
    /// Reads the egress rules of `policy`.
    ///
    /// # Errors
    /// A [`BuildError`] when the policy allows wildcards, an allowed host is not a plain DNS
    /// name, a host is both allowed and never allowed, an address range does not parse, or a
    /// sandbox profile names an egress profile that does not exist.
    pub fn from_policy(policy: &SecurityPolicy) -> Result<Self, BuildError> {
        let egress = &policy.egress;
        if egress.allow_wildcards {
            return Err(BuildError::ProtectionDisabled {
                key: "egress.allow_wildcards",
                found: "true".to_owned(),
            });
        }
        let mut never_allowed = BTreeSet::new();
        for entry in &egress.never_allow_from_sandbox {
            let host = normalize_host(&entry.host).map_err(|e| BuildError::UnknownValue {
                key: "egress.never_allow_from_sandbox.host",
                found: format!("{} ({e})", entry.host),
            })?;
            never_allowed.insert(host);
        }
        let mut profiles = BTreeMap::new();
        let listed = [
            (EgressProfileId::None, &egress.profiles.none),
            (EgressProfileId::FetchDeps, &egress.profiles.fetch_deps),
            (EgressProfileId::Agent, &egress.profiles.agent),
            (
                EgressProfileId::Troubleshooter,
                &egress.profiles.troubleshooter,
            ),
        ];
        for (id, profile) in listed {
            let mut allows = Vec::new();
            for a in &profile.allow {
                if a.id == MCP_GATEWAY_ENTRY && id != EgressProfileId::Troubleshooter {
                    return Err(BuildError::Contradiction(format!(
                        "egress profile {} lists {MCP_GATEWAY_ENTRY}, which only the troubleshooter profile may reach",
                        id.as_str()
                    )));
                }
                let host = normalize_host(&a.host).map_err(|e| BuildError::UnknownValue {
                    key: "egress.profiles.allow.host",
                    found: format!("{} ({e})", a.host),
                })?;
                if never_allowed.contains(&host) {
                    return Err(BuildError::Contradiction(format!(
                        "egress profile {} allows {host}, which egress.never_allow_from_sandbox lists",
                        id.as_str()
                    )));
                }
                allows.push(Allow {
                    id: a.id.clone(),
                    host,
                    ports: a.ports.iter().copied().collect(),
                    methods: a.methods.iter().cloned().collect(),
                });
            }
            if id == EgressProfileId::None && !allows.is_empty() {
                return Err(BuildError::Contradiction(
                    "the egress profile `none` allows a host".to_owned(),
                ));
            }
            profiles.insert(id, allows);
        }

        let mut refused_ranges = Vec::new();
        for text in egress
            .proxy_rules
            .reject_resolved_ip_ranges
            .iter()
            .map(String::as_str)
            .chain(BUILTIN_REFUSED)
        {
            refused_ranges.push(Cidr::parse(text).ok_or_else(|| BuildError::UnknownValue {
                key: "egress.proxy_rules.reject_resolved_ip_ranges",
                found: text.to_owned(),
            })?);
        }

        let mut sandbox_to_egress = BTreeMap::new();
        let sandbox = &policy.sandbox.profiles;
        for (kind, profile) in [
            (SandboxProfileKind::Agent, &sandbox.agent),
            (SandboxProfileKind::Verify, &sandbox.verify),
            (SandboxProfileKind::FetchDeps, &sandbox.fetch_deps),
            (SandboxProfileKind::Troubleshooter, &sandbox.troubleshooter),
        ] {
            let id = EgressProfileId::parse(&profile.egress_profile).ok_or_else(|| {
                BuildError::UnknownValue {
                    key: "sandbox.profiles.egress_profile",
                    found: profile.egress_profile.clone(),
                }
            })?;
            if (id == EgressProfileId::Troubleshooter)
                != (kind == SandboxProfileKind::Troubleshooter)
            {
                return Err(BuildError::Contradiction(format!(
                    "sandbox profile {} uses egress profile {}; the troubleshooter egress profile belongs to the troubleshooter sandbox profile alone",
                    kind.as_str(),
                    id.as_str()
                )));
            }
            sandbox_to_egress.insert(kind, id);
        }
        Ok(Self {
            profiles,
            never_allowed,
            refused_ranges,
            sandbox_to_egress,
            max_bytes_per_job: egress.proxy_rules.max_bytes_per_job,
        })
    }

    /// The egress profile a sandbox profile uses.
    #[must_use]
    pub fn profile_of(&self, sandbox: SandboxProfileKind) -> EgressProfileId {
        self.sandbox_to_egress
            .get(&sandbox)
            .copied()
            .unwrap_or(EgressProfileId::None)
    }

    /// The most bytes one job may transfer.
    #[must_use]
    pub fn max_bytes_per_job(&self) -> u64 {
        self.max_bytes_per_job
    }

    /// Decides one request: the host as the client wrote it, the port, and the method.
    #[must_use]
    pub fn check(
        &self,
        profile: EgressProfileId,
        host: &str,
        port: u16,
        method: &str,
    ) -> EgressVerdict {
        let area = "egress";
        let denied = |reason, rule: RuleRef| EgressVerdict::Denied { reason, rule };
        let host = match normalize_host(host) {
            Ok(h) => h,
            Err(refusal) => {
                return denied(
                    EgressDenial::MalformedHost(refusal),
                    RuleRef::new(area, "allow_wildcards"),
                );
            }
        };
        if self.never_allowed.contains(&host) {
            return denied(
                EgressDenial::NeverAllowed,
                RuleRef::new(area, "never_allow_from_sandbox"),
            );
        }
        let entries: &[Allow] = self.profiles.get(&profile).map_or(&[], Vec::as_slice);
        let Some(entry) = entries.iter().find(|a| a.host == host) else {
            return denied(
                EgressDenial::HostNotAllowed,
                RuleRef::new("egress.profiles", profile.as_str()),
            );
        };
        let rule = RuleRef::new(
            "egress.profiles",
            format!("{}:{}", profile.as_str(), entry.id),
        );
        if !entry.ports.contains(&port) {
            return denied(EgressDenial::PortNotAllowed, rule);
        }
        if !entry.methods.contains(method) {
            return denied(EgressDenial::MethodNotAllowed, rule);
        }
        EgressVerdict::Allowed { rule }
    }

    /// Decides whether the proxy may connect to the address a name resolved to.
    #[must_use]
    pub fn check_address(&self, ip: IpAddr) -> EgressVerdict {
        let refuse = || EgressVerdict::Denied {
            reason: EgressDenial::AddressRefused,
            rule: RuleRef::new("egress.proxy_rules", "reject_resolved_ip_ranges"),
        };
        let mut candidates = vec![ip];
        if let IpAddr::V6(v6) = ip
            && let Some(v4) = embedded_v4(v6)
        {
            candidates.push(IpAddr::V4(v4));
        }
        if candidates.iter().any(|candidate| {
            self.refused_ranges.iter().any(|c| c.contains(*candidate))
                || matches!(candidate, IpAddr::V4(v4) if v4.is_broadcast() || v4.is_unspecified())
        }) {
            return refuse();
        }
        EgressVerdict::Allowed {
            rule: RuleRef::new("egress.proxy_rules", "reject_resolved_ip_ranges"),
        }
    }
}
