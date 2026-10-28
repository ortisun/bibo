//! The configuration of the relay: what the supervisor puts on its command line.
//!
//! The configuration comes from the supervisor as arguments, never from the sandbox, and a bad
//! one stops the program before it accepts a connection (`infra/sandbox-images/egress-sidecar/
//! README.md`: it fails closed). Nothing is guessed, there is no default for what the relay may
//! reach, and an unknown or repeated flag is an error.
//!
//! ```text
//! factory-egress-sidecar --mode broker  --listen 0.0.0.0:8443 --upstream 172.17.0.1:9443 \
//!                        [--max-bytes N] [--job ID] [--max-connections N]
//! factory-egress-sidecar --mode connect --listen 0.0.0.0:3128 --allow index.crates.io:443 \
//!                        --allow static.crates.io:443 [--max-bytes N] [--job ID]
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use super::policy::{Cidr, HostRule, default_deny_ranges};

/// The per-job transfer cap, `egress.proxy_rules.max_bytes_per_job`: 2 GiB.
pub const DEFAULT_MAX_BYTES: u64 = 2_147_483_648;

/// What the relay does with a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// The `agent` profile: every connection is relayed to the broker at one fixed address.
    /// Nothing the sandbox sends is read, and no name is resolved: the address is pinned by the
    /// supervisor.
    Broker {
        /// The broker's address.
        upstream: SocketAddr,
    },
    /// The `fetch_deps` profile: a `CONNECT` proxy for an exact-host allowlist. Names are
    /// resolved here, checked and pinned.
    Connect {
        /// The hosts and ports that may be reached.
        allow: Vec<HostRule>,
    },
}

/// Everything the relay is started with.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Where to listen.
    pub listen: SocketAddr,
    /// What to do with a connection.
    pub mode: Mode,
    /// The most bytes the job may move through the relay, both directions together.
    pub max_bytes: u64,
    /// The most connections served at once.
    pub max_connections: usize,
    /// How long to wait to connect upstream.
    pub connect_timeout: Duration,
    /// How long a connection may be silent in both directions before it is closed.
    pub idle_timeout: Duration,
    /// How long the sandbox side may take to send its `CONNECT` line.
    pub head_timeout: Duration,
    /// The ranges refused after a name is resolved.
    pub deny_ranges: Vec<Cidr>,
    /// The job, as the supervisor names it, for the decision log. Never read for a decision.
    pub job: Option<String>,
}

/// Why the arguments were not accepted. The messages hold no value the caller passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// A flag the relay does not know.
    #[error("unknown argument")]
    UnknownArgument,
    /// A flag that was given twice.
    #[error("repeated argument")]
    Repeated,
    /// A flag with no value.
    #[error("missing value")]
    MissingValue,
    /// A value that cannot be used.
    #[error("bad value")]
    BadValue,
    /// A required flag is absent.
    #[error("missing required argument")]
    MissingRequired,
    /// A flag that belongs to the other mode.
    #[error("argument does not belong to this mode")]
    WrongMode,
}

fn once<'a>(slot: &mut Option<&'a str>, value: &'a str) -> Result<(), ConfigError> {
    if slot.is_some() {
        return Err(ConfigError::Repeated);
    }
    *slot = Some(value);
    Ok(())
}

fn parse_num<T: std::str::FromStr>(text: &str) -> Result<T, ConfigError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ConfigError::BadValue);
    }
    text.parse().map_err(|_| ConfigError::BadValue)
}

impl RelayConfig {
    /// Reads the command line, without the program name.
    ///
    /// # Errors
    /// [`ConfigError`].
    pub fn from_args(args: &[String]) -> Result<Self, ConfigError> {
        let mut mode = None;
        let mut listen = None;
        let mut upstream = None;
        let mut max_bytes = None;
        let mut max_connections = None;
        let mut job = None;
        let mut connect_timeout = None;
        let mut idle_timeout = None;
        let mut allow: Vec<&str> = Vec::new();
        let mut extra_deny: Vec<&str> = Vec::new();

        let mut iter = args.iter();
        while let Some(flag) = iter.next() {
            let mut value = || {
                iter.next()
                    .map(String::as_str)
                    .ok_or(ConfigError::MissingValue)
            };
            match flag.as_str() {
                "--mode" => once(&mut mode, value()?)?,
                "--listen" => once(&mut listen, value()?)?,
                "--upstream" => once(&mut upstream, value()?)?,
                "--max-bytes" => once(&mut max_bytes, value()?)?,
                "--max-connections" => once(&mut max_connections, value()?)?,
                "--job" => once(&mut job, value()?)?,
                "--connect-timeout-secs" => once(&mut connect_timeout, value()?)?,
                "--idle-timeout-secs" => once(&mut idle_timeout, value()?)?,
                "--allow" => allow.push(value()?),
                "--deny-range" => extra_deny.push(value()?),
                _ => return Err(ConfigError::UnknownArgument),
            }
        }

        let listen: SocketAddr = listen
            .ok_or(ConfigError::MissingRequired)?
            .parse()
            .map_err(|_| ConfigError::BadValue)?;
        // The relay listens on a port of 1024 or higher (the image README).
        if listen.port() < 1024 {
            return Err(ConfigError::BadValue);
        }
        let mode = match mode.ok_or(ConfigError::MissingRequired)? {
            "broker" => {
                if !allow.is_empty() || !extra_deny.is_empty() {
                    return Err(ConfigError::WrongMode);
                }
                let upstream: SocketAddr = upstream
                    .ok_or(ConfigError::MissingRequired)?
                    .parse()
                    .map_err(|_| ConfigError::BadValue)?;
                if upstream.port() == 0
                    || upstream.ip().is_unspecified()
                    || upstream.ip().is_multicast()
                    || upstream == listen
                {
                    return Err(ConfigError::BadValue);
                }
                Mode::Broker { upstream }
            }
            "connect" => {
                if upstream.is_some() {
                    return Err(ConfigError::WrongMode);
                }
                if allow.is_empty() {
                    return Err(ConfigError::MissingRequired);
                }
                let mut rules: Vec<HostRule> = Vec::new();
                for text in allow {
                    let rule = HostRule::parse(text).ok_or(ConfigError::BadValue)?;
                    match rules.iter_mut().find(|r| r.host == rule.host) {
                        Some(existing) => existing.ports.extend(rule.ports),
                        None => rules.push(rule),
                    }
                }
                Mode::Connect { allow: rules }
            }
            _ => return Err(ConfigError::BadValue),
        };

        // Extra refused ranges add to the defaults. Nothing removes one.
        let mut deny_ranges = default_deny_ranges();
        for text in extra_deny {
            deny_ranges.push(Cidr::parse(text).ok_or(ConfigError::BadValue)?);
        }

        let max_bytes = match max_bytes {
            Some(text) => parse_num::<u64>(text)?,
            None => DEFAULT_MAX_BYTES,
        };
        if max_bytes == 0 {
            return Err(ConfigError::BadValue);
        }
        let max_connections = match max_connections {
            Some(text) => parse_num::<usize>(text)?,
            None => 64,
        };
        if !(1..=1024).contains(&max_connections) {
            return Err(ConfigError::BadValue);
        }
        let secs = |text: Option<&str>, default: u64| -> Result<Duration, ConfigError> {
            let value = match text {
                Some(text) => parse_num::<u64>(text)?,
                None => default,
            };
            if !(1..=3600).contains(&value) {
                return Err(ConfigError::BadValue);
            }
            Ok(Duration::from_secs(value))
        };
        let job = match job {
            Some(text) => {
                // The job label goes into the decision log. Keep it a plain token.
                if text.is_empty()
                    || text.len() > 64
                    || !text
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(ConfigError::BadValue);
                }
                Some(text.to_owned())
            }
            None => None,
        };
        Ok(Self {
            listen,
            mode,
            max_bytes,
            max_connections,
            connect_timeout: secs(connect_timeout, 10)?,
            idle_timeout: secs(idle_timeout, 600)?,
            head_timeout: Duration::from_secs(10),
            deny_ranges,
            job,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_broker_command_line_is_read() {
        let config = RelayConfig::from_args(&args(
            "--mode broker --listen 0.0.0.0:8443 --upstream 172.17.0.1:9443 --max-bytes 1000 --job job-1",
        ))
        .expect("a config");
        assert_eq!(
            config.mode,
            Mode::Broker {
                upstream: "172.17.0.1:9443".parse().expect("address")
            }
        );
        assert_eq!(config.max_bytes, 1000);
        assert_eq!(config.job.as_deref(), Some("job-1"));
        assert_eq!(config.max_connections, 64);
    }

    #[test]
    fn a_connect_command_line_merges_ports_of_one_host() {
        let config = RelayConfig::from_args(&args(
            "--mode connect --listen 0.0.0.0:3128 --allow index.crates.io:443 --allow static.crates.io:443 --allow index.crates.io:8443",
        ))
        .expect("a config");
        let Mode::Connect { allow } = config.mode else {
            panic!("connect mode");
        };
        assert_eq!(allow.len(), 2);
        assert_eq!(allow[0].host, "index.crates.io");
        assert_eq!(allow[0].ports, vec![443, 8443]);
        assert_eq!(config.max_bytes, DEFAULT_MAX_BYTES);
    }

    #[test]
    fn anything_unclear_stops_the_program_before_it_listens() {
        let bad = [
            "",
            "--mode broker --listen 0.0.0.0:8443",
            "--mode broker --upstream 172.17.0.1:9443",
            "--mode connect --listen 0.0.0.0:3128",
            "--mode proxy --listen 0.0.0.0:3128",
            "--mode broker --listen 0.0.0.0:80 --upstream 172.17.0.1:9443",
            "--mode broker --listen 0.0.0.0:8443 --upstream localhost:9443",
            "--mode broker --listen 0.0.0.0:8443 --upstream 0.0.0.0:9443",
            "--mode broker --listen 0.0.0.0:8443 --upstream 0.0.0.0:8443",
            "--mode broker --listen 0.0.0.0:8443 --upstream 10.0.0.1:0",
            "--mode broker --listen 0.0.0.0:8443 --upstream 10.0.0.1:9 --listen 0.0.0.0:8444",
            "--mode broker --listen 0.0.0.0:8443 --upstream 10.0.0.1:9 --allow a.test:443",
            "--mode broker --listen 0.0.0.0:8443 --upstream 10.0.0.1:9 --max-bytes 0",
            "--mode broker --listen 0.0.0.0:8443 --upstream 10.0.0.1:9 --max-bytes -5",
            "--mode broker --listen 0.0.0.0:8443 --upstream 10.0.0.1:9 --max-connections 5000",
            "--mode broker --listen 0.0.0.0:8443 --upstream 10.0.0.1:9 --job a/b",
            "--mode broker --listen 0.0.0.0:8443 --upstream 10.0.0.1:9 --flag",
            "--mode broker --listen 0.0.0.0:8443 --upstream",
            "--mode connect --listen 0.0.0.0:3128 --allow 10.0.0.5:443",
            "--mode connect --listen 0.0.0.0:3128 --allow evil.test",
            "--mode connect --listen 0.0.0.0:3128 --allow a.test:443 --upstream 10.0.0.1:9",
            "--mode connect --listen 0.0.0.0:3128 --allow a.test:443 --deny-range nonsense",
        ];
        for text in bad {
            assert!(
                RelayConfig::from_args(&args(text)).is_err(),
                "should be refused: {text:?}"
            );
        }
    }

    #[test]
    fn extra_refused_ranges_add_to_the_defaults() {
        let config = RelayConfig::from_args(&args(
            "--mode connect --listen 0.0.0.0:3128 --allow a.test:443 --deny-range 203.0.113.0/24",
        ))
        .expect("a config");
        assert_eq!(config.deny_ranges.len(), default_deny_ranges().len() + 1);
    }
}
