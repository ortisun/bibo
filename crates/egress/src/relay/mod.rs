//! The per-job egress relay, the logic of the `factory-egress-sidecar` program.
//!
//! It holds no credential and needs only the standard library, so the sidecar image carries none
//! of the broker. It has two modes (`docs/security/sandbox-policy.md` section 5.2):
//!
//! * **broker** (the `agent` profile). The sandbox can reach this relay and nothing else, and the
//!   relay reaches the broker at one address that the supervisor wrote on its command line. Every
//!   connection is relayed there, so a sandbox that asks for any other host, port or protocol gets
//!   the broker's own refusal, and the relay resolves no name that the sandbox supplies. The
//!   `troubleshooter` profile adds one second fixed relay (`--second-listen`, `--second-upstream`,
//!   ADR 0021 Decision 5): one more listener relayed to one more fixed address, the MCP gateway,
//!   under the same quota and connection limit. It is off unless the supervisor configures it.
//! * **connect** (the `fetch_deps` profile). A `CONNECT` proxy for an exact-host allowlist: the
//!   target is checked before it is resolved, the resolved addresses are checked against the
//!   refused ranges, the connection goes to the address that was checked, and a byte quota ends a
//!   transfer that passes the cap.
//!
//! Both modes write one JSON line per decision and per closed connection, and a `ready` line when
//! the listener is bound.

pub mod config;
pub mod engine;
pub mod policy;

pub use config::{ConfigError, DEFAULT_MAX_BYTES, Mode, RelayConfig, SecondRelay};
pub use engine::{
    Connector, DecisionLog, MemoryLog, Relay, RelayHandle, Resolver, StdoutLog, SystemResolver,
    TcpConnector,
};
pub use policy::{Cidr, Denial, HostPolicy, HostRule, Target};
