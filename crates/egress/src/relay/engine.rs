//! The relay's network side: accept, decide, connect to the address that was checked, and copy
//! bytes under a quota.
//!
//! Names are resolved through a [`Resolver`] and connections made through a [`Connector`], so the
//! tests can answer a name with a rebinding sequence and watch every connection attempt; the
//! program uses the system resolver and plain TCP. The relay never connects to anything but the
//! one address of broker mode or the one address it resolved, checked and pinned in connect mode.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};

use super::config::{Mode, RelayConfig};
use super::policy::{Denial, HostPolicy};

/// Resolves a host name to addresses.
pub trait Resolver: Send + Sync {
    /// The addresses of `host`, or `None` when it does not resolve. It is called once per
    /// connection, and the answer is checked and used for that connection only.
    fn resolve(&self, host: &str) -> Option<Vec<IpAddr>>;
}

/// The operating system's resolver.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str) -> Option<Vec<IpAddr>> {
        let found = (host, 0_u16).to_socket_addrs().ok()?;
        let ips: Vec<IpAddr> = found.map(|a| a.ip()).collect();
        (!ips.is_empty()).then_some(ips)
    }
}

/// Opens a connection to an address.
pub trait Connector: Send + Sync {
    /// Connects to `addr`.
    ///
    /// # Errors
    /// The connection error.
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream>;
}

/// Plain TCP.
#[derive(Debug, Default, Clone, Copy)]
pub struct TcpConnector;

impl Connector for TcpConnector {
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        TcpStream::connect_timeout(&addr, timeout)
    }
}

/// Where decisions are written: one JSON object per event.
pub trait DecisionLog: Send + Sync {
    /// Records one event.
    fn emit(&self, event: &Value);
}

/// Writes each event as one line on standard output, which the supervisor reads through the
/// attached stream and redacts (the profile uses `--log-driver none`).
#[derive(Debug, Default, Clone, Copy)]
pub struct StdoutLog;

impl DecisionLog for StdoutLog {
    fn emit(&self, event: &Value) {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "{event}");
        let _ = out.flush();
    }
}

/// Keeps events in memory, for tests.
#[derive(Debug, Default)]
pub struct MemoryLog {
    events: Mutex<Vec<Value>>,
}

impl MemoryLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of the events so far.
    #[must_use]
    pub fn events(&self) -> Vec<Value> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

impl DecisionLog for MemoryLog {
    fn emit(&self, event: &Value) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }
    }
}

/// The byte allowance of the job.
#[derive(Debug)]
struct Quota {
    used: AtomicU64,
    max: u64,
}

impl Quota {
    /// Takes up to `want` bytes of what is left and returns how many were granted.
    fn take(&self, want: u64) -> u64 {
        loop {
            let used = self.used.load(Ordering::SeqCst);
            let grant = want.min(self.max.saturating_sub(used));
            if grant == 0 {
                return 0;
            }
            if self
                .used
                .compare_exchange(used, used + grant, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return grant;
            }
        }
    }

    fn is_exhausted(&self) -> bool {
        self.used.load(Ordering::SeqCst) >= self.max
    }
}

/// The relay: configuration, the two seams and the state shared by its connections.
pub struct Relay {
    config: RelayConfig,
    policy: Option<HostPolicy>,
    resolver: Arc<dyn Resolver>,
    connector: Arc<dyn Connector>,
    log: Arc<dyn DecisionLog>,
    quota: Quota,
    active: AtomicUsize,
}

/// A running relay. Dropping it stops it.
pub struct RelayHandle {
    addr: SocketAddr,
    relay: Arc<Relay>,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Relay {
    /// A relay over this configuration.
    #[must_use]
    pub fn new(
        config: RelayConfig,
        resolver: Arc<dyn Resolver>,
        connector: Arc<dyn Connector>,
        log: Arc<dyn DecisionLog>,
    ) -> Self {
        let policy = match &config.mode {
            Mode::Connect { allow } => {
                Some(HostPolicy::new(allow.clone(), config.deny_ranges.clone()))
            }
            Mode::Broker { .. } => None,
        };
        let quota = Quota {
            used: AtomicU64::new(0),
            max: config.max_bytes,
        };
        Self {
            config,
            policy,
            resolver,
            connector,
            log,
            quota,
            active: AtomicUsize::new(0),
        }
    }

    /// Binds the listener, writes the ready line and starts serving.
    ///
    /// # Errors
    /// The bind error. The program then exits non-zero before it accepts a connection.
    pub fn start(self) -> io::Result<RelayHandle> {
        let listener = TcpListener::bind(self.config.listen)?;
        let addr = listener.local_addr()?;
        let relay = Arc::new(self);
        let stop = Arc::new(AtomicBool::new(false));
        relay.log.emit(&json!({
            "event": "ready",
            "mode": relay.mode_name(),
            "listen": addr.to_string(),
            "job": relay.config.job,
        }));
        let (worker, flag) = (Arc::clone(&relay), Arc::clone(&stop));
        let thread = thread::Builder::new()
            .name("relay-accept".to_owned())
            .spawn(move || worker.accept_loop(&listener, &flag))?;
        Ok(RelayHandle {
            addr,
            relay,
            stop,
            thread: Mutex::new(Some(thread)),
        })
    }

    fn mode_name(&self) -> &'static str {
        match self.config.mode {
            Mode::Broker { .. } => "broker",
            Mode::Connect { .. } => "connect",
        }
    }

    fn accept_loop(self: &Arc<Self>, listener: &TcpListener, stop: &AtomicBool) {
        for incoming in listener.incoming() {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let Ok(client) = incoming else {
                continue;
            };
            if self.active.fetch_add(1, Ordering::SeqCst) >= self.config.max_connections {
                self.active.fetch_sub(1, Ordering::SeqCst);
                self.refuse(client, Denial::TooManyConnections, "", 0);
                continue;
            }
            let worker = Arc::clone(self);
            let spawned = thread::Builder::new()
                .name("relay-conn".to_owned())
                .spawn(move || {
                    worker.serve(client);
                    worker.active.fetch_sub(1, Ordering::SeqCst);
                });
            if spawned.is_err() {
                self.active.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }

    fn serve(&self, client: TcpStream) {
        let _ = client.set_nodelay(true);
        if self.quota.is_exhausted() {
            return self.refuse(client, Denial::QuotaExhausted, "", 0);
        }
        match &self.config.mode {
            Mode::Broker { upstream } => self.serve_broker(client, *upstream),
            Mode::Connect { .. } => self.serve_connect(client),
        }
    }

    // ---- broker mode -------------------------------------------------------------------------

    /// Every byte goes to the one address the supervisor gave. Nothing the sandbox sends is read
    /// or used to choose where to connect, so there is nothing to resolve and nothing to trick.
    fn serve_broker(&self, client: TcpStream, upstream: SocketAddr) {
        let host = upstream.ip().to_string();
        let server = match self
            .connector
            .connect(upstream, self.config.connect_timeout)
        {
            Ok(server) => server,
            Err(_) => {
                return self.refuse(client, Denial::UpstreamUnreachable, &host, upstream.port());
            }
        };
        self.decision(true, "broker", &host, upstream.port());
        self.pump(client, server, &[], &host, upstream.port());
    }

    // ---- connect mode ------------------------------------------------------------------------

    fn serve_connect(&self, mut client: TcpStream) {
        let _ = client.set_read_timeout(Some(self.config.head_timeout));
        let Some((authority, method_ok, leftover)) = read_connect_line(&mut client) else {
            return self.refuse(client, Denial::Malformed, "", 0);
        };
        if !method_ok {
            return self.refuse(client, Denial::MethodNotAllowed, &authority, 0);
        }
        let Some(policy) = &self.policy else {
            return self.refuse(client, Denial::Malformed, &authority, 0);
        };
        let target = match policy.check_target(&authority) {
            Ok(target) => target,
            Err(denial) => return self.refuse(client, denial, &authority, 0),
        };
        // The name is resolved here, once, and the answer is checked before anything is
        // connected. The connection goes to the address that was checked.
        let Some(answers) = self.resolver.resolve(&target.host) else {
            return self.refuse(client, Denial::ResolveFailed, &target.host, target.port);
        };
        let ip = match policy.check_resolved(&answers) {
            Ok(ip) => ip,
            Err(denial) => return self.refuse(client, denial, &target.host, target.port),
        };
        let pinned = SocketAddr::new(ip, target.port);
        let server = match self.connector.connect(pinned, self.config.connect_timeout) {
            Ok(server) => server,
            Err(_) => {
                return self.refuse(
                    client,
                    Denial::UpstreamUnreachable,
                    &target.host,
                    target.port,
                );
            }
        };
        self.decision(true, "allowed", &target.host, target.port);
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
        self.pump(client, server, &leftover, &target.host, target.port);
    }

    // ---- shared ------------------------------------------------------------------------------

    fn clip(text: &str) -> String {
        text.chars().take(253).collect()
    }

    fn decision(&self, allow: bool, reason: &str, host: &str, port: u16) {
        self.log.emit(&json!({
            "event": "egress_decision",
            "decision": if allow { "allow" } else { "deny" },
            "reason": reason,
            "mode": self.mode_name(),
            "host": Self::clip(host),
            "port": port,
            "job": self.config.job,
        }));
    }

    /// Refuses a connection: the decision is logged first, then the client is told.
    fn refuse(&self, mut client: TcpStream, denial: Denial, host: &str, port: u16) {
        self.decision(false, denial.as_str(), host, port);
        if matches!(self.config.mode, Mode::Connect { .. }) && denial != Denial::Malformed {
            let status = denial.status();
            let reason = match status {
                405 => "Method Not Allowed",
                502 => "Bad Gateway",
                503 => "Service Unavailable",
                _ => "Forbidden",
            };
            let allow = if status == 405 {
                "Allow: CONNECT\r\n"
            } else {
                ""
            };
            let _ = client.set_write_timeout(Some(Duration::from_secs(2)));
            let _ = client.write_all(
                format!("HTTP/1.1 {status} {reason}\r\n{allow}Connection: close\r\nContent-Length: 0\r\n\r\n")
                    .as_bytes(),
            );
        }
        let _ = client.shutdown(Shutdown::Both);
    }

    /// Copies both directions under the quota until either side ends, then logs the totals.
    fn pump(&self, client: TcpStream, server: TcpStream, first: &[u8], host: &str, port: u16) {
        let idle = Some(self.config.idle_timeout);
        let _ = client.set_read_timeout(idle);
        let _ = server.set_read_timeout(idle);
        let _ = client.set_write_timeout(idle);
        let _ = server.set_write_timeout(idle);
        let (Ok(client_back), Ok(server_back)) = (client.try_clone(), server.try_clone()) else {
            return;
        };
        let up = Arc::new(AtomicU64::new(0));
        let down = Arc::new(AtomicU64::new(0));
        let quota = &self.quota;
        thread::scope(|scope| {
            let down_count = Arc::clone(&down);
            scope.spawn(move || copy(server_back, client, quota, &down_count, &[]));
            copy(client_back, server, quota, &up, first);
        });
        self.log.emit(&json!({
            "event": "egress_closed",
            "mode": self.mode_name(),
            "host": Self::clip(host),
            "port": port,
            "bytes_up": up.load(Ordering::SeqCst),
            "bytes_down": down.load(Ordering::SeqCst),
            "quota_exhausted": self.quota.is_exhausted(),
            "job": self.config.job,
        }));
    }
}

/// Reads the request line of a `CONNECT` and whatever bytes came after the head. Returns the
/// authority, whether the method was CONNECT, and the bytes to pass on. `None` for a head that is
/// not HTTP at all.
fn read_connect_line(client: &mut TcpStream) -> Option<(String, bool, Vec<u8>)> {
    const LIMIT: usize = 8 * 1024;
    let mut buffer = Vec::with_capacity(512);
    let mut chunk = [0_u8; 1024];
    let end = loop {
        let n = client.read(&mut chunk).ok().filter(|n| *n > 0)?;
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if buffer.len() > LIMIT {
            return None;
        }
    };
    let leftover = buffer.split_off(end);
    let head = std::str::from_utf8(&buffer).ok()?;
    let line = head.split("\r\n").next()?;
    let mut parts = line.split(' ');
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return None;
    }
    Some((target.to_owned(), method == "CONNECT", leftover))
}

/// Copies from one socket to the other until the source ends, the destination fails, or the quota
/// runs out. The destination's write side is then closed so the peer sees the end.
fn copy(mut from: TcpStream, mut to: TcpStream, quota: &Quota, count: &AtomicU64, first: &[u8]) {
    let mut buffer = [0_u8; 16 * 1024];
    let mut exhausted = false;
    let mut send = |bytes: &[u8]| -> bool {
        let granted = quota.take(bytes.len() as u64);
        let granted_len = usize::try_from(granted).unwrap_or(0);
        if granted_len > 0 && to.write_all(&bytes[..granted_len]).is_err() {
            return false;
        }
        count.fetch_add(granted, Ordering::SeqCst);
        if granted_len < bytes.len() {
            exhausted = true;
            return false;
        }
        true
    };
    let mut ok = first.is_empty() || send(first);
    while ok {
        match from.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => ok = send(&buffer[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    let _ = to.shutdown(Shutdown::Write);
    if exhausted || !ok {
        // The allowance is gone or the other side failed: end both directions now.
        let _ = to.shutdown(Shutdown::Both);
        let _ = from.shutdown(Shutdown::Both);
    }
}

impl RelayHandle {
    /// The address the relay listens on.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The bytes moved so far, both directions together.
    #[must_use]
    pub fn bytes_moved(&self) -> u64 {
        self.relay.quota.used.load(Ordering::SeqCst)
    }

    /// Waits for the accept loop to end, which happens only after `shutdown`. The program calls
    /// this to stay alive.
    pub fn wait(&self) {
        let handle = self.thread.lock().ok().and_then(|mut t| t.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }

    /// Stops accepting connections. Connections already open finish.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let wake = if self.addr.ip().is_unspecified() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.addr.port())
        } else {
            self.addr
        };
        let _ = TcpStream::connect_timeout(&wake, Duration::from_secs(1));
        self.wait();
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}
