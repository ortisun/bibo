//! NT-SBX-05: the egress relay's allowlist, against flipping DNS and an echo listener.
//!
//! The world: a DNS server whose answers the test controls (FX-DNS), a "registry" web server that
//! counts its hits, and an echo listener that records every connection. The relay resolves through
//! a client that really queries the DNS server over UDP, and connects through a connector that
//! sends the one public address (a documentation address, which no network routes) to the registry
//! and every other address, public or private, to the echo listener. A denied request is therefore
//! proved by two zero counts: the registry saw no hit, and the echo listener saw no connection, and
//! the connector was never asked for a private address.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use factory_egress::relay::{
    Connector, Denial, HostRule, Mode, Relay, RelayConfig, RelayHandle, Resolver, TcpConnector,
    policy::default_deny_ranges,
};
use factory_testkit::fx::dns::{DnsAnswer, EchoListener, FlippingDns, ScriptedHttp};
use factory_testkit::fx::http::HttpResponse;

/// The "public" address of the registry: RFC 5737 TEST-NET-1, routed nowhere.
const PUBLIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

/// Asks the DNS server for the A records of a name, the way a stub resolver does.
struct DnsClient {
    server: SocketAddr,
}

impl Resolver for DnsClient {
    fn resolve(&self, host: &str) -> Option<Vec<IpAddr>> {
        let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
        socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in host.split('.') {
            query.push(u8::try_from(label.len()).ok()?);
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 1, 0, 1]);
        socket.send_to(&query, self.server).ok()?;
        let mut buffer = [0_u8; 512];
        let (n, _) = socket.recv_from(&mut buffer).ok()?;
        parse_a_records(&buffer[..n])
    }
}

fn skip_name(packet: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *packet.get(at)?;
        if len == 0 {
            return Some(at + 1);
        }
        if len & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        at += 1 + usize::from(len);
    }
}

fn parse_a_records(packet: &[u8]) -> Option<Vec<IpAddr>> {
    if packet.len() < 12 || packet[3] & 0x0f != 0 {
        return None;
    }
    let answers = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
    let mut at = skip_name(packet, 12)? + 4;
    let mut found = Vec::new();
    for _ in 0..answers {
        at = skip_name(packet, at)?;
        let kind = u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]);
        let len = usize::from(u16::from_be_bytes([
            *packet.get(at + 8)?,
            *packet.get(at + 9)?,
        ]));
        let data = packet.get(at + 10..at + 10 + len)?;
        if kind == 1 && len == 4 {
            found.push(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            )));
        }
        at += 10 + len;
    }
    (!found.is_empty()).then_some(found)
}

/// Records every address it is asked to connect to, then connects to whatever the test mapped it
/// to: the registry for the public address, the echo listener for every other.
struct Mapped {
    registry: SocketAddr,
    echo: SocketAddr,
    attempts: Arc<Mutex<Vec<SocketAddr>>>,
}

impl Connector for Mapped {
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
        self.attempts.lock().expect("attempts").push(addr);
        let target = if addr.ip() == IpAddr::V4(PUBLIC) {
            self.registry
        } else {
            self.echo
        };
        TcpConnector.connect(target, timeout)
    }
}

struct World {
    dns: FlippingDns,
    echo: EchoListener,
    registry: ScriptedHttp,
    log: Arc<factory_egress::relay::MemoryLog>,
    attempts: Arc<Mutex<Vec<SocketAddr>>>,
    relay: RelayHandle,
}

impl World {
    fn new(max_bytes: u64) -> Self {
        let dns = FlippingDns::start().expect("dns");
        let echo = EchoListener::start().expect("echo");
        let registry = ScriptedHttp::start("registry").expect("registry");
        registry.on("/pkg", HttpResponse::text(200, "package bytes"));
        registry.large("/big", 1_000_000);

        let public = DnsAnswer::A(PUBLIC);
        dns.always("registry.test", public);
        dns.always("loopback.test", DnsAnswer::A(Ipv4Addr::new(127, 0, 0, 1)));
        dns.always("private.test", DnsAnswer::A(Ipv4Addr::new(10, 0, 0, 5)));
        dns.always(
            "metadata.test",
            DnsAnswer::A(Ipv4Addr::new(169, 254, 169, 254)),
        );
        dns.set(
            "rebind.test",
            vec![public, DnsAnswer::A(Ipv4Addr::new(10, 0, 0, 5))],
        );
        dns.always("evil.test", public);
        dns.always("registry.test.evil.test", public);

        let attempts = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::new(factory_egress::relay::MemoryLog::new());
        let allow = [
            "registry.test",
            "loopback.test",
            "private.test",
            "metadata.test",
            "rebind.test",
        ]
        .iter()
        .map(|h| HostRule::parse(&format!("{h}:443")).expect("a rule"))
        .collect();
        let config = RelayConfig {
            listen: "127.0.0.1:0".parse().expect("address"),
            mode: Mode::Connect { allow },
            max_bytes,
            max_connections: 16,
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(5),
            head_timeout: Duration::from_secs(2),
            deny_ranges: default_deny_ranges(),
            job: Some("job-test".to_owned()),
        };
        let relay = Relay::new(
            config,
            Arc::new(DnsClient { server: dns.addr() }),
            Arc::new(Mapped {
                registry: registry.addr(),
                echo: echo.addr(),
                attempts: attempts.clone(),
            }),
            log.clone(),
        )
        .start()
        .expect("the relay starts");
        Self {
            dns,
            echo,
            registry,
            log,
            attempts,
            relay,
        }
    }

    /// Sends `CONNECT authority` and returns the status and the open connection.
    fn connect(&self, authority: &str) -> (u16, TcpStream) {
        let mut stream = TcpStream::connect(self.relay.local_addr()).expect("connect to the relay");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        stream
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .expect("write");
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap_or(0) == 0 {
                break;
            }
            head.push(byte[0]);
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        let status = text
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, stream)
    }

    /// Fetches a path of the registry through an established tunnel and returns what came back.
    fn fetch(stream: &mut TcpStream, path: &str) -> Vec<u8> {
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: registry.test\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .expect("write");
        let mut body = Vec::new();
        let _ = stream.read_to_end(&mut body);
        body
    }

    fn assert_nothing_reached_anything(&self, what: &str) {
        assert_eq!(
            self.registry.hit_count(),
            0,
            "{what}: the registry was reached"
        );
        assert_eq!(
            self.echo.connection_count(),
            0,
            "{what}: the echo listener was reached"
        );
        assert!(
            self.attempts.lock().expect("attempts").is_empty(),
            "{what}: a connection was attempted"
        );
    }

    fn decisions(&self, reason: &str) -> usize {
        self.log
            .events()
            .iter()
            .filter(|e| e["decision"] == "deny" && e["reason"] == reason)
            .count()
    }
}

#[test]
fn negative_nt_sbx_05_a_host_that_is_not_on_the_list_is_refused_before_it_is_resolved() {
    let world = World::new(1 << 20);
    for (authority, reason) in [
        ("evil.test:443", "not_allowlisted"),
        ("registry.test.evil.test:443", "not_allowlisted"),
        ("EVIL.test.:443", "not_allowlisted"),
        ("registry.test@evil.test:443", "userinfo"),
        ("192.0.2.10:443", "ip_literal"),
        ("127.0.0.1:443", "ip_literal"),
        ("[::1]:443", "ip_literal"),
        ("2130706433:443", "ip_literal"),
        ("registry.test:22", "port_not_allowed"),
        ("registry.test:8443", "port_not_allowed"),
        ("github.com:443", "never_allowed"),
    ] {
        let (status, _) = world.connect(authority);
        assert_eq!(status, 403, "{authority}");
        assert!(
            world.decisions(reason) >= 1,
            "{authority} should be logged as {reason}"
        );
    }
    world.assert_nothing_reached_anything("a target that is not allowed");
    for name in ["evil.test", "registry.test.evil.test", "registry.test"] {
        assert_eq!(
            world.dns.query_count(name),
            0,
            "{name} must not even be resolved"
        );
    }
}

#[test]
fn negative_nt_sbx_05_a_name_that_resolves_to_an_internal_address_is_refused_after_resolution() {
    let world = World::new(1 << 20);
    for (authority, name) in [
        ("loopback.test:443", "loopback.test"),
        ("private.test:443", "private.test"),
        ("metadata.test:443", "metadata.test"),
    ] {
        let (status, _) = world.connect(authority);
        assert_eq!(status, 403, "{authority}");
        assert_eq!(world.dns.query_count(name), 1, "{name} is resolved once");
    }
    assert_eq!(world.decisions("resolved_to_denied_range"), 3);
    world.assert_nothing_reached_anything("a name that resolves to an internal address");
}

#[test]
fn negative_nt_sbx_05_a_rebinding_answer_cannot_redirect_a_connection_that_was_checked() {
    let world = World::new(1 << 20);
    // First connection: the name answers with the public address. It is checked, and the
    // connection goes to that address and no other.
    let (status, mut tunnel) = world.connect("rebind.test:443");
    assert_eq!(status, 200);
    let body = World::fetch(&mut tunnel, "/pkg");
    assert!(String::from_utf8_lossy(&body).contains("package bytes"));
    assert_eq!(
        world.dns.query_count("rebind.test"),
        1,
        "one resolution for one connection"
    );
    // Second connection: the name now answers with an internal address. It is refused.
    let (status, _) = world.connect("rebind.test:443");
    assert_eq!(status, 403);
    assert_eq!(world.dns.query_count("rebind.test"), 2);
    assert_eq!(
        world.echo.connection_count(),
        0,
        "the internal address was never connected to"
    );
    let attempts = world.attempts.lock().expect("attempts").clone();
    assert_eq!(attempts, vec![SocketAddr::new(IpAddr::V4(PUBLIC), 443)]);
}

#[test]
fn negative_nt_sbx_05_the_allowed_host_works_in_every_spelling_of_its_name() {
    let world = World::new(1 << 20);
    for authority in [
        "registry.test:443",
        "Registry.TEST:443",
        "registry.test.:443",
    ] {
        let (status, mut tunnel) = world.connect(authority);
        assert_eq!(status, 200, "{authority}");
        let body = World::fetch(&mut tunnel, "/pkg");
        assert!(
            String::from_utf8_lossy(&body).contains("package bytes"),
            "{authority}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    assert_eq!(
        world.registry.hit_count(),
        3,
        "the control request reaches the registry"
    );
}

#[test]
fn negative_nt_sbx_05_other_methods_and_plain_proxying_are_refused() {
    let world = World::new(1 << 20);
    for request in [
        "GET http://registry.test/pkg HTTP/1.1\r\nHost: registry.test\r\n\r\n",
        "POST /pkg HTTP/1.1\r\nHost: registry.test\r\n\r\n",
        "CONNECT registry.test:443 HTTP/2\r\n\r\n",
    ] {
        let mut stream = TcpStream::connect(world.relay.local_addr()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        stream.write_all(request.as_bytes()).expect("write");
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        assert!(
            !answer.contains("200"),
            "{request:?} was accepted: {answer}"
        );
    }
    world.assert_nothing_reached_anything("a method other than CONNECT");
    assert_eq!(world.decisions("method_not_allowed"), 2);
}

#[test]
fn negative_nt_sbx_05_the_byte_quota_ends_a_transfer_at_the_cap() {
    let cap = 20_000;
    let world = World::new(cap);
    let (status, mut tunnel) = world.connect("registry.test:443");
    assert_eq!(status, 200);
    let body = World::fetch(&mut tunnel, "/big");
    let received = body.len() as u64;
    assert!(received > 0, "something was transferred before the cap");
    assert!(
        received < cap,
        "the client received {received}, the cap is {cap}"
    );
    assert_eq!(
        world.relay.bytes_moved(),
        cap,
        "the relay moved exactly the cap and no more"
    );
    let closed = world
        .log
        .events()
        .into_iter()
        .find(|e| e["event"] == "egress_closed")
        .expect("a close line");
    assert_eq!(closed["quota_exhausted"], true);
    // With the allowance gone, a new connection is refused and nothing more moves.
    let registry_hits = world.registry.hit_count();
    let (status, _) = world.connect("registry.test:443");
    assert_eq!(status, 403);
    assert_eq!(world.decisions("quota_exhausted"), 1);
    assert_eq!(world.registry.hit_count(), registry_hits);
    assert_eq!(world.relay.bytes_moved(), cap);
}

#[test]
fn the_decision_log_has_one_line_per_decision_with_the_job_and_no_free_text() {
    let world = World::new(1 << 20);
    let _ = world.connect("evil.test:443");
    let (_, mut tunnel) = world.connect("registry.test:443");
    let _ = World::fetch(&mut tunnel, "/pkg");
    drop(tunnel);
    std::thread::sleep(Duration::from_millis(200));
    let events = world.log.events();
    assert_eq!(events[0]["event"], "ready");
    let deny = events
        .iter()
        .find(|e| e["decision"] == "deny")
        .expect("a deny");
    assert_eq!(deny["job"], "job-test");
    assert_eq!(deny["host"], "evil.test:443");
    assert_eq!(deny["reason"], "not_allowlisted");
    let allow = events
        .iter()
        .find(|e| e["decision"] == "allow")
        .expect("an allow");
    assert_eq!(allow["host"], "registry.test");
    assert_eq!(allow["port"], 443);
    assert_eq!(Denial::NotAllowlisted.as_str(), "not_allowlisted");
}
