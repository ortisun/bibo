//! The relay in broker mode (the `agent` profile), in front of the real broker listener and the
//! fake provider: the sandbox reaches the broker through the relay and nothing else, whatever it
//! asks for, and the relay resolves no name. The second fixed relay of the `troubleshooter`
//! profile (ADR 0021 Decision 5) is off unless configured, and when it is on it reaches its one
//! address and nothing else.

mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use factory_egress::relay::policy::default_deny_ranges;
use factory_egress::relay::{
    Connector, MemoryLog, Mode, Relay, RelayConfig, RelayHandle, Resolver, SecondRelay,
    TcpConnector,
};
use factory_testkit::fx::dns::EchoListener;
use factory_testkit::fx::http::send_request;
use support::{CEILING, HttpRig};

/// A resolver that fails the test if it is asked anything: broker mode resolves nothing.
struct NeverResolves(Arc<Mutex<Vec<String>>>);

impl Resolver for NeverResolves {
    fn resolve(&self, host: &str) -> Option<Vec<std::net::IpAddr>> {
        self.0.lock().expect("calls").push(host.to_owned());
        None
    }
}

struct Recording(Arc<Mutex<Vec<SocketAddr>>>);

impl Connector for Recording {
    fn connect(&self, addr: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
        self.0.lock().expect("attempts").push(addr);
        TcpConnector.connect(addr, timeout)
    }
}

struct Path {
    relay: RelayHandle,
    resolutions: Arc<Mutex<Vec<String>>>,
    attempts: Arc<Mutex<Vec<SocketAddr>>>,
    log: Arc<MemoryLog>,
}

fn relay_to(upstream: SocketAddr, max_bytes: u64) -> Path {
    relay_with(upstream, None, max_bytes)
}

fn relay_with(upstream: SocketAddr, second: Option<SocketAddr>, max_bytes: u64) -> Path {
    let resolutions = Arc::new(Mutex::new(Vec::new()));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::new(MemoryLog::new());
    let relay = Relay::new(
        RelayConfig {
            listen: "127.0.0.1:0".parse().expect("address"),
            mode: Mode::Broker {
                upstream,
                second: second.map(|upstream| SecondRelay {
                    listen: "127.0.0.1:0".parse().expect("address"),
                    upstream,
                }),
            },
            max_bytes,
            max_connections: 16,
            connect_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(5),
            head_timeout: Duration::from_secs(2),
            deny_ranges: default_deny_ranges(),
            job: Some("job-test".to_owned()),
        },
        Arc::new(NeverResolves(resolutions.clone())),
        Arc::new(Recording(attempts.clone())),
        log.clone(),
    )
    .start()
    .expect("the relay starts");
    Path {
        relay,
        resolutions,
        attempts,
        log,
    }
}

#[test]
fn a_request_through_the_relay_reaches_the_broker_and_the_provider_sees_only_the_real_key() {
    let rig = HttpRig::new();
    let path = relay_to(rig.addr(), 1 << 30);
    let token = rig.claude_token(CEILING);
    // The sandbox's tool talks to the relay as if it were the provider.
    let response = send_request(
        path.relay.local_addr(),
        "POST",
        "/v1/messages?beta=true",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", token.secret.expose()),
        ],
        br#"{"model":"claude-test-model","stream":true,"max_tokens":50}"#,
    )
    .expect("an answer through the relay");
    assert_eq!(response.status, 200);
    assert!(response.text().contains("message_stop"));
    let seen = rig.provider.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].header("x-api-key"),
        Some(rig.anthropic_key.as_str())
    );
    assert_eq!(*path.attempts.lock().expect("attempts"), vec![rig.addr()]);
    assert!(path.resolutions.lock().expect("calls").is_empty());
}

#[test]
fn whatever_the_sandbox_asks_for_the_relay_connects_to_the_broker_only_and_resolves_nothing() {
    let rig = HttpRig::new();
    let echo = EchoListener::start().expect("echo");
    let path = relay_to(rig.addr(), 1 << 30);
    // A sandbox that tries a proxy request, an absolute URL and a CONNECT to another host. The
    // relay passes the bytes to the broker, which refuses them; the bytes go nowhere else.
    for request in [
        "CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n".to_owned(),
        format!("GET http://{}/ HTTP/1.1\r\nHost: {}\r\n\r\n", echo.addr(), echo.addr()),
        "POST http://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Length: 2\r\n\r\n{}".to_owned(),
        "garbage that is not http at all\r\n\r\n".to_owned(),
    ] {
        let mut stream = TcpStream::connect(path.relay.local_addr()).expect("connect");
        stream.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
        stream.write_all(request.as_bytes()).expect("write");
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        assert!(
            !answer.starts_with("HTTP/1.1 200"),
            "{request:?} was accepted: {answer}"
        );
    }
    assert_eq!(
        rig.provider.hits(),
        0,
        "the broker forwarded nothing to the provider"
    );
    assert_eq!(
        echo.connection_count(),
        0,
        "nothing reached the host the sandbox named"
    );
    let attempts = path.attempts.lock().expect("attempts").clone();
    assert!(!attempts.is_empty());
    assert!(
        attempts.iter().all(|a| *a == rig.addr()),
        "every connection went to the broker: {attempts:?}"
    );
    assert!(
        path.resolutions.lock().expect("calls").is_empty(),
        "the relay resolved a name the sandbox supplied"
    );
}

#[test]
fn a_broker_that_is_down_is_a_logged_refusal_and_not_a_hang() {
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr")
    };
    let path = relay_to(dead, 1 << 30);
    let mut stream = TcpStream::connect(path.relay.local_addr()).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n").expect("write");
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    assert!(out.is_empty());
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        path.log
            .events()
            .iter()
            .any(|e| e["decision"] == "deny" && e["reason"] == "upstream_unreachable")
    );
}

#[test]
fn the_byte_quota_applies_in_broker_mode_too() {
    let rig = HttpRig::new();
    let path = relay_to(rig.addr(), 300);
    let token = rig.claude_token(CEILING);
    let result = send_request(
        path.relay.local_addr(),
        "POST",
        "/v1/messages",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", token.secret.expose()),
        ],
        br#"{"model":"claude-test-model","stream":true,"max_tokens":50}"#,
    );
    // The answer is longer than the 300 bytes the job may move, so it is cut off.
    if let Ok(response) = result {
        assert!(
            !response.text().contains("message_stop"),
            "the answer arrived whole"
        );
    }
    assert_eq!(path.relay.bytes_moved(), 300);
}

#[test]
fn the_second_relay_is_off_unless_configured() {
    let rig = HttpRig::new();
    let path = relay_to(rig.addr(), 1 << 30);
    assert_eq!(path.relay.second_addr(), None);
    let ready = path
        .log
        .events()
        .into_iter()
        .find(|e| e["event"] == "ready")
        .expect("a ready line");
    assert!(ready["second_listen"].is_null(), "{ready}");
}

#[test]
fn the_second_relay_reaches_its_one_address_whatever_the_sandbox_asks_for() {
    let rig = HttpRig::new();
    let gateway = EchoListener::start().expect("a stand-in gateway");
    let elsewhere = EchoListener::start().expect("another host");
    let path = relay_with(rig.addr(), Some(gateway.addr()), 1 << 30);
    let second = path.relay.second_addr().expect("the second listener");
    assert_ne!(second, path.relay.local_addr());
    for request in [
        "POST /mcp HTTP/1.1\r\nHost: egress:8444\r\nContent-Length: 2\r\n\r\n{}".to_owned(),
        "CONNECT evil.test:443 HTTP/1.1\r\nHost: evil.test:443\r\n\r\n".to_owned(),
        format!(
            "GET http://{}/ HTTP/1.1\r\nHost: {}\r\n\r\n",
            elsewhere.addr(),
            elsewhere.addr()
        ),
    ] {
        let mut stream = TcpStream::connect(second).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        stream.write_all(request.as_bytes()).expect("write");
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        assert!(
            !answer.starts_with("HTTP/1.1 200"),
            "{request:?} was answered by the relay: {answer}"
        );
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        gateway.connection_count(),
        3,
        "every connection reached the gateway"
    );
    assert_eq!(
        elsewhere.connection_count(),
        0,
        "nothing reached the host the sandbox named"
    );
    assert_eq!(
        rig.provider.hits(),
        0,
        "nothing on the second relay reached the broker"
    );
    let attempts = path.attempts.lock().expect("attempts").clone();
    assert!(
        attempts.iter().all(|a| *a == gateway.addr()),
        "every connection went to the gateway: {attempts:?}"
    );
    assert!(path.resolutions.lock().expect("calls").is_empty());
    assert!(
        path.log
            .events()
            .iter()
            .any(|e| e["decision"] == "allow" && e["reason"] == "second_relay")
    );
}

#[test]
fn the_first_relay_still_reaches_only_the_broker_when_a_second_relay_is_on() {
    let rig = HttpRig::new();
    let gateway = EchoListener::start().expect("a stand-in gateway");
    let path = relay_with(rig.addr(), Some(gateway.addr()), 1 << 30);
    let token = rig.claude_token(CEILING);
    let response = send_request(
        path.relay.local_addr(),
        "POST",
        "/v1/messages",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", token.secret.expose()),
        ],
        br#"{"model":"claude-test-model","stream":true,"max_tokens":50}"#,
    )
    .expect("an answer through the relay");
    assert_eq!(response.status, 200);
    assert_eq!(gateway.connection_count(), 0);
    assert_eq!(*path.attempts.lock().expect("attempts"), vec![rig.addr()]);
}

#[test]
fn the_second_relay_shares_the_job_byte_quota() {
    let rig = HttpRig::new();
    let gateway = EchoListener::start().expect("a stand-in gateway");
    let path = relay_with(rig.addr(), Some(gateway.addr()), 64);
    let second = path.relay.second_addr().expect("the second listener");
    let mut stream = TcpStream::connect(second).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let _ = stream.write_all(&[b'x'; 200]);
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(path.relay.bytes_moved(), 64);
    // The quota is the job's: the broker relay has nothing left either.
    let mut late = TcpStream::connect(path.relay.local_addr()).expect("connect");
    late.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");
    let _ = late.write_all(b"GET / HTTP/1.1\r\n\r\n");
    let mut nothing = Vec::new();
    let _ = late.read_to_end(&mut nothing);
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        path.log
            .events()
            .iter()
            .any(|e| e["decision"] == "deny" && e["reason"] == "quota_exhausted")
    );
    assert_eq!(rig.provider.hits(), 0);
}
