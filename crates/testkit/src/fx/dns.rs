//! FX-DNS: servers that let a test control what the network answers.
//!
//! The egress relay and the fetch tool must resist three tricks: a name that resolves to a
//! private or metadata address, a name that answers with a public address first and a private one
//! second (DNS rebinding), and a redirect to an internal address. This file provides the three
//! pieces that make those tests possible, all on `127.0.0.1`:
//!
//! * [`FlippingDns`] is a DNS server over UDP. A test gives it, for each name, a list of answers.
//!   Each query takes the next one and the last repeats, so `[public, private]` is a rebinding
//!   name. Its answers have a time to live of zero, so a resolver cannot cache the first.
//! * [`EchoListener`] is a TCP listener that records every connection and the first bytes sent.
//!   A test that expects a connection never to be made asserts the count is zero.
//! * [`ScriptedHttp`] is an HTTP server with a table of canned answers (a redirect, a large body, a
//!   slow body) that records every request. An "upstream" that must see no traffic for a denied
//!   request is a `ScriptedHttp` whose hit count is checked.
//!
//! The "public" address in these tests is from the documentation ranges (192.0.2.0/24, RFC 5737),
//! which no real network routes, so nothing here can reach a real host.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::http::{HttpRequest, HttpResponse, HttpServer};

/// One answer a name can be given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsAnswer {
    /// An IPv4 address.
    A(Ipv4Addr),
    /// An IPv6 address.
    Aaaa(Ipv6Addr),
    /// The name does not exist (response code 3).
    NxDomain,
    /// The server failed (response code 2).
    ServFail,
}

impl DnsAnswer {
    fn describe(self) -> String {
        match self {
            DnsAnswer::A(ip) => format!("A {ip}"),
            DnsAnswer::Aaaa(ip) => format!("AAAA {ip}"),
            DnsAnswer::NxDomain => "NXDOMAIN".to_owned(),
            DnsAnswer::ServFail => "SERVFAIL".to_owned(),
        }
    }
}

/// A query the server received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryRecord {
    /// 1 for the first query.
    pub seq: u64,
    /// The name, lower case, without the final dot.
    pub name: String,
    /// The record type: 1 for A, 28 for AAAA.
    pub record_type: u16,
    /// What the server answered.
    pub answer: String,
}

impl QueryRecord {
    /// The record as JSON, with the fidelity label.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fidelity": "fake",
            "seq": self.seq,
            "name": self.name,
            "type": self.record_type,
            "answer": self.answer,
        })
    }
}

#[derive(Debug, Default)]
struct DnsState {
    scripts: BTreeMap<String, Script>,
    queries: Vec<QueryRecord>,
    malformed: usize,
}

#[derive(Debug)]
struct Script {
    answers: Vec<DnsAnswer>,
    next: usize,
}

/// A DNS server whose answers a test controls. Dropping it stops it.
#[derive(Debug)]
pub struct FlippingDns {
    addr: SocketAddr,
    state: Arc<Mutex<DnsState>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FlippingDns {
    /// Starts a server on a free UDP port of `127.0.0.1`.
    ///
    /// # Errors
    /// Returns the I/O error when the socket cannot be bound.
    pub fn start() -> io::Result<Self> {
        let socket = UdpSocket::bind(("127.0.0.1", 0))?;
        socket.set_read_timeout(Some(Duration::from_millis(50)))?;
        let addr = socket.local_addr()?;
        let state = Arc::new(Mutex::new(DnsState::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            thread::spawn(move || serve_dns(&socket, &state, &stop))
        };
        Ok(Self {
            addr,
            state,
            stop,
            thread: Some(thread),
        })
    }

    /// The address to point a resolver at.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Gives a name a list of answers, one per query, with the last one repeating. Replaces any
    /// earlier list for the name and starts again from the first answer.
    pub fn set(&self, name: &str, answers: Vec<DnsAnswer>) {
        assert!(!answers.is_empty(), "a name needs at least one answer");
        self.lock()
            .scripts
            .insert(normalise(name), Script { answers, next: 0 });
    }

    /// Gives a name one answer for ever.
    pub fn always(&self, name: &str, answer: DnsAnswer) {
        self.set(name, vec![answer]);
    }

    /// Every query received, in order.
    #[must_use]
    pub fn queries(&self) -> Vec<QueryRecord> {
        self.lock().queries.clone()
    }

    /// How many queries asked for this name.
    #[must_use]
    pub fn query_count(&self, name: &str) -> usize {
        let wanted = normalise(name);
        self.lock()
            .queries
            .iter()
            .filter(|q| q.name == wanted)
            .count()
    }

    /// How many packets arrived that were not a well-formed query. None got an answer.
    #[must_use]
    pub fn malformed_packets(&self) -> usize {
        self.lock().malformed
    }

    /// The server as JSON, with the fidelity label.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "fidelity": "fake",
            "server": "factory-testkit-fake (dns)",
            "queries": self.queries().iter().map(QueryRecord::to_json).collect::<Vec<_>>(),
            "malformed_packets": self.malformed_packets(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DnsState> {
        self.state.lock().expect("the DNS lock is never poisoned")
    }
}

impl Drop for FlippingDns {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn normalise(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn serve_dns(socket: &UdpSocket, state: &Mutex<DnsState>, stop: &AtomicBool) {
    let mut buffer = [0u8; 1500];
    while !stop.load(Ordering::SeqCst) {
        let Ok((length, peer)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let mut state = state.lock().expect("the DNS lock is never poisoned");
        let Some(query) = parse_query(&buffer[..length]) else {
            state.malformed += 1;
            continue;
        };
        let answer = match state.scripts.get_mut(&query.name) {
            Some(script) => {
                let answer = script.answers[script.next.min(script.answers.len() - 1)];
                script.next += 1;
                answer
            }
            None => DnsAnswer::NxDomain,
        };
        let seq = state.queries.len() as u64 + 1;
        state.queries.push(QueryRecord {
            seq,
            name: query.name.clone(),
            record_type: query.record_type,
            answer: answer.describe(),
        });
        drop(state);
        let _ = socket.send_to(&build_response(&buffer[..length], &query, answer), peer);
    }
}

struct Query {
    name: String,
    record_type: u16,
    /// The length of the header plus the question, so the response can copy exactly that.
    question_end: usize,
}

/// Reads a DNS query with one question and no name compression (RFC 1035 section 4.1).
fn parse_query(packet: &[u8]) -> Option<Query> {
    if packet.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    // Must be a query (QR bit clear), with exactly one question and nothing else.
    if flags & 0x8000 != 0 || question_count != 1 {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    let mut total = 0usize;
    loop {
        let length = usize::from(*packet.get(at)?);
        at += 1;
        if length == 0 {
            break;
        }
        // A label over 63 bytes, or a pointer (the top two bits set), is not allowed in a query.
        if length > 63 {
            return None;
        }
        total += length + 1;
        if total > 255 {
            return None;
        }
        let label = packet.get(at..at + length)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at += length;
    }
    let record_type = u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]);
    let class = u16::from_be_bytes([*packet.get(at + 2)?, *packet.get(at + 3)?]);
    if class != 1 {
        return None;
    }
    Some(Query {
        name: labels.join("."),
        record_type,
        question_end: at + 4,
    })
}

fn build_response(packet: &[u8], query: &Query, answer: DnsAnswer) -> Vec<u8> {
    let recursion_desired = packet[2] & 0x01;
    let (code, record): (u8, Option<(u16, Vec<u8>)>) = match answer {
        DnsAnswer::A(ip) if query.record_type == 1 => (0, Some((1, ip.octets().to_vec()))),
        DnsAnswer::Aaaa(ip) if query.record_type == 28 => (0, Some((28, ip.octets().to_vec()))),
        // The name exists but has no record of the type asked for.
        DnsAnswer::A(_) | DnsAnswer::Aaaa(_) => (0, None),
        DnsAnswer::NxDomain => (3, None),
        DnsAnswer::ServFail => (2, None),
    };
    let mut response = Vec::with_capacity(query.question_end + 32);
    response.extend_from_slice(&packet[..2]); // id
    // QR, authoritative answer, recursion desired copied, recursion available, response code.
    response.push(0x84 | recursion_desired);
    response.push(0x80 | code);
    response.extend_from_slice(&[0, 1]); // one question
    response.extend_from_slice(&[0, u8::from(record.is_some())]); // answers
    response.extend_from_slice(&[0, 0, 0, 0]); // no authority or additional records
    response.extend_from_slice(&packet[12..query.question_end]);
    if let Some((record_type, data)) = record {
        response.extend_from_slice(&[0xC0, 0x0C]); // the name, as a pointer to the question
        response.extend_from_slice(&record_type.to_be_bytes());
        response.extend_from_slice(&[0, 1]); // class IN
        response.extend_from_slice(&[0, 0, 0, 0]); // time to live: zero
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(&data);
    }
    response
}

/// A connection the echo listener saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRecord {
    /// Who connected.
    pub peer: SocketAddr,
    /// The first bytes sent, at most 256, read for up to a tenth of a second.
    pub first_bytes: Vec<u8>,
}

/// A TCP listener that does nothing but note who connects. Dropping it stops it.
#[derive(Debug)]
pub struct EchoListener {
    addr: SocketAddr,
    connections: Arc<Mutex<Vec<ConnectionRecord>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl EchoListener {
    /// Starts a listener on a free TCP port of `127.0.0.1`.
    ///
    /// # Errors
    /// Returns the I/O error when the socket cannot be bound.
    pub fn start() -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        let connections = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let connections = Arc::clone(&connections);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(mut stream) = stream else { continue };
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
                    let mut buffer = [0u8; 256];
                    let read = stream.read(&mut buffer).unwrap_or(0);
                    if let Ok(peer) = stream.peer_addr() {
                        connections
                            .lock()
                            .expect("the listener lock is never poisoned")
                            .push(ConnectionRecord {
                                peer,
                                first_bytes: buffer[..read].to_vec(),
                            });
                    }
                }
            })
        };
        Ok(Self {
            addr,
            connections,
            stop,
            thread: Some(thread),
        })
    }

    /// The address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Every connection so far.
    #[must_use]
    pub fn connections(&self) -> Vec<ConnectionRecord> {
        self.connections
            .lock()
            .expect("the listener lock is never poisoned")
            .clone()
    }

    /// How many connections were made.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections().len()
    }
}

impl Drop for EchoListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Debug)]
struct WebState {
    routes: Vec<(String, HttpResponse)>,
    hits: Vec<HttpRequest>,
}

/// An HTTP server with canned answers by path prefix, that records every request it gets.
#[derive(Debug)]
pub struct ScriptedHttp {
    server: HttpServer,
    state: Arc<Mutex<WebState>>,
}

impl ScriptedHttp {
    /// Starts a server on a free port of `127.0.0.1`. Until a route is added it answers 404.
    ///
    /// # Errors
    /// Returns the I/O error when the socket cannot be bound.
    pub fn start(name: &str) -> io::Result<Self> {
        let state = Arc::new(Mutex::new(WebState {
            routes: Vec::new(),
            hits: Vec::new(),
        }));
        let handler_state = Arc::clone(&state);
        let server = HttpServer::start(name, move |request| {
            let mut state = handler_state
                .lock()
                .expect("the scripted server lock is never poisoned");
            state.hits.push(request.clone());
            // The longest matching prefix wins.
            state
                .routes
                .iter()
                .filter(|(prefix, _)| request.path().starts_with(prefix.as_str()))
                .max_by_key(|(prefix, _)| prefix.len())
                .map_or_else(
                    || HttpResponse::text(404, "not scripted"),
                    |(_, r)| r.clone(),
                )
        })?;
        Ok(Self { server, state })
    }

    /// Answers requests under `path_prefix` with this response.
    pub fn on(&self, path_prefix: &str, response: HttpResponse) {
        self.lock().routes.push((path_prefix.to_owned(), response));
    }

    /// Answers requests under `path_prefix` with a redirect.
    pub fn redirect(&self, path_prefix: &str, status: u16, location: &str) {
        self.on(path_prefix, HttpResponse::redirect(status, location));
    }

    /// Answers requests under `path_prefix` with a body of `bytes` bytes.
    pub fn large(&self, path_prefix: &str, bytes: usize) {
        self.on(
            path_prefix,
            HttpResponse::empty(200).with_body(vec![b'x'; bytes]),
        );
    }

    /// Answers requests under `path_prefix` after waiting.
    pub fn slow(&self, path_prefix: &str, delay: Duration) {
        self.on(
            path_prefix,
            HttpResponse::text(200, "late").with_delay(delay),
        );
    }

    /// Every request received, in order.
    #[must_use]
    pub fn hits(&self) -> Vec<HttpRequest> {
        self.lock().hits.clone()
    }

    /// How many requests were received.
    #[must_use]
    pub fn hit_count(&self) -> usize {
        self.lock().hits.len()
    }

    /// How many requests were for a path under this prefix.
    #[must_use]
    pub fn hits_under(&self, path_prefix: &str) -> usize {
        self.lock()
            .hits
            .iter()
            .filter(|h| h.path().starts_with(path_prefix))
            .count()
    }

    /// The address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.server.addr()
    }

    /// `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, WebState> {
        self.state
            .lock()
            .expect("the scripted server lock is never poisoned")
    }
}

#[cfg(test)]
mod tests;
