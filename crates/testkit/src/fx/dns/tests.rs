use std::io::Write;
use std::net::TcpStream;

use super::*;
use crate::fx::http::send_request;

/// A DNS query for one name, written by hand from RFC 1035 so the test does not rely on the
/// server's own parser.
fn build_query(id: u16, name: &str, record_type: u16) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]); // recursion desired
    packet.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&[0, 1]);
    packet
}

/// Sends a packet and waits briefly for an answer.
fn ask(server: &FlippingDns, packet: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    socket.send_to(packet, server.addr()).unwrap();
    let mut buffer = [0u8; 1500];
    let (length, _) = socket.recv_from(&mut buffer).ok()?;
    Some(buffer[..length].to_vec())
}

struct Reply {
    rcode: u8,
    answers: Vec<Vec<u8>>,
    ttl: Option<u32>,
}

fn read_reply(response: &[u8]) -> Reply {
    let answer_count = usize::from(u16::from_be_bytes([response[6], response[7]]));
    // Skip the question: header, then labels, then type and class.
    let mut at = 12;
    while response[at] != 0 {
        at += usize::from(response[at]) + 1;
    }
    at += 5;
    let mut answers = Vec::new();
    let mut ttl = None;
    for _ in 0..answer_count {
        assert_eq!(
            &response[at..at + 2],
            &[0xC0, 0x0C],
            "the name is a pointer"
        );
        ttl = Some(u32::from_be_bytes(
            response[at + 6..at + 10].try_into().unwrap(),
        ));
        let length = usize::from(u16::from_be_bytes([response[at + 10], response[at + 11]]));
        answers.push(response[at + 12..at + 12 + length].to_vec());
        at += 12 + length;
    }
    Reply {
        rcode: response[3] & 0x0F,
        answers,
        ttl,
    }
}

fn a_record(server: &FlippingDns, name: &str) -> Reply {
    read_reply(&ask(server, &build_query(7, name, 1)).expect("an answer"))
}

const PUBLIC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const METADATA: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

#[test]
fn the_wire_format_matches_rfc_1035_byte_for_byte() {
    let server = FlippingDns::start().unwrap();
    server.always("example.test", DnsAnswer::A(Ipv4Addr::new(192, 0, 2, 1)));
    let query = build_query(0x1234, "example.test", 1);
    assert_eq!(
        query,
        [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1
        ],
        "the hand-built query is the one in the RFC's layout"
    );
    let response = ask(&server, &query).unwrap();
    assert_eq!(
        response,
        [
            0x12, 0x34, // same id
            0x85, 0x80, // QR, AA, RD copied; RA, rcode 0
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // 1 question, 1 answer
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
            0xC0, 0x0C, // name: pointer to the question
            0x00, 0x01, 0x00, 0x01, // type A, class IN
            0x00, 0x00, 0x00, 0x00, // time to live zero
            0x00, 0x04, 192, 0, 2, 1
        ]
    );
}

#[test]
fn a_name_can_flip_from_a_public_address_to_a_private_one_and_stays_there() {
    let server = FlippingDns::start().unwrap();
    server.set(
        "rebind.test",
        vec![
            DnsAnswer::A(PUBLIC),
            DnsAnswer::A(LOOPBACK),
            DnsAnswer::A(METADATA),
        ],
    );
    let seen: Vec<Vec<u8>> = (0..5)
        .map(|_| a_record(&server, "rebind.test").answers.remove(0))
        .collect();
    assert_eq!(seen[0], PUBLIC.octets());
    assert_eq!(seen[1], LOOPBACK.octets());
    assert_eq!(seen[2], METADATA.octets());
    assert_eq!(seen[3], METADATA.octets(), "the last answer repeats");
    assert_eq!(seen[4], METADATA.octets());

    // A new list starts again from its first answer.
    server.set(
        "rebind.test",
        vec![DnsAnswer::A(PUBLIC), DnsAnswer::A(LOOPBACK)],
    );
    assert_eq!(a_record(&server, "rebind.test").answers[0], PUBLIC.octets());
    assert_eq!(
        a_record(&server, "rebind.test").answers[0],
        LOOPBACK.octets()
    );
    server.always("rebind.test", DnsAnswer::A(PUBLIC));
    assert_eq!(a_record(&server, "rebind.test").answers[0], PUBLIC.octets());
}

#[test]
fn answers_carry_a_zero_time_to_live_so_a_resolver_cannot_cache_the_first() {
    let server = FlippingDns::start().unwrap();
    server.always("ttl.test", DnsAnswer::A(PUBLIC));
    assert_eq!(a_record(&server, "ttl.test").ttl, Some(0));
}

#[test]
fn missing_names_failures_and_other_record_types_are_answered_as_a_server_would() {
    let server = FlippingDns::start().unwrap();
    server.always("v4-only.test", DnsAnswer::A(PUBLIC));
    server.always("v6.test", DnsAnswer::Aaaa(Ipv6Addr::LOCALHOST));
    server.always("broken.test", DnsAnswer::ServFail);
    server.always("gone.test", DnsAnswer::NxDomain);

    assert_eq!(
        a_record(&server, "nobody.test").rcode,
        3,
        "an unknown name does not exist"
    );
    assert_eq!(a_record(&server, "gone.test").rcode, 3);
    assert_eq!(a_record(&server, "broken.test").rcode, 2);
    // The name exists but has no AAAA record: success with an empty answer.
    let nodata = read_reply(&ask(&server, &build_query(1, "v4-only.test", 28)).unwrap());
    assert_eq!((nodata.rcode, nodata.answers.len()), (0, 0));
    let v6 = read_reply(&ask(&server, &build_query(1, "v6.test", 28)).unwrap());
    assert_eq!(v6.answers[0], Ipv6Addr::LOCALHOST.octets());
    // And an A query for the AAAA-only name.
    let none = a_record(&server, "v6.test");
    assert_eq!((none.rcode, none.answers.len()), (0, 0));
}

#[test]
fn names_match_without_regard_to_case_or_a_final_dot() {
    let server = FlippingDns::start().unwrap();
    server.always("Registry.NPMJS.example.", DnsAnswer::A(PUBLIC));
    assert_eq!(
        a_record(&server, "REGISTRY.npmjs.EXAMPLE").answers[0],
        PUBLIC.octets()
    );
    assert_eq!(server.query_count("registry.npmjs.example"), 1);
}

#[test]
fn every_query_is_recorded_with_its_answer_and_labelled_fake() {
    let server = FlippingDns::start().unwrap();
    server.set("a.test", vec![DnsAnswer::A(PUBLIC), DnsAnswer::A(LOOPBACK)]);
    a_record(&server, "a.test");
    a_record(&server, "a.test");
    a_record(&server, "unknown.test");
    let queries = server.queries();
    assert_eq!(queries.len(), 3);
    assert_eq!(queries[0].answer, "A 192.0.2.10");
    assert_eq!(queries[1].answer, "A 127.0.0.1");
    assert_eq!(queries[2].answer, "NXDOMAIN");
    assert_eq!(queries[0].record_type, 1);
    assert_eq!(server.query_count("a.test"), 2);
    let json = server.to_json();
    assert_eq!(json["fidelity"], "fake");
    assert_eq!(json["queries"][0]["fidelity"], "fake");
}

#[test]
fn malformed_packets_get_no_answer_and_do_not_stop_the_server() {
    let server = FlippingDns::start().unwrap();
    server.always("ok.test", DnsAnswer::A(PUBLIC));

    let mut two_questions = build_query(1, "ok.test", 1);
    two_questions[5] = 2;
    let mut as_response = build_query(1, "ok.test", 1);
    as_response[2] |= 0x80;
    let mut long_label = build_query(1, "ok.test", 1);
    long_label[12] = 64; // a label may be at most 63 bytes
    let mut pointer = build_query(1, "ok.test", 1);
    pointer[12] = 0xC0; // compression is not allowed in a question
    let mut wrong_class = build_query(1, "ok.test", 1);
    let last = wrong_class.len() - 1;
    wrong_class[last] = 3;
    let truncated = build_query(1, "ok.test", 1)[..20].to_vec();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("short", vec![1, 2, 3]),
        ("two questions", two_questions),
        ("already a response", as_response),
        ("label too long", long_label),
        ("compression pointer", pointer),
        ("class not IN", wrong_class),
        ("truncated", truncated),
    ];
    for (name, packet) in &cases {
        assert!(ask(&server, packet).is_none(), "{name} must get no answer");
    }
    assert_eq!(server.malformed_packets(), cases.len());
    assert!(
        server.queries().is_empty(),
        "a malformed packet is not a query"
    );
    assert_eq!(a_record(&server, "ok.test").answers[0], PUBLIC.octets());
}

#[test]
fn rebinding_beats_a_client_that_resolves_twice_and_not_one_that_resolves_once() {
    // The attack, in miniature. A name answers with a public address when the client checks it
    // and with the address of an internal listener when the client connects. A client that
    // resolves again to connect reaches the listener. A client that connects to the address it
    // checked does not. The fixture has to make the first possible and the second visible.
    let internal = EchoListener::start().unwrap();
    let dns = FlippingDns::start().unwrap();
    dns.set(
        "rebind.test",
        vec![DnsAnswer::A(PUBLIC), DnsAnswer::A(LOOPBACK)],
    );

    let resolve = |name: &str| -> Ipv4Addr {
        let reply = a_record(&dns, name);
        let octets: [u8; 4] = reply.answers[0].clone().try_into().unwrap();
        Ipv4Addr::from(octets)
    };
    let is_public = |ip: Ipv4Addr| !ip.is_loopback() && !ip.is_link_local() && !ip.is_private();

    // The careless client: check one answer, connect to the next.
    let checked = resolve("rebind.test");
    assert!(is_public(checked), "the check passes");
    let used = resolve("rebind.test");
    assert!(
        used.is_loopback(),
        "the connection goes to the internal address"
    );
    let mut stream = TcpStream::connect((used, internal.addr().port())).unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    drop(stream);
    // Wait for the listener's short read to finish before looking.
    thread::sleep(Duration::from_millis(250));
    assert_eq!(
        internal.connection_count(),
        1,
        "the attack reached the listener"
    );

    // The careful client: use the address it checked, and never connect to a non-public one.
    dns.set(
        "rebind.test",
        vec![DnsAnswer::A(PUBLIC), DnsAnswer::A(LOOPBACK)],
    );
    let pinned = resolve("rebind.test");
    assert!(is_public(pinned));
    // It would connect to `pinned` (a documentation address) and never to the listener.
    assert_eq!(
        internal.connection_count(),
        1,
        "no new connection reached the listener"
    );
}

#[test]
fn the_echo_listener_notes_each_connection_and_what_was_sent() {
    let listener = EchoListener::start().unwrap();
    assert_eq!(listener.connection_count(), 0, "nothing connected yet");
    let mut first = TcpStream::connect(listener.addr()).unwrap();
    first.write_all(b"hello there").unwrap();
    drop(first);
    drop(TcpStream::connect(listener.addr()).unwrap());
    thread::sleep(Duration::from_millis(400));
    let connections = listener.connections();
    assert_eq!(connections.len(), 2);
    assert_eq!(connections[0].first_bytes, b"hello there");
    assert!(connections[1].first_bytes.is_empty());
    assert!(connections[0].peer.ip().is_loopback());
}

#[test]
fn the_scripted_http_server_redirects_delays_floods_and_counts() {
    let web = ScriptedHttp::start("upstream").unwrap();
    assert_eq!(web.hit_count(), 0);

    // Nothing is scripted yet.
    let response = send_request(web.addr(), "GET", "/x", &[], b"").unwrap();
    assert_eq!(response.status, 404);
    assert_eq!(web.hit_count(), 1);

    web.redirect("/go", 302, "http://127.0.0.1:9/internal");
    let response = send_request(web.addr(), "GET", "/go/there", &[], b"").unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(
        response.header("location"),
        Some("http://127.0.0.1:9/internal")
    );

    web.large("/big", 3 * 1024 * 1024);
    let response = send_request(web.addr(), "GET", "/big", &[], b"").unwrap();
    assert_eq!(response.body.len(), 3 * 1024 * 1024);

    web.slow("/slow", Duration::from_millis(300));
    let started = std::time::Instant::now();
    send_request(web.addr(), "GET", "/slow", &[], b"").unwrap();
    assert!(started.elapsed() >= Duration::from_millis(300));

    // The longest prefix wins.
    web.on("/go/special", HttpResponse::text(200, "special"));
    let response = send_request(web.addr(), "GET", "/go/special/x", &[], b"").unwrap();
    assert_eq!(response.text(), "special");

    assert_eq!(web.hit_count(), 5);
    assert_eq!(web.hits_under("/go"), 2);
    assert_eq!(
        web.hits_under("/never"),
        0,
        "an untouched path has zero hits"
    );
    assert_eq!(web.hits()[0].method, "GET");
    assert_eq!(
        send_request(web.addr(), "GET", "/x", &[], b"")
            .unwrap()
            .header("x-factory-fidelity"),
        Some("fake")
    );
}
