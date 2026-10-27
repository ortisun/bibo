use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use super::*;

/// A server that echoes the request back as JSON, so a test can see what arrived.
fn echo_server() -> HttpServer {
    HttpServer::start("echo", |request| {
        HttpResponse::json(
            200,
            &serde_json::json!({
                "method": request.method,
                "path": request.path(),
                "query": request.query(),
                "headers": request.headers,
                "body": request.body_text(),
            }),
        )
    })
    .unwrap()
}

/// Sends raw bytes and reads whatever comes back until the server closes.
fn raw(server: &HttpServer, bytes: &[u8]) -> String {
    let mut stream = TcpStream::connect(server.addr()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(bytes).unwrap();
    // Tell the server nothing more is coming, so a request that promised more than it sent is
    // refused at once and not after the read timeout.
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

#[test]
fn the_server_listens_on_loopback_only_and_labels_every_answer_fake() {
    let server = echo_server();
    assert!(server.addr().ip().is_loopback());
    assert!(server.base_url().starts_with("http://127.0.0.1:"));
    let response = send_request(server.addr(), "GET", "/x?a=1", &[], b"").unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.header("x-factory-fidelity"), Some("fake"));
    assert!(
        response
            .header("server")
            .unwrap()
            .contains("factory-testkit-fake (echo)")
    );
    // Error responses carry the label too.
    let bad = raw(&server, b"NONSENSE\r\n\r\n");
    assert!(bad.starts_with("HTTP/1.1 400"), "{bad}");
    assert!(bad.contains("X-Factory-Fidelity: fake"), "{bad}");
}

#[test]
fn a_request_arrives_whole_with_headers_in_their_own_spelling() {
    let server = echo_server();
    let response = send_request(
        server.addr(),
        "POST",
        "/repos/o/r/issues?state=open&q=a%20b",
        &[("X-Custom", "Value One"), ("x-custom", "second")],
        br#"{"k":"v"}"#,
    )
    .unwrap();
    let echoed = response.json().unwrap();
    assert_eq!(echoed["method"], "POST");
    assert_eq!(echoed["path"], "/repos/o/r/issues");
    assert_eq!(echoed["query"], "state=open&q=a%20b");
    assert_eq!(echoed["body"], r#"{"k":"v"}"#);
    let headers = echoed["headers"].to_string();
    assert!(headers.contains("X-Custom") && headers.contains("x-custom"));
}

#[test]
fn request_helpers_read_headers_and_query_parameters() {
    let captured = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&captured);
    let server = HttpServer::start("capture", move |request| {
        *sink.lock().unwrap() = Some(request.clone());
        HttpResponse::empty(204)
    })
    .unwrap();
    send_request(
        server.addr(),
        "GET",
        "/p?name=a%2Bb+c&flag&empty=",
        &[
            ("Authorization", "token abc"),
            ("X-Two", "1"),
            ("x-two", "2"),
        ],
        b"",
    )
    .unwrap();
    let request = captured.lock().unwrap().clone().unwrap();
    assert_eq!(request.header("authorization"), Some("token abc"));
    assert_eq!(request.headers_named("X-TWO"), ["1", "2"]);
    assert_eq!(request.query_param("name").as_deref(), Some("a+b c"));
    assert_eq!(request.query_param("flag").as_deref(), Some(""));
    assert_eq!(request.query_param("empty").as_deref(), Some(""));
    assert_eq!(request.query_param("missing"), None);
    assert!(request.peer.ip().is_loopback());
}

#[test]
fn a_chunked_body_is_decoded_and_100_continue_is_answered() {
    let server = echo_server();
    let reply = raw(
        &server,
        b"POST /c HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n3\r\nabc\r\n4;ext=1\r\ndefg\r\n0\r\n\r\n",
    );
    assert!(reply.starts_with("HTTP/1.1 100 Continue"), "{reply}");
    assert!(reply.contains("\"body\":\"abcdefg\""), "{reply}");
}

#[test]
fn oversize_and_malformed_requests_are_refused_without_a_panic() {
    let server = echo_server();
    // A body larger than the limit is refused before it is read.
    let big = raw(
        &server,
        format!(
            "POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            32 * 1024 * 1024
        )
        .as_bytes(),
    );
    assert!(big.starts_with("HTTP/1.1 413"), "{big}");
    // A body shorter than it says.
    let short = raw(
        &server,
        b"POST /x HTTP/1.1\r\nContent-Length: 50\r\n\r\nshort",
    );
    assert!(short.starts_with("HTTP/1.1 400"), "{short}");
    // A header with no colon, and a header name with a space.
    assert!(raw(&server, b"GET / HTTP/1.1\r\nbroken header\r\n\r\n").starts_with("HTTP/1.1 400"));
    assert!(raw(&server, b"GET / HTTP/1.1\r\nBad Name: x\r\n\r\n").starts_with("HTTP/1.1 400"));
    // A head without end and over the limit.
    let long_head = format!("GET / HTTP/1.1\r\nX: {}\r\n", "a".repeat(70 * 1024));
    assert!(raw(&server, long_head.as_bytes()).starts_with("HTTP/1.1 431"));
    // The server is still serving.
    assert_eq!(
        send_request(server.addr(), "GET", "/ok", &[], b"")
            .unwrap()
            .status,
        200
    );
}

#[test]
fn a_panicking_handler_gives_a_500_and_leaves_the_server_up() {
    let server = HttpServer::start("boom", |request| {
        assert!(request.path() != "/boom", "the handler fails on purpose");
        HttpResponse::text(200, "fine")
    })
    .unwrap();
    assert_eq!(
        send_request(server.addr(), "GET", "/boom", &[], b"")
            .unwrap()
            .status,
        500
    );
    assert_eq!(
        send_request(server.addr(), "GET", "/fine", &[], b"")
            .unwrap()
            .text(),
        "fine"
    );
}

#[test]
fn a_delayed_response_is_delayed() {
    let server = HttpServer::start("slow", |_| {
        HttpResponse::text(200, "late").with_delay(Duration::from_millis(300))
    })
    .unwrap();
    let started = std::time::Instant::now();
    let response = send_request(server.addr(), "GET", "/", &[], b"").unwrap();
    assert_eq!(response.text(), "late");
    assert!(started.elapsed() >= Duration::from_millis(300));
}

#[test]
fn responses_with_redirects_and_empty_bodies_round_trip() {
    let server = HttpServer::start("redirect", |_| {
        HttpResponse::redirect(302, "http://attacker.test/next")
    })
    .unwrap();
    let response = send_request(server.addr(), "GET", "/", &[], b"").unwrap();
    assert_eq!(response.status, 302);
    assert_eq!(
        response.header("location"),
        Some("http://attacker.test/next")
    );
    assert!(response.body.is_empty());
}

#[test]
fn connections_are_counted_and_the_port_closes_on_drop() {
    let server = echo_server();
    let addr = server.addr();
    send_request(addr, "GET", "/a", &[], b"").unwrap();
    send_request(addr, "GET", "/b", &[], b"").unwrap();
    assert_eq!(server.connection_count(), 2);
    drop(server);
    assert!(
        TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err(),
        "the port is still open after the server was dropped"
    );
}

#[test]
fn percent_decoding_keeps_what_it_cannot_decode() {
    assert_eq!(percent_decode("a%20b+c%2"), "a b c%2");
    assert_eq!(percent_decode("%zz%41"), "%zzA");
    assert_eq!(percent_decode(""), "");
}
