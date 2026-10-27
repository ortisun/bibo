//! A small HTTP/1.1 server and client for the fake servers, on the standard library only.
//!
//! The fake GitHub server, the fake registry and the scripted web server all need to answer real
//! HTTP so that an adapter built on a real HTTP client can be pointed at them. This module is the
//! shared plumbing:
//!
//! * [`HttpServer`] binds `127.0.0.1` on a free port (there is no way to bind anything else),
//!   serves each connection on its own thread, closes the connection after one response, and
//!   adds `Server: factory-testkit-fake` and `X-Factory-Fidelity: fake` to every response, so
//!   nothing it says can be taken for the real service.
//! * [`send_request`] is a client for tests: one request, the whole response.
//!
//! It is a test double, not a web server. It reads a request head of at most 64 KiB and a body of
//! at most 16 MiB, supports `Content-Length` and chunked bodies and `Expect: 100-continue`, gives
//! up on a client that sends nothing for five seconds, and does not speak TLS, keep-alive or
//! HTTP/2.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const MAX_HEAD_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// One request, as the server read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// `GET`, `POST` and so on, as sent.
    pub method: String,
    /// The request target: the path and the query.
    pub target: String,
    /// `HTTP/1.1`.
    pub version: String,
    /// The headers in the order and spelling they arrived.
    pub headers: Vec<(String, String)>,
    /// The body, after any chunked decoding.
    pub body: Vec<u8>,
    /// Who connected.
    pub peer: SocketAddr,
}

impl HttpRequest {
    /// The path, without the query.
    #[must_use]
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or_default()
    }

    /// The query string, without the `?`.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, query)| query)
    }

    /// The first value of a query parameter, percent-decoded.
    #[must_use]
    pub fn query_param(&self, key: &str) -> Option<String> {
        self.query()?.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(name) == key).then(|| percent_decode(value))
        })
    }

    /// The first header with this name, compared without regard to case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Every header with this name, in order. A request may repeat a header.
    #[must_use]
    pub fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// The body as text, with invalid UTF-8 replaced.
    #[must_use]
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON, if it is.
    #[must_use]
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

/// A response to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// Extra headers. `Content-Length`, `Connection`, `Server` and `X-Factory-Fidelity` are added.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
    /// How long to wait before sending anything, to model a slow server.
    pub delay: Duration,
}

impl HttpResponse {
    /// A response with no body.
    #[must_use]
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
            delay: Duration::ZERO,
        }
    }

    /// A JSON body with the right content type.
    #[must_use]
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Self::empty(status)
            .with_header("Content-Type", "application/json; charset=utf-8")
            .with_body(value.to_string().into_bytes())
    }

    /// A plain text body.
    #[must_use]
    pub fn text(status: u16, text: &str) -> Self {
        Self::empty(status)
            .with_header("Content-Type", "text/plain; charset=utf-8")
            .with_body(text.as_bytes().to_vec())
    }

    /// A redirect to `location`.
    #[must_use]
    pub fn redirect(status: u16, location: &str) -> Self {
        Self::empty(status).with_header("Location", location)
    }

    /// Adds a header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// Sets the body.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Waits this long before answering.
    #[must_use]
    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        304 => "Not Modified",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

type Handler = dyn Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static;

/// A running server on `127.0.0.1`. Dropping it stops it.
#[derive(Debug)]
pub struct HttpServer {
    name: String,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    connections: Arc<AtomicUsize>,
    thread: Option<JoinHandle<()>>,
}

impl HttpServer {
    /// Starts a server that answers every request with `handler`. `name` appears in the `Server`
    /// header so a log line shows which fake answered.
    ///
    /// # Errors
    /// Returns the I/O error when no loopback socket can be bound.
    pub fn start<H>(name: &str, handler: H) -> io::Result<Self>
    where
        H: Fn(&HttpRequest) -> HttpResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(AtomicUsize::new(0));
        let handler: Arc<Handler> = Arc::new(handler);
        let server_name = name.to_owned();
        let thread = {
            let stop = Arc::clone(&stop);
            let connections = Arc::clone(&connections);
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let handler = Arc::clone(&handler);
                    let server_name = server_name.clone();
                    thread::spawn(move || serve_connection(stream, &*handler, &server_name));
                }
            })
        };
        Ok(Self {
            name: name.to_owned(),
            addr,
            stop,
            connections,
            thread: Some(thread),
        })
    }

    /// The address the server listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// `http://127.0.0.1:<port>`.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The name given at start.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// How many connections were accepted.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop so it sees the flag.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_connection(mut stream: TcpStream, handler: &Handler, server_name: &str) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(READ_TIMEOUT));
    let Ok(peer) = stream.peer_addr() else { return };
    let response = match read_request(&mut stream, peer) {
        Ok(request) => catch_unwind(AssertUnwindSafe(|| handler(&request)))
            .unwrap_or_else(|_| HttpResponse::text(500, "the fake server's handler panicked")),
        Err(ReadError::Closed) => return,
        Err(ReadError::Status(status, message)) => HttpResponse::text(status, message),
    };
    if !response.delay.is_zero() {
        thread::sleep(response.delay);
    }
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status,
        reason(response.status)
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\nServer: factory-testkit-fake ({server_name})\r\nX-Factory-Fidelity: fake\r\n\r\n",
        response.body.len()
    ));
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
    // Drain what the client may still be sending so closing does not reset the connection
    // before the client has read the response.
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut sink = [0u8; 1024];
    while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
}

enum ReadError {
    /// The client closed the connection before sending a request.
    Closed,
    /// The request is unusable; answer with this status and message.
    Status(u16, &'static str),
}

fn read_request(stream: &mut TcpStream, peer: SocketAddr) -> Result<HttpRequest, ReadError> {
    let mut reader = BufReader::new(stream.try_clone().map_err(|_| ReadError::Closed)?);
    let mut head_bytes = 0usize;
    let mut lines = Vec::new();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).map_err(|_| ReadError::Closed)?;
        if read == 0 {
            return Err(ReadError::Closed);
        }
        head_bytes += read;
        if head_bytes > MAX_HEAD_BYTES {
            return Err(ReadError::Status(431, "the request head is too large"));
        }
        let line = line.trim_end_matches(['\r', '\n']).to_owned();
        if line.is_empty() {
            if lines.is_empty() {
                // Tolerate a blank line before the request line, as RFC 9112 allows.
                continue;
            }
            break;
        }
        lines.push(line);
    }
    let mut parts = lines[0].split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ReadError::Status(400, "malformed request line"));
    };
    if !version.starts_with("HTTP/1.") || method.is_empty() || target.is_empty() {
        return Err(ReadError::Status(400, "malformed request line"));
    }
    let mut headers = Vec::new();
    for line in &lines[1..] {
        let Some((name, value)) = line.split_once(':') else {
            return Err(ReadError::Status(400, "malformed header line"));
        };
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(ReadError::Status(400, "malformed header name"));
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    let find = |wanted: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(wanted))
            .map(|(_, v)| v.as_str())
    };
    if find("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    let body =
        if find("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
            read_chunked(&mut reader)?
        } else if let Some(length) = find("content-length") {
            let length: usize = length
                .parse()
                .map_err(|_| ReadError::Status(400, "bad content-length"))?;
            if length > MAX_BODY_BYTES {
                return Err(ReadError::Status(413, "the request body is too large"));
            }
            let mut body = vec![0u8; length];
            reader
                .read_exact(&mut body)
                .map_err(|_| ReadError::Status(400, "the body is shorter than content-length"))?;
            body
        } else {
            Vec::new()
        };
    Ok(HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers,
        body,
        peer,
    })
}

fn read_chunked(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>, ReadError> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader
            .read_line(&mut size_line)
            .map_err(|_| ReadError::Status(400, "bad chunked body"))?;
        let size_text = size_line.trim().split(';').next().unwrap_or_default();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| ReadError::Status(400, "bad chunk size"))?;
        if size == 0 {
            // Skip optional trailers up to the blank line.
            loop {
                let mut trailer = String::new();
                let read = reader.read_line(&mut trailer).unwrap_or(0);
                if read == 0 || trailer.trim().is_empty() {
                    break;
                }
            }
            return Ok(body);
        }
        if body.len() + size > MAX_BODY_BYTES {
            return Err(ReadError::Status(413, "the request body is too large"));
        }
        let start = body.len();
        body.resize(start + size, 0);
        reader
            .read_exact(&mut body[start..])
            .map_err(|_| ReadError::Status(400, "short chunk"))?;
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|_| ReadError::Status(400, "missing chunk terminator"))?;
    }
}

/// Decodes `%XX` escapes and turns `+` into a space. Invalid escapes are kept as they are.
#[must_use]
pub fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let high = char::from(bytes[i + 1]).to_digit(16);
                let low = char::from(bytes[i + 2]).to_digit(16);
                if let (Some(high), Some(low)) = (high, low) {
                    out.push((high * 16 + low) as u8);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A response read by [`send_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResponse {
    /// The status code.
    pub status: u16,
    /// The headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl ClientResponse {
    /// The first header with this name, compared without regard to case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The body as text.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON, if it is.
    #[must_use]
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

/// Sends one request to `addr` and reads the whole response. The connection is closed after it.
///
/// # Errors
/// Returns the I/O error when the connection fails, or `InvalidData` when the answer is not HTTP.
pub fn send_request(
    addr: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<ClientResponse> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_owned());
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| bad("the status line is not HTTP"))?;
    let mut response_headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            response_headers.push((name.to_owned(), value.trim().to_owned()));
        }
    }
    let header = |wanted: &str| {
        response_headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(wanted))
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    if header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line)?;
            let size = usize::from_str_radix(size_line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| bad("bad chunk size"))?;
            if size == 0 {
                break;
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..])?;
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf)?;
        }
    } else if let Some(length) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        body.resize(length, 0);
        reader.read_exact(&mut body)?;
    } else {
        reader.read_to_end(&mut body)?;
    }
    Ok(ClientResponse {
        status,
        headers: response_headers,
        body,
    })
}

#[cfg(test)]
mod tests;
