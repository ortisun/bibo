//! The HTTP/1.1 the sandbox speaks to the broker, on the standard library and `httparse`.
//!
//! Only what the two tools send is accepted, and everything else is refused with a short error:
//! HTTP/1.1, a request head of bounded size, one `Content-Length` and no `Transfer-Encoding`
//! (a request with both is the shape of a smuggling attempt, and the tools send neither chunked
//! bodies nor trailers), and a path and query made of a small character set. A connection serves
//! one request and is closed, so there is no pipelining to confuse.

use std::io::{self, Read, Write};
use std::net::TcpStream;

/// Why a request could not be read. Each maps to one status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadError {
    /// The peer closed the connection before sending a request.
    Closed,
    /// The head is not valid HTTP/1.1, or holds something this server refuses.
    Malformed,
    /// The head is larger than the limit.
    HeadTooLarge,
    /// The body is larger than the limit.
    BodyTooLarge,
    /// A body is needed and no length was given.
    LengthRequired,
    /// The client was too slow.
    Timeout,
    /// The connection failed.
    Io,
}

impl ReadError {
    /// The status to answer with, or `None` when the connection is just dropped.
    #[must_use]
    pub const fn status(self) -> Option<u16> {
        match self {
            Self::Closed | Self::Io => None,
            Self::Malformed => Some(400),
            Self::HeadTooLarge => Some(431),
            Self::BodyTooLarge => Some(413),
            Self::LengthRequired => Some(411),
            Self::Timeout => Some(408),
        }
    }

    fn from_io(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::UnexpectedEof => Self::Closed,
            _ => Self::Io,
        }
    }
}

/// The parts of a request head the broker uses.
#[derive(Debug, Clone)]
pub struct RequestHead {
    /// `GET`, `POST` and so on, as sent.
    pub method: String,
    /// The path, without the query.
    pub path: String,
    /// The query, without the `?`, when there is one.
    pub query: Option<String>,
    /// Header names in lower case, and their values, in the order sent.
    pub headers: Vec<(String, String)>,
    /// The declared body length.
    pub content_length: Option<usize>,
}

impl RequestHead {
    /// The value of a header, when it is present once. A header that is repeated gives `None`,
    /// because the broker does not choose between two credentials or two types.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        let mut found = self.headers.iter().filter(|(n, _)| n == name);
        let first = found.next()?;
        if found.next().is_some() {
            return None;
        }
        Some(first.1.as_str())
    }

    /// True when a header is present at all.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.headers.iter().any(|(n, _)| n == name)
    }
}

fn path_char_ok(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte)
}

fn query_char_ok(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~=&%+,:".contains(&byte)
}

/// Reads the request head. Returns it and the bytes that followed it in the same reads.
///
/// # Errors
/// [`ReadError`].
pub fn read_head(
    stream: &mut TcpStream,
    max_head_bytes: usize,
) -> Result<(RequestHead, Vec<u8>), ReadError> {
    let mut buffer = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 4096];
    loop {
        let read = match stream.read(&mut chunk) {
            Ok(0) if buffer.is_empty() => return Err(ReadError::Closed),
            Ok(0) => return Err(ReadError::Malformed),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ReadError::from_io(&e)),
        };
        buffer.extend_from_slice(&chunk[..read]);
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut request = httparse::Request::new(&mut headers);
        match request.parse(&buffer) {
            Ok(httparse::Status::Complete(end)) => {
                let head = interpret(&request)?;
                let rest = buffer.split_off(end);
                return Ok((head, rest));
            }
            Ok(httparse::Status::Partial) => {
                if buffer.len() > max_head_bytes {
                    return Err(ReadError::HeadTooLarge);
                }
            }
            Err(httparse::Error::TooManyHeaders) => return Err(ReadError::HeadTooLarge),
            Err(_) => return Err(ReadError::Malformed),
        }
    }
}

fn interpret(request: &httparse::Request<'_, '_>) -> Result<RequestHead, ReadError> {
    if request.version != Some(1) {
        return Err(ReadError::Malformed);
    }
    let method = request.method.ok_or(ReadError::Malformed)?.to_owned();
    let target = request.path.ok_or(ReadError::Malformed)?;
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (target, None),
    };
    if !path.starts_with('/') || !path.bytes().all(path_char_ok) {
        return Err(ReadError::Malformed);
    }
    if let Some(query) = query
        && (query.len() > 256 || !query.bytes().all(query_char_ok))
    {
        return Err(ReadError::Malformed);
    }
    let mut headers = Vec::with_capacity(request.headers.len());
    let mut content_length: Option<usize> = None;
    for header in request.headers.iter() {
        let name = header.name.to_ascii_lowercase();
        let value = std::str::from_utf8(header.value)
            .map_err(|_| ReadError::Malformed)?
            .trim()
            .to_owned();
        if value.bytes().any(|b| b.is_ascii_control()) {
            return Err(ReadError::Malformed);
        }
        match name.as_str() {
            "transfer-encoding" => return Err(ReadError::Malformed),
            "content-length" => {
                let parsed = value
                    .bytes()
                    .all(|b| b.is_ascii_digit())
                    .then(|| value.parse::<usize>().ok())
                    .flatten()
                    .ok_or(ReadError::Malformed)?;
                if content_length.is_some_and(|earlier| earlier != parsed) {
                    return Err(ReadError::Malformed);
                }
                content_length = Some(parsed);
            }
            _ => {}
        }
        headers.push((name, value));
    }
    Ok(RequestHead {
        method,
        path: path.to_owned(),
        query: query.map(str::to_owned),
        headers,
        content_length,
    })
}

/// Reads the body that follows a head: `already` is what came with the head.
///
/// # Errors
/// [`ReadError`].
pub fn read_body(
    stream: &mut TcpStream,
    mut already: Vec<u8>,
    length: usize,
) -> Result<Vec<u8>, ReadError> {
    if already.len() > length {
        // More bytes than the length declares: a second request, which this server does not take.
        return Err(ReadError::Malformed);
    }
    let mut chunk = [0_u8; 16 * 1024];
    while already.len() < length {
        let want = (length - already.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => return Err(ReadError::Malformed),
            Ok(n) => already.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ReadError::from_io(&e)),
        }
    }
    Ok(already)
}

/// The reason phrase of the statuses the broker sends.
fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        411 => "Length Required",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Status",
    }
}

fn head(status: u16, headers: &[(&str, &str)], framing: &str) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} {}\r\n", reason(status));
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    out.push_str(framing);
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

/// Writes a whole response with a `Content-Length`.
///
/// # Errors
/// The write error.
pub fn write_response(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<()> {
    let framing = format!("Content-Length: {}\r\n", body.len());
    stream.write_all(&head(status, headers, &framing))?;
    stream.write_all(body)?;
    stream.flush()
}

/// Writes the head of a response whose body follows in chunks.
///
/// # Errors
/// The write error.
pub fn write_chunked_head(
    stream: &mut TcpStream,
    status: u16,
    headers: &[(&str, &str)],
) -> io::Result<()> {
    stream.write_all(&head(status, headers, "Transfer-Encoding: chunked\r\n"))?;
    stream.flush()
}

/// Writes one chunk and flushes it, so an event reaches the tool as soon as it is read.
///
/// # Errors
/// The write error.
pub fn write_chunk(stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
    if data.is_empty() {
        return Ok(());
    }
    stream.write_all(format!("{:x}\r\n", data.len()).as_bytes())?;
    stream.write_all(data)?;
    stream.write_all(b"\r\n")?;
    stream.flush()
}

/// Ends a chunked body.
///
/// # Errors
/// The write error.
pub fn write_last_chunk(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(b"0\r\n\r\n")?;
    stream.flush()
}

/// Sends the interim response for `Expect: 100-continue`.
///
/// # Errors
/// The write error.
pub fn write_continue(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Feeds raw bytes through a real socket and returns what `read_head` makes of them.
    fn parse(raw: &[u8]) -> Result<(RequestHead, Vec<u8>), ReadError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let payload = raw.to_vec();
        let writer = std::thread::spawn(move || {
            let mut client = TcpStream::connect(addr).expect("connect");
            client.write_all(&payload).expect("write");
            client
                .shutdown(std::net::Shutdown::Write)
                .expect("shutdown");
            std::thread::sleep(std::time::Duration::from_millis(50));
        });
        let (mut server_side, _) = listener.accept().expect("accept");
        server_side
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("timeout");
        let result = read_head(&mut server_side, 8 * 1024);
        writer.join().expect("writer");
        result
    }

    #[test]
    fn a_plain_request_is_read_and_its_names_are_lower_cased() {
        let (head, rest) = parse(
            b"POST /v1/messages?beta=true HTTP/1.1\r\nHost: x\r\nX-Api-Key: abc\r\nContent-Length: 2\r\n\r\n{}",
        )
        .expect("a request");
        assert_eq!(head.method, "POST");
        assert_eq!(head.path, "/v1/messages");
        assert_eq!(head.query.as_deref(), Some("beta=true"));
        assert_eq!(head.header("x-api-key"), Some("abc"));
        assert_eq!(head.content_length, Some(2));
        assert_eq!(rest, b"{}");
    }

    #[test]
    fn requests_with_smuggling_shapes_or_odd_targets_are_refused() {
        let cases: &[(&str, &[u8])] = &[
            (
                "chunked",
                b"POST /v1/messages HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            ),
            (
                "two different lengths",
                b"POST /v1/messages HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            ),
            (
                "a signed length",
                b"POST /v1/messages HTTP/1.1\r\nContent-Length: +5\r\n\r\n",
            ),
            ("http 1.0", b"POST /v1/messages HTTP/1.0\r\n\r\n"),
            (
                "a space in the path",
                b"POST /v1/mess ages HTTP/1.1\r\n\r\n",
            ),
            (
                "an absolute target",
                b"POST http://evil.test/v1/messages HTTP/1.1\r\n\r\n",
            ),
            (
                "a percent in the path",
                b"POST /v1/%2e%2e/x HTTP/1.1\r\n\r\n",
            ),
            (
                "a fragment in the query",
                b"POST /v1/messages?a=b#c HTTP/1.1\r\n\r\n",
            ),
            (
                "a header with a control byte",
                b"POST /v1/messages HTTP/1.1\r\nX: a\x01b\r\n\r\n",
            ),
        ];
        for (name, raw) in cases {
            assert_eq!(parse(raw).unwrap_err(), ReadError::Malformed, "{name}");
        }
    }

    #[test]
    fn a_head_that_never_ends_is_cut_off_at_the_limit() {
        let mut raw = b"POST /v1/messages HTTP/1.1\r\nX-Pad: ".to_vec();
        raw.extend(std::iter::repeat_n(b'a', 20 * 1024));
        assert_eq!(parse(&raw).unwrap_err(), ReadError::HeadTooLarge);
    }

    #[test]
    fn a_repeated_header_has_no_single_value() {
        let (head, _) =
            parse(b"POST /v1/messages HTTP/1.1\r\nX-Api-Key: a\r\nX-Api-Key: b\r\n\r\n")
                .expect("a request");
        assert_eq!(head.header("x-api-key"), None);
        assert!(head.has("x-api-key"));
    }

    #[test]
    fn an_empty_connection_is_closed_not_malformed() {
        assert_eq!(parse(b"").unwrap_err(), ReadError::Closed);
    }
}
