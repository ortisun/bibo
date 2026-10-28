//! A labelled fake model provider on the loopback address, for the broker's tests.
//!
//! FIDELITY: FAKE. It answers the four model routes with canned text and a usage report in the
//! shape of the Anthropic Messages API (server-sent events) and the OpenAI Responses and Chat
//! Completions APIs, records every request it receives (the headers as received, with the
//! credential, so a test can see what the broker sent upstream), and can be told to misbehave: cut
//! a stream short, answer an error, delay events, or echo a request header back. It holds no
//! provider behaviour that was not seen in `fixtures/recordings/agent-cli/fake/fake_provider.py`.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// What the fake provider received.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: String,
    /// Header names in lower case, values as received.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Recorded {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// How the fake answers.
#[derive(Debug, Clone)]
pub struct Script {
    /// Anthropic usage: input, cache write, cache read, output.
    pub anthropic: (u64, u64, u64, u64),
    /// OpenAI usage: input (cached tokens included), cached, output.
    pub openai: (u64, u64, u64),
    /// A pause before each event of a stream.
    pub event_delay: Duration,
    /// Close the connection after this many events, with no usage report.
    pub cut_after_events: Option<usize>,
    /// Answer this status with an error body instead of the normal answer.
    pub error_status: Option<u16>,
    /// An extra response header, as a name and a value. Used to play a provider that echoes a
    /// credential back.
    pub extra_header: Option<(String, String)>,
    /// Put the `x-api-key` or `authorization` header of the request into the text of the answer.
    pub echo_credential_in_body: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            anthropic: (1234, 7, 89, 56),
            openai: (1234, 89, 56),
            event_delay: Duration::ZERO,
            cut_after_events: None,
            error_status: None,
            extra_header: None,
            echo_credential_in_body: false,
        }
    }
}

pub struct FakeProvider {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Recorded>>>,
    script: Arc<Mutex<Script>>,
    stop: Arc<AtomicBool>,
}

impl FakeProvider {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind the fake provider");
        let addr = listener.local_addr().expect("address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let script = Arc::new(Mutex::new(Script::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (r, s, st) = (requests.clone(), script.clone(), stop.clone());
        thread::spawn(move || {
            for stream in listener.incoming() {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let (r, s) = (r.clone(), s.clone());
                thread::spawn(move || handle(stream, &r, &s));
            }
        });
        Self {
            addr,
            requests,
            script,
            stop,
        }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn set(&self, change: impl FnOnce(&mut Script)) {
        change(&mut self.script.lock().expect("script"));
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("requests").clone()
    }

    pub fn hits(&self) -> usize {
        self.requests().len()
    }
}

impl Drop for FakeProvider {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Recorded> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    let end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?.to_owned();
    let (path, query) = target
        .split_once('?')
        .map_or((target.clone(), String::new()), |(p, q)| {
            (p.to_owned(), q.to_owned())
        });
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(n, _)| n == "content-length")
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = buffer[end..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Recorded {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn chunk(stream: &mut TcpStream, data: &str) -> std::io::Result<()> {
    stream.write_all(format!("{:x}\r\n{data}\r\n", data.len()).as_bytes())?;
    stream.flush()
}

fn handle(mut stream: TcpStream, requests: &Mutex<Vec<Recorded>>, script: &Mutex<Script>) {
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    requests.lock().expect("requests").push(request.clone());
    let script = script.lock().expect("script").clone();
    let wants_stream = request.json()["stream"].as_bool().unwrap_or(false);
    let extra = script
        .extra_header
        .as_ref()
        .map(|(n, v)| format!("{n}: {v}\r\n"))
        .unwrap_or_default();
    let credential = request
        .header("x-api-key")
        .or_else(|| request.header("authorization"))
        .unwrap_or("")
        .to_owned();
    let text = if script.echo_credential_in_body {
        format!("your credential was {credential}")
    } else {
        "hello from the fake provider".to_owned()
    };

    if let Some(status) = script.error_status {
        let body = r#"{"type":"error","error":{"type":"fake_error","message":"scripted failure"}}"#;
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 {status} Scripted\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
        return;
    }

    let anthropic = request.path.starts_with("/v1/messages");
    let (a_in, a_cw, a_cr, a_out) = script.anthropic;
    let (o_in, o_cached, o_out) = script.openai;

    if request.path == "/v1/messages/count_tokens" {
        let body = format!("{{\"input_tokens\":{a_in}}}");
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
        return;
    }

    if !wants_stream {
        let body = if anthropic {
            format!(
                "{{\"type\":\"message\",\"content\":[{{\"type\":\"text\",\"text\":\"{text}\"}}],\"usage\":{{\"input_tokens\":{a_in},\"cache_creation_input_tokens\":{a_cw},\"cache_read_input_tokens\":{a_cr},\"output_tokens\":{a_out}}}}}"
            )
        } else {
            format!(
                "{{\"output_text\":\"{text}\",\"usage\":{{\"input_tokens\":{o_in},\"input_tokens_details\":{{\"cached_tokens\":{o_cached}}},\"output_tokens\":{o_out}}}}}"
            )
        };
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
        return;
    }

    let events: Vec<String> = if anthropic {
        vec![
            format!(
                "event: message_start\ndata: {{\"type\":\"message_start\",\"message\":{{\"usage\":{{\"input_tokens\":{a_in},\"cache_creation_input_tokens\":{a_cw},\"cache_read_input_tokens\":{a_cr},\"output_tokens\":1}}}}}}\n\n"
            ),
            format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"delta\":{{\"type\":\"text_delta\",\"text\":\"{text}\"}}}}\n\n"
            ),
            format!(
                "event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\"usage\":{{\"output_tokens\":{a_out}}}}}\n\n"
            ),
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_owned(),
        ]
    } else {
        vec![
            "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{}}\n\n"
                .to_owned(),
            format!(
                "event: response.output_text.delta\ndata: {{\"type\":\"response.output_text.delta\",\"delta\":\"{text}\"}}\n\n"
            ),
            format!(
                "event: response.completed\ndata: {{\"type\":\"response.completed\",\"response\":{{\"usage\":{{\"input_tokens\":{o_in},\"input_tokens_details\":{{\"cached_tokens\":{o_cached}}},\"output_tokens\":{o_out}}}}}}}\n\n"
            ),
        ]
    };
    if stream
        .write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{extra}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .is_err()
    {
        return;
    }
    for (i, event) in events.iter().enumerate() {
        if script.cut_after_events == Some(i) {
            return;
        }
        if !script.event_delay.is_zero() {
            thread::sleep(script.event_delay);
        }
        if chunk(&mut stream, event).is_err() {
            return;
        }
    }
    let _ = stream.write_all(b"0\r\n\r\n");
}
