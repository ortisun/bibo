//! A span and a metric leave the process as OTLP over HTTP and arrive at a receiver.
//!
//! The receiver is a small HTTP server in this file, listening on a local port. It stands in for
//! the OpenTelemetry Collector. The test proves the wire path of this crate: the real OTLP
//! exporter, the real batch processors and the guard in front of them. It does not prove that
//! the collector accepts the data. `infra/otel/README.md` describes that check.
//!
//! If the test cannot open a local port, it fails with a message that starts with `BLOCKED`. A
//! blocked run is never a pass.

mod common;

use factory_observability::spans::{self, Job};
use factory_observability::telemetry::{TelemetryConfig, build_pipeline};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const CORRELATION: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77";

#[derive(Debug, Clone)]
struct Received {
    method: String,
    path: String,
    content_type: String,
    body: Vec<u8>,
}

impl Received {
    fn contains(&self, needle: &str) -> bool {
        self.body
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }
}

struct Receiver {
    port: u16,
    requests: Arc<Mutex<Vec<Received>>>,
}

impl Receiver {
    fn start() -> Receiver {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| {
            panic!("BLOCKED: cannot open a local port for the OTLP receiver: {error}")
        });
        let port = listener.local_addr().expect("local address").port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    let _ = serve(stream, &shared);
                });
            }
        });
        Receiver { port, requests }
    }

    fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Wait until a request for `path` has arrived, or give up after `patience`.
    fn wait_for(&self, path: &str, patience: Duration) -> Option<Received> {
        let deadline = Instant::now() + patience;
        loop {
            if let Some(found) = self
                .requests
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.path == path)
                .cloned()
            {
                return Some(found);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(25));
        }
    }
}

/// Answer HTTP/1.1 requests on one connection until the client closes it.
fn serve(stream: TcpStream, store: &Mutex<Vec<Received>>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line)? == 0 {
            return Ok(());
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_string();
        let path = parts.next().unwrap_or_default().to_string();

        let mut headers: HashMap<String, String> = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        let body = if headers
            .get("transfer-encoding")
            .is_some_and(|v| v.eq_ignore_ascii_case("chunked"))
        {
            read_chunked(&mut reader)?
        } else {
            let length: usize = headers
                .get("content-length")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body)?;
            body
        };

        store.lock().unwrap().push(Received {
            method,
            path,
            content_type: headers.get("content-type").cloned().unwrap_or_default(),
            body,
        });
        writer.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: application/x-protobuf\r\ncontent-length: 0\r\n\r\n",
        )?;
    }
}

fn read_chunked(reader: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line)?;
        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
        if size == 0 {
            let mut end = String::new();
            reader.read_line(&mut end)?;
            return Ok(body);
        }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        body.extend_from_slice(&chunk);
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf)?;
    }
}

fn config_for(receiver: &Receiver) -> TelemetryConfig {
    TelemetryConfig::from_lookup("factory-smoke", "9.9.9", |key| match key {
        "OTEL_EXPORTER_OTLP_ENDPOINT" => Some(receiver.endpoint()),
        "FACTORY_ENV" => Some("smoke".to_string()),
        _ => None,
    })
    .expect("a local http endpoint is valid")
}

#[test]
fn a_span_reaches_a_local_otlp_receiver() {
    let receiver = Receiver::start();
    let pipeline = build_pipeline(&config_for(&receiver), io::sink).expect("pipeline builds");
    let secret = format!("ghp_{}", "a".repeat(36));

    pipeline.in_scope(|| {
        let job = spans::job_span(&Job {
            correlation_id: CORRELATION,
            job_id: "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78",
            tenant_id: "tenant-1",
        });
        spans::record_outcome(&job, "passed");
        // A careless call site puts a token into an attribute and a prompt into a field.
        spans::record_error_class(&job, &format!("clone failed using {secret}"));
        let _entered = job.enter();
        tracing::info!(prompt = "a very private prompt", "inside the job");
    });
    pipeline.flush().expect("flush reaches the receiver");

    let request = receiver
        .wait_for("/v1/traces", Duration::from_secs(10))
        .expect("no span reached the receiver within ten seconds");
    assert_eq!(request.method, "POST");
    assert_eq!(request.content_type, "application/x-protobuf");
    assert!(!request.body.is_empty());
    // Protobuf strings are plain UTF-8 on the wire, so these are the real field contents.
    for expected in [
        "factory.job",
        "factory.correlation_id",
        CORRELATION,
        "factory.tenant_id",
        "service.name",
        "factory-smoke",
        "deployment.environment.name",
        "smoke",
    ] {
        assert!(request.contains(expected), "the request lacks {expected:?}");
    }
    assert!(
        request.contains("[REDACTED:github_token_classic]"),
        "the secret was not replaced by its placeholder"
    );
    assert!(!request.contains(&secret), "the secret left the process");
    assert!(
        !request.contains("a very private prompt"),
        "an unlisted field left the process"
    );
    pipeline.shutdown().expect("clean shutdown");
}

#[test]
fn a_scrubber_supplied_in_the_config_is_the_one_that_runs_on_exported_spans() {
    let receiver = Receiver::start();
    let config = config_for(&receiver).with_scrubber(Arc::new(common::ReplaceScrubber {
        from: "needle",
        to: "haystack",
    }));
    let pipeline = build_pipeline(&config, io::sink).expect("pipeline builds");
    pipeline.in_scope(|| {
        let job = spans::job_span(&Job {
            correlation_id: CORRELATION,
            job_id: "a needle",
            tenant_id: "tenant-1",
        });
        drop(job);
    });
    pipeline.flush().expect("flush reaches the receiver");
    let request = receiver
        .wait_for("/v1/traces", Duration::from_secs(10))
        .expect("no span reached the receiver");
    assert!(
        request.contains("a haystack"),
        "the supplied scrubber did not run"
    );
    assert!(!request.contains("needle"));
    pipeline.shutdown().expect("clean shutdown");
}

#[test]
fn a_metric_reaches_a_local_otlp_receiver_with_only_its_listed_labels() {
    let receiver = Receiver::start();
    let pipeline = build_pipeline(&config_for(&receiver), io::sink).expect("pipeline builds");

    pipeline.in_scope(|| {
        tracing::info!(
            monotonic_counter.factory_retries_total = 1u64,
            stage = "INTAKE",
            job_id = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78",
        );
    });
    pipeline.flush().expect("flush reaches the receiver");

    let request = receiver
        .wait_for("/v1/metrics", Duration::from_secs(10))
        .expect("no metric reached the receiver within ten seconds");
    assert_eq!(request.method, "POST");
    assert_eq!(request.content_type, "application/x-protobuf");
    for expected in [
        "factory_retries_total",
        "{retry}",
        "stage",
        "INTAKE",
        "factory-smoke",
    ] {
        assert!(request.contains(expected), "the request lacks {expected:?}");
    }
    assert!(
        !request.contains("job_id"),
        "an identifier became a metric label"
    );
    assert!(!request.contains("0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78"));
    pipeline.shutdown().expect("clean shutdown");
}

#[test]
fn a_dead_collector_does_not_stop_the_process() {
    // Bind a port, note it and close it again, so nothing is listening there.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0")
            .unwrap_or_else(|error| panic!("BLOCKED: cannot open a local port: {error}"));
        listener.local_addr().unwrap().port()
    };
    let config = TelemetryConfig::from_lookup("factory-smoke", "9.9.9", |key| {
        (key == "OTEL_EXPORTER_OTLP_ENDPOINT").then(|| format!("http://127.0.0.1:{port}"))
    })
    .unwrap();
    let pipeline = build_pipeline(&config, io::sink).expect("building does not need a collector");
    pipeline.in_scope(|| {
        drop(tracing::info_span!("factory.job"));
    });
    let started = Instant::now();
    // The flush reports the failure. It must return and must not hang.
    let _ = pipeline.flush();
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "flush hung on a dead collector"
    );
    let _ = pipeline.shutdown();
}
