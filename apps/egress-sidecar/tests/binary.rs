//! The built `factory-egress-sidecar` program, started the way the supervisor starts it: with
//! arguments, reading its ready line and its decision lines from standard output.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::Duration;

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

struct Sidecar {
    child: Child,
    lines: Receiver<String>,
    listen: SocketAddr,
}

impl Sidecar {
    fn start(args: &[String]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_factory-egress-sidecar"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the sidecar starts");
        let stdout = child.stdout.take().expect("stdout");
        let (send, lines) = channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        let listen = args
            .iter()
            .position(|a| a == "--listen")
            .and_then(|i| args.get(i + 1))
            .and_then(|a| a.parse().ok())
            .expect("a listen address in the arguments");
        Self {
            child,
            lines,
            listen,
        }
    }

    fn next_line(&self) -> serde_json::Value {
        let line = self
            .lines
            .recv_timeout(Duration::from_secs(10))
            .expect("a line on standard output");
        serde_json::from_str(&line).expect("a JSON line")
    }

    fn connect(&self) -> TcpStream {
        let stream =
            TcpStream::connect_timeout(&self.listen, Duration::from_secs(5)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        stream
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn args(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn a_command_line_that_is_not_accepted_ends_the_program_with_code_two_before_it_listens() {
    let port = free_port();
    let bad = [
        String::new(),
        format!("--mode broker --listen 127.0.0.1:{port}"),
        format!("--mode connect --listen 127.0.0.1:{port}"),
        format!("--mode other.test --listen 127.0.0.1:{port}"),
        format!("--mode broker --listen 127.0.0.1:{port} --upstream 127.0.0.1:9 --surprise-flag"),
        format!("--mode connect --listen 127.0.0.1:{port} --allow evil.test"),
    ];
    for text in bad {
        let output = Command::new(env!("CARGO_BIN_EXE_factory-egress-sidecar"))
            .args(args(&text))
            .stdin(Stdio::null())
            .output()
            .expect("the program runs");
        assert_eq!(output.status.code(), Some(2), "arguments: {text:?}");
        assert!(
            output.stdout.is_empty(),
            "nothing is written to standard output: {text:?}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("evil.test") && !stderr.contains("other.test"),
            "a value from the command line must not be echoed: {stderr}"
        );
        // And it is not listening.
        assert!(
            TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().expect("addr"),
                Duration::from_millis(200)
            )
            .is_err()
        );
    }
}

#[test]
fn a_listener_that_cannot_bind_ends_the_program_with_code_one() {
    let taken = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = taken.local_addr().expect("addr").port();
    let output = Command::new(env!("CARGO_BIN_EXE_factory-egress-sidecar"))
        .args(args(&format!(
            "--mode broker --listen 127.0.0.1:{port} --upstream 127.0.0.1:9"
        )))
        .stdin(Stdio::null())
        .output()
        .expect("the program runs");
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty(), "no ready line was written");
}

#[test]
fn broker_mode_says_ready_and_relays_to_the_upstream_address_and_nowhere_else() {
    let upstream = TcpListener::bind("127.0.0.1:0").expect("bind");
    let up_addr = upstream.local_addr().expect("addr");
    let accepted = thread::spawn(move || {
        let mut count = 0;
        upstream.set_nonblocking(false).expect("blocking");
        while let Ok((mut stream, _)) = upstream.accept() {
            count += 1;
            let mut buffer = [0_u8; 64];
            let n = stream.read(&mut buffer).unwrap_or(0);
            let _ = stream.write_all(&buffer[..n]);
            if count == 1 {
                break;
            }
        }
        count
    });
    let port = free_port();
    let sidecar = Sidecar::start(&args(&format!(
        "--mode broker --listen 127.0.0.1:{port} --upstream {up_addr} --job job-1"
    )));
    let ready = sidecar.next_line();
    assert_eq!(ready["event"], "ready");
    assert_eq!(ready["mode"], "broker");
    assert_eq!(ready["job"], "job-1");

    let mut stream = sidecar.connect();
    stream.write_all(b"ping").expect("write");
    let mut echoed = [0_u8; 4];
    stream
        .read_exact(&mut echoed)
        .expect("the echo comes back through the relay");
    assert_eq!(&echoed, b"ping");
    drop(stream);
    assert_eq!(accepted.join().expect("upstream thread"), 1);
    let decision = sidecar.next_line();
    assert_eq!(decision["decision"], "allow");
    assert_eq!(decision["mode"], "broker");
}

#[test]
fn connect_mode_with_the_system_resolver_refuses_a_name_that_resolves_to_loopback() {
    // The target accepts connections on the loopback address. The relay must not make one.
    let target = TcpListener::bind("127.0.0.1:0").expect("bind");
    target.set_nonblocking(true).expect("nonblocking");
    let target_port = target.local_addr().expect("addr").port();
    let port = free_port();
    let sidecar = Sidecar::start(&args(&format!(
        "--mode connect --listen 127.0.0.1:{port} --allow localhost:{target_port}"
    )));
    assert_eq!(sidecar.next_line()["event"], "ready");

    let ask = |authority: &str| -> String {
        let mut stream = sidecar.connect();
        stream
            .write_all(format!("CONNECT {authority} HTTP/1.1\r\n\r\n").as_bytes())
            .expect("write");
        let mut answer = String::new();
        let _ = stream.read_to_string(&mut answer);
        answer
    };
    assert!(ask(&format!("localhost:{target_port}")).starts_with("HTTP/1.1 403"));
    assert!(ask(&format!("127.0.0.1:{target_port}")).starts_with("HTTP/1.1 403"));
    assert!(ask(&format!("evil.test:{target_port}")).starts_with("HTTP/1.1 403"));
    let reasons: Vec<String> = (0..3)
        .map(|_| {
            sidecar.next_line()["reason"]
                .as_str()
                .unwrap_or("")
                .to_owned()
        })
        .collect();
    assert_eq!(
        reasons,
        vec!["resolved_to_denied_range", "ip_literal", "not_allowlisted"]
    );
    assert!(
        target.accept().is_err(),
        "the relay connected to the loopback target"
    );
}
