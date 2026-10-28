//! The command line, driven as a process against a hostile server on loopback.
//!
//! `factory-cli` is built by `cargo build -p factory-cli` when a test starts; nothing here edits
//! the CLI package.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::support::repository_root;
use crate::util::{new_uuid, runtime_token};

fn cli_binary() -> PathBuf {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let status = Command::new(cargo)
        .args(["build", "-p", "factory-cli", "--locked", "--quiet"])
        .env("CARGO_INCREMENTAL", "0")
        .current_dir(repository_root())
        .status()
        .expect("cargo runs");
    assert!(status.success(), "BLOCKED: factory-cli did not build");
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map_or_else(|| repository_root().join("target"), PathBuf::from);
    target.join("debug/factory-cli")
}

fn token_file(token: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("review-cli-{}", new_uuid().simple()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join("token");
    std::fs::write(&file, token).expect("token file");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("mode");
    file
}

/// Serves one connection with `response` and returns the port and the thread that yields the
/// request it read.
fn serve_once(response: String) -> (u16, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("address").port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 4096];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => request.extend_from_slice(&chunk[..n]),
            }
        }
        let _ = stream.write_all(response.as_bytes());
        String::from_utf8_lossy(&request).into_owned()
    });
    (port, handle)
}

fn json_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// API-10. The CLI prints strings the server sent without removing control characters. Every
/// value the real API sends is typed on its side, so nothing a tenant writes reaches the terminal
/// today; a server that is wrong, replaced or compromised can clear the screen, retitle the
/// window or rewrite earlier lines.
#[test]
#[ignore = "confirmed defect API-10: the CLI writes control characters from the server to the terminal"]
fn api_10_the_cli_does_not_print_terminal_escapes_sent_by_the_server() {
    let binary = cli_binary();
    let token = runtime_token();
    let file = token_file(&token);
    let body = r#"{"job_id":"j","status":"\u001b[2J\u001b]0;owned\u0007\u001b[31mRUNNING","repository_id":"r","requester_id":"p","autonomy_level":"L1","execution_mode":"test","created_at":"t","stages":[{"kind":"\u001b[1A\u001b[2Kcleared","run_number":1,"status":"PASSED","stage_run_id":"s"}]}"#;
    let (port, server) = serve_once(json_response("200 OK", body));
    let output = Command::new(binary)
        .args([
            "status",
            "--api",
            &format!("http://127.0.0.1:{port}"),
            "--token-file",
        ])
        .arg(&file)
        .arg(new_uuid().to_string())
        .output()
        .expect("the CLI runs");
    let _ = server.join();
    let escapes = output.stdout.iter().filter(|byte| **byte == 0x1b).count()
        + output.stderr.iter().filter(|byte| **byte == 0x1b).count();
    assert_eq!(
        escapes,
        0,
        "the CLI printed {escapes} escape bytes: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// The token is not sent to the host a redirect names, and a token file that is a symbolic link is
/// refused before anything is sent.
#[test]
#[ignore = "held probe: passes today; the CLI does not follow redirects and refuses a linked token file"]
fn held_cli_does_not_follow_a_redirect_and_refuses_a_linked_token_file() {
    let binary = cli_binary();
    let token = runtime_token();
    let file = token_file(&token);

    // A redirect to a second loopback server: it must receive no connection.
    let thief = TcpListener::bind("127.0.0.1:0").expect("bind");
    thief.set_nonblocking(true).expect("nonblocking");
    let thief_port = thief.local_addr().expect("address").port();
    let (port, server) = serve_once(format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{thief_port}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    ));
    let output = Command::new(&binary)
        .args([
            "status",
            "--api",
            &format!("http://127.0.0.1:{port}"),
            "--token-file",
        ])
        .arg(&file)
        .arg(new_uuid().to_string())
        .output()
        .expect("the CLI runs");
    let request = server.join().expect("server");
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: bearer"),
        "the first request carried the token"
    );
    let deadline = Instant::now() + Duration::from_millis(700);
    let mut followed = false;
    while Instant::now() < deadline {
        if thief.accept().is_ok() {
            followed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        !followed,
        "the redirect was followed and the second host was contacted"
    );
    assert!(!output.status.success());
    let shown = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!shown.contains(&token), "the token was printed");

    // A symbolic link to a good token file.
    let link = file.with_file_name("link");
    std::os::unix::fs::symlink(&file, &link).expect("symlink");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("address").port();
    let output = Command::new(&binary)
        .args([
            "status",
            "--api",
            &format!("http://127.0.0.1:{port}"),
            "--token-file",
        ])
        .arg(&link)
        .arg(new_uuid().to_string())
        .output()
        .expect("the CLI runs");
    assert!(!output.status.success());
    assert!(
        listener.accept().is_err(),
        "a request was sent with a linked token file"
    );
}
