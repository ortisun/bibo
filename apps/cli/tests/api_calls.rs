//! The commands that talk to the API, against a small loopback server that answers with what a test
//! tells it to and records what it was sent.
//!
//! What these tests show: the token goes out as a bearer header and nowhere else, a refusal, a
//! blocked service and an unreachable one end differently, a token file that others can read is
//! refused before anything is sent, and nothing secret is printed.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use factory_cli::{Exit, run};

const JOB: &str = "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b";
const RUN: &str = "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6c";

/// A token built from parts, so that no token-shaped literal sits in the source.
fn token() -> String {
    ["sfat_", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"].concat()
}

struct Fake {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
}

/// Answers each connection with the next canned `(status, body)`, in order, then stops.
fn fake(answers: Vec<(u16, &'static str)>) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&requests);
    thread::spawn(move || {
        for (status, body) in answers {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 4096];
            let head_end = loop {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break None;
                }
                raw.extend_from_slice(&chunk[..n]);
                if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break Some(at + 4);
                }
            };
            let Some(head_end) = head_end else { continue };
            let head = String::from_utf8_lossy(&raw[..head_end]).to_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while raw.len() < head_end + length {
                let n = stream.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
            }
            seen.lock()
                .expect("lock")
                .push(String::from_utf8_lossy(&raw).into_owned());
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    Fake { addr, requests }
}

fn token_file(mode: u32) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "factory-cli-calls-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join("token");
    std::fs::write(&file, format!("{}\n", token())).expect("write");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).expect("mode");
    file
}

fn words(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

struct Ran {
    exit: Exit,
    out: String,
    err: String,
}

fn cli(line: &str) -> Ran {
    cli_with(&words(line))
}

fn cli_with(args: &[String]) -> Ran {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit = run(args, &|_| None, &mut out, &mut err);
    let ran = Ran {
        exit,
        out: String::from_utf8_lossy(&out).into_owned(),
        err: String::from_utf8_lossy(&err).into_owned(),
    };
    // Whatever happened, the token is in neither stream.
    for (name, text) in [("stdout", &ran.out), ("stderr", &ran.err)] {
        assert!(
            !text.contains(&token()[5..]),
            "the token is in {name}: {text}"
        );
    }
    ran
}

#[test]
fn status_sends_the_token_as_a_bearer_header_and_prints_plain_english() {
    let api = fake(vec![(
        200,
        r#"{"job_id":"j-1","status":"ACTIVE","repository_id":"r","requester_id":"p","autonomy_level":"L0","execution_mode":"test","created_at":"2026-10-28T10:00:00Z","stages":[{"stage_run_id":"s","kind":"INTAKE","run_number":1,"status":"PASSED"}]}"#,
    )]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "status --api http://{} --token-file {} {JOB}",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.contains("Job j-1 is ACTIVE."), "{}", ran.out);
    assert!(ran.out.contains("INTAKE run 1: PASSED"));
    let sent = api.requests.lock().expect("lock").clone();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].starts_with(&format!("GET /v1/jobs/{JOB} ")),
        "{}",
        sent[0]
    );
    assert!(sent[0].contains(&format!("Bearer {}", token())));
}

#[test]
fn a_refusal_a_blocked_service_and_an_unreachable_one_end_differently() {
    let file = token_file(0o600);
    for (status, body, expected) in [
        (401, r#"{"error":"unauthorized"}"#, Exit::Refused),
        (403, r#"{"error":"forbidden"}"#, Exit::Refused),
        (404, r#"{"error":"not_found"}"#, Exit::Refused),
        (409, r#"{"error":"conflict"}"#, Exit::Refused),
        (429, r#"{"error":"rate_limited"}"#, Exit::Blocked),
        (503, r#"{"error":"unavailable"}"#, Exit::Blocked),
    ] {
        let api = fake(vec![(status, body)]);
        let ran = cli(&format!(
            "timeline --api http://{} --token-file {} {JOB}",
            api.addr,
            file.display()
        ));
        assert_eq!(ran.exit, expected, "{status}: {}", ran.err);
        assert!(ran.err.contains(&status.to_string()), "{}", ran.err);
    }
    // Nothing listens: unreachable, and a different code from the other two.
    let closed = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = closed.local_addr().expect("addr");
    drop(closed);
    let ran = cli(&format!(
        "status --api http://{addr} --token-file {} {JOB}",
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Unreachable);
    let codes = [Exit::Refused, Exit::Blocked, Exit::Unreachable].map(Exit::code);
    assert_eq!(codes, [2, 3, 4]);
}

#[test]
fn a_token_file_that_others_can_read_is_refused_before_anything_is_sent() {
    let api = fake(vec![(200, "{}")]);
    for mode in [0o644, 0o640, 0o604] {
        let file = token_file(mode);
        let ran = cli(&format!(
            "status --api http://{} --token-file {} {JOB}",
            api.addr,
            file.display()
        ));
        assert_eq!(ran.exit, Exit::Failed, "mode {mode:o}");
        assert!(ran.err.contains("token file"), "{}", ran.err);
    }
    assert!(api.requests.lock().expect("lock").is_empty());
    // The token is not an argument and not an environment variable.
    let file = token_file(0o600);
    let ran = cli(&format!(
        "status --api http://{} --token {} {JOB}",
        api.addr,
        token()
    ));
    assert_eq!(ran.exit, Exit::Failed);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let exit = run(
        &words(&format!("status --api http://{} {JOB}", api.addr)),
        &|name| (name == "FACTORY_TOKEN").then(token),
        &mut out,
        &mut err,
    );
    assert_eq!(
        exit,
        Exit::Failed,
        "an environment variable is not a token file"
    );
    let _ = file;
    assert!(api.requests.lock().expect("lock").is_empty());
}

#[test]
fn a_token_is_never_sent_in_clear_text_over_a_network() {
    let file = token_file(0o600);
    for address in [
        "http://10.0.0.5:8080",
        "http://factory.example.com",
        "https://user:pw@factory.example.com",
        "ftp://127.0.0.1",
    ] {
        let ran = cli(&format!(
            "status --api {address} --token-file {} {JOB}",
            file.display()
        ));
        assert_eq!(ran.exit, Exit::Failed, "{address}");
        assert!(!ran.err.contains("pw@"), "{}", ran.err);
    }
}

#[test]
fn submit_sends_the_text_the_repository_and_a_key_it_prints() {
    let api = fake(vec![(
        201,
        r#"{"job_id":"j-2","status":"RECEIVED","created":true}"#,
    )]);
    let file = token_file(0o600);
    let text = file.with_file_name("request.txt");
    std::fs::write(&text, "Add a word count.\nSecond line.").expect("write");
    let ran = cli(&format!(
        "submit --api http://{} --token-file {} --repository {JOB} --text-file {} --source-ref org/repo-0#12 --key retry-1",
        api.addr,
        file.display(),
        text.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(
        ran.out.contains("Created job j-2 (RECEIVED)."),
        "{}",
        ran.out
    );
    assert!(ran.out.contains("--key retry-1"));
    let sent = api.requests.lock().expect("lock")[0].clone();
    assert!(sent.starts_with("POST /v1/jobs "));
    assert!(sent.to_lowercase().contains("idempotency-key: retry-1"));
    assert!(
        sent.contains(r#""text":"Add a word count.\nSecond line.""#),
        "{sent}"
    );
    assert!(sent.contains(&format!(r#""repository_id":"{JOB}""#)));
    assert!(sent.contains(r#""source_ref":"org/repo-0#12""#), "{sent}");
    // Without --key a fresh one is made and shown, so the operator can retry with it.
    let again = fake(vec![(
        200,
        r#"{"job_id":"j-2","status":"RECEIVED","created":false}"#,
    )]);
    let ran = cli(&format!(
        "submit --api http://{} --token-file {} --repository {JOB} --text-file {} --source-ref org/repo-0#12",
        again.addr,
        file.display(),
        text.display()
    ));
    assert!(
        ran.out.contains("Found the existing job j-2"),
        "{}",
        ran.out
    );
    assert!(ran.out.contains("Idempotency key: "));
}

#[test]
fn a_decision_is_read_by_the_shared_grammar_and_merge_is_not_a_verb() {
    let api = fake(vec![(
        202,
        r#"{"decision_id":"d-1","status":"recorded","applied":false}"#,
    )]);
    let file = token_file(0o600);
    let head = "a".repeat(40);
    let evidence = format!("sha256:{}", "b".repeat(64));
    let ran = cli_with(&words(&format!(
        "approve --api http://{} --token-file {} --key k-1 {JOB} {RUN} head={head} evidence={evidence} looks right",
        api.addr,
        file.display()
    )));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(
        ran.out
            .contains("Decision d-1 is recorded; the worker has not applied it yet, and the timeline shows the outcome."),
        "{}",
        ran.out
    );
    let sent = api.requests.lock().expect("lock")[0].clone();
    assert!(sent.starts_with(&format!("POST /v1/jobs/{JOB}/decisions ")));
    for part in [
        r#""verb":"approve""#,
        &format!(r#""stage_run_id":"{RUN}""#),
        &format!(r#""head":"{head}""#),
        &format!(r#""evidence":"{evidence}""#),
        r#""reason":"looks right""#,
    ] {
        assert!(sent.contains(part), "{part} in {sent}");
    }
    // Words the grammar does not take stop here, before any request.
    for line in [
        format!("merge {JOB}"),
        format!("approve {JOB} {RUN} head=zz evidence={evidence}"),
        format!("approve {JOB}"),
        format!("rework {JOB} {RUN} reason without a target"),
        format!("cancel {JOB}"),
        "cancel not-a-uuid because".to_owned(),
    ] {
        let ran = cli(&format!(
            "{line} --api http://{} --token-file {}",
            api.addr,
            file.display()
        ));
        assert_eq!(ran.exit, Exit::Failed, "{line}");
    }
    assert_eq!(api.requests.lock().expect("lock").len(), 1);
}

#[test]
fn health_says_whether_the_api_is_running_and_ready() {
    let ready = fake(vec![
        (200, r#"{"status":"live"}"#),
        (
            200,
            r#"{"ready":true,"checks":[{"name":"policy","status":"pass"}]}"#,
        ),
    ]);
    let ran = cli(&format!("health --api http://{}", ready.addr));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(
        ran.out.contains("The API is running.") && ran.out.contains("The API is ready."),
        "{}",
        ran.out
    );
    let behind = fake(vec![
        (200, r#"{"status":"live"}"#),
        (
            503,
            r#"{"ready":false,"checks":[{"name":"database schema","status":"fail"}]}"#,
        ),
    ]);
    let ran = cli(&format!("health --api http://{}", behind.addr));
    assert_eq!(ran.exit, Exit::Blocked);
    assert!(
        ran.out.contains("not ready") && ran.out.contains("database schema: fail"),
        "{}",
        ran.out
    );
}

#[test]
fn the_two_dependency_verbs_are_read_by_the_dependency_grammar_and_sent_as_words() {
    let api = fake(vec![
        (
            202,
            r#"{"decision_id":"d-2","status":"recorded","applied":false}"#,
        ),
        (
            202,
            r#"{"decision_id":"d-3","status":"recorded","applied":false}"#,
        ),
    ]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "approve-dependency --api http://{} --token-file {} --key k-2 {JOB} tally-counter 0.3.1 Read the maintainers and the licence.",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.contains("Decision d-2 is recorded"), "{}", ran.out);
    // A checksum prefix and a stage run may be named.
    let checksum = "ab".repeat(8);
    let ran = cli(&format!(
        "approve-build-code --api http://{} --token-file {} --key k-3 --stage-run {RUN} {JOB} tally-counter 0.3.1 sha256:{checksum} Read the build script, it sets cfg flags.",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let sent = api.requests.lock().expect("lock").clone();
    assert_eq!(sent.len(), 2);
    assert!(sent[0].starts_with(&format!("POST /v1/jobs/{JOB}/decisions ")));
    for part in [
        r#""verb":"approve-dependency""#,
        r#""package":"tally-counter""#,
        r#""version":"0.3.1""#,
        r#""reason":"Read the maintainers and the licence.""#,
    ] {
        assert!(sent[0].contains(part), "{part} in {}", sent[0]);
    }
    assert!(!sent[0].contains("checksum"), "{}", sent[0]);
    for part in [
        r#""verb":"approve-build-code""#,
        &format!(r#""checksum":"{checksum}""#),
        &format!(r#""stage_run_id":"{RUN}""#),
        r#""reason":"Read the build script, it sets cfg flags.""#,
    ] {
        assert!(sent[1].contains(part), "{part} in {}", sent[1]);
    }
    // What the grammar refuses stops here, before any request.
    for line in [
        format!("approve-dependency {JOB}"),
        format!("approve-dependency {JOB} tally-counter"),
        format!("approve-dependency {JOB} ../etc 1.0.0 A reason that is long enough"),
        format!("approve-dependency {JOB} tally-counter latest A reason that is long enough"),
        format!(
            "approve-dependency {JOB} tally-counter 0.3.1 DEADBEEFDEADBEEF A reason that is long enough"
        ),
        format!("approve-dependency {JOB} tally-counter 0.3.1 short"),
        format!("approve-dependency {JOB} tally-counter 0.3.1"),
        "approve-dependency not-a-uuid tally-counter 0.3.1 A reason that is long enough".to_owned(),
        format!(
            "approve-dependency --stage-run nope {JOB} tally-counter 0.3.1 A reason that is long enough"
        ),
    ] {
        let ran = cli(&format!(
            "{line} --api http://{} --token-file {}",
            api.addr,
            file.display()
        ));
        assert_eq!(ran.exit, Exit::Failed, "{line}: {}", ran.err);
    }
    assert_eq!(api.requests.lock().expect("lock").len(), 2);
}

#[test]
fn unblock_names_the_stage_run_and_says_why_and_sends_nothing_else() {
    let api = fake(vec![(
        202,
        r#"{"decision_id":"d-4","status":"recorded","applied":false}"#,
    )]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "unblock --api http://{} --token-file {} --key k-4 {JOB} {RUN} The Docker daemon is back; run the stage again.",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.contains("Decision d-4 is recorded"), "{}", ran.out);
    let sent = api.requests.lock().expect("lock")[0].clone();
    assert!(sent.starts_with(&format!("POST /v1/jobs/{JOB}/decisions ")));
    for part in [
        r#""verb":"unblock""#,
        &format!(r#""stage_run_id":"{RUN}""#),
        r#""reason":"The Docker daemon is back; run the stage again.""#,
    ] {
        assert!(sent.contains(part), "{part} in {sent}");
    }
    // No other word is sent: the engine reads the guard for itself.
    for part in ["head", "evidence", "target", "package", "checksum"] {
        assert!(!sent.contains(part), "{part} in {sent}");
    }
    // What the command refuses stops here, before any request.
    for line in [
        format!("unblock {JOB}"),
        format!("unblock {JOB} {RUN}"),
        format!("unblock {JOB} {RUN} short"),
        format!("unblock {JOB} not-a-uuid A reason that is long enough"),
        format!("unblock not-a-uuid {RUN} A reason that is long enough"),
        format!("unblock --stage-run {RUN} {JOB} {RUN} A reason that is long enough"),
    ] {
        let ran = cli(&format!(
            "{line} --api http://{} --token-file {}",
            api.addr,
            file.display()
        ));
        assert_eq!(ran.exit, Exit::Failed, "{line}: {}", ran.err);
    }
    assert_eq!(api.requests.lock().expect("lock").len(), 1);
}
