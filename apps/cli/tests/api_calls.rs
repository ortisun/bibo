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
            // A body that is not a JSON object is a document, and the API sends a document as text
            // or as bytes. A leading `!` marks one that is bytes.
            let (content_type, body) = if body.starts_with('{') {
                ("application/json", body)
            } else if let Some(rest) = body.strip_prefix('!') {
                ("application/octet-stream", rest)
            } else {
                ("text/plain; charset=utf-8", body)
            };
            let reply = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

#[test]
fn approve_project_build_code_names_the_file_and_the_start_of_its_hash() {
    let api = fake(vec![
        (
            202,
            r#"{"decision_id":"d-5","status":"recorded","applied":false}"#,
        ),
        (
            202,
            r#"{"decision_id":"d-6","status":"recorded","applied":false}"#,
        ),
    ]);
    let file = token_file(0o600);
    let hash = "ab".repeat(8);
    let ran = cli(&format!(
        "approve-project-build-code --api http://{} --token-file {} --key k-5 {JOB} build.rs {hash} Read the script, it only prints cargo directives.",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.contains("Decision d-5 is recorded"), "{}", ran.out);
    // A prefix with sha256: and a stage run may be given.
    let ran = cli(&format!(
        "approve-project-build-code --api http://{} --token-file {} --key k-6 --stage-run {RUN} {JOB} crates/a/build.rs sha256:{hash} Read the script, it only prints cargo directives.",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let sent = api.requests.lock().expect("lock").clone();
    assert_eq!(sent.len(), 2);
    assert!(sent[0].starts_with(&format!("POST /v1/jobs/{JOB}/decisions ")));
    for part in [
        r#""verb":"approve-project-build-code""#,
        r#""path":"build.rs""#,
        &format!(r#""digest":"{hash}""#),
        r#""reason":"Read the script, it only prints cargo directives.""#,
    ] {
        assert!(sent[0].contains(part), "{part} in {}", sent[0]);
    }
    assert!(!sent[0].contains("stage_run_id"), "{}", sent[0]);
    for part in [
        r#""path":"crates/a/build.rs""#,
        &format!(r#""digest":"{hash}""#),
        &format!(r#""stage_run_id":"{RUN}""#),
    ] {
        assert!(sent[1].contains(part), "{part} in {}", sent[1]);
    }
    // What the grammar refuses stops here, before any request.
    for line in [
        format!("approve-project-build-code {JOB}"),
        format!("approve-project-build-code {JOB} build.rs"),
        format!("approve-project-build-code {JOB} build.rs {hash}"),
        format!("approve-project-build-code {JOB} build.rs {hash} short"),
        format!("approve-project-build-code {JOB} ../build.rs {hash} A reason that is long enough"),
        format!("approve-project-build-code {JOB} /etc/passwd {hash} A reason that is long enough"),
        format!("approve-project-build-code {JOB} build.rs abab A reason that is long enough"),
        format!(
            "approve-project-build-code {JOB} build.rs ABABABABABABABAB A reason that is long enough"
        ),
        format!(
            "approve-project-build-code not-a-uuid build.rs {hash} A reason that is long enough"
        ),
        format!(
            "approve-project-build-code --stage-run nope {JOB} build.rs {hash} A reason that is long enough"
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

const GATE_REPORTS: &str = r#"{"job_id":"j","truncated":false,"reports":[
  {"stage_run_id":"r1","stage":"VALIDATION","gate":"build","title":"Build","outcome":"BLOCKED","code":"policy_unresolvable","reason":"waits","report_sha256":"sha256:aaaa","recorded_at":"2026-10-29T10:00:00Z","readable":true},
  {"stage_run_id":"r1","stage":"VALIDATION","gate":"format","title":"Format","outcome":"PASSED","code":null,"reason":"ok","report_sha256":"sha256:bbbb","recorded_at":"2026-10-29T10:00:01Z","readable":true},
  {"stage_run_id":"r2","stage":"REVIEW","gate":null,"title":null,"outcome":null,"code":null,"reason":null,"report_sha256":"sha256:cccc","recorded_at":"2026-10-29T10:00:02Z","readable":false}
]}"#;

#[test]
fn status_with_gates_prints_the_job_and_then_the_gate_reports() {
    let api = fake(vec![
        (
            200,
            r#"{"job_id":"j","status":"BLOCKED","repository_id":"r","requester_id":"p","autonomy_level":"L1","execution_mode":"test","created_at":"2026-10-29T09:00:00Z","stages":[]}"#,
        ),
        (200, GATE_REPORTS),
    ]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "status --gates --api http://{} --token-file {} {JOB}",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.contains("Job j is BLOCKED."), "{}", ran.out);
    for line in [
        "Gate reports (3):",
        "VALIDATION build: BLOCKED (policy_unresolvable), sha256:aaaa",
        "VALIDATION format: PASSED, sha256:bbbb",
        "REVIEW: a report that could not be read, sha256:cccc",
    ] {
        assert!(ran.out.contains(line), "{line} in {}", ran.out);
    }
    let sent = api.requests.lock().expect("lock").clone();
    assert_eq!(sent.len(), 2);
    assert!(sent[0].starts_with(&format!("GET /v1/jobs/{JOB} ")));
    assert!(sent[1].starts_with(&format!("GET /v1/jobs/{JOB}/gate-reports ")));
    // Without the flag, the second request is not made.
    let api = fake(vec![(
        200,
        r#"{"job_id":"j","status":"BLOCKED","repository_id":"r","requester_id":"p","autonomy_level":"L1","execution_mode":"test","created_at":"x","stages":[]}"#,
    )]);
    let ran = cli(&format!(
        "status --api http://{} --token-file {} {JOB}",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok);
    assert!(!ran.out.contains("Gate reports"));
    assert_eq!(api.requests.lock().expect("lock").len(), 1);
}

#[test]
fn answer_names_the_stage_run_and_sends_the_text_one_question_to_a_line() {
    let api = fake(vec![(
        202,
        r#"{"decision_id":"d-9","status":"recorded","applied":false}"#,
    )]);
    let file = token_file(0o600);
    let ran = cli_with(&words(&format!(
        "answer --api http://{} --token-file {} --key k-9 {JOB} {RUN} -- Q-001: yes, add a line for --json Q-002: no",
        api.addr,
        file.display()
    )));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.contains("Decision d-9 is recorded"), "{}", ran.out);
    let sent = api.requests.lock().expect("lock")[0].clone();
    assert!(sent.starts_with(&format!("POST /v1/jobs/{JOB}/decisions ")));
    assert!(
        sent.to_lowercase().contains("idempotency-key: k-9"),
        "{sent}"
    );
    for part in [
        r#""verb":"answer""#,
        &format!(r#""stage_run_id":"{RUN}""#),
        r#""answer":"Q-001: yes, add a line for --json\nQ-002: no""#,
    ] {
        assert!(sent.contains(part), "{part} in {sent}");
    }
    // An answer carries no reason, head, evidence or target: the words after the ids are the text.
    for absent in [r#""reason""#, r#""head""#, r#""target""#] {
        assert!(!sent.contains(absent), "{absent} in {sent}");
    }

    // One argument may hold the lines itself.
    let api = fake(vec![(
        202,
        r#"{"decision_id":"d-10","status":"recorded","applied":false}"#,
    )]);
    let mut args = words(&format!(
        "answer --api http://{} --token-file {} {JOB} {RUN}",
        api.addr,
        file.display()
    ));
    args.push("Q-001: yes\nQ-002: no".to_owned());
    let ran = cli_with(&args);
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    let sent = api.requests.lock().expect("lock")[0].clone();
    assert!(
        sent.contains(r#""answer":"Q-001: yes\nQ-002: no""#),
        "{sent}"
    );

    // What is not an answer stops here, before any request.
    let long = "x".repeat(901);
    for line in [
        format!("answer {JOB} {RUN}"),
        format!("answer {JOB} Q-001: yes"),
        format!("answer not-a-uuid {RUN} Q-001: yes"),
        format!("answer {JOB} {long}"),
        format!("answer {JOB} {RUN} {long}"),
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
fn a_refused_answer_exits_2_and_says_so() {
    let api = fake(vec![(403, r#"{"error":"forbidden"}"#)]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "answer --api http://{} --token-file {} {JOB} {RUN} Q-001: yes",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Refused, "{}", ran.err);
}

#[test]
fn show_draft_lists_the_questions_and_the_command_that_answers_them() {
    let escape = r"\u001b[2J";
    let body = format!(
        r#"{{"job_id":"{JOB}","stage_run_id":"{RUN}","status":"WAITING_FOR_HUMAN","run_number":1,
        "draft":{{"number":1,"commit":"{}","feature_directory":"specs/x","artifact_sha256":"sha256:dddd","saved_at":"2026-10-29T10:00:00Z"}},
        "ledger_head":{{"sequence":7,"hash":"sha256:eeee"}},
        "approval":{{"window_hours":72,"approvable":true,"head":"{}","evidence":"sha256:eeee"}},
        "questions":[{{"id":"Q-001","question":"Should the --help text add a line for --json?{escape}"}},{{"id":"Q-002","question":"Exit code on error?"}}],
        "answerable":true}}"#,
        "a".repeat(40),
        "a".repeat(40)
    );
    let body: &'static str = Box::leak(body.into_boxed_str());
    let api = fake(vec![(200, body)]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "show-draft --api http://{} --token-file {} {JOB}",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    for part in [
        "The stage asked 2 question(s):",
        "Q-001: Should the --help text add a line for --json?",
        "Q-002: Exit code on error?",
        &format!(
            "factory-cli answer --api URL --token-file FILE {JOB} {RUN} -- Q-001: <answer> Q-002: <answer>"
        ),
    ] {
        assert!(ran.out.contains(part), "{part} in {}", ran.out);
    }
    assert!(
        !ran.out.contains('\u{1b}'),
        "an escape reached the terminal"
    );
}

#[test]
fn show_draft_prints_the_values_an_approval_needs_and_nothing_a_server_can_inject() {
    let escape = r"\u001b[2J";
    let body = format!(
        r#"{{"job_id":"j","stage_run_id":"{RUN}","status":"WAITING_FOR_HUMAN","run_number":1,
        "draft":{{"number":2,"commit":"{}","feature_directory":"specs/x{escape}","artifact_sha256":"sha256:dddd","saved_at":"2026-10-29T10:00:00Z"}},
        "ledger_head":{{"sequence":7,"hash":"sha256:eeee"}},
        "approval":{{"window_hours":72,"approvable":true,"head":"{}","evidence":"sha256:eeee"}}}}"#,
        "a".repeat(40),
        "a".repeat(40)
    );
    let body: &'static str = Box::leak(body.into_boxed_str());
    let api = fake(vec![(200, body)]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "show-draft --api http://{} --token-file {} --stage-run {RUN} {JOB}",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    for part in [
        &format!("Commit that holds it: {}", "a".repeat(40)),
        "Ledger head: entry 7, sha256:eeee",
        "Draft document: sha256:dddd",
        &format!("head={} evidence=sha256:eeee", "a".repeat(40)),
        "72 hours",
    ] {
        assert!(ran.out.contains(part), "{part} in {}", ran.out);
    }
    assert!(
        !ran.out.contains('\u{1b}'),
        "an escape reached the terminal"
    );
    let sent = api.requests.lock().expect("lock")[0].clone();
    assert!(sent.starts_with(&format!(
        "GET /v1/jobs/{JOB}/specification-draft?stage_run_id={RUN} "
    )));
    // What is not a job id or a stage run id is not sent.
    for line in [
        "show-draft not-a-uuid".to_owned(),
        format!("show-draft --stage-run nope {JOB}"),
        "show-draft".to_owned(),
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
fn artifact_prints_text_through_the_sanitizer_and_does_not_print_data() {
    let hash = "ab".repeat(32);
    let api = fake(vec![
        (200, "line one\n\u{1b}[2Jline two\r\n"),
        (200, "!\u{0}\u{1}binary"),
        (404, r#"{"error":"not_found"}"#),
    ]);
    let file = token_file(0o600);
    let line = |what: &str| {
        format!(
            "artifact --api http://{} --token-file {} {JOB} {what}",
            api.addr,
            file.display()
        )
    };
    let ran = cli(&line(&hash));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.contains("line one\n"), "{:?}", ran.out);
    assert!(
        !ran.out.contains('\u{1b}') && !ran.out.contains('\r'),
        "a control character reached the terminal: {:?}",
        ran.out
    );
    assert!(ran.out.contains("line two"));
    // Data that is not text is not printed.
    let ran = cli(&line(&format!("sha256:{hash}")));
    assert_eq!(ran.exit, Exit::Failed);
    assert!(ran.out.is_empty(), "{:?}", ran.out);
    assert!(ran.err.contains("not text"), "{}", ran.err);
    // A refusal ends as any other.
    let ran = cli(&line(&hash));
    assert_eq!(ran.exit, Exit::Refused, "{}", ran.err);
    let sent = api.requests.lock().expect("lock").clone();
    assert!(sent[0].starts_with(&format!("GET /v1/jobs/{JOB}/artifacts/{hash} ")));
    // A hash that is not 64 lower case digits is not sent.
    for bad in ["abc", &hash.to_ascii_uppercase(), "../etc/passwd"] {
        let ran = cli(&line(bad));
        assert_eq!(ran.exit, Exit::Failed, "{bad}");
    }
    assert_eq!(api.requests.lock().expect("lock").len(), 3);
}

#[test]
fn ack_translation_warning_names_the_approval_run_and_the_number() {
    let api = fake(vec![(
        202,
        r#"{"decision_id":"d-7","status":"recorded","applied":false}"#,
    )]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "ack-translation-warning --api http://{} --token-file {} --key k-7 {JOB} {RUN} 2 The translation says what the original says.",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.contains("Decision d-7 is recorded"), "{}", ran.out);
    let sent = api.requests.lock().expect("lock")[0].clone();
    assert!(sent.starts_with(&format!("POST /v1/jobs/{JOB}/decisions ")));
    for part in [
        r#""verb":"ack-translation-warning""#,
        &format!(r#""stage_run_id":"{RUN}""#),
        r#""warning":2"#,
        r#""reason":"The translation says what the original says.""#,
    ] {
        assert!(sent.contains(part), "{part} in {sent}");
    }
    // What the command refuses stops here, before any request.
    for line in [
        format!("ack-translation-warning {JOB} {RUN}"),
        format!("ack-translation-warning {JOB} {RUN} 0 A reason that is long enough"),
        format!("ack-translation-warning {JOB} {RUN} -1 A reason that is long enough"),
        format!("ack-translation-warning {JOB} {RUN} two A reason that is long enough"),
        format!("ack-translation-warning {JOB} {RUN} 10001 A reason that is long enough"),
        format!("ack-translation-warning {JOB} {RUN} 1 short"),
        format!("ack-translation-warning {JOB} not-a-uuid 1 A reason that is long enough"),
        format!("ack-translation-warning not-a-uuid {RUN} 1 A reason that is long enough"),
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

const REPOSITORY: &str = "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6d";
const MAP_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

/// What the API answers to a request to register, confirm or enable: recorded, not applied yet (REG-2).
const REQUESTED: &str = r#"{"request_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a70","kind":"register","repository_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6d","state":"requested","changed":true}"#;
/// The state of that request once the worker applied it.
const APPLIED: &str = r#"{"request_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a70","kind":"register","repository_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6d","state":"applied","code":null}"#;

/// The repository alone, as `GET /v1/repositories/{id}` answers: the member `repository` of a body.
fn the_repository(body: &str) -> &'static str {
    let value: serde_json::Value = serde_json::from_str(body).expect("json");
    let inner = value.get("repository").map_or(value.clone(), Clone::clone);
    Box::leak(inner.to_string().into_boxed_str())
}

const REPOSITORY_BODY: &str = r#"{"repository":{"repository_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6d","full_name":"org/widgets","default_branch":"main","github_installation_id":7001,"github_repository_id":8001,"enabled":false,"protection_preflight_passed":false,"autonomy_ceiling":"L0","version":1,"project_map":null},"changed":true}"#;

#[test]
fn repository_register_sends_the_ids_the_name_and_a_key_and_says_what_comes_next() {
    let api = fake(vec![
        (202, REQUESTED),
        (200, APPLIED),
        (200, the_repository(REPOSITORY_BODY)),
    ]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "repository register --api http://{} --token-file {} --key k-r --installation 7001 --github-repository 8001 --name org/widgets",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    for part in [
        "The repository is registered.",
        "org/widgets",
        "Enabled:            no",
        "not attested yet. The repository cannot be enabled.",
        "Idempotency key: k-r",
    ] {
        assert!(ran.out.contains(part), "{part} in {}", ran.out);
    }
    let sent = api.requests.lock().expect("lock")[0].clone();
    assert!(sent.starts_with("POST /v1/repositories "), "{sent}");
    assert!(
        sent.to_lowercase().contains("idempotency-key: k-r"),
        "{sent}"
    );
    for part in [
        r#""installation_id":7001"#,
        r#""github_repository_id":8001"#,
        r#""full_name":"org/widgets""#,
        r#""default_branch":"main""#,
    ] {
        assert!(sent.contains(part), "{part} in {sent}");
    }
    // Nothing that grants anything is sent.
    for part in ["enabled", "autonomy", "project_map", "commit"] {
        assert!(!sent.contains(part), "{part} in {sent}");
    }
    // What the command refuses stops here, before any request.
    for line in [
        "repository register",
        "repository register --installation 7001 --github-repository 8001",
        "repository register --installation 0 --github-repository 8001 --name org/widgets",
        "repository register --installation x --github-repository 8001 --name org/widgets",
        "repository register --installation 7001 --github-repository -1 --name org/widgets",
        "repository register --installation 7001 --github-repository 8001 --name org/widgets extra",
        "repository register --enabled true --installation 7001 --github-repository 8001 --name org/widgets",
        "repository",
        "repository delete",
    ] {
        let ran = cli(&format!(
            "{line} --api http://{} --token-file {}",
            api.addr,
            file.display()
        ));
        assert_eq!(ran.exit, Exit::Failed, "{line}: {}", ran.err);
    }
    assert_eq!(
        api.requests.lock().expect("lock").len(),
        3,
        "the request, the state of the request and the repository: the refused lines sent nothing"
    );
    let sent = api.requests.lock().expect("lock").clone();
    assert!(
        sent[1].starts_with("GET /v1/repository-changes/0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a70 "),
        "{}",
        sent[1]
    );
    assert!(
        sent[2].starts_with("GET /v1/repositories/0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6d "),
        "{}",
        sent[2]
    );
}

#[test]
fn repository_confirm_map_sends_the_commit_and_the_reason_and_calls_it_a_statement() {
    let body = REPOSITORY_BODY.replace(
        r#""project_map":null"#,
        &format!(
            r#""project_map":{{"commit":"{MAP_COMMIT}","attested_by":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6e","attested_at":"2026-11-02T12:00:00Z","verified_by_engine":false}}"#
        ),
    );
    let body: &'static str = Box::leak(body.into_boxed_str());
    let api = fake(vec![
        (202, REQUESTED),
        (200, APPLIED),
        (200, the_repository(body)),
    ]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "repository confirm-map --api http://{} --token-file {} --key k-m {REPOSITORY} {MAP_COMMIT} I read the map files in the merged pull request.",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    for part in [
        "The repository is attested.",
        MAP_COMMIT,
        "This is a person's statement; the engine did not read the repository.",
    ] {
        assert!(ran.out.contains(part), "{part} in {}", ran.out);
    }
    let sent = api.requests.lock().expect("lock")[0].clone();
    assert!(
        sent.starts_with(&format!("POST /v1/repositories/{REPOSITORY}/project-map ")),
        "{sent}"
    );
    for part in [
        &format!(r#""commit":"{MAP_COMMIT}""#),
        r#""reason":"I read the map files in the merged pull request.""#,
    ] {
        assert!(sent.contains(part), "{part} in {sent}");
    }
    // What the command refuses stops here, before any request: a commit that is not 40 lowercase
    // hexadecimal characters, a reason that is short, an id that is not a UUID.
    let upper = MAP_COMMIT.to_uppercase();
    let reason = "I read the map files in the merged pull request.";
    for line in [
        format!("repository confirm-map {REPOSITORY}"),
        format!("repository confirm-map {REPOSITORY} {MAP_COMMIT}"),
        format!("repository confirm-map {REPOSITORY} {MAP_COMMIT} short"),
        format!("repository confirm-map {REPOSITORY} main {reason}"),
        format!("repository confirm-map {REPOSITORY} {upper} {reason}"),
        format!(
            "repository confirm-map {REPOSITORY} {} {reason}",
            &MAP_COMMIT[..39]
        ),
        format!("repository confirm-map not-a-uuid {MAP_COMMIT} {reason}"),
    ] {
        let ran = cli(&format!(
            "{line} --api http://{} --token-file {}",
            api.addr,
            file.display()
        ));
        assert_eq!(ran.exit, Exit::Failed, "{line}: {}", ran.err);
    }
    assert_eq!(api.requests.lock().expect("lock").len(), 3);
}

#[test]
fn repository_enable_disable_and_show_use_their_own_paths() {
    let enabled = REPOSITORY_BODY.replace(
        r#""enabled":false"#,
        &format!(
            r#""enabled":true,"enabled_for":{{"commit":"{MAP_COMMIT}","enabled_by":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6e","enabled_at":"2026-11-02T10:00:00Z"}}"#
        ),
    );
    let enabled: &'static str = Box::leak(enabled.into_boxed_str());
    let shown = r#"{"repository_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6d","full_name":"org/widgets","default_branch":"main","github_installation_id":7001,"github_repository_id":8001,"enabled":true,"protection_preflight_passed":false,"autonomy_ceiling":"L0","version":3,"project_map":null}"#;
    let api = fake(vec![
        (202, REQUESTED),
        (200, APPLIED),
        (200, the_repository(enabled)),
        (200, REPOSITORY_BODY),
        (200, shown),
    ]);
    let file = token_file(0o600);
    let base = format!("--api http://{} --token-file {}", api.addr, file.display());
    let ran = cli(&format!(
        "repository enable {base} --key k-e {REPOSITORY} {MAP_COMMIT}"
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(
        ran.out.contains("The repository is enabled."),
        "{}",
        ran.out
    );
    assert!(
        ran.out.contains(&format!(
            "Enabled:            yes, for the map at commit {MAP_COMMIT} (enabled by 0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6e"
        )),
        "{}",
        ran.out
    );
    let ran = cli(&format!(
        "repository disable {base} --key k-d {REPOSITORY} Switching it off while the map is rewritten."
    ));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(
        ran.out.contains("The repository is disabled."),
        "{}",
        ran.out
    );
    let ran = cli(&format!("repository show {base} {REPOSITORY}"));
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    assert!(ran.out.contains("Version:            3"), "{}", ran.out);
    let sent = api.requests.lock().expect("lock").clone();
    assert!(
        sent[0].starts_with(&format!("POST /v1/repositories/{REPOSITORY}/enable ")),
        "{}",
        sent[0]
    );
    assert!(
        sent[0].ends_with(&format!(r#"{{"commit":"{MAP_COMMIT}"}}"#)),
        "an enable names the commit and, with no reason, nothing else: {}",
        sent[0]
    );
    assert!(
        sent[3].starts_with(&format!("POST /v1/repositories/{REPOSITORY}/disable ")),
        "{}",
        sent[3]
    );
    assert!(
        sent[3].contains(r#""reason":"Switching it off while the map is rewritten.""#),
        "{}",
        sent[3]
    );
    assert!(
        sent[4].starts_with(&format!("GET /v1/repositories/{REPOSITORY} ")),
        "{}",
        sent[4]
    );
    // What the command refuses stops here.
    for line in [
        "repository enable".to_owned(),
        "repository enable not-a-uuid".to_owned(),
        // An enable names the commit that was read: none, a short one, or a branch is refused.
        format!("repository enable {REPOSITORY}"),
        format!("repository enable {REPOSITORY} short"),
        format!("repository enable {REPOSITORY} main"),
        format!("repository enable {REPOSITORY} {MAP_COMMIT} short"),
        format!("repository disable {REPOSITORY} short"),
        "repository show".to_owned(),
        format!("repository show {REPOSITORY} extra"),
        format!("repository show --key k {REPOSITORY}"),
    ] {
        let ran = cli(&format!("{line} {base}"));
        assert_eq!(ran.exit, Exit::Failed, "{line}: {}", ran.err);
    }
    assert_eq!(api.requests.lock().expect("lock").len(), 5);
}

#[test]
fn enabling_without_a_map_has_a_plain_refusal_and_exit_code_2() {
    let api = fake(vec![(409, r#"{"error":"project_map_not_attested"}"#)]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "repository enable --api http://{} --token-file {} {REPOSITORY} {MAP_COMMIT}",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Refused, "{}", ran.err);
    assert!(
        ran.err.contains("no project map that a person attested")
            && ran.err.contains("confirm-map"),
        "{}",
        ran.err
    );
    assert!(ran.out.is_empty(), "{}", ran.out);
}

#[test]
fn enabling_a_map_that_moved_has_a_plain_refusal_and_exit_code_2() {
    let api = fake(vec![(409, r#"{"error":"project_map_changed"}"#)]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "repository enable --api http://{} --token-file {} {REPOSITORY} {MAP_COMMIT}",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Refused, "{}", ran.err);
    assert!(
        ran.err.contains("attested again since you read it") && ran.err.contains("repository show"),
        "{}",
        ran.err
    );
    assert!(ran.out.is_empty(), "{}", ran.out);
}

#[test]
fn repository_register_sends_the_rule_about_the_enabler_and_only_as_a_switch_at_registration() {
    let api = fake(vec![(202, REQUESTED), (202, REQUESTED), (202, REQUESTED)]);
    let file = token_file(0o600);
    let base = format!("--api http://{} --token-file {}", api.addr, file.display());
    // The requests are not waited for here: this test is about what the body says.
    let line = "repository register --wait-seconds 0 --installation 7001 --github-repository 8001 --name org/widgets";
    // The default is the strict rule, and the body says so.
    assert_eq!(cli(&format!("{line} {base}")).exit, Exit::Ok);
    // The switch alone, and the switch spelled out, both reach the body.
    assert_eq!(
        cli(&format!("{line} --single-maintainer {base}")).exit,
        Exit::Ok
    );
    assert_eq!(
        cli(&format!("{line} --single-maintainer=false {base}")).exit,
        Exit::Ok
    );
    let sent = api.requests.lock().expect("lock").clone();
    assert!(
        sent[0].contains(r#""single_maintainer":false"#),
        "{}",
        sent[0]
    );
    assert!(
        sent[1].contains(r#""single_maintainer":true"#),
        "{}",
        sent[1]
    );
    assert!(
        sent[2].contains(r#""single_maintainer":false"#),
        "{}",
        sent[2]
    );
    // A switch that is not true or false stops before a request, and so does the switch on another
    // command: the rule is written at registration and nowhere else.
    for refused in [
        format!("{line} --single-maintainer=maybe {base}"),
        format!("repository enable --single-maintainer {base} {REPOSITORY} {MAP_COMMIT}"),
        format!(
            "repository confirm-map --single-maintainer {base} {REPOSITORY} {MAP_COMMIT} I read the map."
        ),
    ] {
        let ran = cli(&refused);
        assert_eq!(ran.exit, Exit::Failed, "{refused}: {}", ran.err);
    }
    assert_eq!(api.requests.lock().expect("lock").len(), 3);
}

#[test]
fn repository_show_names_the_rule_and_says_why_an_enabled_repository_is_closed() {
    let strict_open = r#"{"repository_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6d","full_name":"org/widgets","default_branch":"main","github_installation_id":7001,"github_repository_id":8001,"single_maintainer":false,"enabled":true,"standing":{"attestor_is_active_human":true,"enabler_is_active_human":true,"open_for_new_jobs":true},"protection_preflight_passed":false,"autonomy_ceiling":"L0","version":3,"project_map":null}"#;
    let closed = strict_open
        .replace(
            r#""single_maintainer":false"#,
            r#""single_maintainer":true"#,
        )
        .replace(
            r#""attestor_is_active_human":true"#,
            r#""attestor_is_active_human":false"#,
        )
        .replace(
            r#""open_for_new_jobs":true"#,
            r#""open_for_new_jobs":false"#,
        );
    let closed: &'static str = Box::leak(closed.into_boxed_str());
    let api = fake(vec![(200, strict_open), (200, closed)]);
    let file = token_file(0o600);
    let base = format!("--api http://{} --token-file {}", api.addr, file.display());
    let open = cli(&format!("repository show {base} {REPOSITORY}"));
    assert_eq!(open.exit, Exit::Ok, "{}", open.err);
    assert!(
        open.out.contains("Rule:               strict"),
        "{}",
        open.out
    );
    assert!(open.out.contains("Open for new jobs:  yes"), "{}", open.out);
    let shut = cli(&format!("repository show {base} {REPOSITORY}"));
    assert_eq!(shut.exit, Exit::Ok, "{}", shut.err);
    assert!(
        shut.out.contains("Rule:               single maintainer"),
        "{}",
        shut.out
    );
    assert!(
        shut.out.contains("Open for new jobs:  NO. The repository is enabled on file, but the person who attested the map is no longer an active human"),
        "{}",
        shut.out
    );
}

#[test]
fn enabling_a_map_one_attested_has_a_plain_refusal_and_exit_code_2() {
    let api = fake(vec![(409, r#"{"error":"enabler_is_attestor"}"#)]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "repository enable --api http://{} --token-file {} {REPOSITORY} {MAP_COMMIT}",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Refused, "{}", ran.err);
    assert!(
        ran.err
            .contains("you attested this repository's project map")
            && ran.err.contains("another person"),
        "{}",
        ran.err
    );
    assert!(ran.out.is_empty(), "{}", ran.out);
}

#[test]
fn a_change_the_worker_has_not_applied_in_time_is_recorded_and_says_how_to_look_again() {
    let pending = r#"{"request_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a70","kind":"register","repository_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6d","state":"requested","code":null}"#;
    let api = fake(vec![
        (202, REQUESTED),
        (202, REQUESTED),
        (200, pending),
        (200, pending),
        (200, pending),
    ]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "repository register --api http://{} --token-file {} --key k-w --wait-seconds 0 --installation 7001 --github-repository 8001 --name org/widgets",
        api.addr,
        file.display()
    ));
    // With a wait of zero the command sends the request and does not look at the state.
    assert_eq!(ran.exit, Exit::Ok, "{}", ran.err);
    for part in [
        "The request is recorded and signed.",
        "The command did not wait.",
        "factory-cli repository change 0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a70",
    ] {
        assert!(ran.out.contains(part), "{part} in {}", ran.out);
    }
    assert_eq!(api.requests.lock().expect("lock").len(), 1);

    // One second of patience: the worker has not settled it, and the command ends blocked (exit 3).
    let ran = cli(&format!(
        "repository confirm-map --api http://{} --token-file {} --key k-w2 --wait-seconds 1 {REPOSITORY} {MAP_COMMIT} I read the map files in the merged pull request.",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Blocked, "{}", ran.err);
    assert!(
        ran.out
            .contains("The worker had not applied it after 1 seconds."),
        "{}",
        ran.out
    );
    // The state of the request, read on its own.
    let again = cli(&format!(
        "repository change --api http://{} --token-file {} 0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a70",
        api.addr,
        file.display()
    ));
    assert_eq!(again.exit, Exit::Ok, "{}", again.err);
}

#[test]
fn a_refused_change_says_the_code_in_plain_words_and_exits_2() {
    let refused = r#"{"request_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a70","kind":"register","repository_id":"0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6d","state":"refused","code":"not_permitted"}"#;
    let api = fake(vec![(202, REQUESTED), (200, refused)]);
    let file = token_file(0o600);
    let ran = cli(&format!(
        "repository register --api http://{} --token-file {} --key k-x --installation 7001 --github-repository 8001 --name org/widgets",
        api.addr,
        file.display()
    ));
    assert_eq!(ran.exit, Exit::Refused, "{}", ran.err);
    assert!(
        ran.err.contains("checked the protected allowlist again")
            && ran.err.contains("Nothing changed."),
        "{}",
        ran.err
    );
    assert!(ran.out.is_empty(), "{}", ran.out);
    // Bad waits stop before a request.
    for line in [
        "--wait-seconds -1",
        "--wait-seconds soon",
        "--wait-seconds 601",
    ] {
        let ran = cli(&format!(
            "repository register {line} --api http://{} --token-file {} --installation 7001 --github-repository 8001 --name org/widgets",
            api.addr,
            file.display()
        ));
        assert_eq!(ran.exit, Exit::Failed, "{line}: {}", ran.err);
    }
    assert_eq!(api.requests.lock().expect("lock").len(), 2);
}
