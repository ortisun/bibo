//! The first checks against the real agent image in a real hardened container with the spike's fake
//! provider behind the job network. A BLOCKED reason (no Docker, a missing image) is a failing
//! test with a message that starts `BLOCKED:`, never a skip.

mod support;

use factory_ports::agent::{AgentRuntime, Capability};
use factory_runtime::probe::NeverCancelled;
use factory_runtime::{
    ClaudeCodeConfig, ClaudeCodeRuntime, CodexConfig, CodexRuntime, VerifiedTarget,
};
use support::docker::{HostWorkspace, Lab};
use support::{Harness, request};

#[tokio::test]
async fn real_smoke_claude_probes_and_runs_a_turn() {
    let lab = Lab::start();
    let h = Harness::new();
    h.register_secret("job-token", &lab.key);
    let ws = HostWorkspace::new(&[]);
    let mut session = lab.session(&h, &ws).await;
    assert!(
        VerifiedTarget::check(&factory_ports::sandbox::SandboxSession::posture(&session).clone())
            .is_ok(),
        "{:?}",
        session.posture
    );
    let runtime = ClaudeCodeRuntime::new(ClaudeCodeConfig::default(), h.io.clone());
    let found = runtime.probe(&mut session).await.expect("a probe");
    assert_eq!(found.runtime_version, "2.1.311");
    assert!(found.supports(Capability::HeadlessMultiTurn), "{found:?}");
    let mut req = request(
        &h,
        "claude-code-cli",
        "claude-sonnet-5-5",
        &lab.broker_url(),
    );
    req.prompt.instructions = "FAKE:OUTPUT {\"ok\":true}".to_owned();
    let report = runtime.run(&mut session, req, &NeverCancelled).await;
    let output = report.outcome.clone().expect("an output");
    assert_eq!(String::from_utf8_lossy(output.as_bytes()), "{\"ok\": true}");
    println!("{:?}", report.usage);
    println!("{}", h.transcript_of(&report).await.lines().count());
    assert!(!lab.model_requests().is_empty());
}

#[tokio::test]
async fn real_smoke_codex_probes_and_runs_a_turn() {
    let lab = Lab::start();
    let h = Harness::new();
    h.register_secret("job-token", &lab.key);
    let ws = HostWorkspace::new(&[]);
    let mut session = lab.session(&h, &ws).await;
    let runtime = CodexRuntime::new(CodexConfig::default(), h.io.clone());
    let found = runtime.probe(&mut session).await.expect("a probe");
    assert_eq!(found.runtime_version, "0.163.0");
    let mut req = request(&h, "codex-cli", "gpt-fake", &lab.broker_url());
    req.prompt.instructions = "FAKE:OUTPUT {\"ok\":true}".to_owned();
    let report = runtime.run(&mut session, req, &NeverCancelled).await;
    let output = report.outcome.clone().expect("an output");
    assert_eq!(String::from_utf8_lossy(output.as_bytes()), "{\"ok\": true}");
    println!("{:?}", report.usage);
    assert!(!lab.model_requests().is_empty());
}
