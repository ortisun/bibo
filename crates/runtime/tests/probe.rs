//! The capability probe of both adapters (work package done criterion 1): recorded help text turns
//! into the expected flag observations, the pinned versions are accepted, any other version blocks
//! the stage, and the router reads the results as `probed`.
//!
//! The session is the scripted stand-in (labelled fake) answering from the spike's recorded help
//! text; `tests/real_probe.rs`-style checks against the real image are in `verdicts.rs`.

mod support;

use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_ports::agent::{
    AgentRuntime, Capability, ModelRouter, ProbeError, ProbedCapabilities, RoutingError,
    RoutingNeed, RuntimeCapabilities,
};
use factory_runtime::{ClaudeCodeConfig, ClaudeCodeRuntime, CodexConfig, CodexRuntime};
use factory_testkit::router::{RouteRule, StaticModelRouter};
use support::Harness;
use support::scripted::{ScriptedSession, Step, Tool};

fn claude(h: &Harness) -> ClaudeCodeRuntime {
    ClaudeCodeRuntime::new(ClaudeCodeConfig::default(), h.io.clone(), h.attestation())
}

fn codex(h: &Harness) -> CodexRuntime {
    CodexRuntime::new(CodexConfig::default(), h.io.clone(), h.attestation())
}

fn session(h: &Harness, tool: Tool) -> ScriptedSession {
    ScriptedSession::new(h, tool, Step::exits(0, ""))
}

fn supported(found: &RuntimeCapabilities) -> Vec<Capability> {
    let mut list: Vec<Capability> = found
        .observations
        .iter()
        .filter(|o| o.supported)
        .map(|o| o.capability)
        .collect();
    list.sort();
    list
}

#[tokio::test]
async fn probe_claude_turns_the_recorded_help_into_the_expected_observations() {
    let h = Harness::new();
    let mut s = session(&h, Tool::Claude);
    let found = claude(&h).probe(&mut s).await.expect("a probe");
    assert_eq!(found.runtime_version, "2.1.311");
    let mut want = vec![
        Capability::StructuredStream,
        Capability::HeadlessMultiTurn,
        Capability::BudgetFlag,
        Capability::SkillInvocation,
        Capability::BaseUrlOverride,
        Capability::CredentialFromFile,
        Capability::PermissionDenialReport,
    ];
    want.sort();
    assert_eq!(supported(&found), want);
    // The factory schemas are rejected by the tool, so the capability is recorded as absent.
    assert!(!found.supports(Capability::JsonSchemaOutput));
    assert!(found.observations.iter().all(|o| !o.source.is_empty()));
}

#[tokio::test]
async fn probe_codex_turns_the_recorded_help_into_the_expected_observations() {
    let h = Harness::new();
    let mut s = session(&h, Tool::Codex);
    let found = codex(&h).probe(&mut s).await.expect("a probe");
    assert_eq!(found.runtime_version, "0.163.0");
    let mut want = vec![
        Capability::StructuredStream,
        Capability::HeadlessMultiTurn,
        Capability::SkillInvocation,
        Capability::BaseUrlOverride,
        Capability::CredentialFromFile,
    ];
    want.sort();
    assert_eq!(supported(&found), want);
    // Codex has no budget flag and reports no denials (spike section 4.7).
    assert!(!found.supports(Capability::BudgetFlag));
    assert!(!found.supports(Capability::PermissionDenialReport));
}

#[tokio::test]
async fn probe_a_second_probe_of_the_same_tool_gives_the_same_record() {
    let h = Harness::new();
    let runtime = claude(&h);
    let mut s = session(&h, Tool::Claude);
    let first = runtime.probe(&mut s).await.expect("first");
    let second = runtime.probe(&mut s).await.expect("second");
    assert_eq!(first, second);
}

#[tokio::test]
async fn probe_an_unknown_version_is_refused_and_blocks_the_stage() {
    let h = Harness::new();
    for text in [
        "2.1.312 (Claude Code)\n",
        "3.0.0\n",
        "nonsense\n",
        "2.1.31\n",
    ] {
        let mut s = session(&h, Tool::Claude).with_version(text);
        let error = claude(&h).probe(&mut s).await.expect_err("refused");
        assert!(
            matches!(error, ProbeError::UnsupportedVersion { .. }),
            "{text:?}: {error:?}"
        );
    }
    let mut s = session(&h, Tool::Codex).with_version("codex-cli 0.164.0\n");
    assert_eq!(
        codex(&h).probe(&mut s).await,
        Err(ProbeError::UnsupportedVersion {
            found: "0.164.0".to_owned()
        })
    );
}

#[tokio::test]
async fn probe_a_run_on_an_unsupported_version_does_not_start_the_tool() {
    let h = Harness::new();
    let mut s = session(&h, Tool::Claude).with_version("2.1.312 (Claude Code)\n");
    let watch = s.watch();
    let req = support::request(
        &h,
        "claude-code-cli",
        "claude-sonnet-5-5",
        "http://egress:8080",
    );
    let report = claude(&h)
        .run(&mut s, req, &factory_runtime::probe::NeverCancelled)
        .await;
    assert!(report.outcome.is_err());
    assert!(watch.tool_run().is_none(), "the tool must not start");
}

#[tokio::test]
async fn probe_a_flag_that_help_does_not_show_makes_its_capability_false() {
    let h = Harness::new();
    let cases = [
        ("--setting-sources", Capability::SkillInvocation),
        ("--output-format", Capability::StructuredStream),
        ("--max-budget-usd", Capability::BudgetFlag),
        ("--settings", Capability::CredentialFromFile),
    ];
    for (flag, capability) in cases {
        let mut s = session(&h, Tool::Claude).without_flag(flag);
        let found = claude(&h).probe(&mut s).await.expect("a probe");
        assert!(!found.supports(capability), "without {flag}");
    }
    for (flag, capability) in [
        ("--json", Capability::StructuredStream),
        ("--config", Capability::BaseUrlOverride),
    ] {
        let mut s = session(&h, Tool::Codex).without_flag(flag);
        let found = codex(&h).probe(&mut s).await.expect("a probe");
        assert!(!found.supports(capability), "without {flag}");
    }
}

#[tokio::test]
async fn probe_the_hidden_max_turns_flag_is_tested_by_behavior_not_by_help() {
    let h = Harness::new();
    // The help text never names it, in the real tool or in the recording.
    assert!(!support::recorded::CLAUDE_HELP.contains("--max-turns"));
    let mut s = session(&h, Tool::Claude);
    let watch = s.watch();
    let found = claude(&h).probe(&mut s).await.expect("a probe");
    assert!(found.supports(Capability::HeadlessMultiTurn));
    assert!(
        watch
            .seen()
            .iter()
            .any(|c| c.argv.iter().any(|a| a == "--max-turns=notanumber")),
        "the probe must try the flag"
    );
    // A tool that answers the trial with "unknown option" has no usable turn cap.
    let mut s = session(&h, Tool::Claude).without_max_turns();
    let found = claude(&h).probe(&mut s).await.expect("a probe");
    assert!(!found.supports(Capability::HeadlessMultiTurn));
}

#[tokio::test]
async fn probe_a_codex_without_a_feature_the_adapter_switches_off_is_not_headless() {
    let h = Harness::new();
    let mut s = session(&h, Tool::Codex).without_feature("unbounded_connection_retries");
    let found = codex(&h).probe(&mut s).await.expect("a probe");
    assert!(!found.supports(Capability::HeadlessMultiTurn));
    let source = &found
        .observations
        .iter()
        .find(|o| o.capability == Capability::HeadlessMultiTurn)
        .expect("an observation")
        .source;
    assert!(source.contains("unbounded_connection_retries"), "{source}");
}

#[tokio::test]
async fn probe_a_missing_binary_is_reported_as_missing() {
    let h = Harness::new();
    let mut s = session(&h, Tool::Claude).without_binary();
    assert_eq!(
        claude(&h).probe(&mut s).await,
        Err(ProbeError::BinaryMissing)
    );
    let mut s = session(&h, Tool::Codex).without_binary();
    assert_eq!(
        codex(&h).probe(&mut s).await,
        Err(ProbeError::BinaryMissing)
    );
}

fn need(required: Vec<Capability>, probed: ProbedCapabilities) -> RoutingNeed {
    RoutingNeed {
        stage: StageKind::Specification,
        tier: RecommendedTier::Standard,
        required,
        risk: RiskTier::Low,
        exclude: Vec::new(),
        probed,
    }
}

#[tokio::test]
async fn probe_the_router_uses_what_the_probe_found() {
    let h = Harness::new();
    let rule = |runtime: &str, capabilities: &[Capability]| RouteRule {
        stage: StageKind::Specification,
        tier: RecommendedTier::Standard,
        model: factory_ports::agent::ModelSelection {
            runtime: factory_ports::agent::RuntimeId::new(runtime).expect("a runtime id"),
            model: factory_domain::values::NonEmptyString::parse("some-model").expect("a model"),
        },
        capabilities: capabilities.to_vec(),
    };
    let claude_runtime = claude(&h);
    let mut s = session(&h, Tool::Claude);
    let found = claude_runtime.probe(&mut s).await.expect("a probe");
    let mut probed = ProbedCapabilities::default();
    probed.0.insert(claude_runtime.id().clone(), found);
    let router = StaticModelRouter::new(vec![rule(
        "claude-code-cli",
        &[Capability::SkillInvocation],
    )]);
    let decision = router
        .route(&need(vec![Capability::SkillInvocation], probed.clone()))
        .expect("a route");
    assert_eq!(decision.model.runtime.as_str(), "claude-code-cli");

    // A tool whose probe lacks the capability is not offered, whatever the table says.
    let mut s = session(&h, Tool::Claude).without_flag("--setting-sources");
    let found = claude_runtime.probe(&mut s).await.expect("a probe");
    let mut lacking = ProbedCapabilities::default();
    lacking.0.insert(claude_runtime.id().clone(), found);
    assert_eq!(
        router.route(&need(vec![Capability::SkillInvocation], lacking)),
        Err(RoutingError::CapabilityUnavailable(
            Capability::SkillInvocation
        ))
    );
    // A runtime that was not probed is not a candidate.
    assert!(
        router
            .route(&need(
                vec![Capability::SkillInvocation],
                ProbedCapabilities::default()
            ))
            .is_err()
    );
}
