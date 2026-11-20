//! The broker's record of the turns of a job (`TurnAttestation`, finding RR-14 of
//! docs/reviews/isolation-core-security-rereview.md, part b).
//!
//! The agent tool runs in a sandbox, and what it prints could have been written by another process
//! of the sandbox. The broker sits outside and reads the provider's own answer, so it can say how the
//! last model answer of a token ended. These tests drive the real listener against the labelled fake
//! provider and read the record through the port the runtime adapters use.

mod support;

use factory_ports::agent::{AnswerEnd, TurnAttestation};
use serde_json::json;
use support::{CEILING, CLAUDE_MODEL, Ending, HttpRig};

async fn summary(
    rig: &HttpRig,
    token: &factory_ports::agent::IssuedJobToken,
) -> factory_ports::agent::TurnSummary {
    TurnAttestation::turn_summary(rig.rig.core.as_ref(), &token.id)
        .await
        .expect("a summary")
}

#[tokio::test]
async fn a_token_that_made_no_request_has_no_answer() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let s = summary(&rig, &token).await;
    assert_eq!((s.answers, s.last_answer, s.in_flight), (0, None, 0));
    assert_eq!(s.usage.requests, 0);
}

#[tokio::test]
async fn an_answer_that_ended_the_turn_is_recorded_for_both_providers_and_both_shapes() {
    let rig = HttpRig::new();
    for stream in [false, true] {
        let claude = rig.claude_token(CEILING);
        assert_eq!(rig.claude(&claude, stream).status, 200);
        let s = summary(&rig, &claude).await;
        assert_eq!(
            (s.answers, s.last_answer, s.in_flight),
            (1, Some(AnswerEnd::EndTurn), 0),
            "claude, stream = {stream}"
        );
        assert_eq!(s.usage.requests, 1);

        let codex = rig.codex_token(CEILING);
        assert_eq!(rig.codex(&codex, stream).status, 200);
        let s = summary(&rig, &codex).await;
        assert_eq!(
            (s.answers, s.last_answer, s.in_flight),
            (1, Some(AnswerEnd::EndTurn), 0),
            "codex, stream = {stream}"
        );
    }
}

#[tokio::test]
async fn an_answer_that_asked_for_a_tool_is_not_an_end_of_turn() {
    let rig = HttpRig::new();
    rig.provider.set(|s| s.ending = Ending::ToolUse);
    for stream in [false, true] {
        let claude = rig.claude_token(CEILING);
        assert_eq!(rig.claude(&claude, stream).status, 200);
        assert_eq!(
            summary(&rig, &claude).await.last_answer,
            Some(AnswerEnd::ToolUse),
            "claude, stream = {stream}"
        );
        let codex = rig.codex_token(CEILING);
        assert_eq!(rig.codex(&codex, stream).status, 200);
        assert_eq!(
            summary(&rig, &codex).await.last_answer,
            Some(AnswerEnd::ToolUse),
            "codex, stream = {stream}"
        );
    }
}

#[tokio::test]
async fn an_answer_cut_at_the_output_limit_is_not_an_end_of_turn() {
    let rig = HttpRig::new();
    rig.provider.set(|s| s.ending = Ending::MaxTokens);
    for stream in [false, true] {
        let claude = rig.claude_token(CEILING);
        assert_eq!(rig.claude(&claude, stream).status, 200);
        assert_eq!(
            summary(&rig, &claude).await.last_answer,
            Some(AnswerEnd::Cut)
        );
        let codex = rig.codex_token(CEILING);
        assert_eq!(rig.codex(&codex, stream).status, 200);
        assert_eq!(
            summary(&rig, &codex).await.last_answer,
            Some(AnswerEnd::Cut)
        );
    }
}

#[tokio::test]
async fn the_last_answer_is_the_answer_to_the_latest_request() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    rig.provider.set(|s| s.ending = Ending::ToolUse);
    assert_eq!(rig.claude(&token, true).status, 200);
    assert_eq!(
        summary(&rig, &token).await.last_answer,
        Some(AnswerEnd::ToolUse)
    );
    rig.provider.set(|s| s.ending = Ending::EndTurn);
    assert_eq!(rig.claude(&token, true).status, 200);
    let s = summary(&rig, &token).await;
    assert_eq!((s.answers, s.last_answer), (2, Some(AnswerEnd::EndTurn)));
    // A further request that the provider answers with a failure replaces the record: a run whose
    // last request failed has not ended its turn.
    rig.provider.set(|s| s.error_status = Some(500));
    assert_eq!(rig.claude(&token, true).status, 500);
    let s = summary(&rig, &token).await;
    assert_eq!((s.answers, s.last_answer), (2, Some(AnswerEnd::Failed)));
}

#[tokio::test]
async fn a_count_tokens_call_never_changes_the_record_of_the_turns() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    rig.provider.set(|s| s.ending = Ending::ToolUse);
    assert_eq!(rig.claude(&token, false).status, 200);
    let counted = rig.post(
        "/v1/messages/count_tokens",
        ("x-api-key", token.secret.expose()),
        &json!({"model": CLAUDE_MODEL, "messages": []}),
    );
    assert_eq!(counted.status, 200);
    let s = summary(&rig, &token).await;
    assert_eq!((s.answers, s.last_answer), (1, Some(AnswerEnd::ToolUse)));
    assert_eq!(s.usage.requests, 2, "the call still counts as a request");
}

#[tokio::test]
async fn a_stream_cut_before_its_report_is_a_failed_answer() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    rig.provider.set(|s| s.cut_after_events = Some(2));
    // The client sees a stream that ends early and its helper panics on the bad chunk, so the
    // request is sent by hand and the answer is ignored.
    let _ = factory_testkit::fx::http::send_request(
        rig.addr(),
        "POST",
        "/v1/messages",
        &[
            ("Content-Type", "application/json"),
            ("x-api-key", token.secret.expose()),
        ],
        json!({"model": CLAUDE_MODEL, "stream": true, "max_tokens": 5})
            .to_string()
            .as_bytes(),
    );
    let s = summary(&rig, &token).await;
    assert_eq!((s.answers, s.last_answer), (0, Some(AnswerEnd::Failed)));
}

#[tokio::test]
async fn a_refused_request_leaves_the_record_alone() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    assert_eq!(rig.claude(&token, false).status, 200);
    let refused = rig.post(
        "/v1/messages",
        ("x-api-key", token.secret.expose()),
        &json!({"model": "not-the-token-model", "max_tokens": 5}),
    );
    assert_ne!(refused.status, 200);
    let s = summary(&rig, &token).await;
    assert_eq!((s.answers, s.last_answer), (1, Some(AnswerEnd::EndTurn)));
}

#[tokio::test]
async fn an_unknown_token_has_no_summary_and_the_record_survives_a_revoke() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    assert_eq!(rig.claude(&token, false).status, 200);
    rig.rig.core.revoke_token(&token.id);
    let s = summary(&rig, &token).await;
    assert_eq!(s.last_answer, Some(AnswerEnd::EndTurn));
    let stranger =
        factory_ports::agent::JobTokenId::from_uuid(factory_ports::clock::Uuid::from_u128(77));
    assert!(
        TurnAttestation::turn_summary(rig.rig.core.as_ref(), &stranger)
            .await
            .is_err()
    );
}
