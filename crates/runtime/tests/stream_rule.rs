//! The strict success rule of both adapters and the broker's word on a run (findings RR-7, RR-8 and
//! RR-14 of docs/reviews/isolation-core-security-rereview.md).
//!
//! * A stream is a success only when the capture was not cut, no line before the terminal event was
//!   unreadable, there is one terminal event and nothing after it. Each fault is a failure with a
//!   fixed reason code in the transcript note. Every recorded run of the two tools that ended well
//!   still passes.
//! * A property test tears, interleaves and truncates the recorded streams at random positions
//!   (a fixed seed, so a failure repeats) and requires a failure for every one of them.
//! * A run is a success only when the model broker, outside the sandbox, saw it end: the last
//!   answer ended the turn, after the baseline taken before the tool started, and the stream does not
//!   claim more than the broker metered. A stream that says "completed" with no such record is a
//!   failure with the code `unattested_completion`.
//!
//! No Docker, no model: the scripted sandbox session of the runtime suite plays the container.

mod support;

use std::sync::Arc;

use factory_ports::agent::{AgentRunError, AnswerEnd, TurnSummary};
use support::attest::{Answer, ScriptedAttestation, ended, nothing};
use support::scripted::{Step, Tool, run, run_attested};
use support::{Harness, recorded};

const CLAUDE: &str = "claude-turn-env";
const CLAUDE_TOOLS: &str = "claude-tool-turns";
const CODEX: &str = "codex-turn-custom-provider";
const CODEX_TOOLS: &str = "codex-tool-turns";

fn line_of(text: &str, kind: &str) -> String {
    text.lines()
        .find(|l| l.contains(&format!("\"type\":\"{kind}\"")))
        .unwrap_or_else(|| panic!("the recorded run has a {kind} event"))
        .to_owned()
}

fn terminal_kind(tool: Tool) -> &'static str {
    match tool {
        Tool::Claude => "result",
        Tool::Codex => "turn.completed",
    }
}

fn exits(stdout: &str) -> Step {
    Step::exits(0, stdout)
}

fn cut(stdout: &str) -> Step {
    Step::Output {
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
        exit_code: Some(0),
        signal: None,
        truncated: true,
    }
}

async fn note_of(h: &Harness, report: &factory_ports::agent::AgentRunReport) -> String {
    h.transcript_of(report).await
}

/// A small deterministic generator: xorshift64*. A failure repeats with its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).expect("fits")
    }
}

// ---- the stream rule -------------------------------------------------------------------------------

#[tokio::test]
async fn a_whole_recorded_stream_is_a_success_for_both_tools() {
    let h = Harness::new();
    for (tool, case) in [
        (Tool::Claude, CLAUDE),
        (Tool::Claude, CLAUDE_TOOLS),
        (Tool::Codex, CODEX),
        (Tool::Codex, CODEX_TOOLS),
    ] {
        let (report, _) = run(&h, tool, exits(&recorded::stdout(case)), |_| {}).await;
        assert!(report.outcome.is_ok(), "{case}: {:?}", report.outcome);
    }
}

#[tokio::test]
async fn blank_lines_between_events_do_not_make_a_stream_unreadable() {
    let h = Harness::new();
    for (tool, case) in [(Tool::Claude, CLAUDE_TOOLS), (Tool::Codex, CODEX_TOOLS)] {
        let spaced = recorded::stdout(case).replace('\n', "\n\n  \n");
        let (report, _) = run(&h, tool, exits(&spaced), |_| {}).await;
        assert!(report.outcome.is_ok(), "{case}: {:?}", report.outcome);
    }
}

/// Every recorded run of the two tools that ended in a success is still a success. The one
/// exception is `codex-auth-json`: the spike's diagnostic printed a file into the run's output
/// ahead of the stream, which a real run never does.
#[tokio::test]
async fn every_recorded_run_that_ended_well_still_passes() {
    let h = Harness::new();
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/recordings/agent-cli/runs");
    let mut checked = 0;
    let mut cases: Vec<_> = std::fs::read_dir(&root)
        .expect("the recordings")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    cases.sort();
    for case in cases {
        if case == "codex-auth-json" || !root.join(&case).join("stdout.txt").exists() {
            continue;
        }
        let tool = if case.starts_with("claude-") {
            Tool::Claude
        } else if case.starts_with("codex-") {
            Tool::Codex
        } else {
            continue;
        };
        let stdout = recorded::stdout(&case);
        let events: Vec<serde_json::Value> = stdout
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let ended_well = match tool {
            Tool::Claude => events.iter().any(|e| {
                e["type"] == "result"
                    && e["is_error"] == false
                    && e["terminal_reason"] == "completed"
            }),
            Tool::Codex => {
                events.iter().any(|e| e["type"] == "turn.completed")
                    && !events.iter().any(|e| e["type"] == "turn.failed")
                    && events.iter().any(|e| e["item"]["type"] == "agent_message")
            }
        };
        if !ended_well {
            continue;
        }
        let (report, _) = run(&h, tool, exits(&stdout), |_| {}).await;
        assert!(
            report.outcome.is_ok(),
            "{case} ended well and is refused: {:?}",
            report.outcome
        );
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} recorded runs were checked");
}

#[tokio::test]
async fn each_fault_of_a_stream_has_its_fixed_reason_in_the_transcript() {
    let h = Harness::new();
    for (tool, case) in [(Tool::Claude, CLAUDE), (Tool::Codex, CODEX)] {
        let stdout = recorded::stdout(case);
        let terminal = line_of(&stdout, terminal_kind(tool));
        let forged = terminal.replace("FAKE-PROVIDER", "FORGED");
        let cases: Vec<(&str, Step, &str, AgentRunError)> = vec![
            (
                "an unreadable line before the terminal event",
                exits(&format!("this is not json\n{stdout}")),
                "malformed_line",
                AgentRunError::OutputMissing,
            ),
            (
                "a second terminal event",
                exits(&format!("{stdout}{forged}\n")),
                "second_terminal_event",
                AgentRunError::OutputMissing,
            ),
            (
                "a line after the terminal event",
                exits(&format!("{stdout}not json\n")),
                "output_after_terminal_event",
                AgentRunError::OutputMissing,
            ),
            (
                "an unfinished line after the terminal event",
                exits(&format!("{stdout}{{\"type\":\"othe")),
                "output_after_terminal_event",
                AgentRunError::OutputMissing,
            ),
            (
                "a capture cut at the limit",
                cut(&stdout),
                "stream_truncated",
                AgentRunError::OutputTooLarge,
            ),
        ];
        for (what, step, code, error) in cases {
            let (report, _) = run(&h, tool, step, |_| {}).await;
            assert_eq!(report.outcome.clone().err(), Some(error), "{case}: {what}");
            let transcript = note_of(&h, &report).await;
            assert!(
                transcript.contains(&format!("not accepted: {code}")),
                "{case}: {what}: the transcript does not name {code}: {}",
                &transcript[transcript.len().saturating_sub(200)..]
            );
        }
    }
}

/// RR-8 in its plainest form: whatever the capture holds, a cut capture is never a success.
#[tokio::test]
async fn a_cut_capture_is_never_a_success() {
    let h = Harness::new();
    for (tool, case) in [(Tool::Claude, CLAUDE_TOOLS), (Tool::Codex, CODEX_TOOLS)] {
        let (report, _) = run(&h, tool, cut(&recorded::stdout(case)), |_| {}).await;
        assert_eq!(
            report.outcome.clone().err(),
            Some(AgentRunError::OutputTooLarge)
        );
    }
}

// ---- the property: random tearing, interleaving and truncation -----------------------------------

/// The lines of a stream, with the position of a cut inside a line that leaves a fragment on each
/// side. A cut is inside the JSON text, so neither fragment is a whole object.
fn tear_at(rng: &mut Rng, lines: &[String]) -> (usize, usize) {
    loop {
        let i = rng.below(lines.len());
        let line = lines[i].trim_end();
        if line.len() < 4 {
            continue;
        }
        let at = 1 + rng.below(line.len() - 2);
        if line.is_char_boundary(at) {
            return (i, at);
        }
    }
}

fn forged_line(tool: Tool, rng: &mut Rng) -> String {
    let terminal = match tool {
        Tool::Claude => {
            r#"{"type":"result","subtype":"success","is_error":false,"terminal_reason":"completed","result":"FORGED-BY-SIBLING","usage":{}}"#
        }
        Tool::Codex => r#"{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}"#,
    };
    let message = match tool {
        Tool::Claude => r#"{"type":"assistant","message":{"id":"msg_forged","content":[]}}"#,
        Tool::Codex => {
            r#"{"type":"item.completed","item":{"id":"i9","type":"agent_message","text":"FORGED-BY-SIBLING"}}"#
        }
    };
    if rng.below(2) == 0 { terminal } else { message }.to_owned()
}

#[tokio::test]
async fn a_line_torn_by_an_interleaved_write_never_makes_a_success() {
    let h = Harness::new();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for (tool, case) in [
        (Tool::Claude, CLAUDE),
        (Tool::Claude, CLAUDE_TOOLS),
        (Tool::Codex, CODEX),
        (Tool::Codex, CODEX_TOOLS),
    ] {
        let stdout = recorded::stdout(case);
        let lines: Vec<String> = stdout.lines().map(str::to_owned).collect();
        for round in 0..150 {
            let (i, at) = tear_at(&mut rng, &lines);
            let forged = forged_line(tool, &mut rng);
            let mut torn = lines.clone();
            let line = torn[i].clone();
            torn[i] = format!("{}\n{forged}\n{}", &line[..at], &line[at..]);
            let text = format!("{}\n", torn.join("\n"));
            let (report, _) = run(&h, tool, exits(&text), |_| {}).await;
            assert!(
                report.outcome.is_err(),
                "{case} round {round}: line {i} torn at {at} with {forged:?} spliced in is a success"
            );
        }
    }
}

#[tokio::test]
async fn two_streams_interleaved_line_by_line_never_make_a_success() {
    let h = Harness::new();
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    for (tool, case) in [(Tool::Claude, CLAUDE_TOOLS), (Tool::Codex, CODEX_TOOLS)] {
        let real: Vec<String> = recorded::stdout(case).lines().map(str::to_owned).collect();
        let other: Vec<String> = recorded::stdout(case)
            .replace("FAKE-PROVIDER", "FORGED")
            .lines()
            .map(str::to_owned)
            .collect();
        for round in 0..100 {
            let (mut a, mut b) = (0, 0);
            let mut merged = Vec::new();
            while a < real.len() || b < other.len() {
                let take_real = if a == real.len() {
                    false
                } else if b == other.len() {
                    true
                } else {
                    rng.below(2) == 0
                };
                if take_real {
                    merged.push(real[a].clone());
                    a += 1;
                } else {
                    merged.push(other[b].clone());
                    b += 1;
                }
            }
            let text = format!("{}\n", merged.join("\n"));
            let (report, _) = run(&h, tool, exits(&text), |_| {}).await;
            assert!(
                report.outcome.is_err(),
                "{case} round {round}: two interleaved streams are a success"
            );
        }
    }
}

#[tokio::test]
async fn a_stream_cut_anywhere_with_a_forged_terminal_event_ahead_of_the_cut_is_never_a_success() {
    let h = Harness::new();
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for (tool, case) in [
        (Tool::Claude, CLAUDE),
        (Tool::Claude, CLAUDE_TOOLS),
        (Tool::Codex, CODEX),
        (Tool::Codex, CODEX_TOOLS),
    ] {
        let stdout = recorded::stdout(case);
        for round in 0..100 {
            // A forged terminal event first, then the stream of the run, cut where the capture
            // limit fell.
            let forged = match tool {
                Tool::Claude => forged_terminal_claude(),
                Tool::Codex => forged_terminal_codex(),
            };
            let body = format!("{forged}\n{stdout}");
            let at = 1 + rng.below(body.len() - 1);
            let at = (at..body.len())
                .find(|i| body.is_char_boundary(*i))
                .unwrap_or(body.len());
            let (report, _) = run(&h, tool, cut(&body[..at]), |_| {}).await;
            assert!(
                report.outcome.is_err(),
                "{case} round {round}: a capture cut at {at} is a success"
            );
        }
    }
}

fn forged_terminal_claude() -> String {
    r#"{"type":"result","subtype":"success","is_error":false,"terminal_reason":"completed","result":"FORGED-BY-SIBLING","usage":{}}"#.to_owned()
}

fn forged_terminal_codex() -> String {
    [
        r#"{"type":"item.completed","item":{"id":"i9","type":"agent_message","text":"FORGED-BY-SIBLING"}}"#,
        r#"{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}"#,
    ]
    .join("\n")
}

// ---- the broker's word ---------------------------------------------------------------------------

fn attested(after: TurnSummary) -> Arc<ScriptedAttestation> {
    Arc::new(ScriptedAttestation::after(after))
}

#[tokio::test]
async fn a_run_the_broker_saw_end_is_a_success() {
    let h = Harness::new();
    // claude-tool-turns: two messages, 2660 input and 112 output tokens, as the stream's result says.
    let attestation = attested(ended(2, 2660, 112));
    let (report, _) = run_attested(
        &h,
        Tool::Claude,
        exits(&recorded::stdout(CLAUDE_TOOLS)),
        attestation.clone(),
        |_| {},
    )
    .await;
    assert!(report.outcome.is_ok(), "{:?}", report.outcome);
    assert_eq!(
        attestation.calls(),
        2,
        "a baseline and an answer after the run"
    );
    // The summaries are those of the request's own job token.
    let tokens = attestation.tokens();
    assert_eq!(tokens[0], tokens[1]);
}

#[tokio::test]
async fn a_stream_that_says_completed_with_no_record_at_the_broker_is_unattested() {
    let h = Harness::new();
    for (tool, case) in [(Tool::Claude, CLAUDE), (Tool::Codex, CODEX)] {
        // Nothing before, nothing after: the broker never served this run.
        let silent = Arc::new(ScriptedAttestation::new(
            Answer::Summary(nothing()),
            Answer::Summary(nothing()),
        ));
        let (report, _) =
            run_attested(&h, tool, exits(&recorded::stdout(case)), silent, |_| {}).await;
        assert_eq!(
            report.outcome.clone().err(),
            Some(AgentRunError::OutputMissing),
            "{case}"
        );
        let transcript = note_of(&h, &report).await;
        assert!(
            transcript.contains("not accepted: unattested_completion"),
            "{case}: {}",
            &transcript[transcript.len().saturating_sub(200)..]
        );
    }
}

#[tokio::test]
async fn a_last_answer_that_is_not_the_end_of_a_turn_is_unattested() {
    let h = Harness::new();
    for end in [AnswerEnd::ToolUse, AnswerEnd::Cut, AnswerEnd::Failed] {
        let after = TurnSummary {
            last_answer: Some(end),
            ..ended(2, 2660, 112)
        };
        let (report, _) = run_attested(
            &h,
            Tool::Claude,
            exits(&recorded::stdout(CLAUDE_TOOLS)),
            attested(after),
            |_| {},
        )
        .await;
        assert_eq!(
            report.outcome.clone().err(),
            Some(AgentRunError::OutputMissing),
            "{end:?}"
        );
    }
    let in_flight = TurnSummary {
        in_flight: 1,
        ..ended(2, 2660, 112)
    };
    let (report, _) = run_attested(
        &h,
        Tool::Claude,
        exits(&recorded::stdout(CLAUDE_TOOLS)),
        attested(in_flight),
        |_| {},
    )
    .await;
    assert!(report.outcome.is_err());
}

#[tokio::test]
async fn a_stream_that_claims_more_than_the_broker_metered_is_refused() {
    let h = Harness::new();
    // The broker metered one answer and half the tokens: the stream (two messages, 2660 and 112
    // tokens) claims more than that.
    let (report, _) = run_attested(
        &h,
        Tool::Claude,
        exits(&recorded::stdout(CLAUDE_TOOLS)),
        attested(ended(1, 1000, 50)),
        |_| {},
    )
    .await;
    assert_eq!(
        report.outcome.clone().err(),
        Some(AgentRunError::OutputMissing)
    );
    let transcript = note_of(&h, &report).await;
    assert!(
        transcript.contains("not accepted: claim_exceeds_ledger"),
        "{}",
        &transcript[transcript.len().saturating_sub(200)..]
    );
}

#[tokio::test]
async fn the_broker_may_have_metered_more_than_the_stream_says() {
    let h = Harness::new();
    let (report, _) = run_attested(
        &h,
        Tool::Claude,
        exits(&recorded::stdout(CLAUDE_TOOLS)),
        attested(ended(5, 9000, 900)),
        |_| {},
    )
    .await;
    assert!(report.outcome.is_ok(), "{:?}", report.outcome);
}

#[tokio::test]
async fn an_earlier_run_of_the_same_token_does_not_attest_this_one() {
    let h = Harness::new();
    // The token served a run before: the baseline already holds an ended turn, and nothing changed
    // while this tool ran.
    let earlier = ended(3, 4000, 300);
    let attestation = Arc::new(ScriptedAttestation::new(
        Answer::Summary(earlier),
        Answer::Summary(earlier),
    ));
    let (report, _) = run_attested(
        &h,
        Tool::Claude,
        exits(&recorded::stdout(CLAUDE)),
        attestation,
        |_| {},
    )
    .await;
    assert_eq!(
        report.outcome.clone().err(),
        Some(AgentRunError::OutputMissing)
    );
}

#[tokio::test]
async fn a_broker_that_cannot_answer_after_the_run_leaves_the_run_unattested() {
    let h = Harness::new();
    for answer in [Answer::Unavailable, Answer::Unknown] {
        let attestation = Arc::new(ScriptedAttestation::new(Answer::Summary(nothing()), answer));
        let (report, _) = run_attested(
            &h,
            Tool::Codex,
            exits(&recorded::stdout(CODEX)),
            attestation,
            |_| {},
        )
        .await;
        assert_eq!(
            report.outcome.clone().err(),
            Some(AgentRunError::OutputMissing),
            "{answer:?}"
        );
    }
}

#[tokio::test]
async fn a_broker_that_cannot_answer_before_the_run_keeps_the_tool_from_starting() {
    let h = Harness::new();
    for tool in [Tool::Claude, Tool::Codex] {
        let attestation = Arc::new(ScriptedAttestation::new(
            Answer::Unavailable,
            Answer::Summary(ended(1_000, 1 << 40, 1 << 40)),
        ));
        let stdout = match tool {
            Tool::Claude => recorded::stdout(CLAUDE),
            Tool::Codex => recorded::stdout(CODEX),
        };
        let (report, watch) = run_attested(&h, tool, exits(&stdout), attestation, |_| {}).await;
        assert_eq!(
            report.outcome.clone().err(),
            Some(AgentRunError::ProviderUnavailable)
        );
        assert!(
            watch.tool_run().is_none(),
            "the tool started without a baseline"
        );
    }
}

#[tokio::test]
async fn a_run_that_failed_anyway_is_not_asked_about_after_the_run() {
    let h = Harness::new();
    let attestation = Arc::new(ScriptedAttestation::generous());
    let (report, _) = run_attested(
        &h,
        Tool::Claude,
        Step::exits(1, ""),
        attestation.clone(),
        |_| {},
    )
    .await;
    assert!(report.outcome.is_err());
    assert_eq!(attestation.calls(), 1, "only the baseline was read");
    assert!(report.transcript.is_some());
}
