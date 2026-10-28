//! Size limits, the budget from the manifest, and the explicit truncation record.

use factory_domain::values::{PositiveInt, Sha256Digest};
use factory_workflow::prompts::{AssemblyError, Limits};

use super::prompts_check::{attribute, decode, neutralize_oracle};
use super::prompts_support::{
    AssembleAny, agent, all_inputs, assembler_with, input, names, outside_lines,
};

fn with_max_tokens(id: &str, max_tokens: i64) -> super::prompts_support::Agent {
    let mut agent = agent(id);
    agent.manifest.resource_limits.max_tokens =
        PositiveInt::new(max_tokens).expect("a positive number");
    agent
}

#[test]
fn prompts_limits_a_one_mebibyte_line_is_cut_and_the_block_says_so() {
    let agent = with_max_tokens("intake-classifier", 4_000_000);
    let text = "A".repeat(1 << 20);
    let limits = Limits::default();
    let assembled = assembler_with(limits.clone())
        .assemble_any((&agent, vec![input(&agent, "request", text.clone())]))
        .expect("a long line assembles");

    let decoded = decode(&outside_lines(&agent), &names(&agent), assembled.text());
    assert!(decoded.problems.is_empty(), "{:#?}", decoded.problems);

    let header = &decoded.headers[0];
    assert_eq!(attribute(header, "truncated"), Some("yes"));
    let omitted: usize = attribute(header, "omitted")
        .and_then(|v| v.parse().ok())
        .expect("a number");
    assert!(omitted > 0);
    assert_eq!(decoded.bodies[0].len() + omitted, text.len());
    assert!(text.starts_with(&decoded.bodies[0]));

    let record = assembled.manifest().input("request").expect("a record");
    assert!(record.truncated);
    assert_eq!(record.omitted_bytes, omitted);
    assert_eq!(record.included_bytes, decoded.bodies[0].len());
    assert_eq!(record.original_bytes, 1 << 20);
    assert_eq!(record.original_sha256, Sha256Digest::of(text.as_bytes()));
    assert!(record.block_bytes <= limits.max_block_bytes);
    assert!(assembled.manifest().has_signal("truncated"));
}

#[test]
fn prompts_limits_an_input_under_the_limits_is_not_touched() {
    let agent = agent("intake-classifier");
    let assembled = assembler_with(Limits::default())
        .assemble_any((&agent, vec![input(&agent, "request", "small text")]))
        .expect("assembles");
    let decoded = decode(&outside_lines(&agent), &names(&agent), assembled.text());
    assert_eq!(attribute(&decoded.headers[0], "truncated"), Some("no"));
    assert_eq!(attribute(&decoded.headers[0], "omitted"), Some("0"));
    let record = assembled.manifest().input("request").expect("a record");
    assert!(!record.truncated);
    assert_eq!(record.omitted_bytes, 0);
    assert!(!assembled.manifest().has_signal("truncated"));
}

#[test]
fn prompts_limits_a_cut_never_splits_a_character() {
    let agent = with_max_tokens("intake-classifier", 4_000_000);
    let text = "\u{65E5}\u{672C}\u{8A9E}\u{1F600}".repeat(40_000);
    let limits = Limits {
        max_block_bytes: 10_001,
        ..Limits::default()
    };
    let assembled = assembler_with(limits)
        .assemble_any((&agent, vec![input(&agent, "request", text.clone())]))
        .expect("assembles");
    let decoded = decode(&outside_lines(&agent), &names(&agent), assembled.text());
    assert!(decoded.problems.is_empty(), "{:#?}", decoded.problems);
    assert!(text.starts_with(&decoded.bodies[0]));
    assert!(!decoded.bodies[0].is_empty());
}

#[test]
fn prompts_limits_lines_count_toward_the_limit_with_their_quote_prefixes() {
    let agent = with_max_tokens("intake-classifier", 4_000_000);
    let text = "x\n".repeat(200_000);
    let limits = Limits {
        max_block_bytes: 40_000,
        ..Limits::default()
    };
    let assembled = assembler_with(limits.clone())
        .assemble_any((&agent, vec![input(&agent, "request", text)]))
        .expect("assembles");
    let record = assembled.manifest().input("request").expect("a record");
    assert!(record.truncated);
    assert!(
        record.block_bytes <= limits.max_block_bytes,
        "{}",
        record.block_bytes
    );
    assert!(record.block_bytes > limits.max_block_bytes - 400);
}

#[test]
fn prompts_limits_the_manifest_budget_bounds_the_whole_prompt() {
    // 10_000 tokens, 25 percent for the prompt, 3 bytes a token: 7_500 bytes.
    let agent = with_max_tokens("code-reviewer", 10_000);
    let limits = Limits::default();
    let assembled = assembler_with(limits.clone())
        .assemble_any((
            &agent,
            all_inputs(&agent, |_| "line of text\n".repeat(5_000)),
        ))
        .expect("assembles within the budget");
    let manifest = assembled.manifest();
    assert_eq!(manifest.budget_bytes, 7_500);
    assert!(
        assembled.text().len() <= 7_500,
        "{}",
        assembled.text().len()
    );
    assert_eq!(manifest.prompt_bytes, assembled.text().len());
    assert_eq!(
        manifest.estimated_tokens,
        limits.estimate_tokens(assembled.text().len())
    );
    assert!(manifest.inputs.iter().all(|i| i.truncated));
    let decoded = decode(&outside_lines(&agent), &names(&agent), assembled.text());
    assert!(decoded.problems.is_empty(), "{:#?}", decoded.problems);
}

#[test]
fn prompts_limits_a_small_input_is_kept_whole_while_large_ones_are_cut_to_a_common_level() {
    let agent = with_max_tokens("code-reviewer", 10_000);
    let inputs = vec![
        input(&agent, "frozen_specification", "tiny spec"),
        input(&agent, "diff", "d".repeat(100_000)),
        input(&agent, "gate_reports", "g".repeat(100_000)),
    ];
    let assembled = assembler_with(Limits::default())
        .assemble_any((&agent, inputs))
        .expect("assembles");
    let m = assembled.manifest();
    let spec = m.input("frozen_specification").expect("record");
    let diff = m.input("diff").expect("record");
    let gate = m.input("gate_reports").expect("record");
    assert!(!spec.truncated);
    assert_eq!(spec.included_bytes, "tiny spec".len());
    assert!(diff.truncated && gate.truncated);
    assert!(diff.included_bytes.abs_diff(gate.included_bytes) <= 1);
}

#[test]
fn prompts_limits_a_budget_too_small_for_the_instructions_fails() {
    let agent = with_max_tokens("code-reviewer", 100);
    let result = assembler_with(Limits::default())
        .assemble_any((&agent, all_inputs(&agent, |_| "x".to_owned())));
    assert!(
        matches!(result, Err(AssemblyError::BudgetTooSmall { .. })),
        "{result:?}"
    );
}

#[test]
fn prompts_limits_the_prompt_byte_limit_applies_when_the_token_budget_is_larger() {
    let agent = agent("builder");
    let limits = Limits {
        max_prompt_bytes: 12_000,
        ..Limits::default()
    };
    let assembled = assembler_with(limits)
        .assemble_any((&agent, all_inputs(&agent, |_| "a line\n".repeat(20_000))))
        .expect("assembles");
    assert!(assembled.text().len() <= 12_000);
    assert_eq!(assembled.manifest().budget_bytes, 12_000);
}

#[test]
fn prompts_limits_an_input_over_the_read_limit_is_refused_not_cut() {
    let agent = agent("intake-classifier");
    let limits = Limits {
        max_read_bytes_per_input: 1_000,
        ..Limits::default()
    };
    let result = assembler_with(limits)
        .assemble_any((&agent, vec![input(&agent, "request", "z".repeat(1_001))]));
    assert!(
        matches!(result, Err(AssemblyError::InputTooLarge { .. })),
        "{result:?}"
    );
}

#[test]
fn prompts_limits_inputs_over_the_total_read_limit_are_refused() {
    let agent = agent("code-reviewer");
    let limits = Limits {
        max_read_bytes_per_input: 1_000,
        max_read_bytes_total: 2_500,
        ..Limits::default()
    };
    let result =
        assembler_with(limits).assemble_any((&agent, all_inputs(&agent, |_| "z".repeat(900))));
    assert!(
        matches!(result, Err(AssemblyError::InputsTooLarge { .. })),
        "{result:?}"
    );
}

#[test]
fn prompts_limits_what_is_left_out_is_always_recorded_never_silent() {
    // For every size around the limit, an input is either whole and marked `truncated=no`, or
    // cut and marked `truncated=yes` with the exact count of omitted bytes.
    let agent = agent("intake-classifier");
    let limits = Limits {
        max_block_bytes: 2_000,
        ..Limits::default()
    };
    for size in (0..4_000).step_by(37) {
        let text = "ab\n".repeat(size / 3 + 1);
        let assembled = assembler_with(limits.clone())
            .assemble_any((&agent, vec![input(&agent, "request", text.clone())]))
            .expect("assembles");
        let decoded = decode(&outside_lines(&agent), &names(&agent), assembled.text());
        let cleaned = neutralize_oracle(&text);
        let omitted: usize = attribute(&decoded.headers[0], "omitted")
            .and_then(|v| v.parse().ok())
            .expect("a number");
        let flag = attribute(&decoded.headers[0], "truncated").expect("a flag");
        assert_eq!(
            decoded.bodies[0].len() + omitted,
            cleaned.len(),
            "size {size}"
        );
        assert_eq!(flag == "yes", omitted > 0, "size {size}");
    }
}
