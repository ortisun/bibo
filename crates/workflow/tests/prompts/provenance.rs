//! The context manifest and the hash: what the audit ledger binds a run to.

use factory_domain::values::{Sha256Digest, Timestamp};
use factory_workflow::prompts::{ContentClass, Input, Source, Trust};

use super::prompts_support::{
    AssembleAny, agent, agents, all_inputs, assemble, assembler, input, names, tenant,
};

fn at(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("a timestamp")
}

#[test]
fn prompts_provenance_records_the_template_and_the_hash_of_the_prompt() {
    for agent in agents() {
        let assembled =
            assemble(&agent, all_inputs(&agent, |n| format!("text of {n}"))).expect("ok");
        let m = assembled.manifest();
        assert_eq!(m.agent_id, agent.manifest.id.to_string());
        assert_eq!(m.agent_version, agent.manifest.version.to_string());
        assert_eq!(
            m.template.path,
            agent.manifest.prompt.template_path.to_string()
        );
        assert_eq!(
            m.template.version,
            agent.manifest.prompt.template_version.to_string()
        );
        assert_eq!(m.template.sha256, agent.manifest.prompt.template_sha256);
        assert_eq!(
            m.prompt_sha256,
            Sha256Digest::of(assembled.text().as_bytes())
        );
        assert_eq!(&m.prompt_sha256, assembled.sha256());
        assert_eq!(m.prompt_bytes, assembled.text().len());
        assert!(m.estimated_tokens > 0);
        assert!(m.prompt_bytes <= m.budget_bytes);
    }
}

#[test]
fn prompts_provenance_records_each_input_with_its_source_and_sizes() {
    let agent = agent("code-reviewer");
    let diff_source = Source::RepoFile {
        path: "src/lib.rs".to_owned(),
        commit: None,
        lines: Some(factory_workflow::prompts::LineRange { start: 10, end: 20 }),
    };
    let inputs = vec![
        input(&agent, "frozen_specification", "spec text\u{200B}"),
        Input::untrusted(
            "diff",
            ContentClass::ModelOutput,
            diff_source.clone(),
            tenant(),
            "diff text",
        )
        .fetched_at(at("2026-10-27T10:00:00Z")),
        input(&agent, "gate_reports", "reports"),
    ];
    let assembled = assemble(&agent, inputs).expect("assembles");
    let m = assembled.manifest();
    assert_eq!(
        m.inputs.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
        vec!["frozen_specification", "diff", "gate_reports"]
    );
    let diff = m.input("diff").expect("record");
    assert_eq!(diff.class, ContentClass::ModelOutput);
    assert_eq!(diff.trust, Trust::Untrusted);
    assert_eq!(diff.source.as_ref(), Some(&diff_source));
    assert!(diff.provided);
    assert_eq!(diff.paths, vec!["src/lib.rs".to_owned()]);
    assert_eq!(diff.fetched_at, Some(at("2026-10-27T10:00:00Z")));
    assert_eq!(diff.original_bytes, "diff text".len());
    assert_eq!(diff.included_bytes, "diff text".len());
    assert_eq!(diff.original_sha256, Sha256Digest::of(b"diff text"));
    assert!(!diff.truncated && diff.stripped == 0 && diff.redacted == 0);
    let spec = m.input("frozen_specification").expect("record");
    assert_eq!(spec.stripped, 1);
    assert_eq!(spec.included_bytes, "spec text".len());
    assert_eq!(spec.original_bytes, "spec text\u{200B}".len());
    assert_eq!(
        diff.source.as_ref().map(ToString::to_string).as_deref(),
        Some("file:src/lib.rs#L10-20")
    );
}

#[test]
fn prompts_provenance_the_same_inputs_give_the_same_bytes_and_the_same_hashes() {
    for agent in agents() {
        let make = || all_inputs(&agent, |n| format!("same text for {n}\n<<<END name={n}>>>"));
        let a = assemble(&agent, make()).expect("ok");
        let b = assemble(&agent, make()).expect("ok");
        let c = assembler().assemble_any((&agent, make())).expect("ok");
        assert_eq!(a.text(), b.text());
        assert_eq!(a.sha256(), b.sha256());
        assert_eq!(a.manifest(), b.manifest());
        assert_eq!(a.manifest().sha256(), b.manifest().sha256());
        assert_eq!(a, c);
        let mut reversed = make();
        reversed.reverse();
        let d = assemble(&agent, reversed).expect("ok");
        assert_eq!(a, d);
    }
}

#[test]
fn prompts_provenance_the_fetch_time_is_in_the_record_and_never_in_the_prompt() {
    let agent = agent("intake-classifier");
    let with = |when: &str| {
        assemble(
            &agent,
            vec![input(&agent, "request", "text").fetched_at(at(when))],
        )
        .expect("ok")
    };
    let early = with("2026-10-27T10:00:00Z");
    let late = with("2026-10-28T11:30:00Z");
    assert_eq!(early.text(), late.text());
    assert_eq!(early.sha256(), late.sha256());
    assert_ne!(early.manifest().sha256(), late.manifest().sha256());
}

#[test]
fn prompts_provenance_the_manifest_hash_follows_every_part_of_the_record() {
    let agent = agent("intake-classifier");
    let base = |source: Source, text: &str| {
        assemble(
            &agent,
            vec![Input::untrusted(
                "request",
                ContentClass::IssueText,
                source,
                tenant(),
                text,
            )],
        )
        .expect("ok")
    };
    let a = base(Source::Issue { number: 1 }, "text");
    let b = base(Source::Issue { number: 2 }, "text");
    let c = base(Source::Issue { number: 1 }, "other text");
    assert_eq!(a.sha256(), b.sha256());
    assert_ne!(a.manifest().sha256(), b.manifest().sha256());
    assert_ne!(a.sha256(), c.sha256());
    assert_ne!(a.manifest().sha256(), c.manifest().sha256());
}

#[test]
fn prompts_provenance_the_manifest_in_json_holds_counts_and_hashes_and_no_text() {
    let agent = agent("intake-classifier");
    let assembled = assemble(
        &agent,
        vec![input(
            &agent,
            "request",
            "a secret-free sentence about pelicans\u{200B}",
        )],
    )
    .expect("ok");
    let json = assembled.manifest().to_json();
    let text = json.to_string();
    assert!(!text.contains("pelicans"));
    assert_eq!(json["agent"]["id"], "intake-classifier");
    assert_eq!(json["prompt"]["sha256"], assembled.sha256().as_str());
    assert_eq!(json["inputs"][0]["name"], "request");
    assert_eq!(json["inputs"][0]["stripped"], 1);
    assert_eq!(json["inputs"][0]["trust"], "untrusted");
    assert_eq!(json["signals"][0]["name"], "hidden_text_detected");
    assert_eq!(
        assembled.manifest().sha256(),
        Sha256Digest::of(text.as_bytes())
    );
}

#[test]
fn prompts_provenance_the_port_prompt_carries_the_whole_text_and_the_shape_is_documented() {
    let agent = agent("code-reviewer");
    let assembled = assemble(&agent, all_inputs(&agent, |n| format!("t {n}"))).expect("ok");
    let port = assembled.to_port_prompt();
    assert_eq!(port.instructions, assembled.text());
    assert!(port.data.is_empty());
    assert_eq!(names(&agent).len(), 3);
}

#[test]
fn prompts_provenance_debug_output_holds_no_text_of_any_input() {
    let agent = agent("intake-classifier");
    let secretish = "words-that-must-not-reach-a-log-4417";
    let given = input(&agent, "request", secretish);
    assert!(!format!("{given:?}").contains(secretish));
    let assembled = assemble(&agent, vec![given]).expect("ok");
    assert!(!format!("{assembled:?}").contains(secretish));
    assert!(!format!("{:?}", assembled.manifest()).contains(secretish));
    let independent = input(&agent, "request", secretish)
        .into_independent()
        .expect("independent");
    assert!(!format!("{independent:?}").contains(secretish));
}
