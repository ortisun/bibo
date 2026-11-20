//! The gate as the engine sees it: reports, outcomes, severity, schema, the manifest.

use std::collections::BTreeSet;

use factory_domain::contracts::gate_report::{BlockedCode, DefinitionSource, NotApplicableCode};
use factory_domain::contracts::{Contract, GateReport, ProjectManifest, StageContract};
use factory_domain::ids::{AttemptId, GateReportId, JobId, StageRunId};
use factory_domain::values::{GitSha, Timestamp};
use factory_domain::vocabulary::{ExecutionMode, GateOutcome};
use factory_workflow::gates::framework::{
    BlockCause, Expectation, Resolution, check_evidence, resolve,
};
use factory_workflow::gates::readability::{
    Artifact, Catalog, GATE_ID, MAX_TOTAL_BYTES, Options, RULES_JSON, ReadabilityGate,
    ReportContext, ReviewerPolicy, RuleId, Severity,
};
use serde_json::{Value, json};
use uuid::Uuid;

use super::readability_corpus::{FILES, samples, verdict_of};
use super::readability_schema_check::{SCHEMA, problems};

const MANIFEST_THAT_SWITCHES_OFF_THE_TAG: &str = include_str!(
    "../../../../schemas/examples/project-manifest/valid/word-count-conventional-commit-titles.json"
);
const MANIFEST_THAT_SWITCHES_OFF_A_BLOCKING_RULE: &str = include_str!(
    "../../../../schemas/examples/project-manifest/invalid/blocking-readability-rule-switched-off.json"
);
const STAGE_CONTRACT: &str =
    include_str!("../../../../schemas/examples/stage-contract/valid/specification-stage.json");

pub fn context(reviewer: ReviewerPolicy) -> ReportContext {
    ReportContext {
        gate_report_id: GateReportId::from_uuid(Uuid::from_u128(1)),
        job_id: JobId::from_uuid(Uuid::from_u128(2)),
        stage_run_id: StageRunId::from_uuid(Uuid::from_u128(3)),
        attempt_id: Some(AttemptId::from_uuid(Uuid::from_u128(4))),
        execution_mode: ExecutionMode::Test,
        definition_source: DefinitionSource::CentralConfig,
        definition_commit: GitSha::parse("1405df66cbe219b0bf6355bc3d60361a8376b6b4")
            .expect("a Git object id"),
        started_at: Timestamp::parse("2026-10-27T09:20:00Z").expect("a timestamp"),
        finished_at: Timestamp::parse("2026-10-27T09:20:01Z").expect("a timestamp"),
        reviewer,
    }
}

fn report_for(artifacts: &[Artifact<'_>]) -> GateReport {
    ReadabilityGate::new(Options::new())
        .evaluate(artifacts, &context(ReviewerPolicy::Optional))
        .expect("a report")
}

fn check_ids(report: &GateReport) -> (BTreeSet<String>, BTreeSet<String>) {
    let failed = report
        .failures
        .iter()
        .flatten()
        .map(|f| f.check_id.as_str().to_owned())
        .collect();
    let warned = report
        .warnings
        .iter()
        .flatten()
        .map(|w| w.check_id.as_str().to_owned())
        .collect();
    (failed, warned)
}

#[test]
fn readability_never_edits_and_separates_severity() {
    let catalog = Catalog::embedded().expect("the catalog loads");
    let gate = ReadabilityGate::new(Options::new());
    let ctx = context(ReviewerPolicy::Optional);
    let mut seen = [0_usize; 3];
    for sample in samples() {
        let (title, body) = (sample.title.clone(), sample.body.clone());
        let report = gate.evaluate(&[sample.artifact()], &ctx).expect("a report");
        // The text is the same, byte for byte.
        assert_eq!(sample.title, title, "{}", sample.id);
        assert_eq!(sample.body, body, "{}", sample.id);
        // Blocking findings are in `failures`, warnings in `warnings`, and nothing is in both.
        let (failed, warned) = check_ids(&report);
        assert!(failed.is_disjoint(&warned), "{}", sample.id);
        for id in &failed {
            let rule = RuleId::parse(id).expect("a rule of the gate");
            assert_eq!(catalog.severity(rule), Severity::Block, "{id}");
        }
        for id in &warned {
            let rule = RuleId::parse(id).expect("a rule of the gate");
            assert_eq!(catalog.severity(rule), Severity::Warn, "{id}");
        }
        // The outcome is the verdict of the deterministic findings.
        let expected: Vec<RuleId> = sample
            .breaks
            .iter()
            .filter_map(|id| RuleId::parse(id))
            .collect();
        let verdict = verdict_of(expected.iter().map(|rule| catalog.severity(*rule)));
        let expect_failed: BTreeSet<String> = expected
            .iter()
            .filter(|rule| catalog.severity(**rule) == Severity::Block)
            .map(|rule| rule.as_str().to_owned())
            .collect();
        assert_eq!(failed, expect_failed, "{}", sample.id);
        match verdict {
            "block" => {
                assert_eq!(report.outcome, GateOutcome::Failed, "{}", sample.id);
                seen[2] += 1;
            }
            other => {
                // A report with only warnings is PASSED with an empty failures list.
                assert_eq!(report.outcome, GateOutcome::Passed, "{}", sample.id);
                assert_eq!(report.failures.as_deref(), Some(&[][..]), "{}", sample.id);
                assert_eq!(warned.is_empty(), other == "pass", "{}", sample.id);
                seen[usize::from(other == "warn")] += 1;
            }
        }
    }
    assert!(
        seen.iter().all(|n| *n > 0),
        "all three verdicts occur: {seen:?}"
    );
}

#[test]
fn a_text_that_warns_and_blocks_reports_each_in_its_own_list() {
    // Blocks (identifier chain, pipe) and warns (all capitals).
    let report = report_for(&[Artifact::title("SF-FEAT-027 | FIN-VAL | AGT-QNT: DCF MOD")]);
    assert_eq!(report.outcome, GateOutcome::Failed);
    let (failed, warned) = check_ids(&report);
    assert_eq!(
        failed,
        BTreeSet::from([
            "title-opaque-prefix".to_owned(),
            "title-machine-label".to_owned()
        ])
    );
    assert_eq!(
        warned,
        BTreeSet::from(["title-not-sentence-case".to_owned()])
    );
    // Warnings carry a suggested fix and a location, failures a location.
    let warning = report
        .warnings
        .as_ref()
        .and_then(|w| w.first())
        .expect("a warning");
    assert!(!warning.suggested_fix.as_str().is_empty());
    assert_eq!(
        warning.location.as_ref().map(|l| l.path.as_str()),
        Some("title")
    );
}

#[test]
fn a_clean_text_passes_with_empty_lists_and_says_the_review_did_not_run() {
    let report = report_for(&[Artifact::title("Add password reset support")]);
    assert_eq!(report.outcome, GateOutcome::Passed);
    assert_eq!(check_ids(&report), (BTreeSet::new(), BTreeSet::new()));
    assert!(report.reason.as_str().contains("advisory language review"));
    assert!(report.reason.as_str().contains("did not run"));
}

#[test]
fn the_report_locates_findings_in_the_artifact_that_has_them() {
    let first = Artifact::task("Add password reset support", "Short body.").at("tasks/1");
    let second = Artifact::request("Fix stuff", "A sentence.").at("tasks/2");
    let report = report_for(&[first, second]);
    let failure = report
        .failures
        .as_ref()
        .and_then(|f| f.iter().find(|f| f.check_id.as_str() == "title-vague"))
        .expect("a title-vague failure");
    assert_eq!(
        failure.location.as_ref().map(|l| l.path.as_str()),
        Some("tasks/2/title")
    );
}

#[test]
fn a_gate_that_cannot_run_is_blocked_and_never_passed() {
    let ctx = context(ReviewerPolicy::Optional);
    let artifacts = [Artifact::title("Add password reset support")];

    // The rules failed to load.
    let broken = RULES_JSON.replacen("\"id\": \"title-vague\"", "\"id\": \"title-unheard\"", 1);
    let report = ReadabilityGate::with_catalog_text(&broken, Options::new())
        .evaluate(&artifacts, &ctx)
        .expect("a report");
    assert_eq!(report.outcome, GateOutcome::Blocked);
    assert_eq!(
        report.blocked_reason.as_ref().map(|r| r.code),
        Some(BlockedCode::PolicyUnresolvable)
    );
    assert!(report.warnings.as_ref().is_none_or(Vec::is_empty));

    // More text than the gate reads in one run.
    let huge = "a".repeat(MAX_TOTAL_BYTES + 1);
    let report = report_for(&[Artifact::request("Add password reset support", &huge)]);
    assert_eq!(report.outcome, GateOutcome::Blocked);
    assert_eq!(
        report.blocked_reason.as_ref().map(|r| r.code),
        Some(BlockedCode::EnvironmentUnsupported)
    );

    // The stage requires the advisory review, which this gate does not run.
    let report = ReadabilityGate::new(Options::new())
        .evaluate(&artifacts, &context(ReviewerPolicy::Required))
        .expect("a report");
    assert_eq!(report.outcome, GateOutcome::Blocked);
    assert_eq!(
        report.blocked_reason.as_ref().map(|r| r.code),
        Some(BlockedCode::ToolUnavailable)
    );
}

#[test]
fn nothing_to_check_is_not_applicable_and_never_passed() {
    let report = report_for(&[]);
    assert_eq!(report.outcome, GateOutcome::NotApplicable);
    assert_eq!(
        report.not_applicable_reason.as_ref().map(|r| r.code),
        Some(NotApplicableCode::NoMatchingFiles)
    );
}

#[test]
fn ids_are_stable_when_titles_change() {
    let (_, json) = FILES
        .iter()
        .find(|(name, _)| *name == "identity")
        .expect("the identity file");
    let doc: Value = serde_json::from_str(json).expect("JSON");
    let gate = ReadabilityGate::new(Options::new());
    let ctx = context(ReviewerPolicy::Optional);
    let mut pairs = 0;
    for case in doc["cases"].as_array().expect("cases") {
        pairs += 1;
        let metadata = case["input"]["metadata"].clone();
        let before = metadata.to_string();
        // The identifiers, as text a title could carry.
        let ids: Vec<String> = metadata
            .as_object()
            .expect("metadata")
            .values()
            .map(|v| v.as_str().map_or_else(|| format!("#{v}"), str::to_owned))
            .collect();
        let mut reports = Vec::new();
        for version in case["input"]["versions"].as_array().expect("versions") {
            let title = version["title"].as_str().expect("a title");
            let report = gate
                .evaluate(&[Artifact::title(title)], &ctx)
                .expect("a report");
            let embeds_an_id = ids.iter().any(|id| title.contains(id.as_str()));
            if embeds_an_id {
                // A title that carries an identifier is refused, so none is ever accepted.
                assert_eq!(report.outcome, GateOutcome::Failed, "{title}");
            }
            let label = version["verdict"].as_str().expect("a verdict");
            assert_eq!(
                report.outcome,
                if label == "block" {
                    GateOutcome::Failed
                } else {
                    GateOutcome::Passed
                },
                "{title}"
            );
            reports.push(report);
        }
        // Rewording the title changes the findings, never the identity of the report.
        assert!(
            reports
                .windows(2)
                .all(|pair| pair[0].metadata == pair[1].metadata),
            "the report metadata depends on the title"
        );
        // The metadata of the item went through untouched: the gate never receives it.
        assert_eq!(metadata.to_string(), before);
        // The last version is the one the author keeps, and it carries no identifier.
        let last = case["input"]["versions"]
            .as_array()
            .and_then(|v| v.last())
            .and_then(|v| v["title"].as_str())
            .expect("a last title");
        assert!(!ids.iter().any(|id| last.contains(id.as_str())), "{last}");
    }
    assert_eq!(pairs, 2);
}

#[test]
fn english_check_respects_quotes_and_code() {
    let gate = ReadabilityGate::new(Options::new());
    let portuguese = "O jogo deve salvar o progresso do jogador mesmo sem conexão";
    let flagged = |title: &str, body: &str| -> bool {
        gate.findings(&[Artifact::request(title, body)])
            .expect("findings")
            .iter()
            .any(|f| f.rule == RuleId::TextNotEnglish)
    };
    let title = "Save level progress without a connection";

    // Portuguese prose is flagged, in the body and in the title.
    assert!(flagged(title, &format!("{portuguese}.")));
    assert!(flagged(
        "O jogo deve salvar o progresso do jogador",
        "The game keeps the progress."
    ));
    // Mixed: one English and one Portuguese sentence.
    assert!(flagged(
        title,
        "The importer must reject files larger than 10 MB. O importador deve mostrar uma mensagem clara quando o arquivo for rejeitado."
    ));

    // Quoted source text is not flagged: double quotes, a block quotation, inline code, a fence.
    let english = "The label stays as the requester wrote it.";
    assert!(!flagged(
        title,
        &format!("{english} The text is \"{portuguese}\" in the source.")
    ));
    assert!(!flagged(title, &format!("{english}\n\n> {portuguese}.")));
    assert!(!flagged(
        title,
        &format!("{english} The text is `{portuguese}` in the source.")
    ));
    assert!(!flagged(
        title,
        &format!("{english}\n\n```\n{portuguese}.\n```\n")
    ));

    // A "quotation" of more than 300 characters is not a quotation, so it cannot hide prose.
    let long = format!("\"{}\"", format!("{portuguese}. ").repeat(6));
    assert!(long.chars().count() > 300);
    assert!(flagged(title, &format!("{english} {long}")));

    // English that mentions a Portuguese term is fine.
    assert!(!flagged(
        title,
        "Keep the names IPCA and Selic as they are, because they are the terms the finance team uses."
    ));
}

fn to_value(report: &GateReport) -> Value {
    serde_json::to_value(report).expect("a report is JSON")
}

#[test]
fn readability_reports_match_the_schema() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("the schema is JSON");

    // The checker has teeth: valid examples pass, invalid ones fail.
    let valid: Value = serde_json::from_str(include_str!(
        "../../../../schemas/examples/gate-report/valid/readability-passed-with-warnings.json"
    ))
    .expect("JSON");
    assert_eq!(problems(&schema, &valid), Vec::<String>::new());
    for invalid in [
        include_str!("../../../../schemas/examples/gate-report/invalid/passed-with-failures.json"),
        include_str!(
            "../../../../schemas/examples/gate-report/invalid/warning-with-a-severity-field.json"
        ),
        include_str!(
            "../../../../schemas/examples/gate-report/invalid/warning-without-suggested-fix.json"
        ),
        include_str!(
            "../../../../schemas/examples/gate-report/invalid/blocked-report-with-warnings.json"
        ),
        include_str!(
            "../../../../schemas/examples/gate-report/invalid/not-applicable-report-with-warnings.json"
        ),
    ] {
        let value: Value = serde_json::from_str(invalid).expect("JSON");
        assert!(!problems(&schema, &value).is_empty(), "{invalid}");
    }

    // Every report the gate makes, for every case of the corpus and for every kind of outcome.
    let gate = ReadabilityGate::new(Options::new());
    let mut reports = Vec::new();
    for sample in samples() {
        reports.push(
            gate.evaluate(&[sample.artifact()], &context(ReviewerPolicy::Optional))
                .expect("a report"),
        );
    }
    let huge = "a".repeat(MAX_TOTAL_BYTES + 1);
    let broken = RULES_JSON.replacen("\"id\": \"title-vague\"", "\"id\": \"title-unheard\"", 1);
    let title_only = [Artifact::title("Add password reset support")];
    reports.push(report_for(&[]));
    reports.push(report_for(&[Artifact::request(
        "Add password reset support",
        &huge,
    )]));
    reports.push(
        ReadabilityGate::with_catalog_text(&broken, Options::new())
            .evaluate(&title_only, &context(ReviewerPolicy::Optional))
            .expect("a report"),
    );
    reports.push(
        gate.evaluate(&title_only, &context(ReviewerPolicy::Required))
            .expect("a report"),
    );
    let mut outcomes = BTreeSet::new();
    for report in &reports {
        outcomes.insert(report.outcome.as_str());
        let value = to_value(report);
        assert_eq!(problems(&schema, &value), Vec::<String>::new(), "{value}");
        // The domain types hold the schema's patterns: the report reads back as the same value.
        let back = GateReport::from_json_value(value).expect("the report reads back");
        assert_eq!(&back, report);
    }
    assert_eq!(
        outcomes,
        BTreeSet::from(["PASSED", "FAILED", "BLOCKED", "NOT_APPLICABLE"])
    );
}

#[test]
fn readability_manifest_switches_off_only_warning_rules() {
    let gate_with = |options: Options, title: &str| -> BTreeSet<String> {
        ReadabilityGate::new(options)
            .findings(&[Artifact::title(title)])
            .expect("findings")
            .iter()
            .map(|f| f.rule.as_str().to_owned())
            .collect()
    };
    let tagged = "feat(auth): add OpenID Connect login";
    assert!(gate_with(Options::new(), tagged).contains("title-type-tag"));

    // The manifest of the repository lists title-type-tag.
    let manifest = ProjectManifest::from_json_str(MANIFEST_THAT_SWITCHES_OFF_THE_TAG)
        .expect("a valid manifest");
    let options = Options::from_manifest(&manifest);
    assert!(!gate_with(options.clone(), tagged).contains("title-type-tag"));

    // Nothing else is off: the other title rules still fire on the same switched-off options.
    let report = |title: &str| gate_with(options.clone(), title);
    assert!(report("[BUG] Login fails on slow networks").contains("title-opaque-prefix"));
    assert!(report("Fix stuff").contains("title-vague"));
    assert!(report("Add Password Reset Support").contains("title-not-sentence-case"));
    assert!(report("Add password reset support.").contains("title-trailing-punctuation"));

    // A manifest that lists a rule that blocks is refused before the gate sees it.
    assert!(ProjectManifest::from_json_str(MANIFEST_THAT_SWITCHES_OFF_A_BLOCKING_RULE).is_err());

    // The gate refuses it too: only title-type-tag is a valid name.
    assert!(Options::from_rule_ids(["title-type-tag"]).is_ok());
    let catalog = Catalog::embedded().expect("the catalog loads");
    for rule in RuleId::ALL {
        if *rule != RuleId::TitleTypeTag {
            assert!(
                Options::from_rule_ids([rule.as_str()]).is_err(),
                "{} must not be switchable",
                rule.as_str()
            );
        }
    }
    for reviewer in catalog.reviewer_rules() {
        assert!(Options::from_rule_ids([reviewer.id.as_str()]).is_err());
    }
    assert!(Options::from_rule_ids(["no-such-rule"]).is_err());
}

fn engine_contract() -> StageContract {
    let mut doc: Value = serde_json::from_str(STAGE_CONTRACT).expect("JSON");
    doc["evaluator"] = json!({ "kind": "deterministic_gate", "gate_ids": [GATE_ID] });
    StageContract::from_json_value(doc).expect("a valid contract")
}

#[test]
fn the_engine_accepts_the_report_and_reads_its_outcome() {
    let ctx = context(ReviewerPolicy::Optional);
    let expect = Expectation {
        job: ctx.job_id,
        stage_run: ctx.stage_run_id,
        attempt: ctx.attempt_id.expect("an attempt"),
        mode: ExecutionMode::Test,
    };
    let contract = engine_contract();
    let gate = ReadabilityGate::new(Options::new());
    let decide = |artifact: Artifact<'_>, ctx: &ReportContext| {
        let decision = gate.decide(&[artifact], ctx).expect("a decision");
        check_evidence(&decision, &expect).expect("the engine accepts the evidence");
        resolve(&contract, &decision)
    };

    // Warnings only: the stage passes.
    assert_eq!(
        decide(Artifact::title("Add Password Reset Support"), &ctx),
        Resolution::Pass
    );
    // A blocking finding: the gate failed.
    assert!(matches!(
        decide(Artifact::title("Fix stuff"), &ctx),
        Resolution::Failed { .. }
    ));
    // A gate that cannot run blocks the stage.
    assert_eq!(
        decide(
            Artifact::title("Add password reset support"),
            &context(ReviewerPolicy::Required)
        ),
        Resolution::Blocked(BlockCause::GateBlocked(
            factory_domain::values::Slug::parse(GATE_ID).expect("a slug")
        ))
    );
    // A report about another stage run is refused.
    let mut other = context(ReviewerPolicy::Optional);
    other.stage_run_id = StageRunId::from_uuid(Uuid::from_u128(99));
    let decision = gate
        .decide(&[Artifact::title("Add password reset support")], &other)
        .expect("a decision");
    assert!(check_evidence(&decision, &expect).is_err());
}
