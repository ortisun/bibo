use factory_domain::knowledge::{EntryKind, Status};
use factory_domain::metrics::{
    Comparison, Experiment, Improvement, Measured, Measurement, Metric, Outcome, SafeRange,
    Setting, Share, Window, Windows,
};
use factory_domain::values::{GitSha, Slug, Timestamp};

use super::*;

const DESIGN: &str = include_str!("../../../../docs/architecture/project-knowledge-base.md");

/// The example entry of the design document, between the fences that follow "## An entry".
fn documented_example() -> String {
    let section = &DESIGN[DESIGN.find("## An entry").expect("the section exists")..];
    let start = section.find("```markdown\n").expect("the example starts") + "```markdown\n".len();
    let end = section[start..].find("\n```").expect("the example ends");
    format!("{}\n", &section[start..start + end])
}

fn header_line(text: &str) -> Option<usize> {
    read_header(text).expect_err("refused").line
}

#[test]
fn the_example_of_the_design_document_is_read() {
    let header =
        read_header(&documented_example()).expect("the documented example is a valid entry");
    let entry = header.as_entry().expect("a person's entry");
    assert_eq!(entry.id.as_str(), "BR-0007");
    assert_eq!(entry.id.kind(), EntryKind::BusinessRule);
    assert_eq!(entry.status, Status::Active);
    assert_eq!(entry.links.len(), 2);
    assert_eq!(
        entry.last_verified.as_ref().map(GitSha::as_str),
        Some("3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d")
    );
}

#[test]
fn every_metric_entry_the_factory_renders_is_read_back() {
    for metric in Metric::ALL {
        let definition = metric.definition();
        let header = read_header(&definition.render_entry())
            .unwrap_or_else(|error| panic!("{}: {error}", definition.identifier()));
        assert_eq!(header.id().as_str(), definition.identifier());
        assert_eq!(header.title(), definition.title);
        assert_eq!(header.status(), Some(Status::Active));
    }
}

#[test]
fn a_measurement_entry_is_read_back() {
    let at = |text: &str| Timestamp::parse(text).expect("valid");
    for (from, to, id) in [
        ("2026-11-16T00:00:00Z", "2026-11-23T00:00:00Z", "M-2026-W47"),
        (
            "2026-11-16T00:00:00Z",
            "2026-12-16T00:00:00Z",
            "M-2026-11-16-to-2026-12-16",
        ),
    ] {
        let measurement = Measurement {
            window: Window::new(at(from), at(to)).expect("ordered"),
            query_version: 2,
            computed_at_commit: GitSha::parse(&"1".repeat(40)).expect("valid"),
            rows: vec![],
            stands_out: vec!["MT-0001 improved: a line with a colon".to_owned()],
        };
        let header =
            read_header(&measurement.render_entry().expect("renders")).expect("reads back");
        assert_eq!((header.id().as_str(), header.status()), (id, None));
    }
}

#[test]
fn an_improvement_entry_with_text_that_looks_like_yaml_is_read_back() {
    // `on` is a YAML 1.1 boolean, `4` an integer and the hypothesis holds `: ` and ` #`: each
    // would break an unquoted header.
    let tiers = [Slug::parse("large").expect("valid")];
    let range = SafeRange {
        parallel_tasks_limit: 8,
        evaluated_tiers: &tiers,
        reviewers: &[],
    };
    let experiment = Experiment::declare(
        Slug::parse("on").expect("valid"),
        Setting::ParallelTasks(2),
        Setting::ParallelTasks(4),
        Metric::LeadTimeToPullRequest,
        Share::DEFAULT,
        Windows::DEFAULT,
        &range,
    )
    .expect("valid experiment");
    let guards: Vec<Comparison> = experiment
        .kind()
        .guards()
        .iter()
        .map(|metric| Comparison {
            metric: *metric,
            difference: Measured::TooFewSamples {
                samples: 1,
                minimum: 20,
            },
        })
        .collect();
    let improvement = Improvement {
        number: 3,
        experiment: &experiment,
        hypothesis: "More tasks at once: shorter lead time # we hope \"so\"",
        target: Comparison {
            metric: Metric::LeadTimeToPullRequest,
            difference: Measured::TooFewSamples {
                samples: 1,
                minimum: 20,
            },
        },
        guards: &guards,
        outcome: Outcome::Promoted,
        decided_at: Timestamp::parse("2026-11-23T00:05:00Z").expect("valid"),
    };
    let header = read_header(&improvement.render_entry().expect("renders")).expect("reads back");
    assert_eq!(header.id().as_str(), "IM-0003");
    assert_eq!(
        header.title(),
        "More tasks at once: shorter lead time # we hope \"so\""
    );
}

#[test]
fn the_frame_of_the_header_is_checked() {
    assert_eq!(header_line("no header\n"), Some(1));
    assert_eq!(
        read_header("---\nid: T-0001\n").expect_err("open").line,
        None
    );
    assert!(
        read_header("---\r\nid: T-0001\r\n---\r\n")
            .expect_err("carriage return")
            .detail
            .contains("carriage return")
    );
    // The first line --- after the header closes it; a body may hold more.
    let text = "---\nid: T-0001\nkind: term\ntitle: Settlement date\nstatus: active\n---\n\nThe day.\n\n---\n";
    assert_eq!(read_header(text).expect("valid").id().as_str(), "T-0001");
}

#[test]
fn a_value_readers_disagree_on_is_refused_with_its_line() {
    let base = "---\nid: BR-0001\nkind: business-rule\ntitle: A rule\nstatus: active\nno_test_yet: checked by hand\n";
    // Line numbers count the opening ---, so the first field is on line 2.
    let with = |extra: &str| format!("{base}{extra}---\n");
    assert!(read_header(&with("")).is_ok());
    assert_eq!(
        header_line(&with(
            "recorded_from: { kind: person, by: me, date: 2026-11-20 }\n"
        )),
        Some(7)
    );
    assert_eq!(
        header_line(&with(
            "recorded_from: { kind: person, by: me, on: \"2026-11-20\" }\n"
        )),
        Some(7)
    );
    assert_eq!(
        header_line(&with(
            "last_verified: 1234567890123456789012345678901234567890\n"
        )),
        Some(7)
    );
    assert!(
        read_header(&with(
            "recorded_from: { kind: person, by: me, date: \"2026-11-20\" }\n"
        ))
        .is_ok()
    );
}

#[test]
fn an_unknown_field_and_a_broken_rule_name_their_line() {
    let text =
        "---\nid: BR-0001\nkind: business-rule\ntitle: A rule\nstatus: active\ncolour: blue\n---\n";
    let error = read_header(text).expect_err("unknown field");
    assert_eq!(error.line, Some(6), "{error}");
    let text = "---\nid: BR-0001\nkind: business-rule\ntitle: A rule\nstatus: active\nsources:\n  code: [src/a.rs, ../b.rs]\n---\n";
    let error = read_header(text).expect_err("a path outside the repository");
    assert_eq!(error.line, Some(7), "{error}");
    assert!(error.detail.starts_with("sources.code[1]: "), "{error}");
    let text = "---\nid: FL-0001\nkind: business-rule\ntitle: A rule\nstatus: active\n---\n";
    assert_eq!(
        read_header(text).expect_err("kind and prefix").line,
        Some(2)
    );
    let text = "---\nid: BR-0001\ntitle: A rule\nstatus: active\n---\n";
    assert!(
        read_header(text)
            .expect_err("no kind")
            .detail
            .starts_with("kind")
    );
}

#[test]
fn a_header_of_the_factory_is_read_into_its_own_closed_shape() {
    let metric = Metric::FirstPassGateSuccess.definition().render_entry();
    let with_extra = metric.replacen("status: active\n", "status: active\nowners: [me]\n", 1);
    assert!(
        read_header(&with_extra).is_err(),
        "a field of a person's entry is not one of a metric"
    );
    let text = "---\nid: M-2026-W47\nkind: measurement\ntitle: t\nwindow: { from: \"2026-11-16T00:00:00Z\", to: \"x\" }\nquery_version: 1\ncomputed_at_commit: \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n---\n";
    let error = read_header(text).expect_err("a window that is no instant");
    assert!(error.detail.starts_with("window.to"), "{error}");
    assert_eq!(error.line, Some(5));
}

#[test]
fn an_unreadable_file_is_a_finding_and_not_a_failure_of_the_whole_base() {
    let finding = read_file("terms/T-0001-a.md", "nothing").expect_err("unreadable");
    assert_eq!(
        finding,
        Finding::Unreadable {
            file: "terms/T-0001-a.md".to_owned(),
            detail: "line 1: an entry starts with a line ---, then its header".to_owned()
        }
    );
    let read = read_file(
        "measurements/M-2026-W47.md",
        &Measurement {
            window: Window::new(
                Timestamp::parse("2026-11-16T00:00:00Z").expect("valid"),
                Timestamp::parse("2026-11-23T00:00:00Z").expect("valid"),
            )
            .expect("ordered"),
            query_version: 1,
            computed_at_commit: GitSha::parse(&"a".repeat(40)).expect("valid"),
            rows: vec![],
            stands_out: vec![],
        }
        .render_entry()
        .expect("renders"),
    )
    .expect("reads");
    assert_eq!(read.file, "measurements/M-2026-W47.md");
}
