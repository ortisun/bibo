use std::collections::BTreeSet;

use super::*;
use crate::knowledge::entry::{Entry, FactoryEntry, RawEntry, RawSources};

fn entry(id: &str, kind: &str, status: &str, edit: impl FnOnce(&mut RawEntry)) -> Header {
    let mut raw = RawEntry {
        id: id.to_owned(),
        kind: kind.to_owned(),
        title: format!("The entry {id}"),
        status: status.to_owned(),
        owners: vec![],
        sources: RawSources::default(),
        no_test_yet: None,
        links: vec![],
        last_verified: None,
        supersedes: vec![],
        recorded_from: None,
    };
    edit(&mut raw);
    Header::Entry(Box::new(Entry::check(&raw).expect("a valid header")))
}

fn file(file: &str, header: Header) -> KnowledgeFile {
    KnowledgeFile {
        file: file.to_owned(),
        header,
    }
}

fn set(paths: &[&str]) -> BTreeSet<String> {
    paths.iter().map(|path| (*path).to_owned()).collect()
}

/// A small, correct knowledge base: a rule with its test, the flow and the term it links to, and
/// a measurement of the factory.
fn base() -> KnowledgeBase {
    KnowledgeBase::new(vec![
        file(
            "business-rules/BR-0007-refund-needs-second-approval.md",
            entry("BR-0007", "business-rule", "active", |raw| {
                raw.sources.code = vec!["src/refunds/".to_owned()];
                raw.sources.tests = vec!["tests/refunds.rs::refund_above_limit".to_owned()];
                raw.links = vec!["FL-0003".to_owned(), "T-0012".to_owned()];
            }),
        ),
        file(
            "flows/FL-0003-refund.md",
            entry("FL-0003", "flow", "active", |raw| {
                raw.sources.code = vec!["src/refunds/flow.rs".to_owned()];
            }),
        ),
        file(
            "terms/T-0012-settlement-date.md",
            entry("T-0012", "term", "active", |raw| {
                raw.title = "Settlement date".to_owned()
            }),
        ),
        file(
            "measurements/M-2026-W47.md",
            Header::Factory(
                FactoryEntry::check(
                    "M-2026-W47",
                    "measurement",
                    "Process numbers, week 47 of 2026",
                    None,
                )
                .expect("valid"),
            ),
        ),
    ])
}

fn head() -> BTreeSet<String> {
    set(&[
        "src/refunds/approval.rs",
        "src/refunds/flow.rs",
        "tests/refunds.rs",
    ])
}

#[test]
fn a_correct_knowledge_base_has_no_finding() {
    let base = base();
    let index = base.render_index();
    let (head, changed) = (head(), set(&[]));
    assert_eq!(
        base.check(
            Some(&index),
            Change {
                head_paths: &head,
                changed_paths: &changed
            }
        ),
        []
    );
}

#[test]
fn the_index_lists_each_kind_in_order_and_each_entry_once() {
    assert_eq!(
        base().render_index(),
        "# Knowledge base\n\n\
         Every entry of the knowledge base, by kind. The factory writes this file from the entries, \
         and its documentation gate reports a line that is missing or out of date.\n\
         \n## Flows\n\n| Identifier | Title | Status |\n|---|---|---|\n\
         | [FL-0003](flows/FL-0003-refund.md) | The entry FL-0003 | active |\n\
         \n## Business rules\n\n| Identifier | Title | Status |\n|---|---|---|\n\
         | [BR-0007](business-rules/BR-0007-refund-needs-second-approval.md) | The entry BR-0007 | active |\n\
         \n## Terms\n\n| Identifier | Title | Status |\n|---|---|---|\n\
         | [T-0012](terms/T-0012-settlement-date.md) | Settlement date | active |\n\
         \n## Measurements\n\n| Identifier | Title | Status |\n|---|---|---|\n\
         | [M-2026-W47](measurements/M-2026-W47.md) | Process numbers, week 47 of 2026 | recorded |\n"
    );
    assert_eq!(KnowledgeBase::new(vec![]).render_index().lines().count(), 3);
}

#[test]
fn a_title_cannot_break_the_table_of_the_index() {
    let base = KnowledgeBase::new(vec![file(
        "terms/T-0001-a.md",
        entry("T-0001", "term", "proposed", |raw| {
            raw.title = "a | b".to_owned()
        }),
    )]);
    assert!(
        base.render_index()
            .contains("| [T-0001](terms/T-0001-a.md) | a \\| b | proposed |\n")
    );
}

#[test]
fn the_index_reports_the_exact_line_to_add_and_the_line_for_nothing() {
    let base = base();
    assert_eq!(base.check_index(None), [Finding::IndexMissing]);
    let index = base.render_index();
    let without = index.replace(
        "| [FL-0003](flows/FL-0003-refund.md) | The entry FL-0003 | active |\n",
        "",
    );
    assert_eq!(
        base.check_index(Some(&without)),
        [Finding::IndexLineMissing {
            line: "| [FL-0003](flows/FL-0003-refund.md) | The entry FL-0003 | active |".to_owned()
        }]
    );
    let extra = format!("{index}| [F-0001](features/F-0001-gone.md) | Gone | active |   \n");
    assert_eq!(
        base.check_index(Some(&extra)),
        [Finding::IndexLineUnknown {
            line: "| [F-0001](features/F-0001-gone.md) | Gone | active |".to_owned()
        }]
    );
    // A line whose status is out of date is both: the line to add, and the line for nothing.
    let stale = index.replace(
        "| Settlement date | active |",
        "| Settlement date | proposed |",
    );
    assert_eq!(base.check_index(Some(&stale)).len(), 2);
}

#[test]
fn a_file_lives_in_the_directory_of_its_kind_and_is_named_after_its_identifier() {
    let rule = |path: &str| file(path, entry("BR-0001", "business-rule", "proposed", |_| {}));
    let cases = [
        ("business-rules/BR-0001-a.md", None),
        ("business-rules/BR-0001-a.b_c-d.md", None),
        ("flows/BR-0001-a.md", Some("outside")),
        ("business-rules/deep/BR-0001-a.md", Some("outside")),
        ("BR-0001-a.md", Some("outside")),
        ("business-rules/BR-0002-a.md", Some("named")),
        ("business-rules/BR-0001.md", Some("named")),
        ("business-rules/BR-0001-.md", Some("named")),
        ("business-rules/BR-0001-A.md", Some("named")),
        ("business-rules/BR-0001-a.txt", Some("named")),
        ("business-rules/BR-00012-a.md", Some("named")),
    ];
    for (path, expected) in cases {
        let found = KnowledgeBase::new(vec![rule(path)]).well_formed();
        let kind = found.first().map(|finding| match finding {
            Finding::FileOutsideItsDirectory { .. } => "outside",
            Finding::FileNotNamedAfterItsIdentifier { .. } => "named",
            other => panic!("{other:?}"),
        });
        assert_eq!(kind, expected, "{path}");
    }
    let week = |path: &str| {
        KnowledgeBase::new(vec![file(
            path,
            Header::Factory(
                FactoryEntry::check("M-2026-W47", "measurement", "t", None).expect("valid"),
            ),
        )])
        .well_formed()
    };
    assert_eq!(week("measurements/M-2026-W47.md"), []);
    assert_eq!(week("measurements/M-2026-W47-x.md").len(), 1);
}

#[test]
fn an_identifier_is_used_once_and_every_link_resolves() {
    let twice = KnowledgeBase::new(vec![
        file(
            "terms/T-0001-b.md",
            entry("T-0001", "term", "active", |_| {}),
        ),
        file(
            "terms/T-0001-a.md",
            entry("T-0001", "term", "active", |_| {}),
        ),
        file(
            "flows/FL-0001-a.md",
            entry("FL-0001", "flow", "active", |raw| {
                raw.links = vec!["T-0001".to_owned(), "T-0002".to_owned()];
                raw.supersedes = vec!["FL-0009".to_owned()];
            }),
        ),
    ]);
    assert_eq!(
        twice.well_formed(),
        [
            Finding::DuplicateIdentifier {
                entry: EntryId::parse("T-0001").expect("valid"),
                files: vec![
                    "terms/T-0001-a.md".to_owned(),
                    "terms/T-0001-b.md".to_owned()
                ],
            },
            Finding::UnknownEntry {
                entry: EntryId::parse("FL-0001").expect("valid"),
                field: "links",
                named: EntryId::parse("T-0002").expect("valid"),
            },
            Finding::UnknownEntry {
                entry: EntryId::parse("FL-0001").expect("valid"),
                field: "supersedes",
                named: EntryId::parse("FL-0009").expect("valid"),
            },
        ]
    );
    // The duplicate counts once in the index.
    assert_eq!(twice.render_index().matches("[T-0001]").count(), 1);
}

#[test]
fn a_missing_source_is_found_and_a_directory_exists_when_a_file_is_under_it() {
    let base = base();
    let (changed, empty) = (set(&[]), set(&["src/refunds/flow.rs"]));
    let found = base.check_change(Change {
        head_paths: &empty,
        changed_paths: &changed,
    });
    assert_eq!(
        found,
        [Finding::MissingSource {
            entry: EntryId::parse("BR-0007").expect("valid"),
            field: "sources.tests[0]".to_owned(),
            path: "tests/refunds.rs".to_owned(),
        }],
        "the directory src/refunds/ exists through src/refunds/flow.rs"
    );
    let nothing = set(&[]);
    assert_eq!(
        base.check_change(Change {
            head_paths: &nothing,
            changed_paths: &changed
        })
        .len(),
        3
    );
}

#[test]
fn an_active_rule_needs_a_test_or_a_reason_and_a_proposed_one_does_not() {
    let rule = |status: &str, edit: fn(&mut RawEntry)| {
        KnowledgeBase::new(vec![file(
            "business-rules/BR-0001-a.md",
            entry("BR-0001", "business-rule", status, edit),
        )])
    };
    let (head, changed) = (set(&[]), set(&[]));
    let change = Change {
        head_paths: &head,
        changed_paths: &changed,
    };
    assert_eq!(
        rule("active", |_| {}).check_change(change),
        [Finding::RuleWithoutTest {
            entry: EntryId::parse("BR-0001").expect("valid")
        }]
    );
    assert_eq!(
        rule("active", |raw| raw.no_test_yet =
            Some("checked by hand".to_owned()))
        .check_change(change),
        []
    );
    assert_eq!(rule("proposed", |_| {}).check_change(change), []);
    assert_eq!(
        rule("retired", |raw| raw.sources.code =
            vec!["gone.rs".to_owned()])
        .check_change(change),
        []
    );
    // A flow needs no test.
    let flow = KnowledgeBase::new(vec![file(
        "flows/FL-0001-a.md",
        entry("FL-0001", "flow", "active", |_| {}),
    )]);
    assert_eq!(flow.check_change(change), []);
}

#[test]
fn touched_code_must_be_confirmed_in_the_same_change() {
    let base = base();
    let head = head();
    let check = |changed: &[&str]| {
        let changed = set(changed);
        base.check_change(Change {
            head_paths: &head,
            changed_paths: &changed,
        })
    };
    let unconfirmed = |id: &str, path: &str| Finding::Unconfirmed {
        entry: EntryId::parse(id).expect("valid"),
        path: path.to_owned(),
    };

    assert_eq!(check(&["README.md", "src/other.rs"]), []);
    // A file under the rule's directory touches the rule; the flow's own file touches both.
    assert_eq!(
        check(&["src/refunds/approval.rs"]),
        [unconfirmed("BR-0007", "src/refunds/approval.rs")]
    );
    assert_eq!(
        check(&["src/refunds/flow.rs"]),
        [
            unconfirmed("BR-0007", "src/refunds/flow.rs"),
            unconfirmed("FL-0003", "src/refunds/flow.rs")
        ]
    );
    // Changing the entry's own file confirms it, and only it.
    assert_eq!(
        check(&[
            "src/refunds/flow.rs",
            "docs/knowledge/flows/FL-0003-refund.md"
        ]),
        [unconfirmed("BR-0007", "src/refunds/flow.rs")]
    );
    // The first changed path of its code is named, in path order.
    assert_eq!(
        check(&["src/refunds/z.rs", "src/refunds/a.rs"]),
        [unconfirmed("BR-0007", "src/refunds/a.rs")]
    );
    // A file with a similar name is not under the directory.
    assert_eq!(check(&["src/refunds-old/a.rs"]), []);
}

#[test]
fn the_same_input_gives_the_same_sorted_findings() {
    let broken = KnowledgeBase::new(vec![
        file(
            "terms/T-0001-a.md",
            entry("T-0001", "term", "active", |raw| {
                raw.links = vec!["F-0009".to_owned()]
            }),
        ),
        file(
            "flows/T-0002-a.md",
            entry("T-0002", "term", "active", |raw| {
                raw.sources.code = vec!["x.rs".to_owned()]
            }),
        ),
    ]);
    let (head, changed) = (set(&[]), set(&["x.rs"]));
    let change = Change {
        head_paths: &head,
        changed_paths: &changed,
    };
    let first = broken.check(None, change);
    assert_eq!(first, broken.check(None, change));
    let mut sorted = first.clone();
    sorted.sort();
    assert_eq!(first, sorted);
    assert_eq!(first.len(), 5, "{first:#?}");
    assert!(first.iter().all(|finding| !finding.to_string().is_empty()));
}
