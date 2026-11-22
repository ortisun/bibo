use super::*;

/// A raw business rule that passes every rule.
pub(crate) fn raw_rule() -> RawEntry {
    RawEntry {
        id: "BR-0007".to_owned(),
        kind: "business-rule".to_owned(),
        title: "A refund above the limit needs a second approval".to_owned(),
        status: "active".to_owned(),
        owners: vec!["payments-team".to_owned()],
        sources: RawSources {
            specifications: vec!["docs/specifications/012-refunds.md".to_owned()],
            code: vec!["src/refunds/approval.rs".to_owned()],
            tests: vec![
                "tests/refunds_approval.rs::refund_above_limit_waits_for_a_second_approver"
                    .to_owned(),
            ],
            decisions: vec!["docs/adr/0004-refund-limits.md".to_owned()],
        },
        no_test_yet: None,
        links: vec!["FL-0003".to_owned(), "T-0012".to_owned()],
        last_verified: Some("3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d".to_owned()),
        supersedes: vec![],
        recorded_from: Some(RawRecordedFrom {
            kind: "specification".to_owned(),
            by: "@maintainer".to_owned(),
            date: "2026-11-20".to_owned(),
        }),
    }
}

fn refused(raw: &RawEntry) -> String {
    Entry::check(raw)
        .expect_err("the header breaks a rule")
        .field
}

#[test]
fn the_example_of_the_design_document_is_an_entry() {
    let entry = Entry::check(&raw_rule()).expect("valid");
    assert_eq!(entry.id.as_str(), "BR-0007");
    assert_eq!(entry.status, Status::Active);
    assert_eq!(
        entry.sources.tests[0].path.as_str(),
        "tests/refunds_approval.rs"
    );
    assert_eq!(
        entry.sources.tests[0].name.as_deref(),
        Some("refund_above_limit_waits_for_a_second_approver")
    );
    let from = entry.recorded_from.clone().expect("recorded");
    assert_eq!(
        (from.kind, from.date.to_string()),
        (RecordedFromKind::Specification, "2026-11-20".to_owned())
    );
    let named: Vec<String> = entry
        .named_entries()
        .map(|(field, id)| format!("{field}:{id}"))
        .collect();
    assert_eq!(named, ["links:FL-0003", "links:T-0012"]);
}

#[test]
fn the_kind_and_the_identifier_must_agree() {
    let mut raw = raw_rule();
    raw.kind = "flow".to_owned();
    assert_eq!(refused(&raw), "id");
    raw.kind = "rule".to_owned();
    assert_eq!(refused(&raw), "kind");
    for factory in ["metric", "measurement", "improvement"] {
        raw.kind = factory.to_owned();
        assert_eq!(refused(&raw), "kind", "{factory}");
    }
    let mut raw = raw_rule();
    raw.id = "BR-7".to_owned();
    assert_eq!(refused(&raw), "id");
}

#[test]
fn a_title_is_one_line_of_at_most_200_characters() {
    let mut raw = raw_rule();
    raw.title = "é".repeat(200);
    assert!(Entry::check(&raw).is_ok());
    raw.title = "é".repeat(201);
    assert_eq!(refused(&raw), "title");
    for title in ["", "   ", "two\nlines", "tab\there"] {
        raw.title = title.to_owned();
        assert_eq!(refused(&raw), "title", "{title:?}");
    }
    raw.title = "  trimmed  ".to_owned();
    assert_eq!(Entry::check(&raw).expect("valid").title, "trimmed");
}

#[test]
fn a_path_is_relative_and_has_no_empty_or_dot_part() {
    for path in ["src/a.rs", "src/", "a", "docs/adr/0004.md"] {
        assert!(RepoPath::parse(path).is_ok(), "{path}");
    }
    for path in [
        "",
        "/etc/passwd",
        "../outside",
        "src/../x",
        "src/./x",
        "src//x",
        "src\\x",
        "./x",
        "a\u{0}b",
        "/",
    ] {
        assert!(RepoPath::parse(path).is_err(), "{path:?}");
    }
    assert!(RepoPath::parse(&"a".repeat(1024)).is_ok());
    assert!(RepoPath::parse(&"a".repeat(1025)).is_err());
    let mut raw = raw_rule();
    raw.sources.code.push("../secrets".to_owned());
    assert_eq!(refused(&raw), "sources.code[1]");
    let mut raw = raw_rule();
    raw.sources.tests = vec!["tests/a.rs::".to_owned()];
    assert_eq!(refused(&raw), "sources.tests[0]");
    raw.sources.tests = vec!["tests/a.rs::two words".to_owned()];
    assert_eq!(refused(&raw), "sources.tests[0]");
    raw.sources.tests = vec!["tests/a.rs".to_owned()];
    assert!(Entry::check(&raw).is_ok());
}

#[test]
fn a_directory_covers_the_paths_under_it_and_a_file_only_itself() {
    let dir = RepoPath::parse("src/refunds/").expect("valid");
    let file = RepoPath::parse("src/refunds/approval.rs").expect("valid");
    assert!(dir.covers("src/refunds/approval.rs"));
    assert!(dir.covers("src/refunds/deep/x.rs"));
    assert!(!dir.covers("src/refundsx/a.rs"));
    assert!(!dir.covers("src/refunds"));
    assert!(file.covers("src/refunds/approval.rs"));
    assert!(!file.covers("src/refunds/approval.rs.bak"));
    assert!(dir.overlaps(&file) && file.overlaps(&dir));
    assert!(!file.overlaps(&RepoPath::parse("src/other.rs").expect("valid")));
}

#[test]
fn only_a_business_rule_without_a_test_says_why() {
    let mut raw = raw_rule();
    raw.no_test_yet =
        Some("the limit is checked by hand until the payment test rig exists".to_owned());
    assert_eq!(refused(&raw), "no_test_yet"); // it names a test too
    raw.sources.tests.clear();
    assert!(Entry::check(&raw).expect("valid").no_test_yet.is_some());
    raw.no_test_yet = Some(" ".to_owned());
    assert_eq!(refused(&raw), "no_test_yet");
    let mut flow = raw_rule();
    flow.id = "FL-0003".to_owned();
    flow.kind = "flow".to_owned();
    flow.links.clear();
    flow.sources.tests.clear();
    flow.no_test_yet = Some("no test".to_owned());
    assert_eq!(refused(&flow), "no_test_yet");
}

#[test]
fn links_and_replacements_are_valid_named_once_and_never_the_entry_itself() {
    let mut raw = raw_rule();
    raw.links = vec!["FL-0003".to_owned(), "FL-0003".to_owned()];
    assert_eq!(refused(&raw), "links[1]");
    raw.links = vec!["FL-3".to_owned()];
    assert_eq!(refused(&raw), "links[0]");
    raw.links = vec!["BR-0007".to_owned()];
    assert_eq!(refused(&raw), "links");
    raw.links = vec![];
    raw.supersedes = vec!["BR-0007".to_owned()];
    assert_eq!(refused(&raw), "supersedes");
    raw.supersedes = vec!["BR-0001".to_owned(), "M-2026-W47".to_owned()];
    assert!(Entry::check(&raw).is_ok());
}

#[test]
fn the_last_confirmation_is_a_full_commit_id() {
    let mut raw = raw_rule();
    for text in [
        "3f2a9c1",
        "3F2A9C1D5E7B9A1C3E5F7A9B1C3D5E7F9A1B3C5D",
        "",
        "g".repeat(40).as_str(),
    ] {
        raw.last_verified = Some(text.to_owned());
        assert_eq!(refused(&raw), "last_verified", "{text:?}");
    }
    raw.last_verified = Some("a".repeat(64));
    assert!(Entry::check(&raw).is_ok());
    raw.last_verified = None;
    assert!(Entry::check(&raw).is_ok());
}

#[test]
fn the_date_of_a_source_exists_in_the_calendar() {
    let mut raw = raw_rule();
    let at = |raw: &mut RawEntry, date: &str| {
        raw.recorded_from.as_mut().expect("recorded").date = date.to_owned();
    };
    for date in [
        "2024-02-29",
        "2026-01-01",
        "2026-12-31",
        "0001-01-01",
        "9999-12-31",
    ] {
        at(&mut raw, date);
        assert!(Entry::check(&raw).is_ok(), "{date}");
    }
    for date in [
        "2026-02-29",
        "2026-13-01",
        "2026-00-10",
        "2026-04-31",
        "2026-1-01",
        "26-01-01",
        "2026/01/01",
        "2026-01-01T00:00:00Z",
        "+026-01-01",
        "2026-0a-01",
    ] {
        at(&mut raw, date);
        assert_eq!(refused(&raw), "recorded_from.date", "{date}");
    }
    let mut raw = raw_rule();
    raw.recorded_from.as_mut().expect("recorded").kind = "chat".to_owned();
    assert_eq!(refused(&raw), "recorded_from.kind");
}

#[test]
fn a_header_of_the_factory_holds_its_three_fields() {
    let metric = FactoryEntry::check(
        "MT-0006",
        "metric",
        "First-pass gate success",
        Some("active"),
    )
    .expect("valid");
    assert_eq!(metric.status, Some(Status::Active));
    let week = FactoryEntry::check(
        "M-2026-W47",
        "measurement",
        "Process numbers, week 47 of 2026",
        None,
    )
    .expect("valid");
    assert_eq!(week.status, None);
    assert_eq!(
        FactoryEntry::check("M-2026-W47", "measurement", "t", Some("active"))
            .expect_err("no status")
            .field,
        "status"
    );
    assert_eq!(
        FactoryEntry::check("IM-0001", "improvement", "t", None)
            .expect_err("a status")
            .field,
        "status"
    );
    assert_eq!(
        FactoryEntry::check("BR-0001", "business-rule", "t", Some("active"))
            .expect_err("a person's kind")
            .field,
        "kind"
    );
    assert_eq!(
        FactoryEntry::check("MT-0001", "improvement", "t", Some("active"))
            .expect_err("mismatch")
            .field,
        "id"
    );
}
