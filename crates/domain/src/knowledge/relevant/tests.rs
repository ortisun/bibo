use super::*;
use crate::knowledge::base::KnowledgeFile;
use crate::knowledge::entry::{Entry, Header, RawEntry, RawSources};

fn entry(id: &str, kind: &str, status: &str, edit: impl FnOnce(&mut RawEntry)) -> KnowledgeFile {
    let mut raw = RawEntry {
        id: id.to_owned(),
        kind: kind.to_owned(),
        title: format!("Entry {id}"),
        status: status.to_owned(),
        owners: vec![],
        sources: RawSources::default(),
        no_test_yet: (kind == "business-rule").then(|| "none".to_owned()),
        links: vec![],
        last_verified: None,
        supersedes: vec![],
        recorded_from: None,
    };
    edit(&mut raw);
    KnowledgeFile {
        file: format!("x/{id}-a.md"),
        header: Header::Entry(Box::new(Entry::check(&raw).expect("valid"))),
    }
}

fn paths(texts: &[&str]) -> Vec<RepoPath> {
    texts
        .iter()
        .map(|text| RepoPath::parse(text).expect("valid"))
        .collect()
}

fn ids(list: &[EntryId]) -> Vec<&str> {
    list.iter().map(EntryId::as_str).collect()
}

fn base() -> KnowledgeBase {
    KnowledgeBase::new(vec![
        entry("BR-0007", "business-rule", "active", |raw| {
            raw.sources.code = vec!["src/refunds/".to_owned()];
            raw.links = vec![
                "FL-0003".to_owned(),
                "T-0012".to_owned(),
                "C-0001".to_owned(),
            ];
        }),
        entry("FL-0003", "flow", "active", |raw| {
            raw.links = vec!["I-0002".to_owned()]
        }),
        entry("T-0012", "term", "active", |raw| {
            raw.title = "Settlement date".to_owned()
        }),
        entry("C-0001", "constraint", "retired", |_| {}),
        entry("I-0002", "integration", "active", |_| {}),
        entry("F-0001", "feature", "proposed", |raw| {
            raw.sources.specifications = vec!["specs/001/spec.md".to_owned()]
        }),
        entry("F-0002", "feature", "retired", |raw| {
            raw.sources.specifications = vec!["specs/001/spec.md".to_owned()]
        }),
    ])
}

#[test]
fn nothing_matches_an_empty_request() {
    assert_eq!(
        base().relevant(RelevanceRequest {
            specifications: &[],
            owned_paths: &[],
            terms: &[]
        }),
        Relevance::default()
    );
}

#[test]
fn an_owned_path_selects_its_entry_and_one_link_out() {
    for owned in [
        &["src/refunds/approval.rs"][..],
        &["src/"],
        &["src/refunds/"],
    ] {
        let relevance = base().relevant(RelevanceRequest {
            specifications: &[],
            owned_paths: &paths(owned),
            terms: &[],
        });
        assert_eq!(ids(&relevance.direct), ["BR-0007"], "{owned:?}");
        // One link out: the flow and the term, not the retired constraint, not the flow's own link.
        assert_eq!(ids(&relevance.linked), ["FL-0003", "T-0012"], "{owned:?}");
    }
    let unrelated = base().relevant(RelevanceRequest {
        specifications: &[],
        owned_paths: &paths(&["src/refundsx.rs"]),
        terms: &[],
    });
    assert_eq!(unrelated, Relevance::default());
}

#[test]
fn a_specification_and_a_term_select_entries_and_a_retired_one_never() {
    let terms = ["  SETTLEMENT date ".to_owned(), String::new()];
    let relevance = base().relevant(RelevanceRequest {
        specifications: &paths(&["specs/001/spec.md"]),
        owned_paths: &[],
        terms: &terms,
    });
    assert_eq!(ids(&relevance.direct), ["F-0001", "T-0012"]);
    assert!(relevance.linked.is_empty());
}

#[test]
fn an_entry_named_directly_is_not_also_counted_as_linked() {
    let terms = ["settlement date".to_owned()];
    let relevance = base().relevant(RelevanceRequest {
        specifications: &[],
        owned_paths: &paths(&["src/refunds/a.rs"]),
        terms: &terms,
    });
    assert_eq!(ids(&relevance.direct), ["BR-0007", "T-0012"]);
    assert_eq!(ids(&relevance.linked), ["FL-0003"]);
}
