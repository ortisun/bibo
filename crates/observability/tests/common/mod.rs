//! Helpers shared by the integration tests. Not every test file uses every helper.
#![allow(dead_code)]

use std::collections::BTreeSet;

/// The conventions page. The tests compare its tables with the constants in the crate, so the
/// page and the code cannot drift apart without a test failing.
pub const CONVENTIONS: &str = include_str!("../../../../docs/observability/conventions.md");

/// The rows of the table between `<!-- table:NAME -->` and `<!-- /table:NAME -->`, header and
/// separator removed. Each cell is trimmed and loses the backticks around it.
pub fn table(page: &str, name: &str) -> Vec<Vec<String>> {
    let begin = format!("<!-- table:{name} -->");
    let end = format!("<!-- /table:{name} -->");
    let start = page
        .find(&begin)
        .unwrap_or_else(|| panic!("the conventions page has no marker {begin}"));
    let stop = page
        .find(&end)
        .unwrap_or_else(|| panic!("the conventions page has no marker {end}"));
    assert!(start < stop, "marker {end} comes before {begin}");
    page[start + begin.len()..stop]
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .skip(2) // header row and separator row
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().trim_matches('`').to_string())
                .collect()
        })
        .collect()
}

/// Split a cell such as "`a`, `b`" into its set of names.
pub fn names_in(cell: &str) -> BTreeSet<String> {
    cell.split(',')
        .map(|part| part.trim().trim_matches('`').to_string())
        .filter(|part| !part.is_empty() && part != "none")
        .collect()
}
