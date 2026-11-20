//! ST-07 across the whole repository: every span name, attribute key and metric that a crate
//! writes in a `tracing` call is in the tables of `docs/observability/conventions.md`.
//!
//! The crates that may only depend on `tracing` cannot import the name constants of the
//! `observability` crate, so they write the names as string literals (ADR 0013, decision 1). This
//! scan reads those literals from the token stream and compares them with the tables, which the
//! observability tests parse from the same markers. It checks:
//!
//! * the name of a span (`span!` and its level macros, and `#[instrument(name = "...")]`),
//! * every field written with the `factory.` prefix, and `error.type`, in a tracing macro,
//! * every metric field (`monotonic_counter.`, `histogram.`, `gauge.`) against the metric's kind,
//!   and every other field of that event against the metric's labels,
//! * every string literal anywhere that looks like a factory name (`factory.x` or `factory_x`).
//!
//! It reads text, so a name built at run time is not seen, and it does not know which span a
//! field belongs to. The trace tests of `s1-observability-instrumentation` cover that side.

use crate::finding::Finding;
use crate::scan::Source;
use crate::syntax::{Kind, Syntax};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metric {
    /// `counter`, `histogram` or `gauge`, as the table writes it.
    pub kind: String,
    pub labels: BTreeSet<String>,
}

/// The tables of the conventions page.
#[derive(Debug, Clone, Default)]
pub struct Conventions {
    pub spans: BTreeSet<String>,
    pub attributes: BTreeSet<String>,
    pub metrics: BTreeMap<String, Metric>,
    pub labels: BTreeSet<String>,
}

impl Conventions {
    /// Read the tables between `<!-- table:NAME -->` and `<!-- /table:NAME -->`.
    pub fn parse(page: &str) -> Result<Self, String> {
        let rows = |name: &str| -> Result<Vec<Vec<String>>, String> {
            let open = format!("<!-- table:{name} -->");
            let close = format!("<!-- /table:{name} -->");
            let start = page
                .find(&open)
                .ok_or_else(|| format!("the conventions page has no `{open}` marker"))?
                + open.len();
            let end = page[start..]
                .find(&close)
                .ok_or_else(|| format!("the conventions page has no `{close}` marker"))?
                + start;
            Ok(page[start..end]
                .lines()
                .map(str::trim)
                .filter(|l| l.starts_with('|'))
                .skip(2) // the header and the separator
                .map(|l| {
                    l.trim_matches('|')
                        .split('|')
                        .map(|cell| cell.trim().to_string())
                        .collect()
                })
                .collect())
        };
        let first = |row: &[String]| row.first().map(|c| c.trim_matches('`').to_string());
        let mut conventions = Self::default();
        for row in rows("spans")? {
            conventions.spans.extend(first(&row));
        }
        for row in rows("attributes")? {
            conventions.attributes.extend(first(&row));
        }
        for row in rows("labels")? {
            conventions.labels.extend(first(&row));
        }
        for row in rows("metrics")? {
            let (Some(name), Some(kind), Some(labels)) = (first(&row), row.get(1), row.get(3))
            else {
                return Err("a row of the metrics table has fewer than four cells".to_string());
            };
            conventions.metrics.insert(
                name,
                Metric {
                    kind: kind.trim_matches('`').to_string(),
                    labels: labels
                        .split(',')
                        .map(|l| l.trim().trim_matches('`').to_string())
                        .filter(|l| !l.is_empty())
                        .collect(),
                },
            );
        }
        if conventions.spans.is_empty() || conventions.metrics.is_empty() {
            return Err("the span or metric table of the conventions page is empty".to_string());
        }
        Ok(conventions)
    }
}

const SPAN_MACROS: [&str; 6] = [
    "span",
    "trace_span",
    "debug_span",
    "info_span",
    "warn_span",
    "error_span",
];
const EVENT_MACROS: [&str; 6] = ["event", "trace", "debug", "info", "warn", "error"];
/// The instrument prefixes of a metric field, and the kind each stands for in the metric table.
const METRIC_PREFIXES: [(&str, &str); 3] = [
    ("monotonic_counter.", "counter"),
    ("histogram.", "histogram"),
    ("gauge.", "gauge"),
];

/// A field written in a macro, with where its name starts.
struct Field {
    name: String,
    at: usize,
}

pub fn check(conventions: &Conventions, crate_name: &str, source: &Source) -> Vec<Finding> {
    let syntax = &source.syntax;
    let mut findings = Vec::new();
    // Offsets of the string literals the macro checks already judged.
    let mut judged: BTreeSet<usize> = BTreeSet::new();
    let mut report = |at: usize, text: String| {
        findings.push(Finding::new(
            "ST-07",
            source.location(at),
            format!("{crate_name}: {text}"),
        ));
    };

    for i in 0..syntax.tokens.len() {
        let Some(name) = syntax
            .tokens
            .get(i)
            .filter(|t| t.kind == Kind::Ident)
            .map(|t| t.text.as_str())
        else {
            continue;
        };
        let is_span = SPAN_MACROS.contains(&name);
        let is_event = EVENT_MACROS.contains(&name);
        if !(is_span || is_event) || !syntax.is_punct(i + 1, "!") {
            continue;
        }
        let open = i + 2;
        if !["(", "[", "{"].iter().any(|d| syntax.is_punct(open, d)) {
            continue;
        }
        let args = arguments(syntax, open);
        let mut fields = Vec::new();
        let mut skipped_level = name != "span";
        let mut seen_name = !is_span;
        for (start, end) in args {
            if is_keyed(syntax, start, "target") || is_keyed(syntax, start, "parent") {
                continue;
            }
            // A span macro: `span!(Level, "name", ..)`, the others `info_span!("name", ..)`.
            if is_span && !skipped_level {
                skipped_level = true;
                continue;
            }
            if is_span && !seen_name {
                seen_name = true;
                match syntax.tokens.get(start).filter(|t| t.kind == Kind::Str && end == start + 1) {
                    Some(literal) => {
                        judged.insert(literal.start);
                        if !conventions.spans.contains(&literal.text) {
                            report(
                                literal.start,
                                format!(
                                    "the span name {:?} is not in the span table of the conventions page",
                                    literal.text
                                ),
                            );
                        }
                    }
                    None => report(
                        syntax.offset(start),
                        "the span name is not a string literal, so ST-07 cannot read it; write the name as a literal from the span table".to_string(),
                    ),
                }
                continue;
            }
            match field_at(syntax, start, end) {
                FieldOrEnd::Field(field) => fields.push(field),
                FieldOrEnd::Message => break,
                FieldOrEnd::Other => {}
            }
        }
        judge_fields(conventions, &fields, &mut judged, &mut report);
    }

    // #[instrument(name = "...", fields(...))]
    for i in 0..syntax.tokens.len() {
        if !starts_instrument_attribute(syntax, i) {
            continue;
        }
        let open = i + 1;
        if !syntax.is_punct(open, "(") {
            report(
                syntax.offset(i),
                "#[instrument] without a name would name the span after the function; give it name = \"...\" from the span table".to_string(),
            );
            continue;
        }
        let mut named = false;
        let mut fields = Vec::new();
        for (start, _) in arguments(syntax, open) {
            if syntax.is_word(start, "name") && syntax.is_punct(start + 1, "=") {
                named = true;
                match syntax.tokens.get(start + 2).filter(|t| t.kind == Kind::Str) {
                    Some(literal) => {
                        judged.insert(literal.start);
                        if !conventions.spans.contains(&literal.text) {
                            report(
                                literal.start,
                                format!(
                                    "the span name {:?} is not in the span table of the conventions page",
                                    literal.text
                                ),
                            );
                        }
                    }
                    None => report(
                        syntax.offset(start),
                        "the span name is not a string literal, so ST-07 cannot read it"
                            .to_string(),
                    ),
                }
            } else if syntax.is_word(start, "fields") && syntax.is_punct(start + 1, "(") {
                for (field_start, field_end) in arguments(syntax, start + 1) {
                    if let FieldOrEnd::Field(field) = field_at(syntax, field_start, field_end) {
                        fields.push(field);
                    }
                }
            }
        }
        if !named {
            report(
                syntax.offset(i),
                "#[instrument] without name = \"...\" would name the span after the function; give it a name from the span table".to_string(),
            );
        }
        judge_fields(conventions, &fields, &mut judged, &mut report);
    }

    // Any other literal that looks like a factory name.
    for token in syntax.tokens.iter().filter(|t| t.kind == Kind::Str) {
        if judged.contains(&token.start) {
            continue;
        }
        let text = token.text.as_str();
        if looks_like_a_factory_name(text, '.')
            && !conventions.spans.contains(text)
            && !conventions.attributes.contains(text)
        {
            report(
                token.start,
                format!(
                    "the name {text:?} starts with factory. but is in no span or attribute table of the conventions page"
                ),
            );
        } else if looks_like_a_factory_name(text, '_') && !conventions.metrics.contains_key(text) {
            report(
                token.start,
                format!(
                    "the name {text:?} starts with factory_ but is in no metric table of the conventions page"
                ),
            );
        }
    }
    findings
}

/// True when token `i` is the `instrument` of `#[instrument` or `#[tracing::instrument`.
fn starts_instrument_attribute(syntax: &Syntax, i: usize) -> bool {
    if !syntax.is_word(i, "instrument") {
        return false;
    }
    let bracket =
        if syntax.is_path_sep(i.wrapping_sub(2)) && syntax.is_word(i.wrapping_sub(3), "tracing") {
            i.wrapping_sub(4)
        } else {
            i.wrapping_sub(1)
        };
    syntax.is_punct(bracket, "[") && syntax.is_punct(bracket.wrapping_sub(1), "#")
}

/// `factory.something` or `factory_something`: lower case letters, digits, underscores and dots.
fn looks_like_a_factory_name(text: &str, separator: char) -> bool {
    text.strip_prefix("factory")
        .and_then(|rest| rest.strip_prefix(separator))
        .is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
        })
}

/// The top-level arguments of the group that opens at token `open`, as token ranges.
fn arguments(syntax: &Syntax, open: usize) -> Vec<(usize, usize)> {
    let close = group_end(syntax, open);
    let mut found = Vec::new();
    let mut start = open + 1;
    let mut i = open + 1;
    while i < close {
        if syntax.is_punct(i, ",") {
            if i > start {
                found.push((start, i));
            }
            start = i + 1;
            i += 1;
        } else if matches!(syntax.tokens[i].text.as_str(), "(" | "[" | "{")
            && syntax.tokens[i].kind == Kind::Punct
        {
            i = group_end(syntax, i) + 1;
        } else {
            i += 1;
        }
    }
    if close > start {
        found.push((start, close));
    }
    found
}

/// The index of the delimiter that closes the group opened at `open`.
fn group_end(syntax: &Syntax, open: usize) -> usize {
    let mut depth = 0usize;
    for (i, t) in syntax.tokens.iter().enumerate().skip(open) {
        if t.kind != Kind::Punct {
            continue;
        }
        match t.text.as_str() {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    syntax.tokens.len()
}

/// True for an argument written `key: value`.
fn is_keyed(syntax: &Syntax, start: usize, key: &str) -> bool {
    syntax.is_word(start, key)
        && syntax.is_punct(start + 1, ":")
        && !syntax.is_punct(start + 2, ":")
}

enum FieldOrEnd {
    Field(Field),
    /// The format string of an event: the arguments after it are values, not fields.
    Message,
    Other,
}

/// Read one argument of a macro as a field: `name = value`, `a.b.c = value`, `"a.b" = value`,
/// `?name`, `%name`, or a bare `name`.
fn field_at(syntax: &Syntax, start: usize, end: usize) -> FieldOrEnd {
    let mut i = start;
    while syntax.is_punct(i, "?") || syntax.is_punct(i, "%") {
        i += 1;
    }
    if let Some(literal) = syntax.tokens.get(i).filter(|t| t.kind == Kind::Str) {
        return if syntax.is_punct(i + 1, "=") && !syntax.is_punct(i + 2, "=") {
            FieldOrEnd::Field(Field {
                name: literal.text.clone(),
                at: literal.start,
            })
        } else {
            FieldOrEnd::Message
        };
    }
    let mut name = String::new();
    let at = syntax.offset(i);
    while let Some(t) = syntax
        .tokens
        .get(i)
        .filter(|t| t.kind == Kind::Ident && i < end)
    {
        name.push_str(&t.text);
        if syntax.is_punct(i + 1, ".") && i + 2 < end {
            name.push('.');
            i += 2;
        } else {
            i += 1;
            break;
        }
    }
    let is_assignment = syntax.is_punct(i, "=") && !syntax.is_punct(i + 1, "=");
    if !name.is_empty() && (is_assignment || i >= end) {
        FieldOrEnd::Field(Field { name, at })
    } else {
        FieldOrEnd::Other
    }
}

fn judge_fields(
    conventions: &Conventions,
    fields: &[Field],
    judged: &mut BTreeSet<usize>,
    report: &mut impl FnMut(usize, String),
) {
    let metric_fields: Vec<(&Field, &str, &str)> = fields
        .iter()
        .filter_map(|f| {
            METRIC_PREFIXES
                .iter()
                .find_map(|(prefix, kind)| f.name.strip_prefix(prefix).map(|n| (f, *kind, n)))
        })
        .collect();
    for (field, kind, name) in &metric_fields {
        judged.insert(field.at);
        match conventions.metrics.get(*name) {
            None => report(
                field.at,
                format!("the metric {name:?} is not in the metric table of the conventions page"),
            ),
            Some(metric) if metric.kind != *kind => report(
                field.at,
                format!(
                    "the metric {name:?} is recorded as a {kind} but the metric table says it is a {}",
                    metric.kind
                ),
            ),
            Some(metric) => {
                for label in fields
                    .iter()
                    .filter(|f| !metric_fields.iter().any(|(m, _, _)| std::ptr::eq(*m, *f)))
                {
                    if !metric.labels.contains(&label.name) {
                        report(
                            label.at,
                            format!(
                                "the label {:?} is not listed for the metric {name:?} (labels: {})",
                                label.name,
                                metric.labels.iter().cloned().collect::<Vec<_>>().join(", ")
                            ),
                        );
                    }
                }
            }
        }
    }
    for field in fields {
        if metric_fields
            .iter()
            .any(|(m, _, _)| std::ptr::eq(*m, field))
        {
            continue;
        }
        let is_factory_name = field.name.starts_with("factory.") || field.name == "error.type";
        if metric_fields.is_empty()
            && is_factory_name
            && !conventions.attributes.contains(&field.name)
        {
            judged.insert(field.at);
            report(
                field.at,
                format!(
                    "the field {:?} is not in the attribute table of the conventions page",
                    field.name
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn real_page() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/observability/conventions.md");
        std::fs::read_to_string(path).expect("read the conventions page")
    }

    #[test]
    fn the_real_page_parses_into_its_tables() {
        let c = Conventions::parse(&real_page()).expect("parse");
        assert!(c.spans.contains("factory.stage_run") && c.spans.len() >= 6);
        assert!(c.attributes.contains("factory.job_id") && c.attributes.contains("error.type"));
        let retries = &c.metrics["factory_retries_total"];
        assert_eq!(retries.kind, "counter");
        assert_eq!(
            retries.labels.iter().cloned().collect::<Vec<_>>(),
            ["stage"]
        );
        assert_eq!(c.metrics["factory_queue_depth"].kind, "gauge");
        assert!(c.labels.contains("outcome"));
    }

    #[test]
    fn a_page_without_a_table_marker_is_an_error() {
        let error = Conventions::parse("| a | b |\n").unwrap_err();
        assert!(error.contains("table:spans"), "{error}");
    }

    #[test]
    fn only_lower_case_dotted_or_underscored_names_look_like_factory_names() {
        assert!(looks_like_a_factory_name("factory.job", '.'));
        assert!(looks_like_a_factory_name("factory_queue_depth", '_'));
        assert!(!looks_like_a_factory_name("factory-workflow", '.'));
        assert!(!looks_like_a_factory_name("factory.Job", '.'));
        assert!(!looks_like_a_factory_name("factory.", '.'));
        assert!(!looks_like_a_factory_name("factory_job", '.'));
    }
}
