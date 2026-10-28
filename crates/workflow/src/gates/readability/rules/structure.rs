//! The structure rules: the sections of a task, the first line of a body, bookkeeping lines, the
//! evidence of a pull request and the parts of a guide.

use super::super::text::{
    LineKind, bold_label, code_spans, heading_text, list_marker, strip_inline_code,
};
use super::title::has_opaque_prefix;
use super::{Ctx, Draft};

/// The optional section of the task template. It is not required, but it still ends the section
/// before it.
const OPTIONAL_SECTION: &str = "dependencies";

fn label_matches(label: &str, wanted: &str) -> bool {
    label
        .trim()
        .trim_end_matches(':')
        .trim()
        .eq_ignore_ascii_case(wanted)
}

/// `task-missing-section`: each of the four sections is present and has at least one non-blank
/// line before the next section.
pub(super) fn task_missing_section(ctx: &Ctx<'_>) -> Option<Draft> {
    let required = &ctx.catalog.lists().required_task_sections;
    let mut found = vec![false; required.len()];
    let mut filled = vec![false; required.len()];
    let mut open: Option<usize> = None;
    for line in &ctx.body.lines {
        let trimmed = line.trimmed();
        let label = match line.kind {
            LineKind::Heading => Some((heading_text(trimmed), true)),
            LineKind::Prose => bold_label(trimmed).map(|label| (label, false)),
            _ => None,
        };
        if let Some((label, is_heading)) = label {
            let label = label.trim_matches(['*', '_']);
            let index = required
                .iter()
                .position(|wanted| label_matches(label, wanted));
            if index.is_some() || is_heading || label_matches(label, OPTIONAL_SECTION) {
                open = index;
                if let Some(slot) = index.and_then(|i| found.get_mut(i)) {
                    *slot = true;
                }
                continue;
            }
        }
        if line.kind != LineKind::Blank
            && let Some(slot) = open.and_then(|i| filled.get_mut(i))
        {
            *slot = true;
        }
    }
    let missing: Vec<&str> = required
        .iter()
        .zip(found.iter().zip(&filled))
        .filter(|(_, (found, filled))| !**found || !**filled)
        .map(|(name, _)| name.as_str())
        .collect();
    (!missing.is_empty()).then(|| Draft {
        part: super::Part::Body,
        line: None,
        message: format!(
            "The task is missing a section, or leaves it empty: {}. A task needs all four sections of the template, each with at least one line.",
            missing.join(", ")
        ),
    })
}

/// `body-metadata-prefix`: the first non-blank line starts like an opaque title prefix, or is a
/// chain of pipe-separated stamps.
pub(super) fn metadata_prefix(ctx: &Ctx<'_>) -> Option<Draft> {
    let first = ctx
        .body
        .lines
        .iter()
        .find(|line| line.kind != LineKind::Blank)?;
    let stripped = strip_inline_code(first.text);
    let trimmed = stripped.trim_start();
    let stamp_chain = !trimmed.starts_with('|')
        && trimmed.contains('|')
        && trimmed
            .split('|')
            .filter(|segment| !segment.trim().is_empty())
            .count()
            >= 2;
    (has_opaque_prefix(trimmed) || stamp_chain).then(|| Draft {
        part: super::Part::Body,
        line: Some(first.number),
        message: "The first line of the body is an identifier chain, a tag chain or a metadata stamp. Start the body with a sentence that explains the context."
            .to_owned(),
    })
}

/// `body-metadata-lines`: lines such as `Assigned agent: backend-2` outside code.
pub(super) fn metadata_lines(ctx: &Ctx<'_>) -> Option<Draft> {
    let keys = &ctx.catalog.lists().metadata_line_keys;
    let mut count = 0_usize;
    let mut first: Option<(u32, &str)> = None;
    for line in ctx.body.text_lines() {
        let trimmed = line.trimmed();
        let text = match list_marker(trimmed) {
            Some((length, _)) => trimmed.get(length..).unwrap_or_default().trim_start(),
            None => trimmed,
        };
        let key = keys.iter().find(|key| starts_with_key(text, key));
        if let Some(key) = key {
            count += 1;
            first.get_or_insert((line.number, key.as_str()));
        }
    }
    let (number, key) = first?;
    Some(Draft {
        part: super::Part::Body,
        line: Some(number),
        message: format!(
            "{count} line(s) of the body state internal bookkeeping, the first being a \"{key}\" line. That value belongs in structured metadata."
        ),
    })
}

/// True when `text` starts with `key` (ASCII case-insensitive), then a colon or equals sign, then
/// a value.
fn starts_with_key(text: &str, key: &str) -> bool {
    let Some(head) = text.as_bytes().get(..key.len()) else {
        return false;
    };
    if !head.eq_ignore_ascii_case(key.as_bytes()) {
        return false;
    }
    let rest = text.get(key.len()..).unwrap_or_default().trim_start();
    rest.strip_prefix([':', '='])
        .is_some_and(|value| !value.trim().is_empty())
}

/// `pr-missing-evidence-link`: no Markdown link, no URL, no `#214`, no code span with a slash.
pub(super) fn missing_evidence_link(ctx: &Ctx<'_>) -> Option<Draft> {
    let body = ctx.artifact.body;
    if has_markdown_link(body)
        || has_url(body)
        || has_issue_reference(body)
        || ctx.body.text_lines().any(|line| {
            code_spans(line.text).iter().any(|(start, end)| {
                line.text
                    .get(*start..*end)
                    .is_some_and(|span| span.contains('/'))
            })
        })
    {
        return None;
    }
    Some(Draft {
        part: super::Part::Body,
        line: None,
        message: "The pull request body links to nothing: no link, no URL, no issue number and no file path."
            .to_owned(),
    })
}

/// An opening bracket with a `](` somewhere after it.
fn has_markdown_link(body: &str) -> bool {
    body.find('[')
        .and_then(|open| body.get(open..))
        .is_some_and(|rest| rest.contains("]("))
}

fn has_url(body: &str) -> bool {
    let lowered = body.to_ascii_lowercase();
    lowered.contains("http://") || lowered.contains("https://")
}

/// `#` and a number, not glued to a word before it.
fn has_issue_reference(body: &str) -> bool {
    let bytes = body.as_bytes();
    bytes.iter().enumerate().any(|(at, byte)| {
        *byte == b'#'
            && bytes.get(at + 1).is_some_and(u8::is_ascii_digit)
            && (at == 0
                || bytes
                    .get(at - 1)
                    .is_some_and(|before| !before.is_ascii_alphanumeric() && *before != b'_'))
    })
}

/// `doc-guide-missing-part`: a how-to guide or tutorial needs prerequisites, two numbered steps,
/// an expected result and troubleshooting.
pub(super) fn guide_missing_part(ctx: &Ctx<'_>) -> Option<Draft> {
    if !ctx.artifact.doc_type.is_some_and(|kind| kind.is_guide()) {
        return None;
    }
    let lists = ctx.catalog.lists();
    let headings: Vec<String> = ctx
        .body
        .lines
        .iter()
        .filter(|line| line.kind == LineKind::Heading)
        .map(|line| heading_text(line.trimmed()).to_lowercase())
        .collect();
    let has_heading = |phrases: &[String]| {
        headings
            .iter()
            .any(|h| phrases.iter().any(|p| h.contains(p.as_str())))
    };
    let numbered = ctx
        .body
        .lines
        .iter()
        .filter(|line| line.kind == LineKind::Item)
        .filter(|line| list_marker(line.trimmed()).is_some_and(|(_, ordered)| ordered))
        .count();
    let mut missing = Vec::new();
    if !has_heading(&lists.guide_prerequisites) {
        missing.push("prerequisites");
    }
    if numbered < 2 {
        missing.push("numbered steps");
    }
    if !has_heading(&lists.guide_expected_result) {
        missing.push("an expected result");
    }
    if !has_heading(&lists.guide_troubleshooting) {
        missing.push("troubleshooting");
    }
    (!missing.is_empty()).then(|| Draft {
        part: super::Part::Body,
        line: None,
        message: format!(
            "The guide lacks {}. A how-to guide or tutorial needs prerequisites, ordered steps, an expected result and troubleshooting.",
            missing.join(", ")
        ),
    })
}
