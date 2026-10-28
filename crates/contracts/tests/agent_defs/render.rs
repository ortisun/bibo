//! A reference renderer for the data blocks of the agent prompts, and the check that tells whether a
//! rendered prompt kept its data inside the blocks.
//!
//! The real prompt assembly is the work package `s1-prompt-assembly` and lives in the workflow
//! crate. This module is not that code. It states, in the smallest form, the properties every
//! renderer of these templates must have, so that the templates can be tested now:
//!
//! * a placeholder line `{{input.name}}` is replaced by one block and nothing else changes;
//! * a block opens with a line that starts `<<<DATA name=` and closes with a line that starts
//!   `<<<END name=`, and every line between them starts with `> `, so no line of data can start
//!   with `<<<` and none can pass for a delimiter;
//! * line breaks of every kind in the data become line breaks of the block, so data cannot start a
//!   line that the block does not quote;
//! * hidden characters, direction controls and other control characters are removed and counted.
//!
//! Text outside the blocks is then identical for every content, which is what the tests compare.

use std::collections::BTreeMap;

use factory_domain::values::Sha256Digest;

pub const OPEN: &str = "<<<DATA name=";
pub const CLOSE: &str = "<<<END name=";

/// What a renderer needs to know about one input: its class, and the text.
pub struct Input {
    pub class: String,
    pub text: String,
}

/// Characters that never reach the model: zero-width and direction-control characters, the soft
/// hyphen, the Mongolian vowel separator and every control character except tab and line feed.
fn is_hidden(c: char) -> bool {
    matches!(c,
        '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{FEFF}' | '\u{00AD}' | '\u{180E}')
        || (c.is_control() && c != '\t' && c != '\n')
}

/// Characters that some readers treat as the end of a line.
fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// Line breaks become `\n`, hidden characters are dropped. Returns the text and how many
/// characters were dropped.
pub fn neutralize(text: &str) -> (String, usize) {
    let mut out = String::with_capacity(text.len());
    let mut dropped = 0;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' && chars.peek() == Some(&'\n') {
            continue;
        }
        if is_line_break(c) {
            out.push('\n');
        } else if is_hidden(c) {
            dropped += 1;
        } else {
            out.push(c);
        }
    }
    (out, dropped)
}

/// One block: the opening line, the quoted lines of data, the closing line.
pub fn render_block(name: &str, input: &Input) -> Vec<String> {
    let (clean, dropped) = neutralize(&input.text);
    let digest = Sha256Digest::of(input.text.as_bytes());
    let mut lines = vec![format!(
        "{OPEN}{name} class={} bytes={} sha256={} stripped={dropped}>>>",
        input.class,
        input.text.len(),
        digest.as_str()
    )];
    if !clean.is_empty() {
        lines.extend(clean.split('\n').map(|line| format!("> {line}")));
    }
    lines.push(format!("{CLOSE}{name}>>>"));
    lines
}

/// The name of a placeholder line, if the line is one.
pub fn placeholder(line: &str) -> Option<&str> {
    line.strip_prefix("{{input.")?.strip_suffix("}}")
}

/// Renders a template. An input that is not given renders as an empty block.
pub fn render(
    template: &str,
    inputs: &BTreeMap<String, Input>,
    class_of: &dyn Fn(&str) -> String,
) -> String {
    let empty = |name: &str| Input {
        class: class_of(name),
        text: String::new(),
    };
    let mut out: Vec<String> = Vec::new();
    for line in template.split('\n') {
        match placeholder(line) {
            Some(name) => match inputs.get(name) {
                Some(input) => out.extend(render_block(name, input)),
                None => out.extend(render_block(name, &empty(name))),
            },
            None => out.push(line.to_owned()),
        }
    }
    out.join("\n")
}

/// A renderer with the flaw this module exists to rule out: it pastes the data between the markers
/// without quoting any line. Only the break tests use it.
pub fn render_unquoted(template: &str, inputs: &BTreeMap<String, Input>) -> String {
    let mut out: Vec<String> = Vec::new();
    for line in template.split('\n') {
        match placeholder(line) {
            Some(name) => {
                out.push(format!(
                    "{OPEN}{name} class=x bytes=0 sha256=x stripped=0>>>"
                ));
                out.push(inputs.get(name).map(|i| i.text.clone()).unwrap_or_default());
                out.push(format!("{CLOSE}{name}>>>"));
            }
            None => out.push(line.to_owned()),
        }
    }
    out.join("\n")
}

/// What is wrong with a rendered prompt: data outside its block, a block that opened or closed in
/// the wrong place, a line inside a block that is not quoted, text outside the blocks that
/// differs from the template, or a block outside the "Untrusted data" section.
pub fn containment_problems(
    template: &str,
    names: &[String],
    inputs: &BTreeMap<String, Input>,
    rendered: &str,
) -> Vec<String> {
    let mut problems = Vec::new();
    let expected_outside: Vec<&str> = template
        .split('\n')
        .filter(|line| placeholder(line).is_none())
        .collect();

    let mut outside: Vec<&str> = Vec::new();
    let mut open: Option<usize> = None;
    let mut data: Vec<Vec<&str>> = Vec::new();
    let mut seen = 0;
    let mut first_open_at = None;
    let mut last_close_at = None;
    for (number, line) in rendered.split('\n').enumerate() {
        match open {
            None if line.starts_with(OPEN) => {
                let expected = names.get(seen).map_or("", String::as_str);
                if !line[OPEN.len()..].starts_with(&format!("{expected} ")) {
                    problems.push(format!(
                        "line {number}: a block opens that is not `{expected}`"
                    ));
                }
                first_open_at.get_or_insert(number);
                open = Some(seen);
                data.push(Vec::new());
            }
            None if line.starts_with(CLOSE) => {
                problems.push(format!(
                    "line {number}: a block closes that was never opened"
                ));
            }
            None => outside.push(line),
            Some(index) if line.starts_with(CLOSE) => {
                let expected = names.get(index).map_or("", String::as_str);
                if line != format!("{CLOSE}{expected}>>>") {
                    problems.push(format!(
                        "line {number}: the block `{expected}` closes with another line"
                    ));
                }
                last_close_at = Some(number);
                open = None;
                seen += 1;
            }
            Some(_) if line.starts_with(OPEN) => {
                problems.push(format!("line {number}: a block opens inside another block"));
            }
            Some(index) => {
                if let Some(text) = line.strip_prefix("> ") {
                    data[index].push(text);
                } else {
                    problems.push(format!(
                        "line {number}: a line inside a block is not quoted"
                    ));
                }
            }
        }
    }
    if open.is_some() {
        problems.push("a block was never closed".to_owned());
    }
    if seen != names.len() {
        problems.push(format!(
            "{seen} blocks were rendered but the template has {}",
            names.len()
        ));
    }
    if outside != expected_outside {
        problems.push("the text outside the blocks differs from the template".to_owned());
    }
    let lines: Vec<&str> = rendered.split('\n').collect();
    let heading_at = |h: &str| lines.iter().position(|l| *l == h);
    match (first_open_at, heading_at("## Untrusted data")) {
        (Some(at), Some(heading)) if at > heading => {}
        _ => problems.push("a block opens before the `Untrusted data` section".to_owned()),
    }
    match (last_close_at, heading_at("## End of data")) {
        (Some(at), Some(heading)) if at < heading => {}
        _ => problems.push("a block closes after the `End of data` section".to_owned()),
    }
    // The data comes back unchanged except for what was removed on purpose.
    for (index, name) in names.iter().enumerate() {
        let wanted = inputs
            .get(name)
            .map(|i| neutralize(&i.text).0)
            .unwrap_or_default();
        let got = data.get(index).map(|d| d.join("\n")).unwrap_or_default();
        if got != wanted {
            problems.push(format!("the data of `{name}` was changed or cut"));
        }
    }
    problems
}
