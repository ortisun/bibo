//! An independent checker for assembled prompts.
//!
//! It shares no code with the assembler: it reads the finished text line by line, the way a
//! person with the format description would, and says what is wrong. It follows the properties
//! the agent definitions state (`agents/README.md`, "How a prompt is built") and that the
//! reference renderer in `crates/contracts/tests/agent_defs/render.rs` checks:
//!
//! * the text outside the blocks is the template, and nothing else;
//! * a block opens with a line that starts `<<<DATA name=` and closes with the line
//!   `<<<END name=...>>>`;
//! * every line between them starts with `> `;
//! * the blocks come in template order, inside the `Untrusted data` section.

#![allow(dead_code)]

pub const OPEN: &str = "<<<DATA name=";
pub const CLOSE: &str = "<<<END name=";

/// What the checker found in a finished prompt.
#[derive(Debug, Default)]
pub struct Decoded {
    /// Everything that is wrong. Empty when the prompt is well formed.
    pub problems: Vec<String>,
    /// The opening line of each block.
    pub headers: Vec<String>,
    /// The data of each block with the quote prefix taken off and the lines joined by `\n`.
    pub bodies: Vec<String>,
}

/// Reads `rendered` against the lines the template has outside its placeholders.
pub fn decode(expected_outside: &[String], names: &[String], rendered: &str) -> Decoded {
    let mut out = Decoded::default();
    let mut outside: Vec<&str> = Vec::new();
    let mut open: Option<usize> = None;
    let mut seen = 0;
    let mut first_open_at = None;
    let mut last_close_at = None;
    let mut lines_in_block: Vec<Vec<&str>> = Vec::new();

    for (number, line) in rendered.split('\n').enumerate() {
        match open {
            None if line.starts_with(OPEN) => {
                let expected = names.get(seen).map_or("", String::as_str);
                if !line[OPEN.len()..].starts_with(&format!("{expected} ")) {
                    out.problems.push(format!(
                        "line {number}: a block opens that is not `{expected}`"
                    ));
                }
                first_open_at.get_or_insert(number);
                out.headers.push(line.to_owned());
                lines_in_block.push(Vec::new());
                open = Some(seen);
            }
            None if line.starts_with(CLOSE) => {
                out.problems.push(format!(
                    "line {number}: a block closes that was never opened"
                ));
            }
            None => outside.push(line),
            Some(index) if line.starts_with(CLOSE) => {
                let expected = names.get(index).map_or("", String::as_str);
                if line != format!("{CLOSE}{expected}>>>") {
                    out.problems.push(format!(
                        "line {number}: the block `{expected}` closes with another line"
                    ));
                }
                last_close_at = Some(number);
                open = None;
                seen += 1;
            }
            Some(_) if line.starts_with(OPEN) => {
                out.problems
                    .push(format!("line {number}: a block opens inside another block"));
            }
            Some(index) => match line.strip_prefix("> ") {
                Some(text) => lines_in_block[index].push(text),
                None => out.problems.push(format!(
                    "line {number}: a line inside a block is not quoted"
                )),
            },
        }
    }
    if open.is_some() {
        out.problems.push("a block was never closed".to_owned());
    }
    if seen != names.len() {
        out.problems.push(format!(
            "{seen} blocks were rendered but the template has {}",
            names.len()
        ));
    }
    if outside != expected_outside {
        out.problems
            .push("the text outside the blocks differs from the template".to_owned());
    }
    let lines: Vec<&str> = rendered.split('\n').collect();
    let heading_at = |h: &str| lines.iter().position(|l| *l == h);
    match (first_open_at, heading_at("## Untrusted data")) {
        (Some(at), Some(heading)) if at > heading => {}
        (None, _) if names.is_empty() => {}
        _ => out
            .problems
            .push("a block opens before the `Untrusted data` section".to_owned()),
    }
    match (last_close_at, heading_at("## End of data")) {
        (Some(at), Some(heading)) if at < heading => {}
        (None, _) if names.is_empty() => {}
        _ => out
            .problems
            .push("a block closes after the `End of data` section".to_owned()),
    }
    out.bodies = lines_in_block.into_iter().map(|l| l.join("\n")).collect();
    out
}

/// Characters that never reach the model. Written out as ranges here on purpose, apart from the
/// assembler's own list, so that a change to one of them shows as a failing test.
pub fn is_hidden_oracle(c: char) -> bool {
    let cp = c as u32;
    let in_ranges = [
        (0x00AD, 0x00AD),
        (0x034F, 0x034F),
        (0x061C, 0x061C),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180F),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x206F),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFEFF, 0xFEFF),
        (0xFFA0, 0xFFA0),
        (0xFFF9, 0xFFFB),
        (0x1BCA0, 0x1BCA3),
        (0xE0000, 0xE007F),
        (0xE0100, 0xE01EF),
    ]
    .iter()
    .any(|(lo, hi)| (*lo..=*hi).contains(&cp));
    in_ranges || (c.is_control() && c != '\t' && c != '\n')
}

pub fn is_line_break_oracle(c: char) -> bool {
    matches!(
        c,
        '\r' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}'
    )
}

/// What a text becomes: line breaks of every kind turn into `\n` (a `\r\n` pair into one), hidden
/// characters go.
pub fn neutralize_oracle(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' && chars.peek() == Some(&'\n') {
            continue;
        }
        if is_line_break_oracle(c) {
            out.push('\n');
        } else if !is_hidden_oracle(c) {
            out.push(c);
        }
    }
    out
}

/// How many hidden characters `text` holds.
pub fn hidden_count_oracle(text: &str) -> usize {
    text.chars()
        .filter(|c| !is_line_break_oracle(*c) && is_hidden_oracle(*c))
        .count()
}

/// Reads text that is exactly one block, such as a request file. Gives the opening line and the
/// data, or says what is wrong.
pub fn decode_block(text: &str, name: &str) -> Result<(String, String), String> {
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    let (first, rest) = lines.split_first().ok_or("empty")?;
    if !first.starts_with(&format!("{OPEN}{name} ")) || !first.ends_with(">>>") {
        return Err(format!("the first line is not the opening line: {first:?}"));
    }
    let (last, middle) = rest.split_last().ok_or("no closing line")?;
    if *last != format!("{CLOSE}{name}>>>") {
        return Err(format!("the last line is not the closing line: {last:?}"));
    }
    let mut data = Vec::new();
    for line in middle {
        data.push(
            line.strip_prefix("> ")
                .ok_or_else(|| format!("a line is not quoted: {line:?}"))?,
        );
    }
    Ok(((*first).to_owned(), data.join("\n")))
}

/// The value of an attribute in an opening line, such as `stripped` in `stripped=3`.
pub fn attribute<'a>(header: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!(" {key}=");
    let start = header.find(&marker)? + marker.len();
    let rest = &header[start..];
    let end = rest.find([' ', '>']).unwrap_or(rest.len());
    Some(&rest[..end])
}
