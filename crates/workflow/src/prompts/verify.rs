//! The assembler's own check of a finished prompt.
//!
//! The check does not trust the code that wrote the text. It reads the finished text line by
//! line against the template, the way a person with the format description would, and refuses it
//! unless:
//!
//! * every line outside the blocks is the template line, with trusted values put in its slots;
//! * every block opens with exactly the opening line the assembler meant, and closes with
//!   exactly the closing line, and no line in between is a closing line;
//! * every line between them starts with `> `, and taking the prefix off gives back exactly the
//!   text the assembler meant to include, with no hidden character and no line break of another
//!   kind in it;
//! * nothing follows the last line of the template.
//!
//! A failure here is a defect in the assembler, not in the input, and the prompt is not released.

use std::collections::BTreeMap;

use super::block::{QUOTE, closing_line};
use super::sanitize::{is_hidden, neutralize};
use super::template::{Line, Piece, Template};

/// A block as the assembler meant to write it.
pub(super) struct Meant<'a> {
    pub name: &'a str,
    pub header: &'a str,
    pub text: &'a str,
}

/// The line of instructions a template line stands for, with its trusted values put in.
pub(super) fn instruction_line(pieces: &[Piece], trusted: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    for piece in pieces {
        match piece {
            Piece::Literal(text) => out.push_str(text),
            Piece::Trusted(name) => {
                if let Some(value) = trusted.get(name) {
                    out.push_str(value);
                }
            }
        }
    }
    out
}

/// Reads one block from the next lines of `got` and checks it against what was meant.
pub(super) fn check_block<'a>(
    got: &mut impl Iterator<Item = &'a str>,
    meant: &Meant<'_>,
) -> Result<(), &'static str> {
    if got.next() != Some(meant.header) {
        return Err("an opening line changed");
    }
    let closing = closing_line(meant.name);
    let mut data: Vec<&str> = Vec::new();
    loop {
        let next = got.next().ok_or("a block is never closed")?;
        if next == closing {
            break;
        }
        data.push(
            next.strip_prefix(QUOTE)
                .ok_or("a line of data is not quoted")?,
        );
    }
    if meant.text.chars().any(is_hidden) {
        return Err("a block holds a hidden character");
    }
    if neutralize(meant.text).text != meant.text {
        return Err("a block holds a line break of another kind");
    }
    let expected_lines = if meant.text.is_empty() {
        0
    } else {
        meant.text.split('\n').count()
    };
    if data.len() != expected_lines || data.join("\n") != meant.text {
        return Err("the data of a block was changed");
    }
    Ok(())
}

/// Checks `rendered`.
pub(super) fn check(
    template: &Template,
    trusted: &BTreeMap<String, String>,
    blocks: &[Meant<'_>],
    rendered: &str,
) -> Result<(), &'static str> {
    let mut got = rendered.split('\n');
    for line in template.lines() {
        match line {
            Line::Text(pieces) => {
                if got.next() != Some(instruction_line(pieces, trusted).as_str()) {
                    return Err("a line of the instructions changed");
                }
            }
            Line::Block(index) => {
                let meant = blocks.get(*index).ok_or("a block is missing")?;
                check_block(&mut got, meant)?;
            }
        }
    }
    if got.next().is_some() {
        return Err("text follows the end of the template");
    }
    Ok(())
}
