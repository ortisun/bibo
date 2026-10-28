//! Reading a prompt template.
//!
//! A template is the `prompt.md` of an agent (`agents/README.md`, "How a prompt is built"). It has
//! the sections the contract names, an input table, and under `## Untrusted data` one placeholder
//! line `{{input.<name>}}` for each input of the table. The assembler replaces each of those
//! lines with one block and changes nothing else.
//!
//! The parser is strict, because a template that is read loosely is a template that can be made
//! to say something else. A template is refused when:
//!
//! * a section is missing, repeated or out of order;
//! * it does not tell the model how a block opens, closes and is quoted;
//! * a table row, class or name cannot be read, or the table and the placeholder lines disagree;
//! * `{{input.` appears anywhere but alone on a line inside the data section, or `{{trusted.`
//!   appears unclosed or inside the data section.
//!
//! A template may also have `{{trusted.<name>}}` slots in its instructions. A slot takes a value
//! that the factory made, checked against a strict grammar, never untrusted text.

use super::class::ContentClass;
use super::error::TemplateError;

/// The most inputs a template may declare.
pub const MAX_INPUTS: usize = 64;

const INPUT_CONTRACT: &str = "## Input contract";
const DATA_HEADING: &str = "## Untrusted data";
const END_HEADING: &str = "## End of data";

const INPUT_OPEN: &str = "{{input.";
const TRUSTED_OPEN: &str = "{{trusted.";
const SLOT_CLOSE: &str = "}}";

/// The phrases that tell the model how a block is marked. A template without them would hand the
/// model data blocks it was never told how to read.
const BLOCK_RULES: [&str; 3] = [
    "starts with `<<<DATA name=`",
    "`<<<END name=`",
    "starts with `> `",
];

/// One input of the template: a row of the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSpec {
    name: String,
    class: ContentClass,
    required: bool,
}

impl InputSpec {
    pub(super) fn new(name: &str, class: ContentClass, required: bool) -> Self {
        Self {
            name: name.to_owned(),
            class,
            required,
        }
    }

    /// The name, which is also the name in the placeholder line and in the block.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The class the template declares.
    #[must_use]
    pub const fn class(&self) -> ContentClass {
        self.class
    }

    /// Whether the agent needs the input. An input that is not required can be empty.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

/// A piece of a line of instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Piece {
    /// Text of the template, kept as it is.
    Literal(String),
    /// A slot for a trusted value.
    Trusted(String),
}

/// A line of the template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Line {
    /// A line of instructions.
    Text(Vec<Piece>),
    /// A placeholder line: the input with this index in the table.
    Block(usize),
}

/// A prompt template that was read and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    lines: Vec<Line>,
    inputs: Vec<InputSpec>,
    trusted: Vec<String>,
}

/// Whether `name` is 1 to 64 lowercase letters, digits and underscores, starting with a letter.
pub(super) fn is_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// The line numbers (from 0) of a heading, or the error when it is not there exactly once.
fn heading_at(lines: &[&str], heading: &'static str) -> Result<usize, TemplateError> {
    let mut found = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| **line == heading)
        .map(|(at, _)| at);
    let first = found
        .next()
        .ok_or(TemplateError::MissingSection { heading })?;
    if found.next().is_some() {
        return Err(TemplateError::DuplicateSection { heading });
    }
    Ok(first)
}

fn cells(row: &str) -> Vec<&str> {
    let inner = row.trim();
    let inner = inner.strip_prefix('|').unwrap_or(inner);
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    inner.split('|').map(str::trim).collect()
}

fn is_separator(cells: &[&str]) -> bool {
    !cells.is_empty()
        && cells
            .iter()
            .all(|c| !c.is_empty() && c.bytes().all(|b| b == b'-' || b == b':'))
}

/// Reads the input table that follows `## Input contract`.
fn read_table(lines: &[&str], from: usize) -> Result<Vec<InputSpec>, TemplateError> {
    let mut inputs: Vec<InputSpec> = Vec::new();
    let mut rows = lines
        .iter()
        .enumerate()
        .skip(from + 1)
        .take_while(|(_, line)| !line.starts_with("## "))
        .skip_while(|(_, line)| !line.starts_with('|'))
        .take_while(|(_, line)| line.starts_with('|'));
    let bad = |at: usize| TemplateError::BadTableRow { line: at + 1 };

    let (head_at, head) = rows
        .next()
        .ok_or(TemplateError::BadTableRow { line: from + 1 })?;
    let head = cells(head);
    let [first, second, third, _, ..] = head.as_slice() else {
        return Err(bad(head_at));
    };
    if !(first.eq_ignore_ascii_case("input")
        && second.eq_ignore_ascii_case("class")
        && third.eq_ignore_ascii_case("required"))
    {
        return Err(bad(head_at));
    }
    let (sep_at, sep) = rows.next().ok_or_else(|| bad(head_at))?;
    if !is_separator(&cells(sep)) {
        return Err(bad(sep_at));
    }
    for (at, row) in rows {
        let row = cells(row);
        let [name_cell, class_cell, required_cell, _, ..] = row.as_slice() else {
            return Err(bad(at));
        };
        let name = name_cell
            .strip_prefix('`')
            .and_then(|n| n.strip_suffix('`'))
            .ok_or_else(|| bad(at))?;
        if !is_name(name) {
            return Err(TemplateError::BadName { line: at + 1 });
        }
        let class =
            ContentClass::parse(class_cell).ok_or(TemplateError::UnknownClass { line: at + 1 })?;
        let required = match *required_cell {
            "yes" => true,
            "no" => false,
            _ => return Err(bad(at)),
        };
        if inputs.iter().any(|i| i.name == name) {
            return Err(TemplateError::DuplicateInput { line: at + 1 });
        }
        if inputs.len() == MAX_INPUTS {
            return Err(TemplateError::TooManyInputs { max: MAX_INPUTS });
        }
        inputs.push(InputSpec {
            name: name.to_owned(),
            class,
            required,
        });
    }
    Ok(inputs)
}

/// Splits a line of instructions into literal text and trusted slots.
fn pieces(
    line: &str,
    number: usize,
    trusted: &mut Vec<String>,
) -> Result<Vec<Piece>, TemplateError> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(at) = rest.find(TRUSTED_OPEN) {
        let (before, after) = rest.split_at(at);
        if !before.is_empty() {
            out.push(Piece::Literal(before.to_owned()));
        }
        let after = &after[TRUSTED_OPEN.len()..];
        let end = after
            .find(SLOT_CLOSE)
            .ok_or(TemplateError::StrayPlaceholder { line: number })?;
        let name = &after[..end];
        if !is_name(name) {
            return Err(TemplateError::BadName { line: number });
        }
        if !trusted.iter().any(|t| t == name) {
            trusted.push(name.to_owned());
        }
        out.push(Piece::Trusted(name.to_owned()));
        rest = &after[end + SLOT_CLOSE.len()..];
    }
    if !rest.is_empty() || out.is_empty() {
        out.push(Piece::Literal(rest.to_owned()));
    }
    Ok(out)
}

impl Template {
    /// Reads and checks a template.
    ///
    /// # Errors
    /// A [`TemplateError`] for the first rule the template breaks.
    pub fn parse(text: &str) -> Result<Self, TemplateError> {
        let lines: Vec<&str> = text.split('\n').collect();
        let contract_at = heading_at(&lines, INPUT_CONTRACT)?;
        let data_at = heading_at(&lines, DATA_HEADING)?;
        let end_at = heading_at(&lines, END_HEADING)?;
        if !(contract_at < data_at && data_at < end_at) {
            return Err(TemplateError::SectionOrder);
        }

        let before_data = lines.get(..data_at).unwrap_or_default().join("\n");
        if !BLOCK_RULES.iter().all(|rule| before_data.contains(rule)) {
            return Err(TemplateError::BlockRulesMissing);
        }

        let inputs = read_table(&lines, contract_at)?;
        let mut trusted: Vec<String> = Vec::new();
        let mut placed: Vec<Option<usize>> = vec![None; inputs.len()];
        let mut out: Vec<Line> = Vec::with_capacity(lines.len());

        for (at, line) in lines.iter().enumerate() {
            let number = at + 1;
            let whole = line
                .strip_prefix(INPUT_OPEN)
                .and_then(|rest| rest.strip_suffix(SLOT_CLOSE));
            if let Some(name) = whole {
                if !is_name(name) {
                    return Err(TemplateError::BadName { line: number });
                }
                if !(data_at < at && at < end_at) {
                    return Err(TemplateError::PlaceholderOutsideData { line: number });
                }
                let index = inputs
                    .iter()
                    .position(|i| i.name == name)
                    .ok_or(TemplateError::PlaceholderNotInTable { line: number })?;
                if placed.get(index).copied().flatten().is_some() {
                    return Err(TemplateError::DuplicatePlaceholder { line: number });
                }
                if let Some(slot) = placed.get_mut(index) {
                    *slot = Some(at);
                }
                out.push(Line::Block(index));
                continue;
            }
            if line.contains(INPUT_OPEN) {
                return Err(TemplateError::StrayPlaceholder { line: number });
            }
            if line.contains(TRUSTED_OPEN) && at >= data_at {
                return Err(TemplateError::PlaceholderOutsideData { line: number });
            }
            out.push(Line::Text(pieces(line, number, &mut trusted)?));
        }
        // The blocks come in the order of the placeholder lines. The table may list the inputs in
        // another order, so the inputs are put in the order of their lines.
        let mut order: Vec<(usize, usize)> = Vec::with_capacity(inputs.len());
        for (index, line) in placed.iter().enumerate() {
            order.push((line.ok_or(TemplateError::InputWithoutPlaceholder)?, index));
        }
        order.sort_unstable();
        let mut new_index = vec![0usize; inputs.len()];
        let mut sorted: Vec<InputSpec> = Vec::with_capacity(inputs.len());
        for (position, (_, old)) in order.iter().enumerate() {
            if let (Some(slot), Some(spec)) = (new_index.get_mut(*old), inputs.get(*old)) {
                *slot = position;
                sorted.push(spec.clone());
            }
        }
        for line in &mut out {
            if let Line::Block(index) = line {
                *index = new_index.get(*index).copied().unwrap_or(*index);
            }
        }
        Ok(Self {
            lines: out,
            inputs: sorted,
            trusted,
        })
    }

    /// The inputs, in the order of the table (which is the order of the placeholder lines in
    /// every template of the repository, and the order the blocks come in).
    #[must_use]
    pub fn inputs(&self) -> &[InputSpec] {
        &self.inputs
    }

    /// The names of the trusted slots, in the order they first appear.
    #[must_use]
    pub fn trusted_slots(&self) -> Vec<String> {
        self.trusted.clone()
    }

    pub(super) fn lines(&self) -> &[Line] {
        &self.lines
    }
}
