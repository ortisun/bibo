//! Making a text the agent wrote safe to show on an issue.
//!
//! Every agent-written field goes through [`one_line`] and is then shown inside [`code_span`].
//! The two together keep the text from doing anything but being read:
//!
//! * **One line.** Every line break and other white space becomes one space, so the text cannot
//!   start a line of its own: no heading, no task list, no list item, no quote, no table, no fence.
//! * **Invisible and reordering characters go.** Control characters, bidirectional controls,
//!   zero-width characters and Unicode tag characters are removed, so what a person reads is what
//!   the text says.
//! * **Defanged.** `<` and `>` become `‹` and `›` (no HTML, no comment, no hidden marker, no
//!   `<https://…>` link), `@` becomes `＠` (no mention, no e-mail link), `#` becomes `＃` (no `#123`
//!   or `owner/repo#123` reference), `://` becomes `[:]//` and `www.` becomes `www[.]` (no
//!   automatic link), and the word `troubleshooter-fingerprint` loses its hyphen.
//! * **Inside a code span.** Nothing inside a code span is a link, a mention, a reference, HTML or
//!   emphasis. The span's delimiter is one backtick longer than the longest run of backticks in the
//!   text, so no backtick in the text can close it.
//!
//! Each step alone would stop most tricks. They are kept together on purpose: a renderer that
//! treats a code span differently from GitHub, or a person who copies the text out, is still safe.

/// True for a character that is removed outright: it is invisible, or it changes the order in
/// which the text is shown.
fn is_removed(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// The text on one line, without invisible characters, at most `max_chars` characters long (an
/// ellipsis marks a cut), and defanged. See the module notes.
#[must_use]
pub fn one_line(text: &str, max_chars: usize) -> String {
    let mut flat = String::with_capacity(text.len());
    let mut space = false;
    for c in text.chars() {
        if is_removed(c) {
            continue;
        }
        if c.is_control() || c.is_whitespace() {
            space = true;
            continue;
        }
        if space && !flat.is_empty() {
            flat.push(' ');
        }
        space = false;
        flat.push(c);
    }
    let cut = if flat.chars().count() > max_chars {
        let mut kept: String = flat.chars().take(max_chars.saturating_sub(1)).collect();
        kept.truncate(kept.trim_end().len());
        kept.push('…');
        kept
    } else {
        flat
    };
    defang(&cut)
}

fn defang(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        match c {
            '<' => out.push('‹'),
            '>' => out.push('›'),
            '@' => out.push('＠'),
            '#' => out.push('＃'),
            other => out.push(other),
        }
    }
    let out = out.replace("://", "[:]//");
    let out = replace_ignoring_case(&out, "www.", "www[.]");
    replace_ignoring_case(
        &out,
        "troubleshooter-fingerprint",
        "troubleshooter fingerprint",
    )
}

/// Replaces every match of the ASCII `needle`, in any letter case, with `with`.
fn replace_ignoring_case(text: &str, needle: &str, with: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while let Some(at) = lower.get(from..).and_then(|rest| rest.find(needle)) {
        let start = from + at;
        out.push_str(text.get(from..start).unwrap_or_default());
        out.push_str(with);
        from = start + needle.len();
    }
    out.push_str(text.get(from..).unwrap_or_default());
    out
}

/// The text as an inline code span. The delimiter is one backtick longer than the longest run of
/// backticks in the text, and a space pads a text that starts or ends with a backtick, so nothing
/// in the text can end the span. A text with a line break is put on one line first.
#[must_use]
pub fn code_span(text: &str) -> String {
    let text = if text.contains(['\n', '\r']) {
        text.replace(['\n', '\r'], " ")
    } else {
        text.to_owned()
    };
    if text.trim().is_empty() {
        return "(empty)".to_owned();
    }
    let longest = text
        .split(|c| c != '`')
        .map(str::len)
        .max()
        .unwrap_or_default();
    let fence = "`".repeat(longest + 1);
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{text}{pad}{fence}")
}
