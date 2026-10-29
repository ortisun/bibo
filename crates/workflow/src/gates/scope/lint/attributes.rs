//! Rust attributes that set the level of a lint, read as tokens (RR-11, RR-12).
//!
//! The rule used to look for the text `allow(` on lines that begin with `#[` or `#![`. Rust does
//! not read attributes that way: white space and comments may stand between `#` and `[`, between
//! the name and its parenthesis, and across lines, and an attribute may follow code on the same
//! line or sit in the body of a macro. So the source is cut into tokens first, with comments and
//! string, character and byte literals skipped whole, and an attribute is whatever follows a `#`,
//! an optional `!` and a `[` up to the matching `]`.
//!
//! What is kept of an attribute is a list of facts: the level it sets (`allow`, `expect`, `warn`,
//! `deny`, `forbid`), the lint it names, whether it is an inner attribute (`#![..]`, the scope of a
//! whole module or crate) or an outer one, and whether it sits in a `cfg_attr` and so applies only
//! under a condition. A `cfg_attr` is read through: `cfg_attr(test, allow(x))` is an `allow`.
//!
//! The two versions of a file are then compared by counting, per lint and scope:
//!
//! * more suppressions (`allow`, `expect`) than before is a relaxation, wherever they sit;
//! * fewer attributes at a level than before, counting the stronger levels in (a `forbid` counts
//!   as a `deny` and as a `warn`), is a relaxation. A lint dropped from a `deny` list, a `forbid`
//!   written as `deny`, a `deny` written as `warn`, a `deny` made conditional with `cfg_attr`, and
//!   an inner attribute made outer are all fewer. A tightening is never fewer.
//!
//! The scanner does not expand macros. An attribute that a macro builds from its arguments
//! (`quiet!(allow(dead_code))`) is not seen. That is a limit of reading the source on the host,
//! and the lint command's own `-D warnings` is the second check for it.

use std::collections::BTreeMap;

/// What an attribute does to a lint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// `allow`.
    Allow,
    /// `expect`: silences the lint as long as it fires.
    Expect,
    /// `warn`.
    Warn,
    /// `deny`.
    Deny,
    /// `forbid`.
    Forbid,
}

impl Level {
    fn of(name: &str) -> Option<Self> {
        match name {
            "allow" => Some(Self::Allow),
            "expect" => Some(Self::Expect),
            "warn" => Some(Self::Warn),
            "deny" => Some(Self::Deny),
            "forbid" => Some(Self::Forbid),
            _ => None,
        }
    }

    fn suppresses(self) -> bool {
        matches!(self, Self::Allow | Self::Expect)
    }
}

/// One lint named by one attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    /// The level the attribute sets.
    pub level: Level,
    /// The lint, as a path such as `dead_code` or `clippy::unwrap_used`.
    pub lint: String,
    /// True for `#![..]`.
    pub inner: bool,
    /// True when the attribute is inside a `cfg_attr`.
    pub conditional: bool,
    /// The line, from 1, of the `#` that starts the attribute.
    pub line: u32,
}

// ------------------------------------------------------------------------------------------
// Tokens
// ------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Punct(char),
    Open(char),
    Close(char),
    /// A string, character, byte, lifetime or number: nothing in it is read.
    Lit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    tok: Tok,
    line: u32,
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c.is_alphabetic()
}

fn is_ident_continue(c: char) -> bool {
    c == '_' || c.is_alphanumeric()
}

/// Skips a quoted literal that starts at `chars[at]` (the opening `"`), honouring `\` escapes.
/// Returns the index after the closing quote, or the end of the input.
fn skip_string(chars: &[char], at: usize, line: &mut u32) -> usize {
    let mut i = at + 1;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                if chars.get(i + 1) == Some(&'\n') {
                    *line += 1;
                }
                i += 2;
            }
            '"' => return i + 1,
            '\n' => {
                *line += 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    chars.len()
}

/// The raw string that starts at `chars[at]` (`#`s then `"`), if there is one. Returns the index
/// after its end.
fn skip_raw_string(chars: &[char], at: usize, line: &mut u32) -> Option<usize> {
    let mut i = at;
    let mut hashes = 0usize;
    while chars.get(i) == Some(&'#') {
        hashes += 1;
        i += 1;
    }
    if chars.get(i) != Some(&'"') {
        return None;
    }
    i += 1;
    while i < chars.len() {
        match chars[i] {
            '\n' => {
                *line += 1;
                i += 1;
            }
            '"' if (1..=hashes).all(|offset| chars.get(i + offset) == Some(&'#')) => {
                return Some(i + 1 + hashes);
            }
            _ => i += 1,
        }
    }
    Some(chars.len())
}

fn tokenize(source: &str) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut line = 1u32;
    let mut i = 0usize;
    let push = |tokens: &mut Vec<Token>, tok: Tok, line: u32| tokens.push(Token { tok, line });
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            c if c.is_whitespace() => i += 1,
            '/' if next == Some('/') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if next == Some('*') => {
                let mut depth = 1usize;
                i += 2;
                while i < chars.len() && depth > 0 {
                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        if chars[i] == '\n' {
                            line += 1;
                        }
                        i += 1;
                    }
                }
            }
            '"' => {
                let start = line;
                i = skip_string(&chars, i, &mut line);
                push(&mut tokens, Tok::Lit, start);
            }
            '\'' => {
                let start = line;
                if next == Some('\\') {
                    // An escape: '\n', '\'', '\x41', '\u{1F600}'.
                    let mut j = i + 3;
                    while j < chars.len() && chars[j] != '\'' {
                        j += 1;
                    }
                    i = (j + 1).min(chars.len());
                } else if chars.get(i + 2) == Some(&'\'') {
                    i += 3;
                } else {
                    // A lifetime or a label.
                    i += 1;
                    while i < chars.len() && is_ident_continue(chars[i]) {
                        i += 1;
                    }
                }
                push(&mut tokens, Tok::Lit, start);
            }
            c if is_ident_start(c) => {
                let start = i;
                let start_line = line;
                while i < chars.len() && is_ident_continue(chars[i]) {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                let after = chars.get(i).copied();
                if matches!(word.as_str(), "r" | "br" | "cr")
                    && matches!(after, Some('"' | '#'))
                    && let Some(end) = skip_raw_string(&chars, i, &mut line)
                {
                    i = end;
                    push(&mut tokens, Tok::Lit, start_line);
                } else if matches!(word.as_str(), "b" | "c") && after == Some('"') {
                    i = skip_string(&chars, i, &mut line);
                    push(&mut tokens, Tok::Lit, start_line);
                } else if word == "b" && after == Some('\'') {
                    // A byte literal: b'x', b'\n'.
                    let mut j = i + 1;
                    if chars.get(j) == Some(&'\\') {
                        j += 1;
                    }
                    j += 1;
                    while j < chars.len() && chars[j] != '\'' {
                        j += 1;
                    }
                    i = (j + 1).min(chars.len());
                    push(&mut tokens, Tok::Lit, start_line);
                } else if word == "r" && after == Some('#') {
                    // A raw identifier: r#allow is the identifier allow.
                    let name_start = i + 1;
                    if chars.get(name_start).copied().is_some_and(is_ident_start) {
                        i = name_start;
                        while i < chars.len() && is_ident_continue(chars[i]) {
                            i += 1;
                        }
                        let name: String = chars[name_start..i].iter().collect();
                        push(&mut tokens, Tok::Ident(name), start_line);
                    } else {
                        push(&mut tokens, Tok::Ident(word), start_line);
                    }
                } else {
                    push(&mut tokens, Tok::Ident(word), start_line);
                }
            }
            c if c.is_ascii_digit() => {
                let start = line;
                while i < chars.len() && (is_ident_continue(chars[i])) {
                    i += 1;
                }
                push(&mut tokens, Tok::Lit, start);
            }
            '(' | '[' | '{' => {
                push(&mut tokens, Tok::Open(c), line);
                i += 1;
            }
            ')' | ']' | '}' => {
                push(&mut tokens, Tok::Close(c), line);
                i += 1;
            }
            other => {
                push(&mut tokens, Tok::Punct(other), line);
                i += 1;
            }
        }
    }
    tokens
}

// ------------------------------------------------------------------------------------------
// Attributes
// ------------------------------------------------------------------------------------------

/// The index of the token that closes the group opened at `open`, if it closes.
fn matching(tokens: &[Token], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, token) in tokens.iter().enumerate().skip(open) {
        match token.tok {
            Tok::Open(_) => depth += 1,
            Tok::Close(_) => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Splits tokens at the commas that are not inside a group.
fn split_commas(tokens: &[Token]) -> Vec<&[Token]> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (index, token) in tokens.iter().enumerate() {
        match token.tok {
            Tok::Open(_) => depth += 1,
            Tok::Close(_) => depth = depth.saturating_sub(1),
            Tok::Punct(',') if depth == 0 => {
                parts.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < tokens.len() {
        parts.push(&tokens[start..]);
    }
    parts
}

/// A path such as `clippy::unwrap_used` at the start of `tokens`: its segments and the number of
/// tokens it takes.
fn read_path(tokens: &[Token]) -> (Vec<String>, usize) {
    let mut segments = Vec::new();
    let mut at = 0usize;
    loop {
        // An optional leading `::`.
        if segments.is_empty()
            && matches!(tokens.get(at).map(|t| &t.tok), Some(Tok::Punct(':')))
            && matches!(tokens.get(at + 1).map(|t| &t.tok), Some(Tok::Punct(':')))
        {
            at += 2;
        }
        let Some(Tok::Ident(name)) = tokens.get(at).map(|t| &t.tok) else {
            break;
        };
        segments.push(name.clone());
        at += 1;
        if matches!(tokens.get(at).map(|t| &t.tok), Some(Tok::Punct(':')))
            && matches!(tokens.get(at + 1).map(|t| &t.tok), Some(Tok::Punct(':')))
        {
            at += 2;
        } else {
            break;
        }
    }
    (segments, at)
}

/// Reads the inside of one attribute (what is between `[` and `]`, or one argument of a
/// `cfg_attr` after its condition).
fn attribute(tokens: &[Token], inner: bool, conditional: bool, line: u32, out: &mut Vec<Fact>) {
    let (path, used) = read_path(tokens);
    let [name] = path.as_slice() else {
        return;
    };
    let rest = &tokens[used..];
    let args = match rest.first().map(|t| &t.tok) {
        Some(Tok::Open('(')) => matching(rest, 0).map(|end| &rest[1..end]),
        _ => None,
    };
    let Some(args) = args else {
        return;
    };
    if name == "cfg_attr" {
        // The first argument is the condition. The others are attributes.
        for part in split_commas(args).into_iter().skip(1) {
            attribute(part, inner, true, line, out);
        }
        return;
    }
    let Some(level) = Level::of(name) else {
        return;
    };
    for part in split_commas(args) {
        let (lint, used) = read_path(part);
        if lint.is_empty() {
            continue;
        }
        // `reason = "..."` is not a lint.
        if lint.len() == 1
            && lint[0] == "reason"
            && matches!(part.get(used).map(|t| &t.tok), Some(Tok::Punct('=')))
        {
            continue;
        }
        out.push(Fact {
            level,
            lint: lint.join("::"),
            inner,
            conditional,
            line,
        });
    }
}

/// Every lint attribute in the source, in order of appearance.
#[must_use]
pub fn facts(source: &str) -> Vec<Fact> {
    let tokens = tokenize(source);
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < tokens.len() {
        if tokens[i].tok == Tok::Punct('#') {
            let mut j = i + 1;
            let inner = matches!(tokens.get(j).map(|t| &t.tok), Some(Tok::Punct('!')));
            if inner {
                j += 1;
            }
            if matches!(tokens.get(j).map(|t| &t.tok), Some(Tok::Open('[')))
                && let Some(end) = matching(&tokens, j)
            {
                attribute(&tokens[j + 1..end], inner, false, tokens[i].line, &mut out);
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

// ------------------------------------------------------------------------------------------
// Comparison
// ------------------------------------------------------------------------------------------

/// What a comparison found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// More suppressions of a lint than before.
    Suppressed {
        /// The line of the newest one.
        line: u32,
        /// True for an inner attribute.
        inner: bool,
        /// True when the lint is a whole group (`warnings`, `clippy::all`, ...).
        group: bool,
    },
    /// Fewer attributes at some level, for a lint, than before.
    Lowered,
}

/// The groups of lints: silencing one silences many.
const GROUPS: [&str; 9] = [
    "warnings",
    "clippy::all",
    "unused",
    "clippy::pedantic",
    "clippy::nursery",
    "clippy::restriction",
    "clippy::style",
    "clippy::correctness",
    "rust_2018_idioms",
];

#[derive(Default)]
struct Tally {
    suppress: u32,
    suppress_lines: Vec<u32>,
    /// Unconditional attributes at `warn` or stronger.
    warn_up: u32,
    /// Unconditional attributes at `deny` or stronger.
    deny_up: u32,
    /// Unconditional attributes at `forbid`.
    forbid: u32,
}

fn tally(facts: &[Fact]) -> BTreeMap<(bool, String), Tally> {
    let mut map: BTreeMap<(bool, String), Tally> = BTreeMap::new();
    for fact in facts {
        let entry = map.entry((fact.inner, fact.lint.clone())).or_default();
        if fact.level.suppresses() {
            entry.suppress += 1;
            entry.suppress_lines.push(fact.line);
            continue;
        }
        if fact.conditional {
            continue;
        }
        entry.warn_up += 1;
        if matches!(fact.level, Level::Deny | Level::Forbid) {
            entry.deny_up += 1;
        }
        if fact.level == Level::Forbid {
            entry.forbid += 1;
        }
    }
    map
}

/// Compares two versions of a source file.
#[must_use]
pub fn compare(before: &str, after: &str) -> Vec<Change> {
    let was = tally(&facts(before));
    let now = tally(&facts(after));
    let mut found = Vec::new();
    for ((inner, lint), tally) in &now {
        let had = was.get(&(*inner, lint.clone()));
        let had_suppress = had.map_or(0, |had| had.suppress);
        if tally.suppress > had_suppress {
            found.push(Change::Suppressed {
                line: tally.suppress_lines.last().copied().unwrap_or(1),
                inner: *inner,
                group: GROUPS.contains(&lint.as_str()),
            });
        }
    }
    for (key, had) in &was {
        let now = now.get(key);
        let (warn_up, deny_up, forbid) =
            now.map_or((0, 0, 0), |now| (now.warn_up, now.deny_up, now.forbid));
        if warn_up < had.warn_up || deny_up < had.deny_up || forbid < had.forbid {
            found.push(Change::Lowered);
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn levels(source: &str) -> Vec<(Level, &'static str, bool, bool)> {
        facts(source)
            .into_iter()
            .map(|fact| {
                let lint: &'static str = Box::leak(fact.lint.into_boxed_str());
                (fact.level, lint, fact.inner, fact.conditional)
            })
            .collect()
    }

    #[test]
    fn the_plain_forms_are_read() {
        assert_eq!(
            levels("#![allow(warnings)]\n#[expect(dead_code)] fn f() {}\n"),
            [
                (Level::Allow, "warnings", true, false),
                (Level::Expect, "dead_code", false, false)
            ]
        );
    }

    #[test]
    fn white_space_comments_and_newlines_between_the_tokens_do_not_hide_an_attribute() {
        for source in [
            "#![allow (warnings)]",
            "# ![allow(warnings)]",
            "#!  [  allow  (  warnings  )  ]",
            "#![\n    allow(warnings)\n]",
            "#\n!\n[\nallow\n(\nwarnings\n)\n]",
            "#/* a */![/* b */allow/* c */(warnings)]",
            "#![allow(// a line comment\nwarnings)]",
            "#![r#allow(warnings)]",
        ] {
            assert_eq!(
                levels(source),
                [(Level::Allow, "warnings", true, false)],
                "{source:?}"
            );
        }
    }

    #[test]
    fn an_attribute_after_code_or_in_a_macro_body_is_read() {
        assert_eq!(levels("fn a() {} #[allow(dead_code)] fn b() {}").len(), 1);
        assert_eq!(
            levels("macro_rules! m { () => { #[allow(dead_code)] fn f() {} }; }").len(),
            1
        );
        assert_eq!(
            levels("fn f() { let a = 1; #[allow(unused_variables)] let b = 2; }").len(),
            1
        );
    }

    #[test]
    fn comments_and_literals_are_skipped_whole() {
        for source in [
            "// #![allow(warnings)]\n",
            "/* #![allow(warnings)] */",
            "/* a /* nested #![allow(warnings)] */ still comment #![allow(x)] */",
            "/// #![allow(warnings)]\nfn f() {}",
            "let s = \"#![allow(warnings)]\";",
            "let s = \"quote \\\" #![allow(warnings)]\";",
            "let s = r\"#![allow(warnings)]\";",
            "let s = r#\"a \" #![allow(warnings)] \"#;",
            "let s = r##\"a \"# #![allow(warnings)] \"##;",
            "let s = b\"#![allow(warnings)]\";",
            "let c = '#'; let d = '\\''; let e = '\"';",
        ] {
            assert!(facts(source).is_empty(), "{source:?}");
        }
        // The text after a literal is read again.
        assert_eq!(
            levels("let c = '\"'; #![allow(warnings)]\n").len(),
            1,
            "a quote in a character literal does not open a string"
        );
        assert_eq!(
            levels("fn f<'a>(x: &'a str) {} #![allow(warnings)]").len(),
            1,
            "a lifetime does not open a character literal"
        );
    }

    #[test]
    fn a_cfg_attr_is_read_through_and_is_conditional() {
        assert_eq!(
            levels("#![cfg_attr(not(test), allow(unused), deny(missing_docs))]"),
            [
                (Level::Allow, "unused", true, true),
                (Level::Deny, "missing_docs", true, true)
            ]
        );
    }

    #[test]
    fn several_lints_a_reason_and_a_path_are_read() {
        assert_eq!(
            levels("#[allow(clippy::too_many_lines, dead_code, reason = \"generated\")]"),
            [
                (Level::Allow, "clippy::too_many_lines", false, false),
                (Level::Allow, "dead_code", false, false)
            ]
        );
    }

    #[test]
    fn other_attributes_are_not_lint_levels() {
        assert!(
            facts("#[derive(Debug)] #[cfg(test)] #[rustfmt::skip] #[doc = \"x\"] #![no_std]")
                .is_empty()
        );
        // A macro matcher is not an attribute.
        assert!(facts("macro_rules! m { ($(#[$meta:meta])*) => {}; }").is_empty());
    }

    #[test]
    fn a_new_suppression_is_found_and_an_unchanged_one_is_not() {
        assert!(compare("#![allow(unused)]\n", "#![allow(unused)]\nfn f() {}\n").is_empty());
        let found = compare("fn f() {}\n", "fn f() {}\n#[allow(dead_code)]\nfn g() {}\n");
        assert_eq!(
            found,
            [Change::Suppressed {
                line: 2,
                inner: false,
                group: false
            }]
        );
        // A second copy of the same suppression is new.
        assert!(
            !compare(
                "#[allow(dead_code)] fn a() {}",
                "#[allow(dead_code)] fn a() {} #[allow(dead_code)] fn b() {}"
            )
            .is_empty()
        );
        // A group is named as one.
        assert_eq!(
            compare("", "#![allow(warnings)]"),
            [Change::Suppressed {
                line: 1,
                inner: true,
                group: true
            }]
        );
    }

    #[test]
    fn a_lost_or_weakened_level_is_found_and_a_stronger_one_is_not() {
        let lowered = [
            ("#![deny(a, b)]", "#![deny(b)]"),
            ("#![forbid(unsafe_code)]", "#![deny(unsafe_code)]"),
            ("#![deny(warnings)]", "#![warn(warnings)]"),
            ("#![deny(warnings)]", ""),
            ("#![deny(warnings)]", "#![cfg_attr(test, deny(warnings))]"),
            ("#![deny(warnings)]", "#[deny(warnings)] fn f() {}"),
            ("#![warn(missing_docs)]", ""),
        ];
        for (before, after) in lowered {
            assert_eq!(
                compare(before, after),
                [Change::Lowered],
                "{before} -> {after}"
            );
        }
        let stronger = [
            ("#![warn(a)]", "#![deny(a)]"),
            ("#![deny(a)]", "#![forbid(a)]"),
            ("", "#![deny(a)] #![forbid(b)]"),
            ("#![allow(a)]", ""),
            ("#![allow(a)]", "#![deny(a)]"),
            ("#![deny(a)]", "#![deny(a, b)]"),
        ];
        for (before, after) in stronger {
            assert!(compare(before, after).is_empty(), "{before} -> {after}");
        }
    }

    #[test]
    fn the_line_of_an_attribute_counts_lines_inside_comments_and_strings() {
        let source = "/* one\ntwo */\nlet s = \"a\nb\";\n#![allow(x)]\n";
        assert_eq!(facts(source)[0].line, 5);
    }

    #[test]
    fn nothing_panics_on_odd_input() {
        for source in [
            "#",
            "#!",
            "#![",
            "#![allow(",
            "'",
            "\"",
            "r#\"",
            "b'",
            "/*",
            "#[allow(a, ,, b)]",
            "#[allow]",
            "#[allow = \"x\"]",
            "#[::allow(x)]",
            "\u{feff}#![allow(x)]",
        ] {
            let _ = facts(source);
        }
    }
}
