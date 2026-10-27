//! A small Rust lexer with token trees, enough for the source scans to stop guessing from text.
//!
//! xtask may use `std` and `serde_json` only (rules file, ADR 0002), so there is no `syn` here.
//! This module reads the token stream instead of the raw text, and from it answers the questions
//! the text scans got wrong in review finding F-12:
//!
//! * which items are test-only, decided from `#[cfg(...)]` and never from a file name,
//! * what a `use` declaration brings into scope, with groups, globs and `as` aliases,
//! * which paths a file mentions once aliases are resolved,
//! * which `allow` and `expect` attributes it carries.
//!
//! What it cannot do is expand macros, follow a path through a re-export in another file, or
//! evaluate a `const`. The README lists these limits.

use crate::scan::{block_comment_end, char_literal_end, is_ident};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Ident,
    Str,
    Punct,
    /// A number, a character literal or a lifetime.
    Other,
}

#[derive(Debug, Clone)]
pub struct Token {
    pub kind: Kind,
    /// Byte range in the source.
    pub start: usize,
    pub end: usize,
    /// The identifier, the single punctuation character, or the decoded string value.
    pub text: String,
}

/// A source file as tokens, with the matching closing delimiter of every opening one.
#[derive(Debug, Clone)]
pub struct Syntax {
    pub tokens: Vec<Token>,
    len: usize,
    close: Vec<usize>,
}

const NONE: usize = usize::MAX;

/// One item of a `use` declaration after groups are flattened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    /// The full path, `["std", "process", "Command"]`.
    pub path: Vec<String>,
    /// The name it is bound to (`Cmd` in `use std::process::Command as Cmd`). `None` for a glob
    /// and for `as _`.
    pub bound: Option<String>,
    pub glob: bool,
    pub at: usize,
}

/// A path written in code, such as `std::process::Command` or `Cmd`, with where it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathUse {
    pub segments: Vec<String>,
    pub at: usize,
    /// Index of the token after the path.
    pub next: usize,
}

/// An `allow` or `expect` attribute and the lints it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintAttribute {
    pub at: usize,
    /// `allow` or `expect`.
    pub level: String,
    pub lint: String,
}

/// A `mod name;` declaration (a module in another file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModDeclaration {
    pub name: String,
    /// The value of `#[path = "..."]`, if present.
    pub path_attribute: Option<String>,
    /// Inline modules that enclose the declaration, outermost first.
    pub inline_parents: Vec<String>,
    /// True when a `cfg` makes the declaration exist only in test builds.
    pub test_only: bool,
}

pub fn lex(source: &str) -> Syntax {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        let next = bytes.get(i + 1).copied();
        if b.is_ascii_whitespace() {
            i += 1;
        } else if b == b'/' && next == Some(b'/') {
            i += bytes[i..]
                .iter()
                .position(|c| *c == b'\n')
                .unwrap_or(bytes.len() - i);
        } else if b == b'/' && next == Some(b'*') {
            i = block_comment_end(bytes, i);
        } else if b == b'"' {
            let (value, end) = plain_string(source, i + 1);
            tokens.push(token(Kind::Str, i, end, value));
            i = end;
        } else if b == b'\'' {
            if let Some(end) = char_literal_end(source, i) {
                tokens.push(token(Kind::Other, i, end, String::new()));
                i = end;
            } else {
                let mut end = i + 1;
                while end < bytes.len() && is_ident(bytes[end]) {
                    end += 1;
                }
                tokens.push(token(Kind::Other, i, end, String::new()));
                i = end;
            }
        } else if b.is_ascii_digit() {
            let mut end = i;
            while end < bytes.len()
                && (is_ident(bytes[end])
                    || (bytes[end] == b'.' && bytes.get(end + 1).is_some_and(u8::is_ascii_digit)))
            {
                end += 1;
            }
            tokens.push(token(Kind::Other, i, end, String::new()));
            i = end;
        } else if is_ident(b) || b >= 0x80 {
            i = lex_word(source, i, &mut tokens);
        } else {
            tokens.push(token(Kind::Punct, i, i + 1, char::from(b).to_string()));
            i += 1;
        }
    }
    let close = match_delimiters(&tokens);
    Syntax {
        tokens,
        len: source.len(),
        close,
    }
}

fn token(kind: Kind, start: usize, end: usize, text: String) -> Token {
    Token {
        kind,
        start,
        end,
        text,
    }
}

/// An identifier, a raw identifier, or a string with a prefix (`b"`, `r#"`, `br"`, `c"`).
fn lex_word(source: &str, start: usize, tokens: &mut Vec<Token>) -> usize {
    let bytes = source.as_bytes();
    let mut end = start;
    while end < bytes.len() && (is_ident(bytes[end]) || bytes[end] >= 0x80) {
        end += 1;
    }
    let word = &source[start..end];
    let after = bytes.get(end).copied();
    let raw_capable = matches!(word, "r" | "br" | "cr");
    if matches!(word, "b" | "c") && after == Some(b'"') {
        let (value, stop) = plain_string(source, end + 1);
        tokens.push(token(Kind::Str, start, stop, value));
        return stop;
    }
    if word == "b" && after == Some(b'\'') {
        let stop = char_literal_end(source, end).unwrap_or(end + 1);
        tokens.push(token(Kind::Other, start, stop, String::new()));
        return stop;
    }
    if raw_capable && matches!(after, Some(b'"' | b'#')) {
        let hashes = bytes[end..].iter().take_while(|c| **c == b'#').count();
        if bytes.get(end + hashes) == Some(&b'"') {
            let body = end + hashes + 1;
            let mut j = body;
            while j < bytes.len() {
                if bytes[j] == b'"'
                    && bytes[j + 1..].iter().take(hashes).all(|c| *c == b'#')
                    && bytes.len() >= j + 1 + hashes
                {
                    let value = source[body..j].to_string();
                    let stop = j + 1 + hashes;
                    tokens.push(token(Kind::Str, start, stop, value));
                    return stop;
                }
                j += 1;
            }
            tokens.push(token(
                Kind::Str,
                start,
                bytes.len(),
                source[body..].to_string(),
            ));
            return bytes.len();
        }
        if word == "r" && hashes == 1 && bytes.get(end + 1).is_some_and(|c| is_ident(*c)) {
            // r#ident
            let mut stop = end + 1;
            while stop < bytes.len() && is_ident(bytes[stop]) {
                stop += 1;
            }
            tokens.push(token(
                Kind::Ident,
                start,
                stop,
                source[end + 1..stop].to_string(),
            ));
            return stop;
        }
    }
    tokens.push(token(Kind::Ident, start, end, word.to_string()));
    end
}

/// The decoded value of a string whose contents start at `from`, and the index after the quote.
fn plain_string(source: &str, from: usize) -> (String, usize) {
    let mut value = String::new();
    let mut chars = source[from..].char_indices();
    while let Some((offset, c)) = chars.next() {
        match c {
            '"' => return (value, from + offset + 1),
            '\\' => match chars.next() {
                Some((_, 'n')) => value.push('\n'),
                Some((_, 't')) => value.push('\t'),
                Some((_, 'r')) => value.push('\r'),
                Some((_, '0')) => value.push('\0'),
                Some((_, other)) => value.push(other),
                None => {}
            },
            other => value.push(other),
        }
    }
    (value, source.len())
}

fn match_delimiters(tokens: &[Token]) -> Vec<usize> {
    let mut close = vec![NONE; tokens.len()];
    let mut stack: Vec<usize> = Vec::new();
    for (i, t) in tokens.iter().enumerate() {
        if t.kind != Kind::Punct {
            continue;
        }
        match t.text.as_str() {
            "(" | "[" | "{" => stack.push(i),
            ")" | "]" | "}" => {
                let wanted = match t.text.as_str() {
                    ")" => "(",
                    "]" => "[",
                    _ => "{",
                };
                if let Some(at) = stack.iter().rposition(|o| tokens[*o].text == wanted) {
                    close[stack[at]] = i;
                    stack.truncate(at);
                }
            }
            _ => {}
        }
    }
    close
}

/// A fixed point on how a `cfg` predicate can come out when the `test` flag is off.
const CAN_BE_FALSE: u8 = 0b01;
const CAN_BE_TRUE: u8 = 0b10;

impl Syntax {
    pub fn is_punct(&self, i: usize, c: &str) -> bool {
        self.tokens
            .get(i)
            .is_some_and(|t| t.kind == Kind::Punct && t.text == c)
    }

    pub fn is_word(&self, i: usize, word: &str) -> bool {
        self.tokens
            .get(i)
            .is_some_and(|t| t.kind == Kind::Ident && t.text == word)
    }

    /// True when token `i` begins a `use` declaration. The `use<'a>` syntax of precise capturing
    /// and a field called `use` do not.
    fn is_use_item(&self, i: usize) -> bool {
        self.is_word(i, "use")
            && !self.is_punct(i.wrapping_sub(1), ".")
            && (self.ident_at(i + 1).is_some()
                || self.is_punct(i + 1, "{")
                || self.is_path_sep(i + 1))
    }

    fn ident_at(&self, i: usize) -> Option<&str> {
        self.tokens
            .get(i)
            .filter(|t| t.kind == Kind::Ident)
            .map(|t| t.text.as_str())
    }

    /// True when tokens `i` and `i + 1` are `::` written without a gap.
    pub fn is_path_sep(&self, i: usize) -> bool {
        self.is_punct(i, ":")
            && self.is_punct(i + 1, ":")
            && self.tokens[i].end == self.tokens[i + 1].start
    }

    fn close_of(&self, open: usize) -> usize {
        match self.close.get(open) {
            Some(c) if *c != NONE => *c,
            _ => self.tokens.len(),
        }
    }

    pub fn offset(&self, token: usize) -> usize {
        self.tokens.get(token).map_or(self.len, |t| t.start)
    }

    // -----------------------------------------------------------------------------------------
    // Attributes and cfg

    /// If token `i` starts an attribute, its parts: whether it is inner (`#!`), the index of the
    /// first token inside the brackets, and the index just after the closing bracket.
    fn attribute_at(&self, i: usize) -> Option<(bool, usize, usize)> {
        if !self.is_punct(i, "#") {
            return None;
        }
        let (inner, open) = if self.is_punct(i + 1, "!") {
            (true, i + 2)
        } else {
            (false, i + 1)
        };
        if !self.is_punct(open, "[") {
            return None;
        }
        let close = self.close_of(open);
        Some((inner, open + 1, (close + 1).min(self.tokens.len())))
    }

    /// Evaluate a `cfg` predicate that starts at token `i`. Returns what values it can take when
    /// the `test` flag is off and every other flag is unknown, and the index after it.
    fn cfg_value(&self, i: usize) -> (u8, usize) {
        let unknown = CAN_BE_FALSE | CAN_BE_TRUE;
        let Some(name) = self.ident_at(i) else {
            return (unknown, i + 1);
        };
        if !self.is_punct(i + 1, "(") {
            if name == "test" {
                return (CAN_BE_FALSE, i + 1);
            }
            // `feature = "x"` and plain flags can be either.
            let next = if self.is_punct(i + 1, "=") {
                i + 3
            } else {
                i + 1
            };
            return (unknown, next);
        }
        let close = self.close_of(i + 1);
        let mut values = Vec::new();
        let mut j = i + 2;
        while j < close {
            let before = j;
            let (v, next) = self.cfg_value(j);
            values.push(v);
            j = if self.is_punct(next, ",") {
                next + 1
            } else {
                next
            };
            j = j.max(before + 1);
        }
        let result = match name {
            "not" => values.first().map_or(unknown, |v| {
                let mut r = 0;
                if v & CAN_BE_FALSE != 0 {
                    r |= CAN_BE_TRUE;
                }
                if v & CAN_BE_TRUE != 0 {
                    r |= CAN_BE_FALSE;
                }
                r
            }),
            "all" => {
                let mut r = 0;
                if values.iter().all(|v| v & CAN_BE_TRUE != 0) {
                    r |= CAN_BE_TRUE;
                }
                if values.iter().any(|v| v & CAN_BE_FALSE != 0) {
                    r |= CAN_BE_FALSE;
                }
                r
            }
            "any" => {
                let mut r = 0;
                if values.iter().any(|v| v & CAN_BE_TRUE != 0) {
                    r |= CAN_BE_TRUE;
                }
                if values.iter().all(|v| v & CAN_BE_FALSE != 0) {
                    r |= CAN_BE_FALSE;
                }
                r
            }
            _ => unknown,
        };
        (result, close + 1)
    }

    /// True for `#[cfg(...)]` content (starting at token `from`) that is false in every build
    /// that is not a test build: `cfg(test)`, `cfg(all(test, x))`, `cfg(not(not(test)))`.
    /// `cfg(any(test, x))` and `cfg(not(test))` can be true in a production build, so they are not.
    fn is_test_only_cfg(&self, from: usize) -> bool {
        if !self.is_word(from, "cfg") || !self.is_punct(from + 1, "(") {
            return false;
        }
        let (value, _) = self.cfg_value(from + 2);
        value & CAN_BE_TRUE == 0
    }

    /// Byte ranges of the items that exist only in test builds, and whether the whole file does
    /// (an inner `#![cfg(test)]`).
    pub fn test_ranges(&self) -> (Vec<(usize, usize)>, bool) {
        let mut ranges = Vec::new();
        let mut limits: Vec<usize> = Vec::new();
        let mut i = 0;
        while i < self.tokens.len() {
            while limits.last().is_some_and(|l| *l <= i) {
                limits.pop();
            }
            if let Some((inner, content, after)) = self.attribute_at(i) {
                if self.is_test_only_cfg(content) {
                    if inner {
                        let Some(limit) = limits.last() else {
                            return (vec![(0, self.len)], true);
                        };
                        ranges.push((self.offset(i), self.offset(*limit)));
                        i = *limit;
                        continue;
                    }
                    let limit = limits.last().copied().unwrap_or(self.tokens.len());
                    let end = self.element_end(after, limit);
                    ranges.push((self.offset(i), self.tokens[end - 1].end));
                    i = end;
                    continue;
                }
                i = after;
                continue;
            }
            if matches!(self.tokens[i].text.as_str(), "(" | "[" | "{")
                && self.tokens[i].kind == Kind::Punct
            {
                limits.push(self.close_of(i));
            }
            i += 1;
        }
        (ranges, false)
    }

    /// The index just after the element that an attribute annotates, bounded by `limit`, the
    /// closing delimiter of the enclosing group. The element is never allowed to run past the
    /// group it sits in, so a `#[cfg(test)]` on a struct field cannot hide the code after it.
    fn element_end(&self, from: usize, limit: usize) -> usize {
        let mut i = from;
        // Further attributes stack on the same element.
        while let Some((_, _, after)) = self.attribute_at(i) {
            i = after;
        }
        let first = self.ident_at(i).unwrap_or_default().to_string();
        let item_like = matches!(
            first.as_str(),
            "fn" | "mod"
                | "use"
                | "impl"
                | "struct"
                | "enum"
                | "trait"
                | "const"
                | "static"
                | "type"
                | "extern"
                | "unsafe"
                | "async"
                | "pub"
                | "macro_rules"
                | "union"
                | "let"
        );
        let initializer = matches!(first.as_str(), "const" | "static" | "let");
        let mut seen_equals = false;
        while i < limit.min(self.tokens.len()) {
            let t = &self.tokens[i];
            if t.kind == Kind::Punct {
                match t.text.as_str() {
                    ";" => return i + 1,
                    "," if !item_like => return i + 1,
                    "=" if initializer && !self.is_punct(i + 1, ">") => seen_equals = true,
                    "(" | "[" => {
                        i = self.close_of(i) + 1;
                        continue;
                    }
                    "{" => {
                        let mut end = self.close_of(i) + 1;
                        if initializer && seen_equals {
                            i = end;
                            continue;
                        }
                        if self.is_punct(end, ";") || (!item_like && self.is_punct(end, ",")) {
                            end += 1;
                        }
                        return end.min(limit.max(from));
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        i.min(limit).min(self.tokens.len()).max(from)
    }

    /// The names of the functions marked `#[test]`, `#[tokio::test]` or another `...::test`.
    /// `#[cfg(test)]` does not make a function a test.
    pub fn test_function_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        let mut i = 0;
        while i < self.tokens.len() {
            let Some((false, content, after)) = self.attribute_at(i) else {
                i += 1;
                continue;
            };
            // The attribute path: `test`, or `tokio::test`, followed by `(` or the end.
            let (path, next) = self.plain_path(content);
            let marks_a_test = path.last().is_some_and(|last| last == "test")
                && (self.is_punct(next, "]") || self.is_punct(next, "("));
            i = after;
            if !marks_a_test {
                continue;
            }
            let mut j = after;
            while let Some((_, _, further)) = self.attribute_at(j) {
                j = further;
            }
            for _ in 0..8 {
                if self.is_word(j, "fn") {
                    if let Some(name) = self.ident_at(j + 1) {
                        names.push(name.to_string());
                    }
                    break;
                }
                j += 1;
            }
        }
        names
    }

    // -----------------------------------------------------------------------------------------
    // Modules

    /// Every `mod name;` declaration, and the inline modules around it.
    pub fn mod_declarations(&self) -> Vec<ModDeclaration> {
        let (ranges, _) = self.test_ranges();
        let in_test = |offset: usize| ranges.iter().any(|(s, e)| offset >= *s && offset < *e);
        let mut found = Vec::new();
        let mut parents: Vec<(usize, String)> = Vec::new();
        for (i, t) in self.tokens.iter().enumerate() {
            while parents.last().is_some_and(|(close, _)| *close <= i) {
                parents.pop();
            }
            if !(t.kind == Kind::Ident && t.text == "mod") || self.is_path_sep(i.wrapping_sub(2)) {
                continue;
            }
            let Some(name) = self.ident_at(i + 1) else {
                continue;
            };
            if self.is_punct(i + 2, "{") {
                parents.push((self.close_of(i + 2), name.to_string()));
            } else if self.is_punct(i + 2, ";") {
                found.push(ModDeclaration {
                    name: name.to_string(),
                    path_attribute: self.path_attribute_before(i),
                    inline_parents: parents.iter().map(|(_, n)| n.clone()).collect(),
                    test_only: in_test(t.start),
                });
            }
        }
        found
    }

    /// The `#[path = "..."]` attribute among the attributes written directly before token `i`
    /// (a `mod`, or the `pub` in front of it).
    fn path_attribute_before(&self, i: usize) -> Option<String> {
        let mut start = i;
        while start > 0 && self.is_word(start - 1, "pub") {
            start -= 1;
        }
        while start > 0 && self.is_punct(start - 1, "]") {
            let open = (0..start - 1)
                .rev()
                .find(|j| self.is_punct(*j, "[") && self.close_of(*j) == start - 1)?;
            if self.is_word(open + 1, "path") && self.is_punct(open + 2, "=") {
                return self
                    .tokens
                    .get(open + 3)
                    .filter(|t| t.kind == Kind::Str)
                    .map(|t| t.text.clone());
            }
            if open == 0 || !self.is_punct(open - 1, "#") {
                break;
            }
            start = open - 1;
        }
        None
    }

    /// The literal paths of `include!("...")` calls.
    pub fn includes(&self) -> Vec<String> {
        let mut found = Vec::new();
        for i in 0..self.tokens.len() {
            if self.is_word(i, "include")
                && self.is_punct(i + 1, "!")
                && self.is_punct(i + 2, "(")
                && let Some(t) = self.tokens.get(i + 3).filter(|t| t.kind == Kind::Str)
            {
                found.push(t.text.clone());
            }
        }
        found
    }

    // -----------------------------------------------------------------------------------------
    // Imports and paths

    /// Every `use` item, flattened, and every `extern crate x as y` and `type A = a::b::C;` alias,
    /// which bind a name in the same way.
    pub fn imports(&self) -> Vec<Import> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.tokens.len() {
            if self.is_use_item(i) {
                let next = self.use_tree(i + 1, &[], &mut out);
                i = next.max(i + 1);
            } else if self.is_word(i, "extern") && self.is_word(i + 1, "crate") {
                if let (Some(name), true) = (self.ident_at(i + 2), self.is_word(i + 3, "as"))
                    && let Some(alias) = self.ident_at(i + 4)
                {
                    out.push(Import {
                        path: vec![name.to_string()],
                        bound: Some(alias.to_string()),
                        glob: false,
                        at: self.offset(i),
                    });
                }
                i += 2;
            } else if self.is_word(i, "type")
                && self.ident_at(i + 1).is_some()
                && self.is_punct(i + 2, "=")
            {
                let (segments, next) = self.plain_path(i + 3);
                if !segments.is_empty() && self.is_punct(next, ";") {
                    out.push(Import {
                        path: segments,
                        bound: self.ident_at(i + 1).map(str::to_string),
                        glob: false,
                        at: self.offset(i),
                    });
                }
                i += 1;
            } else {
                i += 1;
            }
        }
        out
    }

    /// A path of identifiers joined by `::` from token `i`; stops at anything else.
    fn plain_path(&self, mut i: usize) -> (Vec<String>, usize) {
        let mut segments = Vec::new();
        if self.is_path_sep(i) {
            i += 2;
        }
        while let Some(name) = self.ident_at(i) {
            segments.push(name.to_string());
            if self.is_path_sep(i + 1) && self.ident_at(i + 3).is_some() {
                i += 3;
            } else {
                return (segments, i + 1);
            }
        }
        (segments, i)
    }

    /// Parse one use tree starting at token `i`. Returns the index after it.
    fn use_tree(&self, mut i: usize, prefix: &[String], out: &mut Vec<Import>) -> usize {
        let mut path = prefix.to_vec();
        if self.is_path_sep(i) {
            i += 2;
        }
        loop {
            if self.is_punct(i, "{") {
                let close = self.close_of(i);
                let mut j = i + 1;
                while j < close {
                    j = self.use_tree(j, &path, out);
                    if self.is_punct(j, ",") {
                        j += 1;
                    } else if j < close {
                        j += 1; // never loop on a token this parser does not understand
                    }
                }
                return close + 1;
            }
            if self.is_punct(i, "*") {
                out.push(Import {
                    path,
                    bound: None,
                    glob: true,
                    at: self.offset(i),
                });
                return i + 1;
            }
            let Some(segment) = self.ident_at(i) else {
                return i + 1;
            };
            if self.is_path_sep(i + 1) {
                path.push(segment.to_string());
                i += 3;
                continue;
            }
            let mut bound = Some(segment.to_string());
            let mut next = i + 1;
            if segment == "self" {
                bound = path.last().cloned();
            } else {
                path.push(segment.to_string());
            }
            if self.is_word(i + 1, "as")
                && let Some(alias) = self.ident_at(i + 2)
            {
                bound = (alias != "_").then(|| alias.to_string());
                next = i + 3;
            }
            out.push(Import {
                path,
                bound,
                glob: false,
                at: self.offset(i),
            });
            return next;
        }
    }

    /// Paths written in code outside `use` items: `Cmd::new`, `std::process::Command`, `fs::read`.
    pub fn path_uses(&self) -> Vec<PathUse> {
        let mut found = Vec::new();
        let mut i = 0;
        while i < self.tokens.len() {
            if self.is_use_item(i) {
                // Skip the whole item: imports are analysed on their own.
                while i < self.tokens.len() && !self.is_punct(i, ";") {
                    i = if self.is_punct(i, "{") {
                        self.close_of(i) + 1
                    } else {
                        i + 1
                    };
                }
                continue;
            }
            let Some(name) = self.ident_at(i) else {
                i += 1;
                continue;
            };
            let follows_dot = self.is_punct(i.wrapping_sub(1), ".");
            let continues_path =
                i >= 2 && self.is_path_sep(i - 2) && self.ident_at(i.wrapping_sub(3)).is_some();
            if follows_dot || continues_path {
                i += 1;
                continue;
            }
            let (mut segments, mut next) = (vec![name.to_string()], i + 1);
            while self.is_path_sep(next) && self.ident_at(next + 2).is_some() {
                segments.push(self.tokens[next + 2].text.clone());
                next += 3;
            }
            found.push(PathUse {
                segments,
                at: self.tokens[i].start,
                next,
            });
            i = next;
        }
        found
    }

    // -----------------------------------------------------------------------------------------
    // Lint attributes

    /// Every `allow(...)` and `expect(...)` attribute, including the ones inside
    /// `cfg_attr(<condition>, allow(...))`, with one entry for each lint they name.
    pub fn lint_attributes(&self) -> Vec<LintAttribute> {
        let mut found = Vec::new();
        for i in 0..self.tokens.len() {
            let Some((_, content, after)) = self.attribute_at(i) else {
                continue;
            };
            for j in content..after.saturating_sub(1) {
                let Some(level) = self
                    .ident_at(j)
                    .filter(|l| matches!(*l, "allow" | "expect"))
                else {
                    continue;
                };
                if !self.is_punct(j + 1, "(") {
                    continue;
                }
                let close = self.close_of(j + 1);
                let mut k = j + 2;
                while k < close {
                    let (segments, next) = self.plain_path(k);
                    if !segments.is_empty() && !self.is_punct(next, "=") {
                        found.push(LintAttribute {
                            at: self.tokens[k].start,
                            level: level.to_string(),
                            lint: segments.join("::"),
                        });
                    }
                    // Skip a `reason = "..."` argument or anything else up to the next comma.
                    k = next.max(k + 1);
                    while k < close && !self.is_punct(k, ",") {
                        k = if matches!(self.tokens[k].text.as_str(), "(" | "[" | "{") {
                            self.close_of(k) + 1
                        } else {
                            k + 1
                        };
                    }
                    k += 1;
                }
            }
        }
        found
    }
}

/// What the names of a file stand for after its `use`, `extern crate` and `type` items are
/// applied. One table per file, with no scoping: a name bound anywhere in the file counts
/// everywhere in it, which can only add findings, never hide one.
#[derive(Debug, Default)]
pub struct Resolver {
    aliases: std::collections::BTreeMap<String, Vec<String>>,
    globs: Vec<Vec<String>>,
}

impl Resolver {
    pub fn new(syntax: &Syntax) -> Self {
        let mut resolver = Self::default();
        for import in syntax.imports() {
            if import.glob {
                resolver.globs.push(import.path);
            } else if let Some(bound) = import.bound
                && import.path != [bound.clone()]
            {
                resolver.aliases.insert(bound, import.path);
            }
        }
        resolver
    }

    /// The full paths a written path can stand for: first with its leading name replaced by what
    /// it was imported as (repeatedly, for chains of aliases), then, for a name that nothing
    /// imports by name, once for each glob import that could supply it.
    pub fn candidates(&self, segments: &[String]) -> Vec<Vec<String>> {
        let Some(first) = segments.first() else {
            return Vec::new();
        };
        let mut current = segments.to_vec();
        let mut imported = false;
        for _ in 0..8 {
            match self.aliases.get(&current[0]) {
                Some(target) => {
                    current.splice(0..1, target.iter().cloned());
                    imported = true;
                }
                None => break,
            }
        }
        let mut found = vec![current];
        if !imported
            && !matches!(
                first.as_str(),
                "std" | "core" | "alloc" | "crate" | "self" | "super"
            )
        {
            for glob in &self.globs {
                found.push(
                    glob.iter()
                        .cloned()
                        .chain(segments.iter().cloned())
                        .collect(),
                );
            }
        }
        found
    }
}

/// True when `path` is `prefix` or goes below it, segment by segment.
pub fn is_under(path: &[String], prefix: &str) -> bool {
    let wanted: Vec<&str> = prefix.split("::").collect();
    path.len() >= wanted.len() && path.iter().zip(&wanted).all(|(a, b)| a == b)
}

/// True when `path` ends with the segments of `suffix` (`fs::read` for `std::fs::read`).
pub fn ends_with(path: &[String], suffix: &[&str]) -> bool {
    path.len() >= suffix.len()
        && path[path.len() - suffix.len()..]
            .iter()
            .zip(suffix)
            .all(|(a, b)| a == *b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges_text(source: &str) -> Vec<String> {
        let syntax = lex(source);
        let (ranges, _) = syntax.test_ranges();
        ranges
            .iter()
            .map(|(s, e)| source[*s..*e].to_string())
            .collect()
    }

    #[test]
    fn a_cfg_test_module_is_one_range() {
        let r =
            ranges_text("fn a() {}\n#[cfg(test)]\nmod tests { fn t() { if true {} } }\nfn b() {}");
        assert_eq!(r, ["#[cfg(test)]\nmod tests { fn t() { if true {} } }"]);
    }

    #[test]
    fn a_cfg_test_field_does_not_hide_the_next_function() {
        let source = "struct S {\n    #[cfg(test)]\n    a: u8,\n    b: u8,\n}\nfn production() { danger(); }\n";
        let r = ranges_text(source);
        assert_eq!(r.len(), 1);
        assert!(!r[0].contains("production"), "{r:?}");
    }

    #[test]
    fn a_cfg_test_match_arm_does_not_hide_the_next_arm() {
        let source =
            "fn f(x: u8) { match x {\n #[cfg(test)]\n 1 => helper(),\n _ => danger(),\n } }";
        let r = ranges_text(source);
        assert_eq!(r.len(), 1);
        assert!(!r[0].contains("danger"), "{r:?}");
    }

    #[test]
    fn a_cfg_test_enum_variant_and_parameter_end_at_the_comma() {
        let r = ranges_text("enum E { #[cfg(test)] A(u8), B }\nfn f(#[cfg(test)] x: u8, y: u8) {}");
        assert_eq!(r, ["#[cfg(test)] A(u8),", "#[cfg(test)] x: u8,"]);
    }

    #[test]
    fn a_cfg_test_statement_ends_at_its_semicolon() {
        let r = ranges_text("fn f() { #[cfg(test)] let x = Foo { a: 1 }; real(); }");
        assert_eq!(r, ["#[cfg(test)] let x = Foo { a: 1 };"]);
    }

    #[test]
    fn production_cfgs_are_not_test_only() {
        for cfg in [
            "cfg(not(test))",
            "cfg(any(test, feature = \"x\"))",
            "cfg(feature = \"x\")",
            "cfg(unix)",
        ] {
            assert!(
                ranges_text(&format!("#[{cfg}]\nfn f() {{}}")).is_empty(),
                "{cfg}"
            );
        }
        for cfg in [
            "cfg(test)",
            "cfg(all(test, feature = \"x\"))",
            "cfg(not(not(test)))",
        ] {
            assert_eq!(
                ranges_text(&format!("#[{cfg}]\nfn f() {{}}")).len(),
                1,
                "{cfg}"
            );
        }
    }

    #[test]
    fn an_inner_cfg_test_makes_the_whole_file_test_only() {
        let (ranges, whole) = lex("#![cfg(test)]\nfn t() {}").test_ranges();
        assert!(whole && ranges.len() == 1);
    }

    #[test]
    fn use_groups_globs_and_aliases_are_flattened() {
        let syntax = lex(
            "use std::{process::{Command as Cmd, Stdio}, fs::{self, File}};\nuse ::tokio::process::*;\nuse a::b as _;",
        );
        let imports = syntax.imports();
        let shown: Vec<String> = imports
            .iter()
            .map(|i| {
                format!(
                    "{}={:?}{}",
                    i.path.join("::"),
                    i.bound,
                    if i.glob { "*" } else { "" }
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                "std::process::Command=Some(\"Cmd\")",
                "std::process::Stdio=Some(\"Stdio\")",
                "std::fs=Some(\"fs\")",
                "std::fs::File=Some(\"File\")",
                "tokio::process=None*",
                "a::b=None",
            ]
        );
    }

    #[test]
    fn extern_crate_and_type_aliases_bind_names() {
        let imports = lex("extern crate std as s;\ntype C = std::process::Command;").imports();
        assert_eq!(imports[0].bound.as_deref(), Some("s"));
        assert_eq!(imports[1].path, ["std", "process", "Command"]);
        assert_eq!(imports[1].bound.as_deref(), Some("C"));
    }

    #[test]
    fn paths_in_code_skip_use_items_and_method_calls() {
        let syntax = lex(
            "use std::fs;\nfn f() { fs::read(\"x\"); x.fs::y(); std::process::Command::new(\"a\"); }",
        );
        let paths: Vec<String> = syntax
            .path_uses()
            .iter()
            .map(|p| p.segments.join("::"))
            .collect();
        assert!(paths.contains(&"fs::read".to_string()));
        assert!(paths.contains(&"std::process::Command::new".to_string()));
        assert!(!paths.contains(&"std::fs".to_string()));
    }

    #[test]
    fn lint_attributes_are_found_in_every_spelling() {
        let source = "#![allow(clippy::all)]\n#[allow(dead_code, clippy::disallowed_methods)]\n#[expect(warnings, reason = \"x, y\")]\n#[cfg_attr(unix, allow(clippy::disallowed_types))]\nfn f() {}";
        let found: Vec<String> = lex(source)
            .lint_attributes()
            .iter()
            .map(|a| format!("{} {}", a.level, a.lint))
            .collect();
        assert_eq!(
            found,
            [
                "allow clippy::all",
                "allow dead_code",
                "allow clippy::disallowed_methods",
                "expect warnings",
                "allow clippy::disallowed_types"
            ]
        );
    }

    #[test]
    fn module_declarations_carry_cfg_path_and_parents() {
        let source = "mod plain;\n#[cfg(test)]\nmod tests;\n#[path = \"x/y.rs\"]\nmod moved;\nmod outer { mod inner; }\nmod inline_only { }";
        let mods = lex(source).mod_declarations();
        let shown: Vec<String> = mods
            .iter()
            .map(|m| {
                format!(
                    "{} test={} path={:?} in={:?}",
                    m.name, m.test_only, m.path_attribute, m.inline_parents
                )
            })
            .collect();
        assert_eq!(
            shown,
            [
                "plain test=false path=None in=[]",
                "tests test=true path=None in=[]",
                "moved test=false path=Some(\"x/y.rs\") in=[]",
                "inner test=false path=None in=[\"outer\"]",
            ]
        );
    }

    #[test]
    fn strings_raw_strings_and_lifetimes_do_not_confuse_the_lexer() {
        let syntax =
            lex("let a = r#\"x \" y\"#; let b = b\"z\"; fn f<'a>(x: &'a str) {} let c = '\\'';");
        let strings: Vec<&str> = syntax
            .tokens
            .iter()
            .filter(|t| t.kind == Kind::Str)
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(strings, ["x \" y", "z"]);
    }
}
