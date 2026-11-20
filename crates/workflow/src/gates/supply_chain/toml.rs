//! A small reader for the part of TOML that `Cargo.lock`, `Cargo.toml` and `.cargo/config.toml`
//! use.
//!
//! This crate may not depend on a TOML crate (`docs/architecture/crate-dependency-rules.json`
//! lists the external crates of `workflow`), and the dependency gate has to read files that an
//! untrusted builder wrote. So the reader is written to **refuse** rather than to guess:
//!
//! * a duplicate key or a table defined twice is an error (cargo refuses it too);
//! * anything the grammar below does not name is an error, never a skipped line;
//! * the input size and the nesting depth are bounded.
//!
//! A reader that accepts less than cargo only makes the gate stricter. A reader that accepted
//! more could let a file through that cargo reads differently, which is why every unknown token
//! ends the parse.
//!
//! The grammar: comments, `[table]` and `[[array-of-tables]]` headers with dotted and quoted
//! keys, `key = value` lines with dotted keys, basic and literal strings (also the multi-line
//! forms), integers, floats, booleans, date-times (kept as text), arrays (which may span lines)
//! and inline tables.

use std::collections::{BTreeMap, BTreeSet};

/// The largest document read, in bytes. A `Cargo.lock` of a large workspace is a few megabytes.
pub const MAX_BYTES: usize = 8 * 1024 * 1024;

/// The deepest nesting of arrays and inline tables read.
const MAX_DEPTH: usize = 32;

/// A table of key and value.
pub type Table = BTreeMap<String, Value>;

/// A value of the document.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A string, with escapes resolved.
    Str(String),
    /// An integer.
    Int(i64),
    /// A float.
    Float(f64),
    /// A boolean.
    Bool(bool),
    /// A date or time, kept as written.
    Date(String),
    /// An array.
    Array(Vec<Value>),
    /// A table.
    Table(Table),
}

impl Value {
    /// The text, for a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            _ => None,
        }
    }

    /// The table, for a table.
    #[must_use]
    pub fn as_table(&self) -> Option<&Table> {
        match self {
            Self::Table(table) => Some(table),
            _ => None,
        }
    }

    /// The items, for an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The boolean, for a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(flag) => Some(*flag),
            _ => None,
        }
    }

    /// The integer, for an integer.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(number) => Some(*number),
            _ => None,
        }
    }

    /// A one-line text of the value for comparison and display. Strings are quoted, tables and
    /// arrays are written in key order, so two equal values give the same text.
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::Str(text) => format!("{text:?}"),
            Self::Int(number) => number.to_string(),
            Self::Float(number) => format!("{number:?}"),
            Self::Bool(flag) => flag.to_string(),
            Self::Date(text) => text.clone(),
            Self::Array(items) => {
                let parts: Vec<String> = items.iter().map(Self::canonical).collect();
                format!("[{}]", parts.join(","))
            }
            Self::Table(table) => {
                let parts: Vec<String> = table
                    .iter()
                    .map(|(key, value)| format!("{key:?}={}", value.canonical()))
                    .collect();
                format!("{{{}}}", parts.join(","))
            }
        }
    }
}

/// Why a document was refused. The set is closed and holds no text of the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TomlError {
    /// The document is larger than [`MAX_BYTES`].
    #[error("the document is too large")]
    TooLarge,
    /// Arrays or inline tables are nested too deep.
    #[error("the document is nested too deep")]
    TooDeep,
    /// A key is defined twice, or a table is defined twice.
    #[error("a key or table is defined twice (line {0})")]
    Duplicate(usize),
    /// The text breaks the grammar.
    #[error("the text is not valid TOML (line {0})")]
    Syntax(usize),
}

/// Reads a document.
///
/// # Errors
/// [`TomlError`] for the first problem found.
pub fn parse(text: &str) -> Result<Table, TomlError> {
    if text.len() > MAX_BYTES {
        return Err(TomlError::TooLarge);
    }
    Reader::new(text).document()
}

struct Reader {
    chars: Vec<char>,
    at: usize,
    line: usize,
}

type Res<T> = Result<T, TomlError>;

impl Reader {
    fn new(text: &str) -> Self {
        Self {
            chars: text
                .strip_prefix('\u{feff}')
                .unwrap_or(text)
                .chars()
                .collect(),
            at: 0,
            line: 1,
        }
    }

    fn syntax<T>(&self) -> Res<T> {
        Err(TomlError::Syntax(self.line))
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.at).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.at + offset).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.at += 1;
        if c == '\n' {
            self.line += 1;
        }
        Some(c)
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn starts_with(&self, text: &str) -> bool {
        text.chars()
            .enumerate()
            .all(|(offset, c)| self.peek_at(offset) == Some(c))
    }

    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t')) {
            self.bump();
        }
    }

    fn skip_comment(&mut self) {
        if self.peek() == Some('#') {
            while !matches!(self.peek(), Some('\n') | None) {
                self.bump();
            }
        }
    }

    /// Blanks, comments and line breaks: what may sit between items of an array.
    fn skip_space(&mut self) {
        loop {
            self.skip_blanks();
            match self.peek() {
                Some('#') => self.skip_comment(),
                Some('\n') => {
                    self.bump();
                }
                Some('\r') if self.peek_at(1) == Some('\n') => {
                    self.bump();
                }
                _ => return,
            }
        }
    }

    fn end_of_line(&mut self) -> Res<()> {
        self.skip_blanks();
        self.skip_comment();
        match self.peek() {
            None => Ok(()),
            Some('\n') => {
                self.bump();
                Ok(())
            }
            Some('\r') if self.peek_at(1) == Some('\n') => {
                self.bump();
                self.bump();
                Ok(())
            }
            _ => self.syntax(),
        }
    }

    fn document(mut self) -> Res<Table> {
        let mut root = Table::new();
        let mut path: Vec<String> = Vec::new();
        let mut defined: BTreeSet<Vec<String>> = BTreeSet::new();
        loop {
            self.skip_space();
            let Some(c) = self.peek() else {
                return Ok(root);
            };
            if c == '[' {
                self.bump();
                let array = self.eat('[');
                self.skip_blanks();
                let keys = self.key_path()?;
                self.skip_blanks();
                if !self.eat(']') || (array && !self.eat(']')) {
                    return self.syntax();
                }
                self.end_of_line()?;
                if array {
                    open_array_table(&mut root, &keys, self.line)?;
                } else {
                    if !defined.insert(keys.clone()) {
                        return Err(TomlError::Duplicate(self.line));
                    }
                    open_table(&mut root, &keys, self.line)?;
                }
                path = keys;
            } else {
                let keys = self.key_path()?;
                self.skip_blanks();
                if !self.eat('=') {
                    return self.syntax();
                }
                self.skip_blanks();
                let value = self.value(0)?;
                self.end_of_line()?;
                let line = self.line;
                let table = descend(&mut root, &path, line)?;
                insert_dotted(table, &keys, value, line)?;
            }
        }
    }

    fn key_path(&mut self) -> Res<Vec<String>> {
        let mut keys = vec![self.key()?];
        loop {
            self.skip_blanks();
            if self.peek() != Some('.') {
                return Ok(keys);
            }
            self.bump();
            self.skip_blanks();
            keys.push(self.key()?);
        }
    }

    fn key(&mut self) -> Res<String> {
        match self.peek() {
            Some('"') => self.basic_string(),
            Some('\'') => self.literal_string(),
            Some(c) if is_bare(c) => {
                let mut key = String::new();
                while let Some(c) = self.peek().filter(|c| is_bare(*c)) {
                    key.push(c);
                    self.bump();
                }
                Ok(key)
            }
            _ => self.syntax(),
        }
    }

    fn value(&mut self, depth: usize) -> Res<Value> {
        if depth > MAX_DEPTH {
            return Err(TomlError::TooDeep);
        }
        match self.peek() {
            Some('"') => {
                if self.starts_with("\"\"\"") {
                    self.multiline_basic().map(Value::Str)
                } else {
                    self.basic_string().map(Value::Str)
                }
            }
            Some('\'') => {
                if self.starts_with("'''") {
                    self.multiline_literal().map(Value::Str)
                } else {
                    self.literal_string().map(Value::Str)
                }
            }
            Some('[') => self.array(depth),
            Some('{') => self.inline_table(depth),
            Some(_) => self.scalar(),
            None => self.syntax(),
        }
    }

    fn scalar(&mut self) -> Res<Value> {
        let mut token = String::new();
        while let Some(c) = self.peek() {
            let part_of_date = c == ' ' && !token.is_empty() && self.date_time_continues(&token);
            if matches!(c, ',' | ']' | '}' | '#' | '\n' | '\r' | '\t')
                || (c == ' ' && !part_of_date)
            {
                break;
            }
            token.push(c);
            self.bump();
        }
        classify(&token).map_or_else(|| self.syntax(), Ok)
    }

    /// `1979-05-27 07:32:00Z` has a space between the date and the time.
    fn date_time_continues(&self, token: &str) -> bool {
        token.len() == 10
            && token.chars().filter(|c| *c == '-').count() == 2
            && self.peek_at(1).is_some_and(|c| c.is_ascii_digit())
    }

    fn array(&mut self, depth: usize) -> Res<Value> {
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_space();
            if self.eat(']') {
                return Ok(Value::Array(items));
            }
            items.push(self.value(depth + 1)?);
            self.skip_space();
            if self.eat(',') {
                continue;
            }
            self.skip_space();
            if self.eat(']') {
                return Ok(Value::Array(items));
            }
            return self.syntax();
        }
    }

    fn inline_table(&mut self, depth: usize) -> Res<Value> {
        self.bump();
        let mut table = Table::new();
        self.skip_blanks();
        if self.eat('}') {
            return Ok(Value::Table(table));
        }
        loop {
            self.skip_blanks();
            let keys = self.key_path()?;
            self.skip_blanks();
            if !self.eat('=') {
                return self.syntax();
            }
            self.skip_blanks();
            let value = self.value(depth + 1)?;
            insert_dotted(&mut table, &keys, value, self.line)?;
            self.skip_blanks();
            if self.eat(',') {
                continue;
            }
            if self.eat('}') {
                return Ok(Value::Table(table));
            }
            return self.syntax();
        }
    }

    fn basic_string(&mut self) -> Res<String> {
        self.bump();
        let mut out = String::new();
        loop {
            match self.bump() {
                Some('"') => return Ok(out),
                Some('\\') => out.push(self.escape()?),
                Some('\n') | None => return self.syntax(),
                Some(c) if c.is_control() && c != '\t' => return self.syntax(),
                Some(c) => out.push(c),
            }
        }
    }

    fn literal_string(&mut self) -> Res<String> {
        self.bump();
        let mut out = String::new();
        loop {
            match self.bump() {
                Some('\'') => return Ok(out),
                Some('\n') | None => return self.syntax(),
                Some(c) => out.push(c),
            }
        }
    }

    fn multiline_basic(&mut self) -> Res<String> {
        for _ in 0..3 {
            self.bump();
        }
        self.eat('\r');
        self.eat('\n');
        let mut out = String::new();
        loop {
            if self.starts_with("\"\"\"") {
                for _ in 0..3 {
                    self.bump();
                }
                return Ok(out);
            }
            match self.bump() {
                None => return self.syntax(),
                Some('\\') => {
                    if matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
                        // A line-ending backslash trims the white space that follows.
                        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
                            self.bump();
                        }
                    } else {
                        out.push(self.escape()?);
                    }
                }
                Some(c) => out.push(c),
            }
        }
    }

    fn multiline_literal(&mut self) -> Res<String> {
        for _ in 0..3 {
            self.bump();
        }
        self.eat('\r');
        self.eat('\n');
        let mut out = String::new();
        loop {
            if self.starts_with("'''") {
                for _ in 0..3 {
                    self.bump();
                }
                return Ok(out);
            }
            match self.bump() {
                None => return self.syntax(),
                Some(c) => out.push(c),
            }
        }
    }

    fn escape(&mut self) -> Res<char> {
        let Some(c) = self.bump() else {
            return self.syntax();
        };
        match c {
            'b' => Ok('\u{8}'),
            't' => Ok('\t'),
            'n' => Ok('\n'),
            'f' => Ok('\u{c}'),
            'r' => Ok('\r'),
            '"' => Ok('"'),
            '\\' => Ok('\\'),
            'u' => self.unicode(4),
            'U' => self.unicode(8),
            _ => self.syntax(),
        }
    }

    fn unicode(&mut self, digits: usize) -> Res<char> {
        let mut code = 0_u32;
        for _ in 0..digits {
            let Some(digit) = self.bump().and_then(|c| c.to_digit(16)) else {
                return self.syntax();
            };
            code = code.saturating_mul(16).saturating_add(digit);
        }
        char::from_u32(code).map_or_else(|| self.syntax(), Ok)
    }
}

fn is_bare(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

fn classify(token: &str) -> Option<Value> {
    match token {
        "" => return None,
        "true" => return Some(Value::Bool(true)),
        "false" => return Some(Value::Bool(false)),
        "inf" | "+inf" => return Some(Value::Float(f64::INFINITY)),
        "-inf" => return Some(Value::Float(f64::NEG_INFINITY)),
        "nan" | "+nan" | "-nan" => return Some(Value::Float(f64::NAN)),
        _ => {}
    }
    let first = token.chars().next()?;
    if !(first.is_ascii_digit() || first == '+' || first == '-') {
        return None;
    }
    let plain = token.replace('_', "");
    if let Some(digits) = plain.strip_prefix("0x") {
        return i64::from_str_radix(digits, 16).ok().map(Value::Int);
    }
    if let Some(digits) = plain.strip_prefix("0o") {
        return i64::from_str_radix(digits, 8).ok().map(Value::Int);
    }
    if let Some(digits) = plain.strip_prefix("0b") {
        return i64::from_str_radix(digits, 2).ok().map(Value::Int);
    }
    if let Ok(number) = plain.parse::<i64>() {
        return Some(Value::Int(number));
    }
    if plain
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
        && let Ok(number) = plain.parse::<f64>()
    {
        return Some(Value::Float(number));
    }
    let date_like = token.chars().all(|c| {
        c.is_ascii_digit() || matches!(c, '-' | ':' | 'T' | 't' | 'Z' | 'z' | '.' | '+' | ' ')
    }) && (token.contains('-') || token.contains(':'));
    date_like.then(|| Value::Date(token.to_owned()))
}

/// Finds the table a header names, for key and value lines to go into.
fn descend<'a>(root: &'a mut Table, path: &[String], line: usize) -> Res<&'a mut Table> {
    let mut table = root;
    for key in path {
        let next = table.get_mut(key).ok_or(TomlError::Syntax(line))?;
        table = match next {
            Value::Table(inner) => inner,
            Value::Array(items) => match items.last_mut() {
                Some(Value::Table(inner)) => inner,
                _ => return Err(TomlError::Syntax(line)),
            },
            _ => return Err(TomlError::Syntax(line)),
        };
    }
    Ok(table)
}

/// Makes the table of a `[a.b]` header. Parents that do not exist yet are made empty.
fn open_table(root: &mut Table, keys: &[String], line: usize) -> Res<()> {
    let mut table = root;
    for (index, key) in keys.iter().enumerate() {
        let last = index + 1 == keys.len();
        if last && table.contains_key(key) {
            // A table made earlier by a dotted key or a sub-table header may be re-opened only if
            // it is a table; the explicit-header check above already refused a second `[a]`.
            return match table.get(key) {
                Some(Value::Table(_)) => Ok(()),
                _ => Err(TomlError::Duplicate(line)),
            };
        }
        let entry = table
            .entry(key.clone())
            .or_insert_with(|| Value::Table(Table::new()));
        table = match entry {
            Value::Table(inner) => inner,
            Value::Array(items) => match items.last_mut() {
                Some(Value::Table(inner)) => inner,
                _ => return Err(TomlError::Syntax(line)),
            },
            _ => return Err(TomlError::Duplicate(line)),
        };
    }
    Ok(())
}

/// Adds a table to the array a `[[a.b]]` header names.
fn open_array_table(root: &mut Table, keys: &[String], line: usize) -> Res<()> {
    let Some((last, parents)) = keys.split_last() else {
        return Err(TomlError::Syntax(line));
    };
    if !parents.is_empty() {
        open_table(root, parents, line)?;
    }
    let parent = descend(root, parents, line)?;
    match parent
        .entry(last.clone())
        .or_insert_with(|| Value::Array(Vec::new()))
    {
        Value::Array(items) if items.iter().all(|item| matches!(item, Value::Table(_))) => {
            items.push(Value::Table(Table::new()));
            Ok(())
        }
        _ => Err(TomlError::Duplicate(line)),
    }
}

/// Sets `a.b.c = value` inside `table`, making the tables between.
fn insert_dotted(table: &mut Table, keys: &[String], value: Value, line: usize) -> Res<()> {
    let Some((last, parents)) = keys.split_last() else {
        return Err(TomlError::Syntax(line));
    };
    let mut table = table;
    for key in parents {
        let entry = table
            .entry(key.clone())
            .or_insert_with(|| Value::Table(Table::new()));
        table = match entry {
            Value::Table(inner) => inner,
            _ => return Err(TomlError::Duplicate(line)),
        };
    }
    if table.contains_key(last) {
        return Err(TomlError::Duplicate(line));
    }
    table.insert(last.clone(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(source: &str) -> Table {
        parse(source).expect("a document")
    }

    #[test]
    fn a_lockfile_shape_is_read() {
        let doc = text(
            "# header\nversion = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\ndependencies = [\n \"b\",\n \"c 1.0.0 (registry+https://x)\",\n]\n\n[[package]]\nname = \"b\"\n",
        );
        assert_eq!(doc["version"].as_int(), Some(4));
        let packages = doc["package"].as_array().expect("packages");
        assert_eq!(packages.len(), 2);
        let deps = packages[0].as_table().expect("a table")["dependencies"]
            .as_array()
            .expect("deps");
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn dotted_keys_inline_tables_and_target_headers_are_read() {
        let doc = text(
            "[dependencies]\nserde.workspace = true\nfoo = { version = \"1\", features = [\"a\", \"b\"] }\n\n[target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n\n[dependencies.bar]\ngit = \"https://x.test/bar\"\n",
        );
        let deps = doc["dependencies"].as_table().expect("deps");
        assert_eq!(
            deps["serde"].as_table().expect("t")["workspace"],
            Value::Bool(true)
        );
        assert!(deps["foo"].as_table().is_some());
        assert_eq!(
            deps["bar"].as_table().expect("t")["git"].as_str(),
            Some("https://x.test/bar")
        );
        let target = doc["target"].as_table().expect("target");
        assert!(target.contains_key("cfg(unix)"));
    }

    #[test]
    fn strings_escapes_and_multiline_forms_are_read() {
        let doc = text(
            "a = \"x\\ty\\u00e9\"\nb = 'raw \\n'\nc = \"\"\"\nline one\nline two\"\"\"\nd = '''\nraw\n'''\n",
        );
        assert_eq!(doc["a"].as_str(), Some("x\ty\u{e9}"));
        assert_eq!(doc["b"].as_str(), Some("raw \\n"));
        assert_eq!(doc["c"].as_str(), Some("line one\nline two"));
        assert_eq!(doc["d"].as_str(), Some("raw\n"));
    }

    #[test]
    fn a_duplicate_key_or_table_is_refused() {
        assert!(matches!(
            parse("a = 1\na = 2\n"),
            Err(TomlError::Duplicate(_))
        ));
        assert!(matches!(
            parse("[a]\nx = 1\n[a]\ny = 2\n"),
            Err(TomlError::Duplicate(_))
        ));
        assert!(matches!(
            parse("a.b = 1\na.b = 2\n"),
            Err(TomlError::Duplicate(_))
        ));
    }

    #[test]
    fn unknown_text_is_an_error_and_never_skipped() {
        for bad in [
            "a = \n",
            "a = nonsense\n",
            "[a\nx = 1\n",
            "x y = 1\n",
            "a = [1, 2\n",
            "a = \"unterminated\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn size_and_depth_are_bounded() {
        let deep = format!("a = {}1{}\n", "[".repeat(40), "]".repeat(40));
        assert_eq!(parse(&deep), Err(TomlError::TooDeep));
        let large = "#".repeat(MAX_BYTES + 1);
        assert_eq!(parse(&large), Err(TomlError::TooLarge));
    }

    #[test]
    fn scalars_are_classified() {
        let doc = text("i = 1_000\nf = 1.5\nb = false\nd = 1979-05-27T07:32:00Z\nh = 0xff\n");
        assert_eq!(doc["i"].as_int(), Some(1000));
        assert_eq!(doc["f"], Value::Float(1.5));
        assert_eq!(doc["b"].as_bool(), Some(false));
        assert!(matches!(doc["d"], Value::Date(_)));
        assert_eq!(doc["h"].as_int(), Some(255));
    }
}
