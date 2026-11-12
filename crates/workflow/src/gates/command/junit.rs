//! Reading a JUnit XML test report.
//!
//! JUnit XML is the report that pytest (`--junitxml`), jest-junit, go-junit-report, Maven
//! Surefire, Gradle and cargo-nextest write. It has no formal standard, so this reader accepts
//! the shape those tools share and nothing else:
//!
//! ```text
//! testsuites?                      (optional root, totals optional)
//!   testsuite  tests= failures= errors= skipped=     (may hold more testsuite elements)
//!     testcase  classname= name=
//!       failure | error | skipped                    (direct children decide how the test ended)
//! ```
//!
//! A test case with an `error` or a `failure` child failed. Otherwise a test case with a
//! `skipped` child was skipped. Otherwise it passed. Every other element (`properties`,
//! `system-out`, `system-err`, Surefire's `flakyFailure` and the like) is skipped over.
//!
//! # The report is untrusted input
//!
//! The report is written inside the sandbox, by a test runner that runs the code of the change.
//! This module therefore reads a small, strict subset of XML with its own reader, and refuses
//! everything outside it. A refused report makes the gate `BLOCKED`, with the reason as a plain
//! sentence, and is never a pass.
//!
//! * No document type declaration, no entity declaration and no processing instruction other
//!   than the XML declaration on the first line. The only references are the five predefined
//!   ones (`&lt;` `&gt;` `&amp;` `&apos;` `&quot;`) and numeric character references. Nothing is
//!   ever expanded twice and nothing outside the text is ever read, so the usual attacks on XML
//!   readers (entity expansion, external entities) have nothing to act on.
//! * At most [`MAX_BYTES`] of text, [`MAX_DEPTH`] nested elements and [`MAX_CASES`] test cases.
//! * Every element must close, in order. A report that ends early is refused as truncated.
//! * A `testcase` counts only as a direct child of a `testsuite`, and a `testsuite` only at the
//!   root, under `testsuites` or under another `testsuite`. One that appears anywhere else (for
//!   example inside the captured output of another test) makes the report refused. Text that a
//!   test printed is escaped or wrapped in a character data section by the tool that wrote the
//!   report, so it cannot become an element.
//! * Every `testsuite` must declare `tests`, and it must equal the test cases listed in it. The
//!   attributes `failures`, `errors` and `skipped`, when present, must equal the listed test
//!   cases that have that child. The same holds for the totals on `testsuites`, when present. A
//!   suite that holds other suites may count its own test cases or all the test cases below it.
//! * Two test cases with the same name make the report refused, because the comparison with the
//!   base commit matches tests by name.
//!
//! As with the libtest reading, none of this defends against test code that replaces the whole
//! report with a coherent forged one. The validation stage documents that limit.

use std::collections::BTreeMap;

use super::outcomes::{Outcomes, Status};

/// The largest report that is read, in bytes.
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
/// The deepest nesting of elements that is read.
pub const MAX_DEPTH: usize = 32;
/// The most test cases one report may list.
pub const MAX_CASES: usize = 100_000;
/// The most attributes one element may carry.
const MAX_ATTRIBUTES: usize = 64;
/// The longest name of a test, in bytes.
const MAX_NAME_BYTES: usize = 1024;
/// The longest reference, such as `&#x10FFFF;`, counted from the ampersand to the semicolon.
const MAX_REFERENCE_BYTES: usize = 12;

/// Why a report is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// The report holds no element.
    Empty,
    /// The report is longer than [`MAX_BYTES`].
    TooLarge,
    /// The report ends before its last element closes.
    Truncated,
    /// The text is not well-formed XML of the subset this reader accepts.
    Malformed,
    /// The report holds a document type declaration, an entity declaration or a processing
    /// instruction.
    Declaration,
    /// The report uses a reference other than the five predefined ones and numeric ones.
    Reference,
    /// The elements are nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// The report lists more than [`MAX_CASES`] test cases.
    TooManyCases,
    /// The root element is not `testsuites` or `testsuite`.
    NotJunit,
    /// A `testcase`, `testsuite` or `testsuites` element is in a place where it cannot be.
    Misplaced,
    /// A test case has no name, or a name that is too long.
    Unnamed,
    /// Two test cases have the same name.
    Duplicate,
    /// A total is missing, is not a number, or disagrees with the listed test cases.
    Totals,
}

impl Problem {
    /// The reason as a plain sentence, for the gate report.
    #[must_use]
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::Empty => "The JUnit report is empty, so the gate cannot show that tests ran.",
            Self::TooLarge => {
                "The JUnit report is larger than the factory reads, so it is not accepted as evidence."
            }
            Self::Truncated => {
                "The JUnit report ends before its last element closes, so it is not accepted as evidence."
            }
            Self::Malformed => {
                "The JUnit report is not well-formed XML, so it is not accepted as evidence."
            }
            Self::Declaration => {
                "The JUnit report holds a document type declaration, an entity declaration or a processing instruction, which the factory does not read, so it is not accepted as evidence."
            }
            Self::Reference => {
                "The JUnit report uses an entity reference that is not one of the five predefined ones or a numeric one, so it is not accepted as evidence."
            }
            Self::TooDeep => {
                "The JUnit report nests its elements deeper than the factory reads, so it is not accepted as evidence."
            }
            Self::TooManyCases => {
                "The JUnit report lists more test cases than the factory reads, so it is not accepted as evidence."
            }
            Self::NotJunit => {
                "The report does not start with a testsuites or a testsuite element, so it is not a JUnit report."
            }
            Self::Misplaced => {
                "The JUnit report holds a test case or a test suite in a place where none can be, so it is not accepted as evidence."
            }
            Self::Unnamed => {
                "The JUnit report holds a test case with no name or with a name that is too long, so it is not accepted as evidence."
            }
            Self::Duplicate => {
                "The JUnit report lists two test cases with the same class name and name, so its tests cannot be told apart and it is not accepted as evidence."
            }
            Self::Totals => {
                "The totals of the JUnit report are missing or disagree with the test cases it lists, so it is not accepted as evidence."
            }
        }
    }
}

/// Reads a JUnit XML report. A report that is refused is not consistent and says why.
#[must_use]
pub fn read(text: &str) -> Outcomes {
    match parse(text) {
        Ok(results) => Outcomes::trusted(results),
        Err(problem) => Outcomes::untrusted(BTreeMap::new(), problem.sentence()),
    }
}

/// Reads a JUnit XML report into the tests it lists.
///
/// # Errors
/// The [`Problem`] that makes the report refused.
pub fn parse(text: &str) -> Result<BTreeMap<String, Status>, Problem> {
    if text.len() > MAX_BYTES {
        return Err(Problem::TooLarge);
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    if text.trim().is_empty() {
        return Err(Problem::Empty);
    }
    let mut lexer = Lexer { text, at: 0 };
    let mut reader = Reader::default();
    loop {
        match lexer.next(!reader.stack.is_empty())? {
            Token::Open {
                name,
                attributes,
                empty,
            } => {
                reader.open(name, &attributes)?;
                if empty {
                    reader.close(name)?;
                }
            }
            Token::Close(name) => reader.close(name)?,
            Token::End => return reader.finish(),
        }
    }
}

// ---- the XML subset ------------------------------------------------------------------------

enum Token<'a> {
    Open {
        name: &'a str,
        attributes: Vec<(&'a str, String)>,
        empty: bool,
    },
    Close(&'a str),
    End,
}

struct Lexer<'a> {
    text: &'a str,
    at: usize,
}

const fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

/// The length of the element or attribute name at the start of `text`. Names are ASCII: the
/// tools that write JUnit reports use no other.
fn name_len(text: &str) -> usize {
    let bytes = text.as_bytes();
    match bytes.first() {
        Some(first) if first.is_ascii_alphabetic() || matches!(first, b'_' | b':') => {}
        _ => return 0,
    }
    bytes
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-'))
        .count()
}

/// The character a reference names, without the ampersand and the semicolon.
fn referenced(name: &str) -> Option<char> {
    match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "apos" => Some('\''),
        "quot" => Some('"'),
        _ => {
            let digits = name.strip_prefix('#')?;
            let code = match digits.strip_prefix('x') {
                Some(hex) if !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    u32::from_str_radix(hex, 16).ok()?
                }
                Some(_) => return None,
                None if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                    digits.parse().ok()?
                }
                None => return None,
            };
            char::from_u32(code).filter(|c| *c != '\0')
        }
    }
}

/// Checks every reference in `raw` and, when `out` is given, writes the text with the
/// references replaced.
fn decode(raw: &str, mut out: Option<&mut String>) -> Result<(), Problem> {
    let mut rest = raw;
    while let Some(amp) = rest.find('&') {
        if let Some(out) = out.as_deref_mut() {
            out.push_str(&rest[..amp]);
        }
        let after = &rest[amp + 1..];
        let end = after
            .bytes()
            .take(MAX_REFERENCE_BYTES)
            .position(|b| b == b';')
            .ok_or(Problem::Reference)?;
        let character = referenced(&after[..end]).ok_or(Problem::Reference)?;
        if let Some(out) = out.as_deref_mut() {
            out.push(character);
        }
        rest = &after[end + 1..];
    }
    if let Some(out) = out {
        out.push_str(rest);
    }
    Ok(())
}

impl<'a> Lexer<'a> {
    fn rest(&self) -> &'a str {
        &self.text[self.at..]
    }

    /// Moves to just after `tail`, which is a suffix of the text.
    fn move_to(&mut self, tail: &str) {
        self.at = self.text.len() - tail.len();
    }

    /// Text between two tags. Outside the root element only white space is allowed.
    fn check_text(text: &str, inside: bool) -> Result<(), Problem> {
        if inside {
            decode(text, None)
        } else if text.chars().all(is_space) {
            Ok(())
        } else {
            Err(Problem::Malformed)
        }
    }

    /// The next tag. Text, comments and character data sections are checked and skipped.
    fn next(&mut self, inside: bool) -> Result<Token<'a>, Problem> {
        loop {
            let rest = self.rest();
            let Some(lt) = rest.find('<') else {
                Self::check_text(rest, inside)?;
                self.at = self.text.len();
                return Ok(Token::End);
            };
            Self::check_text(&rest[..lt], inside)?;
            let at_start = self.at == 0 && lt == 0;
            let rest = &rest[lt..];
            if let Some(after) = rest.strip_prefix("<!--") {
                let end = after.find("-->").ok_or(Problem::Truncated)?;
                self.move_to(&after[end + 3..]);
            } else if let Some(after) = rest.strip_prefix("<![CDATA[") {
                if !inside {
                    return Err(Problem::Malformed);
                }
                let end = after.find("]]>").ok_or(Problem::Truncated)?;
                self.move_to(&after[end + 3..]);
            } else if rest.starts_with("<!") {
                return Err(Problem::Declaration);
            } else if let Some(after) = rest.strip_prefix("<?") {
                let is_xml_declaration = at_start
                    && after
                        .strip_prefix("xml")
                        .is_some_and(|tail| tail.starts_with(is_space));
                if !is_xml_declaration {
                    return Err(Problem::Declaration);
                }
                let end = after.find("?>").ok_or(Problem::Truncated)?;
                self.move_to(&after[end + 2..]);
            } else if let Some(after) = rest.strip_prefix("</") {
                let len = name_len(after);
                let tail = after[len..].trim_start_matches(is_space);
                if tail.is_empty() {
                    return Err(Problem::Truncated);
                }
                let Some(tail) = tail.strip_prefix('>').filter(|_| len > 0) else {
                    return Err(Problem::Malformed);
                };
                self.move_to(tail);
                return Ok(Token::Close(&after[..len]));
            } else {
                return self.open_tag(&rest[1..]);
            }
        }
    }

    /// An opening tag, from just after its `<`.
    fn open_tag(&mut self, after: &'a str) -> Result<Token<'a>, Problem> {
        let truncated_or = |rest: &str, problem| {
            if rest.is_empty() {
                Problem::Truncated
            } else {
                problem
            }
        };
        let len = name_len(after);
        if len == 0 {
            return Err(truncated_or(after, Problem::Malformed));
        }
        let name = &after[..len];
        let mut rest = &after[len..];
        let mut attributes: Vec<(&'a str, String)> = Vec::new();
        loop {
            let trimmed = rest.trim_start_matches(is_space);
            let had_space = trimmed.len() != rest.len();
            rest = trimmed;
            if let Some(tail) = rest.strip_prefix("/>") {
                self.move_to(tail);
                return Ok(Token::Open {
                    name,
                    attributes,
                    empty: true,
                });
            }
            if let Some(tail) = rest.strip_prefix('>') {
                self.move_to(tail);
                return Ok(Token::Open {
                    name,
                    attributes,
                    empty: false,
                });
            }
            let len = name_len(rest);
            if len == 0 || !had_space {
                return Err(truncated_or(rest, Problem::Malformed));
            }
            let key = &rest[..len];
            rest = rest[len..].trim_start_matches(is_space);
            rest = rest
                .strip_prefix('=')
                .ok_or_else(|| truncated_or(rest, Problem::Malformed))?
                .trim_start_matches(is_space);
            let quote = match rest.chars().next() {
                Some(quote @ ('"' | '\'')) => quote,
                Some(_) => return Err(Problem::Malformed),
                None => return Err(Problem::Truncated),
            };
            let body = &rest[1..];
            let end = body.find(quote).ok_or(Problem::Truncated)?;
            let raw = &body[..end];
            if raw.contains('<') {
                return Err(Problem::Malformed);
            }
            if attributes.len() >= MAX_ATTRIBUTES || attributes.iter().any(|(k, _)| *k == key) {
                return Err(Problem::Malformed);
            }
            let mut value = String::with_capacity(raw.len());
            decode(raw, Some(&mut value))?;
            attributes.push((key, value));
            rest = &body[end + 1..];
        }
    }
}

// ---- the JUnit shape -----------------------------------------------------------------------

/// The test cases counted in a suite.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Tally {
    cases: u64,
    failures: u64,
    errors: u64,
    skipped: u64,
}

impl Tally {
    fn add(&mut self, other: Self) {
        self.cases += other.cases;
        self.failures += other.failures;
        self.errors += other.errors;
        self.skipped += other.skipped;
    }
}

/// The totals a suite declares in its attributes.
#[derive(Debug, Default, Clone, Copy)]
struct Declared {
    tests: Option<u64>,
    failures: Option<u64>,
    errors: Option<u64>,
    skipped: Option<u64>,
}

impl Declared {
    fn of(attributes: &[(&str, String)]) -> Result<Self, Problem> {
        let number = |key: &str| -> Result<Option<u64>, Problem> {
            let Some((_, value)) = attributes.iter().find(|(k, _)| *k == key) else {
                return Ok(None);
            };
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Problem::Totals);
            }
            value.parse().map(Some).map_err(|_| Problem::Totals)
        };
        Ok(Self {
            tests: number("tests")?,
            failures: number("failures")?,
            errors: number("errors")?,
            skipped: number("skipped")?,
        })
    }

    /// True when every total that is declared equals the count.
    fn agrees_with(&self, counted: Tally) -> bool {
        self.tests.is_none_or(|n| n == counted.cases)
            && self.failures.is_none_or(|n| n == counted.failures)
            && self.errors.is_none_or(|n| n == counted.errors)
            && self.skipped.is_none_or(|n| n == counted.skipped)
    }
}

enum Frame {
    Suites {
        declared: Declared,
        all: Tally,
    },
    Suite {
        declared: Declared,
        /// The test cases listed directly in the suite.
        own: Tally,
        /// Those, and the test cases of the suites inside it.
        all: Tally,
    },
    Case {
        id: String,
        failure: bool,
        error: bool,
        skipped: bool,
    },
    Other,
}

#[derive(Default)]
struct Reader<'a> {
    stack: Vec<(&'a str, Frame)>,
    results: BTreeMap<String, Status>,
    root_closed: bool,
}

const fn is_structural(name: &str) -> bool {
    matches!(name.as_bytes(), b"testsuites" | b"testsuite" | b"testcase")
}

/// The name of a test case: the class name and the name, with control characters made spaces.
fn case_id(attributes: &[(&str, String)]) -> Result<String, Problem> {
    let clean = |key: &str| -> String {
        attributes
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, value)| {
                value
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .collect::<String>()
                    .trim()
                    .to_owned()
            })
            .unwrap_or_default()
    };
    let name = clean("name");
    let class = clean("classname");
    if name.is_empty() {
        return Err(Problem::Unnamed);
    }
    let id = if class.is_empty() || class == name {
        name
    } else {
        format!("{class}::{name}")
    };
    if id.len() > MAX_NAME_BYTES {
        return Err(Problem::Unnamed);
    }
    Ok(id)
}

impl<'a> Reader<'a> {
    fn open(&mut self, name: &'a str, attributes: &[(&str, String)]) -> Result<(), Problem> {
        if self.root_closed {
            return Err(Problem::Malformed);
        }
        if self.stack.len() >= MAX_DEPTH {
            return Err(Problem::TooDeep);
        }
        let suite = |attributes| -> Result<Frame, Problem> {
            Ok(Frame::Suite {
                declared: Declared::of(attributes)?,
                own: Tally::default(),
                all: Tally::default(),
            })
        };
        let frame = match (self.stack.last_mut().map(|(_, frame)| frame), name) {
            (None, "testsuites") => Frame::Suites {
                declared: Declared::of(attributes)?,
                all: Tally::default(),
            },
            (None, "testsuite") => suite(attributes)?,
            (None, _) => return Err(Problem::NotJunit),
            (Some(Frame::Suites { .. } | Frame::Suite { .. }), "testsuite") => suite(attributes)?,
            (Some(Frame::Suite { .. }), "testcase") => Frame::Case {
                id: case_id(attributes)?,
                failure: false,
                error: false,
                skipped: false,
            },
            (Some(_), name) if is_structural(name) => return Err(Problem::Misplaced),
            (
                Some(Frame::Case {
                    failure,
                    error,
                    skipped,
                    ..
                }),
                name,
            ) => {
                match name {
                    "failure" => *failure = true,
                    "error" => *error = true,
                    "skipped" => *skipped = true,
                    _ => {}
                }
                Frame::Other
            }
            (Some(_), _) => Frame::Other,
        };
        self.stack.push((name, frame));
        Ok(())
    }

    fn close(&mut self, name: &str) -> Result<(), Problem> {
        let Some((open, frame)) = self.stack.pop() else {
            return Err(Problem::Malformed);
        };
        if open != name {
            return Err(Problem::Malformed);
        }
        let parent = self.stack.last_mut().map(|(_, frame)| frame);
        match frame {
            Frame::Other => {}
            Frame::Case {
                id,
                failure,
                error,
                skipped,
            } => {
                if self.results.len() >= MAX_CASES {
                    return Err(Problem::TooManyCases);
                }
                let status = if failure || error {
                    Status::Failed
                } else if skipped {
                    Status::Ignored
                } else {
                    Status::Passed
                };
                if self.results.insert(id, status).is_some() {
                    return Err(Problem::Duplicate);
                }
                let one = Tally {
                    cases: 1,
                    failures: u64::from(failure),
                    errors: u64::from(error),
                    skipped: u64::from(skipped),
                };
                if let Some(Frame::Suite { own, all, .. }) = parent {
                    own.add(one);
                    all.add(one);
                }
            }
            Frame::Suite { declared, own, all } => {
                let adds_up = declared.tests.is_some()
                    && (declared.agrees_with(own) || declared.agrees_with(all));
                if !adds_up {
                    return Err(Problem::Totals);
                }
                if let Some(Frame::Suite { all: above, .. } | Frame::Suites { all: above, .. }) =
                    parent
                {
                    above.add(all);
                }
            }
            Frame::Suites { declared, all } => {
                if !declared.agrees_with(all) {
                    return Err(Problem::Totals);
                }
            }
        }
        if self.stack.is_empty() {
            self.root_closed = true;
        }
        Ok(())
    }

    fn finish(self) -> Result<BTreeMap<String, Status>, Problem> {
        if !self.stack.is_empty() {
            return Err(Problem::Truncated);
        }
        if !self.root_closed {
            return Err(Problem::Empty);
        }
        Ok(self.results)
    }
}

#[cfg(test)]
mod tests;
