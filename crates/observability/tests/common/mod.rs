//! Helpers shared by the integration tests. Not every test file uses every helper.
#![allow(dead_code)]

use factory_domain::redaction::{PatternAction, PatternSpec, Redactor};
use factory_observability::redact::{RedactorScrubber, Scrub};
use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

/// Collects everything a log layer writes, so a test can read the lines.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

pub struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = CaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        CaptureWriter(Arc::clone(&self.0))
    }
}

impl Capture {
    pub fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .expect("log output is UTF-8")
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// A scrubber that swaps one word for another. It stands in for the real redactor, to prove that
/// the scrubber handed to the pipeline is the one that runs.
#[derive(Debug)]
pub struct ReplaceScrubber {
    pub from: &'static str,
    pub to: &'static str,
}

impl factory_observability::redact::Scrub for ReplaceScrubber {
    fn scrub<'a>(
        &self,
        text: &'a str,
    ) -> Result<std::borrow::Cow<'a, str>, factory_observability::redact::ScrubError> {
        Ok(if text.contains(self.from) {
            std::borrow::Cow::Owned(text.replace(self.from, self.to))
        } else {
            std::borrow::Cow::Borrowed(text)
        })
    }
}

/// The security policy. The tests build the real redactor from its patterns, so the tests and the
/// composition root read the same source and neither holds a copy.
const POLICY: &str = include_str!("../../../../policies/security.yaml");

/// The text of a YAML single-quoted scalar, starting just after the opening quote. A doubled
/// quote stands for one quote.
fn single_quoted(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
                out.push('\'');
            } else {
                return out;
            }
        } else {
            out.push(c);
        }
    }
    panic!("a quoted scalar in the policy does not end");
}

fn pattern_from_line(line: &str) -> PatternSpec {
    let id = line
        .split("id: ")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .expect("the line has an id")
        .trim();
    let regex = single_quoted(line.split("regex: '").nth(1).expect("the line has a regex"));
    let action = match line
        .rsplit("action: ")
        .next()
        .and_then(|rest| rest.split([',', ' ', '}']).next())
        .expect("the line has an action")
    {
        "block" => PatternAction::Block,
        "flag" => PatternAction::Flag,
        other => panic!("unknown action {other}"),
    };
    PatternSpec::new(id, regex, action)
}

/// The patterns of `secrets.patterns` in the security policy, in the policy's order.
pub fn policy_patterns() -> Vec<PatternSpec> {
    let patterns: Vec<PatternSpec> = POLICY
        .split("\nsecrets:\n")
        .nth(1)
        .and_then(|secrets| secrets.split("  patterns:\n").nth(1))
        .and_then(|rest| rest.split("  entropy_heuristic:").next())
        .expect("the policy has a secrets section with patterns")
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("- { id: "))
        .map(pattern_from_line)
        .collect();
    assert!(
        patterns.len() >= 20,
        "the policy reader found too few patterns"
    );
    patterns
}

/// A redactor with the policy's patterns and no registered secret, as the composition root builds
/// it before it registers the factory's own values.
pub fn policy_redactor() -> Arc<Redactor> {
    Arc::new(
        Redactor::builder()
            .patterns(policy_patterns())
            .build()
            .expect("the policy patterns compile"),
    )
}

/// The `Scrub` seam over [`policy_redactor`].
pub fn policy_scrubber() -> Arc<dyn Scrub> {
    Arc::new(RedactorScrubber::new(policy_redactor()))
}

/// Standard base64 with padding. The leak checks look for a canary in this form, and the crate
/// under test has no encoder of its own to reuse.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The conventions page. The tests compare its tables with the constants in the crate, so the
/// page and the code cannot drift apart without a test failing.
pub const CONVENTIONS: &str = include_str!("../../../../docs/observability/conventions.md");

/// The rows of the table between `<!-- table:NAME -->` and `<!-- /table:NAME -->`, header and
/// separator removed. Each cell is trimmed and loses the backticks around it.
pub fn table(page: &str, name: &str) -> Vec<Vec<String>> {
    let begin = format!("<!-- table:{name} -->");
    let end = format!("<!-- /table:{name} -->");
    let start = page
        .find(&begin)
        .unwrap_or_else(|| panic!("the conventions page has no marker {begin}"));
    let stop = page
        .find(&end)
        .unwrap_or_else(|| panic!("the conventions page has no marker {end}"));
    assert!(start < stop, "marker {end} comes before {begin}");
    page[start + begin.len()..stop]
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('|'))
        .skip(2) // header row and separator row
        .map(|line| {
            line.trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().trim_matches('`').to_string())
                .collect()
        })
        .collect()
}

/// Whether `text` is one well-formed JSON value and nothing else. A small recursive-descent
/// checker, because the crate's dependency list has no JSON parser and the log tests splice a
/// field into JSON that a library produced.
pub fn is_valid_json(text: &str) -> bool {
    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
    }
    impl Reader<'_> {
        fn skip_space(&mut self) {
            while self.at < self.bytes.len() && b" \t\r\n".contains(&self.bytes[self.at]) {
                self.at += 1;
            }
        }
        fn eat(&mut self, byte: u8) -> bool {
            if self.bytes.get(self.at) == Some(&byte) {
                self.at += 1;
                true
            } else {
                false
            }
        }
        fn literal(&mut self, word: &[u8]) -> bool {
            if self.bytes[self.at..].starts_with(word) {
                self.at += word.len();
                true
            } else {
                false
            }
        }
        fn string(&mut self) -> bool {
            if !self.eat(b'"') {
                return false;
            }
            while let Some(&b) = self.bytes.get(self.at) {
                self.at += 1;
                match b {
                    b'"' => return true,
                    b'\\' => {
                        let Some(&escaped) = self.bytes.get(self.at) else {
                            return false;
                        };
                        self.at += 1;
                        if escaped == b'u' {
                            for _ in 0..4 {
                                match self.bytes.get(self.at) {
                                    Some(h) if h.is_ascii_hexdigit() => self.at += 1,
                                    _ => return false,
                                }
                            }
                        } else if !b"\"\\/bfnrt".contains(&escaped) {
                            return false;
                        }
                    }
                    0..=0x1f => return false,
                    _ => {}
                }
            }
            false
        }
        fn number(&mut self) -> bool {
            let start = self.at;
            self.eat(b'-');
            while self
                .bytes
                .get(self.at)
                .is_some_and(|b| b.is_ascii_digit() || b"+-.eE".contains(b))
            {
                self.at += 1;
            }
            self.at > start
        }
        fn value(&mut self) -> bool {
            self.skip_space();
            let ok = match self.bytes.get(self.at) {
                Some(b'{') => self.object(),
                Some(b'[') => self.array(),
                Some(b'"') => self.string(),
                Some(b't') => self.literal(b"true"),
                Some(b'f') => self.literal(b"false"),
                Some(b'n') => self.literal(b"null"),
                Some(_) => self.number(),
                None => false,
            };
            self.skip_space();
            ok
        }
        fn object(&mut self) -> bool {
            self.eat(b'{');
            self.skip_space();
            if self.eat(b'}') {
                return true;
            }
            loop {
                self.skip_space();
                if !self.string() {
                    return false;
                }
                self.skip_space();
                if !self.eat(b':') || !self.value() {
                    return false;
                }
                if self.eat(b',') {
                    continue;
                }
                return self.eat(b'}');
            }
        }
        fn array(&mut self) -> bool {
            self.eat(b'[');
            self.skip_space();
            if self.eat(b']') {
                return true;
            }
            loop {
                if !self.value() {
                    return false;
                }
                if self.eat(b',') {
                    continue;
                }
                return self.eat(b']');
            }
        }
    }
    let mut reader = Reader {
        bytes: text.as_bytes(),
        at: 0,
    };
    reader.value() && reader.at == reader.bytes.len()
}

/// Split a cell such as "`a`, `b`" into its set of names.
pub fn names_in(cell: &str) -> BTreeSet<String> {
    cell.split(',')
        .map(|part| part.trim().trim_matches('`').to_string())
        .filter(|part| !part.is_empty() && part != "none")
        .collect()
}
