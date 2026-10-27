//! Helpers shared by the integration tests. Not every test file uses every helper.
#![allow(dead_code)]

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
