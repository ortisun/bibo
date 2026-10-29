//! A strict JSON reader for request bodies.
//!
//! The broker must look at the same document the provider will read. A body that two parsers read
//! differently is a way past the check, so this reader refuses every shape on which parsers
//! disagree, instead of picking one reading:
//!
//! * a byte order mark, or any text before the document (RFC 8259 allows white space only);
//! * text after the document;
//! * an object that names a key twice, compared after the escapes are decoded (`"model"` and
//!   `"mod\u0065l"` are the same key). `serde_json` alone keeps the last of two equal keys, and a
//!   provider may keep the first;
//! * nesting deeper than [`MAX_DEPTH`], so that no later recursion can run out of stack;
//! * more than [`MAX_VALUES`] values in all, or more than [`MAX_WIDTH`] in one array or object. The
//!   reader builds the whole document before the schema looks at it, and a body of the largest size
//!   the listener accepts, made of `0,0,0,...`, holds millions of values and took 218 MB to build
//!   (finding RR-6). The count is checked as each value starts, so the tree never grows past the
//!   limit;
//! * anything `serde_json` refuses for a scalar: bad numbers, raw control characters in a string,
//!   bad escapes, lone surrogates, invalid UTF-8.
//!
//! Structure (objects and arrays) is read here; every scalar token is handed to `serde_json`, so
//! the number and string grammar is the library's.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use super::Violation;

/// The deepest nesting of arrays and objects a body may have. Real requests nest tool schemas
/// about ten levels deep.
pub const MAX_DEPTH: usize = 64;

/// The most values (scalars, strings, arrays and objects, and each object member) a body may hold
/// in all. The largest request recorded from the real tools holds about 2,000; a long conversation
/// with tool results holds some tens of thousands at most, because the text of a result is one
/// string. At about 70 bytes a value this bounds the tree of one body to about 7 MB.
pub const MAX_VALUES: usize = 100_000;

/// The most members of one array or object. The widest array in the recordings has 25.
pub const MAX_WIDTH: usize = 10_000;

/// Reads `bytes` as one JSON document.
///
/// # Errors
/// [`Violation::Malformed`] for anything that is not exactly one well-formed document,
/// [`Violation::DuplicateKey`] for an object with a repeated key, [`Violation::TooDeep`] for
/// nesting past [`MAX_DEPTH`] and [`Violation::TooManyValues`] for a document past [`MAX_VALUES`]
/// values or [`MAX_WIDTH`] members in one array or object.
pub fn parse(bytes: &[u8]) -> Result<Value, Violation> {
    let mut reader = Reader {
        bytes,
        at: 0,
        values: 0,
    };
    reader.skip_space();
    let value = reader.value(0)?;
    reader.skip_space();
    if reader.at != bytes.len() {
        return Err(Violation::Malformed);
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    /// How many values have been started so far.
    values: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    /// Counts one more value and refuses the document when the total is past the limit. Called
    /// before the value is built, so memory never grows past the limit.
    fn count(&mut self) -> Result<(), Violation> {
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err(Violation::TooManyValues);
        }
        Ok(())
    }

    fn value(&mut self, depth: usize) -> Result<Value, Violation> {
        self.count()?;
        match self.peek().ok_or(Violation::Malformed)? {
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'"' => self.string().map(Value::String),
            b't' | b'f' | b'n' | b'-' | b'0'..=b'9' => self.scalar(),
            _ => Err(Violation::Malformed),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, Violation> {
        if depth > MAX_DEPTH {
            return Err(Violation::TooDeep);
        }
        self.at += 1;
        let mut map = Map::new();
        let mut seen = BTreeSet::new();
        self.skip_space();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(map));
        }
        loop {
            self.skip_space();
            if self.peek() != Some(b'"') {
                return Err(Violation::Malformed);
            }
            let key = self.string()?;
            self.skip_space();
            if self.peek() != Some(b':') {
                return Err(Violation::Malformed);
            }
            self.at += 1;
            self.skip_space();
            if map.len() >= MAX_WIDTH {
                return Err(Violation::TooManyValues);
            }
            let value = self.value(depth)?;
            if !seen.insert(key.clone()) {
                return Err(Violation::DuplicateKey);
            }
            map.insert(key, value);
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(map));
                }
                _ => return Err(Violation::Malformed),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, Violation> {
        if depth > MAX_DEPTH {
            return Err(Violation::TooDeep);
        }
        self.at += 1;
        let mut items = Vec::new();
        self.skip_space();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_space();
            if items.len() >= MAX_WIDTH {
                return Err(Violation::TooManyValues);
            }
            items.push(self.value(depth)?);
            self.skip_space();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(Violation::Malformed),
            }
        }
    }

    /// A string token: from the opening quote to the closing one, escapes skipped over by pairs.
    fn string(&mut self) -> Result<String, Violation> {
        let start = self.at;
        self.at += 1;
        loop {
            match self.peek().ok_or(Violation::Malformed)? {
                b'"' => {
                    self.at += 1;
                    break;
                }
                b'\\' => self.at += 2,
                _ => self.at += 1,
            }
        }
        let token = self.bytes.get(start..self.at).ok_or(Violation::Malformed)?;
        serde_json::from_slice::<String>(token).map_err(|_| Violation::Malformed)
    }

    /// A number, `true`, `false` or `null`: the run of characters that can spell one.
    fn scalar(&mut self) -> Result<Value, Violation> {
        let start = self.at;
        while matches!(
            self.peek(),
            Some(b'a'..=b'z' | b'0'..=b'9' | b'-' | b'+' | b'.' | b'E')
        ) {
            self.at += 1;
        }
        let token = self.bytes.get(start..self.at).ok_or(Violation::Malformed)?;
        serde_json::from_slice::<Value>(token).map_err(|_| Violation::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Value {
        parse(text.as_bytes()).expect("a document")
    }

    #[test]
    fn it_reads_what_a_compliant_parser_reads() {
        assert_eq!(
            ok(" {\"a\": [1, 2.5e3, -0, true, null, \"x\\n\\u00e9\"]} \n")["a"][5],
            "x\né"
        );
        assert_eq!(ok("{}"), Value::Object(Map::new()));
        assert_eq!(ok("[]"), Value::Array(Vec::new()));
        assert_eq!(ok("\"s\""), "s");
    }

    #[test]
    fn a_repeated_key_is_refused_even_when_one_spelling_is_escaped() {
        for text in [
            r#"{"model":"a","model":"b"}"#,
            r#"{"model":"a","mod\u0065l":"b"}"#,
            r#"{"x":{"k":1,"k":1}}"#,
            r#"{"x":[{"k":1,"k":2}]}"#,
        ] {
            assert_eq!(
                parse(text.as_bytes()),
                Err(Violation::DuplicateKey),
                "{text}"
            );
        }
        // The same key in two different objects is fine.
        assert!(parse(br#"{"a":{"k":1},"b":{"k":1}}"#).is_ok());
    }

    #[test]
    fn a_byte_order_mark_leading_or_trailing_text_and_loose_syntax_are_refused() {
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(b"{}");
        for bad in [
            bom.as_slice(),
            b"{} x",
            b"{}{}",
            b"{'a':1}",
            b"{\"a\":1,}",
            b"[1,]",
            b"{\"a\" 1}",
            b"{\"a\":01}",
            b"{\"a\":+1}",
            b"{\"a\":.5}",
            b"{\"a\":NaN}",
            b"{\"a\":\"\x01\"}",
            b"{\"a\":\"\\ud800\"}",
            b"{\"a\":\"\xff\"}",
            b"",
            b"{",
            b"{\"a\":\"",
            // A comment, which some parsers skip.
            b"{/*x*/}",
        ] {
            assert_eq!(
                parse(bad),
                Err(Violation::Malformed),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn a_body_past_the_value_limits_is_refused_before_it_is_built() {
        // Too wide: more members than one array or object may hold.
        let wide = |n: usize| format!("[{}0]", "0,".repeat(n));
        assert!(parse(wide(MAX_WIDTH - 1).as_bytes()).is_ok());
        assert_eq!(
            parse(wide(MAX_WIDTH).as_bytes()),
            Err(Violation::TooManyValues)
        );
        let members = |n: usize| {
            let body: Vec<String> = (0..n).map(|i| format!("\"k{i}\":0")).collect();
            format!("{{{}}}", body.join(","))
        };
        assert!(parse(members(MAX_WIDTH).as_bytes()).is_ok());
        assert_eq!(
            parse(members(MAX_WIDTH + 1).as_bytes()),
            Err(Violation::TooManyValues)
        );
        // Too many in all, though no array is wide: rows of twenty values.
        let row = format!("[{}0],", "0,".repeat(19));
        let rows = |n: usize| format!("[{}[]]", row.repeat(n));
        assert!(parse(rows(2_000).as_bytes()).is_ok());
        assert!(
            MAX_VALUES / 21 < MAX_WIDTH,
            "the rows must be narrower than the width limit"
        );
        assert_eq!(
            parse(rows(MAX_VALUES / 21 + 100).as_bytes()),
            Err(Violation::TooManyValues)
        );
        // The count stops the reader at the limit: it does not read on to the end of a huge body.
        let huge = format!("[{}]", "[0],".repeat(10_000_000));
        assert_eq!(parse(huge.as_bytes()), Err(Violation::TooManyValues));
        // A legitimate body of the largest recorded size is nowhere near the limit.
        assert!(parse(wide(25).as_bytes()).is_ok());
    }

    #[test]
    fn nesting_past_the_limit_is_refused_without_running_out_of_stack() {
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(deep(MAX_DEPTH).as_bytes()).is_ok());
        assert_eq!(
            parse(deep(MAX_DEPTH + 1).as_bytes()),
            Err(Violation::TooDeep)
        );
        assert_eq!(
            parse("[".repeat(1_000_000).as_bytes()),
            Err(Violation::TooDeep)
        );
        let objects = format!(
            "{}1{}",
            "{\"a\":".repeat(MAX_DEPTH + 1),
            "}".repeat(MAX_DEPTH + 1)
        );
        assert_eq!(parse(objects.as_bytes()), Err(Violation::TooDeep));
    }
}
