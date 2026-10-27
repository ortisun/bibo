//! Reading Rust sources for the source-scan rules.
//!
//! The scans work on text, not on a syntax tree, so they first blank out what must not match:
//! comments, test-only items and, for identifier scans, string contents. Blanking keeps every
//! byte offset and newline where it was, so a hit maps straight to a line number.

use std::fs;
use std::path::{Path, PathBuf};

/// A source file in two views of the same length.
pub struct Masked {
    /// Comments blanked. Strings kept, for scans that look for text in a string.
    pub with_strings: String,
    /// Comments and the contents of string and character literals blanked, for scans that look
    /// for identifiers.
    pub code: String,
}

pub fn mask(source: &str) -> Masked {
    let bytes = source.as_bytes();
    let mut with_strings = bytes.to_vec();
    let mut code = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let next = bytes.get(i + 1).copied();
        match bytes[i] {
            b'/' if next == Some(b'/') => {
                let end = bytes[i..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(bytes.len(), |p| i + p);
                blank(&mut with_strings, i, end);
                blank(&mut code, i, end);
                i = end;
            }
            b'/' if next == Some(b'*') => {
                let end = block_comment_end(bytes, i);
                blank(&mut with_strings, i, end);
                blank(&mut code, i, end);
                i = end;
            }
            b'"' => {
                let end = string_end(bytes, i + 1);
                blank(&mut code, i + 1, end.saturating_sub(1).max(i + 1));
                i = end;
            }
            b'r' | b'b' if starts_raw_string(bytes, i) => {
                let (open, end) = raw_string_span(bytes, i);
                blank(&mut code, open, end.saturating_sub(1).max(open));
                i = end;
            }
            b'\'' => {
                if let Some(end) = char_literal_end(source, i) {
                    blank(&mut code, i + 1, end - 1);
                    i = end;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    // Only whole runs of bytes were replaced by ASCII spaces, so both views are valid UTF-8.
    Masked {
        with_strings: String::from_utf8(with_strings).unwrap_or_default(),
        code: String::from_utf8(code).unwrap_or_default(),
    }
}

/// Replace `[start, end)` with spaces, keeping newlines.
fn blank(buffer: &mut [u8], start: usize, end: usize) {
    let end = end.min(buffer.len());
    for byte in &mut buffer[start.min(end)..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

/// The index just after a block comment that starts at `start`. Block comments nest.
fn block_comment_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0;
    let mut i = start;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            depth += 1;
            i += 2;
        } else if bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/') {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    bytes.len()
}

/// The index just after the closing quote of a string whose contents start at `from`.
fn string_end(bytes: &[u8], from: usize) -> usize {
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// True at the `r` or `b` that begins `r"`, `r#"`, `br"` or `br#"`, and not inside an identifier.
fn starts_raw_string(bytes: &[u8], at: usize) -> bool {
    if at > 0 && is_ident(bytes[at - 1]) {
        return false;
    }
    let mut i = at;
    if bytes[i] == b'b' {
        i += 1;
    }
    if bytes.get(i) != Some(&b'r') {
        return false;
    }
    i += 1;
    while bytes.get(i) == Some(&b'#') {
        i += 1;
    }
    bytes.get(i) == Some(&b'"')
}

/// For a raw string starting at `at`, the index of the opening quote's successor and the index
/// just after the closing quote and hashes.
fn raw_string_span(bytes: &[u8], at: usize) -> (usize, usize) {
    let mut i = at;
    if bytes[i] == b'b' {
        i += 1;
    }
    i += 1; // the r
    let hashes = bytes[i..].iter().take_while(|b| **b == b'#').count();
    let contents = i + hashes + 1;
    let mut j = contents;
    while j < bytes.len() {
        if bytes[j] == b'"'
            && bytes[j + 1..]
                .iter()
                .take(hashes)
                .filter(|b| **b == b'#')
                .count()
                == hashes
        {
            return (contents, (j + 1 + hashes).min(bytes.len()));
        }
        j += 1;
    }
    (contents, bytes.len())
}

/// If the quote at `at` opens a character literal, the index just after its closing quote.
/// A lifetime such as `'a` returns `None`.
fn char_literal_end(source: &str, at: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    match bytes.get(at + 1)? {
        b'\\' => {
            // An escape: skip the escaped character, then find the closing quote.
            let escaped = source[at + 2..].chars().next()?;
            let from = at + 2 + escaped.len_utf8();
            bytes[from..]
                .iter()
                .position(|b| *b == b'\'')
                .map(|p| from + p + 1)
        }
        _ => {
            let c = source[at + 1..].chars().next()?;
            let after = at + 1 + c.len_utf8();
            (bytes.get(after) == Some(&b'\'')).then_some(after + 1)
        }
    }
}

/// Byte ranges of items marked `#[cfg(test)]`, found in the `code` view. An item ends at the
/// closing brace of its body, or at the first semicolon outside brackets when it has none.
pub fn test_spans(code: &str) -> Vec<(usize, usize)> {
    const MARKER: &str = "#[cfg(test)]";
    let bytes = code.as_bytes();
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(found) = code[from..].find(MARKER) {
        let start = from + found;
        let end = item_end(bytes, start + MARKER.len());
        spans.push((start, end));
        from = end.max(start + MARKER.len());
    }
    spans
}

fn item_end(bytes: &[u8], from: usize) -> usize {
    let mut depth = 0usize; // parentheses and square brackets
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b';' if depth == 0 => return i + 1,
            b'{' if depth == 0 => return matching_brace(bytes, i),
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// The index just after the brace that closes the one at `open`.
fn matching_brace(bytes: &[u8], open: usize) -> usize {
    let mut depth = 0usize;
    for (offset, byte) in bytes[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return open + offset + 1;
                }
            }
            _ => {}
        }
    }
    bytes.len()
}

/// Replace every byte in the ranges with a space, keeping newlines.
pub fn blank_ranges(text: &str, ranges: &[(usize, usize)]) -> String {
    let mut bytes = text.as_bytes().to_vec();
    for (start, end) in ranges {
        blank(&mut bytes, *start, *end);
    }
    String::from_utf8(bytes).unwrap_or_default()
}

/// One production source file, ready to scan.
pub struct Source {
    /// Path relative to the workspace root, with forward slashes.
    pub relative: String,
    pub with_strings: String,
    pub code: String,
}

impl Source {
    /// Mask comments and strings, then blank the items marked `#[cfg(test)]`.
    pub fn from_text(relative: &str, text: &str) -> Self {
        let masked = mask(text);
        let spans = test_spans(&masked.code);
        Self {
            relative: relative.to_string(),
            with_strings: blank_ranges(&masked.with_strings, &spans),
            code: blank_ranges(&masked.code, &spans),
        }
    }

    /// The 1-based line of a byte offset.
    pub fn line(&self, offset: usize) -> usize {
        self.code.as_bytes()[..offset.min(self.code.len())]
            .iter()
            .filter(|b| **b == b'\n')
            .count()
            + 1
    }

    pub fn location(&self, offset: usize) -> String {
        format!("{}:{}", self.relative, self.line(offset))
    }
}

/// The production Rust sources of one crate: `src/**/*.rs` and `build.rs`, without test code.
/// Test code is a file under a `tests`, `benches` or `examples` directory, a file named
/// `tests.rs`, `*_test.rs` or `*_tests.rs`, and an item marked `#[cfg(test)]`.
pub fn production_sources(root: &Path, crate_dir: &Path) -> Result<Vec<Source>, String> {
    let mut files = Vec::new();
    let build = crate_dir.join("build.rs");
    if build.is_file() {
        files.push(build);
    }
    collect_rust_files(&crate_dir.join("src"), &mut files)?;
    files.sort();

    let mut sources = Vec::new();
    for file in files {
        let text = fs::read_to_string(&file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        let relative = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        sources.push(Source::from_text(&relative, &text));
    }
    Ok(sources)
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
            .path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let is_link = fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink());
        if is_link && path.is_dir() {
            // Following it could loop, and not following it would hide code that Cargo compiles.
            return Err(format!(
                "{} is a symbolic link to a directory; source scans do not follow those, so remove it",
                path.display()
            ));
        }
        if path.is_dir() {
            if !matches!(name.as_str(), "tests" | "benches" | "examples") {
                collect_rust_files(&path, files)?;
            }
        } else if name.ends_with(".rs") && !is_test_file_name(&name) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_test_file_name(name: &str) -> bool {
    name == "tests.rs" || name.ends_with("_test.rs") || name.ends_with("_tests.rs")
}

/// The identifier that follows `from`, after any whitespace, and the offset where it starts.
pub fn next_ident(text: &str, from: usize) -> Option<(usize, &str)> {
    let bytes = text.as_bytes();
    let start = from
        + bytes
            .get(from..)?
            .iter()
            .take_while(|b| b.is_ascii_whitespace())
            .count();
    let length = bytes
        .get(start..)?
        .iter()
        .take_while(|b| is_ident(**b))
        .count();
    (length > 0).then(|| (start, &text[start..start + length]))
}

/// The first `{ ... }` block at or after `from`, as (offset of the brace, offset after the
/// closing brace).
pub fn brace_block(code: &str, from: usize) -> Option<(usize, usize)> {
    let open = from + code.get(from..)?.find('{')?;
    Some((open, matching_brace(code.as_bytes(), open)))
}

/// True for an identifier character.
pub fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Offsets where `word` occurs as a whole identifier.
pub fn find_word(text: &str, word: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    text.match_indices(word)
        .map(|(at, _)| at)
        .filter(|at| {
            let before_ok = *at == 0 || !is_ident(bytes[at - 1]);
            let after_ok = bytes.get(at + word.len()).is_none_or(|b| !is_ident(*b));
            before_ok && after_ok
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(source: &str) -> Masked {
        mask(source)
    }

    #[test]
    fn a_line_comment_is_blanked_in_both_views() {
        let m = masked("let a = 1; // docker.sock\nlet b = 2;");
        assert!(!m.with_strings.contains("docker"));
        assert!(!m.code.contains("docker"));
        assert!(m.code.contains("let b = 2;"));
    }

    #[test]
    fn a_nested_block_comment_is_blanked_to_its_end() {
        let m = masked("a /* one /* two */ still */ b");
        assert!(!m.code.contains("two") && !m.code.contains("still"));
        assert!(m.code.starts_with("a ") && m.code.ends_with(" b"));
    }

    #[test]
    fn a_string_is_kept_in_one_view_and_blanked_in_the_other() {
        let m = masked(r#"let a = "--privileged";"#);
        assert!(m.with_strings.contains("--privileged"));
        assert!(!m.code.contains("privileged"));
        assert!(m.code.contains("\"") && m.code.contains("let a"));
    }

    #[test]
    fn slashes_inside_a_string_do_not_start_a_comment() {
        let m = masked("let u = \"https://example.com\"; let after = 1;");
        assert!(m.with_strings.contains("https://example.com"));
        assert!(m.code.contains("let after = 1;"));
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        let m = masked(r#"let a = "say \"docker.sock\" now"; let b = 1;"#);
        assert!(m.with_strings.contains("docker.sock"));
        assert!(m.code.contains("let b = 1;"));
    }

    #[test]
    fn a_raw_string_ends_only_at_its_own_hashes() {
        let m = masked("let a = r#\"a \"quoted\" // not a comment\"#; let b = 1;");
        assert!(m.with_strings.contains("not a comment"));
        assert!(!m.code.contains("quoted"));
        assert!(m.code.contains("let b = 1;"));
    }

    #[test]
    fn a_quote_character_literal_does_not_start_a_string() {
        let m = masked("let q = '\"'; let after = 1; // tail");
        assert!(m.code.contains("let after = 1;"));
        assert!(!m.code.contains("tail"));
    }

    #[test]
    fn an_escaped_quote_character_literal_is_a_character() {
        let m = masked("let q = '\\''; let after = \"x\";");
        assert!(m.with_strings.contains("let after = \"x\";"));
    }

    #[test]
    fn a_lifetime_is_not_a_character_literal() {
        let m = masked("fn f<'a>(x: &'a str) -> &'a str { x } // done");
        assert!(m.code.contains("fn f<'a>(x: &'a str) -> &'a str { x }"));
        assert!(!m.code.contains("done"));
    }

    #[test]
    fn masking_keeps_every_offset_and_newline() {
        let source = "a // c\n\"s\ns\" /* x\ny */ b\n";
        let m = masked(source);
        for view in [&m.with_strings, &m.code] {
            assert_eq!(view.len(), source.len());
            let lines: Vec<usize> = view.match_indices('\n').map(|(i, _)| i).collect();
            let original: Vec<usize> = source.match_indices('\n').map(|(i, _)| i).collect();
            assert_eq!(lines, original);
        }
    }

    #[test]
    fn non_ascii_text_stays_valid() {
        let m = masked("let s = \"caf\u{e9} \u{1f600}\"; // r\u{e9}sum\u{e9}\nlet t = 1;");
        assert!(m.with_strings.contains("caf\u{e9}"));
        assert!(m.code.contains("let t = 1;"));
    }

    #[test]
    fn a_cfg_test_module_is_found_with_its_nested_braces() {
        let code =
            "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { if true { } }\n}\nfn after() {}\n";
        let spans = test_spans(code);
        assert_eq!(spans.len(), 1);
        let blanked = blank_ranges(code, &spans);
        assert!(!blanked.contains("fn t()"));
        assert!(blanked.contains("fn a() {}") && blanked.contains("fn after() {}"));
    }

    #[test]
    fn a_cfg_test_item_that_ends_in_a_semicolon_is_found() {
        let code = "#[cfg(test)]\nuse helper::thing;\nfn kept() {}\n";
        let blanked = blank_ranges(code, &test_spans(code));
        assert!(!blanked.contains("helper"));
        assert!(blanked.contains("fn kept()"));
    }

    #[test]
    fn a_cfg_test_function_with_an_array_type_ends_at_its_body() {
        let code = "#[cfg(test)]\nfn t(a: [u8; 4]) { let _ = a; }\nfn kept() {}\n";
        let blanked = blank_ranges(code, &test_spans(code));
        assert!(!blanked.contains("fn t"));
        assert!(blanked.contains("fn kept()"));
    }

    #[test]
    fn code_after_a_test_module_is_still_scanned() {
        let code = "#[cfg(test)]\nmod tests { fn x() {} }\nfn production() { danger(); }\n";
        let blanked = blank_ranges(code, &test_spans(code));
        assert!(blanked.contains("danger()"));
    }

    #[test]
    fn find_word_matches_whole_identifiers_only() {
        let hits = find_word(
            "begin_system(); begin_system_x(); my_begin_system(); x.begin_system()",
            "begin_system",
        );
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn the_next_identifier_skips_whitespace() {
        assert_eq!(next_ident("fn   merge_it(", 2), Some((5, "merge_it")));
        assert_eq!(next_ident("fn (", 2), None);
    }

    #[test]
    fn a_brace_block_ends_after_its_matching_brace() {
        let code = "trait T { fn a() { } } tail";
        let (open, end) = brace_block(code, 0).unwrap();
        assert_eq!(&code[open..end], "{ fn a() { } }");
    }

    #[test]
    fn a_source_built_from_text_has_no_test_items() {
        let source = Source::from_text(
            "a.rs",
            "fn real() { danger(); }\n#[cfg(test)]\nmod tests { fn t() { hidden(); } }\n",
        );
        assert!(source.code.contains("danger()") && !source.code.contains("hidden()"));
        assert!(!source.with_strings.contains("hidden()"));
    }

    #[test]
    fn line_numbers_start_at_one() {
        let source = Source::from_text("a.rs", "one\ntwo\nthree");
        assert_eq!(source.line(0), 1);
        assert_eq!(source.line(4), 2);
        assert_eq!(source.location(8), "a.rs:3");
    }

    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_to_a_directory_in_src_is_an_error_not_a_blind_spot() {
        let dir = std::env::temp_dir().join(format!("xtask-scan-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let krate = dir.join("crates/k");
        fs::create_dir_all(krate.join("src")).unwrap();
        fs::write(krate.join("src/lib.rs"), "pub fn real() {}\n").unwrap();
        fs::create_dir_all(dir.join("elsewhere")).unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), krate.join("src/hidden")).unwrap();
        let result = production_sources(&dir, &krate);
        let _ = fs::remove_dir_all(&dir);
        let error = result.err().expect("a directory link must be refused");
        assert!(error.contains("symbolic link"), "{error}");
    }

    #[test]
    fn production_sources_skip_test_files_and_directories() {
        let dir = std::env::temp_dir().join(format!("xtask-scan-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let krate = dir.join("crates/k");
        for (path, body) in [
            ("src/lib.rs", "pub fn real() {}\n"),
            ("src/deep/mod.rs", "pub fn deep() {}\n"),
            ("src/tests.rs", "fn skipped() {}\n"),
            ("src/thing_tests.rs", "fn skipped() {}\n"),
            ("src/thing_test.rs", "fn skipped() {}\n"),
            ("src/tests/helper.rs", "fn skipped() {}\n"),
            ("tests/it.rs", "fn skipped() {}\n"),
            ("benches/b.rs", "fn skipped() {}\n"),
            ("examples/e.rs", "fn skipped() {}\n"),
            ("build.rs", "fn main() {}\n"),
            ("src/notes.txt", "not rust\n"),
        ] {
            let path = krate.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }
        let sources = production_sources(&dir, &krate).unwrap();
        let mut names: Vec<&str> = sources.iter().map(|s| s.relative.as_str()).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "crates/k/build.rs",
                "crates/k/src/deep/mod.rs",
                "crates/k/src/lib.rs"
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
