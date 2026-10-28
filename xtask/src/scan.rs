//! Reading Rust sources for the source-scan rules.
//!
//! The scans work on text, not on a syntax tree, so they first blank out what must not match:
//! comments, test-only items and, for identifier scans, string contents. Blanking keeps every
//! byte offset and newline where it was, so a hit maps straight to a line number.

use crate::syntax::{self, Syntax};
use std::collections::{BTreeMap, BTreeSet};
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
pub(crate) fn block_comment_end(bytes: &[u8], start: usize) -> usize {
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
pub(crate) fn char_literal_end(source: &str, at: usize) -> Option<usize> {
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

/// Blank everything after a `#` that is outside quotes, line by line. Keeps offsets and newlines.
pub fn without_hash_comments(text: &str) -> String {
    text.split('\n')
        .map(|line| {
            let mut quote = None;
            for (at, c) in line.char_indices() {
                match (quote, c) {
                    (None, '"' | '\'') => quote = Some(c),
                    (Some(open), c) if c == open => quote = None,
                    (None, '#') => {
                        return format!("{}{}", &line[..at], " ".repeat(line.len() - at));
                    }
                    _ => {}
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One production source file, ready to scan.
pub struct Source {
    /// Path relative to the workspace root, with forward slashes.
    pub relative: String,
    pub with_strings: String,
    pub code: String,
    /// The tokens of the production text, for the scans that resolve imports and aliases.
    pub syntax: Syntax,
}

impl Source {
    /// Mask comments and strings, then blank the items that exist only in test builds. Whether
    /// an item is test-only is decided from its `cfg` attributes alone (see `syntax`).
    pub fn from_text(relative: &str, text: &str) -> Self {
        let masked = mask(text);
        let (spans, _) = syntax::lex(text).test_ranges();
        let production = blank_ranges(text, &spans);
        Self {
            relative: relative.to_string(),
            with_strings: blank_ranges(&masked.with_strings, &spans),
            code: blank_ranges(&masked.code, &spans),
            syntax: syntax::lex(&production),
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

/// What the module tree says about one file.
struct ParsedFile {
    text: String,
    /// The files that `mod x;` and `include!` pull in, with whether a `cfg` makes the pull
    /// test-only.
    children: Vec<(PathBuf, bool)>,
    /// An inner `#![cfg(test)]` makes the whole file test code.
    whole_file_is_test: bool,
}

/// The production Rust sources of one crate, without test code.
///
/// Test code is decided from `cfg` attributes and nothing else (review finding F-12): an item
/// under `#[cfg(test)]` (see `syntax::Syntax::test_ranges`), and a file that is pulled in only
/// by a `mod` declaration under such an attribute, or that starts with `#![cfg(test)]`. A file
/// called `tests.rs` or `webhook_tests.rs`, or one under a `tests` directory inside `src`, is
/// production code unless a `cfg(test)` module declares it, because Cargo compiles it into the
/// library either way. A file in `src` that no module declares is scanned too: it is not
/// compiled today, but an `include!` or a later `mod` line would bring it in.
///
/// The files outside `src` that production targets name (`[lib] path`, `[[bin]] path`) and the
/// files that `#[path]` and `include!` point at are followed. The `tests`, `benches` and
/// `examples` directories at the crate root are separate Cargo targets, not production code.
pub fn production_sources(
    root: &Path,
    crate_dir: &Path,
    target_roots: &[PathBuf],
) -> Result<Vec<Source>, String> {
    let mut found = Vec::new();
    let build = crate_dir.join("build.rs");
    if build.is_file() {
        found.push(build);
    }
    collect_rust_files(&crate_dir.join("src"), &mut found)?;
    let mut roots: Vec<PathBuf> = target_roots.to_vec();
    roots.extend(found.iter().cloned());

    // Parse every file reachable from any candidate, once.
    let mut parsed: BTreeMap<PathBuf, ParsedFile> = BTreeMap::new();
    let mut pending: Vec<PathBuf> = roots.iter().filter_map(|f| clean(f)).collect();
    while let Some(file) = pending.pop() {
        if parsed.contains_key(&file) {
            continue;
        }
        let text = fs::read_to_string(&file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        let syntax = syntax::lex(&text);
        let (_, whole_file_is_test) = syntax.test_ranges();
        let is_target = target_roots
            .iter()
            .any(|t| clean(t).as_deref() == Some(&file));
        let mut children = Vec::new();
        for decl in syntax.mod_declarations() {
            for child in module_files(&file, is_target, &decl) {
                children.push((child, decl.test_only));
            }
        }
        for include in syntax.includes() {
            let dir = file.parent().unwrap_or(Path::new("."));
            children.extend(clean(&dir.join(include)).map(|p| (p, false)));
        }
        pending.extend(children.iter().map(|(c, _)| c.clone()));
        parsed.insert(
            file,
            ParsedFile {
                text,
                children,
                whole_file_is_test,
            },
        );
    }

    // Roots are the production targets and every file no module declares. From them follow the
    // declarations that exist outside test builds.
    let referenced: BTreeSet<&PathBuf> = parsed
        .values()
        .flat_map(|f| f.children.iter().map(|(c, _)| c))
        .collect();
    let mut production: BTreeSet<PathBuf> = BTreeSet::new();
    let mut walk: Vec<PathBuf> = parsed
        .keys()
        .filter(|f| !referenced.contains(f))
        .cloned()
        .chain(target_roots.iter().filter_map(|t| clean(t)))
        .collect();
    while let Some(file) = walk.pop() {
        let Some(info) = parsed.get(&file) else {
            continue;
        };
        if info.whole_file_is_test || !production.insert(file) {
            continue;
        }
        walk.extend(
            info.children
                .iter()
                .filter(|(_, test)| !test)
                .map(|(c, _)| c.clone()),
        );
    }

    let mut sources = Vec::new();
    for file in production {
        let relative = file
            .strip_prefix(clean(root).unwrap_or_else(|| root.to_path_buf()))
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        sources.push(Source::from_text(&relative, &parsed[&file].text));
    }
    Ok(sources)
}

fn clean(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}

/// The existing files that `mod name;` can mean in `file`. A file named `lib.rs`, `main.rs` or
/// `mod.rs`, and any target root, keeps its children beside it; any other file `a/b.rs` keeps
/// them in `a/b/`.
fn module_files(file: &Path, is_target: bool, decl: &syntax::ModDeclaration) -> Vec<PathBuf> {
    let dir = file.parent().unwrap_or(Path::new("."));
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let owns_directory = is_target || matches!(stem, "lib" | "main" | "mod");
    let mut base = if owns_directory {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    for parent in &decl.inline_parents {
        base.push(parent);
    }
    let candidates = match &decl.path_attribute {
        Some(path) => vec![dir.join(path)],
        None => vec![
            base.join(format!("{}.rs", decl.name)),
            base.join(&decl.name).join("mod.rs"),
        ],
    };
    candidates.iter().filter_map(|c| clean(c)).collect()
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
            collect_rust_files(&path, files)?;
        } else if name.ends_with(".rs") {
            files.push(path);
        }
    }
    Ok(())
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
        let blanked = without_test_items(code);
        assert!(!blanked.contains("fn t()"));
        assert!(blanked.contains("fn a() {}") && blanked.contains("fn after() {}"));
    }

    fn without_test_items(code: &str) -> String {
        let (spans, _) = syntax::lex(code).test_ranges();
        blank_ranges(code, &spans)
    }

    #[test]
    fn a_cfg_test_item_that_ends_in_a_semicolon_is_found() {
        let code = "#[cfg(test)]\nuse helper::thing;\nfn kept() {}\n";
        let blanked = without_test_items(code);
        assert!(!blanked.contains("helper"));
        assert!(blanked.contains("fn kept()"));
    }

    #[test]
    fn a_cfg_test_function_with_an_array_type_ends_at_its_body() {
        let code = "#[cfg(test)]\nfn t(a: [u8; 4]) { let _ = a; }\nfn kept() {}\n";
        let blanked = without_test_items(code);
        assert!(!blanked.contains("fn t"));
        assert!(blanked.contains("fn kept()"));
    }

    #[test]
    fn code_after_a_test_module_is_still_scanned() {
        let code = "#[cfg(test)]\nmod tests { fn x() {} }\nfn production() { danger(); }\n";
        assert!(without_test_items(code).contains("danger()"));
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
    fn a_hash_comment_is_blanked_but_a_hash_in_quotes_is_kept() {
        let text = "a: 1 # note safe.directory=*\nb: \"x # y\" # tail\n";
        let blanked = without_hash_comments(text);
        assert_eq!(blanked.len(), text.len());
        assert!(!blanked.contains("note") && !blanked.contains("tail"));
        assert!(blanked.contains("\"x # y\""));
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
        let result = production_sources(&dir, &krate, &[]);
        let _ = fs::remove_dir_all(&dir);
        let error = result.err().expect("a directory link must be refused");
        assert!(error.contains("symbolic link"), "{error}");
    }

    /// Write `files` under a fresh crate directory and return the relative names of the
    /// production sources found.
    fn production_names(label: &str, files: &[(&str, &str)], targets: &[&str]) -> Vec<String> {
        let dir = std::env::temp_dir().join(format!("xtask-scan-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let krate = dir.join("crates/k");
        for (path, body) in files {
            let path = krate.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, body).unwrap();
        }
        let target_roots: Vec<PathBuf> = targets.iter().map(|t| krate.join(t)).collect();
        let sources = production_sources(&dir, &krate, &target_roots).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let mut names: Vec<String> = sources.iter().map(|s| s.relative.clone()).collect();
        names.sort_unstable();
        names
    }

    #[test]
    fn a_file_is_test_code_only_when_a_cfg_test_module_declares_it() {
        let names = production_names(
            "cfg",
            &[
                (
                    "src/lib.rs",
                    "mod real;\n#[cfg(test)]\nmod tests;\n#[cfg(test)]\nmod helper_tests;\n",
                ),
                ("src/real.rs", "pub fn real() {}\n"),
                ("src/tests.rs", "mod nested;\nfn skipped() {}\n"),
                ("src/tests/nested.rs", "fn skipped() {}\n"),
                ("src/helper_tests.rs", "fn skipped() {}\n"),
                ("tests/it.rs", "fn skipped() {}\n"),
                ("benches/b.rs", "fn skipped() {}\n"),
                ("examples/e.rs", "fn skipped() {}\n"),
                ("build.rs", "fn main() {}\n"),
                ("src/notes.txt", "not rust\n"),
            ],
            &[],
        );
        assert_eq!(
            names,
            [
                "crates/k/build.rs",
                "crates/k/src/lib.rs",
                "crates/k/src/real.rs"
            ]
        );
    }

    #[test]
    fn files_named_like_tests_are_production_when_nothing_marks_them_test_only() {
        let names = production_names(
            "names",
            &[
                ("src/lib.rs", "mod webhook_tests;\nmod tests;\n"),
                ("src/webhook_tests.rs", "pub fn m() {}\n"),
                ("src/tests/mod.rs", "pub fn m() {}\n"),
                ("src/thing_test.rs", "pub fn orphan() {}\n"),
            ],
            &[],
        );
        assert_eq!(
            names,
            [
                "crates/k/src/lib.rs",
                "crates/k/src/tests/mod.rs",
                "crates/k/src/thing_test.rs",
                "crates/k/src/webhook_tests.rs"
            ]
        );
    }

    #[test]
    fn an_inner_cfg_test_attribute_makes_a_declared_file_test_only() {
        let names = production_names(
            "inner",
            &[
                ("src/lib.rs", "mod only_for_tests;\n"),
                ("src/only_for_tests.rs", "#![cfg(test)]\nfn t() {}\n"),
            ],
            &[],
        );
        assert_eq!(names, ["crates/k/src/lib.rs"]);
    }

    #[test]
    fn path_attributes_and_include_follow_files_outside_src() {
        let names = production_names(
            "path",
            &[
                (
                    "src/lib.rs",
                    "#[path = \"../shared/moved.rs\"]\nmod moved;\ninclude!(\"../generated.rs\");\n",
                ),
                ("shared/moved.rs", "pub fn m() {}\n"),
                ("generated.rs", "pub fn g() {}\n"),
                ("shared/unrelated.rs", "pub fn u() {}\n"),
            ],
            &[],
        );
        assert_eq!(
            names,
            [
                "crates/k/generated.rs",
                "crates/k/shared/moved.rs",
                "crates/k/src/lib.rs"
            ]
        );
    }

    #[test]
    fn a_target_root_outside_src_is_scanned_with_its_modules() {
        let names = production_names(
            "target",
            &[
                ("src/lib.rs", ""),
                ("other/entry.rs", "mod child;\n"),
                ("other/child.rs", ""),
            ],
            &["other/entry.rs"],
        );
        assert_eq!(
            names,
            [
                "crates/k/other/child.rs",
                "crates/k/other/entry.rs",
                "crates/k/src/lib.rs"
            ]
        );
    }
}
