//! Policy regular expressions compile the same way in a production build as in a test build.
//!
//! The policy uses case-insensitive patterns. Unicode-aware case folding needs the `unicode-case`
//! feature of the `regex` crate, and this crate does not enable it. A test build gets it by
//! accident, because a development dependency enables it, so every test passed while a production
//! build refused the real policy. The fix is to compile policy patterns without Unicode mode, which
//! is also how the redactor compiles them. These tests pin the behavior that does not depend on
//! which features happen to be switched on.

use factory_contracts::policy::RegexText;

fn compile(pattern: &str) -> regex::bytes::Regex {
    RegexText(pattern.to_owned())
        .compile()
        .unwrap_or_else(|e| panic!("`{pattern}` must compile: {e}"))
}

#[test]
fn case_insensitive_matching_is_ascii_only() {
    let re = compile("(?i)k");
    assert!(re.is_match(b"K"), "an ASCII capital must match");
    // The Kelvin sign folds to `k` in Unicode mode. The redactor compiles policy patterns without
    // Unicode mode, so the loader must accept exactly the patterns it will use.
    assert!(
        !re.is_match("\u{212A}".as_bytes()),
        "the Kelvin sign must not match: policy patterns are compiled in ASCII mode"
    );
}

#[test]
fn a_word_boundary_follows_ascii_word_characters() {
    let re = compile(r"\bgh[ou]_[A-Za-z0-9]{4}\b");
    assert!(re.is_match(b"a ghu_ab12 b"));
    // A letter outside ASCII is not a word character in ASCII mode, so the boundary holds.
    assert!(re.is_match("\u{e9}ghu_ab12".as_bytes()));
}

#[test]
fn an_invalid_pattern_is_still_refused() {
    assert!(RegexText("(unclosed".to_owned()).compile().is_err());
    assert!(
        RegexText(r"(?<=a)b".to_owned()).compile().is_err(),
        "no look-around"
    );
}
