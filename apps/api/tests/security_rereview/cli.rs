//! The command line's rule for text that came from the server (API-10), attacked with the whole of
//! the control range and with the characters that hide or reorder text. The module under test is the
//! CLI's own file, included as it is, so no binary has to be built.

#[path = "../../../cli/src/render.rs"]
#[allow(dead_code)]
mod render;

/// Every control character, one by one, in front of and inside a word: C0, DEL and C1, which holds
/// the single-character CSI (0x9b), the operating system command (0x9d) and the device control string
/// (0x90). An escape sequence, a hyperlink escape (OSC 8) and a title change are strings of these.
#[test]
fn held_every_control_character_and_every_escape_sequence_is_removed() {
    let controls: Vec<char> = (0_u32..=0x1f)
        .chain(0x7f..=0x9f)
        .filter_map(char::from_u32)
        .collect();
    for c in &controls {
        let text = format!("a{c}b");
        let shown = render::printable(&text);
        assert!(
            !shown.contains(*c),
            "U+{:04X} survived: {shown:?}",
            *c as u32
        );
    }
    for text in [
        "\u{1b}[2J\u{1b}[H",
        "\u{1b}]8;;https://attacker.test\u{7}click\u{1b}]8;;\u{7}",
        "\u{1b}]0;new title\u{7}",
        "\u{9b}2J",
        "\u{9d}0;title\u{9c}",
        "\u{90}q#0\u{9c}",
        "line one\rline two",
        "a\u{8}\u{8}b",
    ] {
        let shown = render::printable(text);
        assert!(
            !shown.chars().any(|c| c.is_control()),
            "{text:?} left a control character in {shown:?}"
        );
    }
    // The finished block keeps line feeds and tabs and nothing else.
    let block = render::printable_block("a\nb\tc\u{1b}[31mred\u{9b}0m\r");
    assert!(
        !block
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t'),
        "{block:?}"
    );
}

/// RR-9 (fixed). The rule listed the zero-width marks, the embeddings and overrides, the isolates and the line
/// separators, and misses others of the same kind. The Arabic letter mark (U+061C) is a bidirectional
/// control and reorders the text around it; the six deprecated format characters (U+206A to U+206F)
/// switch shaping and swapping; and the tag characters (U+E0000 to U+E007F) are invisible copies of
/// ASCII that a terminal or a pasted line carries without showing them. The outbound text filter of
/// the GitHub adapter already removes U+061C, U+00AD and U+180E; the CLI does not.
#[test]
fn rr_9_characters_that_reorder_or_hide_text_are_removed_from_server_text() {
    let mut survivors = Vec::new();
    let candidates: Vec<char> = std::iter::once('\u{061c}')
        .chain('\u{206a}'..='\u{206f}')
        .chain(std::iter::once('\u{00ad}'))
        .chain(std::iter::once('\u{180e}'))
        .chain('\u{e0000}'..='\u{e007f}')
        .collect();
    for c in candidates {
        let text = format!("a{c}b");
        let shown = render::printable(&text);
        if shown.contains(c) {
            survivors.push(format!("U+{:04X}", c as u32));
        }
    }
    assert!(
        survivors.is_empty(),
        "{} characters survive printable(), the first of them {}",
        survivors.len(),
        survivors
            .iter()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    );
}

/// Plain text, including text in other scripts, is not touched.
#[test]
fn held_ordinary_text_is_left_alone() {
    for text in [
        "queued",
        "ok: 12 tests",
        "caf\u{e9} \u{65e5}\u{672c}\u{8a9e} \u{627}\u{644}",
    ] {
        assert_eq!(render::printable(text), text);
    }
}

/// The CLI and the names in a repository share one rule for text that hides or reorders (RR-9): every
/// character that `RepoPath` refuses as hidden, and every control character, is replaced by
/// `printable`, over the whole range of code points. A character added to one rule is in the other,
/// because there is one function.
#[test]
fn rr_9_the_cli_removes_every_character_that_a_repository_name_may_not_hold() {
    let mut survivors = Vec::new();
    for code in 0_u32..=0x0010_ffff {
        let Some(c) = char::from_u32(code) else {
            continue;
        };
        if !(c.is_control() || factory_ports::paths::hides_text(c)) {
            continue;
        }
        if render::printable(&format!("a{c}b")).contains(c) {
            survivors.push(code);
            if survivors.len() > 5 {
                break;
            }
        }
    }
    assert!(survivors.is_empty(), "survivors: {survivors:x?}");
}
