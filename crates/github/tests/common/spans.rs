//! A reading of code spans that is independent of the filter under test.
//!
//! The filter decides which mentions and references to write in a code span. A test that asked the
//! filter itself where code spans are could not catch a mistake in that decision, and the review
//! that found AUT-7 showed the old check ("every `@` is preceded by a backtick") was satisfied by
//! the attack. This reads the text the way CommonMark reads backtick strings, over a whole
//! paragraph (a looser reading than the filter's, which trusts a span only on one line), and says
//! what is left outside every span.

/// The text with every code span replaced by a single space. A string of `n` backticks opens a span
/// that the next string of exactly `n` backticks closes, a backslash escapes the punctuation after
/// it outside a span, and a string with no partner is plain text.
pub fn outside_code_spans(text: &str) -> String {
    let mut shown = String::new();
    for paragraph in text.split("\n\n") {
        let chars: Vec<char> = paragraph.chars().collect();
        let mut index = 0;
        while index < chars.len() {
            let c = chars[index];
            if c == '\\' && chars.get(index + 1).is_some_and(char::is_ascii_punctuation) {
                shown.push(c);
                shown.push(chars[index + 1]);
                index += 2;
            } else if c == '`' {
                let run = chars[index..].iter().take_while(|x| **x == '`').count();
                let mut search = index + run;
                let mut close = None;
                while search < chars.len() {
                    if chars[search] == '`' {
                        let other = chars[search..].iter().take_while(|x| **x == '`').count();
                        if other == run {
                            close = Some(search + other);
                            break;
                        }
                        search += other;
                    } else {
                        search += 1;
                    }
                }
                match close {
                    Some(end) => {
                        shown.push(' ');
                        index = end;
                    }
                    None => {
                        shown.extend(std::iter::repeat_n('`', run));
                        index += run;
                    }
                }
            } else {
                shown.push(c);
                index += 1;
            }
        }
        shown.push_str("\n\n");
    }
    shown
}

/// Panics when the text leaves a mention or a cross-repository reference outside every code span.
pub fn assert_no_live_mention(text: &str, what: &str) {
    let shown = outside_code_spans(text);
    assert!(
        !shown.contains('@'),
        "{what}: a mention is outside every code span: {text}"
    );
    assert!(
        !shown.contains("victim/repo#"),
        "{what}: a reference to another repository is outside every code span: {text}"
    );
}
