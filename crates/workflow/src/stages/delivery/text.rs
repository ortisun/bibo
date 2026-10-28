//! Text on its way to the pull request: made safe before it is placed in a sentence, and checked
//! as a whole before it is sent.
//!
//! The delivery stage writes every sentence of the pull request itself, from typed evidence. The
//! few fragments that a person or a model wrote earlier (the title of the frozen specification, a
//! gate name) are placed into those sentences only through [`fragment`], which keeps letters,
//! digits and a small set of punctuation and drops everything that could be markup, a link, an
//! image, a mention or hidden content. A fragment can therefore never open a structure of its own
//! in the Markdown around it.
//!
//! [`finish`] then checks the whole body: no secret (`Redactor::contains_secret`, fail closed), no
//! character that renders as markup where the template did not put it, no URL that is not on the
//! allow list, and no more than the size cap. The adapter cleans outbound text again; this check is
//! the stage's own, so the stage does not depend on the adapter to be safe.

use factory_domain::redaction::Redactor;

/// The largest body the stage sends, in bytes (`output_hygiene.max_body_bytes`).
pub const MAX_BODY_BYTES: usize = 60_000;

/// The most characters of one fragment.
const MAX_FRAGMENT_CHARS: usize = 120;

/// Why a text cannot be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TextRefused {
    /// The text holds something that looks like a secret, or the scan could not decide.
    #[error("the text holds something that looks like a secret")]
    Secret,
    /// The text is empty after cleaning, or longer than the cap.
    #[error("the text is empty or too long")]
    Size,
    /// The text holds a URL that is not on the allow list, an image or raw HTML.
    #[error("the text holds a link, an image or markup that is not allowed")]
    Markup,
}

/// True for a character that is invisible or changes how text is laid out: control characters,
/// zero-width characters and bidirectional controls.
fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00ad}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

/// A fragment of untrusted text made safe to place inside a sentence: one line, letters, digits,
/// spaces and `. , : ; ' " - / ? %`. Markup, links, mentions, images and hidden characters are
/// dropped, and a word that starts a URL is dropped whole.
#[must_use]
pub fn fragment(text: &str) -> String {
    let words: Vec<String> = text
        .split_whitespace()
        .filter(|word| {
            let lower = word.to_ascii_lowercase();
            !(lower.contains("://") || lower.starts_with("www.") || lower.starts_with("data:"))
        })
        .map(|word| {
            word.chars()
                .filter(|c| !hidden(*c))
                .filter(|c| {
                    c.is_alphanumeric()
                        || matches!(
                            c,
                            '.' | ',' | ':' | ';' | '\'' | '"' | '-' | '/' | '?' | '%'
                        )
                })
                .collect::<String>()
        })
        .filter(|word| !word.is_empty())
        .collect();
    let joined = words.join(" ");
    joined
        .chars()
        .take(MAX_FRAGMENT_CHARS)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// Every host in `text` that follows `http://` or `https://`.
fn url_hosts(text: &str) -> Vec<&str> {
    let mut hosts = Vec::new();
    for scheme in ["https://", "http://"] {
        for (at, _) in text.match_indices(scheme) {
            let rest = &text[at + scheme.len()..];
            let end = rest
                .find(|c: char| {
                    matches!(
                        c,
                        '/' | ')' | ']' | ' ' | '\n' | '"' | '\'' | '>' | '?' | '#'
                    )
                })
                .unwrap_or(rest.len());
            hosts.push(&rest[..end]);
        }
    }
    hosts
}

/// Checks a finished title or body.
///
/// # Errors
/// [`TextRefused`]: a secret (or a scan that failed), an empty or oversized text, an image, raw
/// HTML, an HTML comment, a hidden character, a link to a host that is not on `allowed_hosts`, or
/// a mention that would notify someone.
pub fn finish(text: &str, redactor: &Redactor, allowed_hosts: &[&str]) -> Result<(), TextRefused> {
    match redactor.contains_secret(text.as_bytes()) {
        Ok(false) => {}
        Ok(true) | Err(_) => return Err(TextRefused::Secret),
    }
    if text.trim().is_empty() || text.len() > MAX_BODY_BYTES {
        return Err(TextRefused::Size);
    }
    if text.chars().any(|c| hidden(c) && c != '\n' && c != '\t') {
        return Err(TextRefused::Markup);
    }
    if text.contains("![")
        || text.contains("<!--")
        || text.contains('<')
        || text.contains("](javascript:")
    {
        return Err(TextRefused::Markup);
    }
    for host in url_hosts(text) {
        let host = host.to_ascii_lowercase();
        let allowed = allowed_hosts
            .iter()
            .any(|ok| host == *ok || host.ends_with(&format!(".{ok}")));
        if !allowed {
            return Err(TextRefused::Markup);
        }
    }
    // A mention is an `@` that starts a word and is not inside a code span written by the
    // template. The template writes none, so any `@` at all is refused.
    if text.contains('@') {
        return Err(TextRefused::Markup);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::redaction::PatternAction;

    fn redactor() -> Redactor {
        Redactor::builder()
            .pattern("token", "tok_[A-Za-z0-9]{20}", PatternAction::Block)
            .build()
            .expect("a redactor")
    }

    #[test]
    fn a_fragment_keeps_words_and_loses_markup_links_and_mentions() {
        let hostile = "Add [login](https://evil.test/?d=1) ![x](https://evil.test/p.png) @everyone <b>now</b>\u{200b}";
        let cleaned = fragment(hostile);
        for bad in ["[", "]", "(", ")", "!", "@", "<", ">", "://", "\u{200b}"] {
            assert!(!cleaned.contains(bad), "{bad:?} survived in {cleaned:?}");
        }
        assert!(cleaned.starts_with("Add"), "{cleaned}");
    }

    #[test]
    fn a_fragment_is_one_line_and_bounded() {
        let long = "word ".repeat(200);
        let cleaned = fragment(&format!("a\nb\r\n{long}"));
        assert!(!cleaned.contains('\n'));
        assert!(cleaned.chars().count() <= MAX_FRAGMENT_CHARS);
    }

    #[test]
    fn cleaning_twice_changes_nothing() {
        let once = fragment("Fix the `parser` for @bob; see https://x.test and more");
        assert_eq!(fragment(&once), once);
    }

    #[test]
    fn a_body_with_a_secret_is_refused_whatever_else_it_says() {
        let secret = format!("{}{}", "tok_", "A1b2C3d4E5f6G7h8I9j0");
        let body = format!("Plain words only. {secret}");
        assert_eq!(
            finish(&body, &redactor(), &["github.com"]),
            Err(TextRefused::Secret)
        );
    }

    #[test]
    fn images_html_mentions_and_foreign_links_are_refused() {
        let r = redactor();
        for bad in [
            "text ![x](https://github.com/a.png)",
            "text <img src=x>",
            "text <!-- hidden -->",
            "text @someone",
            "text [here](https://evil.test/p)",
            "text https://evil.test/p",
            "text\u{202e}reversed",
        ] {
            assert_eq!(
                finish(bad, &r, &["github.com"]),
                Err(TextRefused::Markup),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_link_to_the_code_host_and_plain_prose_pass() {
        let body = "Closes #12.\n\nSee [the change](https://github.com/owner/repo/pull/3).";
        assert_eq!(finish(body, &redactor(), &["github.com"]), Ok(()));
    }

    #[test]
    fn an_empty_or_oversized_body_is_refused() {
        let r = redactor();
        assert_eq!(finish("  \n", &r, &[]), Err(TextRefused::Size));
        assert_eq!(
            finish(&"a".repeat(MAX_BODY_BYTES + 1), &r, &[]),
            Err(TextRefused::Size)
        );
    }
}
