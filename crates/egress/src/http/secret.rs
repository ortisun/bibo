//! The provider key: the one real credential the broker holds.
//!
//! A [`ProviderKey`] is read from a file that the composition root names (the secret manager
//! delivers it as a file, or a person puts one there for a local run), is never printed, never
//! compared with `==` and never written anywhere except the credential header of the one request
//! to the provider it belongs to.

use std::fmt;
use std::io::Read;
use std::path::Path;

/// The shortest key accepted. The redactor does not register values shorter than 8 characters, and
/// no real provider key is anywhere near this short, so a shorter one is a configuration mistake.
pub const MIN_KEY_LEN: usize = 16;

/// The longest key accepted, and the most bytes read from a key file.
pub const MAX_KEY_LEN: usize = 512;

/// Why a key was not accepted. The set is closed and the messages hold no part of the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    /// The key file could not be read.
    #[error("the key file could not be read")]
    Unreadable,
    /// The key is shorter than the minimum or longer than the maximum.
    #[error("the key has an unacceptable length")]
    Length,
    /// The key holds a character that cannot be in an HTTP header value.
    #[error("the key holds a character that is not allowed")]
    Characters,
}

/// How every Claude subscription token made by `claude setup-token` starts.
pub const SUBSCRIPTION_TOKEN_PREFIX: &str = "sk-ant-oat01-";

/// Why a subscription token was not accepted. The messages hold no part of the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The file holds nothing but whitespace.
    #[error("the token file is empty; run `claude setup-token` and save the token it prints")]
    Empty,
    /// There is whitespace inside the token.
    #[error(
        "the token file has a line break or space inside the token; it was probably wrapped when copied. Save the token again as one line"
    )]
    WrappedWhenCopied,
    /// The value is not a subscription token.
    #[error(
        "the token file does not hold a Claude subscription token: it must start with sk-ant-oat01- (make one with `claude setup-token`; an API key belongs to mode api_key)"
    )]
    NotASubscriptionToken,
    /// The token breaks a rule every credential follows.
    #[error("the subscription token is unusable: {0}")]
    Key(KeyError),
}

/// A provider credential: an API key, or the owner's subscription token.
#[derive(Clone)]
pub struct ProviderKey(String);

impl ProviderKey {
    /// Wraps a key held in memory, such as a test key made at run time.
    ///
    /// # Errors
    /// [`KeyError`] when the key is too short, too long or holds a character outside printable
    /// ASCII.
    pub fn new(key: String) -> Result<Self, KeyError> {
        if !(MIN_KEY_LEN..=MAX_KEY_LEN).contains(&key.len()) {
            return Err(KeyError::Length);
        }
        if !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(KeyError::Characters);
        }
        Ok(Self(key))
    }

    /// Reads a key from a file. One trailing newline is removed. The file is read to at most
    /// [`MAX_KEY_LEN`] plus one byte, so a file that is not a key cannot fill the memory.
    ///
    /// # Errors
    /// [`KeyError`] as for [`ProviderKey::new`], or `Unreadable`.
    pub fn from_file(path: &Path) -> Result<Self, KeyError> {
        let file = std::fs::File::open(path).map_err(|_| KeyError::Unreadable)?;
        let mut text = String::new();
        file.take(MAX_KEY_LEN as u64 + 2)
            .read_to_string(&mut text)
            .map_err(|_| KeyError::Unreadable)?;
        let trimmed = text
            .strip_suffix("\r\n")
            .or_else(|| text.strip_suffix('\n'))
            .unwrap_or(&text);
        Self::new(trimmed.to_owned())
    }

    /// The owner's Claude subscription token, from the text of its file (ADR 0020).
    ///
    /// Whitespace around the token is removed. Whitespace inside it is refused by name: a token
    /// pasted from a terminal that wrapped it holds a line break or a space, and the provider then
    /// answers 401 "OAuth access token is invalid" (seen by the owner on 2026-11-12). A value that
    /// does not start with [`SUBSCRIPTION_TOKEN_PREFIX`] is refused too: an API key in its place
    /// would be sent the wrong way, and anything else is not a token at all.
    ///
    /// # Errors
    /// [`TokenError`].
    pub fn subscription_token(text: &str) -> Result<Self, TokenError> {
        let token = text.trim();
        if token.is_empty() {
            return Err(TokenError::Empty);
        }
        if token.chars().any(char::is_whitespace) {
            return Err(TokenError::WrappedWhenCopied);
        }
        if !token.starts_with(SUBSCRIPTION_TOKEN_PREFIX) {
            return Err(TokenError::NotASubscriptionToken);
        }
        Self::new(token.to_owned()).map_err(TokenError::Key)
    }

    /// The key text. Used for the credential header and for the redactor, nowhere else.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_shows_nothing_in_debug_output() {
        let key = ProviderKey::new("k".repeat(40)).expect("a key");
        let shown = format!("{key:?}");
        assert_eq!(shown, "ProviderKey(<redacted>)");
        assert!(!shown.contains(key.expose()));
    }

    #[test]
    fn a_key_of_the_wrong_length_or_with_odd_characters_is_refused() {
        assert_eq!(
            ProviderKey::new("short".to_owned()).unwrap_err(),
            KeyError::Length
        );
        assert_eq!(
            ProviderKey::new("x".repeat(MAX_KEY_LEN + 1)).unwrap_err(),
            KeyError::Length
        );
        assert_eq!(
            ProviderKey::new(format!("{} {}", "x".repeat(20), "y".repeat(20))).unwrap_err(),
            KeyError::Characters
        );
        assert_eq!(
            ProviderKey::new(format!("{}\n{}", "x".repeat(20), "y".repeat(20))).unwrap_err(),
            KeyError::Characters
        );
    }

    #[test]
    fn a_subscription_token_is_trimmed_and_refused_when_wrapped_or_of_another_kind() {
        let body = "Ab1-_".repeat(20);
        let token = format!("{SUBSCRIPTION_TOKEN_PREFIX}{body}");
        let read = ProviderKey::subscription_token(&format!("  {token}\n")).expect("a token");
        assert_eq!(read.expose(), token);
        let (head, tail) = token.split_at(40);
        for wrapped in [
            format!("{head}\n{tail}"),
            format!("{head} {tail}"),
            format!("{head}\n {tail}\n"),
        ] {
            assert_eq!(
                ProviderKey::subscription_token(&wrapped).unwrap_err(),
                TokenError::WrappedWhenCopied
            );
        }
        assert_eq!(
            ProviderKey::subscription_token(&format!("sk-ant-api03-{body}")).unwrap_err(),
            TokenError::NotASubscriptionToken
        );
        assert_eq!(
            ProviderKey::subscription_token(" \n").unwrap_err(),
            TokenError::Empty
        );
        assert!(
            TokenError::WrappedWhenCopied.to_string().contains(
                "line break or space inside the token; it was probably wrapped when copied"
            )
        );
    }

    #[test]
    fn a_key_file_loses_one_trailing_newline_and_a_missing_file_is_unreadable() {
        let dir = std::env::temp_dir().join(format!("egress-key-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a directory");
        let path = dir.join("key");
        std::fs::write(&path, format!("{}\n", "z".repeat(30))).expect("a file");
        let key = ProviderKey::from_file(&path).expect("a key");
        assert_eq!(key.expose(), "z".repeat(30));
        std::fs::remove_dir_all(&dir).expect("cleanup");
        assert_eq!(
            ProviderKey::from_file(&path).unwrap_err(),
            KeyError::Unreadable
        );
    }
}
