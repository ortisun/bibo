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

/// A provider API key.
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
