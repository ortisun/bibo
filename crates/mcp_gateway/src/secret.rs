//! Credentials read from files, and the per-run bearer token. Neither is ever shown by `Debug`,
//! `Display` or an error.

use std::fmt;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};

/// A credential value. `Debug` shows `<redacted>`; the value leaves only through
/// [`SecretValue::expose`], inside this crate and to the caller that builds a header.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wraps a value read by the caller, for an upstream built in code (tests, the app).
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The value itself. Put it in a header or register it with the redactor; never log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(<redacted>)")
    }
}

/// A credential file could not be used. The message names the file, never its content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CredentialError {
    /// The file does not exist or cannot be opened or read.
    #[error("the {what} file {} cannot be read", path.display())]
    Unreadable {
        /// What the file holds, such as "Datadog API key".
        what: &'static str,
        /// The file.
        path: PathBuf,
    },
    /// The path is not a regular file.
    #[error("the {what} file {} is not a regular file", path.display())]
    NotAFile {
        /// What the file holds.
        what: &'static str,
        /// The file.
        path: PathBuf,
    },
    /// Group or others may read or write the file.
    #[error(
        "the {what} file {} has mode {mode:o}; it must be 0600 or stricter (chmod 600)",
        path.display()
    )]
    TooOpen {
        /// What the file holds.
        what: &'static str,
        /// The file.
        path: PathBuf,
        /// The permission bits found.
        mode: u32,
    },
    /// The first line is empty.
    #[error("the {what} file {} is empty", path.display())]
    Empty {
        /// What the file holds.
        what: &'static str,
        /// The file.
        path: PathBuf,
    },
    /// The value holds a character an HTTP header value cannot carry.
    #[error("the {what} file {} holds a value that is not a valid HTTP header value", path.display())]
    NotAHeaderValue {
        /// What the file holds.
        what: &'static str,
        /// The file.
        path: PathBuf,
    },
}

/// The largest credential file read, so a wrong path to a large file fails fast.
const MAX_CREDENTIAL_FILE_BYTES: u64 = 16 * 1024;

/// Reads a credential from a file that only its owner may read or write (mode 0600 or stricter).
/// The value is the first line without its line end. The mode is checked on the opened file, so
/// the file checked is the file read.
///
/// # Errors
/// A [`CredentialError`] naming the file, never its content.
pub fn read_secret_file(path: &Path, what: &'static str) -> Result<SecretValue, CredentialError> {
    let unreadable = || CredentialError::Unreadable {
        what,
        path: path.to_path_buf(),
    };
    let file = std::fs::File::open(path).map_err(|_| unreadable())?;
    let metadata = file.metadata().map_err(|_| unreadable())?;
    if !metadata.is_file() {
        return Err(CredentialError::NotAFile {
            what,
            path: path.to_path_buf(),
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(CredentialError::TooOpen {
            what,
            path: path.to_path_buf(),
            mode,
        });
    }
    let mut text = String::new();
    file.take(MAX_CREDENTIAL_FILE_BYTES)
        .read_to_string(&mut text)
        .map_err(|_| unreadable())?;
    let value = text.lines().next().unwrap_or("").trim_end().to_owned();
    if value.is_empty() {
        return Err(CredentialError::Empty {
            what,
            path: path.to_path_buf(),
        });
    }
    if !value.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(CredentialError::NotAHeaderValue {
            what,
            path: path.to_path_buf(),
        });
    }
    Ok(SecretValue(value))
}

/// The bearer token of one agent run: 256 random bits from the operating system, base64url
/// without padding (43 characters). `Debug` shows `<redacted>`.
#[derive(Clone, PartialEq, Eq)]
pub struct RunToken(String);

impl RunToken {
    /// A fresh token.
    pub(crate) fn generate() -> Result<Self, ring::error::Unspecified> {
        let mut bytes = [0_u8; 32];
        SystemRandom::new().fill(&mut bytes)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// The token, for the agent's MCP configuration (`Authorization: Bearer <token>`). Never log
    /// it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether `presented` is this token, compared in time that does not depend on where the
    /// first difference is.
    pub(crate) fn matches(&self, presented: &str) -> bool {
        constant_time_eq(self.0.as_bytes(), presented.as_bytes())
    }
}

impl fmt::Debug for RunToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RunToken(<redacted>)")
    }
}

/// Equality whose time depends only on the length of `expected`.
fn constant_time_eq(expected: &[u8], presented: &[u8]) -> bool {
    let mut difference = u8::from(expected.len() != presented.len());
    for (index, byte) in expected.iter().enumerate() {
        difference |= byte ^ presented.get(index).copied().unwrap_or(0);
    }
    std::hint::black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scratch(name: &str, mode: u32, content: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "factory-mcp-gateway-secret-{}-{name}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("value");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(content.as_bytes()).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[test]
    fn a_file_readable_by_others_is_refused_without_its_content() {
        let path = scratch("open", 0o644, "fake-credential-for-a-test\n");
        let error = read_secret_file(&path, "Datadog API key").expect_err("refused");
        let text = error.to_string();
        assert!(text.contains("mode 644"), "{text}");
        assert!(text.contains(&path.display().to_string()), "{text}");
        assert!(!text.contains("fake-credential"), "{text}");
        assert!(!format!("{error:?}").contains("fake-credential"));
    }

    #[test]
    fn group_readable_and_group_writable_are_refused_too() {
        for mode in [0o640, 0o620, 0o604, 0o660] {
            let path = scratch(&format!("mode-{mode:o}"), mode, "fake-credential\n");
            assert!(matches!(
                read_secret_file(&path, "token"),
                Err(CredentialError::TooOpen { .. })
            ));
        }
    }

    #[test]
    fn mode_0600_and_0400_are_read_first_line_only() {
        let path = scratch("private", 0o600, "first-line-value\nsecond\n");
        let value = read_secret_file(&path, "token").expect("read");
        assert_eq!(value.expose(), "first-line-value");
        assert_eq!(format!("{value:?}"), "SecretValue(<redacted>)");
        let path = scratch("readonly", 0o400, "other-value");
        assert_eq!(
            read_secret_file(&path, "token").expect("read").expose(),
            "other-value"
        );
    }

    #[test]
    fn empty_missing_and_control_characters_are_refused() {
        let path = scratch("empty", 0o600, "\n");
        assert!(matches!(
            read_secret_file(&path, "token"),
            Err(CredentialError::Empty { .. })
        ));
        let missing = std::env::temp_dir().join("factory-mcp-gateway-no-such-file");
        assert!(matches!(
            read_secret_file(&missing, "token"),
            Err(CredentialError::Unreadable { .. })
        ));
        let path = scratch("control", 0o600, "bad\u{7}value\n");
        assert!(matches!(
            read_secret_file(&path, "token"),
            Err(CredentialError::NotAHeaderValue { .. })
        ));
    }

    #[test]
    fn run_tokens_are_256_bits_base64url_distinct_and_redacted_in_debug() {
        let a = RunToken::generate().expect("token");
        let b = RunToken::generate().expect("token");
        assert_eq!(a.expose().len(), 43);
        assert!(
            a.expose()
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_ne!(a, b);
        assert_eq!(format!("{a:?}"), "RunToken(<redacted>)");
        assert!(a.matches(a.expose()));
        assert!(!a.matches(b.expose()));
        assert!(!a.matches(""));
        assert!(!a.matches(&a.expose()[..42]));
        assert!(!a.matches(&format!("{}x", a.expose())));
    }
}
