//! The HTTP client of the command line.
//!
//! One agent, built to be safe for a bearer token:
//!
//! * the address must be `https`, or `http` to a loopback host; a token is never sent in clear text
//!   over a network;
//! * an address with a user name or password in it is refused;
//! * redirects are off (a `Location` on another host would otherwise receive the token);
//! * environment proxies are off;
//! * a 30 second timeout over the whole call and a 4 MiB limit on the answer.
//!
//! The token is read from a file when the client is built and lives in a value that prints as a
//! placeholder. It reaches the wire in the `Authorization` header and nowhere else.

use std::path::Path;
use std::time::Duration;

use factory_composition::config::{SecretFile, SecretText};
use serde_json::Value;
use ureq::http;

/// The longest the command waits for the API.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// The largest answer the command reads.
pub const MAX_ANSWER_BYTES: u64 = 4 * 1024 * 1024;

/// Why the client could not even ask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The address is not usable. The text says why, without repeating the address.
    BadAddress(&'static str),
    /// The token file is missing, unsafe or empty. The text names the file, never its content.
    Token(String),
}

impl std::error::Error for ClientError {}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadAddress(why) => write!(f, "the API address is not usable: {why}"),
            Self::Token(why) => f.write_str(why),
        }
    }
}

/// What the API answered.
#[derive(Debug, Clone)]
pub struct Answer {
    /// The HTTP status.
    pub status: u16,
    /// The body as JSON, or `Null` when it is not JSON.
    pub body: Value,
}

/// How a call failed before there was an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// The connection could not be made, or the TLS handshake failed.
    Connect,
    /// The API did not answer in time.
    Timeout,
    /// The answer was not HTTP or was too large.
    Protocol,
}

impl std::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Connect => "the API could not be reached",
            Self::Timeout => "the API did not answer in time",
            Self::Protocol => "the API did not answer in a way this command understands",
        })
    }
}

/// A checked base address: `scheme://host[:port]`, no path, no credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base(String);

impl Base {
    /// Checks an address.
    ///
    /// # Errors
    /// [`ClientError::BadAddress`].
    pub fn parse(text: &str) -> Result<Self, ClientError> {
        let (scheme, rest) = text.split_once("://").ok_or(ClientError::BadAddress(
            "it must start with https:// or http://",
        ))?;
        let authority = rest.trim_end_matches('/');
        if authority.is_empty()
            || authority.contains(['/', '?', '#', '@', ' '])
            || authority.chars().any(char::is_control)
        {
            return Err(ClientError::BadAddress(
                "it must be scheme://host or scheme://host:port with no path and no credentials",
            ));
        }
        let host = if let Some(bracketed) = authority.strip_prefix('[') {
            bracketed.split(']').next().unwrap_or("")
        } else {
            authority.split(':').next().unwrap_or("")
        };
        match scheme {
            "https" => {}
            "http" if matches!(host, "127.0.0.1" | "localhost" | "::1") => {}
            "http" => {
                return Err(ClientError::BadAddress(
                    "http is allowed only to a loopback address; use https",
                ));
            }
            _ => {
                return Err(ClientError::BadAddress("the scheme must be https or http"));
            }
        }
        Ok(Self(format!("{scheme}://{authority}")))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.0)
    }

    fn is_plain(&self) -> bool {
        self.0.starts_with("http://")
    }
}

/// Reads a token from a file.
///
/// # Errors
/// [`ClientError::Token`] when the file is a symbolic link, is not a regular file, can be read by
/// group or others, cannot be read, or is empty.
pub fn read_token(path: &Path) -> Result<SecretText, ClientError> {
    let secret = SecretFile::at(path)
        .read()
        .map_err(|error| ClientError::Token(format!("the token file cannot be used: {error}")))?;
    if secret.expose().is_empty() {
        return Err(ClientError::Token(format!(
            "the token file {} is empty",
            path.display()
        )));
    }
    Ok(secret)
}

/// A client for one API.
pub struct ApiClient {
    base: Base,
    token: Option<SecretText>,
    agent: ureq::Agent,
}

impl std::fmt::Debug for ApiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiClient")
            .field("base", &self.base)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .finish_non_exhaustive()
    }
}

impl ApiClient {
    /// A client for `base`, with a token for the routes that need one.
    #[must_use]
    pub fn new(base: Base, token: Option<SecretText>) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .https_only(!base.is_plain())
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(TIMEOUT))
            .user_agent("factory-cli")
            .build()
            .into();
        Self { base, token, agent }
    }

    /// `GET path`.
    ///
    /// # Errors
    /// [`Unreachable`] when there is no answer.
    pub fn get(&self, path: &str) -> Result<Answer, Unreachable> {
        self.send(http::Method::GET, path, None, None)
    }

    /// `POST path` with a JSON body and an idempotency key.
    ///
    /// # Errors
    /// [`Unreachable`] when there is no answer.
    pub fn post(&self, path: &str, key: &str, body: &Value) -> Result<Answer, Unreachable> {
        let bytes = serde_json::to_vec(body).map_err(|_| Unreachable::Protocol)?;
        self.send(http::Method::POST, path, Some(key), Some(bytes))
    }

    fn send(
        &self,
        method: http::Method,
        path: &str,
        key: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<Answer, Unreachable> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(self.base.url(path))
            .header("Accept", "application/json");
        if let Some(token) = &self.token {
            builder = builder.header("Authorization", format!("Bearer {}", token.expose()));
        }
        if let Some(key) = key {
            builder = builder.header("Idempotency-Key", key);
        }
        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }
        let request = builder
            .body(body.unwrap_or_default())
            .map_err(|_| Unreachable::Protocol)?;
        let mut response = self.agent.run(request).map_err(|error| match error {
            ureq::Error::Timeout(_) => Unreachable::Timeout,
            ureq::Error::Io(_)
            | ureq::Error::ConnectionFailed
            | ureq::Error::HostNotFound
            | ureq::Error::Tls(_)
            | ureq::Error::Rustls(_)
            | ureq::Error::TlsRequired => Unreachable::Connect,
            _ => Unreachable::Protocol,
        })?;
        let status = response.status().as_u16();
        let bytes = response
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER_BYTES)
            .read_to_vec()
            .map_err(|_| Unreachable::Protocol)?;
        Ok(Answer {
            status,
            body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_https_or_http_to_loopback_with_no_path_or_credentials() {
        for good in [
            "https://factory.example.com",
            "https://factory.example.com:8443/",
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
        ] {
            assert!(Base::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "factory.example.com",
            "http://factory.example.com",
            "http://10.0.0.5:8080",
            "ftp://127.0.0.1",
            "https://user:pw@factory.example.com",
            "https://factory.example.com/v1",
            "https://factory.example.com?x=1",
            "https://",
            "https://a b",
        ] {
            assert!(Base::parse(bad).is_err(), "{bad}");
        }
        // The refusal does not repeat what was typed.
        let shown = Base::parse("https://user:pw@h").unwrap_err().to_string();
        assert!(!shown.contains("pw"));
    }

    #[test]
    fn plain_http_is_recognised_for_the_agent() {
        assert!(Base::parse("http://127.0.0.1:1").expect("ok").is_plain());
        assert!(!Base::parse("https://example.com").expect("ok").is_plain());
    }

    #[test]
    fn a_client_never_prints_its_token() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cli-token-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("t");
        std::fs::write(&file, ["sfat_", "visible-in-no-output"].concat()).expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("mode");
        let token = read_token(&file).expect("reads");
        let client = ApiClient::new(Base::parse("http://127.0.0.1:1").expect("ok"), Some(token));
        assert!(!format!("{client:?}").contains("visible-in-no-output"));
        // A token file that others can read is refused, and the refusal names the file only.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("mode");
        let refused = read_token(&file).unwrap_err().to_string();
        assert!(!refused.contains("visible-in-no-output"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
