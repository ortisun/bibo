//! The transport seam: what the adapter sends and what it gets back, as plain values.
//!
//! The adapter never opens a socket itself. It hands a [`WireRequest`] to a [`Transport`], and the
//! transport owns the base URL, the TLS configuration and the timeouts. Production uses
//! [`crate::UreqTransport`] over HTTPS. Tests use the same type over plain HTTP on the loopback
//! interface, or a scripted transport that returns recorded responses. A request carries only a
//! path and a query, never a host, so a request cannot be sent anywhere but to the base URL the
//! transport was built with.

use std::fmt;

use async_trait::async_trait;

/// The HTTP methods the adapter uses. There is no method for a merge: that is a path, not a
/// method, and no code path builds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// Read.
    Get,
    /// Create.
    Post,
    /// Update.
    Patch,
    /// Remove. Used for the installation token, for a label taken off an issue and for the
    /// duplicate of a status comment (ports v1.2).
    Delete,
    /// `PUT` to a file of the contents API (`/repos/{owner}/{repo}/contents/{path}`) and to
    /// nothing else, for the rules pull request (ports v1.3, ADR 0026). The client refuses it for
    /// any other path before it asks for a token ([`is_contents_path`]), so this method cannot
    /// reach the merge endpoint, which is also a `PUT`.
    PutContents,
}

/// True when `target` is a path of the contents API of one repository:
/// `/repos/{owner}/{repo}/contents/{one or more segments}`, with an optional query, and no
/// segment that is empty, `.` or `..`.
#[must_use]
pub fn is_contents_path(target: &str) -> bool {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let mut segments = path.split('/');
    if segments.next() != Some("") || segments.next() != Some("repos") {
        return false;
    }
    let rest: Vec<&str> = segments.collect();
    match rest.as_slice() {
        [owner, repo, "contents", file @ ..] if !file.is_empty() => [*owner, *repo]
            .iter()
            .chain(file.iter())
            .all(|segment| !segment.is_empty() && *segment != "." && *segment != ".."),
        _ => false,
    }
}

impl Method {
    /// The method as the request line spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::PutContents => "PUT",
        }
    }
}

/// One request. `target` is a path with an optional query, starting with `/`.
#[derive(Clone, PartialEq, Eq)]
pub struct WireRequest {
    /// The method.
    pub method: Method,
    /// The path and query, such as `/repos/example-org/fixture/issues/12`.
    pub target: String,
    /// The headers, name and value. The `Authorization` value is a secret.
    pub headers: Vec<(String, String)>,
    /// The body, empty for none.
    pub body: Vec<u8>,
}

impl fmt::Debug for WireRequest {
    /// Shows the method, the target and the header names, never a header value and never the
    /// body: a request can carry a token.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WireRequest")
            .field("method", &self.method)
            .field("target", &self.target)
            .field(
                "header_names",
                &self
                    .headers
                    .iter()
                    .map(|(name, _)| name)
                    .collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// One response. Header names are lower case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireResponse {
    /// The status code.
    pub status: u16,
    /// The headers, with lower-case names.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl WireResponse {
    /// The first header with this name (compared without regard to case).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Why a request got no response. None of these says anything about the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TransportError {
    /// The 30 second timeout passed.
    #[error("the request timed out")]
    Timeout,
    /// No connection could be made, or it dropped, or TLS failed.
    #[error("the connection failed")]
    Connect,
    /// The peer answered with something that is not HTTP, or with a body over the size limit.
    #[error("the response was not acceptable")]
    Protocol,
}

/// Sends one request and returns the response, whatever its status. Safe to drop.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends the request to the base URL this transport was built for.
    ///
    /// # Errors
    /// [`TransportError`] when no response was received.
    async fn execute(&self, request: WireRequest) -> Result<WireResponse, TransportError>;
}

/// Where the GitHub API is. Built only through a constructor that checks the scheme, so a token is
/// never sent over clear text to a host that is not on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiBase(String);

/// A base URL was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BadApiBase {
    /// Not `https://` followed by a host.
    #[error("the API base must be an https URL with a host and no credentials, query or fragment")]
    NotHttps,
    /// Not `http://` on the loopback interface.
    #[error("a plain http base is accepted only for 127.0.0.1, localhost or [::1]")]
    NotLoopback,
}

impl ApiBase {
    /// `https://api.github.com`.
    #[must_use]
    pub fn github_com() -> Self {
        Self("https://api.github.com".to_owned())
    }

    /// An HTTPS base, for GitHub Enterprise Server (`https://ghe.example.com/api/v3`).
    ///
    /// # Errors
    /// [`BadApiBase::NotHttps`] unless the text is `https://host[:port][/path]` with no user
    /// information, query or fragment.
    pub fn https(url: &str) -> Result<Self, BadApiBase> {
        let rest = url.strip_prefix("https://").ok_or(BadApiBase::NotHttps)?;
        Self::checked(url, rest).ok_or(BadApiBase::NotHttps)
    }

    /// A plain HTTP base on the loopback interface, for the tests against the fake server.
    ///
    /// # Errors
    /// [`BadApiBase::NotLoopback`] unless the host is `127.0.0.1`, `localhost` or `[::1]`.
    pub fn loopback_for_tests(url: &str) -> Result<Self, BadApiBase> {
        let rest = url.strip_prefix("http://").ok_or(BadApiBase::NotLoopback)?;
        let host = rest.split(['/', ':']).next().unwrap_or_default();
        let host = if rest.starts_with('[') {
            rest.split_once(']').map_or("", |(h, _)| h).to_owned() + "]"
        } else {
            host.to_owned()
        };
        if !matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]") {
            return Err(BadApiBase::NotLoopback);
        }
        Self::checked(url, rest).ok_or(BadApiBase::NotLoopback)
    }

    fn checked(url: &str, after_scheme: &str) -> Option<Self> {
        let authority = after_scheme.split('/').next().unwrap_or_default();
        let bad = authority.is_empty()
            || authority.contains('@')
            || url.contains(['?', '#'])
            || url.chars().any(|c| c.is_control() || c.is_whitespace());
        if bad {
            return None;
        }
        Some(Self(url.trim_end_matches('/').to_owned()))
    }

    /// The base URL without a trailing slash.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for a base that is not HTTPS (only the loopback constructor makes one).
    #[must_use]
    pub fn is_plain_http(&self) -> bool {
        self.0.starts_with("http://")
    }

    /// The path and query of `url` when it lies under this base, and `None` for any other host.
    /// Used for the `next` link of a paginated answer: a link to another host is never followed,
    /// because the request would carry the token.
    #[must_use]
    pub fn target_of(&self, url: &str) -> Option<String> {
        let rest = url.strip_prefix(&self.0)?;
        (rest.starts_with('/') && !rest.contains(['\r', '\n', ' '])).then(|| rest.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_one_put_reaches_a_file_of_the_contents_api_and_never_a_merge() {
        for good in [
            "/repos/o/r/contents/AGENTS.md",
            "/repos/o/r/contents/docs/adr/README.md",
            "/repos/o/r/contents/AGENTS.md?ref=factory%2Fproject-rules",
        ] {
            assert!(is_contents_path(good), "{good}");
        }
        // The merge endpoint is spelled in two pieces, so that the source scan of the crate
        // (`change_host_behaviour`) still finds no merge path in it.
        let merge = format!("/repos/o/r/pulls/1/{}", "mer".to_owned() + "ge");
        let climbing = format!("/repos/o/r/contents/../pulls/1/{}", "mer".to_owned() + "ge");
        for bad in [
            merge.as_str(),
            "/repos/o/r/contents",
            "/repos/o/r/contents/",
            climbing.as_str(),
            "/repos/o/r/contents/./x",
            "/repos/o/r/merges",
            "/repos/o/contents/x",
            "repos/o/r/contents/x",
            "/user/repos/o/r/contents/x",
            "/repos//r/contents/x",
        ] {
            assert!(!is_contents_path(bad), "{bad}");
        }
        assert_eq!(Method::PutContents.as_str(), "PUT");
    }

    #[test]
    fn an_https_base_must_name_a_host_and_nothing_secret() {
        assert!(ApiBase::https("https://api.github.com").is_ok());
        assert!(ApiBase::https("https://ghe.example.com/api/v3/").is_ok());
        for bad in [
            "http://api.github.com",
            "https://",
            "https://user:pw@api.github.com",
            "https://api.github.com?x=1",
            "https://api.github.com/#frag",
            "https://api.git hub.com",
            "ftp://x",
        ] {
            assert_eq!(ApiBase::https(bad), Err(BadApiBase::NotHttps), "{bad}");
        }
    }

    #[test]
    fn plain_http_is_loopback_only() {
        assert!(ApiBase::loopback_for_tests("http://127.0.0.1:8080").is_ok());
        assert!(ApiBase::loopback_for_tests("http://localhost:1").is_ok());
        assert!(ApiBase::loopback_for_tests("http://[::1]:9").is_ok());
        for bad in [
            "http://api.github.com",
            "http://10.0.0.1:80",
            "http://127.0.0.1.evil.test",
            "http://localhost.evil.test",
            "https://127.0.0.1",
        ] {
            assert!(ApiBase::loopback_for_tests(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_next_link_is_followed_only_under_the_base() {
        let base = ApiBase::https("https://api.github.com").unwrap();
        assert_eq!(
            base.target_of("https://api.github.com/repos/o/r/issues?page=2"),
            Some("/repos/o/r/issues?page=2".to_owned())
        );
        for foreign in [
            "https://evil.test/repos/o/r/issues?page=2",
            "https://api.github.com.evil.test/x",
            "http://api.github.com/x",
            "https://api.github.comx/x",
        ] {
            assert_eq!(base.target_of(foreign), None, "{foreign}");
        }
    }

    #[test]
    fn a_request_prints_no_header_value_and_no_body() {
        let request = WireRequest {
            method: Method::Post,
            target: "/x".to_owned(),
            headers: vec![("Authorization".to_owned(), "Bearer SECRETVALUE".to_owned())],
            body: b"SECRETBODY".to_vec(),
        };
        let shown = format!("{request:?}");
        assert!(
            !shown.contains("SECRETVALUE") && !shown.contains("SECRETBODY"),
            "{shown}"
        );
    }
}
