//! The package registry source: a small client for the crates.io API.
//!
//! The dependency gate asks it about a package a change adds as a new direct dependency
//! ([`RegistryMetadata`]). It reads `GET /api/v1/crates/<name>` and keeps what the policy shows to
//! the person who decides (`new_direct_dependency.heuristics_recorded`): whether the name exists,
//! when the crate was first published, its downloads, its repository link and the license of the
//! version asked about.
//!
//! # What it promises
//!
//! * **Unknown is the default.** Whatever it cannot read is `None` in the record, and the gate reads
//!   `None` as the worst case. A timeout, a refused connection, a status other than 200 and 404, an
//!   answer larger than the cap, an answer that is not the expected JSON, a date that is not a
//!   date: each gives the all-unknown record, never a guess and never an error the gate has to
//!   handle. Only a 404 says something: the name does not exist (`exists: Some(false)`).
//! * **Nothing the caller sends reaches the URL unchecked.** A name that is not `[A-Za-z0-9_-]` up
//!   to 64 characters is unknown without a request, so a crafted name cannot add a path, a query
//!   or a host.
//! * **The address is the configuration's.** The request goes to `registry.base_url` and nowhere
//!   else; redirects are off, environment proxies are off, https is required unless the base is on
//!   the loopback interface (the configuration refuses plain http in production).
//! * **It identifies itself.** The registry's policy asks clients to send a `User-Agent` with a way
//!   to reach the operator; the configuration supplies it and the production profile requires it.
//! * **It is bounded.** One request has a wall time (`registry.timeout_seconds`) and a cap on the
//!   answer (`registry.max_response_bytes`).
//!
//! # UNVERIFIED
//!
//! Nothing here has run against the real crates.io: the tests answer from a loopback server with
//! the shape of the documented API. The fields used (`crate.created_at`, `crate.downloads`,
//! `crate.repository`, `versions[].num`, `versions[].license`) are the ones the API returns today;
//! a change in them makes the record unknown and not wrong.

use std::time::Duration;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
use factory_workflow::gates::supply_chain::facts::{RegistryMetadata, RegistryRecord};
use serde_json::Value;

use crate::config::{RegistryConfig, endpoint_problem};
use crate::profile::Profile;

/// The default `User-Agent` of a profile that does not name one. It names the software and no
/// person, which is why the production profile requires a configured one.
const DEFAULT_AGENT: &str = "software-factory-registry-check";

/// The longest crate name the registry accepts.
const MAX_NAME: usize = 64;

/// Why the client cannot be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryClientError {
    /// The base URL is not usable in this profile.
    #[error("registry.base_url {0}")]
    BaseUrl(&'static str),
}

/// A registry source that asks a crates.io API.
#[derive(Clone)]
pub struct CratesIoRegistry {
    base: String,
    agent: ureq::Agent,
    max_bytes: u64,
}

impl std::fmt::Debug for CratesIoRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CratesIoRegistry")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl CratesIoRegistry {
    /// A client for the configured registry.
    ///
    /// # Errors
    /// [`RegistryClientError::BaseUrl`] when the base URL is not usable in the profile.
    pub fn new(profile: Profile, config: &RegistryConfig) -> Result<Self, RegistryClientError> {
        if let Some(problem) = endpoint_problem(profile, &config.base_url) {
            return Err(RegistryClientError::BaseUrl(problem));
        }
        let plain = config.base_url.starts_with("http://");
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .https_only(!plain)
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(Duration::from_secs(config.timeout_seconds)))
            .user_agent(config.user_agent.as_deref().unwrap_or(DEFAULT_AGENT))
            .build()
            .into();
        Ok(Self {
            base: config.base_url.trim_end_matches('/').to_owned(),
            agent,
            max_bytes: config.max_response_bytes,
        })
    }

    fn url_of(&self, name: &str) -> Option<String> {
        let clean = !name.is_empty()
            && name.len() <= MAX_NAME
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        clean.then(|| format!("{}/api/v1/crates/{name}", self.base))
    }

    /// One blocking request: the status and the body, or `None` when no answer was read.
    fn fetch(agent: &ureq::Agent, url: &str, max_bytes: u64) -> Option<(u16, Vec<u8>)> {
        let mut response = agent
            .get(url)
            .header("accept", "application/json")
            .call()
            .ok()?;
        let status = response.status().as_u16();
        if status != 200 {
            return Some((status, Vec::new()));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(max_bytes)
            .read_to_vec()
            .ok()?;
        Some((status, body))
    }
}

/// A time the registry wrote, as a UTC timestamp. The registry spells UTC as `+00:00`, and the
/// domain type reads only the `Z` form. A zero offset is rewritten; any other offset is unknown,
/// because shifting a time is a guess this client does not make.
fn utc_time(text: &str) -> Option<Timestamp> {
    let normalized = text
        .strip_suffix("+00:00")
        .or_else(|| text.strip_suffix("-00:00"))
        .map_or_else(|| text.to_owned(), |head| format!("{head}Z"));
    Timestamp::parse(&normalized).ok()
}

/// The record a body of the API makes, for the version asked about. Pure, so the tests read the
/// documented shapes without a server.
#[must_use]
pub fn record_of(body: &[u8], version: &str) -> RegistryRecord {
    let Ok(document) = serde_json::from_slice::<Value>(body) else {
        return RegistryRecord::default();
    };
    let Some(krate) = document.get("crate").filter(|value| value.is_object()) else {
        return RegistryRecord::default();
    };
    RegistryRecord {
        exists: Some(true),
        first_published: krate
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(utc_time),
        license: document
            .get("versions")
            .and_then(Value::as_array)
            .and_then(|versions| {
                versions
                    .iter()
                    .find(|entry| entry.get("num").and_then(Value::as_str) == Some(version))
            })
            .and_then(|entry| entry.get("license"))
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_owned),
        repository: krate
            .get("repository")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .map(str::to_owned),
        downloads: krate.get("downloads").and_then(Value::as_u64),
    }
}

#[async_trait]
impl RegistryMetadata for CratesIoRegistry {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn lookup(&self, name: &str, version: &str) -> RegistryRecord {
        let Some(url) = self.url_of(name) else {
            return RegistryRecord::default();
        };
        let agent = self.agent.clone();
        let max_bytes = self.max_bytes;
        let answer = tokio::task::spawn_blocking(move || Self::fetch(&agent, &url, max_bytes))
            .await
            .ok()
            .flatten();
        match answer {
            Some((200, body)) => record_of(&body, version),
            // The one answer that says something about the package: it is not in the registry.
            Some((404, _)) => RegistryRecord {
                exists: Some(false),
                ..RegistryRecord::default()
            },
            _ => RegistryRecord::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHAPE: &str = r#"{
        "crate": {"id": "serde", "name": "serde", "created_at": "2014-12-19T21:49:41.309388+00:00",
                  "downloads": 123456789, "repository": "https://github.com/serde-rs/serde"},
        "versions": [
            {"num": "1.0.1", "license": "MIT OR Apache-2.0", "created_at": "2015-01-01T00:00:00Z"},
            {"num": "1.0.0", "license": "MIT", "created_at": "2014-12-19T21:49:41Z"}
        ]
    }"#;

    #[test]
    fn the_documented_shape_gives_every_fact() {
        let record = record_of(SHAPE.as_bytes(), "1.0.1");
        assert_eq!(record.exists, Some(true));
        assert_eq!(record.downloads, Some(123_456_789));
        assert_eq!(record.license.as_deref(), Some("MIT OR Apache-2.0"));
        assert_eq!(
            record.repository.as_deref(),
            Some("https://github.com/serde-rs/serde")
        );
        assert!(record.first_published.is_some(), "{record:?}");
    }

    #[test]
    fn a_version_the_registry_does_not_list_has_no_license_and_the_rest_stays() {
        let record = record_of(SHAPE.as_bytes(), "9.9.9");
        assert_eq!(record.license, None);
        assert_eq!(record.downloads, Some(123_456_789));
    }

    #[test]
    fn anything_unparseable_is_unknown_and_never_a_guess() {
        for body in [
            &b""[..],
            b"not json",
            b"[]",
            b"{}",
            br#"{"crate": "serde"}"#,
            br#"{"crate": null}"#,
        ] {
            assert_eq!(
                record_of(body, "1.0.0"),
                RegistryRecord::default(),
                "{body:?}"
            );
        }
        // A crate with fields of the wrong type keeps what is right and drops what is not.
        let record = record_of(
            br#"{"crate": {"created_at": "yesterday", "downloads": "many", "repository": 7},
                 "versions": [{"num": "1.0.0", "license": ""}]}"#,
            "1.0.0",
        );
        assert_eq!(record.exists, Some(true));
        assert_eq!(record.first_published, None);
        assert_eq!(record.downloads, None);
        assert_eq!(record.repository, None);
        assert_eq!(record.license, None);
    }

    #[test]
    fn a_name_that_could_change_the_url_is_unknown_without_a_request() {
        let config = RegistryConfig {
            base_url: "http://127.0.0.1:9".to_owned(),
            user_agent: None,
            timeout_seconds: 1,
            max_response_bytes: 4096,
        };
        let client = CratesIoRegistry::new(Profile::Local, &config).expect("a client");
        for name in [
            "",
            "a/b",
            "a?x=1",
            "a#b",
            "../x",
            "a b",
            "a@b",
            &"x".repeat(65),
        ] {
            assert_eq!(client.url_of(name), None, "{name:?}");
        }
        assert_eq!(
            client.url_of("serde_json-2"),
            Some("http://127.0.0.1:9/api/v1/crates/serde_json-2".to_owned())
        );
    }

    #[test]
    fn production_cannot_build_a_client_for_plain_http() {
        let config = RegistryConfig {
            base_url: "http://127.0.0.1:9".to_owned(),
            user_agent: Some("factory".to_owned()),
            timeout_seconds: 1,
            max_response_bytes: 4096,
        };
        assert!(CratesIoRegistry::new(Profile::Production, &config).is_err());
    }
}
