//! The authenticated client the two ports share: one request with the right token, conditional
//! reads, and paginated reads with caps.
//!
//! * **Tokens.** Every call asks the minter for a token for the scope. A job that has ended gets
//!   none. A 401 means the token died early (revoked elsewhere, or clock skew): the token is
//!   dropped and the call is tried once more with a new one.
//! * **Conditional reads.** The answer to a read is kept with its `ETag`, per tenant and path, and
//!   the next read of the same path sends `If-None-Match`. A 304 is a live confirmation that
//!   nothing changed and costs no rate limit. The cache is bounded and holds small bodies only.
//! * **Pagination.** `Link: rel="next"` is followed only when it points under the API base (the
//!   request carries the token) and only up to the page cap. A listing that is not finished at the
//!   cap says so, and the caller decides whether that is an error.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use factory_domain::ids::TenantId;
use factory_ports::githost::{GitHostError, GitScope};
use serde_json::Value;

use crate::core::{HttpCore, error_for};
use crate::token::{Caller, TokenClass, TokenMinter, api_headers};
use crate::wire::{ApiBase, Method, WireRequest, WireResponse};

/// How listings are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageLimits {
    /// Items asked for per page (GitHub allows up to 100).
    pub per_page: u32,
    /// The most pages one listing reads.
    pub max_pages: u32,
    /// The most pages the events of one issue are read for. More than `max_pages`, because the
    /// design gate has to see the end of the list: the newest event is the one that counts, and a
    /// list that is still not finished at this cap is an `Unavailable` answer, never a guess
    /// from the part that was read.
    pub event_pages: u32,
}

impl Default for PageLimits {
    fn default() -> Self {
        Self {
            per_page: 100,
            max_pages: 10,
            event_pages: 30,
        }
    }
}

/// The largest body kept for a conditional read.
const CACHE_BODY_LIMIT: usize = 256 * 1024;

/// How many answers are kept for conditional reads.
const CACHE_ENTRIES: usize = 256;

/// A successful answer.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    /// The headers of the answer that carried the body.
    pub headers: Vec<(String, String)>,
    /// The body as JSON, `Null` when it was empty.
    pub json: Value,
}

impl Reply {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// The items of a listing and whether the cap stopped it early.
#[derive(Debug, Clone)]
pub(crate) struct Pages {
    pub items: Vec<Value>,
    /// True when more pages existed than the cap allows.
    pub truncated: bool,
}

/// An answer kept for a conditional read: its `ETag`, its body and its headers.
type Cached = (String, Vec<u8>, Vec<(String, String)>);

#[derive(Default)]
struct EtagCache {
    entries: HashMap<(TenantId, String), Cached>,
    order: VecDeque<(TenantId, String)>,
}

pub(crate) struct Client {
    core: Arc<HttpCore>,
    minter: Arc<TokenMinter>,
    base: ApiBase,
    pages: PageLimits,
    etags: Mutex<EtagCache>,
}

impl Client {
    pub(crate) fn new(
        core: Arc<HttpCore>,
        minter: Arc<TokenMinter>,
        base: ApiBase,
        pages: PageLimits,
    ) -> Self {
        Self {
            core,
            minter,
            base,
            pages,
            etags: Mutex::new(EtagCache::default()),
        }
    }

    /// The page cap for the events of one issue.
    pub(crate) fn event_pages(&self) -> u32 {
        self.pages.event_pages
    }

    pub(crate) fn minter(&self) -> &Arc<TokenMinter> {
        &self.minter
    }

    /// One call. `conditional` reads send `If-None-Match` when an answer is cached.
    pub(crate) async fn call(
        &self,
        scope: &GitScope,
        class: TokenClass,
        method: Method,
        target: &str,
        body: Option<&Value>,
        conditional: bool,
    ) -> Result<Reply, GitHostError> {
        self.call_as(Caller::Job(scope, class), method, target, body, conditional)
            .await
    }

    /// One call for a job or for a troubleshooting run, with the caller's credential.
    pub(crate) async fn call_as(
        &self,
        caller: Caller<'_>,
        method: Method,
        target: &str,
        body: Option<&Value>,
        conditional: bool,
    ) -> Result<Reply, GitHostError> {
        let payload = body.map(|v| v.to_string().into_bytes()).unwrap_or_default();
        let key = (caller.tenant(), target.to_owned());
        let mut retried = false;
        loop {
            let bearer = self.minter.token_as(caller).await?;
            let mut headers = api_headers(bearer.expose(), !payload.is_empty());
            let cached = if conditional && method == Method::Get {
                self.cached(&key)
            } else {
                None
            };
            if let Some((etag, _, _)) = &cached {
                headers.push(("If-None-Match".to_owned(), etag.clone()));
            }
            let response = self
                .core
                .send(WireRequest {
                    method,
                    target: target.to_owned(),
                    headers,
                    body: payload.clone(),
                })
                .await?;
            if response.status == 401 && !retried {
                retried = true;
                self.minter.discard(caller, &bearer).await;
                continue;
            }
            return self.reply_from(&key, response, cached, conditional);
        }
    }

    fn reply_from(
        &self,
        key: &(TenantId, String),
        response: WireResponse,
        cached: Option<Cached>,
        conditional: bool,
    ) -> Result<Reply, GitHostError> {
        if response.status == 304
            && let Some((_, body, headers)) = cached
        {
            return Ok(Reply {
                headers,
                json: parse(&body)?,
            });
        }
        if !(200..300).contains(&response.status) {
            return Err(error_for(&response));
        }
        let json = parse(&response.body)?;
        if conditional
            && response.body.len() <= CACHE_BODY_LIMIT
            && let Some(etag) = response.header("etag")
        {
            self.remember(
                key.clone(),
                etag.to_owned(),
                response.body.clone(),
                response.headers.clone(),
            );
        }
        Ok(Reply {
            headers: response.headers,
            json,
        })
    }

    fn cached(&self, key: &(TenantId, String)) -> Option<Cached> {
        self.etags
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .get(key)
            .cloned()
    }

    fn remember(
        &self,
        key: (TenantId, String),
        etag: String,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) {
        let mut cache = self.etags.lock().unwrap_or_else(PoisonError::into_inner);
        if cache
            .entries
            .insert(key.clone(), (etag, body, headers))
            .is_none()
        {
            cache.order.push_back(key);
            while cache.order.len() > CACHE_ENTRIES {
                if let Some(oldest) = cache.order.pop_front() {
                    cache.entries.remove(&oldest);
                }
            }
        }
    }

    /// A plain live read with the stage token.
    pub(crate) async fn get(&self, scope: &GitScope, target: &str) -> Result<Reply, GitHostError> {
        self.call(scope, TokenClass::Stage, Method::Get, target, None, true)
            .await
    }

    /// Reads a listing page by page, up to the cap, with the stage token.
    pub(crate) async fn get_pages(
        &self,
        scope: &GitScope,
        target: &str,
    ) -> Result<Pages, GitHostError> {
        self.get_pages_as(scope, TokenClass::Stage, target).await
    }

    /// Reads a listing page by page, up to the cap, with the credential of `class`.
    pub(crate) async fn get_pages_as(
        &self,
        scope: &GitScope,
        class: TokenClass,
        target: &str,
    ) -> Result<Pages, GitHostError> {
        self.get_pages_up_to(scope, class, target, self.pages.max_pages)
            .await
    }

    /// Like [`get_pages_as`](Self::get_pages_as), with a page cap chosen for this one call. A
    /// reader that must see the end of a list (the events of an issue, for the design gate) asks
    /// for more pages than the default and still treats `truncated` as a failure.
    pub(crate) async fn get_pages_up_to(
        &self,
        scope: &GitScope,
        class: TokenClass,
        target: &str,
        max_pages: u32,
    ) -> Result<Pages, GitHostError> {
        self.pages_as(Caller::Job(scope, class), target, max_pages)
            .await
    }

    /// Reads a listing page by page, up to `max_pages`, as a job or as a troubleshooting run.
    pub(crate) async fn pages_as(
        &self,
        caller: Caller<'_>,
        target: &str,
        max_pages: u32,
    ) -> Result<Pages, GitHostError> {
        let separator = if target.contains('?') { '&' } else { '?' };
        let mut next = format!("{target}{separator}per_page={}", self.pages.per_page);
        let mut items = Vec::new();
        for _ in 0..max_pages {
            let reply = self
                .call_as(caller, Method::Get, &next, None, false)
                .await?;
            let link = reply.header("link").and_then(next_link).map(str::to_owned);
            match reply.json {
                Value::Array(page) => items.extend(page),
                _ => return Err(GitHostError::Unavailable),
            }
            let Some(link) = link else {
                return Ok(Pages {
                    items,
                    truncated: false,
                });
            };
            match self.base.target_of(&link) {
                Some(target) => next = target,
                // A link to another host is never followed: the request would carry the token.
                None => {
                    return Ok(Pages {
                        items,
                        truncated: true,
                    });
                }
            }
        }
        Ok(Pages {
            items,
            truncated: true,
        })
    }
}

fn parse(body: &[u8]) -> Result<Value, GitHostError> {
    if body.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_slice(body).map_err(|_| GitHostError::Unavailable)
}

/// The URL of `rel="next"` in a `Link` header.
pub(crate) fn next_link(header: &str) -> Option<&str> {
    let mut rest = header;
    while let Some(open) = rest.find('<') {
        let after = rest.get(open + 1..)?;
        let close = after.find('>')?;
        let url = after.get(..close)?;
        let tail = after.get(close + 1..)?;
        let params_end = tail.find('<').unwrap_or(tail.len());
        let params = tail.get(..params_end)?;
        let is_next = params
            .split(';')
            .any(|p| p.trim().trim_end_matches(',').trim().replace(' ', "") == "rel=\"next\"");
        if is_next {
            return Some(url);
        }
        rest = tail.get(params_end..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_next_link_is_found_among_others() {
        let header = r#"<https://api.github.com/r?page=1>; rel="prev", <https://api.github.com/r?page=3>; rel="next", <https://api.github.com/r?page=9>; rel="last""#;
        assert_eq!(next_link(header), Some("https://api.github.com/r?page=3"));
        assert_eq!(
            next_link(r#"<https://api.github.com/r?page=2>; rel="next""#),
            Some("https://api.github.com/r?page=2")
        );
    }

    #[test]
    fn no_next_link_means_the_last_page() {
        assert_eq!(
            next_link(r#"<https://api.github.com/r?page=1>; rel="prev""#),
            None
        );
        assert_eq!(next_link(""), None);
        assert_eq!(next_link("garbage"), None);
        assert_eq!(next_link("<unclosed; rel=\"next\""), None);
    }
}
