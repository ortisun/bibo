//! The route table, the router built from it, and the pipeline every request goes through.
//!
//! [`ROUTES`] is the one list of what the API serves. The router is built from it, the OpenAPI
//! document is checked against it (`tests/openapi_contract.rs`), and the README renders it. A route
//! that is not in the table does not exist, and a route in the table that the OpenAPI document does
//! not describe fails the build's tests.
//!
//! # The pipeline
//!
//! For a route in the table, [`dispatch`] does these in order, and each step ends the request when
//! it fails:
//!
//! 1. the whole request runs under one deadline (`limits.request_timeout_ms`);
//! 2. the source address, which is the TCP peer and never a forwarded header, is counted against its
//!    rate limit;
//! 3. a route that needs a token authenticates it **before the body is read**, so an anonymous
//!    caller cannot make the API read, buffer or parse anything;
//! 4. a route with a body checks the content type, then reads at most the limit under its own
//!    deadline: a declared length above the limit is refused without reading a byte, a body that
//!    turns out larger is cut off, and a slow sender is answered `408`;
//! 5. the handler runs and its answer is rendered with the security headers and the correlation id.
//!
//! An unknown path is `404`, an unknown method on a known path is `405`, and both have the same
//! body shape as every other error.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{MethodFilter, on};
use http_body_util::{BodyExt, Limited};
use tracing::Instrument;

use crate::answers::{Answer, ApiError, CORRELATION_HEADER, Reply, render};
use crate::auth::{Caller, authenticate};
use crate::limits::Key;
use crate::state::ApiState;
use crate::{decisions, health, jobs, openapi, reads, repositories, webhook};

/// The TCP peer of a connection, put in the request by the server. Nothing else is ever used as
/// the source address.
#[derive(Debug, Clone, Copy)]
pub struct Peer(pub SocketAddr);

/// The body limit of a webhook, in bytes: `webhook.max_body_bytes` of `policies/security.yaml`.
pub const WEBHOOK_MAX_BODY_BYTES: usize = 1_048_576;

/// What a route does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `/healthz`.
    Live,
    /// `/readyz`.
    Ready,
    /// `/openapi.json`.
    OpenApi,
    /// `POST /v1/jobs`.
    SubmitJob,
    /// `GET /v1/jobs`.
    ListJobs,
    /// `GET /v1/jobs/{job_id}`.
    JobStatus,
    /// `GET /v1/jobs/{job_id}/timeline`.
    JobTimeline,
    /// `GET /v1/jobs/{job_id}/specification-draft`.
    SpecificationDraft,
    /// `GET /v1/jobs/{job_id}/gate-reports`.
    GateReports,
    /// `GET /v1/jobs/{job_id}/artifacts/{sha256}`.
    Artifact,
    /// `POST /v1/jobs/{job_id}/decisions`.
    Decide,
    /// `POST /v1/repositories`.
    RegisterRepository,
    /// `GET /v1/repositories/{repository_id}`.
    GetRepository,
    /// `POST /v1/repositories/{repository_id}/project-map`.
    AttestProjectMap,
    /// `POST /v1/repositories/{repository_id}/enable`.
    EnableRepository,
    /// `POST /v1/repositories/{repository_id}/disable`.
    DisableRepository,
    /// `GET /v1/repository-changes/{request_id}`.
    GetRepositoryChange,
    /// `POST /v1/webhooks/github`.
    GithubWebhook,
}

/// How a route authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    /// Anyone.
    Open,
    /// A bearer token, then the roles of the allowlist.
    Token,
    /// The HMAC signature of GitHub's secret over the raw body.
    Signature,
}

/// One route.
#[derive(Debug, Clone, Copy)]
pub struct RouteSpec {
    /// The HTTP method.
    pub method: &'static str,
    /// The path, with `{name}` for a parameter, as OpenAPI writes it.
    pub path: &'static str,
    /// What it does.
    pub op: Op,
    /// The `operationId` in the OpenAPI document.
    pub operation_id: &'static str,
    /// How it authenticates.
    pub auth: Auth,
    /// True when the request has a body.
    pub has_body: bool,
}

/// Everything the API serves.
pub const ROUTES: &[RouteSpec] = &[
    RouteSpec {
        method: "GET",
        path: "/healthz",
        op: Op::Live,
        operation_id: "liveness",
        auth: Auth::Open,
        has_body: false,
    },
    RouteSpec {
        method: "GET",
        path: "/readyz",
        op: Op::Ready,
        operation_id: "readiness",
        auth: Auth::Open,
        has_body: false,
    },
    RouteSpec {
        method: "GET",
        path: "/openapi.json",
        op: Op::OpenApi,
        operation_id: "openapi",
        auth: Auth::Open,
        has_body: false,
    },
    RouteSpec {
        method: "POST",
        path: "/v1/jobs",
        op: Op::SubmitJob,
        operation_id: "submitJob",
        auth: Auth::Token,
        has_body: true,
    },
    RouteSpec {
        method: "GET",
        path: "/v1/jobs",
        op: Op::ListJobs,
        operation_id: "listJobs",
        auth: Auth::Token,
        has_body: false,
    },
    RouteSpec {
        method: "GET",
        path: "/v1/jobs/{job_id}",
        op: Op::JobStatus,
        operation_id: "getJob",
        auth: Auth::Token,
        has_body: false,
    },
    RouteSpec {
        method: "GET",
        path: "/v1/jobs/{job_id}/timeline",
        op: Op::JobTimeline,
        operation_id: "getJobTimeline",
        auth: Auth::Token,
        has_body: false,
    },
    RouteSpec {
        method: "GET",
        path: "/v1/jobs/{job_id}/specification-draft",
        op: Op::SpecificationDraft,
        operation_id: "getSpecificationDraft",
        auth: Auth::Token,
        has_body: false,
    },
    RouteSpec {
        method: "GET",
        path: "/v1/jobs/{job_id}/gate-reports",
        op: Op::GateReports,
        operation_id: "listGateReports",
        auth: Auth::Token,
        has_body: false,
    },
    RouteSpec {
        method: "GET",
        path: "/v1/jobs/{job_id}/artifacts/{sha256}",
        op: Op::Artifact,
        operation_id: "getArtifact",
        auth: Auth::Token,
        has_body: false,
    },
    RouteSpec {
        method: "POST",
        path: "/v1/jobs/{job_id}/decisions",
        op: Op::Decide,
        operation_id: "decideJob",
        auth: Auth::Token,
        has_body: true,
    },
    RouteSpec {
        method: "POST",
        path: "/v1/repositories",
        op: Op::RegisterRepository,
        operation_id: "registerRepository",
        auth: Auth::Token,
        has_body: true,
    },
    RouteSpec {
        method: "GET",
        path: "/v1/repositories/{repository_id}",
        op: Op::GetRepository,
        operation_id: "getRepository",
        auth: Auth::Token,
        has_body: false,
    },
    RouteSpec {
        method: "POST",
        path: "/v1/repositories/{repository_id}/project-map",
        op: Op::AttestProjectMap,
        operation_id: "attestProjectMap",
        auth: Auth::Token,
        has_body: true,
    },
    RouteSpec {
        method: "POST",
        path: "/v1/repositories/{repository_id}/enable",
        op: Op::EnableRepository,
        operation_id: "enableRepository",
        auth: Auth::Token,
        has_body: true,
    },
    RouteSpec {
        method: "POST",
        path: "/v1/repositories/{repository_id}/disable",
        op: Op::DisableRepository,
        operation_id: "disableRepository",
        auth: Auth::Token,
        has_body: true,
    },
    RouteSpec {
        method: "GET",
        path: "/v1/repository-changes/{request_id}",
        op: Op::GetRepositoryChange,
        operation_id: "getRepositoryChange",
        auth: Auth::Token,
        has_body: false,
    },
    RouteSpec {
        method: "POST",
        path: "/v1/webhooks/github",
        op: Op::GithubWebhook,
        operation_id: "receiveGithubWebhook",
        auth: Auth::Signature,
        has_body: true,
    },
];

fn filter_of(method: &str) -> MethodFilter {
    match method {
        "GET" => MethodFilter::GET,
        _ => MethodFilter::POST,
    }
}

/// The correlation id for a request: the caller's, if it is a UUID in the form the store keeps,
/// or a new one. Anything else the caller sent is dropped, not echoed.
fn correlation_of(headers: &HeaderMap, state: &ApiState) -> String {
    let mut values = headers.get_all(CORRELATION_HEADER).iter();
    let sent = values.next().and_then(|value| value.to_str().ok());
    if let (Some(text), None) = (sent, values.next())
        && factory_domain::ids::CorrelationId::parse(text).is_ok()
    {
        return text.to_owned();
    }
    state.ports.ids.new_uuid().hyphenated().to_string()
}

/// The values of the `{name}` segments of `template` as they appear in `actual`.
fn path_params<'a>(template: &str, actual: &'a str) -> Vec<&'a str> {
    template
        .split('/')
        .zip(actual.split('/'))
        .filter(|(pattern, _)| pattern.starts_with('{'))
        .map(|(_, value)| value)
        .collect()
}

fn media_type_is_json(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(axum::http::header::CONTENT_TYPE).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return false;
    };
    value.to_str().is_ok_and(|text| {
        text.split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    })
}

/// Reads a body of at most `limit` bytes within the body deadline.
async fn read_body(
    parts: &Parts,
    body: Body,
    limit: usize,
    state: &ApiState,
) -> Result<Vec<u8>, ApiError> {
    let declared = parts
        .headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<usize>().ok());
    if declared.is_some_and(|length| length > limit) {
        return Err(ApiError::PayloadTooLarge);
    }
    let read = tokio::time::timeout(
        state.limits.body_timeout(),
        Limited::new(body, limit).collect(),
    )
    .await
    .map_err(|_| ApiError::RequestTimeout)?;
    match read {
        Ok(collected) => Ok(collected.to_bytes().to_vec()),
        Err(error) if error.is::<http_body_util::LengthLimitError>() => {
            Err(ApiError::PayloadTooLarge)
        }
        Err(_) => Err(ApiError::BadRequest("body")),
    }
}

async fn run(
    state: &ApiState,
    spec: &RouteSpec,
    parts: Parts,
    body: Body,
    correlation: &str,
) -> Answer {
    let ip: IpAddr = parts
        .extensions
        .get::<Peer>()
        .map_or(IpAddr::from([0, 0, 0, 0]), |peer| peer.0.ip());
    if !state
        .limiter
        .allow(Key::Ip(ip), state.limits.per_ip_per_minute, Instant::now())
    {
        return Err(ApiError::RateLimited);
    }
    let caller: Option<Caller> = match spec.auth {
        Auth::Token => Some(authenticate(state, &parts.headers).await?),
        Auth::Open | Auth::Signature => None,
    };
    let bytes = if spec.has_body {
        let limit = match spec.op {
            Op::GithubWebhook => WEBHOOK_MAX_BODY_BYTES,
            _ => state.limits.max_body_bytes,
        };
        if spec.auth == Auth::Token && !media_type_is_json(&parts.headers) {
            return Err(ApiError::UnsupportedMediaType);
        }
        read_body(&parts, body, limit, state).await?
    } else {
        Vec::new()
    };
    let params = path_params(spec.path, parts.uri.path());
    let job_id = params.first().copied().unwrap_or("");
    // Work on one job runs inside a `factory.job` span (ADR 0013), with the correlation id and the
    // tenant of the caller. The job id is the path value only when it is a job id: nothing else the
    // caller sent becomes an attribute.
    let job_span = |caller: &Caller| {
        let known = factory_domain::ids::JobId::parse(job_id).map(|id| id.as_text());
        factory_composition::telemetry::job_stretch(
            correlation,
            known.as_deref().unwrap_or("none"),
            &caller.tenant.as_text(),
        )
    };
    match (spec.op, caller) {
        (Op::Live, _) => health::live(),
        (Op::Ready, _) => health::ready(state).await,
        (Op::OpenApi, _) => Ok(Reply::ok(openapi::document().clone())),
        (Op::GithubWebhook, _) => webhook::receive(state, &parts.headers, &bytes).await,
        (Op::SubmitJob, Some(caller)) => {
            jobs::submit(state, &caller, &parts.headers, &bytes, correlation).await
        }
        (Op::ListJobs, Some(caller)) => jobs::list(state, &caller, parts.uri.query()).await,
        (Op::JobStatus, Some(caller)) => {
            jobs::status(state, &caller, job_id)
                .instrument(job_span(&caller))
                .await
        }
        (Op::JobTimeline, Some(caller)) => {
            jobs::timeline(state, &caller, job_id)
                .instrument(job_span(&caller))
                .await
        }
        (Op::SpecificationDraft, Some(caller)) => {
            reads::specification_draft(state, &caller, job_id, parts.uri.query())
                .instrument(job_span(&caller))
                .await
        }
        (Op::GateReports, Some(caller)) => {
            reads::gate_reports(state, &caller, job_id)
                .instrument(job_span(&caller))
                .await
        }
        (Op::Artifact, Some(caller)) => {
            reads::artifact(state, &caller, job_id, params.get(1).copied().unwrap_or(""))
                .instrument(job_span(&caller))
                .await
        }
        (Op::Decide, Some(caller)) => {
            decisions::decide(state, &caller, job_id, &parts.headers, &bytes)
                .instrument(job_span(&caller))
                .await
        }
        (Op::RegisterRepository, Some(caller)) => {
            repositories::register(state, &caller, &parts.headers, &bytes).await
        }
        (Op::GetRepository, Some(caller)) => repositories::show(state, &caller, job_id).await,
        (Op::AttestProjectMap, Some(caller)) => {
            repositories::attest_map(state, &caller, job_id, &parts.headers, &bytes).await
        }
        (Op::EnableRepository, Some(caller)) => {
            repositories::switch(state, &caller, job_id, &parts.headers, &bytes, true).await
        }
        (Op::DisableRepository, Some(caller)) => {
            repositories::switch(state, &caller, job_id, &parts.headers, &bytes, false).await
        }
        (Op::GetRepositoryChange, Some(caller)) => {
            repositories::change_status(state, &caller, job_id).await
        }
        // A token route without a caller cannot happen: authentication ran first.
        (_, None) => Err(ApiError::Unauthorized),
    }
}

async fn dispatch(state: Arc<ApiState>, index: usize, request: Request) -> Response {
    let spec = &ROUTES[index];
    let (parts, body) = request.into_parts();
    let correlation = correlation_of(&parts.headers, &state);
    let deadline = state.limits.request_timeout();
    let answer = tokio::time::timeout(deadline, run(&state, spec, parts, body, &correlation))
        .await
        .unwrap_or(Err(ApiError::Unavailable));
    render(answer, &correlation)
}

/// The router: every route of [`ROUTES`], and the same uniform answer for an unknown path and an
/// unknown method.
pub fn router(state: Arc<ApiState>) -> Router {
    let mut router = Router::new();
    for (index, spec) in ROUTES.iter().enumerate() {
        let shared = Arc::clone(&state);
        router = router.route(
            spec.path,
            on(filter_of(spec.method), move |request: Request| {
                let shared = Arc::clone(&shared);
                async move { dispatch(shared, index, request).await }
            }),
        );
    }
    let for_missing = Arc::clone(&state);
    let for_method = Arc::clone(&state);
    router
        .fallback(move |request: Request| {
            let state = Arc::clone(&for_missing);
            async move {
                let correlation = correlation_of(request.headers(), &state);
                render(Err(ApiError::NotFound), &correlation)
            }
        })
        .method_not_allowed_fallback(move |request: Request| {
            let state = Arc::clone(&for_method);
            async move {
                let correlation = correlation_of(request.headers(), &state);
                render(Err(ApiError::MethodNotAllowed), &correlation)
            }
        })
}

/// Status codes the table promises each route may answer with, for the contract test.
#[must_use]
pub fn declared_statuses(op: Op) -> &'static [StatusCode] {
    match op {
        Op::Live => &[StatusCode::OK],
        Op::Ready => &[StatusCode::OK, StatusCode::SERVICE_UNAVAILABLE],
        Op::OpenApi => &[StatusCode::OK],
        Op::SubmitJob => &[StatusCode::OK, StatusCode::CREATED],
        Op::ListJobs
        | Op::JobStatus
        | Op::JobTimeline
        | Op::SpecificationDraft
        | Op::GateReports
        | Op::Artifact => &[StatusCode::OK],
        Op::Decide => &[StatusCode::ACCEPTED],
        // Register, attest and enable are signed requests that the worker applies (REG-2).
        Op::RegisterRepository | Op::AttestProjectMap | Op::EnableRepository => {
            &[StatusCode::ACCEPTED]
        }
        Op::GetRepository | Op::GetRepositoryChange | Op::DisableRepository => &[StatusCode::OK],
        Op::GithubWebhook => &[StatusCode::ACCEPTED],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parameter_is_read_from_its_segment() {
        assert_eq!(
            path_params("/v1/jobs/{job_id}/timeline", "/v1/jobs/abc/timeline"),
            vec!["abc"]
        );
        assert!(path_params("/v1/jobs", "/v1/jobs").is_empty());
    }

    #[test]
    fn no_two_routes_share_a_method_and_a_path() {
        for (i, a) in ROUTES.iter().enumerate() {
            for b in &ROUTES[i + 1..] {
                assert!(
                    !(a.method == b.method && a.path == b.path),
                    "{} {}",
                    a.method,
                    a.path
                );
            }
            assert!(!a.operation_id.is_empty());
        }
    }

    #[test]
    fn no_route_is_named_for_a_merge_or_a_deployment() {
        // ST-05: the factory has no way to merge or deploy, and no route says it has.
        for route in ROUTES {
            for word in ["merge", "deploy", "ready", "undraft"] {
                assert!(
                    !route.path.split('/').any(|segment| segment == word),
                    "{}",
                    route.path
                );
            }
        }
    }

    #[test]
    fn only_a_json_content_type_is_a_json_body() {
        let mut headers = HeaderMap::new();
        assert!(!media_type_is_json(&headers));
        for (value, expected) in [
            ("application/json", true),
            ("Application/JSON; charset=utf-8", true),
            ("text/plain", false),
            ("application/jsonp", false),
            ("application/json, text/html", false),
        ] {
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                value.parse().expect("header value"),
            );
            assert_eq!(media_type_is_json(&headers), expected, "{value}");
        }
    }
}
