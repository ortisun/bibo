//! Every answer the API gives.
//!
//! A success is a [`Reply`]: a status and a JSON value the handler built from typed values. A
//! failure is an [`ApiError`]: a variant from a closed set. The body of a failure is
//! `{"error": "<code>"}`, and a 400 adds `"field"`, the name of a field of the API's own schema.
//! Nothing the caller sent is ever echoed, no library message is shown, and a refusal does not say
//! which of several tests failed, so the answer to a missing token, an expired token, a token of
//! another audience and a malformed header is the same bytes.
//!
//! Every response, success or failure, carries the same security headers and the correlation id.

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use serde_json::{Value, json};

/// The correlation id of one request: the one the caller sent, if it is a UUID, or a new one.
#[derive(Debug, Clone)]
pub struct Correlation(pub String);

/// The header that carries the correlation id in and out.
pub const CORRELATION_HEADER: &str = "x-correlation-id";

/// Why a request failed. The set is closed; the variants map to one status and one code each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApiError {
    /// The request is malformed. The name is a field of the API's own schema, or `body`.
    #[error("the request is not valid")]
    BadRequest(&'static str),
    /// No usable credential. One answer for every reason.
    #[error("authentication is required")]
    Unauthorized,
    /// The caller is known and may not do this.
    #[error("not permitted")]
    Forbidden,
    /// No such route or object. The answer for another tenant's object is this one.
    #[error("not found")]
    NotFound,
    /// The route exists for another method.
    #[error("method not allowed")]
    MethodNotAllowed,
    /// The request conflicts with the state of the object.
    #[error("conflict")]
    Conflict,
    /// The body is larger than the limit.
    #[error("payload too large")]
    PayloadTooLarge,
    /// The content type is not `application/json`.
    #[error("unsupported media type")]
    UnsupportedMediaType,
    /// The caller was too slow to send the request.
    #[error("request timeout")]
    RequestTimeout,
    /// A rate limit is exceeded.
    #[error("rate limited")]
    RateLimited,
    /// The service cannot answer now: the database is unreachable or the work took too long.
    #[error("unavailable")]
    Unavailable,
    /// A repository cannot be enabled until a person has attested its project map.
    #[error("the project map has not been attested")]
    ProjectMapNotAttested,
}

impl ApiError {
    /// The HTTP status.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            Self::Conflict => StatusCode::CONFLICT,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::ProjectMapNotAttested => StatusCode::CONFLICT,
        }
    }

    /// The code in the body.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::Conflict => "conflict",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::RequestTimeout => "request_timeout",
            Self::RateLimited => "rate_limited",
            Self::Unavailable => "unavailable",
            Self::ProjectMapNotAttested => "project_map_not_attested",
        }
    }

    fn body(self) -> Value {
        match self {
            Self::BadRequest(field) => json!({"error": self.code(), "field": field}),
            _ => json!({"error": self.code()}),
        }
    }
}

/// Maps a store failure to the answer, never to the failure's own text. A row that is missing for
/// this tenant is `NotFound`, which is also what another tenant's row is.
impl From<factory_ports::store::StoreError> for ApiError {
    fn from(error: factory_ports::store::StoreError) -> Self {
        use factory_ports::store::StoreError;
        match error {
            StoreError::NotFound | StoreError::TenantMismatch => Self::NotFound,
            StoreError::Conflict => Self::Conflict,
            _ => {
                tracing::warn!(error = %error, "a store call failed");
                Self::Unavailable
            }
        }
    }
}

/// A document for download: bytes of a stored artifact under a content type the API fixes.
///
/// The bytes are untrusted text or data. They are never served as a page: the type is one of two
/// the API chooses (`text/plain; charset=utf-8` or `application/octet-stream`), the response says
/// `nosniff`, and it is an attachment.
#[derive(Debug, Clone)]
pub struct Download {
    /// The bytes, as stored.
    pub bytes: Vec<u8>,
    /// The content type: one of the two the API serves.
    pub content_type: &'static str,
    /// The name the file is saved under: letters, digits and a dot, made by the API.
    pub file_name: String,
}

/// A success: a status and a JSON value, or a document for download.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The status.
    pub status: StatusCode,
    /// The body.
    pub body: Value,
    /// When set, the answer is this document and `body` is not sent.
    pub download: Option<Download>,
}

impl Reply {
    /// A reply with a status and a body.
    #[must_use]
    pub const fn new(status: StatusCode, body: Value) -> Self {
        Self {
            status,
            body,
            download: None,
        }
    }

    /// 200 with a document to save.
    #[must_use]
    pub const fn download(document: Download) -> Self {
        Self {
            status: StatusCode::OK,
            body: Value::Null,
            download: Some(document),
        }
    }

    /// 200.
    #[must_use]
    pub const fn ok(body: Value) -> Self {
        Self::new(StatusCode::OK, body)
    }
}

/// What a handler returns.
pub type Answer = Result<Reply, ApiError>;

const SECURITY_HEADERS: [(&str, &str); 4] = [
    ("cache-control", "no-store"),
    ("x-content-type-options", "nosniff"),
    (
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'",
    ),
    ("referrer-policy", "no-referrer"),
];

/// Builds the response for an answer. The correlation id and the security headers are on every
/// response, so an error looks the same as a success from the outside.
#[must_use]
pub fn render(answer: Answer, correlation: &str) -> Response {
    let (status, body, error, download) = match answer {
        Ok(reply) => (reply.status, reply.body, None, reply.download),
        Err(error) => (error.status(), error.body(), Some(error), None),
    };
    // A `Value` always serializes.
    let (bytes, content_type) = match &download {
        Some(document) => (document.bytes.clone(), document.content_type),
        None => (
            serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec()),
            "application/json",
        ),
    };
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Some(document) = &download
        && let Ok(value) =
            HeaderValue::from_str(&format!("attachment; filename=\"{}\"", document.file_name))
    {
        headers.insert(header::CONTENT_DISPOSITION, value);
    }
    for (name, value) in SECURITY_HEADERS {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
    if let Ok(value) = HeaderValue::from_str(correlation) {
        headers.insert(HeaderName::from_static(CORRELATION_HEADER), value);
    }
    match error {
        Some(ApiError::Unauthorized) => {
            headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        Some(ApiError::RateLimited) => {
            headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        _ => {}
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_has_one_status_and_one_code_and_the_codes_differ() {
        let all = [
            ApiError::BadRequest("text"),
            ApiError::Unauthorized,
            ApiError::Forbidden,
            ApiError::NotFound,
            ApiError::MethodNotAllowed,
            ApiError::Conflict,
            ApiError::PayloadTooLarge,
            ApiError::UnsupportedMediaType,
            ApiError::RequestTimeout,
            ApiError::RateLimited,
            ApiError::Unavailable,
        ];
        let mut codes: Vec<_> = all.iter().map(|e| e.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }

    #[test]
    fn an_error_body_has_the_code_and_nothing_the_caller_sent() {
        let body = ApiError::Unauthorized.body();
        assert_eq!(body, json!({"error": "unauthorized"}));
        assert_eq!(
            ApiError::BadRequest("text").body(),
            json!({"error": "bad_request", "field": "text"})
        );
    }

    #[test]
    fn a_store_failure_is_never_shown_and_a_missing_row_is_not_found() {
        use factory_ports::store::{FaultCode, StoreError};
        assert_eq!(ApiError::from(StoreError::NotFound), ApiError::NotFound);
        assert_eq!(
            ApiError::from(StoreError::TenantMismatch),
            ApiError::NotFound
        );
        assert_eq!(
            ApiError::from(StoreError::Internal(FaultCode::PermissionDenied)),
            ApiError::Unavailable
        );
    }

    #[test]
    fn a_response_carries_the_security_headers_and_the_correlation_id() {
        let response = render(Err(ApiError::NotFound), "0190-abc");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        for (name, value) in SECURITY_HEADERS {
            assert_eq!(response.headers()[name], value);
        }
        assert_eq!(response.headers()["x-correlation-id"], "0190-abc");
    }
}
