//! The REST routes of the fake GitHub server: routing, authentication, and one function per
//! endpoint. Status codes and messages follow GitHub's, so an adapter written against this
//! handles the same cases as it will against the real service.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{
    CheckRun, Comment, DOCS, Fault, Issue, MintRecord, Pull, PushRecord, Repo, RequestRecord,
    Review, State, TOKEN_LIFETIME_SECONDS, TokenRecord, iso, level_rank, mask_authorization,
    new_token_value,
};
use crate::fx::encoding::{Base64Alphabet, base64_decode, base64_encode};
use crate::fx::http::{HttpRequest, HttpResponse, percent_decode};

// ---- errors ----------------------------------------------------------------------------------

/// An error to send back, in GitHub's error body.
pub(crate) struct ApiError {
    status: u16,
    message: String,
    errors: Option<Value>,
    headers: Vec<(String, String)>,
}

impl ApiError {
    fn new(status: u16, message: &str) -> Self {
        Self {
            status,
            message: message.to_owned(),
            errors: None,
            headers: Vec::new(),
        }
    }

    fn validation(resource: &str, field: &str, code: &str, message: Option<&str>) -> Self {
        let mut error = json!({"resource": resource, "field": field, "code": code});
        if let Some(message) = message {
            error["message"] = json!(message);
        }
        Self {
            status: 422,
            message: "Validation Failed".to_owned(),
            errors: Some(json!([error])),
            headers: Vec::new(),
        }
    }

    fn into_response(self) -> HttpResponse {
        let mut body = json!({
            "message": self.message,
            "documentation_url": DOCS,
            "status": self.status.to_string(),
        });
        if let Some(errors) = self.errors {
            body["errors"] = errors;
        }
        let mut response = HttpResponse::json(self.status, &body);
        response.headers.extend(self.headers);
        response
    }
}

type Outcome = Result<HttpResponse, ApiError>;

fn not_found() -> ApiError {
    ApiError::new(404, "Not Found")
}

fn forbidden() -> ApiError {
    ApiError::new(403, "Resource not accessible by integration")
}

// ---- routing ---------------------------------------------------------------------------------

/// The endpoints the fake serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    App,
    Installation,
    MintToken,
    RevokeToken,
    InstallationRepositories,
    Repo,
    Issue,
    /// The issues of a repository, filtered by state and labels (the troubleshooter, ports v1.3).
    IssuesList,
    /// A new issue (the troubleshooter, ports v1.3).
    IssueCreate,
    IssueComments,
    IssueEvents,
    CreateComment,
    IssueLabels,
    LabelsAdd,
    LabelRemove,
    CommentUpdate,
    CommentDelete,
    Collaborator,
    Branch,
    BranchProtection,
    /// A file or a directory at a commit, the default branch when no `ref` is given (the workflow
    /// files, for the preflight, and the rules file).
    Contents,
    /// Creates or replaces one file on a branch, as one new commit (the rules pull request).
    ContentsPut,
    RefGet,
    RefCreate,
    RefUpdate,
    RefDelete,
    PullsList,
    PullCreate,
    PullGet,
    PullUpdate,
    PullMerge,
    ReviewsList,
    ReviewCreate,
    CheckRunCreate,
    StatusCreate,
    /// The one read of GraphQL the fake knows (DR-1).
    Graphql,
}

impl Route {
    /// The template used in the request log and in `fail_next`.
    pub(crate) fn template(self) -> &'static str {
        match self {
            Route::App => "GET /app",
            Route::Installation => "GET /app/installations/{id}",
            Route::MintToken => "POST /app/installations/{id}/access_tokens",
            Route::RevokeToken => "DELETE /installation/token",
            Route::InstallationRepositories => "GET /installation/repositories",
            Route::Repo => "GET /repos/{owner}/{repo}",
            Route::Issue => "GET /repos/{owner}/{repo}/issues/{number}",
            Route::IssuesList => "GET /repos/{owner}/{repo}/issues",
            Route::IssueCreate => "POST /repos/{owner}/{repo}/issues",
            Route::IssueComments => "GET /repos/{owner}/{repo}/issues/{number}/comments",
            Route::IssueEvents => "GET /repos/{owner}/{repo}/issues/{number}/events",
            Route::CreateComment => "POST /repos/{owner}/{repo}/issues/{number}/comments",
            Route::IssueLabels => "GET /repos/{owner}/{repo}/issues/{number}/labels",
            Route::LabelsAdd => "POST /repos/{owner}/{repo}/issues/{number}/labels",
            Route::LabelRemove => "DELETE /repos/{owner}/{repo}/issues/{number}/labels/{name}",
            Route::CommentUpdate => "PATCH /repos/{owner}/{repo}/issues/comments/{id}",
            Route::CommentDelete => "DELETE /repos/{owner}/{repo}/issues/comments/{id}",
            Route::Collaborator => "GET /repos/{owner}/{repo}/collaborators/{username}/permission",
            Route::Branch => "GET /repos/{owner}/{repo}/branches/{branch}",
            Route::BranchProtection => "GET /repos/{owner}/{repo}/branches/{branch}/protection",
            Route::Contents => "GET /repos/{owner}/{repo}/contents/{path}",
            Route::ContentsPut => "PUT /repos/{owner}/{repo}/contents/{path}",
            Route::RefGet => "GET /repos/{owner}/{repo}/git/ref/heads/{branch}",
            Route::RefCreate => "POST /repos/{owner}/{repo}/git/refs",
            Route::RefUpdate => "PATCH /repos/{owner}/{repo}/git/refs/heads/{branch}",
            Route::RefDelete => "DELETE /repos/{owner}/{repo}/git/refs/heads/{branch}",
            Route::PullsList => "GET /repos/{owner}/{repo}/pulls",
            Route::PullCreate => "POST /repos/{owner}/{repo}/pulls",
            Route::PullGet => "GET /repos/{owner}/{repo}/pulls/{number}",
            Route::PullUpdate => "PATCH /repos/{owner}/{repo}/pulls/{number}",
            Route::PullMerge => "PUT /repos/{owner}/{repo}/pulls/{number}/merge",
            Route::ReviewsList => "GET /repos/{owner}/{repo}/pulls/{number}/reviews",
            Route::ReviewCreate => "POST /repos/{owner}/{repo}/pulls/{number}/reviews",
            Route::CheckRunCreate => "POST /repos/{owner}/{repo}/check-runs",
            Route::StatusCreate => "POST /repos/{owner}/{repo}/statuses/{sha}",
            Route::Graphql => "POST /graphql",
        }
    }
}

/// Finds the route and its path parameters, percent-decoded.
pub(crate) fn match_route(method: &str, path: &str) -> Option<(Route, Vec<String>)> {
    let segments: Vec<String> = path
        .trim_matches('/')
        .split('/')
        .map(percent_decode_path)
        .collect();
    let s: Vec<&str> = segments.iter().map(String::as_str).collect();
    let params = |from: &[&str]| from.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>();
    let found = match (method, s.as_slice()) {
        ("GET", ["app"]) => (Route::App, vec![]),
        ("GET", ["app", "installations", id]) => (Route::Installation, params(&[id])),
        ("POST", ["app", "installations", id, "access_tokens"]) => {
            (Route::MintToken, params(&[id]))
        }
        ("DELETE", ["installation", "token"]) => (Route::RevokeToken, vec![]),
        ("GET", ["installation", "repositories"]) => (Route::InstallationRepositories, vec![]),
        ("GET", ["repos", o, r]) => (Route::Repo, params(&[o, r])),
        ("GET", ["repos", o, r, "issues", n]) => (Route::Issue, params(&[o, r, n])),
        ("GET", ["repos", o, r, "issues"]) => (Route::IssuesList, params(&[o, r])),
        ("POST", ["repos", o, r, "issues"]) => (Route::IssueCreate, params(&[o, r])),
        ("GET", ["repos", o, r, "issues", n, "comments"]) => {
            (Route::IssueComments, params(&[o, r, n]))
        }
        ("GET", ["repos", o, r, "issues", n, "events"]) => (Route::IssueEvents, params(&[o, r, n])),
        ("POST", ["repos", o, r, "issues", n, "comments"]) => {
            (Route::CreateComment, params(&[o, r, n]))
        }
        ("GET", ["repos", o, r, "issues", n, "labels"]) => (Route::IssueLabels, params(&[o, r, n])),
        ("POST", ["repos", o, r, "issues", n, "labels"]) => (Route::LabelsAdd, params(&[o, r, n])),
        ("DELETE", ["repos", o, r, "issues", n, "labels", name]) => {
            (Route::LabelRemove, params(&[o, r, n, name]))
        }
        ("PATCH", ["repos", o, r, "issues", "comments", id]) => {
            (Route::CommentUpdate, params(&[o, r, id]))
        }
        ("DELETE", ["repos", o, r, "issues", "comments", id]) => {
            (Route::CommentDelete, params(&[o, r, id]))
        }
        ("GET", ["repos", o, r, "collaborators", u, "permission"]) => {
            (Route::Collaborator, params(&[o, r, u]))
        }
        ("GET", ["repos", o, r, "branches", rest @ ..]) if !rest.is_empty() => {
            if rest.len() >= 2 && rest.last() == Some(&"protection") {
                (
                    Route::BranchProtection,
                    params(&[o, r, &rest[..rest.len() - 1].join("/")]),
                )
            } else {
                (Route::Branch, params(&[o, r, &rest.join("/")]))
            }
        }
        ("GET", ["repos", o, r, "contents", rest @ ..]) if !rest.is_empty() => {
            (Route::Contents, params(&[o, r, &rest.join("/")]))
        }
        ("PUT", ["repos", o, r, "contents", rest @ ..]) if !rest.is_empty() => {
            (Route::ContentsPut, params(&[o, r, &rest.join("/")]))
        }
        ("GET", ["repos", o, r, "git", "ref", "heads", rest @ ..]) if !rest.is_empty() => {
            (Route::RefGet, params(&[o, r, &rest.join("/")]))
        }
        ("POST", ["repos", o, r, "git", "refs"]) => (Route::RefCreate, params(&[o, r])),
        ("PATCH", ["repos", o, r, "git", "refs", "heads", rest @ ..]) if !rest.is_empty() => {
            (Route::RefUpdate, params(&[o, r, &rest.join("/")]))
        }
        ("DELETE", ["repos", o, r, "git", "refs", "heads", rest @ ..]) if !rest.is_empty() => {
            (Route::RefDelete, params(&[o, r, &rest.join("/")]))
        }
        ("GET", ["repos", o, r, "pulls"]) => (Route::PullsList, params(&[o, r])),
        ("POST", ["repos", o, r, "pulls"]) => (Route::PullCreate, params(&[o, r])),
        ("GET", ["repos", o, r, "pulls", n]) => (Route::PullGet, params(&[o, r, n])),
        ("PATCH", ["repos", o, r, "pulls", n]) => (Route::PullUpdate, params(&[o, r, n])),
        ("PUT", ["repos", o, r, "pulls", n, "merge"]) => (Route::PullMerge, params(&[o, r, n])),
        ("GET", ["repos", o, r, "pulls", n, "reviews"]) => (Route::ReviewsList, params(&[o, r, n])),
        ("POST", ["repos", o, r, "pulls", n, "reviews"]) => {
            (Route::ReviewCreate, params(&[o, r, n]))
        }
        ("POST", ["repos", o, r, "check-runs"]) => (Route::CheckRunCreate, params(&[o, r])),
        ("POST", ["repos", o, r, "statuses", sha]) => (Route::StatusCreate, params(&[o, r, sha])),
        ("POST", ["graphql"]) => (Route::Graphql, vec![]),
        _ => return None,
    };
    Some(found)
}

/// Decodes `%XX` in a path segment. Unlike a query, `+` stays a plus.
fn percent_decode_path(segment: &str) -> String {
    percent_decode(&segment.replace('+', "%2B"))
}

// ---- authentication --------------------------------------------------------------------------

enum Auth {
    Anonymous,
    App { issuer: String },
    Token(usize),
    Bad(String),
}

/// A structurally valid JWT with a placeholder signature.
pub(crate) fn build_jwt(app_id: u64, issued_at: i64, expires_at: i64) -> String {
    let encode = |text: &str| base64_encode(text.as_bytes(), Base64Alphabet::UrlSafe, false);
    format!(
        "{}.{}.{}",
        encode(r#"{"alg":"RS256","typ":"JWT"}"#),
        encode(&format!(
            r#"{{"iat":{issued_at},"exp":{expires_at},"iss":"{app_id}"}}"#
        )),
        encode("fake-signature")
    )
}

/// Checks the claims of an App JWT. The signature is not verified (see the module docs).
fn check_jwt(credential: &str, now: i64, app_id: u64) -> Result<String, String> {
    let parts: Vec<&str> = credential.split('.').collect();
    let decode = |part: &str| -> Option<Value> {
        let bytes = base64_decode(part, Base64Alphabet::UrlSafe)?;
        serde_json::from_slice(&bytes).ok()
    };
    let [header, claims, signature] = parts.as_slice() else {
        return Err("A JSON web token could not be decoded".to_owned());
    };
    let (Some(header), Some(claims)) = (decode(header), decode(claims)) else {
        return Err("A JSON web token could not be decoded".to_owned());
    };
    if header["alg"] != "RS256" {
        return Err("A JSON web token could not be decoded".to_owned());
    }
    if signature.is_empty() {
        return Err("A JSON web token could not be decoded".to_owned());
    }
    let issuer = match &claims["iss"] {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        _ => return Err("'Issuer' claim ('iss') must be the App id".to_owned()),
    };
    if issuer != app_id.to_string() {
        return Err("'Issuer' claim ('iss') does not match this App".to_owned());
    }
    let (Some(issued_at), Some(expires_at)) = (claims["iat"].as_i64(), claims["exp"].as_i64())
    else {
        return Err(
            "'Issued at' claim ('iat') must be an Integer representing the time that the assertion was issued"
                .to_owned(),
        );
    };
    if issued_at > now + 60 {
        return Err("'Issued at' claim ('iat') must be an Integer representing the time that the assertion was issued".to_owned());
    }
    if expires_at <= now {
        return Err("'Expiration time' claim ('exp') must be a numeric value representing the future time at which the assertion expires".to_owned());
    }
    if expires_at - issued_at > 600 {
        return Err("'Expiration time' claim ('exp') is too far in the future".to_owned());
    }
    Ok(issuer)
}

fn authenticate(state: &mut State, request: &HttpRequest, now: i64) -> Auth {
    let Some(header) = request.header("authorization") else {
        return Auth::Anonymous;
    };
    let (scheme, credential) = header.split_once(' ').unwrap_or(("", header));
    let credential = credential.trim();
    if !(scheme.eq_ignore_ascii_case("bearer") || scheme.eq_ignore_ascii_case("token")) {
        return Auth::Bad("unsupported authorization scheme".to_owned());
    }
    if credential.starts_with("ghs_") {
        let Some(index) = state.tokens.iter().position(|t| t.value == credential) else {
            return Auth::Bad("unknown token".to_owned());
        };
        let token = &mut state.tokens[index];
        if token.revoked_at.is_some() {
            token.uses_after_revoke += 1;
            return Auth::Bad("revoked token".to_owned());
        }
        if now >= token.expires_at {
            return Auth::Bad("expired token".to_owned());
        }
        token.uses += 1;
        return Auth::Token(index);
    }
    if credential.matches('.').count() == 2 {
        return match check_jwt(credential, now, state.app.id) {
            Ok(issuer) => Auth::App { issuer },
            Err(message) => Auth::Bad(message),
        };
    }
    Auth::Bad("unknown credential".to_owned())
}

// ---- the request pipeline --------------------------------------------------------------------

pub(crate) fn handle(state: &mut State, now: i64, request: &HttpRequest) -> HttpResponse {
    let route = match_route(&request.method, request.path());
    let template = route
        .as_ref()
        .map_or("UNROUTED", |(route, _)| route.template());
    let auth = authenticate(state, request, now);

    let mut response = if let Some(fault) = take_fault(state, template) {
        let mut error = ApiError::new(fault.status, &fault.message);
        error.headers = fault.headers;
        error.into_response()
    } else {
        match &route {
            None => not_found().into_response(),
            Some((route, params)) => match dispatch(state, now, request, *route, params, &auth) {
                Ok(response) => response,
                Err(error) => error.into_response(),
            },
        }
    };
    // Every body has the same JSON shape, but only 404 and the like need a note for humans.
    if response.status == 204 {
        response.body.clear();
    }

    let summary = match &auth {
        Auth::Anonymous => super::AuthSummary::None,
        Auth::App { issuer } => super::AuthSummary::AppJwt {
            issuer: issuer.clone(),
        },
        Auth::Token(index) => super::AuthSummary::InstallationToken {
            token_id: state.tokens[*index].id,
        },
        Auth::Bad(reason) => super::AuthSummary::Rejected {
            reason: reason.clone(),
        },
    };
    let headers = request
        .headers
        .iter()
        .map(|(name, value)| {
            if name.eq_ignore_ascii_case("authorization")
                || name.eq_ignore_ascii_case("proxy-authorization")
            {
                (name.clone(), mask_authorization(value))
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect();
    state.log.push(RequestRecord {
        seq: state.log.len() as u64 + 1,
        at: now,
        method: request.method.clone(),
        path: request.path().to_owned(),
        query: request.query().map(str::to_owned),
        route: template.to_owned(),
        headers,
        body: request.body.clone(),
        auth: summary,
        status: response.status,
    });
    response
}

fn take_fault(state: &mut State, template: &str) -> Option<Fault> {
    let index = state
        .faults
        .iter()
        .position(|f| f.route == "*" || f.route == template)?;
    let fault = state.faults[index].clone();
    match state.faults[index].remaining {
        Some(1) => {
            state.faults.remove(index);
        }
        Some(left) => state.faults[index].remaining = Some(left - 1),
        None => {}
    }
    Some(fault)
}

fn dispatch(
    state: &mut State,
    now: i64,
    request: &HttpRequest,
    route: Route,
    params: &[String],
    auth: &Auth,
) -> Outcome {
    match route {
        Route::App | Route::Installation | Route::MintToken => match auth {
            Auth::App { .. } => {}
            Auth::Anonymous => {
                return Err(ApiError::new(401, "A JSON web token could not be decoded"));
            }
            Auth::Bad(message) => return Err(ApiError::new(401, public_message(message))),
            Auth::Token(_) => {
                return Err(ApiError::new(401, "A JSON web token could not be decoded"));
            }
        },
        _ => match auth {
            Auth::Token(_) => {}
            Auth::Anonymous | Auth::App { .. } => {
                return Err(ApiError::new(401, "Requires authentication"));
            }
            Auth::Bad(_) => return Err(ApiError::new(401, "Bad credentials")),
        },
    }
    let token = match auth {
        Auth::Token(index) => Some(state.tokens[*index].clone()),
        _ => None,
    };
    match route {
        Route::App => Ok(get_app(state)),
        Route::Installation => get_installation(state, &params[0]),
        Route::MintToken => mint_token(state, now, request, &params[0]),
        Route::RevokeToken => revoke_token(state, now, token.as_ref()),
        Route::InstallationRepositories => Ok(installation_repositories(state, token.as_ref())),
        Route::Graphql => {
            let token = token.expect("the match above sent only token requests here");
            Ok(graphql(state, request, &token))
        }
        _ => {
            let token = token.expect("the match above sent only token requests here");
            dispatch_repo(state, now, request, route, params, &token)
        }
    }
}

/// The one query of GraphQL the fake answers: the time the body of an issue was last edited
/// (DR-1). GitHub answers a query it cannot run with status 200 and an `errors` member, and so does
/// this: a query that is not this one (a mutation above all), a repository the token cannot see,
/// a token without `issues: read`, and an issue that is not there.
fn graphql(state: &State, request: &HttpRequest, token: &TokenRecord) -> HttpResponse {
    let refused = |message: &str| {
        HttpResponse::json(
            200,
            &json!({"data": Value::Null, "errors": [{"message": message}]}),
        )
    };
    let Ok(body) = body_json(request) else {
        return HttpResponse::json(400, &json!({"message": "Problems parsing JSON"}));
    };
    let query = body["query"].as_str().unwrap_or_default();
    if !query.trim_start().starts_with("query")
        || query.contains("mutation")
        || !query.contains("lastEditedAt")
    {
        return refused("this fake answers only the read of lastEditedAt");
    }
    let variables = &body["variables"];
    let (Some(owner), Some(name), Some(number)) = (
        variables["owner"].as_str(),
        variables["name"].as_str(),
        variables["number"].as_u64(),
    ) else {
        return refused("variables owner, name and number are required");
    };
    if require(token, "issues", "read").is_err() {
        return refused("Resource not accessible by integration");
    }
    let Ok(full) = repo_access(state, token, owner, name) else {
        return refused("Could not resolve to a Repository");
    };
    let Some(issue) = state.repos[&full].issues.get(&number) else {
        return HttpResponse::json(
            200,
            &json!({"data": {"repository": {"issue": Value::Null}}, "errors": [{"type": "NOT_FOUND", "message": "Could not resolve to an Issue"}]}),
        );
    };
    HttpResponse::json(
        200,
        &json!({"data": {"repository": {"issue": {
            "lastEditedAt": issue.body_edited_at.map_or(Value::Null, |at| json!(iso(at))),
        }}}}),
    )
}

/// A JWT problem is reported to the caller in GitHub's words; any other bad credential is just
/// "Bad credentials".
fn public_message(reason: &str) -> &str {
    if reason.starts_with("'") || reason.starts_with("A JSON web token") {
        reason
    } else {
        "Bad credentials"
    }
}

// ---- App endpoints ---------------------------------------------------------------------------

fn get_app(state: &State) -> HttpResponse {
    HttpResponse::json(
        200,
        &json!({
            "id": state.app.id,
            "slug": state.app.slug,
            "name": state.app.slug,
            "node_id": format!("A_fake_{}", state.app.id),
            "permissions": state.app.permissions,
            "events": ["issues", "issue_comment", "pull_request", "pull_request_review"],
        }),
    )
}

fn get_installation(state: &State, id: &str) -> Outcome {
    let installation = id
        .parse::<u64>()
        .ok()
        .and_then(|id| state.installations.get(&id))
        .ok_or_else(not_found)?;
    Ok(HttpResponse::json(
        200,
        &json!({
            "id": installation.id,
            "app_id": state.app.id,
            "account": {"login": installation.account_login, "id": installation.account_id},
            "repository_selection": "selected",
            "permissions": state.app.permissions,
            "suspended_at": Value::Null,
        }),
    ))
}

fn mint_token(state: &mut State, now: i64, request: &HttpRequest, id: &str) -> Outcome {
    let installation = id
        .parse::<u64>()
        .ok()
        .and_then(|id| state.installations.get(&id))
        .cloned()
        .ok_or_else(not_found)?;
    let body: Option<Value> = if request.body.is_empty() {
        None
    } else {
        Some(
            serde_json::from_slice(&request.body)
                .map_err(|_| ApiError::new(400, "Problems parsing JSON"))?,
        )
    };

    // Repositories: names within the installation's account.
    let requested_repositories: Option<Vec<String>> = body
        .as_ref()
        .and_then(|b| b.get("repositories"))
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(|n| n.as_str().map(str::to_owned))
                .collect()
        });
    let granted_repositories: Vec<String> = match &requested_repositories {
        Some(names) => {
            let mut full = Vec::new();
            for name in names {
                let full_name = format!("{}/{}", installation.account_login, name);
                if !installation.repositories.contains(&full_name) {
                    return Err(ApiError::new(
                        422,
                        "There is at least one repository that does not exist or is not accessible to the parent installation.",
                    ));
                }
                full.push(full_name);
            }
            full
        }
        None => installation.repositories.iter().cloned().collect(),
    };

    // Permissions: never more than the App holds.
    let requested_permissions: Option<BTreeMap<String, String>> = body
        .as_ref()
        .and_then(|b| b.get("permissions"))
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
                .collect()
        });
    let granted_permissions = match &requested_permissions {
        Some(wanted) => {
            for (name, level) in wanted {
                let held = state.app.permissions.get(name).map_or(0, |l| level_rank(l));
                if level_rank(level) == 0 || level_rank(level) > held {
                    return Err(ApiError::new(
                        422,
                        "The permissions requested are not granted to this installation.",
                    ));
                }
            }
            wanted.clone()
        }
        None => state.app.permissions.clone(),
    };

    let selected = requested_repositories.is_some();
    let token_id = state.tokens.len() as u64 + 1;
    let value = new_token_value(&mut state.rng);
    let expires_at = now + TOKEN_LIFETIME_SECONDS;
    state.tokens.push(TokenRecord {
        id: token_id,
        value: value.clone(),
        installation_id: installation.id,
        repositories: granted_repositories.clone(),
        permissions: granted_permissions.clone(),
        expires_at,
        revoked_at: None,
        uses: 0,
        uses_after_revoke: 0,
    });
    state.mints.push(MintRecord {
        request_seq: state.log.len() as u64 + 1,
        token_id,
        installation_id: installation.id,
        request_body: body,
        requested_repositories,
        requested_permissions,
        granted_repositories: granted_repositories.clone(),
        granted_permissions: granted_permissions.clone(),
    });
    let repositories: Vec<Value> = granted_repositories
        .iter()
        .filter_map(|name| state.repos.get(name))
        .map(repo_json)
        .collect();
    Ok(HttpResponse::json(
        201,
        &json!({
            "token": value,
            "expires_at": iso(expires_at),
            "permissions": granted_permissions,
            "repository_selection": if selected { "selected" } else { "all" },
            "repositories": repositories,
        }),
    ))
}

fn revoke_token(state: &mut State, now: i64, token: Option<&TokenRecord>) -> Outcome {
    let token = token.expect("a token request");
    if let Some(record) = state.tokens.iter_mut().find(|t| t.id == token.id) {
        record.revoked_at = Some(now);
    }
    Ok(HttpResponse::empty(204))
}

fn installation_repositories(state: &State, token: Option<&TokenRecord>) -> HttpResponse {
    let token = token.expect("a token request");
    let repositories: Vec<Value> = token
        .repositories
        .iter()
        .filter_map(|name| state.repos.get(name))
        .map(repo_json)
        .collect();
    HttpResponse::json(
        200,
        &json!({"total_count": repositories.len(), "repositories": repositories}),
    )
}

// ---- repository endpoints --------------------------------------------------------------------

pub(crate) fn repo_json(repo: &Repo) -> Value {
    let (owner, name) = repo
        .full_name
        .split_once('/')
        .unwrap_or(("", &repo.full_name));
    json!({
        "id": repo.id,
        "node_id": format!("R_fake_{}", repo.id),
        "name": name,
        "full_name": repo.full_name,
        "private": true,
        "owner": {"login": owner},
        "default_branch": repo.default_branch,
        "html_url": format!("https://github.test/{}", repo.full_name),
    })
}

fn require(token: &TokenRecord, permission: &str, level: &str) -> Result<(), ApiError> {
    let held = token
        .permissions
        .get(permission)
        .map_or(0, |l| level_rank(l));
    if held >= level_rank(level) {
        Ok(())
    } else {
        Err(forbidden())
    }
}

/// The repository a token may use, or a 404, which is what GitHub says for a repository the
/// token cannot see, whether it exists or not.
fn repo_access(
    state: &State,
    token: &TokenRecord,
    owner: &str,
    name: &str,
) -> Result<String, ApiError> {
    let full = format!("{owner}/{name}");
    if token.repositories.contains(&full) && state.repos.contains_key(&full) {
        Ok(full)
    } else {
        Err(not_found())
    }
}

fn parse_number(text: &str) -> Result<u64, ApiError> {
    text.parse().map_err(|_| not_found())
}

fn body_json(request: &HttpRequest) -> Result<Value, ApiError> {
    serde_json::from_slice(&request.body).map_err(|_| ApiError::new(400, "Problems parsing JSON"))
}

pub(crate) fn issue_json(state: &State, repo: &Repo, issue: &Issue) -> Value {
    let (owner_and_name, number) = (&repo.full_name, issue.number);
    let author = state.users.get(&issue.author);
    let mut value = json!({
        "id": repo.id * 10_000 + number,
        "node_id": format!("I_fake_{}_{number}", repo.id),
        "number": number,
        "title": issue.title,
        "body": issue.body,
        "state": issue.state,
        "user": author.map_or_else(|| json!({"login": issue.author}), super::User::json),
        "author_association": author.map_or("NONE", |u| u.association.as_str()),
        "labels": issue.labels.iter().enumerate().map(|(i, name)| json!({"id": i + 1, "name": name})).collect::<Vec<_>>(),
        "comments": issue.comments.len(),
        "created_at": iso(issue.created_at),
        "updated_at": iso(issue.updated_at),
        "html_url": format!("https://github.test/{owner_and_name}/issues/{number}"),
    });
    if issue.is_pull {
        value["pull_request"] = json!({"url": format!("https://api.github.test/repos/{owner_and_name}/pulls/{number}")});
    }
    value
}

/// `GET /repos/{owner}/{repo}/issues`: the issues and pull requests of a repository, as GitHub
/// lists them. `state` is `open` (the default), `closed` or `all`; `labels` is a comma-separated
/// list that every issue listed must carry, without regard to case; `sort=created` with
/// `direction` `asc` or `desc` (the default). Paged like the other lists.
fn issues_list(state: &State, request: &HttpRequest, token: &TokenRecord, full: &str) -> Outcome {
    require(token, "issues", "read")?;
    let repo = &state.repos[full];
    let wanted_state = request
        .query_param("state")
        .unwrap_or_else(|| "open".to_owned());
    let wanted_labels: Vec<String> = request
        .query_param("labels")
        .map(|v| {
            v.split(',')
                .map(|l| l.trim().to_owned())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let ascending = request.query_param("direction").as_deref() == Some("asc");
    let per_page = request
        .query_param("per_page")
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(30, |n| n.clamp(1, 100));
    let page = request
        .query_param("page")
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(1, |n| n.max(1));
    let mut listed: Vec<&Issue> = repo
        .issues
        .values()
        .filter(|issue| wanted_state == "all" || issue.state == wanted_state)
        .filter(|issue| {
            wanted_labels
                .iter()
                .all(|want| issue.labels.iter().any(|l| l.eq_ignore_ascii_case(want)))
        })
        .collect();
    listed.sort_by_key(|issue| (issue.created_at, issue.number));
    if !ascending {
        listed.reverse();
    }
    let last_page = listed.len().div_ceil(per_page).max(1);
    let list: Vec<Value> = listed
        .into_iter()
        .skip((page - 1) * per_page)
        .take(per_page)
        .map(|issue| issue_json(state, repo, issue))
        .collect();
    let mut response = HttpResponse::json(200, &Value::Array(list));
    if page < last_page {
        let host = request.header("host").unwrap_or("127.0.0.1");
        let rest: String = request
            .query()
            .unwrap_or_default()
            .split('&')
            .filter(|p| !p.starts_with("page=") && !p.starts_with("per_page=") && !p.is_empty())
            .map(|p| format!("&{p}"))
            .collect();
        let at = |n: usize| {
            format!(
                "<http://{host}{}?per_page={per_page}&page={n}{rest}>",
                request.path()
            )
        };
        response = response.with_header(
            "Link",
            &format!(
                "{}; rel=\"next\", {}; rel=\"last\"",
                at(page + 1),
                at(last_page)
            ),
        );
    }
    Ok(response)
}

/// `POST /repos/{owner}/{repo}/issues`: a new issue written by the App, with the labels given.
fn issue_create(
    state: &mut State,
    now: i64,
    request: &HttpRequest,
    token: &TokenRecord,
    full: &str,
) -> Outcome {
    require(token, "issues", "write")?;
    let body = body_json(request)?;
    let title = body["title"].as_str().unwrap_or_default().to_owned();
    if title.trim().is_empty() {
        return Err(ApiError::validation(
            "Issue",
            "title",
            "missing_field",
            None,
        ));
    }
    if title.chars().count() > 256 {
        return Err(ApiError::validation(
            "Issue",
            "title",
            "custom",
            Some("title is too long (maximum is 256 characters)"),
        ));
    }
    let text = body["body"].as_str().unwrap_or_default().to_owned();
    if text.chars().count() > 65_536 {
        return Err(ApiError::validation(
            "Issue",
            "body",
            "custom",
            Some("body is too long (maximum is 65536 characters)"),
        ));
    }
    let labels: Vec<String> = body["labels"]
        .as_array()
        .map(|names| {
            names
                .iter()
                .filter_map(|l| l.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let author = state.app.bot_login();
    let ids: Vec<u64> = labels.iter().map(|_| state.new_id()).collect();
    let repo = state.repos.get_mut(full).expect("checked by the caller");
    let number = repo.next_number;
    repo.next_number += 1;
    let events = labels
        .iter()
        .zip(ids)
        .map(|(label, id)| super::IssueEvent {
            id,
            event: "labeled".to_owned(),
            actor: author.clone(),
            label: Some(label.clone()),
            created_at: now,
        })
        .collect();
    repo.issues.insert(
        number,
        Issue {
            number,
            title,
            body: text,
            state: "open".to_owned(),
            is_pull: false,
            author,
            labels,
            created_at: now,
            updated_at: now,
            body_edited_at: None,
            comments: Vec::new(),
            events,
            events_newest_first: false,
        },
    );
    let repo = &state.repos[full];
    Ok(HttpResponse::json(
        201,
        &issue_json(state, repo, &repo.issues[&number]),
    ))
}

fn labels_json(labels: &[String]) -> Value {
    Value::Array(
        labels
            .iter()
            .enumerate()
            .map(|(i, name)| json!({"id": i + 1, "name": name, "color": "ededed"}))
            .collect(),
    )
}

fn comment_json(state: &State, repo: &Repo, issue: &Issue, comment: &Comment) -> Value {
    let author = state.users.get(&comment.author);
    json!({
        "id": comment.id,
        "node_id": format!("IC_fake_{}", comment.id),
        "body": comment.body,
        "user": author.map_or_else(|| json!({"login": comment.author}), super::User::json),
        "author_association": author.map_or("NONE", |u| u.association.as_str()),
        "created_at": iso(comment.created_at),
        "updated_at": iso(comment.created_at),
        "issue_url": format!("https://api.github.test/repos/{}/issues/{}", repo.full_name, issue.number),
    })
}

pub(crate) fn pull_json(state: &State, repo: &Repo, pull: &Pull) -> Option<Value> {
    let owner = repo.full_name.split('/').next().unwrap_or_default();
    let author = state.users.get(&pull.author);
    let base_sha = repo
        .branches
        .get(&pull.base_ref)
        .cloned()
        .unwrap_or_default();
    Some(json!({
        "id": repo.id * 10_000 + pull.number,
        "node_id": format!("PR_fake_{}_{}", repo.id, pull.number),
        "number": pull.number,
        "state": pull.state,
        "draft": pull.draft,
        "merged": pull.merged,
        "title": pull.title,
        "body": pull.body,
        "user": author.map_or_else(|| json!({"login": pull.author}), super::User::json),
        "head": {"ref": pull.head_ref, "sha": pull.head_sha, "label": format!("{owner}:{}", pull.head_ref)},
        "base": {"ref": pull.base_ref, "sha": base_sha, "label": format!("{owner}:{}", pull.base_ref)},
        "merge_commit_sha": pull.merge_commit_sha,
        "created_at": iso(pull.created_at),
        "updated_at": iso(pull.updated_at),
        "closed_at": pull.closed_at.map(iso),
        "merged_at": pull.closed_at.filter(|_| pull.merged).map(iso),
        "html_url": format!("https://github.test/{}/pull/{}", repo.full_name, pull.number),
    }))
}

fn protection_summary(protection: &super::Protection) -> Value {
    json!({
        "enabled": true,
        "required_status_checks": {
            "enforcement_level": "everyone",
            "contexts": protection.required_checks.iter().map(|c| c.context.clone()).collect::<Vec<_>>(),
            "checks": protection.required_checks.iter().map(|c| json!({"context": c.context, "app_id": c.app_id})).collect::<Vec<_>>(),
        },
    })
}

/// The tree of a commit: its own when the contents write route or a lever made it, and the
/// repository's one tree otherwise.
pub(crate) fn tree_of(repo: &Repo, sha: &str) -> BTreeMap<String, Option<String>> {
    repo.trees
        .get(sha)
        .cloned()
        .unwrap_or_else(|| repo.files.clone())
}

/// A blob id for a file's text: 40 hexadecimal characters that change with the text. Not git's
/// own blob hash; a caller only sends it back.
pub(crate) fn blob_sha(text: Option<&str>) -> String {
    let digest = crate::fx::digest::sha256(text.unwrap_or("\u{0}no text").as_bytes());
    crate::fx::encoding::hex_encode(digest.get(..20).unwrap_or(&digest), false)
}

/// Moves every open pull request whose head is `branch` to `sha`, and makes older approvals
/// stale.
pub(crate) fn move_pull_heads(repo: &mut Repo, branch: &str, sha: &str) {
    for pull in repo.pulls.values_mut() {
        if pull.head_ref == branch && pull.state == "open" {
            sha.clone_into(&mut pull.head_sha);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn dispatch_repo(
    state: &mut State,
    now: i64,
    request: &HttpRequest,
    route: Route,
    params: &[String],
    token: &TokenRecord,
) -> Outcome {
    let full = repo_access(state, token, &params[0], &params[1])?;
    match route {
        Route::Repo => {
            require(token, "metadata", "read")?;
            Ok(HttpResponse::json(200, &repo_json(&state.repos[&full])))
        }
        Route::Issue => {
            require(token, "issues", "read")?;
            let repo = &state.repos[&full];
            let issue = repo
                .issues
                .get(&parse_number(&params[2])?)
                .ok_or_else(not_found)?;
            Ok(with_etag(request, 200, &issue_json(state, repo, issue)))
        }
        Route::IssuesList => issues_list(state, request, token, &full),
        Route::IssueCreate => issue_create(state, now, request, token, &full),
        Route::IssueEvents => {
            require(token, "issues", "read")?;
            let repo = &state.repos[&full];
            let issue = repo
                .issues
                .get(&parse_number(&params[2])?)
                .ok_or_else(not_found)?;
            // GitHub pages this list (30 by default, 100 at most) and says where the next page is
            // in the `Link` header. The order is oldest first unless the test says otherwise.
            let per_page = request
                .query_param("per_page")
                .and_then(|v| v.parse::<usize>().ok())
                .map_or(30, |n| n.clamp(1, 100));
            let page = request
                .query_param("page")
                .and_then(|v| v.parse::<usize>().ok())
                .map_or(1, |n| n.max(1));
            let mut listed: Vec<&super::IssueEvent> = issue.events.iter().collect();
            if issue.events_newest_first {
                listed.reverse();
            }
            let last_page = listed.len().div_ceil(per_page).max(1);
            let events: Vec<Value> = listed
                .into_iter()
                .skip((page - 1) * per_page)
                .take(per_page)
                .map(|event| {
                    let actor = state.users.get(&event.actor);
                    let mut value = json!({
                        "id": event.id,
                        "node_id": format!("E_fake_{}", event.id),
                        "event": event.event,
                        "actor": actor.map_or_else(|| json!({"login": event.actor}), super::User::json),
                        "created_at": iso(event.created_at),
                    });
                    if let Some(label) = &event.label {
                        value["label"] = json!({"name": label});
                    }
                    value
                })
                .collect();
            let mut response = HttpResponse::json(200, &Value::Array(events));
            if page < last_page {
                let host = request.header("host").unwrap_or("127.0.0.1");
                let at = |n: usize| {
                    format!(
                        "<http://{host}{}?per_page={per_page}&page={n}>",
                        request.path()
                    )
                };
                response = response.with_header(
                    "Link",
                    &format!(
                        "{}; rel=\"next\", {}; rel=\"last\"",
                        at(page + 1),
                        at(last_page)
                    ),
                );
            }
            Ok(response)
        }
        Route::IssueComments => {
            require(token, "issues", "read")?;
            let repo = &state.repos[&full];
            let issue = repo
                .issues
                .get(&parse_number(&params[2])?)
                .ok_or_else(not_found)?;
            // GitHub pages this list too (30 by default, 100 at most), says where the next page is
            // in the `Link` header, and with `since` lists only the comments written or changed
            // at that time or later.
            let per_page = request
                .query_param("per_page")
                .and_then(|v| v.parse::<usize>().ok())
                .map_or(30, |n| n.clamp(1, 100));
            let page = request
                .query_param("page")
                .and_then(|v| v.parse::<usize>().ok())
                .map_or(1, |n| n.max(1));
            let since = request
                .query_param("since")
                .and_then(|v| factory_domain::values::Timestamp::parse(&v).ok())
                .map(|at| at.unix_seconds());
            let listed: Vec<&super::Comment> = issue
                .comments
                .iter()
                .filter(|c| since.is_none_or(|since| c.created_at >= since))
                .collect();
            let last_page = listed.len().div_ceil(per_page).max(1);
            let list: Vec<Value> = listed
                .into_iter()
                .skip((page - 1) * per_page)
                .take(per_page)
                .map(|c| comment_json(state, repo, issue, c))
                .collect();
            let mut response = HttpResponse::json(200, &Value::Array(list));
            if page < last_page {
                let host = request.header("host").unwrap_or("127.0.0.1");
                let since_part = request
                    .query_param("since")
                    .map_or_else(String::new, |v| format!("&since={v}"));
                let at = |n: usize| {
                    format!(
                        "<http://{host}{}?per_page={per_page}&page={n}{since_part}>",
                        request.path()
                    )
                };
                response = response.with_header(
                    "Link",
                    &format!(
                        "{}; rel=\"next\", {}; rel=\"last\"",
                        at(page + 1),
                        at(last_page)
                    ),
                );
            }
            Ok(response)
        }
        Route::CreateComment => {
            let may_write = require(token, "issues", "write").is_ok()
                || require(token, "pull_requests", "write").is_ok();
            if !may_write {
                return Err(forbidden());
            }
            let number = parse_number(&params[2])?;
            let body = body_json(request)?;
            let text = body["body"].as_str().unwrap_or_default();
            if text.is_empty() {
                return Err(ApiError::validation(
                    "IssueComment",
                    "body",
                    "missing_field",
                    None,
                ));
            }
            if text.chars().count() > 65_536 {
                return Err(ApiError::validation(
                    "IssueComment",
                    "body",
                    "custom",
                    Some("body is too long (maximum is 65536 characters)"),
                ));
            }
            let id = state.new_id();
            let author = state.app.bot_login();
            let repo = state.repos.get_mut(&full).expect("checked above");
            let issue = repo.issues.get_mut(&number).ok_or_else(not_found)?;
            issue.comments.push(Comment {
                id,
                author,
                body: text.to_owned(),
                created_at: now,
            });
            issue.updated_at = now;
            let comment = issue.comments.last().expect("just pushed").clone();
            let issue = issue.clone();
            let repo = &state.repos[&full];
            Ok(HttpResponse::json(
                201,
                &comment_json(state, repo, &issue, &comment),
            ))
        }
        Route::IssueLabels => {
            require(token, "issues", "read")?;
            let issue = state.repos[&full]
                .issues
                .get(&parse_number(&params[2])?)
                .ok_or_else(not_found)?;
            Ok(HttpResponse::json(200, &labels_json(&issue.labels)))
        }
        Route::LabelsAdd => {
            require(token, "issues", "write")?;
            let number = parse_number(&params[2])?;
            let body = body_json(request)?;
            let wanted: Vec<String> = body["labels"]
                .as_array()
                .ok_or_else(|| {
                    ApiError::validation(
                        "Label",
                        "labels",
                        "invalid",
                        Some("labels must be a list"),
                    )
                })?
                .iter()
                .filter_map(|l| l.as_str().or_else(|| l["name"].as_str()).map(str::to_owned))
                .collect();
            if wanted.is_empty() {
                return Err(ApiError::validation(
                    "Label",
                    "labels",
                    "missing_field",
                    None,
                ));
            }
            let actor = state.app.bot_login();
            let ids: Vec<u64> = wanted.iter().map(|_| state.new_id()).collect();
            let issue = state
                .repos
                .get_mut(&full)
                .and_then(|r| r.issues.get_mut(&number))
                .ok_or_else(not_found)?;
            for (label, id) in wanted.into_iter().zip(ids) {
                // Label names are unique without regard to case, as on GitHub.
                if !issue.labels.iter().any(|l| l.eq_ignore_ascii_case(&label)) {
                    issue.events.push(super::IssueEvent {
                        id,
                        event: "labeled".to_owned(),
                        actor: actor.clone(),
                        label: Some(label.clone()),
                        created_at: now,
                    });
                    issue.labels.push(label);
                }
            }
            issue.updated_at = now;
            Ok(HttpResponse::json(200, &labels_json(&issue.labels)))
        }
        Route::LabelRemove => {
            require(token, "issues", "write")?;
            let number = parse_number(&params[2])?;
            let actor = state.app.bot_login();
            let id = state.new_id();
            let issue = state
                .repos
                .get_mut(&full)
                .and_then(|r| r.issues.get_mut(&number))
                .ok_or_else(not_found)?;
            let Some(position) = issue
                .labels
                .iter()
                .position(|l| l.eq_ignore_ascii_case(&params[3]))
            else {
                return Err(ApiError::new(404, "Label does not exist"));
            };
            let label = issue.labels.remove(position);
            issue.events.push(super::IssueEvent {
                id,
                event: "unlabeled".to_owned(),
                actor,
                label: Some(label),
                created_at: now,
            });
            issue.updated_at = now;
            Ok(HttpResponse::json(200, &labels_json(&issue.labels)))
        }
        Route::CommentUpdate => {
            require(token, "issues", "write")?;
            let comment_id = parse_number(&params[2])?;
            let text = body_json(request)?["body"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            if text.is_empty() {
                return Err(ApiError::validation(
                    "IssueComment",
                    "body",
                    "missing_field",
                    None,
                ));
            }
            if text.chars().count() > 65_536 {
                return Err(ApiError::validation(
                    "IssueComment",
                    "body",
                    "custom",
                    Some("body is too long (maximum is 65536 characters)"),
                ));
            }
            let repo = state.repos.get_mut(&full).expect("checked above");
            let number = repo
                .issues
                .iter()
                .find(|(_, issue)| issue.comments.iter().any(|c| c.id == comment_id))
                .map(|(number, _)| *number)
                .ok_or_else(not_found)?;
            let issue = repo.issues.get_mut(&number).expect("just found");
            let comment = issue
                .comments
                .iter_mut()
                .find(|c| c.id == comment_id)
                .expect("just found");
            comment.body = text;
            let comment = comment.clone();
            issue.updated_at = now;
            let issue = issue.clone();
            let repo = &state.repos[&full];
            Ok(HttpResponse::json(
                200,
                &comment_json(state, repo, &issue, &comment),
            ))
        }
        Route::CommentDelete => {
            require(token, "issues", "write")?;
            let comment_id = parse_number(&params[2])?;
            let repo = state.repos.get_mut(&full).expect("checked above");
            for issue in repo.issues.values_mut() {
                if let Some(position) = issue.comments.iter().position(|c| c.id == comment_id) {
                    issue.comments.remove(position);
                    issue.updated_at = now;
                    return Ok(HttpResponse::empty(204));
                }
            }
            Err(not_found())
        }
        Route::Collaborator => {
            require(token, "metadata", "read")?;
            let user = state.users.get(&params[2]).ok_or_else(not_found)?;
            Ok(HttpResponse::json(
                200,
                &json!({"permission": user.role, "role_name": user.role, "user": user.json()}),
            ))
        }
        Route::Branch => {
            require(token, "contents", "read")?;
            let repo = &state.repos[&full];
            let sha = repo.branches.get(&params[2]).ok_or_else(not_found)?;
            let mut body = json!({
                "name": params[2],
                "commit": {"sha": sha},
                "protected": repo.protection.contains_key(&params[2]),
            });
            if let Some(protection) = repo.protection.get(&params[2]) {
                body["protection"] = protection_summary(protection);
            }
            Ok(HttpResponse::json(200, &body))
        }
        Route::Contents => {
            require(token, "contents", "read")?;
            let repo = &state.repos[&full];
            // The tree of the commit `ref` names (a branch or a commit id), else of the default
            // branch.
            let reference = request
                .query_param("ref")
                .unwrap_or_else(|| repo.default_branch.clone());
            let sha = repo.branches.get(&reference).cloned().unwrap_or(reference);
            let tree = tree_of(repo, &sha);
            let files = &tree;
            let path = params[2].as_str();
            let name = |path: &str| path.rsplit('/').next().unwrap_or(path).to_owned();
            if let Some(text) = files.get(path) {
                let blob = blob_sha(text.as_deref());
                let size = text.as_ref().map_or(2_000_000, String::len);
                // A file. One the fake has no text for answers as GitHub does for a file over
                // 1 MB: another encoding and an empty content.
                let (encoding, content) = match text {
                    Some(text) => (
                        "base64",
                        crate::fx::encoding::base64_encode(
                            text.as_bytes(),
                            crate::fx::encoding::Base64Alphabet::Standard,
                            true,
                        ),
                    ),
                    None => ("none", String::new()),
                };
                return Ok(HttpResponse::json(
                    200,
                    &json!({"type": "file", "name": name(path), "path": path, "sha": blob,
                        "size": size, "encoding": encoding, "content": content}),
                ));
            }
            // A directory: its direct children, a deeper path as one `dir` entry.
            let prefix = format!("{path}/");
            let mut children: BTreeMap<String, &str> = BTreeMap::new();
            for file in files.keys() {
                if let Some(rest) = file.strip_prefix(&prefix) {
                    match rest.split_once('/') {
                        Some((directory, _)) => children.insert(directory.to_owned(), "dir"),
                        None => children.insert(rest.to_owned(), "file"),
                    };
                }
            }
            if children.is_empty() {
                return Err(not_found());
            }
            let listing: Vec<Value> = children
                .iter()
                .map(|(child, kind)| {
                    json!({"type": kind, "name": child, "path": format!("{prefix}{child}")})
                })
                .collect();
            Ok(HttpResponse::json(200, &Value::Array(listing)))
        }
        Route::ContentsPut => {
            require(token, "contents", "write")?;
            let body = body_json(request)?;
            let path = params[2].clone();
            let Some(branch) = body["branch"].as_str().map(str::to_owned) else {
                // GitHub writes to the default branch when no branch is named. The fake refuses,
                // so that a caller that forgot the branch is caught.
                return Err(ApiError::validation(
                    "Contents",
                    "branch",
                    "missing_field",
                    None,
                ));
            };
            let text = body["content"]
                .as_str()
                .and_then(|encoded| {
                    let joined: String = encoded.split_whitespace().collect();
                    crate::fx::encoding::base64_decode(
                        &joined,
                        crate::fx::encoding::Base64Alphabet::Standard,
                    )
                })
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or_else(|| ApiError::validation("Contents", "content", "invalid", None))?;
            if body["message"].as_str().is_none_or(|m| m.trim().is_empty()) {
                return Err(ApiError::validation(
                    "Contents",
                    "message",
                    "missing_field",
                    None,
                ));
            }
            let app_slug = state.app.slug.clone();
            let sha = state.new_sha();
            let repo = state.repos.get_mut(&full).expect("checked above");
            let Some(tip) = repo.branches.get(&branch).cloned() else {
                return Err(not_found());
            };
            if let Some(protection) = repo.protection.get(&branch)
                && protection.require_pull_request
                && !protection.bypass_apps.contains(&app_slug)
            {
                return Err(ApiError::new(
                    409,
                    &format!("Protected branch update failed for refs/heads/{branch}."),
                ));
            }
            let mut tree = tree_of(repo, &tip);
            // Replacing a file needs the blob id of the file it replaces, as on GitHub.
            match (tree.get(&path), body["sha"].as_str()) {
                (Some(existing), Some(given)) if given != blob_sha(existing.as_deref()) => {
                    return Err(ApiError::new(409, "does not match"));
                }
                (Some(_), None) => {
                    return Err(ApiError::new(422, "\"sha\" wasn't supplied."));
                }
                _ => {}
            }
            let created = !tree.contains_key(&path);
            tree.insert(path.clone(), Some(text.clone()));
            repo.trees.insert(sha.clone(), tree);
            repo.branches.insert(branch.clone(), sha.clone());
            move_pull_heads(repo, &branch, &sha);
            state.pushes.push(PushRecord {
                repo: full,
                branch,
                kind: "update".to_owned(),
                sha: sha.clone(),
                token_id: Some(token.id),
            });
            Ok(HttpResponse::json(
                if created { 201 } else { 200 },
                &json!({"content": {"path": path, "sha": blob_sha(Some(&text))},
                        "commit": {"sha": sha}}),
            ))
        }
        Route::BranchProtection => {
            require(token, "administration", "read")?;
            let repo = &state.repos[&full];
            let protection = repo
                .protection
                .get(&params[2])
                .ok_or_else(|| ApiError::new(404, "Branch not protected"))?;
            Ok(HttpResponse::json(
                200,
                &json!({
                    "required_status_checks": protection_summary(protection)["required_status_checks"],
                    "enforce_admins": {"enabled": protection.enforce_admins},
                    "required_pull_request_reviews": if protection.require_pull_request {
                        json!({
                            "required_approving_review_count": protection.required_approvals,
                            "dismiss_stale_reviews": protection.dismiss_stale_reviews,
                            "require_code_owner_reviews": protection.require_code_owner_reviews,
                            "bypass_pull_request_allowances": {"apps": protection.bypass_apps.iter().map(|a| json!({"slug": a})).collect::<Vec<_>>()},
                        })
                    } else { Value::Null },
                    "allow_force_pushes": {"enabled": protection.allow_force_pushes},
                    "allow_deletions": {"enabled": protection.allow_deletions},
                }),
            ))
        }
        Route::RefGet => {
            require(token, "contents", "read")?;
            let sha = state.repos[&full]
                .branches
                .get(&params[2])
                .ok_or_else(not_found)?;
            Ok(HttpResponse::json(
                200,
                &json!({"ref": format!("refs/heads/{}", params[2]), "object": {"sha": sha, "type": "commit"}}),
            ))
        }
        Route::RefCreate => {
            require(token, "contents", "write")?;
            let body = body_json(request)?;
            let reference = body["ref"].as_str().unwrap_or_default();
            let sha = body["sha"].as_str().unwrap_or_default();
            let Some(branch) = reference.strip_prefix("refs/heads/") else {
                return Err(ApiError::new(422, "Reference name is invalid"));
            };
            if !is_sha(sha) {
                return Err(ApiError::new(422, "Object does not exist"));
            }
            let repo = state.repos.get_mut(&full).expect("checked above");
            if repo.branches.contains_key(branch) {
                return Err(ApiError::new(422, "Reference already exists"));
            }
            repo.branches.insert(branch.to_owned(), sha.to_owned());
            state.pushes.push(PushRecord {
                repo: full,
                branch: branch.to_owned(),
                kind: "create".to_owned(),
                sha: sha.to_owned(),
                token_id: Some(token.id),
            });
            Ok(HttpResponse::json(
                201,
                &json!({"ref": reference, "object": {"sha": sha, "type": "commit"}}),
            ))
        }
        Route::RefUpdate => {
            require(token, "contents", "write")?;
            let branch = params[2].clone();
            let body = body_json(request)?;
            let sha = body["sha"].as_str().unwrap_or_default().to_owned();
            let force = body["force"].as_bool().unwrap_or(false);
            if !is_sha(&sha) {
                return Err(ApiError::new(422, "Object does not exist"));
            }
            let app_slug = state.app.slug.clone();
            let repo = state.repos.get_mut(&full).expect("checked above");
            if !repo.branches.contains_key(&branch) {
                return Err(ApiError::new(422, "Reference does not exist"));
            }
            if let Some(protection) = repo.protection.get(&branch)
                && ((protection.require_pull_request
                    && !protection.bypass_apps.contains(&app_slug))
                    || (force && !protection.allow_force_pushes))
            {
                return Err(ApiError::new(
                    403,
                    &format!("Protected branch update failed for refs/heads/{branch}."),
                ));
            }
            repo.branches.insert(branch.clone(), sha.clone());
            move_pull_heads(repo, &branch, &sha);
            state.pushes.push(PushRecord {
                repo: full,
                branch: branch.clone(),
                kind: "update".to_owned(),
                sha: sha.clone(),
                token_id: Some(token.id),
            });
            Ok(HttpResponse::json(
                200,
                &json!({"ref": format!("refs/heads/{branch}"), "object": {"sha": sha, "type": "commit"}}),
            ))
        }
        Route::RefDelete => {
            require(token, "contents", "write")?;
            let branch = params[2].clone();
            let repo = state.repos.get_mut(&full).expect("checked above");
            if !repo.branches.contains_key(&branch) {
                return Err(ApiError::new(422, "Reference does not exist"));
            }
            if repo
                .protection
                .get(&branch)
                .is_some_and(|p| !p.allow_deletions)
                || branch == repo.default_branch
            {
                return Err(ApiError::new(
                    403,
                    &format!("Protected branch update failed for refs/heads/{branch}."),
                ));
            }
            repo.branches.remove(&branch);
            state.pushes.push(PushRecord {
                repo: full,
                branch,
                kind: "delete".to_owned(),
                sha: String::new(),
                token_id: Some(token.id),
            });
            Ok(HttpResponse::empty(204))
        }
        Route::PullsList => {
            require(token, "pull_requests", "read")?;
            let repo = &state.repos[&full];
            let wanted_state = request
                .query_param("state")
                .unwrap_or_else(|| "open".to_owned());
            let wanted_head = request.query_param("head");
            let list: Vec<Value> = repo
                .pulls
                .values()
                .filter(|p| wanted_state == "all" || p.state == wanted_state)
                .filter(|p| {
                    wanted_head.as_ref().is_none_or(|head| {
                        let owner = full.split('/').next().unwrap_or_default();
                        head == &format!("{owner}:{}", p.head_ref)
                    })
                })
                .filter_map(|p| pull_json(state, repo, p))
                .collect();
            Ok(HttpResponse::json(200, &Value::Array(list)))
        }
        Route::PullCreate => create_pull(state, now, request, token, &full),
        Route::PullGet => {
            require(token, "pull_requests", "read")?;
            let repo = &state.repos[&full];
            let pull = repo
                .pulls
                .get(&parse_number(&params[2])?)
                .ok_or_else(not_found)?;
            Ok(with_etag(
                request,
                200,
                &pull_json(state, repo, pull).ok_or_else(not_found)?,
            ))
        }
        Route::PullUpdate => update_pull(state, now, request, token, &full, &params[2]),
        Route::PullMerge => merge_pull(state, now, request, token, &full, &params[2]),
        Route::ReviewsList => {
            require(token, "pull_requests", "read")?;
            let repo = &state.repos[&full];
            let pull = repo
                .pulls
                .get(&parse_number(&params[2])?)
                .ok_or_else(not_found)?;
            Ok(HttpResponse::json(
                200,
                &Value::Array(pull.reviews.iter().map(|r| review_json(state, r)).collect()),
            ))
        }
        Route::ReviewCreate => {
            require(token, "pull_requests", "write")?;
            let number = parse_number(&params[2])?;
            let body = body_json(request)?;
            let event = body["event"].as_str().unwrap_or("COMMENT");
            let state_name = match event {
                "APPROVE" => "APPROVED",
                "REQUEST_CHANGES" => "CHANGES_REQUESTED",
                "COMMENT" => "COMMENTED",
                _ => {
                    return Err(ApiError::validation(
                        "PullRequestReview",
                        "event",
                        "invalid",
                        None,
                    ));
                }
            };
            let id = state.new_id();
            let author = state.app.bot_login();
            let repo = state.repos.get_mut(&full).expect("checked above");
            let pull = repo.pulls.get_mut(&number).ok_or_else(not_found)?;
            let commit_id = body["commit_id"]
                .as_str()
                .map_or_else(|| pull.head_sha.clone(), str::to_owned);
            pull.reviews.push(Review {
                id,
                author,
                state: state_name.to_owned(),
                commit_id,
                body: body["body"].as_str().unwrap_or_default().to_owned(),
            });
            let review = pull.reviews.last().expect("just pushed").clone();
            Ok(HttpResponse::json(200, &review_json(state, &review)))
        }
        Route::CheckRunCreate => {
            require(token, "checks", "write")?;
            let body = body_json(request)?;
            let name = body["name"].as_str().unwrap_or_default();
            let head_sha = body["head_sha"].as_str().unwrap_or_default();
            if name.is_empty() {
                return Err(ApiError::validation(
                    "CheckRun",
                    "name",
                    "missing_field",
                    None,
                ));
            }
            if !is_sha(head_sha) {
                return Err(ApiError::validation(
                    "CheckRun", "head_sha", "invalid", None,
                ));
            }
            let status = body["status"].as_str().unwrap_or("queued");
            let conclusion = body["conclusion"].as_str().map(str::to_owned);
            if status == "completed" && conclusion.is_none() {
                return Err(ApiError::validation(
                    "CheckRun",
                    "conclusion",
                    "missing_field",
                    None,
                ));
            }
            let app_id = state.app.id;
            let id = state.new_id();
            state
                .repos
                .get_mut(&full)
                .expect("checked above")
                .checks
                .push(CheckRun {
                    name: name.to_owned(),
                    head_sha: head_sha.to_owned(),
                    status: status.to_owned(),
                    conclusion: conclusion.clone(),
                    app_id,
                });
            Ok(HttpResponse::json(
                201,
                &json!({"id": id, "name": name, "head_sha": head_sha, "status": status, "conclusion": conclusion, "app": {"id": app_id}}),
            ))
        }
        Route::StatusCreate => {
            require(token, "statuses", "write")?;
            let sha = &params[2];
            if !is_sha(sha) {
                return Err(ApiError::new(422, "No commit found for SHA"));
            }
            let body = body_json(request)?;
            let value = body["state"].as_str().unwrap_or_default();
            if !["error", "failure", "pending", "success"].contains(&value) {
                return Err(ApiError::validation("Status", "state", "invalid", None));
            }
            let id = state.new_id();
            let entry = json!({
                "id": id, "sha": sha, "state": value,
                "context": body["context"].as_str().unwrap_or("default"),
                "description": body["description"],
            });
            state
                .repos
                .get_mut(&full)
                .expect("checked above")
                .statuses
                .push(entry.clone());
            Ok(HttpResponse::json(201, &entry))
        }
        Route::App
        | Route::Installation
        | Route::MintToken
        | Route::RevokeToken
        | Route::InstallationRepositories
        | Route::Graphql => unreachable!("handled before the repository check"),
    }
}

/// A weak entity tag for a JSON document: the first eight bytes of its SHA-256. It changes when
/// the content changes, which is all `PullRequestState::body_etag` needs.
fn etag_of(value: &Value) -> String {
    format!(
        "W/\"{}\"",
        crate::fx::encoding::hex_encode(
            &crate::fx::digest::sha256(value.to_string().as_bytes())[..8],
            false
        )
    )
}

/// A JSON answer with an `ETag`, or 304 with no body when the caller already has this version
/// (`If-None-Match`), as GitHub answers.
fn with_etag(request: &HttpRequest, status: u16, value: &Value) -> HttpResponse {
    let etag = etag_of(value);
    if request.header("if-none-match") == Some(etag.as_str()) {
        return HttpResponse::empty(304).with_header("ETag", &etag);
    }
    HttpResponse::json(status, value).with_header("ETag", &etag)
}

fn is_sha(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn review_json(state: &State, review: &Review) -> Value {
    let author = state.users.get(&review.author);
    json!({
        "id": review.id,
        "user": author.map_or_else(|| json!({"login": review.author}), super::User::json),
        "state": review.state,
        "commit_id": review.commit_id,
        "body": review.body,
    })
}

fn create_pull(
    state: &mut State,
    now: i64,
    request: &HttpRequest,
    token: &TokenRecord,
    full: &str,
) -> Outcome {
    require(token, "pull_requests", "write")?;
    let body = body_json(request)?;
    let title = body["title"].as_str().unwrap_or_default();
    if title.trim().is_empty() {
        return Err(ApiError::validation(
            "PullRequest",
            "title",
            "missing_field",
            None,
        ));
    }
    let owner = full.split('/').next().unwrap_or_default();
    // `head` is `branch` or `owner:branch`.
    let head_text = body["head"].as_str().unwrap_or_default();
    let head = head_text
        .split_once(':')
        .map_or(head_text, |(_, branch)| branch);
    let base = body["base"].as_str().unwrap_or_default();
    let repo = &state.repos[full];
    let Some(head_sha) = repo.branches.get(head).cloned() else {
        return Err(ApiError::validation("PullRequest", "head", "invalid", None));
    };
    if !repo.branches.contains_key(base) {
        return Err(ApiError::validation("PullRequest", "base", "invalid", None));
    }
    if head == base {
        return Err(ApiError::validation(
            "PullRequest",
            "base",
            "custom",
            Some(&format!("No commits between {base} and {head}")),
        ));
    }
    // GitHub refuses a second open pull request for the same head and base.
    if repo
        .pulls
        .values()
        .any(|p| p.state == "open" && p.head_ref == head && p.base_ref == base)
    {
        return Err(ApiError::validation(
            "PullRequest",
            "base",
            "custom",
            Some(&format!(
                "A pull request already exists for {owner}:{head}."
            )),
        ));
    }
    let author = state.app.bot_login();
    let draft = body["draft"].as_bool().unwrap_or(false);
    let text = body["body"].as_str().unwrap_or_default().to_owned();
    let repo = state.repos.get_mut(full).expect("checked above");
    let number = repo.next_number;
    repo.next_number += 1;
    repo.pulls.insert(
        number,
        Pull {
            number,
            title: title.to_owned(),
            body: text.clone(),
            state: "open".to_owned(),
            draft,
            merged: false,
            closed_at: None,
            merge_commit_sha: None,
            head_ref: head.to_owned(),
            head_sha,
            base_ref: base.to_owned(),
            author: author.clone(),
            created_at: now,
            updated_at: now,
            reviews: Vec::new(),
        },
    );
    // GitHub keeps an issue record for every pull request, so comments and labels work on it.
    repo.issues.insert(
        number,
        Issue {
            number,
            title: title.to_owned(),
            body: text,
            state: "open".to_owned(),
            is_pull: true,
            author,
            labels: Vec::new(),
            created_at: now,
            updated_at: now,
            body_edited_at: None,
            comments: Vec::new(),
            events: Vec::new(),
            events_newest_first: false,
        },
    );
    let repo = &state.repos[full];
    let pull = &repo.pulls[&number];
    Ok(HttpResponse::json(
        201,
        &pull_json(state, repo, pull).expect("a pull request that exists"),
    ))
}

fn update_pull(
    state: &mut State,
    now: i64,
    request: &HttpRequest,
    token: &TokenRecord,
    full: &str,
    number: &str,
) -> Outcome {
    require(token, "pull_requests", "write")?;
    let number = parse_number(number)?;
    let body = body_json(request)?;
    let repo = state.repos.get_mut(full).expect("checked by the caller");
    let pull = repo.pulls.get_mut(&number).ok_or_else(not_found)?;
    if let Some(title) = body["title"].as_str() {
        title.clone_into(&mut pull.title);
    }
    if let Some(text) = body["body"].as_str() {
        text.clone_into(&mut pull.body);
    }
    if let Some(new_state) = body["state"].as_str() {
        if !["open", "closed"].contains(&new_state) {
            return Err(ApiError::validation(
                "PullRequest",
                "state",
                "invalid",
                None,
            ));
        }
        if pull.merged && new_state == "open" {
            return Err(ApiError::new(422, "Validation Failed"));
        }
        // Closing sets the time of the close once; opening it again takes the time away.
        pull.closed_at = match new_state {
            "closed" => pull.closed_at.or(Some(now)),
            _ => None,
        };
        new_state.clone_into(&mut pull.state);
    }
    // `draft` is not accepted here, as on GitHub: marking a pull request ready needs GraphQL.
    pull.updated_at = now;
    let (title, text, closed) = (pull.title.clone(), pull.body.clone(), pull.state.clone());
    if let Some(issue) = repo.issues.get_mut(&number) {
        issue.title = title;
        issue.body = text;
        issue.state = closed;
        issue.updated_at = now;
    }
    let repo = &state.repos[full];
    let pull = &repo.pulls[&number];
    Ok(HttpResponse::json(
        200,
        &pull_json(state, repo, pull).expect("a pull request that exists"),
    ))
}

fn merge_pull(
    state: &mut State,
    now: i64,
    request: &HttpRequest,
    token: &TokenRecord,
    full: &str,
    number: &str,
) -> Outcome {
    require(token, "pull_requests", "write")?;
    require(token, "contents", "write")?;
    let number = parse_number(number)?;
    let body = if request.body.is_empty() {
        json!({})
    } else {
        body_json(request)?
    };
    let repo = &state.repos[full];
    let pull = repo.pulls.get(&number).ok_or_else(not_found)?;
    if pull.merged {
        return Err(ApiError::new(405, "Pull Request is not mergeable"));
    }
    if pull.state != "open" {
        return Err(ApiError::new(405, "Pull Request is not mergeable"));
    }
    if pull.draft {
        return Err(ApiError::new(405, "Pull Request is still a draft"));
    }
    // The stale head check. The caller names the commit it reviewed; if the branch has moved,
    // GitHub says so and merges nothing.
    if let Some(expected) = body["sha"].as_str()
        && expected != pull.head_sha
    {
        return Err(ApiError::new(
            409,
            "Head branch was modified. Review and try the merge again.",
        ));
    }
    if let Some(protection) = repo.protection.get(&pull.base_ref) {
        for required in &protection.required_checks {
            let passed = repo.checks.iter().any(|check| {
                check.name == required.context
                    && check.head_sha == pull.head_sha
                    && check.status == "completed"
                    && check.conclusion.as_deref() == Some("success")
                    && required.app_id.is_none_or(|app| app == check.app_id)
            });
            if !passed {
                return Err(ApiError::new(
                    405,
                    &format!(
                        "Required status check \"{}\" is expected.",
                        required.context
                    ),
                ));
            }
        }
        if protection.required_approvals > 0 {
            let approvals = pull
                .reviews
                .iter()
                .filter(|review| review.state == "APPROVED")
                .filter(|review| {
                    !protection.dismiss_stale_reviews || review.commit_id == pull.head_sha
                })
                .filter(|review| review.author != pull.author)
                .filter(|review| state.users.get(&review.author).is_some_and(|u| !u.is_bot))
                .map(|review| review.author.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            if approvals < protection.required_approvals as usize {
                return Err(ApiError::new(
                    405,
                    &format!(
                        "At least {} approving review{} required by reviewers with write access.",
                        protection.required_approvals,
                        if protection.required_approvals == 1 {
                            " is"
                        } else {
                            "s are"
                        }
                    ),
                ));
            }
        }
    }
    let merge_sha = state.new_sha();
    let repo = state.repos.get_mut(full).expect("checked by the caller");
    let pull = repo.pulls.get_mut(&number).expect("checked above");
    pull.merged = true;
    "closed".clone_into(&mut pull.state);
    pull.merge_commit_sha = Some(merge_sha.clone());
    pull.updated_at = now;
    pull.closed_at = Some(now);
    let base = pull.base_ref.clone();
    repo.branches.insert(base, merge_sha.clone());
    if let Some(issue) = repo.issues.get_mut(&number) {
        "closed".clone_into(&mut issue.state);
    }
    Ok(HttpResponse::json(
        200,
        &json!({"sha": merge_sha, "merged": true, "message": "Pull Request successfully merged"}),
    ))
}
