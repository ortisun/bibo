//! The OpenAPI document is valid and the router matches it (work package done criterion).
//!
//! The contract is `openapi.json`, written first. `ROUTES` is the list the router is built from.
//! The checks here fail when the two drift, and the last tests show that they do: a document with an
//! operation removed, one with an operation added, and one with a changed security requirement are
//! each caught.

mod support;

use std::collections::BTreeSet;

use factory_api::openapi::{DOCUMENT_TEXT, document, operations};
use factory_api::routes::{Auth, Op, ROUTES, RouteSpec, declared_statuses};
use serde_json::Value;
use support::{Env, Req};

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

fn resolve<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let path = reference.strip_prefix("#/")?;
    path.split('/').try_fold(root, |node, key| node.get(key))
}

fn walk_refs(root: &Value, node: &Value, problems: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "$ref" {
                    match value.as_str() {
                        Some(reference) if resolve(root, reference).is_some() => {}
                        other => problems.push(format!("a reference does not resolve: {other:?}")),
                    }
                } else {
                    walk_refs(root, value, problems);
                }
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| walk_refs(root, item, problems)),
        _ => {}
    }
}

/// The structural rules of OpenAPI 3.0 that matter to a client, checked without a library.
fn problems_in(doc: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    if !doc["openapi"]
        .as_str()
        .is_some_and(|v| v.starts_with("3.0."))
    {
        problems.push("openapi must be a 3.0.x version".to_owned());
    }
    for field in ["title", "version"] {
        if doc["info"][field].as_str().is_none_or(str::is_empty) {
            problems.push(format!("info.{field} is missing"));
        }
    }
    let Some(paths) = doc["paths"].as_object().filter(|paths| !paths.is_empty()) else {
        problems.push("there are no paths".to_owned());
        return problems;
    };
    walk_refs(doc, doc, &mut problems);
    let schemes: BTreeSet<&str> = doc["components"]["securitySchemes"]
        .as_object()
        .map(|schemes| schemes.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let mut ids = BTreeSet::new();
    for (path, item) in paths {
        if !path.starts_with('/') {
            problems.push(format!("{path}: a path starts with /"));
        }
        let templated: BTreeSet<&str> = path
            .split('/')
            .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
            .collect();
        for method in METHODS {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let label = format!("{} {path}", method.to_uppercase());
            match operation["operationId"].as_str() {
                Some(id) if ids.insert(id.to_owned()) => {}
                other => problems.push(format!(
                    "{label}: operationId missing or repeated: {other:?}"
                )),
            }
            if operation["summary"].as_str().is_none_or(str::is_empty) {
                problems.push(format!("{label}: no summary"));
            }
            let Some(responses) = operation["responses"].as_object().filter(|r| !r.is_empty())
            else {
                problems.push(format!("{label}: no responses"));
                continue;
            };
            if !responses.keys().any(|code| code.starts_with('2')) {
                problems.push(format!("{label}: no success response"));
            }
            for code in responses.keys() {
                let well_formed = code == "default"
                    || (code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()));
                if !well_formed {
                    problems.push(format!("{label}: bad status key {code}"));
                }
            }
            for requirement in operation["security"].as_array().into_iter().flatten() {
                for scheme in requirement.as_object().into_iter().flat_map(|r| r.keys()) {
                    if !schemes.contains(scheme.as_str()) {
                        problems.push(format!("{label}: unknown security scheme {scheme}"));
                    }
                }
            }
            if operation.get("security").is_none() {
                problems.push(format!("{label}: security must be stated, [] for none"));
            }
            let mut declared = BTreeSet::new();
            for parameter in operation["parameters"].as_array().into_iter().flatten() {
                let parameter = parameter
                    .get("$ref")
                    .and_then(Value::as_str)
                    .and_then(|r| resolve(doc, r))
                    .unwrap_or(parameter);
                if parameter["in"] == "path" {
                    if parameter["required"] != true {
                        problems.push(format!("{label}: a path parameter is required"));
                    }
                    if let Some(name) = parameter["name"].as_str() {
                        declared.insert(name);
                    }
                }
            }
            if declared != templated {
                problems.push(format!(
                    "{label}: path parameters {declared:?} differ from the template {templated:?}"
                ));
            }
            if let Some(body) = operation.get("requestBody")
                && body["content"]["application/json"]["schema"].is_null()
            {
                problems.push(format!("{label}: a request body needs a JSON schema"));
            }
        }
    }
    problems
}

/// Whether the route table and the document describe the same API.
fn drift(doc: &Value, routes: &[RouteSpec]) -> Vec<String> {
    let mut problems = Vec::new();
    let documented = operations(doc);
    let served: BTreeSet<(String, String)> = routes
        .iter()
        .map(|route| (route.method.to_owned(), route.path.to_owned()))
        .collect();
    for missing in served.difference(&documented) {
        problems.push(format!("served and not documented: {missing:?}"));
    }
    for extra in documented.difference(&served) {
        problems.push(format!("documented and not served: {extra:?}"));
    }
    for route in routes {
        let operation = &doc["paths"][route.path][route.method.to_lowercase()];
        if operation.is_null() {
            continue;
        }
        if operation["operationId"] != route.operation_id {
            problems.push(format!(
                "{} {}: operationId differs",
                route.method, route.path
            ));
        }
        let security: Vec<&str> = operation["security"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|requirement| requirement.as_object().into_iter().flat_map(|r| r.keys()))
            .map(String::as_str)
            .collect();
        let expected: &[&str] = match route.auth {
            Auth::Open => &[],
            Auth::Token => &["bearerToken"],
            Auth::Signature => &["githubSignature"],
        };
        if security != expected {
            problems.push(format!(
                "{} {}: security {security:?}, expected {expected:?}",
                route.method, route.path
            ));
        }
        if route.has_body != operation.get("requestBody").is_some() {
            problems.push(format!(
                "{} {}: the request body differs",
                route.method, route.path
            ));
        }
        for status in declared_statuses(route.op) {
            if operation["responses"].get(status.as_str()).is_none() {
                problems.push(format!(
                    "{} {}: status {status} is not documented",
                    route.method, route.path
                ));
            }
        }
    }
    problems
}

#[test]
fn the_document_is_valid_openapi() {
    let problems = problems_in(document());
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn the_router_and_the_document_describe_the_same_api() {
    let problems = drift(document(), ROUTES);
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn a_drift_between_the_document_and_the_routes_is_caught() {
    // Deliberate breaks: each edit below is a change someone could make to one side only.
    let mut without_operation: Value = serde_json::from_str(DOCUMENT_TEXT).expect("json");
    without_operation["paths"]["/v1/jobs"]
        .as_object_mut()
        .expect("path")
        .remove("post");
    assert!(
        drift(&without_operation, ROUTES)
            .iter()
            .any(|p| p.contains("served and not documented"))
    );

    let mut extra_operation: Value = serde_json::from_str(DOCUMENT_TEXT).expect("json");
    extra_operation["paths"]["/v1/jobs/{job_id}"]["delete"] = serde_json::json!({
        "operationId": "deleteJob", "summary": "x", "security": [], "responses": {"204": {"description": "x"}}
    });
    assert!(
        drift(&extra_operation, ROUTES)
            .iter()
            .any(|p| p.contains("documented and not served"))
    );

    let mut open_by_mistake: Value = serde_json::from_str(DOCUMENT_TEXT).expect("json");
    open_by_mistake["paths"]["/v1/jobs"]["post"]["security"] = serde_json::json!([]);
    assert!(
        drift(&open_by_mistake, ROUTES)
            .iter()
            .any(|p| p.contains("security"))
    );

    let mut renamed: Value = serde_json::from_str(DOCUMENT_TEXT).expect("json");
    renamed["paths"]["/healthz"]["get"]["operationId"] = serde_json::json!("health");
    assert!(
        drift(&renamed, ROUTES)
            .iter()
            .any(|p| p.contains("operationId"))
    );

    let mut dropped_status: Value = serde_json::from_str(DOCUMENT_TEXT).expect("json");
    dropped_status["paths"]["/v1/jobs/{job_id}/decisions"]["post"]["responses"]
        .as_object_mut()
        .expect("responses")
        .remove("202");
    assert!(
        drift(&dropped_status, ROUTES)
            .iter()
            .any(|p| p.contains("status 202"))
    );

    // A route nobody documented.
    let mut routes = ROUTES.to_vec();
    routes.push(RouteSpec {
        method: "GET",
        path: "/v1/secret",
        op: Op::Live,
        operation_id: "secret",
        auth: Auth::Open,
        has_body: false,
    });
    assert!(
        drift(document(), &routes)
            .iter()
            .any(|p| p.contains("/v1/secret"))
    );

    // And the structural checks catch a broken document.
    let mut broken: Value = serde_json::from_str(DOCUMENT_TEXT).expect("json");
    broken["paths"]["/healthz"]["get"]["responses"]["200"] =
        serde_json::json!({"$ref": "#/components/responses/Nope"});
    broken["paths"]["/v1/jobs/{job_id}"]["get"]["parameters"] = serde_json::json!([]);
    let problems = problems_in(&broken);
    assert!(
        problems.iter().any(|p| p.contains("does not resolve")),
        "{problems:?}"
    );
    assert!(
        problems.iter().any(|p| p.contains("path parameters")),
        "{problems:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_documented_operation_is_served_and_nothing_else_is() {
    let env = Env::start().await;
    let id = "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b";
    for route in ROUTES {
        let path = route.path.replace("{job_id}", id);
        // An anonymous request reaches the handler of the route, so it is never the fallback 404.
        let reply = env.send(Req::new(route.method, &path)).await;
        let expected = match route.auth {
            Auth::Open => 200,
            Auth::Token | Auth::Signature => 401,
        };
        assert_eq!(reply.status, expected, "{} {path}", route.method);
        // Every other method on the path is refused.
        for other in ["PUT", "PATCH", "DELETE", "GET", "POST"] {
            if ROUTES
                .iter()
                .any(|r| r.path == route.path && r.method == other)
            {
                continue;
            }
            let reply = env.send(Req::new(other, &path)).await;
            assert_eq!(reply.status, 405, "{other} {path}");
        }
    }
    for path in [
        "/",
        "/v1",
        "/v1/jobs/x/y/z",
        "/admin",
        "/metrics",
        "/debug/pprof",
        "/v1/merge",
        "/v1/deploy",
    ] {
        assert_eq!(env.send(Req::get(path)).await.status, 404, "{path}");
    }
    // The statuses seen above are documented for their operations.
    let served = env.send(Req::get("/openapi.json")).await;
    let on_the_wire: Value = serde_json::from_slice(&served.body).expect("json");
    assert_eq!(&on_the_wire, document(), "the served document is the file");
    assert_eq!(
        on_the_wire,
        serde_json::from_str::<Value>(DOCUMENT_TEXT).expect("json")
    );
    for (path, status) in [
        ("/v1/jobs", "401"),
        ("/v1/jobs/{job_id}", "401"),
        ("/v1/jobs/{job_id}/decisions", "401"),
    ] {
        let method = if path.ends_with("decisions") {
            "post"
        } else {
            "get"
        };
        assert!(
            on_the_wire["paths"][path][method]["responses"]
                .get(status)
                .is_some(),
            "{path}"
        );
    }
    env.stop().await;
}
