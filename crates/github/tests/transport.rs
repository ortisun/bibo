//! The real HTTP transport against servers on the loopback interface.

use factory_github::{
    ApiBase, MAX_RESPONSE_BYTES, Method, Transport, TransportError, UreqTransport, WireRequest,
};
use factory_testkit::fx::github::FakeGithub;
use factory_testkit::fx::http::{HttpResponse, HttpServer};

fn get(target: &str) -> WireRequest {
    WireRequest {
        method: Method::Get,
        target: target.to_owned(),
        headers: vec![(
            "Accept".to_owned(),
            "application/vnd.github+json".to_owned(),
        )],
        body: Vec::new(),
    }
}

fn transport(url: &str) -> UreqTransport {
    UreqTransport::new(ApiBase::loopback_for_tests(url).expect("a loopback base"))
}

#[tokio::test]
async fn a_request_reaches_the_fake_and_the_answer_comes_back_with_lower_case_header_names() {
    let fake = FakeGithub::new();
    let server = fake.serve().expect("the fake server starts");
    let response = transport(&server.base_url())
        .execute(get("/repos/example-org/none"))
        .await
        .expect("a response");
    assert_eq!(response.status, 401, "a request with no credential");
    assert_eq!(response.header("x-factory-fidelity"), Some("fake"));
    assert!(
        response
            .headers
            .iter()
            .all(|(n, _)| *n == n.to_ascii_lowercase())
    );
    assert_eq!(fake.requests().len(), 1);
}

#[tokio::test]
async fn a_redirect_is_not_followed_so_a_token_cannot_follow_it_to_another_host() {
    let other = HttpServer::start("elsewhere", |_| HttpResponse::text(200, "elsewhere")).unwrap();
    let target = format!("{}/stolen", other.base_url());
    let first =
        HttpServer::start("redirecting", move |_| HttpResponse::redirect(302, &target)).unwrap();
    let response = transport(&first.base_url())
        .execute(get("/anything"))
        .await
        .expect("a response");
    assert_eq!(response.status, 302);
    assert_eq!(
        other.connection_count(),
        0,
        "nothing connected to the other host"
    );
}

#[tokio::test]
async fn a_response_over_the_size_limit_is_refused() {
    let big = vec![b'a'; usize::try_from(MAX_RESPONSE_BYTES).unwrap() + 1024];
    let server = HttpServer::start("big", move |_| {
        HttpResponse::text(200, "x").with_body(big.clone())
    })
    .unwrap();
    let outcome = transport(&server.base_url()).execute(get("/big")).await;
    assert_eq!(outcome, Err(TransportError::Protocol));
}

#[tokio::test]
async fn a_server_that_is_not_there_is_a_connect_error_and_a_path_must_start_with_a_slash() {
    let dead = {
        let server = HttpServer::start("gone", |_| HttpResponse::empty(200)).unwrap();
        server.base_url()
    };
    assert_eq!(
        transport(&dead).execute(get("/x")).await,
        Err(TransportError::Connect)
    );
    assert_eq!(
        transport(&dead).execute(get("no-slash")).await,
        Err(TransportError::Protocol)
    );
}

#[test]
fn an_https_base_cannot_be_built_from_a_plain_http_url() {
    assert!(ApiBase::https("http://127.0.0.1:1").is_err());
}
