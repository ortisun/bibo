//! `GET /v1/process-metrics/snapshot` through the real server on a loopback port and a real
//! PostgreSQL: who may ask, what a window that cannot be read is answered with, that a build which
//! does not know its commit hands out nothing, and the entry itself.
//!
//! The database needs a PostgreSQL server (`docs/database/running.md`); a test that cannot get one
//! panics with `BLOCKED:` and is never a pass.

mod support;

use factory_api::auth::Caller;
use factory_api::process_metrics::{build_commit, snapshot};
use factory_domain::values::GitSha;
use factory_domain::vocabulary::HumanRole;
use serde_json::json;
use support::{Env, Req};

const WEEK: &str = "/v1/process-metrics/snapshot?from=2026-11-16T00:00:00Z&to=2026-11-23T00:00:00Z";

macro_rules! env_test {
    ($name:ident, |$env:ident| $body:block) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            let $env = Env::start().await;
            $body
            $env.stop().await;
        }
    };
}

env_test!(only_a_listed_person_with_a_token_may_ask, |env| {
    let anonymous = env.send(Req::get(WEEK)).await;
    assert_eq!(anonymous.status, 401);
    let outsider = env.send(Req::get(WEEK).bearer(&env.a.outsider.token)).await;
    assert_eq!(outsider.status, 403);
    // Every designation may read: the answer holds only totals of the caller's own tenant.
    for person in [&env.a.requester, &env.a.approver, &env.a.operator] {
        let reply = env.send(Req::get(WEEK).bearer(&person.token)).await;
        // The test build knows its commit only when the person who built it set it.
        let expected = if build_commit().is_some() { 200 } else { 503 };
        assert_eq!(reply.status, expected, "{}: {}", person.login, reply.text());
    }
});

env_test!(
    a_window_that_cannot_be_read_is_a_400_that_names_the_field,
    |env| {
        let cases = [
            ("/v1/process-metrics/snapshot", "from"),
            (
                "/v1/process-metrics/snapshot?from=2026-11-16T00:00:00Z",
                "to",
            ),
            (
                "/v1/process-metrics/snapshot?from=soon&to=2026-11-23T00:00:00Z",
                "from",
            ),
            (
                "/v1/process-metrics/snapshot?from=2026-11-23T00:00:00Z&to=2026-11-16T00:00:00Z",
                "to",
            ),
            (
                "/v1/process-metrics/snapshot?from=2024-01-01T00:00:00Z&to=2026-01-01T00:00:00Z",
                "to",
            ),
            (
                "/v1/process-metrics/snapshot?from=2026-11-16T00:00:00Z&to=2026-11-23T00:00:00Z&x=1",
                "query",
            ),
        ];
        for (path, field) in cases {
            let reply = env
                .send(Req::get(path).bearer(&env.a.requester.token))
                .await;
            assert_eq!(
                (reply.status, reply.json()["field"].clone()),
                (400, json!(field)),
                "{path}"
            );
        }
    }
);

env_test!(
    the_entry_of_a_tenant_names_its_window_and_the_commit_that_computed_it,
    |env| {
        let caller = Caller {
            tenant: env.a.id,
            principal: env.a.requester.principal,
            github_user_id: Some(env.a.requester.github_id),
            roles: vec![HumanRole::Requester],
        };
        let query = Some("from=2026-11-16T00:00:00Z&to=2026-11-23T00:00:00Z");
        let commit = GitSha::parse("3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d").expect("valid");

        // A build that does not know its commit hands out nothing, whoever asks.
        let unknown = snapshot(&env.state, &caller, query, None).await;
        assert_eq!(
            unknown.err(),
            Some(factory_api::answers::ApiError::Unavailable)
        );

        let reply = snapshot(&env.state, &caller, query, Some(commit))
            .await
            .expect("a snapshot");
        let body = reply.body;
        assert_eq!(body["id"], "M-2026-W47");
        assert_eq!(body["path"], "measurements/M-2026-W47.md");
        assert_eq!(body["query_version"], 1);
        assert_eq!(
            body["computed_at_commit"],
            "3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d"
        );
        assert_eq!(
            body["window"],
            json!({"from": "2026-11-16T00:00:00Z", "to": "2026-11-23T00:00:00Z"})
        );
        let entry = body["entry"].as_str().expect("the entry is text");
        assert!(
            entry.starts_with("---\nid: M-2026-W47\nkind: measurement\n"),
            "{entry}"
        );
        // The tenant has no job: every stored metric has too few samples, and both windows exist.
        for row in [
            "| MT-0001 lead-time-to-pull-request, median | too few samples | 0 | too few samples |",
            "| MT-0007 rework-rounds | too few samples | 0 | too few samples |",
            "| MT-0012 cost-per-accepted-pull-request | not measured yet | | not measured yet |",
        ] {
            assert!(entry.contains(row), "missing row: {row}\n{entry}");
        }
        // Nothing was written: the handler only reads.
        assert_eq!(env.db.number("SELECT count(*) FROM jobs").await, 0);

        // A person who is not on the allowlist is refused before anything is read.
        let nobody = Caller {
            roles: vec![],
            ..caller
        };
        assert_eq!(
            snapshot(&env.state, &nobody, query, None).await.err(),
            Some(factory_api::answers::ApiError::Forbidden)
        );
    }
);
