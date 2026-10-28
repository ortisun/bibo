//! The control of `the_pool_resets_a_session_level_tenant_when_a_connection_is_reused` in
//! `tenant_isolation.rs`: a pool built without the reset hands the next borrower the tenant of a
//! session-level `SET`. This is why the pool resets the setting when a connection is reused
//! (`docs/database/for-the-storage-crate.md`, step 6).

mod support;

use diesel::sql_query;
use diesel_async::pooled_connection::RecyclingMethod;
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use factory_storage::pg::PgPool;
use support::{Scene, config_for};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pool_without_the_reset_would_leak_the_tenant() {
    let scene = Scene::new().await;
    let mut one = config_for(&scene.db).await.tenant;
    one.max_connections = 1;
    let weak = PgPool::with_recycling("tenant", &one, RecyclingMethod::Fast).expect("pool");
    {
        let mut poisoned = weak.raw_connection_for_tests().await.expect("connection");
        poisoned
            .batch_execute(&format!("SET factory.tenant_id = '{}'", scene.a.as_uuid()))
            .await
            .expect("session-level set");
    }
    let mut next = weak
        .raw_connection_for_tests()
        .await
        .expect("the same connection");
    let seen =
        sql_query("SELECT coalesce(current_setting('factory.tenant_id', true), '<null>') AS v")
            .get_result::<support::server::Scalar>(&mut *next)
            .await
            .expect("read");
    assert_eq!(
        seen.v,
        scene.a.as_uuid().to_string(),
        "without the reset the next borrower inherits the tenant"
    );
}
