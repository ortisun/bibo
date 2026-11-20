// Scenarios that need a store built to break a rule of the contract. A real database cannot be
// made to lie, so these run on the in-memory store only, and the PostgreSQL runner does not
// include this file.

#[tokio::test]
async fn a_commit_the_store_cannot_confirm_is_never_reported_as_a_success() {
    // The store loses the answer and then says the witness is not stored. The engine must not
    // call that a success: the call fails with an error that can be repeated, and the caller
    // reads the state before it acts again. The defect makes `committed` answer "no" always.
    let world = World::with_store_defect(factory_testkit::store::StoreDefect::LosesWitness).await;
    let job = world
        .engine
        .receive_job(world.tenant, world.requester, world.repository)
        .await
        .expect("receive");
    world.backend.lose_next_commit_answer().await;
    let refused = world.engine.admit_job(world.tenant, job).await;
    let Err(error) = refused else {
        panic!("an unconfirmed commit was reported as a success: {refused:?}");
    };
    assert!(error.is_retryable(), "{error:?}");
}
