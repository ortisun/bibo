//! The contract suite for the `ModelRouter` port: a pure, deterministic choice with a closed set
//! of ways to say no.

use std::future::Future;

use async_trait::async_trait;
use factory_ports::agent::{Capability, FlagSet, ModelRouter, RoutingError, RoutingNeed};

use super::{Check, Context, Report, check_list, ensure, ensure_eq, ensure_err, run_checks, skip};

/// What the suite needs beyond the `ModelRouter` port itself.
#[async_trait]
pub trait RouterSubject: Send + Sync {
    /// The router under test.
    fn router(&self) -> &dyn ModelRouter;

    /// Needs the router can answer. They must include one for the specification stage and one for
    /// another stage.
    fn routable_needs(&self) -> Vec<RoutingNeed>;

    /// A need the routing policy has no entry for.
    fn unroutable_need(&self) -> RoutingNeed;

    /// A need that names a capability no candidate has, with that capability. `None` when the
    /// subject cannot make one.
    fn need_with_an_unavailable_capability(&self) -> Option<(RoutingNeed, Capability)>;
}

/// A check of the router contract.
pub type RouterCheck = Check<dyn RouterSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: RouterSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn RouterSubject>
    })
    .await
}

/// Every check of the router contract.
#[must_use]
pub fn checks() -> Vec<RouterCheck> {
    check_list![dyn RouterSubject;
        the_same_need_always_gets_the_same_decision,
        the_flag_set_follows_the_stage,
        a_need_with_no_entry_has_no_route,
        a_missing_capability_is_reported_by_name,
    ]
}

async fn the_same_need_always_gets_the_same_decision(
    subject: &dyn RouterSubject,
) -> Result<(), String> {
    let needs = subject.routable_needs();
    ensure!(!needs.is_empty(), "the subject offered no routable need");
    for need in needs {
        let first = subject.router().route(&need).ctx("first route")?;
        for _ in 0..10 {
            let again = subject.router().route(&need).ctx("repeat route")?;
            ensure_eq!(
                again,
                first.clone(),
                "a repeated decision for {:?}",
                need.stage
            );
        }
    }
    Ok(())
}

async fn the_flag_set_follows_the_stage(subject: &dyn RouterSubject) -> Result<(), String> {
    let needs = subject.routable_needs();
    ensure!(
        needs
            .iter()
            .any(|n| FlagSet::for_stage(n.stage) == FlagSet::Specification)
            && needs
                .iter()
                .any(|n| FlagSet::for_stage(n.stage) == FlagSet::Standard),
        "the subject must offer a specification need and a need for another stage"
    );
    for need in needs {
        let decision = subject.router().route(&need).ctx("route")?;
        ensure_eq!(
            decision.flag_set,
            FlagSet::for_stage(need.stage),
            "the flag set for the {} stage",
            need.stage
        );
    }
    Ok(())
}

async fn a_need_with_no_entry_has_no_route(subject: &dyn RouterSubject) -> Result<(), String> {
    ensure_err!(
        subject.router().route(&subject.unroutable_need()),
        RoutingError::NoRoute,
        "a need the routing policy does not cover"
    );
    Ok(())
}

async fn a_missing_capability_is_reported_by_name(
    subject: &dyn RouterSubject,
) -> Result<(), String> {
    let Some((need, capability)) = subject.need_with_an_unavailable_capability() else {
        skip!("this subject cannot make a need with an unavailable capability");
    };
    ensure_eq!(
        subject.router().route(&need).err(),
        Some(RoutingError::CapabilityUnavailable(capability)),
        "a need that requires a capability no candidate has"
    );
    Ok(())
}
