//! One runtime that serves every tenant: each call reaches the runtime of the tenant that owns the
//! attempt, a tenant's runtime is made once, and an attempt nobody claimed is refused.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_composition::indexing::ActiveJobs;
use factory_composition::runtimes::TenantRuntimes;
use factory_domain::ids::{AttemptId, TenantId};
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, ProbeError, RuntimeCapabilities,
    RuntimeId, Usage,
};
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{SandboxProfile, SandboxProvider, SandboxSession};
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::clock::{FakeCancel, FakeClock};
use factory_testkit::fixtures::{Ids, sandbox_policy, sandbox_spec};
use factory_testkit::router::probe_of;
use factory_testkit::sandbox::FakeSandbox;

fn tenant(n: u128) -> TenantId {
    TenantId::from_uuid(uuid::Uuid::from_u128(n))
}

fn attempt(n: u128) -> AttemptId {
    AttemptId::from_uuid(uuid::Uuid::from_u128(n))
}

/// A runtime that remembers which tenant it was made for and answers with it.
struct ForTenant {
    id: RuntimeId,
    tenant: TenantId,
    calls: Arc<Mutex<Vec<TenantId>>>,
}

#[async_trait]
impl AgentRuntime for ForTenant {
    fn id(&self) -> &RuntimeId {
        &self.id
    }

    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn probe(&self, _: &mut dyn SandboxSession) -> Result<RuntimeCapabilities, ProbeError> {
        self.calls.lock().expect("lock").push(self.tenant);
        Ok(probe_of(&[]))
    }

    async fn run(
        &self,
        _: &mut dyn SandboxSession,
        _: AgentRunRequest,
        _: &dyn CancelSignal,
    ) -> AgentRunReport {
        self.calls.lock().expect("lock").push(self.tenant);
        AgentRunReport {
            outcome: Err(AgentRunError::OutputMissing),
            transcript: None,
            usage: Usage::default(),
            runtime_version: None,
            exit: None,
            permission_denials: Vec::new(),
        }
    }
}

async fn session() -> Box<dyn SandboxSession> {
    let clock = Arc::new(FakeClock::new());
    let sandbox = FakeSandbox::new(
        clock,
        Arc::new(InMemoryArtifactStore::new()),
        sandbox_policy(),
    );
    sandbox
        .create_verified(
            sandbox_spec(&Ids::new(), SandboxProfile::Verify),
            &FakeCancel::new(),
        )
        .await
        .expect("a session")
}

#[tokio::test]
async fn a_probe_and_a_run_reach_the_runtime_of_the_tenant_that_owns_the_attempt() {
    let jobs = Arc::new(ActiveJobs::new());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let made = Arc::new(Mutex::new(Vec::new()));
    let runtimes = TenantRuntimes::new(
        RuntimeId::new("fake").expect("a runtime"),
        Fidelity::Fake,
        jobs.clone(),
        {
            let (calls, made) = (calls.clone(), made.clone());
            Box::new(move |tenant| {
                made.lock().expect("lock").push(tenant);
                Some(Arc::new(ForTenant {
                    id: RuntimeId::new("fake").expect("a runtime"),
                    tenant,
                    calls: calls.clone(),
                }) as Arc<dyn AgentRuntime>)
            })
        },
    );
    let mut session = session().await;

    // One attempt of tenant 1 is running: the probe has an unambiguous tenant.
    jobs.enter_attempt(attempt(1), tenant(1));
    runtimes.probe(&mut *session).await.expect("probed");
    // A run is routed by the attempt it is asked about.
    jobs.enter_attempt(attempt(2), tenant(2));
    let request = run_request(attempt(2));
    let report = runtimes
        .run(&mut *session, request, &FakeCancel::new())
        .await;
    assert_eq!(report.outcome, Err(AgentRunError::OutputMissing));
    assert_eq!(
        *calls.lock().expect("lock"),
        vec![tenant(1), tenant(2)],
        "each call reached the runtime of its own tenant"
    );

    // With two tenants running, a probe has no attempt to ask about and refuses to guess.
    assert!(runtimes.probe(&mut *session).await.is_err());
    // A tenant's runtime is made once.
    let again = run_request(attempt(1));
    runtimes.run(&mut *session, again, &FakeCancel::new()).await;
    assert_eq!(made.lock().expect("lock").len(), 2);
    assert_eq!(runtimes.made(), 2);
}

#[tokio::test]
async fn an_attempt_nobody_claimed_is_refused_and_no_runtime_is_made_for_it() {
    let jobs = Arc::new(ActiveJobs::new());
    let runtimes = TenantRuntimes::new(
        RuntimeId::new("fake").expect("a runtime"),
        Fidelity::Fake,
        jobs,
        Box::new(|_| panic!("no runtime may be made for an unknown attempt")),
    );
    let mut session = session().await;
    let report = runtimes
        .run(&mut *session, run_request(attempt(9)), &FakeCancel::new())
        .await;
    assert_eq!(report.outcome, Err(AgentRunError::AuthenticationRequired));
    assert!(runtimes.probe(&mut *session).await.is_err());
    assert_eq!(runtimes.made(), 0);
}

/// A request is a large value; the testkit's fixture with the attempt the dispatcher reads.
fn run_request(attempt: AttemptId) -> AgentRunRequest {
    AgentRunRequest {
        attempt,
        ..factory_testkit::fixtures::agent_run_request(&Ids::new())
    }
}
