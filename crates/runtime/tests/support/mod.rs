//! Shared helpers for the runtime tests: a harness with the artifact store, the redactor and the
//! run IO; requests; the recorded help texts; and the two kinds of sandbox session, a scripted
//! stand-in and a real hardened container.
//!
//! Compiled into each test target with `mod support;`, so a target uses only part of it.
#![allow(dead_code)]

pub mod attest;
pub mod docker;
pub mod hostile;
pub mod scripted;
pub mod telemetry;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::TenantId;
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, NonEmptyString, Uri};
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AgentLimits, AgentRunReport, AgentRunRequest, AssembledPrompt, FlagSet, ModelSelection,
    RuntimeId,
};
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore};
use factory_ports::sandbox::ImageDigest;
use factory_runtime::RunIo;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::fixtures::{Ids, agent_run_request};

/// The image catalog the image build wrote.
pub const IMAGES_JSON: &str = include_str!("../../../../infra/sandbox-images/images.json");

/// The platform of the development machine's daemon.
pub const PLATFORM: &str = "linux/arm64";

/// The recorded outputs of the spike: the help texts and version lines of the pinned tools.
pub mod recorded {
    pub const CLAUDE_VERSION: &str =
        include_str!("../../../../fixtures/recordings/agent-cli/runs/claude-version/stdout.txt");
    pub const CLAUDE_HELP: &str =
        include_str!("../../../../fixtures/recordings/agent-cli/runs/claude-help/stdout.txt");
    pub const CODEX_VERSION: &str =
        include_str!("../../../../fixtures/recordings/agent-cli/runs/codex-version/stdout.txt");
    pub const CODEX_EXEC_HELP: &str =
        include_str!("../../../../fixtures/recordings/agent-cli/runs/codex-exec-help/stdout.txt");
    pub const CODEX_FEATURES: &str = include_str!(
        "../../../../fixtures/recordings/agent-cli/runs/codex-features-list/stdout.txt"
    );

    /// The standard output the spike recorded for one case (a directory under `runs/`).
    ///
    /// # Panics
    /// When the case is not in the recordings.
    pub fn stdout(case: &str) -> String {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/recordings/agent-cli/runs")
            .join(case)
            .join("stdout.txt");
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }
}

/// The agent image of the catalog, by digest.
///
/// # Panics
/// When the catalog has no agent image.
pub fn agent_image() -> ImageDigest {
    let root: serde_json::Value = serde_json::from_str(IMAGES_JSON).expect("images.json");
    let reference = root["platforms"][PLATFORM]["images"]["agent"]["reference"]
        .as_str()
        .expect("an agent image reference");
    ImageDigest::parse(reference).expect("a digest-pinned reference")
}

/// A store that lets the tenant read whatever is put into it. The composition root must do the
/// same for the sandbox's output artifacts: they carry no tenant of their own.
pub struct GrantingStore {
    inner: InMemoryArtifactStore,
    tenant: TenantId,
}

impl GrantingStore {
    pub fn new(tenant: TenantId) -> Self {
        Self {
            inner: InMemoryArtifactStore::new(),
            tenant,
        }
    }

    pub fn tenant(&self) -> TenantId {
        self.tenant
    }
}

#[async_trait]
impl ArtifactStore for GrantingStore {
    fn backend(&self) -> ArtifactBackend {
        self.inner.backend()
    }

    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: MediaType,
    ) -> Result<ArtifactRef, ArtifactError> {
        let reference = self.inner.put(bytes, media_type).await?;
        self.inner.grant(self.tenant, &reference.sha256);
        Ok(reference)
    }

    async fn get(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<Vec<u8>, ArtifactError> {
        self.inner.get(scope, reference).await
    }

    async fn exists(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<bool, ArtifactError> {
        self.inner.exists(scope, reference).await
    }
}

/// The store, the tenant, the redactor and the run IO of one test.
pub struct Harness {
    pub store: Arc<GrantingStore>,
    pub scope: TenantScope,
    pub redactor: Arc<Redactor>,
    pub io: RunIo,
    pub ids: Ids,
}

impl Harness {
    pub fn new() -> Self {
        let ids = Ids::new();
        let tenant = ids.tenant();
        let store = Arc::new(GrantingStore::new(tenant));
        let scope = TenantScope::new(tenant);
        let redactor = Arc::new(Redactor::builder().build().expect("a redactor"));
        let io = RunIo::new(store.clone(), scope, redactor.clone());
        Self {
            store,
            scope,
            redactor,
            io,
            ids,
        }
    }

    /// The model broker's record for a test that is about something other than the attestation: a
    /// broker that saw a long run end well, so that it attests whatever the stream says.
    pub fn attestation(&self) -> Arc<dyn factory_ports::agent::TurnAttestation> {
        Arc::new(attest::ScriptedAttestation::generous())
    }

    /// Makes `value` a secret the redactor finds, as the composition root does for a job token.
    pub fn register_secret(&self, label: &str, value: &str) {
        self.redactor
            .register(label, value)
            .expect("a registrable secret");
    }

    /// Reads a stored artifact back as text.
    pub async fn text_of(&self, reference: &ArtifactRef) -> String {
        let bytes = self
            .store
            .get(&self.scope, reference)
            .await
            .expect("a stored artifact");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// The text of the report's transcript.
    pub async fn transcript_of(&self, report: &AgentRunReport) -> String {
        let reference = report
            .transcript
            .as_ref()
            .expect("the report has a transcript");
        self.text_of(reference).await
    }
}

/// Limits for a run, from plain numbers.
pub fn limits(wall_seconds: u32, cost_usd: f64, tool_calls: u32) -> AgentLimits {
    serde_json::from_value(serde_json::json!({
        "max_wall_time_seconds": wall_seconds,
        "max_tokens": 400_000,
        "max_cost_usd": cost_usd,
        "max_tool_calls": tool_calls,
        "max_delegation_depth": 0
    }))
    .expect("valid limits")
}

/// A well-formed request for `runtime` and `model`, with the broker at `broker`.
pub fn request(h: &Harness, runtime: &str, model: &str, broker: &str) -> AgentRunRequest {
    let mut req = agent_run_request(&h.ids);
    req.model = ModelSelection {
        runtime: RuntimeId::new(runtime).expect("a runtime id"),
        model: NonEmptyString::parse(model).expect("a model name"),
    };
    req.broker.base_url = Uri::parse(broker).expect("a broker address");
    req.limits = limits(120, 5.0, 20);
    req.prompt = AssembledPrompt {
        instructions: "Do the planned task.".to_owned(),
        data: Vec::new(),
    };
    req.flag_set = FlagSet::Standard;
    req
}

/// The JSON events of a transcript or a tool's standard output, one per line.
pub fn events_of(text: &str) -> Vec<serde_json::Value> {
    text.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// The `system/init` event of a Claude Code transcript.
///
/// # Panics
/// When the transcript has none.
pub fn init_of(text: &str) -> serde_json::Value {
    events_of(text)
        .into_iter()
        .find(|e| e["type"] == "system" && e["subtype"] == "init")
        .expect("an init event")
}

/// The text of every `tool_result` in a Claude Code transcript.
pub fn tool_results_of(text: &str) -> Vec<String> {
    events_of(text)
        .iter()
        .filter(|e| e["type"] == "user")
        .filter_map(|e| e["message"]["content"].as_array().cloned())
        .flatten()
        .filter(|part| part["type"] == "tool_result")
        .map(|part| match &part["content"] {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .collect()
}

/// A secret-shaped value made at run time, so that no literal sits in the source.
pub fn runtime_secret(tag: &str) -> String {
    let mut bytes = [0_u8; 16];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = file.read_exact(&mut bytes);
    } else {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        bytes.copy_from_slice(&nanos.to_le_bytes());
    }
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}_{tag}{hex}", "sfjt")
}
