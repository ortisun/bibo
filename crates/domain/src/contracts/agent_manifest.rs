//! `schemas/agent-manifest.schema.json`: the declaration of one specialist agent.
//!
//! There are no prompt-only agents with open shell or production access. Every agent names its
//! tools, its limits and its output schema. An agent that can write files or run commands can
//! only run inside a sandbox. The deterministic policy engine, not the agent, decides which
//! declared tools are actually granted for a given stage.

use serde::{Deserialize, Serialize};

use super::common::{
    NetworkMode, ProductionAccessNone, SchemaRef, SchemaVersion, ShellMode, VersionedRef,
};
use super::{Violations, contract};
use crate::macros::string_enum;
use crate::values::{
    Bounded, HumanText, HumanTitle, NonEmptyString, NonEmptyVec, NonNegativeInt, PositiveFraction,
    PositiveInt, PositiveNumber, SemanticVersion, Sha256Digest, Slug, UniqueVec,
};

string_enum! {
    /// What a tool may do.
    pub enum ToolAccess("tool access") {
        /// Read only.
        Read = "read",
        /// Write files.
        Write = "write",
        /// Run commands, inside the sandbox only.
        ExecuteSandboxed = "execute_sandboxed",
    }
}

string_enum! {
    /// How an agent may use secrets.
    pub enum SecretsMode("secrets mode") {
        /// No secrets.
        None = "none",
        /// Narrow, short-lived secrets.
        ScopedShortLived = "scoped_short_lived",
    }
}

string_enum! {
    /// Where the agent runtime may run an agent. There is no value for the host itself.
    pub enum AgentPlacement("agent placement") {
        /// Inside the hardened sandbox container.
        Sandbox = "sandbox",
        /// On the host with built-in tools disabled, acting through factory tools. The hardening
        /// target, kept off by policy in Slice 1.
        HostToolBridge = "host_tool_bridge",
    }
}

string_enum! {
    /// How capable a recommended model is.
    pub enum RecommendedTier("model tier") {
        /// Small.
        Small = "small",
        /// Standard.
        Standard = "standard",
        /// Large.
        Large = "large",
    }
}

/// One tool the agent may be granted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedTool {
    /// The tool.
    pub name: Slug,
    /// What it may do.
    pub access: ToolAccess,
    /// Path globs the tool may touch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_scope: Option<Vec<NonEmptyString>>,
}

/// Limits on one run of the agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Wall-clock seconds, 1 to 14400.
    pub max_wall_time_seconds: Bounded<1, 14400>,
    /// Model tokens.
    pub max_tokens: PositiveInt,
    /// US dollars, above 0.
    pub max_cost_usd: PositiveNumber,
    /// Tool calls.
    pub max_tool_calls: NonNegativeInt,
    /// How deep delegation may go, 0 to 3.
    pub max_delegation_depth: Bounded<0, 3>,
}

/// File access.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemAccess {
    /// Path globs the agent may read.
    pub read: Vec<NonEmptyString>,
    /// Path globs the agent may write.
    pub write: Vec<NonEmptyString>,
}

/// What the agent may do. No value allows production access or an unrestricted shell.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPermissions {
    /// Files.
    pub filesystem: FilesystemAccess,
    /// Network.
    pub network: NetworkMode,
    /// Hosts, when the network is an allow list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_allowlist: Option<Vec<NonEmptyString>>,
    /// Commands.
    pub shell: ShellMode,
    /// Always `none`.
    pub production_access: ProductionAccessNone,
    /// Secrets.
    pub secrets: SecretsMode,
}

/// A model the agent works well with.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecommendedModel {
    /// The runtime.
    pub runtime_id: Slug,
    /// The model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<NonEmptyString>,
    /// How capable.
    pub tier: RecommendedTier,
    /// Notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<HumanText>,
}

/// The evaluation suite the agent must pass.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvaluationSuite {
    /// The suite.
    pub id: Slug,
    /// Its version.
    pub version: SemanticVersion,
    /// The pass rate it must reach, above 0 and at most 1.
    pub min_pass_rate: PositiveFraction,
}

/// The agent's prompt template.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptTemplate {
    /// Where it is stored.
    pub template_path: NonEmptyString,
    /// Its version.
    pub template_version: SemanticVersion,
    /// Its hash.
    pub template_sha256: Sha256Digest,
}

/// The declaration of one specialist agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, remote = "Self")]
pub struct AgentManifest {
    /// Always 1.
    pub schema_version: SchemaVersion,
    /// The agent.
    pub id: Slug,
    /// Its version.
    pub version: SemanticVersion,
    /// A plain-English title.
    pub title: HumanTitle,
    /// What the agent does.
    pub description: HumanText,
    /// A role such as architect or builder. Roles are open-ended so new domains can add their own.
    pub role: Slug,
    /// The domains it works in.
    pub domains: UniqueVec<Slug, 1>,
    /// Its skills.
    pub skills: UniqueVec<VersionedRef>,
    /// The tools it may be granted.
    pub allowed_tools: NonEmptyVec<AllowedTool>,
    /// The evidence it must leave behind.
    pub required_evidence: Vec<Slug>,
    /// The schema of its input.
    pub inputs_schema: SchemaRef,
    /// The schema of its output.
    pub outputs_schema: SchemaRef,
    /// Its limits.
    pub resource_limits: ResourceLimits,
    /// What it may do.
    pub permissions: AgentPermissions,
    /// Where it may run.
    pub permitted_placements: UniqueVec<AgentPlacement, 1>,
    /// Models it works well with.
    pub recommended_models: NonEmptyVec<RecommendedModel>,
    /// The suite that evaluates it.
    pub evaluation_suite: EvaluationSuite,
    /// Its prompt.
    pub prompt: PromptTemplate,
}

impl AgentManifest {
    fn check(&self, found: &mut Violations) {
        let permissions = &self.permissions;
        if permissions.network == NetworkMode::Allowlist {
            found.require(
                permissions
                    .network_allowlist
                    .as_ref()
                    .is_some_and(|hosts| !hosts.is_empty()),
                "permissions.network_allowlist",
                "a network allow list needs at least one host",
            );
        }

        let can_execute = self
            .allowed_tools
            .iter()
            .any(|tool| tool.access == ToolAccess::ExecuteSandboxed);
        if can_execute {
            found.require(
                permissions.shell == ShellMode::SandboxedTypedWrapper,
                "permissions.shell",
                "an agent with a tool that executes commands must use the sandboxed typed wrapper",
            );
        }

        let read_only = self
            .allowed_tools
            .iter()
            .all(|tool| tool.access == ToolAccess::Read);
        if read_only {
            found.require(
                permissions.shell == ShellMode::None,
                "permissions.shell",
                "an agent whose tools are all read-only has no shell",
            );
            found.require(
                permissions.filesystem.write.is_empty(),
                "permissions.filesystem.write",
                "an agent whose tools are all read-only may write no files",
            );
        }
    }
}

contract!(AgentManifest, "agent-manifest");
