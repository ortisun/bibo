//! `policies/security.yaml` as typed values.
//!
//! The structs follow the file section by section. Every one rejects unknown keys. A field that
//! the file may leave out is an `Option`; every other field is required, so a missing key is an
//! error. Text whose set of values the file states as an `enum` is a closed Rust enum. Text that is
//! an open vocabulary of identifiers (profile names, role names, tool names) stays `String`, and
//! `check.rs` verifies that the references between them point at something.
//!
//! The pure evaluation of these values (which tool is granted, which path is protected) belongs to
//! `s1-policy-evaluation`. This module only reads and validates the document.

use std::collections::BTreeMap;

use super::common::{
    ConfigSource, ConflictResolution, GlobText, PolicyStatus, ProjectOverrides, RegexText,
    SchemaVersionOne, ThreatId, closed_set, strict,
};

strict! {
    /// The whole of `policies/security.yaml`.
    pub struct SecurityPolicy {
        /// Always 1.
        pub schema_version: SchemaVersionOne,
        /// Identity and global rules.
        pub policy: SecurityHeader,
        /// How paths are compared.
        pub matching: PathMatching,
        /// Paths a builder cannot change.
        pub protected_paths: ProtectedPaths,
        /// Where file tools may write.
        pub path_access: PathAccess,
        /// Commands that are refused.
        pub forbidden_command_classes: Vec<ForbiddenCommandClass>,
        /// The tool allow list.
        pub tools: Tools,
        /// The commands agents may run.
        pub command_sets: CommandSets,
        /// Container requirements.
        pub sandbox: Sandbox,
        /// Network egress.
        pub egress: Egress,
        /// Secret patterns and redaction.
        pub secrets: Secrets,
        /// Credential handling.
        pub credentials: Credentials,
        /// Webhook intake.
        pub webhook: Webhook,
        /// Spend and loop limits.
        pub budgets: Budgets,
        /// Gate integrity.
        pub gate_integrity: GateIntegrity,
        /// Untrusted content and agent runtime hardening.
        pub untrusted_content: UntrustedContent,
        /// Per-stage skill profiles.
        pub agent_stage_profiles: AgentStageProfiles,
        /// Text the factory writes to GitHub.
        pub output_hygiene: OutputHygiene,
        /// Supply chain.
        pub supply_chain: SupplyChain,
        /// Tenancy.
        pub tenancy: Tenancy,
        /// Audit.
        pub audit: Audit,
    }
}

closed_set! {
    /// What a request with no matching rule gets in the security policy. The only value is deny.
    pub enum DenyByDefault {
        /// Refuse.
        Deny,
    }
}

strict! {
    /// Identity and global rules of the security policy.
    pub struct SecurityHeader {
        /// Always `security`.
        pub id: String,
        /// The policy version.
        pub version: u32,
        /// Designed or enforced.
        pub status: PolicyStatus,
        /// What a request with no matching rule gets. Required, and only `deny` is valid.
        pub default_action: DenyByDefault,
        /// How rules combine.
        pub conflict_resolution: ConflictResolution,
        /// What a project policy may do.
        pub project_overrides: ProjectOverrides,
        /// Where the file must be read from.
        pub config_source: ConfigSource,
        /// Threats the header answers.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// Section 1: how paths are compared.
    pub struct PathMatching {
        /// The Unicode normalization form.
        pub normalization: String,
        /// Whether matching ignores case.
        pub case_insensitive: bool,
        /// Whether `..` segments are rejected.
        pub reject_dotdot: bool,
        /// Whether absolute paths are rejected.
        pub reject_absolute: bool,
        /// Whether NUL and backslash are rejected.
        pub reject_nul_and_backslash: bool,
        /// What the decision is taken on.
        pub evaluate_on: String,
        /// Whether a rename counts as two paths.
        pub count_rename_source_and_destination: bool,
        /// Whether a mode or type change counts as a modification.
        pub mode_and_type_changes_are_modifications: bool,
        /// Whether a `.git` component is rejected.
        pub reject_dot_git_components: bool,
        /// Whether gitlinks are rejected.
        pub reject_gitlinks: bool,
        /// What happens to a symlink.
        pub symlinks: String,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

closed_set! {
    /// How a protected group restricts a change. The most restrictive mode wins when several
    /// groups match one path: hidden, then deny_write, append_only and additions_only.
    pub enum ProtectionMode {
        /// Not in the checkout at all.
        Hidden,
        /// Any add, modify, delete, rename or mode change blocks the job.
        DenyWrite,
        /// New files are allowed, existing ones may not change.
        AppendOnly,
        /// New files are allowed and an existing file may only gain lines.
        AdditionsOnly,
    }
}

closed_set! {
    /// Which repository a rule applies to.
    pub enum AppliesTo {
        /// The repository the factory works on.
        TargetRepo,
        /// The factory's own repository.
        FactoryRepo,
        /// Both.
        Both,
    }
}

strict! {
    /// One group of protected paths.
    pub struct ProtectedGroup {
        /// The group.
        pub id: String,
        /// How it restricts a change.
        pub mode: ProtectionMode,
        /// Which repository.
        pub applies_to: AppliesTo,
        /// The globs. A leading `!` re-includes, and the loader applies it last.
        pub globs: Vec<GlobText>,
        /// Why the group exists.
        pub reason: String,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// Paths that may change, but only with extra checks and an extra reviewer.
    pub struct SensitiveFiles {
        /// The group.
        pub id: String,
        /// The globs.
        pub globs: Vec<GlobText>,
        /// Ids of `gate_integrity.semantic_checks`.
        pub checks: Vec<String>,
        /// Extra reviewers.
        pub extra_review: Vec<String>,
        /// Which repository, when not both.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub applies_to: Option<AppliesTo>,
    }
}

strict! {
    /// Section 2: protected paths.
    pub struct ProtectedPaths {
        /// What must hold before a change to a protected path is accepted.
        pub default_change_requires: Vec<String>,
        /// The protected groups.
        pub groups: Vec<ProtectedGroup>,
        /// The sensitive files.
        pub sensitive_files: Vec<SensitiveFiles>,
    }
}

strict! {
    /// The audit walk run on a workspace before its diff is computed.
    pub struct WorkspaceAudit {
        /// When it runs.
        pub run: String,
        /// How it walks.
        pub walk: String,
        /// What it rejects.
        pub reject_any_of: Vec<String>,
        /// What happens on a rejection.
        pub on_reject: String,
    }
}

strict! {
    /// Section 3: where file tools may write.
    pub struct PathAccess {
        /// The workspace root inside the sandbox.
        pub workspace_root: String,
        /// Globs a write may match.
        pub write_allow: Vec<GlobText>,
        /// Where the narrowing comes from.
        pub write_scope_source: String,
        /// A reference to the groups whose paths cannot be read.
        pub deny_read_globs_ref: String,
        /// How paths are resolved.
        pub resolve_with: String,
        /// Whether host-side readers follow symlinks.
        pub follow_symlinks_on_host: bool,
        /// The largest file a tool may write.
        pub max_file_bytes: u64,
        /// The most files one task may change.
        pub max_files_changed_per_task: u64,
        /// The largest diff.
        pub max_diff_bytes: u64,
        /// The audit walk.
        pub workspace_audit: WorkspaceAudit,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

closed_set! {
    /// What happens to a command that matches a forbidden class.
    pub enum CommandAction {
        /// Refuse.
        Deny,
        /// Ask a human.
        RequireHuman,
    }
}

strict! {
    /// How a forbidden class matches a command.
    pub struct CommandMatch {
        /// Basenames of executables.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub executables: Option<Vec<String>>,
        /// Exact argv tokens.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub argv_any: Option<Vec<String>>,
        /// Regular expressions applied to the argv joined with spaces.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub argv_regex: Option<Vec<RegexText>>,
    }
}

strict! {
    /// One forbidden command class.
    pub struct ForbiddenCommandClass {
        /// The class.
        pub id: String,
        /// What it is.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// What it matches.
        #[serde(rename = "match")]
        pub matches: CommandMatch,
        /// What happens.
        pub action: CommandAction,
        /// The only sanctioned way around the rule.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub breakglass_tool: Option<String>,
        /// Sandbox profiles where the rule does not apply.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub except_profiles: Option<Vec<String>>,
    }
}

closed_set! {
    /// How risky a tool is.
    pub enum ToolRisk {
        /// Low.
        Low,
        /// Medium.
        Medium,
        /// High.
        High,
    }
}

closed_set! {
    /// When a human must approve a tool call.
    pub enum HumanGate {
        /// Never.
        None,
        /// For each call.
        PerCall,
        /// Once for the task.
        PerTask,
    }
}

strict! {
    /// One argument of a tool.
    pub struct ToolArg {
        /// The kind of value.
        pub kind: String,
        /// Read or write, for a path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub access: Option<String>,
        /// The longest string.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub max_len: Option<u64>,
        /// The rule set that governs an argv.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub policy: Option<String>,
        /// The allowed values of an enum.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub values: Option<Vec<String>>,
        /// The allowed URL schemes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub schemes: Option<Vec<String>>,
    }
}

strict! {
    /// Per-task caps for one tool.
    pub struct ToolLimits {
        /// The most calls in a task.
        pub max_calls_per_task: u64,
        /// The largest result.
        pub max_result_bytes: u64,
        /// A call's time limit in seconds.
        pub timeout_s: u64,
        /// Whether the whole process group is killed at the end of a call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub kill_process_group: Option<bool>,
    }
}

strict! {
    /// What one role may do with a tool, on top of holding it. A role that is on the entry's
    /// `roles` and has no scope here has no extra limit from this entry: the task's owned files,
    /// the protected paths and the command sets still apply.
    pub struct RoleScope {
        /// The paths the role may touch with the tool. A path outside them is refused even when
        /// `path_access` and the protected paths would allow it. They are repository-relative
        /// globs in the same dialect as the protected paths.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub paths: Option<Vec<GlobText>>,
        /// The ids of the `command_sets.sets` the role may run with the tool. A command in another
        /// set is refused for this role.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub command_sets: Option<Vec<String>>,
    }
}

strict! {
    /// One tool.
    pub struct ToolEntry {
        /// The tool.
        pub id: String,
        /// Its risk.
        pub risk: ToolRisk,
        /// What it does.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// False for a tool that is off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub enabled: Option<bool>,
        /// Sandbox profiles where it may run.
        pub profiles: Vec<String>,
        /// Agent roles that may hold it. `*` means every role.
        pub roles: Vec<String>,
        /// Its arguments.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub args: Option<BTreeMap<String, ToolArg>>,
        /// Its caps.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub limits: Option<ToolLimits>,
        /// Narrower limits for named roles, by role. Every key is a role on `roles`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub role_scopes: Option<BTreeMap<String, RoleScope>>,
        /// When a human must approve.
        pub human_gate: HumanGate,
        /// Notes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notes: Option<String>,
    }
}

strict! {
    /// What happens when an agent keeps asking for tools it cannot have.
    pub struct MisuseThreshold {
        /// The most refused requests (an unknown tool, a never-grantable tool or a self-grant)
        /// that one task may make. The request after the last one sends the stage to a person.
        pub max_denied_requests_per_task: u32,
        /// What happens then. The value used is `needs_human`.
        pub on_threshold: String,
    }
}

strict! {
    /// Section 5: the tool allow list.
    pub struct Tools {
        /// What a tool with no entry gets.
        pub default_action: DenyByDefault,
        /// Who issues grants.
        pub grant_authority: String,
        /// Whether an agent may grant itself a tool. Must be false.
        pub agents_may_self_grant: bool,
        /// Tools that are never granted to any agent.
        pub never_grantable: Vec<String>,
        /// When repeated refused requests send the stage to a person.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub misuse_threshold: Option<MisuseThreshold>,
        /// The tools.
        pub entries: Vec<ToolEntry>,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// One executable inside a command set.
    pub struct CommandExecutable {
        /// The subcommands that may run. Empty means none are named.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub allowed_subcommands: Option<Vec<String>>,
        /// Arguments that deny the call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forbidden_args: Option<Vec<String>>,
        /// Arguments the wrapper appends, by sandbox profile.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forced_args: Option<BTreeMap<String, Vec<String>>>,
        /// Narrows `forced_args`: an argument named here, by its text (`--offline`), is added only
        /// to the listed subcommands, because a subcommand that does not accept the argument
        /// (`cargo fmt` refuses `--offline` and `--locked`) fails when it receives it. An argument
        /// not named here is added to every allowed subcommand, as before. Every key must be
        /// forced for some profile and every subcommand must be one of `allowed_subcommands`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forced_arg_subcommands: Option<BTreeMap<String, Vec<String>>>,
    }
}

strict! {
    /// One toolchain's commands.
    pub struct CommandSet {
        /// The set.
        pub id: String,
        /// The executables, by basename.
        pub executables: BTreeMap<String, CommandExecutable>,
        /// The environment the supervisor sets.
        pub env: BTreeMap<String, String>,
        /// Values that replace the same names in `env` for one sandbox profile, by profile name.
        /// The fetch profile uses it to switch the network on where every other profile keeps it
        /// off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub env_by_profile: Option<BTreeMap<String, BTreeMap<String, String>>>,
        /// Notes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub notes: Option<String>,
    }
}

strict! {
    /// Section 6: the commands agents may run.
    pub struct CommandSets {
        /// What a command with no entry gets.
        pub default_action: DenyByDefault,
        /// How an executable is matched.
        pub executable_match: String,
        /// The sets.
        pub sets: Vec<CommandSet>,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// What the sandbox must look like, checked on the created container before it starts.
    pub struct SandboxRequired {
        /// Must be false.
        pub privileged: bool,
        /// How the user is chosen.
        pub user: String,
        /// Whether the root file system is read only.
        pub read_only_rootfs: bool,
        /// Capabilities dropped.
        pub cap_drop: Vec<String>,
        /// Capabilities added.
        pub cap_add: Vec<String>,
        /// Whether new privileges are blocked.
        pub no_new_privileges: bool,
        /// The seccomp rule.
        pub seccomp: String,
        /// The AppArmor rule.
        pub apparmor: String,
        /// The PID namespace.
        pub pid_mode: String,
        /// The IPC namespace.
        pub ipc_mode: String,
        /// The UTS namespace.
        pub uts_mode: String,
        /// The network modes allowed.
        pub network_mode: Vec<String>,
        /// Devices.
        pub devices: Vec<String>,
        /// Extra kernel parameters.
        pub extra_sysctls: BTreeMap<String, String>,
        /// Whether the Docker socket is mounted.
        pub docker_socket_mounted: bool,
        /// The log driver.
        pub log_driver: String,
        /// Whether an init process runs.
        pub init: bool,
        /// How the image is referenced.
        pub image_reference: String,
        /// The pull policy.
        pub pull_policy: String,
        /// The restart policy.
        pub restart_policy: String,
        /// Whether the container is removed with `--rm`.
        pub remove_with_rm_flag: bool,
        /// The environment rules.
        pub environment: SandboxEnvironment,
    }
}

strict! {
    /// The environment rules for a sandbox.
    pub struct SandboxEnvironment {
        /// How names are chosen.
        pub names: String,
        /// Names that are never set.
        pub forbidden_names: Vec<String>,
        /// Who sets proxy variables.
        pub proxy_variables: String,
        /// Whether a secret value in the environment is forbidden.
        pub secret_values_forbidden: bool,
        /// How `PATH` is set.
        pub path: String,
    }
}

strict! {
    /// A mount that is allowed although its source is normally forbidden.
    pub struct SpecialMount {
        /// The source.
        pub source: String,
        /// The target.
        pub target: String,
        /// Whether it is read only.
        pub readonly: bool,
        /// Why.
        pub purpose: String,
    }
}

strict! {
    /// How the workspace is mounted and how version control runs.
    pub struct SandboxWorkspace {
        /// What is mounted.
        pub mount: String,
        /// Whether `.git` is masked.
        pub mask_dot_git: bool,
        /// Whether protected paths are re-mounted read only.
        pub protected_overlay_readonly: bool,
        /// How hidden paths are kept out.
        pub hidden_paths_strategy: String,
        /// Whether hidden paths are not mounted.
        pub hidden_paths_not_mounted: bool,
        /// Whether version control runs on the host.
        pub vcs_operations_run_on_host: bool,
        /// The environment for every host-side git call.
        pub host_git_environment: BTreeMap<String, String>,
        /// How caches are mounted.
        pub caches: String,
        /// Whether a volume is writable across jobs.
        pub cross_job_writable_volumes: bool,
        /// Whether a path is shared across tenants.
        pub cross_tenant_shared_paths: bool,
    }
}

closed_set! {
    /// How a sandbox profile reaches the network.
    pub enum NetworkAccess {
        /// No network.
        None,
        /// Through a proxy with an allow list.
        ProxiedAllowlist,
        /// Only to the model broker.
        ModelBrokerOnly,
        /// To the model broker and the troubleshooter's MCP gateway, each through a fixed relay
        /// of the sidecar (ADR 0021). The `troubleshooter` profile only.
        ModelBrokerAndMcpGateway,
    }
}

strict! {
    /// The workspace mount of one profile.
    pub struct ProfileWorkspace {
        /// Read write or read only.
        pub mode: String,
        /// What part may be written.
        pub scope: String,
    }
}

strict! {
    /// The limits of one profile.
    pub struct ProfileLimits {
        /// CPUs.
        pub cpus: f64,
        /// Memory in megabytes.
        pub memory_mb: u64,
        /// Memory plus swap in megabytes.
        pub memory_swap_mb: u64,
        /// Processes.
        pub pids: u64,
        /// Wall clock in seconds.
        pub wall_clock_s: u64,
        /// Workspace disk in megabytes.
        pub workspace_disk_mb: u64,
        /// Temporary file system in megabytes.
        pub tmpfs_mb: u64,
        /// Open files.
        pub nofile: u64,
        /// Largest file in megabytes.
        pub max_file_mb: u64,
    }
}

strict! {
    /// One sandbox profile.
    pub struct SandboxProfile {
        /// What the profile is for.
        pub purpose: String,
        /// Its network.
        pub network: NetworkAccess,
        /// The egress profile it uses.
        pub egress_profile: String,
        /// Its secrets.
        pub secrets: String,
        /// Its workspace.
        pub workspace: ProfileWorkspace,
        /// Its default limits.
        pub limits: ProfileLimits,
        /// Whether the temporary file system may execute code.
        pub tmpfs_exec: bool,
        /// Where gate definitions come from.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub gate_definitions_from: Option<String>,
        /// Whether holdout data is mounted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub holdouts_mounted: Option<bool>,
    }
}

strict! {
    /// The sandbox profiles.
    pub struct SandboxProfiles {
        /// Downloads dependencies.
        pub fetch_deps: SandboxProfile,
        /// Runs the agent.
        pub agent: SandboxProfile,
        /// Runs the trusted gates.
        pub verify: SandboxProfile,
        /// Runs the troubleshooter (ADR 0021).
        pub troubleshooter: SandboxProfile,
    }
}

strict! {
    /// The supervisor's watchdog.
    pub struct Watchdog {
        /// Who kills at the deadline.
        pub wall_clock_kill: String,
        /// How often disk use is polled.
        pub disk_poll_interval_s: u64,
        /// The most log bytes kept.
        pub max_log_bytes: u64,
        /// What happens at the log cap.
        pub on_log_cap: String,
        /// What happens on a breach.
        pub on_breach: String,
        /// Whether OOM kills are recorded.
        pub record_oom_killed: bool,
    }
}

strict! {
    /// Section 7: the sandbox.
    pub struct Sandbox {
        /// The container runtime.
        pub runtime: String,
        /// Whether a failure to start fails the job.
        pub fail_closed: bool,
        /// What happens when the sandbox cannot start.
        pub host_execution_fallback: String,
        /// What the created container must look like.
        pub required: SandboxRequired,
        /// Sources that may never be mounted.
        pub forbidden_mount_sources: Vec<String>,
        /// Mounts that are allowed anyway.
        pub allowed_special_mounts: Vec<SpecialMount>,
        /// The workspace rules.
        pub workspace: SandboxWorkspace,
        /// The profiles.
        pub profiles: SandboxProfiles,
        /// The watchdog.
        pub watchdog: Watchdog,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// What the egress proxy refuses and bounds.
    pub struct ProxyRules {
        /// IP ranges refused after resolution.
        pub reject_resolved_ip_ranges: Vec<String>,
        /// TLS handling.
        pub tls: String,
        /// The default methods.
        pub methods_default: Vec<String>,
        /// The most bytes per job.
        pub max_bytes_per_job: u64,
        /// Whether every request is logged.
        pub log_every_request: bool,
    }
}

strict! {
    /// A host the sandbox may never reach.
    pub struct NeverAllowedHost {
        /// The host.
        pub host: String,
        /// Why.
        pub reason: String,
    }
}

strict! {
    /// One allowed egress destination.
    pub struct EgressAllow {
        /// The entry.
        pub id: String,
        /// The host.
        pub host: String,
        /// The ports.
        pub ports: Vec<u16>,
        /// The methods.
        pub methods: Vec<String>,
        /// The package ecosystem, when it is for packages.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ecosystem: Option<String>,
        /// Why the host is allowed.
        pub justification: String,
        /// The date a person must look at it again, as `YYYY-MM-DD`.
        pub review_by: String,
        /// Whether the destination terminates TLS.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub terminates_tls: Option<bool>,
    }
}

strict! {
    /// The destinations of one egress profile.
    pub struct EgressProfile {
        /// The allowed destinations. Empty means none.
        pub allow: Vec<EgressAllow>,
    }
}

strict! {
    /// The egress profiles.
    pub struct EgressProfiles {
        /// No network.
        pub none: EgressProfile,
        /// Dependency download.
        pub fetch_deps: EgressProfile,
        /// The agent.
        pub agent: EgressProfile,
        /// The troubleshooter: the model broker and the MCP gateway (ADR 0021).
        pub troubleshooter: EgressProfile,
    }
}

strict! {
    /// A host the broker may call, and the paths it may call there.
    pub struct BrokerUpstream {
        /// The entry.
        pub id: String,
        /// The host.
        pub host: String,
        /// The API paths.
        pub paths: Vec<String>,
        /// Why.
        pub justification: String,
        /// The date a person must look at it again, as `YYYY-MM-DD`.
        pub review_by: String,
    }
}

strict! {
    /// Section 8: egress.
    pub struct Egress {
        /// What a destination with no entry gets.
        pub default_action: DenyByDefault,
        /// How it is enforced.
        pub enforcement: String,
        /// What DNS does inside the sandbox.
        pub sandbox_dns: String,
        /// Whether wildcards are allowed. Must be false.
        pub allow_wildcards: bool,
        /// Whether names resolve only in the proxy.
        pub resolve_in_proxy_only: bool,
        /// The proxy rules.
        pub proxy_rules: ProxyRules,
        /// Hosts that are never allowed.
        pub never_allow_from_sandbox: Vec<NeverAllowedHost>,
        /// The profiles.
        pub profiles: EgressProfiles,
        /// What the broker may call.
        pub broker_upstreams: Vec<BrokerUpstream>,
        /// What widening needs.
        pub widening_requires: Vec<String>,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

closed_set! {
    /// What a secret match does.
    pub enum SecretAction {
        /// Refuse the content.
        Block,
        /// Record a signal and let it through.
        Flag,
    }
}

strict! {
    /// One secret pattern.
    pub struct SecretPattern {
        /// The pattern.
        pub id: String,
        /// The regular expression.
        pub regex: RegexText,
        /// What a match does.
        pub action: SecretAction,
        /// Whether the format is confirmed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub format_status: Option<String>,
    }
}

strict! {
    /// The entropy heuristic.
    pub struct EntropyHeuristic {
        /// Whether it runs.
        pub enabled: bool,
        /// The shortest string it looks at.
        pub min_length: u64,
        /// The Shannon entropy threshold in bits per character.
        pub min_shannon_bits_per_char: f64,
        /// What a match does.
        pub action: SecretAction,
    }
}

strict! {
    /// Secrets the factory itself issued.
    pub struct ExactValues {
        /// Where they are registered from.
        pub register_from: Vec<String>,
        /// The shortest value registered.
        pub min_length: u64,
        /// The encodings matched.
        pub encodings: Vec<String>,
        /// How matches across chunks are found.
        pub split_detection: String,
    }
}

closed_set! {
    /// What a match on a sink does.
    pub enum SinkAction {
        /// Replace the secret and continue.
        Redact,
        /// Refuse.
        Block,
    }
}

strict! {
    /// One sink class.
    pub struct Sink {
        /// What a match does.
        pub on_match: SinkAction,
        /// Where it applies.
        pub applies_to: Vec<String>,
    }
}

strict! {
    /// The sink classes.
    pub struct Sinks {
        /// Logs and traces.
        pub logs_and_traces: Sink,
        /// Domain events.
        pub domain_events: Sink,
        /// Artifacts.
        pub artifacts: Sink,
        /// Text bound for GitHub.
        pub github_bound_text: Sink,
        /// Diffs and files.
        pub diffs_and_files: Sink,
        /// Model context.
        pub model_context: Sink,
        /// Dashboards and the API.
        pub dashboard_and_api: Sink,
    }
}

strict! {
    /// Section 9: secrets.
    pub struct Secrets {
        /// The regex dialect.
        pub scanner_regex_dialect: String,
        /// The patterns.
        pub patterns: Vec<SecretPattern>,
        /// The entropy heuristic.
        pub entropy_heuristic: EntropyHeuristic,
        /// Registered values.
        pub exact_values: ExactValues,
        /// The sinks.
        pub sinks: Sinks,
        /// What happens when the redactor fails.
        pub redactor_failure: String,
        /// Things that never enter model context.
        pub never_in_model_context: Vec<String>,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// The installation token the GitHub App mints.
    pub struct InstallationToken {
        /// When it is minted.
        pub mint: String,
        /// How many repositories it covers.
        pub repositories: String,
        /// How permissions are narrowed.
        pub permissions: String,
        /// Its lifetime in seconds.
        pub lifetime_s: u64,
        /// Whether it is revoked at job end.
        pub revoke_on_job_end: bool,
        /// Seconds a job may stay `BLOCKED` before its tokens are revoked (LB-04). The job is not
        /// ended: its next call mints a new token. A job that waits for a person keeps its token.
        /// At least 60 and at most 86400 (`credentials.github_app.installation_token`).
        pub revoke_when_blocked_after_s: u64,
        /// Who may hold it.
        pub holders: Vec<String>,
        /// Whether it is written to disk.
        pub persisted_to_disk: bool,
        /// Whether the sandbox can see it.
        pub visible_to_sandbox: bool,
        /// Whether it is logged.
        pub logged: bool,
    }
}

strict! {
    /// The GitHub App.
    pub struct GithubApp {
        /// Permissions the App must have, by name.
        pub permissions_required: BTreeMap<String, String>,
        /// Permissions it must not have.
        pub permissions_forbidden: Vec<String>,
        /// The installation token.
        pub installation_token: InstallationToken,
    }
}

strict! {
    /// A stored key with a rotation period.
    pub struct AppPrivateKey {
        /// Where it is stored.
        pub store: String,
        /// Who uses it.
        pub consumers: Vec<String>,
        /// Days between rotations.
        pub rotation_days: u64,
        /// Whether two keys are valid during rotation.
        pub overlapping_keys_during_rotation: bool,
    }
}

strict! {
    /// The webhook secret.
    pub struct WebhookSecret {
        /// Where it is stored.
        pub store: String,
        /// Days between rotations.
        pub rotation_days: u64,
        /// Whether two secrets are valid during rotation.
        pub overlapping_secrets_during_rotation: bool,
    }
}

strict! {
    /// The per-job token the sandbox gets.
    pub struct JobToken {
        /// The prefix.
        pub prefix: String,
        /// Bits of entropy.
        pub entropy_bits: u64,
        /// What it is bound to.
        pub bound_to: Vec<String>,
        /// How long it lasts.
        pub ttl: String,
        /// What it limits.
        pub scope: Vec<String>,
        /// When it is revoked.
        pub revoked_on: Vec<String>,
    }
}

strict! {
    /// The real provider keys of mode `api_key`.
    pub struct RealKeys {
        /// Where they are stored.
        pub store: String,
        /// Whether each deployment has its own.
        pub dedicated_per_deployment: bool,
        /// Whether a provider-side spend limit is required.
        pub hard_spend_limit_required: bool,
        /// Days between rotations.
        pub rotation_days: u64,
    }
}

closed_set! {
    /// Which credential the broker relays to the model providers (ADR 0020).
    #[derive(Default)]
    pub enum ProviderCredentialMode {
        /// The default: the owner's Claude subscription token, held by the broker and sent upstream
        /// as a bearer token. No provider API key and no provider-side spend limit is required.
        /// Codex is unavailable.
        #[default]
        Subscription,
        /// The alternative: provider API keys with a provider-side spend limit, held by the broker,
        /// for both providers.
        ApiKey,
    }
}

impl ProviderCredentialMode {
    /// The word the policy file uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::ApiKey => "api_key",
        }
    }
}

strict! {
    /// The subscription token of mode `subscription`.
    pub struct SubscriptionToken {
        /// The providers whose subscription the broker relays. Anthropic only.
        pub providers: Vec<String>,
        /// How the token is made (`claude_setup_token`).
        pub made_with: String,
        /// Where it is stored.
        pub store: String,
        /// Who holds it. The model broker only.
        pub held_by: Vec<String>,
        /// How the broker sends it upstream (`authorization_bearer`).
        pub sent_upstream_as: String,
        /// The kind it is registered under with the redactor.
        pub registered_for_redaction_as: String,
        /// Whether a provider-side spend limit is required. False: a subscription has none.
        pub provider_side_spend_limit_required: bool,
        /// What bounds the spend instead.
        pub spend_bounded_by: Vec<String>,
        /// The runtimes that cannot run in this mode, named so the factory can say so.
        pub unavailable_runtimes: Vec<String>,
        /// Whether it is kept out of every sandbox. Must be true.
        pub never_in_sandbox: bool,
        /// Days between rotations.
        pub rotation_days: u64,
    }
}

strict! {
    /// Model provider credentials.
    pub struct ModelProviders {
        /// Which credential the broker relays. A file without the key means `subscription`.
        #[serde(default)]
        pub mode: ProviderCredentialMode,
        /// How credentials reach the call.
        pub delivery: String,
        /// The job token.
        pub job_token: JobToken,
        /// The subscription token, for mode `subscription`.
        pub subscription_token: SubscriptionToken,
        /// The real keys, for mode `api_key`.
        pub real_keys: RealKeys,
        /// What happens when a tool cannot use the broker.
        pub fallback_if_cli_cannot_use_broker: String,
    }
}

strict! {
    /// Rotation deadlines.
    pub struct RotationSlas {
        /// Hours for a leaked or suspected secret.
        pub leaked_or_suspected_hours: u64,
        /// Days for a high-privilege secret.
        pub high_privilege_days: u64,
        /// Days for any other.
        pub standard_days: u64,
    }
}

closed_set! {
    /// What happens to a repository whose workflows are exposed to the factory's branches
    /// (threat T-48).
    pub enum ExposedWorkflows {
        /// The repository runs at level L0, unless its owner acknowledged exactly those workflows.
        CapAtL0,
        /// The workflows are named in the audit record and the repository is not capped for them.
        RecordOnly,
    }
}

strict! {
    /// What a repository must have for the factory to act above level L0.
    pub struct RepositoryRequirements {
        /// The default branch is protected.
        pub default_branch_protected: bool,
        /// Pull requests are required.
        pub require_pull_request: bool,
        /// Required checks are pinned to the App.
        pub required_status_checks_pinned_to_app_id: bool,
        /// Whether the App is on a bypass list. Must be false.
        pub app_in_bypass_list: bool,
        /// Force pushes are disabled.
        pub force_push_disabled: bool,
        /// Branch deletion is disabled.
        pub branch_deletion_disabled: bool,
        /// Code owner review is required for protected paths.
        pub require_code_owner_review_for_protected_paths: bool,
        /// Stale approvals are dismissed.
        pub dismiss_stale_approvals_on_new_commits: bool,
        /// The branch pattern the factory pushes to.
        pub factory_branch_pattern: String,
        /// Whether pushes are limited to that pattern.
        pub push_only_to_factory_branch_pattern: bool,
        /// What exposed workflows of the target repository cost it (threat T-48).
        pub exposed_workflows: ExposedWorkflows,
    }
}

strict! {
    /// Section 10: credentials.
    pub struct Credentials {
        /// The GitHub App.
        pub github_app: GithubApp,
        /// The App's private key.
        pub app_private_key: AppPrivateKey,
        /// The webhook secret.
        pub webhook_secret: WebhookSecret,
        /// Model provider credentials.
        pub model_providers: ModelProviders,
        /// Rotation deadlines.
        pub rotation_slas: RotationSlas,
        /// What a repository must have.
        pub repository_requirements: RepositoryRequirements,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// How a webhook signature is checked.
    pub struct WebhookSignature {
        /// The header.
        pub header: String,
        /// The algorithm.
        pub algorithm: String,
        /// The prefix of the value.
        pub prefix: String,
        /// What is signed.
        pub input: String,
        /// How it is compared.
        pub compare: String,
        /// What happens to the legacy header.
        pub legacy_sha1_header: String,
    }
}

strict! {
    /// Delivery de-duplication.
    pub struct WebhookDedupe {
        /// The key.
        pub key: String,
        /// Where it is kept.
        pub store: String,
        /// Days kept.
        pub retention_days: u64,
        /// What a duplicate gets.
        pub on_duplicate: String,
    }
}

strict! {
    /// Semantic idempotency.
    pub struct SemanticIdempotency {
        /// The fields that form the key.
        pub key_fields: Vec<String>,
        /// Days kept.
        pub retention_days: u64,
    }
}

strict! {
    /// One accepted event.
    pub struct AcceptedEvent {
        /// The event.
        pub event: String,
        /// The actions. Empty means no action field.
        pub actions: Vec<String>,
    }
}

strict! {
    /// Webhook rate limits.
    pub struct WebhookRateLimit {
        /// Per installation per minute.
        pub per_installation_per_minute: u64,
        /// Per source address per minute.
        pub per_source_ip_per_minute: u64,
        /// What happens over the limit.
        pub on_exceed: String,
    }
}

strict! {
    /// Section 11: webhook intake.
    pub struct Webhook {
        /// Signature checking.
        pub signature: WebhookSignature,
        /// Headers that must be present.
        pub required_headers: Vec<String>,
        /// Content types accepted.
        pub content_types: Vec<String>,
        /// The largest body.
        pub max_body_bytes: u64,
        /// Verify before parsing.
        pub verify_before_parse: bool,
        /// Verify before touching the database.
        pub verify_before_db_access: bool,
        /// De-duplication.
        pub dedupe: WebhookDedupe,
        /// Semantic idempotency.
        pub semantic_idempotency: SemanticIdempotency,
        /// Whether the payload is only a hint.
        pub payload_is_hint_only: bool,
        /// What is fetched again before acting.
        pub refetch_before_acting: Vec<String>,
        /// What a delivery is bound to.
        pub tenant_binding: Vec<String>,
        /// The events accepted.
        pub accepted_events: Vec<AcceptedEvent>,
        /// Senders ignored.
        pub ignore_senders: Vec<String>,
        /// Rate limits.
        pub rate_limit: WebhookRateLimit,
        /// Seconds to acknowledge.
        pub respond_within_s: u64,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// Ceilings for one task.
    pub struct TaskCeiling {
        /// Dollars.
        pub max_usd: f64,
        /// Input tokens.
        pub max_input_tokens: u64,
        /// Output tokens.
        pub max_output_tokens: u64,
        /// Model requests.
        pub max_turns: u64,
        /// Tool calls.
        pub max_tool_calls: u64,
        /// Wall clock seconds.
        pub max_wall_clock_s: u64,
    }
}

strict! {
    /// Ceilings for one job.
    pub struct JobCeiling {
        /// Dollars.
        pub max_usd: f64,
        /// Rework rounds for code. Default 2.
        pub max_rework_iterations: u32,
        /// Rework rounds for documentation. Default 2.
        pub max_documentation_rework_iterations: u32,
        /// Wall clock seconds.
        pub max_wall_clock_s: u64,
        /// How deep delegation goes.
        pub max_delegation_depth: u32,
    }
}

strict! {
    /// Ceilings for one repository in a day.
    pub struct RepoDayCeiling {
        /// Dollars.
        pub max_usd: f64,
        /// Jobs started.
        pub max_jobs_started: u64,
    }
}

strict! {
    /// Ceilings for one organization in a day.
    pub struct OrgDayCeiling {
        /// Dollars.
        pub max_usd: f64,
    }
}

strict! {
    /// The hard ceilings.
    pub struct HardCeilings {
        /// Per task.
        pub per_task: TaskCeiling,
        /// Per job.
        pub per_job: JobCeiling,
        /// Per repository per day.
        pub per_repo_day: RepoDayCeiling,
        /// Per organization per day.
        pub per_org_day: OrgDayCeiling,
    }
}

strict! {
    /// Rework rules.
    pub struct ReworkRules {
        /// What happens at the cap.
        pub on_cap_reached: String,
        /// How a project may change the cap.
        pub project_override: String,
        /// The default number of rounds.
        pub default_rounds: u32,
    }
}

strict! {
    /// Concurrency limits.
    pub struct Concurrency {
        /// Running jobs per repository.
        pub max_running_jobs_per_repo: u64,
        /// Queued jobs per repository.
        pub max_queued_jobs_per_repo: u64,
        /// Running sandboxes per host.
        pub max_running_sandboxes_per_host: u64,
    }
}

strict! {
    /// Stagnation detection.
    pub struct Stagnation {
        /// Iterations in the window.
        pub window_iterations: u32,
        /// What happens with no new passing evidence.
        pub action_on_no_new_passing_evidence: String,
    }
}

strict! {
    /// Warning and stop thresholds.
    pub struct Thresholds {
        /// The fraction of a ceiling that raises a warning.
        pub warn_at_fraction: f64,
        /// The fraction that stops the work.
        pub stop_at_fraction: f64,
    }
}

strict! {
    /// Caps on one model request.
    pub struct PerRequestCaps {
        /// Input tokens.
        pub max_input_tokens: u64,
        /// Output tokens.
        pub max_output_tokens: u64,
    }
}

strict! {
    /// Section 12: budgets.
    pub struct Budgets {
        /// Who enforces them.
        pub enforced_by: Vec<String>,
        /// What counts as a turn.
        pub turn_accounting: String,
        /// The ceilings.
        pub hard_ceilings: HardCeilings,
        /// Rework rules.
        pub rework: ReworkRules,
        /// Concurrency.
        pub concurrency: Concurrency,
        /// Stagnation.
        pub stagnation: Stagnation,
        /// Thresholds.
        pub thresholds: Thresholds,
        /// What happens at exhaustion.
        pub on_exhaustion: String,
        /// Per request caps.
        pub per_request_caps: PerRequestCaps,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// Test regression rules.
    pub struct TestRegression {
        /// Where the baseline comes from.
        pub baseline_from: String,
        /// Removed tests are forbidden.
        pub forbid_removed_tests: bool,
        /// Newly ignored tests are forbidden.
        pub forbid_newly_ignored_tests: bool,
        /// Newly skipped tests are forbidden.
        pub forbid_newly_skipped_tests: bool,
        /// A drop in assertions is forbidden.
        pub forbid_assertion_count_drop: bool,
        /// New tests are allowed.
        pub new_tests_allowed: bool,
    }
}

strict! {
    /// Flaky test handling.
    pub struct FlakyTests {
        /// Retries allowed.
        pub retries_allowed: u32,
        /// Where flaky tests are listed.
        pub only_for: String,
        /// Whether each retry is recorded.
        pub record_every_retry: bool,
    }
}

strict! {
    /// One semantic check.
    pub struct SemanticCheck {
        /// The check.
        pub id: String,
        /// What it looks for.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        /// What it blocks until.
        pub blocks_until: String,
    }
}

strict! {
    /// A block of a gate that no override may pass.
    pub struct NonOverridableBlock {
        /// The entry, for a project policy that adds one.
        pub id: String,
        /// The gate that is blocked, such as `dependency-review`.
        pub gate: String,
        /// The block code of the gate report, one of the codes of the gate report schema.
        pub code: String,
        /// Why no override may pass it.
        pub reason: String,
    }
}

strict! {
    /// Merge rules.
    pub struct MergeRules {
        /// A merge must name the expected head SHA.
        pub require_expected_head_sha: bool,
        /// Critical gates run again after a sync.
        pub rerun_critical_gates_after_sync: bool,
        /// Required checks are pinned to the App.
        pub required_checks_pinned_to_app_id: bool,
    }
}

strict! {
    /// Section 13: gate integrity.
    pub struct GateIntegrity {
        /// Where gate definitions come from.
        pub gate_definition_source: String,
        /// Where gates run.
        pub gate_runner: String,
        /// Where evidence comes from.
        pub evidence_source: String,
        /// The gate statuses.
        pub gate_status_values: Vec<String>,
        /// The review verdicts.
        pub review_verdict_values: Vec<String>,
        /// What missing evidence is.
        pub missing_evidence_is: String,
        /// What an absent tool is.
        pub tool_absent_is: String,
        /// What a skipped gate is.
        pub skipped_gate_is: String,
        /// Whether a review can override a gate. Must be false.
        pub reviewer_verdict_can_override_gate: bool,
        /// Whether a reviewer sees the builder's justification. Must be false.
        pub reviewer_sees_builder_self_justification: bool,
        /// Gates that cannot be waived.
        pub nonwaivable_gates: Vec<String>,
        /// Blocks that no override may pass, though the gate may be waived for another reason: a
        /// gate that waits for a recorded decision is not passed by a decision nobody recorded
        /// on the subject. A person records the decision and the stage runs again.
        pub non_overridable_blocks: Vec<NonOverridableBlock>,
        /// What evidence is bound to.
        pub evidence_binding: Vec<String>,
        /// What invalidates evidence.
        pub invalidated_by: Vec<String>,
        /// Test regression rules.
        pub test_regression: TestRegression,
        /// Flaky test rules.
        pub flaky_tests: FlakyTests,
        /// The semantic checks.
        pub semantic_checks: Vec<SemanticCheck>,
        /// Merge rules.
        pub merge: MergeRules,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// How prompts are assembled.
    pub struct PromptAssembly {
        /// Whether untrusted text may be in the instruction channel.
        pub untrusted_in_instruction_channel: String,
        /// Whether untrusted text is wrapped in a data envelope.
        pub wrap_in_data_envelope: bool,
        /// Whether a delimiter collision is checked.
        pub envelope_delimiter_collision_check: bool,
    }
}

strict! {
    /// Structured output rules.
    pub struct StructuredOutput {
        /// Whether output is validated against a schema.
        pub schema_validated: bool,
        /// What an unknown field gets.
        pub unknown_fields: String,
        /// How many repairs are allowed.
        pub bounded_repair_attempts: u32,
        /// The largest output.
        pub max_output_bytes: u64,
    }
}

strict! {
    /// The injection signal detector.
    pub struct InjectionDetector {
        /// Whether it runs.
        pub enabled: bool,
        /// Its role.
        pub role: String,
        /// What a signal does.
        pub on_signal: String,
    }
}

strict! {
    /// Factory-side web fetch rules.
    pub struct WebFetch {
        /// Where it runs.
        pub runs_in: String,
        /// The schemes allowed.
        pub schemes: Vec<String>,
        /// Whether the address is pinned after resolution.
        pub resolve_then_pin_ip: bool,
        /// The address ranges refused, as a reference.
        pub reject_resolved_ip_ranges_ref: String,
        /// Whether redirects are checked again.
        pub revalidate_on_redirect: bool,
        /// The most redirects.
        pub max_redirects: u32,
        /// The largest body.
        pub max_bytes: u64,
        /// The content types allowed.
        pub allowed_content_types: Vec<String>,
        /// What happens to cookies and auth headers.
        pub cookies_and_auth_headers: String,
    }
}

strict! {
    /// Where specification authorization comes from.
    pub struct SpecificationAuthorization {
        /// The source.
        pub source: String,
        /// Whether it is read from prose.
        pub parsed_from_prose: String,
    }
}

strict! {
    /// Hardening for the Claude Code command line tool.
    pub struct ClaudeCodeRuntime {
        /// Flags for every stage.
        pub required_flags: Vec<String>,
        /// Where the per-stage flags are.
        pub per_stage_flags_ref: String,
        /// Where settings come from.
        pub settings_source: String,
        /// How tools are limited.
        pub tools_flag: String,
        /// The budget flag.
        pub per_run_budget_flag: String,
        /// Flags forbidden outside a verified sandbox.
        pub forbidden_flags_outside_verified_sandbox: Vec<String>,
        /// How it authenticates.
        pub auth: String,
        /// Environment settings the supervisor makes for every run, as `NAME=value`. The
        /// credential is never one of them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub required_environment: Option<Vec<String>>,
    }
}

strict! {
    /// Hardening for the Codex command line tool.
    pub struct CodexRuntime {
        /// Flags for every run.
        pub required_flags: Vec<String>,
        /// Flags forbidden outside a verified sandbox.
        pub forbidden_flags_outside_verified_sandbox: Vec<String>,
        /// The environment policy.
        pub env_policy: String,
    }
}

strict! {
    /// Agent runtime hardening.
    pub struct AgentRuntimes {
        /// Claude Code.
        pub claude_code: ClaudeCodeRuntime,
        /// Codex.
        pub codex_cli: CodexRuntime,
        /// Whether a probe must pass before an adapter is enabled.
        pub probe_required_before_enable: bool,
        /// Repository files that are never honored.
        pub repo_config_files_never_honored: Vec<String>,
        /// Whether instruction files are data.
        pub instruction_files_are_data: bool,
    }
}

strict! {
    /// Section 14: untrusted content and agent runtime hardening.
    pub struct UntrustedContent {
        /// The classes of untrusted content.
        pub classes: Vec<String>,
        /// Whether content can grant authority.
        pub authority_from_content: String,
        /// Prompt assembly.
        pub prompt_assembly: PromptAssembly,
        /// Structured output.
        pub structured_output: StructuredOutput,
        /// The detector.
        pub injection_signal_detector: InjectionDetector,
        /// Web fetch.
        pub web_fetch: WebFetch,
        /// Specification authorization.
        pub specification_authorization: SpecificationAuthorization,
        /// Runtime hardening.
        pub agent_runtimes: AgentRuntimes,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// Flag changes a profile makes for Claude Code.
    pub struct ClaudeFlags {
        /// Flags added.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub flags_add: Option<Vec<String>>,
        /// Flags removed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub flags_omit: Option<Vec<String>>,
        /// Whether a per-skill permission rule works.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub skill_permission_rule: Option<String>,
    }
}

strict! {
    /// How a profile treats skills for Codex.
    pub struct CodexSkills {
        /// The visibility rule.
        pub skill_visibility: String,
    }
}

strict! {
    /// One allowed skill.
    pub struct AllowedSkill {
        /// The skill.
        pub id: String,
        /// The paths it writes.
        pub writes: Vec<GlobText>,
        /// Whether it needs a protected-path exception.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub protected_path_exception_required: Option<bool>,
    }
}

strict! {
    /// The skills of a profile.
    pub struct SkillRules {
        /// Whether a deny wins over an allow.
        pub deny_wins_over_allow: bool,
        /// The allowed skills.
        pub allowed: Vec<AllowedSkill>,
        /// The denied skills.
        pub denied: Vec<String>,
    }
}

strict! {
    /// Checks made on the host before a run.
    pub struct IntegrityBeforeRun {
        /// The status the integration must report.
        pub integration_status_json: String,
        /// Recorded versions equal the pinned one.
        pub recorded_versions_equal_pinned: bool,
        /// The extensions file is absent.
        pub extensions_file_absent: bool,
        /// Skill file hashes equal the pinned manifest.
        pub skill_file_hashes_equal_pinned_manifest: bool,
    }
}

strict! {
    /// One stage profile.
    pub struct StageProfile {
        /// The profile.
        pub id: String,
        /// The stage kinds it applies to. `*` means every other stage.
        pub applies_to_stage_kinds: Vec<String>,
        /// How skills and slash commands are treated.
        pub skills_and_slash_commands: String,
        /// Skills allowed, when none are named in `skills`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub skills_allowed: Option<Vec<String>>,
        /// Claude Code flags.
        pub claude_code: ClaudeFlags,
        /// Codex rules.
        pub codex_cli: CodexSkills,
        /// Directories hidden in the sandbox.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hide_skill_roots_in_sandbox: Option<Vec<String>>,
        /// What a violation does.
        pub violation: String,
        /// The named skills.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub skills: Option<SkillRules>,
        /// Whether denied skills are hidden.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub hide_denied_skills_in_sandbox: Option<bool>,
        /// What happens to other project skills.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub other_project_skills_and_commands: Option<String>,
        /// Checks before the run.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub integrity_before_run: Option<IntegrityBeforeRun>,
        /// Files whose presence shows a denied skill ran.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub forbidden_artifacts_after_run: Option<Vec<GlobText>>,
        /// How a violation is detected.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub detection: Option<Vec<String>>,
        /// What happens on a violation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub on_violation: Option<Vec<String>>,
    }
}

strict! {
    /// Section 14a: per-stage skill profiles.
    pub struct AgentStageProfiles {
        /// Who picks the profile.
        pub selection_authority: String,
        /// The profile for a stage kind no profile names.
        pub default_profile: String,
        /// The profiles.
        pub profiles: Vec<StageProfile>,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// Section 15: text the factory writes to GitHub.
    pub struct OutputHygiene {
        /// What it covers.
        pub applies_to: Vec<String>,
        /// Whether raw HTML is allowed.
        pub allow_raw_html: bool,
        /// Domains images may come from.
        pub allow_images_from_domains: Vec<String>,
        /// Domains links may point to.
        pub allow_link_domains: Vec<String>,
        /// Whether user mentions are neutralized.
        pub neutralize_user_mentions: bool,
        /// Whether cross-repository references are neutralized.
        pub neutralize_cross_repo_references: bool,
        /// Hidden content that is stripped.
        pub strip_hidden_content: Vec<String>,
        /// The largest body.
        pub max_body_bytes: u64,
        /// The secret check, as a reference.
        pub secrets_check: String,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// Lockfile rules.
    pub struct Lockfiles {
        /// Lockfiles are required.
        pub required: bool,
        /// They are frozen in gates.
        pub frozen_in_gates: bool,
    }
}

strict! {
    /// Licence rules.
    pub struct LicenseRules {
        /// The default for a licence not listed.
        pub default: String,
        /// Licences that are always denied.
        pub always_denied: Vec<String>,
        /// Where the allow list is.
        pub allow_list_in: String,
    }
}

strict! {
    /// Rules for a new direct dependency.
    pub struct NewDirectDependency {
        /// Who approves. Must be a human, always.
        pub approval: String,
        /// What makes a dependency new.
        pub new_means: String,
        /// Heuristics shown to the human.
        pub heuristics_recorded: Vec<String>,
        /// A younger package needs a security approver.
        pub min_first_publish_age_days: u64,
    }
}

strict! {
    /// The advisory database the dependency scan reads.
    pub struct AdvisoryDatabaseRule {
        /// The most whole days old the database may be. A scan against an older database, or one
        /// of unknown age, does not pass. A project policy may lower it, never raise it.
        pub max_age_days: u64,
    }
}

strict! {
    /// When the dependency gates run.
    pub struct DependencyGates {
        /// `dependency_files_change` (only for a change that touches a dependency file) or
        /// `always`. A project policy may move to `always`, never back.
        pub run_when: String,
    }
}

strict! {
    /// SBOM rules.
    pub struct SbomRules {
        /// The format.
        pub format: String,
        /// When it is required.
        pub required_for: Vec<String>,
    }
}

strict! {
    /// Image rules.
    pub struct ImageRules {
        /// Images are pinned by digest.
        pub pinned_by_digest: bool,
        /// The factory builds them from source.
        pub built_from_source_by_factory: bool,
        /// Days between rebuilds.
        pub rebuild_interval_days: u64,
        /// Whether a vulnerability scan is required.
        pub vulnerability_scan: String,
    }
}

strict! {
    /// Section 16: supply chain.
    pub struct SupplyChain {
        /// Allowed registries, as a reference.
        pub registries_allowed_ref: String,
        /// Lockfiles.
        pub lockfiles: Lockfiles,
        /// Licences.
        pub licenses: LicenseRules,
        /// Install scripts.
        pub install_scripts: String,
        /// New direct dependencies.
        pub new_direct_dependency: NewDirectDependency,
        /// The advisory database the scan reads.
        pub advisory_database: AdvisoryDatabaseRule,
        /// When the dependency gates run.
        pub dependency_gates: DependencyGates,
        /// Scanners.
        pub scanners: Vec<String>,
        /// SBOM.
        pub sbom: SbomRules,
        /// Images.
        pub images: ImageRules,
        /// CI actions are pinned to commit SHAs.
        pub ci_actions_pinned_to_commit_sha: bool,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// Object store tenancy.
    pub struct ObjectStoreTenancy {
        /// Each tenant has a prefix.
        pub prefix_per_tenant: bool,
        /// Each tenant has a key.
        pub key_per_tenant: String,
    }
}

strict! {
    /// Messaging tenancy.
    pub struct MessagingTenancy {
        /// Each tenant has a subject prefix.
        pub subject_prefix_per_tenant: bool,
        /// Each tenant has its own publish and subscribe permissions.
        pub per_tenant_publish_subscribe_permissions: bool,
    }
}

strict! {
    /// Sandbox tenancy.
    pub struct SandboxTenancy {
        /// Sandboxes shared between tenants.
        pub shared_between_tenants: String,
        /// Warm pool across tenants.
        pub warm_pool_across_tenants: String,
        /// Writable cache shared.
        pub writable_cache_shared: String,
    }
}

strict! {
    /// Model context tenancy.
    pub struct ModelContextTenancy {
        /// Cross-tenant retrieval.
        pub cross_tenant_retrieval: String,
    }
}

strict! {
    /// Memory store tenancy.
    pub struct MemoryStoreTenancy {
        /// The access boundary.
        pub access_boundary: String,
    }
}

strict! {
    /// Section 17: tenancy.
    pub struct Tenancy {
        /// A tenant id is on every row.
        pub tenant_id_on_every_row: bool,
        /// Row-level security.
        pub database_row_level_security: String,
        /// The object store.
        pub object_store: ObjectStoreTenancy,
        /// Messaging.
        pub messaging: MessagingTenancy,
        /// Sandboxes.
        pub sandbox: SandboxTenancy,
        /// Model context.
        pub model_context: ModelContextTenancy,
        /// Memory stores.
        pub memory_stores: MemoryStoreTenancy,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}

strict! {
    /// The audit hash chain.
    pub struct AuditHashChain {
        /// The algorithm.
        pub algorithm: String,
        /// The scope.
        pub scope: String,
        /// The fields hashed.
        pub fields: Vec<String>,
    }
}

strict! {
    /// The external anchor of the audit chain.
    pub struct AuditAnchor {
        /// Where it is stored.
        pub store: String,
        /// Minutes between anchors.
        pub interval_minutes: u64,
        /// What is anchored.
        pub what: String,
    }
}

strict! {
    /// Section 18: audit.
    pub struct Audit {
        /// Append only.
        pub append_only: bool,
        /// The application role's privileges.
        pub application_db_role_privileges: Vec<String>,
        /// The hash chain.
        pub hash_chain: AuditHashChain,
        /// The database assigns the time.
        pub server_assigned_timestamp: bool,
        /// The anchor.
        pub external_anchor: AuditAnchor,
        /// Minutes between verification runs.
        pub verification_job_interval_minutes: u64,
        /// Fields every event has.
        pub required_event_fields: Vec<String>,
        /// What must be recorded.
        pub must_record: Vec<String>,
        /// Audit is separate from diagnostic logs.
        pub separate_from_diagnostic_logs: bool,
        /// Whether the sandbox can write to it.
        pub sandbox_can_write: bool,
        /// Threats.
        pub threats: Vec<ThreatId>,
    }
}
