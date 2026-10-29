//! `AgentRuntime` adapters for the Claude Code and Codex command line tools (ADR 0005).
//!
//! Both tools run **inside** the `agent` sandbox, behind a per-job relay and a model broker. This
//! crate builds their command lines from closed allow lists, starts them through
//! `SandboxSession::exec`, reads their event streams and reports what happened. It starts no process
//! itself (rule ST-03), never sees a real provider key, and never marks a stage successful: the
//! output it returns is bytes that the engine validates.
//!
//! * [`claude`]: the Claude Code adapter.
//! * [`codex`]: the Codex adapter.
//! * [`command`]: the clean environment and the command vector both build.
//! * [`target`]: the proof that a sandbox may host a tool that runs with a bypass flag.
//! * [`probe`], [`prompt`], [`report`], [`skills`], [`home`], [`io`]: what the two share.

pub mod claude;
pub mod codex;
pub mod command;
mod digest;
pub mod future;
pub mod home;
pub mod io;
pub mod probe;
pub mod prompt;
pub mod report;
pub mod skills;
pub mod target;
mod toolspan;

pub use claude::{ClaudeCodeConfig, ClaudeCodeRuntime};
pub use codex::{CodexConfig, CodexRuntime};
pub use io::RunIo;
pub use skills::{PinnedSkill, SkillBundle, SkillFile};
pub use target::{TargetRefusal, VerifiedTarget};
