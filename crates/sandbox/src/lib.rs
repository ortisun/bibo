//! The Docker sandbox with its posture verifier and supervisor, and the host-side checkout
//! workspace. It is the only crate that starts containers or runs the version-control tool.
//!
//! * [`process`]: the one file that starts a host process, behind the `ProcessRunner` port.
//! * [`container`]: the typed `docker` client, the image catalog, the allow-list mapping from a
//!   `SandboxSpec` to `docker create` arguments, the posture verifier, and the job token file.
//! * [`workspace`]: the host-side git workspace: the job's object store, the attempt's checkout,
//!   and the audit and ingestion of what the sandbox wrote.
//! * [`supervisor`]: `DockerSandboxProvider` and its sessions: create, inspect, compare, start,
//!   self-check, run, enforce the wall clock and the disk cap, tear down, and sweep orphans.

pub mod container;
pub mod process;
pub mod race;
pub mod supervisor;
pub mod workspace;

pub use process::SystemProcessRunner;
pub use supervisor::{DockerSandboxProvider, ProviderConfig, WatchdogSettings};
pub use workspace::{GitWorkspaceProvider, WorkspaceSettings};
