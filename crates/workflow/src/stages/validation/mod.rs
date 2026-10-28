//! The validation stage: "it passed" becomes evidence that the factory measured itself.
//!
//! The builder's work is verified in a **fresh** verify container made for this stage run, from
//! gate definitions read from the **base** commit of the protected branch, and the result is the
//! supervisor's own observation of each command. This is the trusted-gate rule of the master
//! requirement, section 8, and `gate_integrity` in `policies/security.yaml`.
//!
//! # The order of a run
//!
//! 1. The contract binds the run to the hash of the implementation result and the hash of the
//!    policy bundle ([`contract`]).
//! 2. The control plane reads the change from the object store on the host: the changed paths,
//!    both versions of each file and the patch headers ([`gather`]). The sandbox that built the
//!    change is gone.
//! 3. The host-side rules run: protected paths, test protection, secret scan ([`host`]). **A
//!    change that any of them refuses never reaches a sandbox.**
//! 4. The command gates run in a fresh `verify` sandbox over a read-only workspace of the
//!    candidate commit, then the test gate runs again on the base commit as the baseline
//!    ([`sandboxed`]). Tool versions are probed first; a missing tool blocks the gate.
//! 5. One report is built for each gate ([`set`], [`assemble`]) and written, with the evidence
//!    binding ([`binding`]), as the deliverable `validation-evidence`.
//! 6. `evaluate` reads the stored deliverable back, recomputes the binding from independent
//!    sources, adds the `evidence-binding` report and hands the reports to the engine, which
//!    decides with `resolve`.
//!
//! # What is evidence and what is not
//!
//! | Evidence | Not evidence |
//! |---|---|
//! | The exit code, signal, timestamps and redacted streams that the supervisor returned from `exec` | Any file in `/out` or in the workspace that the sandbox wrote |
//! | The committed trees read by `JobRepo` | The builder's account, its transcript or its report |
//! | The gate definitions at the base commit | Any gate definition in the candidate commit |
//!
//! # What this does not defend against
//!
//! * A test that takes over the output device and prints a whole, coherent libtest report, then
//!   exits with code 0. The reading rejects forged lines, a forged summary and counts that do not
//!   add up, but a report that adds up is a report. A stronger defence is a trusted test runner
//!   in a separate process; it is not in this slice.
//! * Task scope (`path_access.write_scope_source`): the owned files of the task come from the
//!   plan, which this stage does not read, so the scope rule is the policy's `write_allow` only.
//!
//! # Interfaces this stage needs from the others
//!
//! * The implementation stage names the commits in the deliverable `implementation-result`
//!   (`{"base_commit": "...", "head_commit": "..."}`), written from the commit that
//!   `Workspace::commit` returned.
//! * The specification stage's deliverable is `specification-contract`.
//! * The artifact store given to the stage must let the handler read what the supervisor and the
//!   workspace stored in this attempt. With the production store, which reads only a hash the
//!   tenant has indexed, the composition root must index at write time, or the gates that read
//!   test output and the patch are `BLOCKED` (they fail closed).

mod assemble;
mod binding;
mod config;
mod contract;
mod gather;
mod handler;
mod host;
mod input;
mod sandboxed;
mod set;

pub use binding::Binding;
pub use config::{
    Bounds, JsonManifestReader, ManifestReader, ManifestRejected, ValidationConfig, VerifySandbox,
};
pub use contract::{EVIDENCE, GATES, POLICY_INPUT};
pub use handler::ValidationHandler;
pub use input::{IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT};
