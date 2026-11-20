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
//! 5. The four dependency and supply chain reports are made by [`supply`], after the command
//!    gates and in their own sandboxes, for a change every host-side rule let through. A change
//!    that touches no dependency file gets four `NOT_APPLICABLE` reports and costs nothing; a new
//!    direct dependency with no recorded decision makes `dependency-review` `BLOCKED` and stops the
//!    stage run for a person; a scanner or an advisory database that is missing, or too old,
//!    blocks. A failed or blocked dependency gate fails the stage like any other gate.
//! 6. One report is built for each gate of the command catalog ([`set`], [`assemble`]) and all
//!    of them are written, with the evidence binding ([`binding`]), as the deliverable
//!    `validation-evidence`.
//! 7. `evaluate` reads the stored deliverable back, recomputes the binding from independent
//!    sources, adds the `evidence-binding` report and hands the reports to the engine, which
//!    decides with `resolve`.
//!
//! # Why the contract says the placement is not applicable
//!
//! The engine fails a stage that declares a sandbox placement and never reports a ready sandbox.
//! This stage may legitimately never create one: a change that a host-side rule refuses must not
//! reach a container. The posture of each sandbox the stage does create is still checked, by the
//! port: `SandboxProvider::create_verified` returns a session only for a container that matches
//! its spec and the policy, and a sandbox that cannot be created blocks the stage run
//! (`StageError::Environment`, rule `S21`) instead of running anything on the host.
//!
//! # What is evidence and what is not
//!
//! | Evidence | Not evidence |
//! |---|---|
//! | The exit code, signal, timestamps and redacted streams that the supervisor returned from `exec` | Any file in `/out` or in the workspace that the sandbox wrote, with the one exception below |
//! | The committed trees read by `JobRepo` | The builder's account, its transcript or its report |
//! | The gate definitions at the base commit | Any gate definition in the candidate commit |
//!
//! The exception is the test report file of a test gate whose manifest entry names one
//! (`test_report.path`, a JUnit XML or TAP report). The test runner writes that file in `/out`,
//! and the supervisor reads it back with a command of its own (`cat`) in the same sandbox, right
//! after the test command. What that command printed is a redacted stream like any other, it is
//! listed in the gate report, and it is read as untrusted input by a strict reader
//! (`gates::command::junit`, `gates::command::tap`). It has the same standing as the standard
//! output of `cargo test`, which is also text that the test process wrote. No other file that the
//! sandbox wrote is read.
//!
//! # What this does not defend against
//!
//! * A test that takes over the output device and prints a whole, coherent libtest report, then
//!   exits with code 0, or a test that writes a whole, coherent report file over the one its test
//!   runner writes. The reading rejects forged lines, a forged summary and counts that do not add
//!   up, but a report that adds up is a report. A report file is easier to replace than an output
//!   stream, because any process of the test run can write it, including one left behind by an
//!   earlier gate in the same sandbox. A stronger defence is a trusted test runner in a separate
//!   process; it is not in this slice.
//! * A covering test that asserts nothing. `acceptance-evidence` counts a test for a requirement
//!   when the test names it, passes on the candidate and did not pass on the baseline run. It
//!   does not read the test. See `gates::scope::acceptance` for what that leaves open.
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
mod supply;

pub use binding::Binding;
pub use config::{
    Bounds, DependencyReadLimits, JsonManifestReader, ManifestReader, ManifestRejected,
    RunSupplyChain, SupplyChainSeams, SupplyChainSettings, ValidationConfig, VerifySandbox,
};
pub use contract::{EVIDENCE, GATES, POLICY_INPUT, SUPPLY_CHAIN_GATES};
pub use handler::{ValidationHandler, current_values, evidence_document};
pub use input::{Candidate, IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, parse_candidate};
