# The control plane: screens and who acts on them

- Status: proposed with [ADR 0031](../adr/0031-control-plane-design-system.md), 2026-11-20. No screen is built; the [reference page](../../design-system/reference/index.html) shows four of them with example data.
- Readers: whoever designs or builds the dashboard of Slice 4.

The control plane is the screen form of what `factory-cli` and the API already do. It adds no power: every action below is a verb of the [command reference](../reference/commands.md), with the same designation and the same refusal codes. What it adds is the overview a person needs to decide well, and the patterns of [security-patterns.md](security-patterns.md) that make a wrong decision hard.

## Navigation

The side navigation has three groups, in the order a person on duty needs them.

| Group | Screen | What it answers | Who acts there |
|---|---|---|---|
| Work | **Overview** | Is the factory healthy, what waits for me, is anything on fire? | Anyone may read. |
| Work | **Decisions** | Every stage run in `WAITING_FOR_HUMAN`, oldest first, with what it waits for. | Approver, security approver, the job's requester (answers). |
| Work | **Jobs** | Every job, its state, its stage, its repository and its age. A job page shows the pipeline, the gates, the timeline and the artifacts. | Operator (pause, resume, cancel, unblock). |
| Assurance | **Evidence ledger** | The hash-chained audit log, its last verification, and a search by job, actor or verb. | Anyone may read; nobody may change it. |
| Assurance | **Gates and policies** | Which gates exist, which policy hash is loaded, which threats each gate covers. | Read-only; policies change through the protected branch. |
| Assurance | **Sandbox and egress** | Image digests in use, sandbox posture checks, egress denials by job. | Read-only. |
| Administration | **Repositories** | Registered repositories, their map commit, enablement, autonomy ceiling and the stop switch. | Operator (register, confirm map, disable), approver (enable). |
| Administration | **Credentials** | Every credential the factory holds, by fingerprint, owner, expiry and last use. Rotation follows the runbooks. | Organisation administrator. |
| Administration | **Access** | People, their designations, their authenticators and their active sessions. | Organisation administrator; each person for their own sessions. |
| Administration | **Troubleshooter** | Findings of the troubleshooter (ADR 0021) and the issues they opened. | Read-only here; triage happens on the issue. |

## The overview

The overview is read in this order, top to bottom:

1. **Incidents first.** A critical callout when the audit chain failed verification or was not verified in the last day, when the worker is not ready, or when a repository was stopped. Nothing appears here unless a person must act.
2. **What waits for you.** The decisions that need the person's own designation, with their age.
3. **Posture.** Four figures: jobs active, jobs waiting for a person, jobs blocked, gate pass rate over seven days. Then the model budget meter of the day and the last chain verification.
4. **Recent jobs.** A table of the latest jobs with their state pill and their current stage.

## A decision

The page of a decision is the most sensitive screen. Its layout is fixed:

- **Left, wide:** what is being decided, in the factory's own words (the specification draft, the pull request summary, the dependency and its version). Below it, every outside text in an untrusted-content frame: the issue as the requester wrote it, the questions and answers.
- **Right, narrow and sticky:** the gate list, then the decision panel with the binding (head commit and evidence digest), the reason field, the separation-of-duties notice and the buttons. Approve asks for step-up.
- **Below:** the job's timeline, so the person sees what happened before.

When the evidence changes while the page is open, the decision panel turns stale and disables itself (security pattern 2).

## A repository

The repository page shows its registration (installation, GitHub numeric id, default branch), the map commit and who attested it, whether it is enabled and by whom, the autonomy ceiling, the rule about the enabler (strict or single-maintainer), the jobs of the repository, and the stop switch. Enabling shows the separation-of-duties notice when the person is the attestor.

## What the screens never do

- Show a secret, a raw log line outside an untrusted-content frame, or an image from a job.
- Offer an override, a "force" or a "skip".
- Change state on a page load or a `GET`.
- Decide something the API would refuse. If the screen and the API disagree, the API is right and the screen has a defect.
