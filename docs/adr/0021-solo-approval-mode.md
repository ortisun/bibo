# 0021: The solo mode: the one approver may approve their own request

- Status: **Decided by the owner** (design "Aprovação solo, definition of done e PR legível", section 6, Slice A; the owner's instruction of 2026-11-20 not to add other users). Built on the branch `fix/agent-report-channel`. No independent review has covered it.
- Date: 2026-11-20
- Deciders: the owner. The engineer wrote the code from the owner's design.
- Amends: the value of `separation_of_duties.approver_may_equal_requester_when_low_risk` in `policies/approval.yaml` (from `true` to `false`), and the rule "the approver is not the requester" of guard `G_APPROVER_AUTHORIZED` for the case below.
- Related: [ADR 0009](0009-operating-defaults-pending-confirmation.md) item 5 (authority from the named allowlist), finding REG-6 (the `single_maintainer` registration), threats T-23, T-29 and T-30.
- Numbering: the design reserved 0020 for this record; 0020 was taken by the subscription mode in the meantime, so this is 0021 (rule 6 of the README keeps the numbers monotonic).

## Context and problem statement

"Nobody approves their own request" lived in four layers: the policy's separation of duties, the approval stage's judge, the engine's guard and the quorum. The engine refused the requester in every tier; the policy allowed the requester at low risk; and the specification approval, the decisions on a dependency, on build code and on a translation warning refused the requester outright.

The owner works alone and will not add other users. In the real end-to-end run E1 the owner files the issue, so the owner is the requester, and is the only approver. The specification draft approval was refused (`approval_granted_or_rejected.denied`, then `decision.rejected` "The person may not take this decision now."), and the pull request approval at the end would be refused too. The job could never finish.

## Decision

**A solo fact, computed in one place.** `AuthorityPolicy::solo_fact(single_maintainer, approver_count)` holds when the policy's switch `solo_mode.enabled` is on, the repository is marked `single_maintainer` (set at registration, REG-6), and exactly one active person of the tenant holds an approving designation (`approver` or `security_approver`) on that repository. An `approver` and a different `security_approver` are two people. The count is the one counter of people that the registration already used (`count_active_people`, which `single_maintainer_is_possible` now calls). The API, the worker's hook, the approval stage and the engine all ask the same function (the engine through `SoloRules::fact`, which `solo_fact` delegates to).

**Who may decide alone.** `separation_of_duties` is now specific to the action:

| Action | Requester as approver |
|---|---|
| `approve_pr`, `freeze_specification`, `add_new_direct_dependency`, `approve_build_code`, `acknowledge_documentation_warning` (`SOLO_ACTIONS`) | refused with `SelfApproval`, except with the solo fact; then authorized and the proof (`AuthorizedApproval`) carries the **solo stamp**. The exception passes over the change's conditions and the security approver's own rule (the one security approver is the requester). |
| `reject_or_request_rework`, `pause_or_resume_job`, `cancel_job`, `waive_failed_gate`, the autonomy changes | the rule of before: allowed when no condition of the change, of the tier or of the security approver applies; the solo fact is ignored. The requester keeps rejecting, reworking, pausing and cancelling their own job at low risk; nobody waives a gate of their own request. |

The designation the action needs is still needed: a critical pull request, build code and a package younger than the minimum age need `security_approver`. The factory never grants one: the owner chooses their own designations on the allowlist.

**The engine checks again at commit.** `Decision::Approve` carries the proof. The engine accepts the requester only with a stamped proof of the acting person (numeric GitHub id) for that stage's action, and reads the facts again in its own transaction: the switch of the policy it runs under (`EngineConfig::solo`), the `single_maintainer` mark (`tx.get_repository`) and the count of approvers (`Authority::approver_count`, a new read of the engine's seam). `check_person` (dependency, warning, build code) does the same and also checks the wait and the phrase (`EngineError::SoloRefused`, audited as `approval_granted_or_rejected` denied).

**Wait and phrase for the riskier decisions.** In whole minutes from the policy (`solo_mode.minimum_wait_minutes`, each 1 to 1440): 10 for a high pull request, 30 for a critical one, 10 for a dependency, 10 for a translation warning, 30 for build code. The wait runs from the `occurred_at` of the stage run's last `stage_run.waiting_for_human` (pull request, warning) or `stage_run.blocked` (dependency, build code) event, which the `Timeline` now keeps, up to the time the database wrote the signed request. A request exactly one wait after the milestone passes. A missing milestone refuses (`solo_delay`): the wait cannot be shown. The phrase is `I confirm the solo approval of <target>`, the target made of typed fields only (`PR <n> at level <tier>`, `dependency <name> <version>`, `build code <name> <version>`, `build code <path>`, `translation warning <n> of job <8 hex>`). It is compared after an ASCII-only normalization and carried as a 16-hex-digit SHA-256 word (`confirm=`) at the end of the signed subject, so the API's MAC covers it and the audit log never holds the text. The specification and a low or medium pull request need neither.

**Quorum.** One approval at every tier in the solo mode (`required_approvals(tier, solo)`); the critical tier's count still counts only `security_approver`s.

**Immediate refusal.** The API runs the same `authorize_action` with the facts it has and answers `409` at once, before recording anything, to the requester who holds the designation: `ineligible_approver` with `reason` (the first of `solo_mode_disabled`, `not_single_maintainer`, `more_than_one_approver`, `designation_missing`), `needed_designation` and `approvers`; or `confirmation_missing` with `expected_confirmation`. Anybody else gets what they got before (the silent `403`). The worker's reasons gain `solo_delay`, `confirmation_missing` and `ineligible_approver` (no longer folded into "not authorized": whoever reaches that point is on the list with the role).

**Audit.** `approval.recorded` says `basis=solo` when the proof carries the stamp, read from the stamp and never from the equality of ids.

**The switch is on in the shipped policy.** `solo_mode.enabled: true`. The per-repository limit is the `single_maintainer` mark plus the count of approvers, both set by the owner. A project policy may switch the mode off or lengthen a wait, never switch it on, shorten a wait or change the template (NT-POL-02 table).

## Options considered

| Option | Why not chosen |
|---|---|
| A. Two GitHub accounts for one person (the second allowlist entry of commit `02b8ec9`) | Separation of duties would hold only on paper, with no wait, no phrase and no record that the requester approved; the owner refused to add users. Kept as an option: a second approver still works and ends the solo mode. |
| B. Keep `approver_may_equal_requester_when_low_risk: true` and widen it | The engine refused the requester at every tier anyway; in Rust a change to `Cargo.toml` is a new dependency, which forces the high tier, so the job would stay in APPROVAL with no way out. |
| C. Solo mode for the pull request and the specification only | VALIDATION blocks on a new dependency the one person may not decide on, and the job never reaches APPROVAL. |
| D. Solo mode for all but the critical tier | Every change to a protected path is critical, so a person alone could never finish one. |
| E. Authority from CODEOWNERS or branch protection | Contradicts ADR 0009 item 5: the allowlist is read only from protected configuration, never from the target repository. |
| F. A second aggregating function for the API and the worker | Duplicates the stage's pure `judge`; the API has no pull request host and no wait milestone, so it would compute different facts. Extending `Refusal` and asking `authorize_action` gives one rule. |
| G. Ship the switch off, as the design proposed, and let the owner turn it on | The owner asked that E1 pass approvals with their one allowlist entry. A disabled switch fails every run until a protected file is edited. Since the mode needs the owner's own `single_maintainer` mark and a single approver, switching it on centrally changes nothing for a tenant with two approving people. Chosen: on, with the mark and the count as the limit. |
| H. Count approvers by a second, solo-specific counter | Two counters could disagree about who is "active" (disabled principals, service accounts). The one counter of REG-6 is reused. |
| I. Read the wait milestone through a new port | The engine already reads every job event in the outbox (`Timeline`); keeping the newest `blocked`/`waiting_for_human` time there needs no port. Its cost: if old events are ever archived, the milestone is missing and the solo decision is refused (fail closed). |
| J. Carry the phrase text in the signed subject | The subject is space-separated and capped at 500 characters; a phrase has spaces and the audit log would keep the text. A 16-hex-digit word fits every grammar (the project build code path is capped at 170 bytes when the word is present: 382 - 10 + 25 + 103 = 500). |

## Consequences

- A compromised account of the one approver approves everything, including new packages and build code. Only the wait, the phrase and the `security_approver` requirement stand in the way, and they defend against haste and mistakes, not against bad faith (threat model T-23, T-29, T-30). The PR phrase is not a secret.
- `Authority` (the engine's seam, `crates/workflow/src/commands/authority.rs`) gains `approver_count` with no default body. Every implementor changed in the same commit ([ports 16.7](../architecture/ports-v1.1.md)).
- The approval of a specification by the requester now goes through the policy's action row `freeze_specification`, whose `min_level` is L1: a repository at L0 (no passed protection preflight) cannot finish a solo specification approval. A pull request approval needed L1 already, so a run at L0 could not finish either way.
- `held_the_engine_refuses_the_requester_as_approver`, `nobody_approves_their_own_request` and the other tests that refuse the requester still pass: outside the solo mode, and with a proof without the stamp, nothing changed.
- Out of scope here (design sections 5, 7, 8 and Slice B): the PR panel and `pr_panel_state` (the wait of a pull request counts from WAITING_FOR_HUMAN, the documented fallback), the definition of done, and the GitHub review channel.
- Rollback: set `solo_mode.enabled: false`, wait until no signed request is pending, then roll back the binaries. The worker reads both the old six-word subjects and the new seven-word ones, so deploy the worker before the API.
