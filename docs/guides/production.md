# Before a live run: what must exist, and what the reviews found

- Status: written on 2026-10-29 from the [acceptance report](../reports/slice-1-acceptance.md), the [findings](../reports/slice-1-findings.md), the [slice plan](../architecture/slice-plan.md), the independent reviews and the architecture decision record (ADR) [0009](../adr/0009-operating-defaults-pending-confirmation.md). Nothing here describes a deployment, because none exists. The factory has never run against a real model, a real GitHub App or a protected repository.
- Form: how-to guide (a checklist) and explanation (the security posture).
- Goal: list what a person must supply and decide before the first live job, and say what the reviewers found, what was fixed and what stays open.

## What "live" means, and why it is blocked

A live run uses real adapters for the model and for GitHub. The acceptance scenarios E1 and E2 are the live runs. They are BLOCKED today. The worker binary passes its start-up checks, prints one `BLOCKED:` line for each adapter that does not exist, and exits with code 3. It claims no job. See the [command reference](../reference/commands.md) for the lines.

Everything that was run so far was run in test mode, with a scripted agent runtime and labelled fakes for the sandbox and for GitHub. No document may present those results as a live result.

## Checklist of what only a person can supply

Each row names the work that stays blocked without it. Tick a row only when you can show it.

| Needed | Why | Where it is defined | Who acts |
|---|---|---|---|
| API keys for the model providers, one for each provider, each with a provider-side hard spend limit, and a written approval of a live smoke budget | The agents run behind a broker that holds the real keys. A subscription login cannot be brokered or metered. | [Slice plan](../architecture/slice-plan.md), sections 2 and 14; [ADR 0009](../adr/0009-operating-defaults-pending-confirmation.md) | A person creates the keys and the limit. |
| A registered GitHub App with the permissions in [secrets and credentials](../security/secrets-and-credentials.md), section 3.1, its identifier and its private key file | Per-job installation tokens, narrowed to one repository, need the App. The issue source and the change host are BLOCKED without it. | The same document; `github.app_id` and `github.key_file` in the [configuration reference](../reference/configuration.md) | A person registers the App. |
| A fixture repository on GitHub with a branch-protection ruleset | A repository that fails the protection preflight runs at level `L0` and opens no pull request. | [ADR 0009](../adr/0009-operating-defaults-pending-confirmation.md); `policies/security.yaml`, `credentials.repository_requirements` | An organization administrator. |
| A statement that the App is on no bypass list, with a production source for it | The source does not exist. `NoAttestations` fails closed, so every repository stays at `L0` until a source exists. | Worker README, item 36 of the cross-stage mismatches | The architect and the security owner decide where the statement comes from. |
| The named requester allowlist in the protected checkout, by numeric GitHub identifier | Only a listed requester can start a job. A designation comes only from this file. | `allowlist/allowlist.yaml`; the format is in the [composition README](../../crates/composition/README.md) | A person names the people. |
| A second code owner in `.github/CODEOWNERS` | Only one owner is listed. GitHub cannot count the owner's approval of their own pull request, so a protected change by the only owner has no second reviewer. | [`.github/CODEOWNERS`](../../.github/CODEOWNERS) | A person adds a second owner or a team. |
| A rebuilt and tested agent image, with its new digest in `infra/sandbox-images/images.json` | The image was pinned before its recipe changed (findings RR-14, SBX-4 and IMG-1). The review tested the old image. | [Isolation re-review](../reviews/isolation-core-security-rereview.md); `infra/sandbox-images/test.sh` | A person with Docker rebuilds it. |
| `policies/model_routing.yaml` | The file does not exist, so the model router is BLOCKED. | [Policy reference](../reference/policies.md) | A person writes it, and the architect confirms it. |
| Real owners in the fixture's `CODEOWNERS` | `fixtures/repos/word-count/CODEOWNERS` lists placeholder handles. | The findings, open items | A person. |
| The decision signing key, the secret files and their modes | The production profile does not start without `decisions.key_file`. A secret file must be a regular file, not a link, not readable by group or others. | [Configuration reference](../reference/configuration.md); [rotate the decision key](../runbooks/rotate-the-decision-key.md) | An operator. |
| TLS and a reverse proxy in front of the API | The API serves plain HTTP. It was tested on loopback only. | [API README](../../apps/api/README.md) | An operator. |
| Backups, and a restore drill on the real stack | A backup is not encrypted. The drill passed on a laptop. | [Backup and restore](../operations/backup-and-restore.md); [restore runbook](../runbooks/restore-from-backup.md) | An operator. |
| Confirmation of the nineteen defaults of ADR 0009 and of the port proposals the reviews depend on | The architect has not confirmed them. | [ADR 0009](../adr/0009-operating-defaults-pending-confirmation.md); the findings, open items | The architect. |
| The composed wiring program that the harness calls `FACTORY_E2E_COMPOSED` | E1 and E2 need it to drive the real adapters. It does not exist. | [Worker README](../../apps/worker/README.md), "The end-to-end `Wiring`" | An engineer. |

The constitution of this repository, `.specify/memory/constitution.md`, carries the ratification date 2026-10-27. That is the date it was written. A person has not ratified it yet, as the [worked example](../spec-kit/worked-example.md) notes. A person must.

## Settings to review before the first job

- **Budget.** `stages.budget.max_cost_usd` defaults to 10.0 dollars for each stage run, and a job has up to 13 stage runs, more after rework. That is far above a small smoke budget. Lower it, and rely on the provider-side limit as the hard stop. The broker refuses a model that has no entry in `broker.prices`.
- **Autonomy level.** The default level is `L1`: the factory makes branches and draft pull requests, and a person decides every promotion. Do not raise it. Raising a level needs an `org_admin`.
- **Tenants.** `worker.tenants` is empty by default. An empty list means the worker admits no received job.
- **Profile.** Run `production`. It refuses a fake for any port. The scenario E9 shows that refusal for the API's ports (six, and a seventh when it has an artifact root) and the worker's ports, in test mode.
- **Docker daemon.** The worker starts the `docker` client with an empty environment, so a `DOCKER_HOST` in the worker's environment is ignored. Name the daemon in the configuration: `sandbox.docker_host` (a `unix://` socket path, or a `tcp://` address on the loopback interface) and, if the client's own configuration is not at its default place, `sandbox.docker_config` (an absolute directory). `sandbox.allow_remote_docker: true` lets the host be a `tcp://` address off the loopback interface, and the `production` profile refuses it: a daemon reached over a network gives whoever sits on that network the control of every container. A value that fails these rules stops the worker at start with a line that begins with the key. See the [configuration reference](../reference/configuration.md#sandbox).
- **First job.** Run it at `L1` with a person reading the audit log. Check that every `decision.applied` and `decision.rejected` row was written by the worker's decision step and carries the allowlist hash. This is condition 9 of the re-review.

## Before a second tenant

One tenant is the only shape this guide supports. Registration trusts what an operator types: the installation number, GitHub's repository id, the name and the branch. Nothing looks at GitHub. With one tenant that is a risk of mistakes. With two it is a way to take another tenant's repository or to bind its webhooks.

These five things are hard preconditions for a second tenant. Do not onboard one before all five exist.

1. **Check the registration against GitHub.** The engine asks GitHub, with an installation token, that the repository id exists, that the installation lists it, and what its full name and default branch are. It stores GitHub's values and not the typed ones.
2. **Bind each installation to its tenant at install time.** The person who installs the App makes the binding, and the platform writes it. An operator does not type it.
3. **Key the repository on the pair.** Today the key is the GitHub repository id alone, so one wrong registration blocks the real owner for good. The key must be the installation and the repository id together.
4. **Add a way to unregister and to transfer.** Today nothing removes or corrects a registration, and only a database administrator can free an id. The path needs a designation of the platform.
5. **Stop the answer from revealing whether an id exists.** A `409` on `repository register` tells an operator of any tenant that the GitHub repository is registered somewhere. The answer must be the same for an id that is free and one that is taken.

The credential for a repository comes from `github.installations` in the protected configuration, not from the registered row. A second source of truth is a risk until the verified binding replaces the static list or is checked against it.

## What the reviews found

Four independent security reviews, two re-reviews, a database review and an architecture review exist. Reviewers did not fix what they reviewed. The table gives each verdict as the reviewer wrote it, and the later re-review where there is one.

| Review | Verdict | What remains |
|---|---|---|
| [API security review](../reviews/api-security-review.md) | Pass with conditions. 13 defects confirmed, 13 probes held. | Conditions: close API-1, API-3 and API-4 before any other person gets a token, and API-6 or compensate at the proxy. The re-review found API-1 holding, API-3 and API-4 partly closed, and API-6 holding for IPv4 and partly closed beyond it. |
| [Authority and evidence security review](../reviews/authority-and-evidence-security-review.md) | Pass with conditions. No high finding. 11 defects confirmed. | See the re-review below. |
| [Supply chain and delivery security review](../reviews/supply-chain-and-delivery-security-review.md) | The gates failed with three high findings. The policy contradictions and the delivery boundary passed with conditions. | The fixes were merged and re-reviewed. The re-review attacked this area less than the others. |
| [Re-review of the authority, API and supply chain fixes](../reviews/authority-api-supply-chain-security-rereview.md) | Pass with conditions in all four areas. 22 defects confirmed in 45 tests. | Section 8 lists nine requirements for the first live run. They are summarized below. |
| [Isolation core security review](../reviews/isolation-core-security-review.md) | Egress failed. Sandbox and runtimes passed with conditions. Prompt assembly passed. Images were not fully reviewed. | Fixed, then re-reviewed. |
| [Isolation core re-review](../reviews/isolation-core-security-rereview.md) | Pass with conditions for the egress schema, the relay ranges, the runtime success rule and the sandbox deny list. The image tooling failed on one point, the signature check in `check-pins.sh`. | The image must be rebuilt, and hypothesis RR-13 about names that print blank is open. |
| [Database review](../reviews/database-review.md) | At 100,000 rows in each hot table, with row-level security forced, every measured query is inside its budget. The numbers are relative, from one laptop. | A retention and partitioning proposal waits for a person. |
| [Architecture review of the foundation](../reviews/architecture-foundation-review.md) | Changes required at the time of the review (2026-10-27), and the tag `ports-v1` was a no-go. | ADR 0014 revised the ports after it. Read the review for what was open. |

### What the re-review requires before the first live run

1. **Decision channel.** Close RR-8 and RR-21, or record them as accepted with an owner and a date, and keep the API database login out of every hand but the builders'. The records that end a request are not authenticated, and junk records can starve real ones.
2. **Lint rule.** Do not count the `lint_relaxation` rule as a control until RR-11 to RR-13 are closed. Put code owners on every `Cargo.toml`, `lib.rs`, `main.rs`, `mod.rs` and `build.rs` the factory may touch.
3. **Profile check.** Give the dependency sources, the bypass attestations and the eight silent seams a fidelity before any adapter exists for them (RR-6, RR-7).
4. **Override.** Wire no override verb until RR-18 is closed. None is wired.
5. **Dependency decisions.** Pass the job's real requester into the proof and add the engine-side comparison (RR-24).
6. **Repositories.** Do not onboard a repository that vendors its crates (RR-16). Do not let a narrowed allowlist entry outlive a rename or a transfer (RR-28).
7. **Secret patterns.** Port the new URL pattern to `.gitleaks.toml` (RR-22), and extend the runtime pattern for RR-1 to RR-4 before agent logs reach a person.
8. **A throwaway repository.** Render the RR-19 and RR-20 vectors and look at them. Time an author's edit after a label (RR-23).
9. **The first job.** See the settings above.

### What held

The reviewers found no way to approve, merge or mark a pull request ready without an authorized person. They found no way to forge a signed decision without the key, to read the key from the database, or to move an approval to another head, base branch, tenant or verb. The token design, the webhook verification and the tenant isolation held against everything tried. The factory has no merge method and no deploy path.

### What is open, and why

- **Open findings.** The [findings of the end-to-end run](../reports/slice-1-findings.md) list SF-01 to SF-08. SF-01 is High: an unauthorized label leaves no audit record of the rejection and no explanation on the issue. A live run would show the same behaviour. Settle it first.
- **Hypotheses.** RR-13, RR-23, RR-28 and the hypotheses H-1 to H-8 of the supply chain and authority reviews were not confirmed or refuted.
- **Not verified at all.** A real GitHub delivery, a deployment behind a proxy, the container images of the services, load above the rate limits, and everything that needs a real model.
- **Shared symmetric key.** A compromised worker can forge a decision request, because it holds the key that verifies. An asymmetric signature would remove that and add a dependency.
- **The API database login can change repositories.** Whoever holds its credentials can register, attest and enable repositories and write the matching audit records, with no signed request (finding REG-2 of the [registration review](../reviews/engine-registration-and-status-security-review.md)). Keep that credential in the builders' hands until the product owner decides between a signed request, a function owned by another role and acceptance.

## Other guidance

- Keep the API on a loopback address or a private network, behind a proxy that terminates TLS. The API reads the TCP peer as the source address and never reads a forwarded header. Behind a proxy every client counts as the proxy, so set `limits.max_connections_per_source` to `limits.max_connections` and cap clients at the proxy.
- Keep the protected checkout read-only to the processes that read it, outside every job workspace.
- Treat every BLOCKED line as missing evidence. Do not turn one into a pass to reach a deadline.
- The factory writes pull request text and documents that a person reads. Keep that person in the loop. The factory never merges.

## Related

- [Quickstart](quickstart.md): the test-mode run on a developer machine.
- [Runbooks](../runbooks/README.md): the situations that exist today.
- [Threat model](../security/threat-model.md) and [sandbox policy](../security/sandbox-policy.md).
