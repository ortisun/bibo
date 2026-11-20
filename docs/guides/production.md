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
| The owner's Claude subscription token, made with `claude setup-token` and saved as one line in a file of mode 0600 (for example `~/claud-oauth-token.txt`), named by the `anthropic` entry of `broker.upstreams` | The agents run behind a broker that holds the real credential. By default that is the owner's subscription (ADR 0020): no provider API key and no provider-side spend limit is needed, and spend is bounded by the factory's own ceilings and the plan's limits. The worker refuses to start in subscription mode without a usable token, and names the problem. Codex is unavailable in this mode. For both tools, set `credentials.model_providers.mode: api_key` and supply an API key with a provider-side spend limit for each provider instead. | [ADR 0020](../adr/0020-subscription-mode-by-default.md); [secrets and credentials](../security/secrets-and-credentials.md), section 4 | The owner. Then run the live check named in ADR 0020. |
| A registered GitHub App with the permissions in [secrets and credentials](../security/secrets-and-credentials.md), section 3.1, its identifier and its private key file. The repository permissions are Metadata read, Contents write, Pull requests write, Issues write, Checks write, Commit statuses write, Actions read and Administration read, each at exactly that level; Administration read was added on 2026-11-12 so that the protection preflight can read classic branch protection | Per-job installation tokens, narrowed to one repository, need the App. The issue source and the change host are BLOCKED without it. An App that holds a permission above its level, or a forbidden one, is refused. An App without Administration read cannot read classic branch protection, and every repository is capped at level `L0` with that reason. | The same document; `github.app_id` and `github.key_file` in the [configuration reference](../reference/configuration.md) | A person registers the App. |
| A fixture repository on GitHub with a branch-protection ruleset or classic branch protection (the preflight reads both and judges the stricter of the two) | A repository that fails the protection preflight runs at level `L0` and opens no pull request. | [ADR 0009](../adr/0009-operating-defaults-pending-confirmation.md); `policies/security.yaml`, `credentials.repository_requirements` | An organization administrator. |
| A statement that the App is on no bypass list, as an entry of `github.bypass_attestations` | The App does not judge the bypass lists: a ruleset's list is not in the rules it reads, and the preflight does not judge the bypass allowances of classic protection. Without an entry for the repository the protection preflight caps it at level `L0` and no pull request opens. An entry has no expiry and no audit record of its own, so remove it when the statement stops being true. | `github.bypass_attestations` in the [configuration reference](../reference/configuration.md) | An organization administrator makes the statement, and the operator records it in the configuration. |
| A valid `.factory/project.yaml` on the protected default branch of the target repository | The validation stage reads its gate commands from this file at the base commit. Without it the `format`, `lint`, `build` and `unit-tests` gates are BLOCKED. The test gate reads the output of `cargo test`, or a report in JUnit XML (Extensible Markup Language) or in the Test Anything Protocol (TAP) that the manifest names, and only the first of these has run against a real tool. The supply-chain gate reads Cargo only. | [Prepare a repository](prepare-a-repository.md) | A maintainer of the target repository. |
| No workflow of the target repository gives a secret, a write token or a self-hosted runner to a `factory/*` branch, or a recorded acknowledgement of the ones that do | The factory pushes agent-written code to a `factory/*` branch of the same repository and opens a draft pull request. GitHub's documentation says that workflows started by `push` or `pull_request` from such a branch run with the repository's secrets, before a person has read the code. The protection preflight reads the workflow files of the default branch and caps the repository at level `L0` when one is exposed. It reads files and not settings, and this project has not exercised the GitHub behaviour, so confirm it on your repository as well. | Threat T-48 in the [threat model](../security/threat-model.md); the section below; `github.workflow_exposure_acknowledgements` in the [configuration reference](../reference/configuration.md) | The owner of the target repository, with a security approver. |
| The named requester allowlist in the protected checkout, by numeric GitHub identifier | Only a listed requester can start a job. A designation comes only from this file. | `allowlist/allowlist.yaml`; the format is in the [composition README](../../crates/composition/README.md) | A person names the people. |
| A second code owner in `.github/CODEOWNERS` | Only one owner is listed. GitHub cannot count the owner's approval of their own pull request, so a protected change by the only owner has no second reviewer. | [`.github/CODEOWNERS`](../../.github/CODEOWNERS) | A person adds a second owner or a team. |
| An independent test of the agent image whose digest is in `infra/sandbox-images/images.json` | The history of the repository records a rebuild with the hardened recipe on 2026-10-29 (commit `8533c86`) and a second rebuild on 2026-11-02 (commit `c5c10fd`). The commit messages say that the image rules passed. No review under `docs/reviews` records a test of the rebuilt image, and the review of 2026-11-03 says it did not cover it. | [Isolation re-review](../reviews/isolation-core-security-rereview.md); `infra/sandbox-images/test.sh` | A person with Docker runs the image tests on the recorded digest and writes down the result. |
| Confirmed numbers in `policies/model_routing.yaml` | The file exists, and the worker loads it at start-up. Its status is `designed` and every price is `unchecked`, so the `production` profile refuses to start with it as it is. Routing is a static table lookup. The keys `escalate_to` and `escalate_after_failed_repairs` are checked when the file is loaded, and nothing acts on them. | [Policy reference](../reference/policies.md#what-policiesmodel_routingyaml-controls) | The project owner reads each price on the provider's page, confirms the ceilings and the caps, and sets the status. |
| Real owners in the `CODEOWNERS` of the fixture's GitHub copy | `fixtures/repos/word-count/CODEOWNERS` lists placeholder handles on purpose. `scripts/setup-fixture-repository.sh` replaces them in the copy it pushes. One real owner is enough while `policies/approval.yaml` lets the approver be the requester for a low-risk change. | [The first real run](first-real-run.md), step 4 | The owner. |
| The decision signing key, the secret files and their modes | The production profile does not start without `decisions.key_file`. A secret file must be a regular file, not a link, not readable by group or others. | [Configuration reference](../reference/configuration.md); [rotate the decision key](../runbooks/rotate-the-decision-key.md) | An operator. |
| TLS and a reverse proxy in front of the API | The API serves plain HTTP. It was tested on loopback only. | [API README](../../apps/api/README.md) | An operator. |
| Backups, and a restore drill on the real stack | A backup is not encrypted. The drill passed on a laptop. | [Backup and restore](../operations/backup-and-restore.md); [restore runbook](../runbooks/restore-from-backup.md) | An operator. |
| Confirmation of the nineteen defaults of ADR 0009 and of the port proposals the reviews depend on | The architect has not confirmed them. | [ADR 0009](../adr/0009-operating-defaults-pending-confirmation.md); the findings, open items | The architect. |
| A first real run of E1 | `scripts/e2e-composed.sh` is the composed wiring program E1 and E2 need. It has not run against GitHub or the provider. In subscription mode the code review waits for a person and the job cannot get past it, so E1 cannot complete until the owner decides how the review is done. | [The first real run](first-real-run.md) | The owner. |

The constitution of this repository, `.specify/memory/constitution.md`, carries the ratification date 2026-10-27. That is the date it was written. A person has not ratified it yet, as the [worked example](../spec-kit/worked-example.md) notes. A person must.

## The target repository's own workflows

This item is required. Do not run a live job against a repository until it is done.

The delivery stage pushes the commit of a job to the branch `factory/job-<id>` of the target repository and opens a draft pull request from it. A model wrote that code, and the model may have followed hostile text in an issue or a file. The factory's gates ran it in a sandbox that holds none of the repository's secrets. The repository's own continuous integration is a second place where it runs, and the factory does not control that place.

GitHub's documentation says the following. This project has never pushed to a real GitHub repository, so none of it was exercised here.

- A workflow that starts on `push` or `pull_request` from a branch of the same repository receives the repository's secrets.
- A push made with the token of a GitHub App starts workflows.
- A draft pull request starts `pull_request` workflows.
- Secrets are withheld from workflows that a pull request from a fork starts.

The builder cannot edit a workflow file, because the path is protected. It does not need to. A test, a build script or a package script that an existing workflow already runs is enough.

Before the first live job, the owner of the target repository does all of the following and shows the result.

1. List every workflow that starts on `push` or `pull_request`, and every secret each one reads.
2. Move each secret that matters into an environment. Protect the environment with required reviewers, or with a deployment branch rule that leaves out `factory/*`.
3. Leave `factory/**` out of the `push` triggers. Set the default permissions of the workflow token to read-only.
4. Keep `factory/*` branches off self-hosted runners.
5. Push a harmless commit to a `factory/test` branch by hand, open a draft pull request, and read which workflows ran and what they could reach.

### What the factory checks, and what it does not

Before the jobs of a tenant are admitted, the protection preflight reads every workflow file of the default branch of the target repository (`.github/workflows/*.yml` and `*.yaml`) and marks a workflow as exposed when a factory branch or its pull request would start it with any of these in reach:

- a secret other than `secrets.GITHUB_TOKEN`;
- a `write` permission, or no declared `permissions` at all;
- a self-hosted runner, or a runner that the file does not name as one of GitHub's (`ubuntu-*`, `windows-*`, `macos-*`);
- the trigger `pull_request_target`;
- a call of a reusable workflow.

A workflow file that cannot be read or parsed counts as exposed. A job behind an `environment:` counts like any other, because the factory cannot read environment protection.

A repository with an exposed workflow runs at level `L0` and opens no pull request. The audit record `repository.protection_preflight` names each workflow and its reasons. [Prepare a repository](prepare-a-repository.md#make-your-workflows-safe-for-factory-branches) gives the two simplest fixes.

If a workflow is exposed on purpose, for example because the only secret it reads is harmless, the owner of the repository can say so. The operator records the statement in `github.workflow_exposure_acknowledgements` of the worker configuration, with the exact list of workflow paths. A list that is not exactly the list the preflight finds covers nothing. Every pass that rests on the statement writes an audit record. The statement has no expiry, so remove it when it stops being true.

The check is not a proof. It reads files and not settings: it cannot see the secrets policy of your organization, the default permissions of the workflow token, the protection of an environment, or what a reusable workflow in another repository does. Its rules are taken from GitHub's documentation and were not exercised against the real GitHub. The five steps above are still required.

One stronger option is not built. The factory could deliver from a fork, so that GitHub's rules for fork pull requests apply. Threat T-48 in the [threat model](../security/threat-model.md) records it, and rates the risk as open.

## The factory's own tools on the host

The scanners and linters that the checks run (`gitleaks`, `actionlint`, `cargo-deny`, `cargo-audit`, `cargo-nextest`, `pyright`, `shellcheck`) come from the factory's own installation, at the versions in `scripts/lib/tool-pins.sh`. A check whose tool is missing is BLOCKED, never passed. On the host, from the factory repository, see what is missing; this changes nothing:

```bash no-run reason="the answer depends on the tools of the machine it runs on"
scripts/setup-tools.sh --check
```

Then run `scripts/setup-tools.sh` without `--check` to install what is missing into `.tools/bin` in the repository, or into another folder with `--prefix DIR`. `scripts/install.sh` runs the same script as its `host-tools` step. `gitleaks` and `actionlint` are installed only from a release archive whose SHA-256 matches the one recorded in the repository. Rust, Node.js, `uv`, Docker and `gh` are reported and left to the operator. [The factory's own tools](onboarding.md#the-factorys-own-tools) in the onboarding guide has the details.

## Settings to review before the first job

- **Budget.** `stages.budget.max_cost_usd` defaults to 10.0 dollars for each stage run, and a job has up to 13 stage runs, more after rework. That is far above a small smoke budget. Lower it, and rely on the provider-side limit as the hard stop. The broker refuses a model that has no entry in `broker.prices`.
- **Autonomy level.** The default level is `L1`: the factory makes branches and draft pull requests, and a person decides every promotion. Do not raise it. Raising a level needs an `org_admin`.
- **Tenants.** `worker.tenants` is empty by default. An empty list means the worker admits no received job.
- **Profile.** Run `production`. It refuses a fake for any port. The scenario E9 shows that refusal for the API's ports (six, and a seventh when it has an artifact root) and the worker's ports, in test mode.
- **Docker daemon.** The worker starts the `docker` client with an empty environment, so a `DOCKER_HOST` in the worker's environment is ignored. Name the daemon in the configuration: `sandbox.docker_host` (a `unix://` socket path, or a `tcp://` address on the loopback interface) and, if the client's own configuration is not at its default place, `sandbox.docker_config` (an absolute directory). `sandbox.allow_remote_docker: true` lets the host be a `tcp://` address off the loopback interface, and the `production` profile refuses it: a daemon reached over a network gives whoever sits on that network the control of every container. A `docker_config` directory that holds a `config.json` with a `currentContext` other than the default, a `contexts` folder with an entry, or `credsStore` or `credHelpers` stops the worker too, because a Docker context can name a daemon on another machine whatever `sandbox.docker_host` says. `sandbox.allow_docker_config_contexts: true` lifts that check in the other profiles, and the `production` profile refuses it (DR-6). Set `sandbox.docker_host` in production, so that the context of the account does not decide which daemon the worker uses. A value that fails these rules stops the worker at start with a line that begins with the key. See the [configuration reference](../reference/configuration.md#sandbox).
- **Images.** `infra/service-images/build.sh` builds the API and the worker as distroless images (no shell, no package manager, no setuid file; one program run as the numeric user `10010:10010` on a read-only root), from the base images that `infra/sandbox-images/pins.env` pins by digest, with `cargo build --release --locked`. A production deployment should build them in its own pipeline from a reviewed commit, record the digest it deploys, and run `infra/service-images/test.sh` on that digest. The worker image does not hold the `docker` client or `git`, which the worker starts on the host: a worker in it cannot start a sandbox or fetch a repository until a person decides how a containerized worker reaches a daemon ([the local deployment](../operations/local-deployment.md#the-service-images)). Nothing here has run in a deployment.
- **Who enables a repository.** The person who enables a repository is not the person who confirmed its project map, unless the repository was registered with `--single-maintainer` (finding REG-6). The API refuses `--single-maintainer` unless the tenant has exactly one active person who holds the designations of the project map and of the enable (`single_maintainer_not_allowed`), and the worker checks again; the count is of people on the protected allowlist who reach the repository and have an active principal, so remove a person who left from the allowlist first. Register a repository as a single-maintainer one only when one person really is the only maintainer, and read the `repository.registered` row in the audit log to see which rule each repository has. `repository show` also says whether the attestor and the enabler are still active humans of the tenant: if either is switched off, the repository is closed to new jobs until a new pair confirms and enables it. There is no list of such repositories yet, so look at each repository after you switch a person off.
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
6. **Repositories.** Do not onboard a repository that vendors its crates (RR-16). Write every narrowed allowlist entry with the GitHub id of the repository, as a mapping with `name` and `github_repository_id`, and not as a bare name (RR-28, built on 2026-11-03). Three cautions for an entry that is narrowed by id. (1) A registration is judged on the typed pair: the typed name must equal the `name` recorded in the entry, so keep that name current when a repository is renamed (RH-2). (2) The design approver is judged by the registered repository's GitHub id when the entry lists one, at intake and at the re-check before the pull request (RH-3, fixed on 2026-11-03): a person narrowed by id keeps the design approval through a rename or a transfer and does not get it on a new repository registered under the old name. An entry with a bare name is judged by the registered name, which a re-created repository passes to; write the entry with the id. (3) **A hard precondition of onboarding a second tenant** is REG-3's: register by asking GitHub for the id and storing GitHub's name and default branch, not the typed ones; until then a person who may register can bind any id to any name. A bare name still works, follows the name through a rename and passes to a new repository under the old name, and the allowlist reader logs a warning for it. Nothing here ran against a real GitHub.
7. **Secret patterns.** Port the new URL pattern to `.gitleaks.toml` (RR-22), and extend the runtime pattern for RR-1 to RR-4 before agent logs reach a person.
8. **A throwaway repository.** Render the RR-19 and RR-20 vectors and look at them. Time an author's edit after a label (RR-23).
9. **The first job.** See the settings above.

### What held

The reviewers found no way to approve, merge or mark a pull request ready without an authorized person. They found no way to forge a signed decision without the key, to read the key from the database, or to move an approval to another head, base branch, tenant or verb. The token design, the webhook verification and the tenant isolation held against everything tried. The factory has no merge method and no deploy path.

### What is open, and why

- **Open findings.** The [findings of the end-to-end run](../reports/slice-1-findings.md) list SF-01 to SF-08. SF-01 is High: an unauthorized label leaves no audit record of the rejection and no explanation on the issue. A live run would show the same behaviour. Settle it first.
- **Hypotheses.** RR-13, RR-23 and the hypotheses H-1 to H-8 of the supply chain and authority reviews were not confirmed or refuted.
- **Not verified at all.** A real GitHub delivery, a deployment behind a proxy, load above the rate limits, and everything that needs a real model. The container images of the services have a recipe and tests (see below) but have never run in a deployment.
- **Shared symmetric key.** A compromised worker can forge a decision request, because it holds the key that verifies. An asymmetric signature would remove that and add a dependency.
- **The API process holds the decision key.** Register, attest and enable are signed requests that the worker applies, and the API database login can do nothing to a repository except switch it off (finding REG-2 of the [registration review](../reviews/engine-registration-and-status-security-review.md), fixed on 2026-11-03). A leak of that login's credential no longer widens the factory's reach. A compromise of the API process still does, as far as the designation of an active person allows, because the process holds the key. The project owner accepted that on 2026-11-03 and reviews it again when a second tenant is onboarded, when the key leaves the API process, or by 2027-05-03. Run the worker before the API when you upgrade, and keep it running: the registration commands wait for it.

## Other guidance

- Keep the API on a loopback address or a private network, behind a proxy that terminates TLS. The API reads the TCP peer as the source address and never reads a forwarded header. Behind a proxy every client counts as the proxy, so set `limits.max_connections_per_source` to `limits.max_connections` and cap clients at the proxy.
- Keep the protected checkout read-only to the processes that read it, outside every job workspace.
- Treat every BLOCKED line as missing evidence. Do not turn one into a pass to reach a deadline.
- The factory writes pull request text and documents that a person reads. Keep that person in the loop. The factory never merges.

## Related

- [Prepare a repository](prepare-a-repository.md): the project manifest and the limits of the gates.
- [Quickstart](quickstart.md): the test-mode run on a developer machine.
- [Runbooks](../runbooks/README.md): the situations that exist today.
- [Threat model](../security/threat-model.md) and [sandbox policy](../security/sandbox-policy.md).
