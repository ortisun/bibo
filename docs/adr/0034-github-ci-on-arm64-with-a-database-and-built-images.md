# 0034: Run the GitHub CI on an arm64 runner, with a PostgreSQL service and the images built in the job

- Status: **Decided by the owner on 2026-11-22** (the arm64 runner and building the images in the job); the engineer wrote how. No independent review has covered it.
- Date: 2026-11-22
- Deciders: the owner chose among four ways to give the GitHub CI the images its tests need; the engineer found the causes and wrote the workflow.
- Related: [ADR 0007](0007-persistence-access-and-tenancy.md) (PostgreSQL and its pinned image), [ADR 0033](0033-documentation-site-on-github-pages.md) (the repository became public, so its CI started to run), [running the database tests](../database/running.md), [the sandbox images](../../infra/sandbox-images/README.md), [local deployment](../operations/local-deployment.md) (the API and worker images).

## Context and problem statement

`scripts/ci.sh` is the one gate, on a laptop and in CI alike. Until 2026-11-22 it had only ever run on the owner's Mac. The GitHub workflow existed, but GitHub's free plan does not run Actions for a private repository whose payments failed, so it had never started. Once the repository was public (ADR 0033), its first run, on `ubuntu-24.04` (x86-64), ended with 41 steps passed, 3 failed and 1 BLOCKED, and the test step stopped after 4 of 6222 tests. Run again with every failure shown, the job hit its 60-minute limit with 257 tests failed.

The failures had four causes, and none was a defect of the factory itself:

1. **Host differences in the code and the tests.** `mode_t` is `u16` on macOS and `u32` on Linux (a clippy error); the runner ships a real `gh` that the installer tests found after they removed their fake one; and the tests kept the directories they hand to a sandbox under the repository's `target/`, which is under `/home` on a Linux checkout, a mount source the policy forbids. These are fixed in code and tests, not in the workflow.
2. **No PostgreSQL server.** The database tests start a private server (`initdb`, `pg_ctl`), use Docker, or use the server that `FACTORY_DB_ADMIN_URL` names. The runner had none of these ready, and `docs/database/running.md` already said that CI should use a service container.
3. **No sandbox images.** The sandbox, runtime, egress and composition tests run real containers of `factory-sandbox/agent`, `verify` and `egress-sidecar`, pinned by digest in `infra/sandbox-images/images.json`. The pins exist for `linux/arm64` only, the platform of the owner's Mac. A test that finds no image of the pinned digest reports `BLOCKED`, which the gate counts as not passed.
4. **No other images.** The `alpine/git` image of one testkit test (pinned by the digest of its multi-platform index) and the API and worker images of the `service-images` step were not on the runner either. `scripts/ci.sh` never builds or pulls on purpose: running a check must not change the machine.

## Considered options

1. **An arm64 runner that builds the images before the gate** (chosen). GitHub offers `ubuntu-24.04-arm` free to public repositories. Its platform is the one the images are pinned for, so a build in the job either gives the committed digests or shows that the recipe does not reproduce on another machine. Every test runs for real. The job gets longer: the images are built on every run.
2. **Pins for `linux/amd64` as well.** Keep the x86-64 runner and record a second set of digests in `images.json`. Every change to an image would then need two builds and two sets of pins, one of them made on a machine the owner does not have.
3. **The images only on the owner's machine.** The GitHub CI would run everything else and report the image tests as `BLOCKED`. It is honest and fast, but the GitHub CI could then never pass, and a pull request would show red for a reason unrelated to it.
4. **The owner's Mac as a self-hosted runner.** The images are already there. But the CI would stop when the Mac is off, and in a public repository a pull request from a fork would run its code on the owner's machine.

## Decision

- **The runner** is `ubuntu-24.04-arm`. The tools are installed for `linux/arm64`: `taiki-e/install-action` picks the arm64 builds itself, and gitleaks and actionlint use the `LINUX_ARM64` hashes already in `scripts/lib/tool-pins.sh`.
- **PostgreSQL** is a container of the image that `infra/compose/local.yml` pins (18.6, by the digest of its multi-platform index), started in a workflow step, listening on the runner's loopback only, and named by `FACTORY_DB_ADMIN_URL`. It runs with the settings of the tests' own private server: `trust` authentication (so no password is written anywhere, which the secret scan would rightly refuse), no `fsync`, and 300 connections. A GitHub service container cannot pass those server settings, which is why it is a step and not a `services:` entry.
- **The images** are built in workflow steps before `scripts/ci.sh`, because building changes the machine and a check must not:
  - the sandbox images by `infra/sandbox-images/build.sh`, with the sidecar program compiled in the verify image as `infra/sandbox-images/egress-sidecar/README.md` describes. The build writes its digests to a file of its own, **never to the committed `images.json`**: the tests look the images up by the committed digests, so an image that does not reproduce stays absent and its tests report `BLOCKED`. A step prints the built and the pinned digest of each image side by side;
  - the API and worker images by `infra/service-images/build.sh`;
  - `alpine/git` pulled by the pinned index digest.
- **The time limit** of the job is 120 minutes.
- **The gate itself does not change**, except that its test step runs with `--no-fail-fast`, so that one failing test does not hide the others. The checks still live in `scripts/ci.sh` only.

## Consequences

- Good: the GitHub CI runs the same tests as a full local run, on the platform the images are pinned for, and every pull request shows the whole gate.
- Good: the first build on a machine other than the owner's is also the first test that the image recipes reproduce elsewhere. `egress-sidecar/README.md` already says that this was never shown.
- Bad: each run builds the images, which adds time. A cache of the image layers between runs is not part of this decision.
- Bad: if a recipe does not reproduce on the runner, its image tests report `BLOCKED` until the recipe is fixed or the owner decides to pin the runner's digests.
- Neutral: on an x86-64 machine, a full local run still needs the images built and pinned for that platform first. Nothing changes for the owner's Mac.

## What was checked

- On the owner's Mac (macOS, arm64): the storage clippy fix, the 230 installer tests, and the API tests that the forbidden mount source had blocked, both with the scratch under `target/` and with it forced to `/tmp`.
- On GitHub (run 45033034531, x86-64, before this decision): the causes above, by reading each failing test's message.
- The result on the arm64 runner is recorded in the pull request that brings this record.
