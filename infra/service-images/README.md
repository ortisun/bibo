# The service images

- Status: written on 2026-11-03. The recipe, the static checks and the compose wiring are checked by `test.sh --static` and `test.sh --self-test`, which need no Docker daemon. What was built and run on a machine is in the section "What was run".
- Form: reference and how-to guide.
- Goal: say how the images of the API and the worker are made, what is in them, what is not, and how to build and test them.

Two images, one recipe: `factory-api:local` (the program `factory-api`) and `factory-worker:local` (the program `factory-worker`). They are the images `infra/compose/local.yml` runs in its `factory` profile. They are not the sandbox images (`infra/sandbox-images/`), which are the containers the worker starts for a job.

| File | What it is |
|---|---|
| `Dockerfile` | One file. The `build` stage compiles both programs once; the `api` and `worker` stages are the final images. |
| `build.sh` | Builds the images from the repository root, in the style of `infra/sandbox-images/build.sh`. |
| `test.sh` | The rules for the built images, and `--static` for the rules that need only the files. |
| `check_static.py` | The static rules, with a self-test that damages the files one rule at a time. |
| `../../.dockerignore` | The build context: everything left out, then exactly what the two programs need to compile let back in. |

## Build and test

```bash no-run reason="needs a Docker daemon, the network for the crates, and about ten minutes of compile time"
infra/service-images/build.sh                  # api and worker, for the platform the daemon runs
infra/service-images/build.sh --only api --jobs 2
infra/service-images/build.sh --builder NAME   # a throwaway builder keeps the whole cache in one place
infra/service-images/test.sh                   # BLOCKED (exit 3) without Docker or without the images
infra/service-images/test.sh --static          # no Docker needed
infra/service-images/test.sh --self-test       # every damage to the files must be caught
```

`build.sh` never reads or mounts a host credential. It downloads the two pinned base images and the public crates that `Cargo.lock` names, and nothing else. It builds with `--provenance=false --sbom=false` and `rewrite-timestamp=true`, so that a rebuild does not change a digest because of the clock; `--check-reproducible` builds each image a second time with `--no-cache` and fails if the image id differs. `--jobs` (default 4) limits the parallel compile jobs, because a release build of this workspace on all cores can use more memory than the Docker VM of a laptop has.

A throwaway builder is the way to keep the cache removable: `docker buildx create --name factory-svc --driver docker-container`, then `build.sh --builder factory-svc`, then `docker buildx rm --force --keep-state=false factory-svc` removes the cache, the downloaded crates and the base images it pulled. The image that was loaded into the daemon is separate and is removed with `docker image rm`.

## What is pinned, and where

| What | Where | Checked by |
|---|---|---|
| The Rust base image, by the digest of its multi-platform index | `RUST_BASE` in `infra/sandbox-images/pins.env` | `infra/sandbox-images/check-pins.sh`, and `test.sh --static` (the digest must be there) |
| The distroless `cc` base image, by digest | `DISTROLESS_BASE` in the same file | the same |
| The compiler | `TOOLCHAIN_VERSION` in the same file, equal to `rust-toolchain.toml` | `build.sh` and the first `RUN` of the Dockerfile |
| The versions of every crate | `Cargo.lock`, used with `--locked` | `test.sh --static` |
| The clock | `SOURCE_DATE_EPOCH` in the same pins file | `test.sh --static` |
| The user, `10010:10010` | `SERVICE_UID` and `SERVICE_GID` in `build.sh` | `test.sh --static` compares it with `FACTORY_UID:-10010` in `infra/compose/local.yml`, and `test.sh` with the user of the built image |

The two bases are the ones the sandbox images use, so there is one set of base pins in the repository and one script that compares them with what the registries publish. The user ids are not in `pins.env` on purpose: `images.json` records a hash of that file, and a change to it would make the tests of the sandbox images say they were built from other pins.

## What is in an image

- The distroless `cc` base: glibc, libgcc, the CA certificates. No shell, no package manager, no setuid file.
- One file added: `/usr/local/bin/factory-api` or `/usr/local/bin/factory-worker`, owned by root, mode 0555, stripped, and the entry point. The environment holds `PATH` and `SSL_CERT_FILE` and nothing else.
- The user is `10010:10010`. The image works on a read-only root: it writes only where the deployment mounts something (the artifact volume at `/var/lib/factory/artifacts`, a temporary directory in memory).
- No credential. The build context is the allow list in `.dockerignore`, so the secrets folder, `.env` files, `.git` and the editor folders are never sent to the daemon. Inside what is let in, a file named like a credential is left out as well (`**/*secret*`, `**/*credential*`, `id_rsa`, `id_ed25519` and their kin, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.kdbx`, `*.jks`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.gitconfig`, `auth.json`), and so are the folders `.aws`, `.ssh`, `.gnupg`, `.docker` and `.kube`, because the build runs the build scripts of every dependency with the network on and the context is the directory, not the repository history (DR-7). The sources of the programs whose names say "secret" or "credential" because they handle them (`crates/egress/src/http/secret.rs` and two more) are let back in by `!**/*secret*.rs` and `!**/*credential*.rs`; the folders come last, because the last rule wins. The rule `DENY-ALL-CONTEXT` requires the lines after the allow list to be exactly the list in `check_static.py`, in that order, and `--self-test` damages the file once for each line. Every configuration value that is a secret is the path of a file that the deployment mounts at run time. The rule `NO-CREDENTIAL` scans the files of the image with the patterns of `policies/security.yaml`. The pattern of the job token that the factory itself mints at run time (`factory_job_token`) is not applied to a **compiled** file, that is a file `looks_compiled` of `fsaudit.py` says is not text (an ELF file, or any file with a control byte or bytes that are not UTF-8), and it is applied to a text file of any size: the broker in the worker holds the constant prefix `sfjt_`, the compiler lays constants side by side with no separator, and the loose pattern then reads the neighbours as part of a token (a first build was refused for that, with a run of 649 characters). A token of 256 random bits cannot be compiled into a program, so nothing is lost; what is given up is a token that someone put into a compiled file (including a non-ELF binary such as a database file), which the review records as DR-5. The option names only `factory_job_token`: the `api_token` pattern finds nothing in either program and is not given up. The vendor patterns still apply to the programs. `infra/sandbox-images/tools/selftest-fsaudit.py` shows the cases (a large text file with a token is a finding; an ELF file and a non-ELF binary with one are skipped) and `infra/sandbox-images/tools/breaks-fsaudit.py` shows five breaks of the option, all caught.
- No health check. The programs have no subcommand that asks their own health, and the image has no shell or `curl`.

## What is not in the worker image

The worker starts two programs on the host: the `docker` client, to make the sandboxes of a job, and `git`, to fetch and push the target repository (`crates/sandbox/src/process.rs`). This image holds neither. A worker that runs in it therefore cannot start a sandbox or fetch a repository, and the job is `BLOCKED` with a named cause, which is the fail-closed answer. Giving a containerized worker those programs and a way to reach a daemon is the open decision recorded in [the local deployment](../../docs/operations/local-deployment.md), "Docker access". The configuration keys for the daemon (`sandbox.docker_host`, `sandbox.docker_config`) are in the [configuration reference](../../docs/reference/configuration.md#sandbox).

## What was run

See the section "What was run" of [the local deployment](../../docs/operations/local-deployment.md#the-service-images) for the commands, the sizes and the results of the build and of `test.sh` on one machine. A rule that is not in that list was not run.
