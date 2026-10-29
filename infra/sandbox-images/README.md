# Sandbox images

The container images that the sandbox supervisor runs (work package `s1-sandbox-images`, ADR 0003, `docs/security/sandbox-policy.md`). There are three. Each has a `Dockerfile`, a `build.sh` and a `README.md` in its own folder.

| Image | Folder | Runs | Holds |
|---|---|---|---|
| `factory-sandbox/agent` | `agent/` | the `agent` profile | Rust 1.98.0 toolchain, `claude` 2.1.311, `codex` 0.163.0, `bash` |
| `factory-sandbox/verify` | `verify/` | the `verify` and `fetch_deps` profiles | Rust 1.98.0 toolchain, no shell |
| `factory-sandbox/egress-sidecar` | `egress-sidecar/` | the per-job relay | one program, `factory-egress-sidecar`, which does not exist yet |

Sizes reported by Docker 29.9.2 on `linux/arm64`: agent about 1.9 GiB, verify about 1.0 GiB, sidecar skeleton about 51 MiB. The two toolchain images do not share a layer, because each is copied into an empty image in one layer. The two agent tools are about 290 MB (`claude`) and 330 MB (`codex` files, of which 67 MB is `codex-code-mode-host`).

None of them has a git binary, a package manager, a network client or a setuid file, and none holds a credential. Each runs as a numeric non-root user. `docs/security/sandbox-policy.md` says why.

## Build

```sh
infra/sandbox-images/build.sh                       # all three, for the platform the Docker daemon runs
infra/sandbox-images/build.sh --only verify         # one image
infra/sandbox-images/build.sh --check-reproducible  # build again with --no-cache and compare digests
```

The build needs Docker 24 or newer with BuildKit (it uses `ADD --checksum`) and the network. It writes the digests to `images.json`. `digests.json` is a link to the same file. The build reads and mounts no host credential. It downloads public files only, and each one must match its pinned checksum, or the build stops.

The egress sidecar builds as a skeleton until its program exists. To put the program in, see `egress-sidecar/README.md`.

## Test

```sh
infra/sandbox-images/test.sh                  # every rule on every image
infra/sandbox-images/test.sh --list           # the rules and their groups
infra/sandbox-images/test.sh --only agent --rule NO-SETID
infra/sandbox-images/smoke.sh                 # group "smoke": the toolchain runs offline, non-root, read-only source
infra/sandbox-images/audit.sh                 # group "audit": no secret, no git, no package manager, agent tools only in the agent image
infra/sandbox-images/negative-tests.sh        # break nine rules on purpose and check that test.sh fails for that reason
infra/sandbox-images/check-pins.sh            # compare pins.env with what the upstream projects publish now (needs the network)
infra/sandbox-images/tools/selftest-check-pins.sh   # check-pins.sh fails when it should, with no network
```

Exit codes, the same as `scripts/ci.sh`: `0` passed, `1` failed, `2` misuse, `3` **BLOCKED**. A run prints `BLOCKED` and exits 3 when there is no Docker command, no reachable daemon, no `images.json` or a missing image. Nothing was tested then, and that is never a pass. A rule that does not apply to the selected images prints `SKIP`, which is not a pass either.

The rules inspect each image from outside (its file system is read with `docker export`, so this works for an image with no tools) and run it under the full hardened profile of `sandbox-policy.md` section 3.2: non-root, `--cap-drop ALL`, `no-new-privileges`, read-only root, `--network none`, and the memory, process and CPU limits. The container and image names carry the label `factory.sandbox-images.test=1`, and `test.sh` removes what it created.

`negative-tests.sh` is the proof that the tests can fail. It builds copies of the real images with one defect each (a program named `git`, a setuid file, the user set to root, an API-key-shaped value in the environment or in a file, an agent tool in the verify image, a shell in the verify image, a readable or a world-writable agent tool, a `.netrc`) and requires `test.sh` to exit 1 with a `FAIL` line for the matching rule **that names what the defect added**, and the same rule on the real image not to show it. A rule that is already red on the real image (a false positive, an image not yet rebuilt) would otherwise make every defect look caught; such a case is reported as `UNPROVEN` and counts as missed. The secret-shaped strings are made at run time.

`tools/selftest-check-pins.sh` does the same for `check-pins.sh`, which reads the network and so cannot be watched failing there: with a stand-in `docker` and keys made at run time it shows that a base image with no digest, a wrong digest or an empty pin fails, that a missing Docker daemon is BLOCKED, and that a signature made by another key in the downloaded key file is refused.

## Pins and reproducibility

`pins.env` is the only place that holds a version, digest or checksum:

- base images by the digest of their multi-platform index (`rust:1.98.0-slim-trixie`, `gcr.io/distroless/cc-debian13:nonroot`),
- every download by version and SHA-256 (clippy, rustfmt, `claude`, the Codex package), for `arm64` and `amd64`,
- the fixed clock `SOURCE_DATE_EPOCH`.

`TOOLCHAIN_VERSION` must equal the channel in `rust-toolchain.toml`. `build.sh` and `test.sh` stop if they differ.

**What is reproducible.** Nothing is installed from a package index at build time, so there is no "latest" in any image. The inputs are digests and checksums. File times and image timestamps are fixed to `SOURCE_DATE_EPOCH`, attestations that carry timestamps are off, and the root file system is copied into an empty image in one layer. `build.sh --check-reproducible` rebuilds without cache and compares the digests. Measured on 2026-10-27 with Docker 29.9.2 and BuildKit 0.34.0 on `linux/arm64`: all three images gave the same digest on the uncached rebuild. The first attempt did not. The Rust installer wrote a random temporary directory name into `lib/rustlib/install.log`, so the verify and agent digests changed on every build; `lib/toolchain.sh` now uses a fixed directory name.

**What is not.**

- The base images are pinned, not rebuilt here. They are the maintainers' builds, and they age: the Debian packages inside `rust:1.98.0-slim-trixie` are from August 2026 and are not patched until the pin moves. The policy proposes a rebuild every 14 days. `check-pins.sh` shows when the tag has moved.
- A digest is only stable for one BuildKit version. Layer compression is part of the manifest, and a different BuildKit or Go version can compress the same bytes differently. The pinned inputs and the uncompressed layer contents do not change.
- The two platforms have different digests. This machine builds `linux/arm64`. The `linux/amd64` pins are filled in from upstream metadata and have **not been built here**.
- The Codex `amd64` package checksum is the one GitHub lists, not one computed from the registry file. The build fails closed if it is wrong.

### Update a pin

1. Find the new value from the upstream source named in the comment above the pin in `pins.env`. Claude Code: the signed `manifest.json`. Rust: the signed `channel-rust-<version>.toml`. Codex: the digest GitHub lists for the npm platform package, and the SHA-512 `dist.integrity` the registry lists for it. Base images: `docker buildx imagetools inspect <tag>`.
2. Edit `pins.env`, for both `arm64` and `amd64`. If the Rust version changes, change `rust-toolchain.toml` and `rust-version` in `Cargo.toml` in the same pull request (ADR 0002).
3. `infra/sandbox-images/check-pins.sh` must print `RESULT: PASSED`. It verifies the signatures of the Claude Code and Rust manifests against the fingerprints in `pins.env`.
4. `infra/sandbox-images/build.sh`, then `test.sh`, `smoke.sh`, `audit.sh` and `negative-tests.sh`.
5. Commit `pins.env` and `images.json` together. A pull request that changes `infra/**` needs a security review (`policies/security.yaml`).

The adapter refuses images by digest only, so an updated pin changes the digests in `images.json` and nothing else needs to move.

## How the adapter uses `images.json`

`images.json` is what `s1-sandbox-adapter` reads. It has one block per platform, and each block has one entry per image.

```text
{ "schema": "factory-sandbox-images/1",
  "profile_images": { "agent": "agent", "fetch_deps": "verify", "verify": "verify", "egress_sidecar": "egress-sidecar" },
  "platforms": { "linux/arm64": { "pins_sha256": "...", "images": { "agent": { ... }, "verify": { ... }, "egress-sidecar": { ... } } } } }
```

For each image the adapter should use these fields:

| Field | Use |
|---|---|
| `reference` | `name@sha256:digest`. Run exactly this with `--pull=never`. Never a tag. |
| `digest` | The manifest digest. Compare it with `Config.Image` of the created container. |
| `status` | `ready`, or `awaiting-binary` for a sidecar that has no program. Refuse anything but `ready` and report the job BLOCKED. |
| `user.uid`, `user.gid` | The value for `--user`. Both are 10000 or higher. |
| `home`, `workdir`, `mount_points` | `HOME=/home/agent` (mount a tmpfs there), `--workdir /workspace`, and the paths that exist in the image for the supervisor's mounts. |
| `env` | The complete environment the image bakes in (`PATH`, and `SSL_CERT_FILE` for the sidecar). Add these names to the posture verifier's allowlist, and no others from the image. |
| `entrypoint`, `cmd` | Both empty for agent and verify: the supervisor passes the argument vector. The sidecar's entrypoint is its program. |
| `tools` | The versions and checksums of what is inside, for the probe and the gate reports. |

Read the block for the platform of the daemon. Check that `pins_sha256` equals the SHA-256 of `pins.env` if you want to know the images are current. The adapter must not build images itself.

**The runtime self-check.** `sandbox-policy.md` section 9 step 5 speaks of an "entrypoint wrapper" that prints `Seccomp`, `NoNewPrivs` and `CapEff` before the workload runs. No package owns that wrapper and these images contain none: the verify image has no shell to run one. The agent and verify images do contain `cat`, so the supervisor can run `cat /proc/self/status` as the first command of a container it has just inspected. `test.sh` (rule `RUNTIME-PROFILE`) does exactly that and requires `Seccomp: 2`, `NoNewPrivs: 1` and zero capability sets. The sidecar image has no `cat`; its program must report its own status, or the supervisor checks the created container with `docker inspect` alone.

**Moving images to the sandbox host.** The digest is the manifest digest the Docker image store reports, and it is stable only if the host keeps it. Push the images to a registry the sandbox host pulls from and pull them by digest (`policies/security.yaml` says images are pre-pulled and verified). `docker save` and `docker load` keep the digest only on a daemon that uses the containerd image store. On a daemon with the older store, a loaded image has no manifest digest, and `docker run name@sha256:...` will not find it.

## Layout

```text
pins.env                  every pin
images.json               digests, written by build.sh (digests.json is a link to it)
build.sh smoke.sh audit.sh test.sh negative-tests.sh check-pins.sh
agent/ verify/ egress-sidecar/   Dockerfile, build.sh, README.md
lib/                      files the Dockerfiles mount: harden.sh, toolchain.sh, the name lists
tools/                    common.sh, fsaudit.py (reads an image from outside), images_json.py, pincheck.py, selftest-check-pins.sh
```

`lib/forbidden-binaries.txt` and `lib/shells.txt` are read by both the build (to delete) and the audit (to check), so the two cannot disagree.

## What is not verified

- A headless turn of `claude` or `codex` against a model provider in these images. The spike recorded turns on Alpine images; here only `--version` runs under the full profile.
- `linux/amd64`: pinned, not built.
- The sigstore bundle of the Codex release. The npm package and the release binary are byte-identical for arm64; the signature was not checked.
- AppArmor, SELinux, rootless Docker, gVisor: this machine has none of them.
- Scanning with a vulnerability database. `test.sh` looks for secrets and forbidden programs, not for CVEs.
