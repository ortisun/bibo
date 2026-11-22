# The egress sidecar image

`factory-sandbox/egress-sidecar` holds one program, `factory-egress-sidecar`, the per-job relay described in `docs/security/sandbox-policy.md` section 5.2. The program exists: work package `s1-egress-and-broker` wrote it (`apps/egress-sidecar`, whose README is the contract the supervisor builds against). This image does not build it; the compiled Linux program is dropped in with `build.sh --binary`. The image never contains a stand-in.

## Two states

| `status` in `images.json` | What the image holds | What the adapter must do |
|---|---|---|
| `awaiting-binary` | The base, the user and the entrypoint. No program. Starting it fails with "no such file or directory". | Refuse to use it. A job that needs a sidecar is BLOCKED. |
| `ready` | The base and exactly one program at `/usr/local/bin/factory-egress-sidecar`. `binary_sha256` in `images.json` is its SHA-256. | Use it, by digest. |

Today the `linux/arm64` entry is `ready` and records the SHA-256 of the program it holds. `test.sh` (rule `SIDECAR-STATE`) checks that a skeleton really has no program and really fails to start, and that a `ready` image holds the program whose hash `images.json` records.

## Supplying the program

```sh
infra/sandbox-images/egress-sidecar/build.sh --binary PATH --sha256 HEX
```

The script refuses the file unless its SHA-256 equals `--sha256` (the person who supplies it states which build they mean), it is an ELF file, and its machine type matches the platform. It copies the file into a one-file build context, so nothing else can enter the image. The program must be built for the platform of the image: static (musl) or linked to glibc 2.41 or older (Debian 13). Build it in the verify image or in CI, not on a Mac.

### Compiling the program in the verify image

This is how the program of the current `ready` entry was made. It needs the network for one reason: cargo fetches the crates that `Cargo.lock` names, and `--locked` refuses any other. The container is not the sandbox profile, so run it only on a trusted machine. It still runs as a non-root user with no capability, a read-only root and the repository mounted read-only.

```sh
OUT=$(mktemp -d) && chmod 777 "$OUT"
VERIFY=$(python3 -c "import json;print(json.load(open('infra/sandbox-images/images.json'))['platforms']['linux/arm64']['images']['verify']['reference'])")
docker run --rm --pull=never --user 10000:10000 --cap-drop ALL --security-opt no-new-privileges --read-only \
  -v "$PWD":/src:ro -v "$OUT":/target --tmpfs /home/agent:rw,exec,uid=10000,gid=10000,size=1g --tmpfs /tmp:rw,exec,size=512m \
  --workdir /src -e CARGO_TARGET_DIR=/target -e CARGO_HOME=/home/agent/.cargo -e HOME=/home/agent -e CARGO_INCREMENTAL=0 \
  "$VERIFY" cargo build --release --locked -p factory-egress-sidecar
shasum -a 256 "$OUT/release/factory-egress-sidecar"
infra/sandbox-images/egress-sidecar/build.sh --binary "$OUT/release/factory-egress-sidecar" --sha256 HEX_FROM_THE_LINE_ABOVE
```

The program of the current `ready` entry (SHA-256 `accde5ca…`, image `sha256:4f2f6a0d…`) was built with this recipe on 2026-11-22, after commit `4f7e78d` (2026-11-20) changed the program and left the image of the older program (`466cce26…`) pinned. Two machines gave the same program and the same image digest: the owner's Mac (Docker Desktop, engine 29.9.3) and a GitHub `ubuntu-24.04-arm` runner (Docker Engine 29.9.3), which builds it on every CI run ([ADR 0034](../../../docs/adr/0034-github-ci-on-arm64-with-a-database-and-built-images.md)). So `binary_sha256` now also says that the program can be rebuilt elsewhere. What is still not shown: that another Docker version or another source path than `/src` gives the same bytes (the path and the unstripped binary are part of what the build records). A change to the program's sources changes its hash: rebuild the image with this recipe in the same change, or the CI's comparison step shows the image as DIFFERENT and the image tests report BLOCKED.

## The base

`gcr.io/distroless/cc-debian13:nonroot`, pinned by digest. It has glibc, libgcc, libstdc++ and CA certificates, and no shell, no package manager and no setuid file. The image sets `USER 10003:10003` and `ENTRYPOINT ["/usr/local/bin/factory-egress-sidecar"]`. Its environment is `PATH` and `SSL_CERT_FILE`, both from the base.

## What the program must be (the proposal that `apps/egress-sidecar` answers)

This is what the image guarantees and what it expects back. The egress package owns the program and may amend it. `apps/egress-sidecar/README.md` says what the program does today.

- **Runs as 10003:10003 on a read-only root with no capabilities.** It may write only to a tmpfs the supervisor mounts. It must not need a writable root, a shell, a home directory or any file the image does not contain.
- **Takes its configuration from the supervisor**, as a file mounted read-only or as arguments, never from the sandbox. The image holds no configuration.
- **Fails closed.** Bad configuration, an unreadable file or a failed listener means a non-zero exit before it accepts a connection.
- **Logs audit events to standard output**, one JSON object per line (job, host, port, bytes, decision). The profile uses `--log-driver none`, so the supervisor reads them through the attached stream and redacts them.
- **Ends on SIGTERM within the 10 seconds of `--stop-timeout`.**
- **Listens on a port of 1024 or higher.** Docker sets `net.ipv4.ip_unprivileged_port_start` to 0, so a low port would also work, but nothing needs one.

## How `test.sh` exercises it

Rule `SIDECAR-CONTRACT` compiles a small probe program in the verify image, builds a throwaway image from this same Dockerfile with the probe at the sidecar's path (under the name `factory-sandbox-test/egress-sidecar:probe-N`, labelled `factory.sandbox-images.test=1`), runs it under the hardened profile and removes it. The probe prints its user, capabilities, `NoNewPrivs`, seccomp mode and the result of one forbidden write. It is not a sidecar, does nothing a relay does, and is never recorded in `images.json`. It proves that the Dockerfile accepts a program and that a program in this image runs non-root on a read-only root.
