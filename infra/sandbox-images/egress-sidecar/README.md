# The egress sidecar image

`factory-sandbox/egress-sidecar` holds one program, `factory-egress-sidecar`, the per-job relay described in `docs/security/sandbox-policy.md` section 5.2. **That program does not exist yet.** Work package `s1-egress-and-broker` writes it (`apps/egress-sidecar`). This image is built so that program can be dropped in. It never contains a stand-in.

## Two states

| `status` in `images.json` | What the image holds | What the adapter must do |
|---|---|---|
| `awaiting-binary` | The base, the user and the entrypoint. No program. Starting it fails with "no such file or directory". | Refuse to use it. A job that needs a sidecar is BLOCKED. |
| `ready` | The base and exactly one program at `/usr/local/bin/factory-egress-sidecar`. `binary_sha256` in `images.json` is its SHA-256. | Use it, by digest. |

Today the entry is `awaiting-binary`. `test.sh` (rule `SIDECAR-STATE`) checks that a skeleton really has no program and really fails to start, and that a `ready` image holds the program whose hash `images.json` records.

## Supplying the program

```sh
infra/sandbox-images/egress-sidecar/build.sh --binary PATH --sha256 HEX
```

The script refuses the file unless its SHA-256 equals `--sha256` (the person who supplies it states which build they mean), it is an ELF file, and its machine type matches the platform. It copies the file into a one-file build context, so nothing else can enter the image. The program must be built for the platform of the image: static (musl) or linked to glibc 2.41 or older (Debian 13). Build it in the verify image or in CI, not on a Mac.

## The base

`gcr.io/distroless/cc-debian13:nonroot`, pinned by digest. It has glibc, libgcc, libstdc++ and CA certificates, and no shell, no package manager and no setuid file. The image sets `USER 10003:10003` and `ENTRYPOINT ["/usr/local/bin/factory-egress-sidecar"]`. Its environment is `PATH` and `SSL_CERT_FILE`, both from the base.

## What the program must be (proposal for `s1-egress-and-broker`)

This is what the image guarantees and what it expects back. The egress package owns the program and may amend it.

- **Runs as 10003:10003 on a read-only root with no capabilities.** It may write only to a tmpfs the supervisor mounts. It must not need a writable root, a shell, a home directory or any file the image does not contain.
- **Takes its configuration from the supervisor**, as a file mounted read-only or as arguments, never from the sandbox. The image holds no configuration.
- **Fails closed.** Bad configuration, an unreadable file or a failed listener means a non-zero exit before it accepts a connection.
- **Logs audit events to standard output**, one JSON object per line (job, host, port, bytes, decision). The profile uses `--log-driver none`, so the supervisor reads them through the attached stream and redacts them.
- **Ends on SIGTERM within the 10 seconds of `--stop-timeout`.**
- **Listens on a port of 1024 or higher.** Docker sets `net.ipv4.ip_unprivileged_port_start` to 0, so a low port would also work, but nothing needs one.

## How `test.sh` exercises it

Rule `SIDECAR-CONTRACT` compiles a small probe program in the verify image, builds a throwaway image from this same Dockerfile with the probe at the sidecar's path (under the name `factory-sandbox-test/egress-sidecar:probe-N`, labelled `factory.sandbox-images.test=1`), runs it under the hardened profile and removes it. The probe prints its user, capabilities, `NoNewPrivs`, seccomp mode and the result of one forbidden write. It is not a sidecar, does nothing a relay does, and is never recorded in `images.json`. It proves that the Dockerfile accepts a program and that a program in this image runs non-root on a read-only root.
