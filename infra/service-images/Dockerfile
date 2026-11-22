# The service images: the API (`factory-api`) and the worker (`factory-worker`).
#
# One file, two final stages. `docker build --target api` and `--target worker` share the `build`
# stage, so the workspace is compiled once for both.
#
#   * Both base images are pinned by digest in infra/sandbox-images/pins.env (RUST_BASE and
#     DISTROLESS_BASE, the same two pins the sandbox images use, checked by check-pins.sh).
#   * The build is `cargo build --release --locked`: the versions in Cargo.lock, nothing newer.
#     The compiler is the one in the Rust base image (the version in rust-toolchain.toml; the build
#     stops if they differ). rust-toolchain.toml itself is not copied: with it, rustup would try to
#     download clippy and rustfmt during the build, and a release build needs neither.
#   * Reproducible: SOURCE_DATE_EPOCH is set, the build and cargo directories are remapped out of
#     the binary, and build.sh clamps every file time of the image to the same epoch.
#   * The final image is distroless `cc` (glibc, libgcc, CA certificates): no shell, no package
#     manager, no setuid file. It holds one file, the program, owned by root, mode 0555. It runs as
#     a numeric non-root user (SERVICE_UID:SERVICE_GID from pins.env, 10010 as infra/compose/local.yml
#     expects) and works on a read-only root: it writes nowhere but the places the deployment mounts.
#   * No credential is read or written. The build downloads public crates from crates.io and
#     nothing else, and the build context is the allow list in the .dockerignore at the repository root.
#
# What the worker image does NOT hold: the `docker` client and `git`, the two programs the worker
# starts on the host (crates/sandbox/src/process.rs). Without them a worker in this image cannot
# start a sandbox or fetch a repository, and the job is BLOCKED. That is the fail-closed answer, and
# the way to give a worker those programs is an open decision (docs/operations/local-deployment.md).
#
# Do not run `docker build` on this file by hand. build.sh passes every ARG from pins.env, from the
# repository root as the build context. An ARG with no value fails the build on purpose, except
# FACTORY_BUILD_COMMIT, which build.sh leaves empty when the tree has changes that are not committed.

ARG RUST_BASE
ARG DISTROLESS_BASE

# ---- build: compile both programs ---------------------------------------------------------------
FROM ${RUST_BASE} AS build

ARG TOOLCHAIN_VERSION
ARG SOURCE_DATE_EPOCH
ARG BUILD_JOBS

# The release profile is set here and not in Cargo.toml, so the workspace keeps its own defaults.
# Symbols are stripped (the images hold no debug information) and nothing is incremental.
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    CARGO_TARGET_DIR=/tmp/target \
    CARGO_INCREMENTAL=0 \
    CARGO_TERM_COLOR=never \
    CARGO_BUILD_JOBS=${BUILD_JOBS} \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_PROFILE_RELEASE_DEBUG=0 \
    RUSTUP_TOOLCHAIN=${TOOLCHAIN_VERSION} \
    RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo-home --remap-path-prefix=/tmp/target=/target"

WORKDIR /src

# Every ARG must have a value, and the compiler of the base image must be the one the repository pins.
RUN test -n "${SOURCE_DATE_EPOCH}" && test -n "${BUILD_JOBS}" \
 && test "$(rustc --version | cut -d' ' -f2)" = "${TOOLCHAIN_VERSION}"

# Exactly what the two programs need to compile, and nothing else (see the .dockerignore).
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY crates crates
COPY apps apps
COPY xtask xtask
COPY schemas schemas
COPY migrations migrations
COPY docs/database/tests/role_readiness.sql docs/database/tests/role_readiness.sql
COPY fixtures/readability/rules.json fixtures/readability/rules.json
COPY onboarding/project-rules onboarding/project-rules

# The commit the programs are built from, as a full Git object id. The API states it in every process
# snapshot (ADR 0029) and answers 503 on that route when it is empty. It is declared here and given to
# this one step only, so that a new commit does not rebuild the layers above.
ARG FACTORY_BUILD_COMMIT=

# The registry cache holds only downloaded crates, which Cargo.lock checks by hash, so it cannot
# change what is built. The target directory is removed in the same step, so it never becomes a
# layer. The programs are copied out before that.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=factory-service-images-registry \
    FACTORY_BUILD_COMMIT="${FACTORY_BUILD_COMMIT}" \
    cargo build --release --locked -p factory-api -p factory-worker \
 && install -D -m 0555 /tmp/target/release/factory-api /out/factory-api \
 && install -D -m 0555 /tmp/target/release/factory-worker /out/factory-worker \
 && rm -rf /tmp/target

# ---- api ----------------------------------------------------------------------------------------
FROM ${DISTROLESS_BASE} AS api

ARG SERVICE_UID
ARG SERVICE_GID

COPY --from=build --chown=0:0 --chmod=0555 /out/factory-api /usr/local/bin/factory-api

WORKDIR /
USER ${SERVICE_UID}:${SERVICE_GID}
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/factory-api"]

LABEL factory.service-images="1" \
      factory.service.role="api" \
      org.opencontainers.image.title="factory API" \
      org.opencontainers.image.description="The factory HTTP API (factory-api). No shell, no package manager, no setuid file."

# ---- worker -------------------------------------------------------------------------------------
FROM ${DISTROLESS_BASE} AS worker

ARG SERVICE_UID
ARG SERVICE_GID

COPY --from=build --chown=0:0 --chmod=0555 /out/factory-worker /usr/local/bin/factory-worker

WORKDIR /
USER ${SERVICE_UID}:${SERVICE_GID}
ENTRYPOINT ["/usr/local/bin/factory-worker"]

LABEL factory.service-images="1" \
      factory.service.role="worker" \
      org.opencontainers.image.title="factory worker" \
      org.opencontainers.image.description="The factory worker (factory-worker). No shell, no package manager, no setuid file, no docker client and no git."
