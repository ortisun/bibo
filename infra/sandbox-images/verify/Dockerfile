# The verify image: the pinned Rust toolchain and nothing else.
#
# Gates run here: cargo build, test, fmt and clippy, with no network, no agent tool, no shell and
# no package manager. Do not run `docker build` on this file by hand. verify/build.sh passes every
# ARG from pins.env. An ARG that has no value fails the build on purpose.
#
# Build context: infra/sandbox-images (only lib/ is sent; see .dockerignore).
#
# Two stages. The first starts from the official Rust image (pinned by digest), installs clippy
# and rustfmt from checksum-pinned archives, and removes what a sandbox does not need. The second
# copies the finished file system into an empty image, so nothing from the base image's
# configuration (its environment variables, labels, default command) is inherited.

ARG RUST_BASE

FROM ${RUST_BASE} AS rootfs

ARG TOOLCHAIN_VERSION
ARG CLIPPY_URL
ARG CLIPPY_SHA256
ARG RUSTFMT_URL
ARG RUSTFMT_SHA256
ARG SANDBOX_UID
ARG SANDBOX_GID

# BuildKit downloads each archive and refuses it if its SHA-256 differs from the pin.
ADD --checksum=sha256:${CLIPPY_SHA256} ${CLIPPY_URL} /tmp/dl/clippy.tar.gz
ADD --checksum=sha256:${RUSTFMT_SHA256} ${RUSTFMT_URL} /tmp/dl/rustfmt.tar.gz

# The scripts come from the build context through a bind mount, so they never enter a layer.
RUN --mount=type=bind,source=lib,target=/tmp/build \
    set -eux; \
    test -n "${TOOLCHAIN_VERSION}" -a -n "${SANDBOX_UID}" -a -n "${SANDBOX_GID}"; \
    sh /tmp/build/toolchain.sh "${TOOLCHAIN_VERSION}"; \
    sh /tmp/build/harden.sh verify "${SANDBOX_UID}" "${SANDBOX_GID}" /usr/sbin/nologin

FROM scratch

ARG SANDBOX_UID
ARG SANDBOX_GID

COPY --from=rootfs / /

# PATH is the only environment variable the image sets. The supervisor sets the rest (HOME, the
# cargo variables) from its own fixed list.
ENV PATH=/opt/rust/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER ${SANDBOX_UID}:${SANDBOX_GID}
WORKDIR /workspace

LABEL factory.sandbox-images="1" \
      factory.sandbox.role="verify" \
      org.opencontainers.image.title="factory sandbox verify image" \
      org.opencontainers.image.description="Rust toolchain for trusted build, test, lint and format gates. No network client, no agent tool, no shell."
