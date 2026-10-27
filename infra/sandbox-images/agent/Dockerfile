# The agent image: the pinned Rust toolchain plus the Claude Code and Codex command line tools.
#
# The agent profile runs the tool and the commands it asks for in this image, with a read-only
# root, no capabilities and only the model broker reachable (docs/security/sandbox-policy.md).
# There is no git, no package manager, no setuid file and no network client. A shell stays, for
# the reason given in agent/README.md.
#
# Do not run `docker build` on this file by hand. agent/build.sh passes every ARG from pins.env.
# An ARG that has no value fails the build on purpose.
#
# Build context: infra/sandbox-images (only lib/ is sent; see .dockerignore).

ARG RUST_BASE

# Codex is published as an npm platform package (a tarball). This stage only downloads it, so the
# tarball never sits in the root file system stage. BuildKit refuses the download if its SHA-256
# differs from the pin.
FROM scratch AS codex-download
ARG CODEX_URL
ARG CODEX_SHA256
ADD --checksum=sha256:${CODEX_SHA256} ${CODEX_URL} /codex.tgz

FROM ${RUST_BASE} AS rootfs

ARG TOOLCHAIN_VERSION
ARG CLIPPY_URL
ARG CLIPPY_SHA256
ARG RUSTFMT_URL
ARG RUSTFMT_SHA256
ARG CLAUDE_URL
ARG CLAUDE_SHA256
ARG CODEX_BINARY_SHA256
ARG CODEX_TRIPLE
ARG SANDBOX_UID
ARG SANDBOX_GID

ADD --checksum=sha256:${CLIPPY_SHA256} ${CLIPPY_URL} /tmp/dl/clippy.tar.gz
ADD --checksum=sha256:${RUSTFMT_SHA256} ${RUSTFMT_URL} /tmp/dl/rustfmt.tar.gz

# Claude Code is one native binary. It belongs to root and nobody can write to it.
ADD --checksum=sha256:${CLAUDE_SHA256} --chown=0:0 --chmod=0755 ${CLAUDE_URL} /usr/local/bin/claude

# Codex: unpack the tarball, check bin/codex against its own pinned SHA-256 as a second line (the
# tarball was already checked by the download), and install the same files the spike image holds,
# except bwrap and the voice libraries. bwrap is Codex's own sandbox helper; it cannot start under
# the default seccomp profile (spike 4.8), so it is only another program that needs namespaces.
RUN --mount=type=bind,from=codex-download,source=/codex.tgz,target=/tmp/codex.tgz \
    set -eux; \
    test -n "${CODEX_BINARY_SHA256}" -a -n "${CODEX_TRIPLE}"; \
    mkdir /tmp/pkg; \
    tar -xzf /tmp/codex.tgz -C /tmp/pkg; \
    v="/tmp/pkg/package/vendor/${CODEX_TRIPLE}"; \
    echo "${CODEX_BINARY_SHA256}  $v/bin/codex" | sha256sum --check --strict -; \
    install -d -o 0 -g 0 -m 0755 /opt/codex /opt/codex/bin /opt/codex/codex-path; \
    install -o 0 -g 0 -m 0755 "$v/bin/codex" "$v/bin/codex-code-mode-host" /opt/codex/bin/; \
    install -o 0 -g 0 -m 0755 "$v/codex-path/rg" /opt/codex/codex-path/rg; \
    install -o 0 -g 0 -m 0644 "$v/codex-package.json" /opt/codex/codex-package.json; \
    rm -rf /tmp/pkg

RUN --mount=type=bind,source=lib,target=/tmp/build \
    set -eux; \
    test -n "${TOOLCHAIN_VERSION}" -a -n "${SANDBOX_UID}" -a -n "${SANDBOX_GID}"; \
    sh /tmp/build/toolchain.sh "${TOOLCHAIN_VERSION}"; \
    sh /tmp/build/harden.sh agent "${SANDBOX_UID}" "${SANDBOX_GID}" /bin/bash

FROM scratch

ARG SANDBOX_UID
ARG SANDBOX_GID

COPY --from=rootfs / /

# PATH is the only environment variable the image sets. The supervisor sets the rest (HOME, the
# broker address, the cargo variables) from its own fixed list. No hook, MCP server, settings file
# or skill is baked in: the home directory is empty and the supervisor mounts a tmpfs over it.
ENV PATH=/opt/rust/bin:/opt/codex/codex-path:/opt/codex/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
USER ${SANDBOX_UID}:${SANDBOX_GID}
WORKDIR /workspace

LABEL factory.sandbox-images="1" \
      factory.sandbox.role="agent" \
      org.opencontainers.image.title="factory sandbox agent image" \
      org.opencontainers.image.description="Rust toolchain plus the Claude Code and Codex command line tools, for the agent profile. No git, no package manager, no setuid file."
