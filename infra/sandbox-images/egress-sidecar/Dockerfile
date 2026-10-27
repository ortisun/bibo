# The egress sidecar image: a minimal image that holds one program, factory-egress-sidecar.
#
# That program does not exist yet. It is written by work package s1-egress-and-broker
# (apps/egress-sidecar). This image is built to receive it and never to invent it:
#
#   * With no program supplied, the image is a skeleton. It has the right user, the right
#     entrypoint and nothing to run. Starting it fails, which is the safe outcome: the supervisor
#     treats a failed sidecar as a BLOCKED job. images.json marks it "awaiting-binary".
#   * With a program supplied, egress-sidecar/build.sh checks its SHA-256 and that it is a Linux
#     executable for this platform, then places it at /usr/local/bin/factory-egress-sidecar.
#
# The base is the distroless "cc" image: glibc, libgcc, libstdc++ and CA certificates, with no
# shell, no package manager and no setuid file. A static musl program and a program linked to
# glibc 2.41 (Debian 13) both run on it.
#
# Do not run `docker build` on this file by hand. egress-sidecar/build.sh builds a small context
# whose payload/ directory is empty or holds exactly one file, and passes every ARG from pins.env.

ARG DISTROLESS_BASE

FROM ${DISTROLESS_BASE}

ARG SIDECAR_UID
ARG SIDECAR_GID

# Empty for the skeleton. Otherwise payload/ holds factory-egress-sidecar and nothing else.
COPY --chown=0:0 --chmod=0555 payload/ /usr/local/bin/

USER ${SIDECAR_UID}:${SIDECAR_GID}
ENTRYPOINT ["/usr/local/bin/factory-egress-sidecar"]

LABEL factory.sandbox-images="1" \
      factory.sandbox.role="egress-sidecar" \
      org.opencontainers.image.title="factory sandbox egress sidecar image" \
      org.opencontainers.image.description="Holds the factory-egress-sidecar program. No shell, no package manager, no setuid file."
