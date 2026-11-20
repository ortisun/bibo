# shellcheck shell=bash
# scripts/lib/tool-pins.sh - the one place that names the versions of the factory's own tools.
#
# scripts/ci.sh reads it for its install hints and scripts/setup-tools.sh reads it to install the tools, so the two
# cannot name different versions. The CI workflow (.github/workflows/ci.yml) and the pyright lockfile
# (.github/tools/pyright/) write the same numbers a second time, because GitHub reads them before any script runs.
# The CI step tool-pins compares them with this file, and fails when one differs.
#
# This file only sets variables. It runs nothing. Each line is NAME="VALUE" so the tool-pins check can read it with a
# regular expression. The scripts that read it use every variable, which shellcheck cannot see from here.
# shellcheck disable=SC2034
#
# A version changes in three steps: change it here, change the workflow and the lockfile, and for gitleaks and
# actionlint write the new SHA-256 of every archive below, copied from the checksum file of that release.

PIN_NEXTEST="0.9.137"
PIN_DENY="0.19.9"
PIN_AUDIT="0.22.2"
PIN_GITLEAKS="8.30.1"
PIN_ACTIONLINT="1.7.12"
PIN_PYRIGHT="1.1.413"
PIN_SHELLCHECK="0.11.0"
PIN_PYYAML="6.0.3"

# SHA-256 of the release archives that scripts/setup-tools.sh downloads, one per supported platform. An archive whose
# hash differs is refused and nothing is installed.
#
# gitleaks 8.30.1, read on 2026-11-12 from
#   https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_checksums.txt
# Archive: gitleaks_8.30.1_<platform>.tar.gz. The darwin arm64 archive was also downloaded and its hash recomputed.
SHA256_GITLEAKS_DARWIN_ARM64="b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
SHA256_GITLEAKS_DARWIN_AMD64="dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"
SHA256_GITLEAKS_LINUX_AMD64="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
SHA256_GITLEAKS_LINUX_ARM64="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"
#
# actionlint 1.7.12, read on 2026-11-12 from
#   https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_checksums.txt
# Archive: actionlint_1.7.12_<platform>.tar.gz. The darwin arm64 archive was also downloaded and its hash recomputed.
SHA256_ACTIONLINT_DARWIN_ARM64="aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f"
SHA256_ACTIONLINT_DARWIN_AMD64="5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644"
SHA256_ACTIONLINT_LINUX_AMD64="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
SHA256_ACTIONLINT_LINUX_ARM64="325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6"
