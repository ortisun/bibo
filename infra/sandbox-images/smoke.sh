#!/usr/bin/env bash
# smoke.sh - run the Rust toolchain offline, as a non-root user, under the hardened profile.
#
#   infra/sandbox-images/smoke.sh [test.sh options]
#
# This is the "toolchain smoke" done check of work package s1-sandbox-images. It runs the rules
# of group "smoke" in test.sh: the toolchain versions in the agent and verify images, and a build,
# test (unit and doc), fmt --check and clippy -D warnings of a small crate in the verify image
# with --network none, a read-only root, a read-only source tree and no capabilities.
#
# Exit codes are those of test.sh: 0 passed, 1 failed, 2 misuse, 3 BLOCKED (no Docker, no image).
exec "$(cd "$(dirname "$0")" && pwd -P)/test.sh" --group smoke "$@"
