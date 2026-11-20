#!/usr/bin/env bash
# audit.sh - look for what must not be in an image.
#
#   infra/sandbox-images/audit.sh [test.sh options]
#
# This is the "audit" done check of work package s1-sandbox-images. It runs the rules of group
# "audit" in test.sh on every image: no credential file, no secret-shaped content or environment
# value, no git, no GitHub command line, no package manager, no network client, and the Claude
# Code and Codex programs only in the agent image, at the pinned checksums.
#
# Exit codes are those of test.sh: 0 passed, 1 failed, 2 misuse, 3 BLOCKED (no Docker, no image).
exec "$(cd "$(dirname "$0")" && pwd -P)/test.sh" --group audit "$@"
