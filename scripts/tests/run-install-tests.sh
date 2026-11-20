#!/usr/bin/env bash
# scripts/tests/run-install-tests.sh - run the installer tests, the tool setup tests, the project map tests and the Codex config tests.
# A step line of scripts/ci.sh cannot hold several commands, so this script runs them all and fails if any fails.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
status=0
python3 -I "$here/test_project_map.py" || status=1
python3 -I "$here/test_codex_config.py" || status=1
python3 -I "$here/test_install.py" || status=1
python3 -I "$here/test_setup_tools.py" || status=1
exit "$status"
