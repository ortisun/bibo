#!/usr/bin/env bash
# scripts/tests/run-install-tests.sh - run the installer tests and the project map tests.
# A step line of scripts/ci.sh cannot hold two commands, so this script runs both and fails if either fails.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
status=0
python3 -I "$here/test_project_map.py" || status=1
python3 -I "$here/test_install.py" || status=1
exit "$status"
