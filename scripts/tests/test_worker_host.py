#!/usr/bin/env python3
"""Tests for scripts/worker-host.sh (ADR 0036). Standard library only; the script itself runs its helper with uv
and PyYAML, so uv must be on PATH. Run it with:
    python3 -I scripts/tests/test_worker_host.py

The script runs for real. `docker`, `getcap`, `sudo` and the worker program are small fakes, the platform comes from
OPS_PLATFORM, and the "database" is a socket this test listens on. Every folder is under the canonical /tmp, which
the sandbox policy allows as a mount source on Linux and on macOS (the system temporary directory of macOS is under
/var, which it forbids). Each test builds a situation that is ready, shows the outcome, and changes one thing.
"""
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
SCRIPT = os.path.join(ROOT, "scripts", "worker-host.sh")
BASH = "/bin/bash" if os.path.exists("/bin/bash") else "bash"
UV = shutil.which("uv") or ""
# A value shaped like nothing secret, written at run time, that must never appear in the output.
PASSWORD = "-".join(["pw", "for", "the", "worker", "login"])

FAKE_DOCKER = r'''#!/bin/sh
case "$1 $2" in
  "info "*) exit 0 ;;
  "context inspect") echo "unix:///fake/docker.sock" ;;
  "version --format") echo "linux/arm64" ;;
  "image inspect") [ -z "$FAKE_NO_IMAGE" ] || exit 1 ;;
  "network inspect") echo "172.17.0.1" ;;
  "run --rm") echo "192.168.65.254  STREAM host.docker.internal" ;;
  *) echo "fake docker: unexpected $*" >&2; exit 9 ;;
esac
'''
FAKE_GETCAP = r'''#!/bin/sh
[ -f "$FAKE_STATE/cap" ] && echo "$1 cap_chown=ep"
exit 0
'''
FAKE_SUDO = r'''#!/bin/sh
echo "$*" >>"$FAKE_STATE/sudo.log"
[ "$1 $2" = "setcap cap_chown+ep" ] && touch "$FAKE_STATE/cap"
exit 0
'''


def write_executable(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o755)


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@unittest.skipIf(not UV, "uv is not on PATH")
class WorkerHost(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="worker-host-test-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin = os.path.join(self.tmp, "bin")
        self.state = os.path.join(self.tmp, "state")
        self.secrets = os.path.join(self.tmp, "secrets")
        self.host = os.path.join(self.tmp, "host")
        self.target = os.path.join(self.tmp, "target")
        for folder in (self.bin, self.state, self.secrets, os.path.join(self.target, "release")):
            os.makedirs(folder)
        write_executable(os.path.join(self.bin, "docker"), FAKE_DOCKER)
        write_executable(os.path.join(self.bin, "getcap"), FAKE_GETCAP)
        write_executable(os.path.join(self.bin, "sudo"), FAKE_SUDO)
        write_executable(os.path.join(self.target, "release", "factory-worker"), "#!/bin/sh\necho started\n")
        for name, value in (("pg_password_worker", PASSWORD), ("pg_password_engine", PASSWORD + "-2"),
                            ("decision_signing_key", "ab" * 32)):
            with open(os.path.join(self.secrets, name), "w", encoding="utf-8") as handle:
                handle.write(value + "\n")
            os.chmod(os.path.join(self.secrets, name), 0o600)
        self.database = socket.socket()
        self.database.bind(("127.0.0.1", 0))
        self.database.listen(8)
        self.port = self.database.getsockname()[1]
        self.addCleanup(self.database.close)
        self.credentials({"worker": {"tenants": []}})

    def credentials(self, mapping):
        os.makedirs(self.host, exist_ok=True)
        import json  # YAML is a superset of JSON, so the file needs no YAML writer.
        with open(os.path.join(self.host, "credentials.yaml"), "w", encoding="utf-8") as handle:
            json.dump(mapping, handle)

    def run_script(self, *args, platform="Darwin", env=None):
        environment = {
            "PATH": ":".join([self.bin, os.path.dirname(UV), os.path.dirname(sys.executable), "/usr/bin", "/bin"]),
            "HOME": self.tmp, "FAKE_STATE": self.state, "OPS_PLATFORM": platform,
            "FACTORY_HOST_DIR": self.host, "FACTORY_SECRETS_DIR": self.secrets,
            "FACTORY_PG_PORT": str(self.port), "CARGO_TARGET_DIR": self.target,
            "UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR", os.path.join(os.path.expanduser("~"), ".cache", "uv")),
        }
        environment.update(env or {})
        done = subprocess.run([BASH, SCRIPT, "--no-build", *args], capture_output=True, text=True, env=environment,
                              stdin=subprocess.DEVNULL)
        return done.returncode, done.stdout + done.stderr

    def config(self):
        with open(os.path.join(self.host, "worker.yaml"), encoding="utf-8") as handle:
            return handle.read()

    def test_a_ready_host_is_reported_ready_and_gets_a_config_with_the_desktop_addresses(self):
        code, out = self.run_script("--check")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.strip().splitlines()[-1], "READY")
        text = self.config()
        self.assertIn("listen: 127.0.0.1:8731", text)
        self.assertIn("192.168.65.254:8731", text, "the sidecar reaches the host-gateway address")
        self.assertIn("docker_host: unix:///fake/docker.sock", text)
        self.assertIn("token_root: %s/tokens" % self.host, text)
        self.assertEqual(mode(os.path.join(self.host, "worker.yaml")), 0o600)
        self.assertNotIn(PASSWORD, out, "no secret is printed")

    def test_the_url_files_reach_the_database_on_loopback_and_only_their_owner_reads_them(self):
        self.assertEqual(self.run_script("--check")[0], 0)
        url = os.path.join(self.host, "secrets", "db_worker")
        with open(url, encoding="utf-8") as handle:
            text = handle.read()
        self.assertEqual(text, "postgres://factory_worker:%s@127.0.0.1:%d/factory" % (PASSWORD, self.port))
        self.assertEqual(mode(url), 0o600)
        self.assertEqual(mode(os.path.join(self.host, "secrets")), 0o700)

    def test_the_credentials_are_merged_over_the_template_without_dropping_its_keys(self):
        self.credentials({"broker": {"upstreams": [{"provider": "anthropic", "base_url": "https://api.anthropic.com",
                                                    "key_file": "/srv/keys/token"}]}})
        self.assertEqual(self.run_script("--check")[0], 0)
        text = self.config()
        self.assertIn("key_file: /srv/keys/token", text)
        self.assertIn("listen: 127.0.0.1:8731", text, "a key the file does not name is kept")

    def test_without_credentials_the_script_stops_blocked_and_names_what_a_person_supplies(self):
        os.remove(os.path.join(self.host, "credentials.yaml"))
        code, out = self.run_script("--check")
        self.assertEqual(code, 3, out)
        self.assertIn("BLOCKED: credentials:", out)
        self.assertIn("broker.upstreams", out)
        self.assertFalse(os.path.exists(os.path.join(self.host, "worker.yaml")), "nothing is written when blocked")

    def test_a_folder_under_a_forbidden_mount_source_is_refused_before_anything_is_written(self):
        code, out = self.run_script("--check", env={"FACTORY_HOST_DIR": "/home/someone/bibo/.local/host-worker"})
        self.assertEqual(code, 3, out)
        self.assertIn("forbidden mount source", out)
        self.assertIn("under /home", out)

    def test_on_linux_the_broker_listens_on_the_bridge_gateway_and_the_tokens_go_to_the_runtime_folder(self):
        runtime = os.path.join(self.tmp, "run-user")
        os.makedirs(runtime)
        open(os.path.join(self.state, "cap"), "w").close()
        code, out = self.run_script("--check", platform="Linux", env={"XDG_RUNTIME_DIR": runtime})
        self.assertEqual(code, 0, out)
        text = self.config()
        self.assertIn("listen: 172.17.0.1:8731", text)
        self.assertIn("token_root: %s/factory-tokens" % runtime, text)

    def test_on_linux_a_program_without_cap_chown_is_blocked_and_the_command_is_named(self):
        code, out = self.run_script("--check", platform="Linux")
        self.assertEqual(code, 3, out)
        self.assertIn("lacks cap_chown", out)
        self.assertIn("sudo setcap cap_chown+ep %s/release/factory-worker" % self.target, out)
        self.assertFalse(os.path.exists(os.path.join(self.state, "sudo.log")), "sudo is never run without --setcap")

    def test_on_linux_setcap_asks_sudo_for_that_capability_only(self):
        code, out = self.run_script("--check", "--setcap", platform="Linux")
        self.assertEqual(code, 0, out)
        with open(os.path.join(self.state, "sudo.log"), encoding="utf-8") as handle:
            self.assertEqual(handle.read().split(), ["setcap", "cap_chown+ep", "%s/release/factory-worker" % self.target])

    def test_missing_images_a_silent_database_and_missing_secrets_each_have_their_own_line(self):
        self.database.close()
        os.remove(os.path.join(self.secrets, "decision_signing_key"))
        code, out = self.run_script("--check", env={"FAKE_NO_IMAGE": "1"})
        self.assertEqual(code, 3, out)
        for word in ("BLOCKED: images:", "BLOCKED: database:", "BLOCKED: secrets:"):
            self.assertIn(word, out)

    def test_without_check_the_worker_is_started_with_the_generated_configuration(self):
        code, out = self.run_script()
        self.assertEqual(code, 0, out)
        self.assertEqual(out.strip().splitlines()[-1], "started")


if __name__ == "__main__":
    unittest.main()
