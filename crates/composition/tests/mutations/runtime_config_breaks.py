"""Deliberate breaks of the start-up checks of the worker's runtime keys (findings DR-6 and DR-9 of
the review of the design gate round two), each of which a test must catch.

    python3 -I crates/composition/tests/mutations/runtime_config_breaks.py [WORD ...]

* DR-9: `github.web_base_url` is read the way the adapter's link filter reads it (`config.rs`,
  `github/src/text.rs`).
* DR-6: a Docker configuration directory that names a daemon or a credential helper stops the start
  unless `sandbox.allow_docker_config_contexts` is set, and the production profile refuses the flag
  (`config.rs`, `providers.rs`).

For each break the script changes one place in the source (the old text must occur exactly once),
runs the tests named for it with `cargo nextest`, and puts the file back. A break is CAUGHT when the
tests fail, MISSED when they pass, and INVALID when the changed source does not compile. The script
exits with 1 if any break is MISSED or INVALID. It leaves the working tree as it found it, also when
it is interrupted, but run it on a clean tree. Words after the script name select the breaks whose
name contains one of them.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
CONFIG = "crates/composition/src/config.rs"
PROVIDERS = "crates/composition/src/providers.rs"

CONFIG_TESTS = (["-p", "factory-composition", "--lib"], "test(config::tests)")
PROVIDER_TESTS = (["-p", "factory-composition", "--test", "providers"], "all()")

# (name, tests, [(file, old, new)])
BREAKS = [
    # ---- DR-9: the link host ----
    (
        "DR-9: the authority of the web address may hold any character (a backslash passes the start-up check)",
        CONFIG_TESTS,
        [(CONFIG, "            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':')))\n        .then_some(\n            \"the host must be a name", "            .all(|_| true))\n        .then_some(\n            \"the host must be a name")],
    ),
    (
        "DR-9: the link host is read by the loose parser of the configuration again (a backslash hides a host)",
        CONFIG_TESTS,
        [(CONFIG, "            && factory_github::keeps_link(&github.web_base_url, &domains);", "            && host_of(&github.web_base_url).map(str::to_ascii_lowercase).as_deref().is_some_and(|host| domains.iter().any(|domain| host == domain || host.ends_with(&format!(\".{domain}\"))));")],
    ),
    (
        "DR-9: the link host check lets a backslash through when the host before it is listed",
        CONFIG_TESTS,
        [(CONFIG, "        let allowed = !github.web_base_url.contains('\\\\')\n            && ", "        let allowed = true\n            && ")],
    ),
    (
        "DR-9: the link host check does not require https, which the filter does",
        CONFIG_TESTS,
        [(CONFIG, "            && factory_github::keeps_link(&github.web_base_url, &domains);", "            && factory_github::keeps_link(&github.web_base_url.replacen(\"http://\", \"https://\", 1), &domains);")],
    ),
    # ---- DR-6: the Docker configuration directory ----
    (
        "DR-6: a contexts folder with an entry is accepted",
        PROVIDER_TESTS,
        [(PROVIDERS, "                if entries.next().is_some() {\n                    return Some(\"has a contexts folder with an entry, which can name a daemon\");\n                }", "                let _ = entries.next();")],
    ),
    (
        "DR-6: a contexts entry that is not a folder is accepted",
        PROVIDER_TESTS,
        [(PROVIDERS, "        Ok(found) if !found.is_dir() => return Some(\"has a contexts entry that is not a folder\"),\n", "        Ok(found) if !found.is_dir() => return None,\n")],
    ),
    (
        "DR-6: a currentContext other than the default is accepted",
        PROVIDER_TESTS,
        [(PROVIDERS, "        Some(_) => {\n            return Some(\"has a config.json that names a currentContext other than the default\");\n        }", "        Some(_) => {}")],
    ),
    (
        "DR-6: a credential helper (credsStore) is accepted",
        PROVIDER_TESTS,
        [(PROVIDERS, "        Some(_) => return Some(\"has a config.json that names a credential helper (credsStore)\"),", "        Some(_) => {}")],
    ),
    (
        "DR-6: credential helpers by registry (credHelpers) are accepted",
        PROVIDER_TESTS,
        [(PROVIDERS, "        Some(_) => return Some(\"has a config.json that names credential helpers (credHelpers)\"),", "        Some(_) => {}")],
    ),
    (
        "DR-6: a config.json that is not JSON, or not an object, is accepted",
        PROVIDER_TESTS,
        [(PROVIDERS, "        return Some(\"has a config.json that is not a JSON object\");", "        return None;")],
    ),
    (
        "DR-6: a config.json of any size is read",
        PROVIDER_TESTS,
        [(PROVIDERS, "const DOCKER_CONFIG_FILE_LIMIT: u64 = 1024 * 1024;", "const DOCKER_CONFIG_FILE_LIMIT: u64 = u64::MAX;")],
    ),
    (
        "DR-6: the content of the directory is never read",
        PROVIDER_TESTS,
        [(PROVIDERS, "        if !sandbox.allow_docker_config_contexts {\n            if let Some(problem)", "        if false {\n            if let Some(problem)")],
    ),
    (
        "DR-6: the flag does not lift the check",
        PROVIDER_TESTS,
        [(PROVIDERS, "        if !sandbox.allow_docker_config_contexts {\n            if let Some(problem)", "        if true {\n            if let Some(problem)")],
    ),
    (
        "DR-6: the client is not told to use the default context",
        PROVIDER_TESTS,
        [(PROVIDERS, "                .push((\"DOCKER_CONTEXT\".to_owned(), \"default\".to_owned()));", "                .push((\"DOCKER_UNRELATED\".to_owned(), \"default\".to_owned()));")],
    ),
    (
        "DR-6: the client is told to use the default context also when the flag is set",
        PROVIDER_TESTS,
        [(PROVIDERS, "        if !sandbox.allow_docker_config_contexts {\n            // What the directory holds when a command runs", "        if true {\n            // What the directory holds when a command runs")],
    ),
    (
        "DR-6: the production profile accepts the flag",
        CONFIG_TESTS,
        [(CONFIG, "        if self.allow_docker_config_contexts && profile == Profile::Production {", "        if false && self.allow_docker_config_contexts && profile == Profile::Production {")],
    ),
]


def command(tests):
    packages, expression = tests
    return ["cargo", "nextest", "run", "--offline", "--no-fail-fast", *packages, "-E", expression]


def failed_tests(output):
    found = set()
    for line in output.splitlines():
        words = line.split()
        if len(words) >= 4 and words[0] == "FAIL":
            found.add(words[-1])
    return sorted(found)


def main():
    originals = {}
    outcomes = []
    only = sys.argv[1:]
    try:
        for name, tests, edits in BREAKS:
            if only and not any(word in name for word in only):
                continue
            texts = {}
            for file, old, new in edits:
                path = ROOT / file
                originals.setdefault(file, path.read_text())
                text = texts.get(file, originals[file])
                if text.count(old) != 1:
                    raise SystemExit(f"{name}: the text to change occurs {text.count(old)} times in {file}")
                texts[file] = text.replace(old, new)
            for file, text in texts.items():
                (ROOT / file).write_text(text)
            done = subprocess.run(command(tests), cwd=ROOT, capture_output=True, text=True)
            output = done.stdout + done.stderr
            for file in texts:
                (ROOT / file).write_text(originals[file])
            if "could not compile" in output or "error[E" in output:
                verdict = "INVALID (does not compile)"
            elif done.returncode == 0:
                verdict = "MISSED"
            else:
                failed = failed_tests(output)
                shown = "; ".join(failed[:3]) + (f"; and {len(failed) - 3} more" if len(failed) > 3 else "")
                verdict = "CAUGHT by " + shown
            outcomes.append((name, verdict))
            print(f"{name}: {verdict}", flush=True)
    finally:
        for file, text in originals.items():
            (ROOT / file).write_text(text)
    bad = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(bad)} of {len(outcomes)} breaks caught")
    sys.exit(1 if bad else 0)


main()
