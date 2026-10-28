#!/usr/bin/env python3
"""The spike's FAKE model provider with three extra directives for the runtime adapter tests.

Fidelity: fake. This file imports `fake_provider` from the agent runtime spike
(fixtures/recordings/agent-cli/fake/, mounted read-only at /fake/spike) and adds, without changing
that file:

  FAKE:OUTPUT <json>          answer with this JSON document as the text of the reply
  FAKE:USAGE <input> <output> report these token counts (and no cache tokens) from now on
  markers                     the request log also counts the strings the runtime tests plant
  /out/script.json            a control file the test writes. It is read on every request and holds
                              any of {"output": <json>, "usage": [in, out], "http": <status>,
                              "sleep": <seconds>}. It takes the place of a directive in the prompt,
                              for a test that cannot change the prompt after the request was built.

It holds no real credential, makes no network call of its own and never reads a key from the
environment: the expected fake key is a file (--key-file) that the test generated at run time.
"""

import json
import re
import sys

sys.path.insert(0, "/fake/spike")

import fake_provider as fp  # noqa: E402  (path set above)

OUTPUT = re.compile(r"FAKE:OUTPUT[ \t]+([^\n]*)")
USAGE = re.compile(r"FAKE:USAGE[ \t]+(\d+)[ \t]+(\d+)")

fp.MARKERS.extend(
    [
        "HOOK-RAN",
        "MCP-RAN",
        "REPO-SKILL-BODY-MARKER",
        "ALPHA-SKILL-BODY-MARKER",
        "BETA-SKILL-BODY-MARKER",
        "HOSTILE-USER-SETTINGS-MARKER",
    ]
)

_original = fp.find_directive
SCRIPT = "/out/script.json"


def _script():
    try:
        with open(SCRIPT, encoding="utf-8") as handle:
            loaded = json.load(handle)
            return loaded if isinstance(loaded, dict) else {}
    except (OSError, ValueError):
        return {}


def find_directive(texts):
    script = _script()
    if "usage" in script:
        fp.USAGE_INPUT, fp.USAGE_OUTPUT = int(script["usage"][0]), int(script["usage"][1])
        fp.USAGE_CACHE_CREATE = 0
        fp.USAGE_CACHE_READ = 0
    if "http" in script:
        return ("HTTP", str(script["http"]))
    if "sleep" in script:
        return ("SLEEP", str(script["sleep"]))
    if "output" in script:
        fp.Config.struct_reply = script["output"]
        return ("STRUCT", "")
    for text in texts:
        usage = USAGE.search(text)
        if usage:
            fp.USAGE_INPUT = int(usage.group(1))
            fp.USAGE_OUTPUT = int(usage.group(2))
            fp.USAGE_CACHE_CREATE = 0
            fp.USAGE_CACHE_READ = 0
    for text in texts:
        output = OUTPUT.search(text)
        if output:
            fp.Config.struct_reply = json.loads(output.group(1))
            return ("STRUCT", "")
    return _original(texts)


fp.find_directive = find_directive

if __name__ == "__main__":
    sys.exit(fp.main(sys.argv[1:]))
