#!/usr/bin/env python3
"""Say what a project's Spec Kit installation lacks for Claude Code and for Codex, and whether its skills are the pinned ones (ADR 0019).

The factory pins one release of Spec Kit. This repository's own `.specify/` is that pin: `.specify/integration.json`
holds the version and `.specify/integrations/<key>.manifest.json` holds the SHA-256 of every file the release writes for
one integration. The worker refuses to start when a skill of the protected checkout differs from those hashes, so the
installer compares a project against the same manifests.

This script only reads. It never runs `specify` and never writes a file. It prints facts, one per line, with a tab
between the fields, and the installer decides what to do:

  absent                      the project has no `.specify/`
  invalid       REASON        `.specify/integration.json` cannot be used
  linked        PATH          a path the installer would read or write is, or goes through, a symbolic link
  reference     VERSION       the version the factory pins
  version       VERSION       the version the project records
  version-mismatch VERSION    the project records another version; nothing else is checked
  installed     KEY           an integration the project lists as installed (one line each)
  unknown       KEY           an installed integration the factory has no pin for
  modified      PATH          a file of an installed integration whose hash is not the pinned one
  missing       PATH          a file of an installed integration that is not there
  unlisted-files KEY PATH     an integration that is not listed but whose files are already there
  to-add        KEY           an integration the factory pins and the project lacks
  will-write    KEY PATH      a file `specify integration install KEY` writes

The project is not trusted. The JSON is read with a size limit, a link is never followed, and a value that came from the
project is checked against a plain pattern before it is printed.

Usage:
  speckit_integration.py inspect --reference ROOT --project DIR

Exit codes: 0 the facts were printed, 1 the reference (the factory's own `.specify/`) is unusable, 2 wrong arguments.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys

KEYS = ("claude", "codex")
MAX_JSON = 65536
MAX_FILE = 4 * 1024 * 1024
PLAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
HEX = re.compile(r"^[0-9a-f]{64}$")


class ReferenceError_(Exception):
    pass


def read_json_object(path):
    """The object in a small regular file, or (None, the reason). A link, a special file or a large file is refused."""
    try:
        info = os.lstat(path)
    except OSError:
        return None, "%s cannot be read" % os.path.basename(path)
    if not os.path.isfile(path) or os.path.islink(path):
        return None, "%s is not a regular file" % os.path.basename(path)
    if info.st_size > MAX_JSON:
        return None, "%s is larger than %d bytes" % (os.path.basename(path), MAX_JSON)
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, ValueError):
        return None, "%s is not plain JSON" % os.path.basename(path)
    if not isinstance(value, dict):
        return None, "%s is not a JSON object" % os.path.basename(path)
    return value, ""


def load_reference(root):
    """(version, {key: {path: sha256}}) from the factory's own `.specify/`."""
    integration, why = read_json_object(os.path.join(root, ".specify", "integration.json"))
    if integration is None:
        raise ReferenceError_(why)
    version = integration.get("version")
    if not isinstance(version, str) or not PLAIN.match(version):
        raise ReferenceError_("the reference integration.json has no usable version")
    manifests = {}
    for key in KEYS:
        manifest, why = read_json_object(os.path.join(root, ".specify", "integrations", key + ".manifest.json"))
        if manifest is None:
            raise ReferenceError_(why)
        files = manifest.get("files")
        if manifest.get("version") != version or not isinstance(files, dict) or not files:
            raise ReferenceError_("the reference manifest of %s does not match version %s" % (key, version))
        for path, digest in files.items():
            if not isinstance(digest, str) or not HEX.match(digest) or path.startswith("/") or ".." in path.split("/"):
                raise ReferenceError_("the reference manifest of %s lists an unusable entry" % key)
        manifests[key] = dict(files)
    return version, manifests


def has_link_component(project, relative):
    """True when any part of the path, the last one included, is a symbolic link. A part that does not exist ends the walk."""
    current = project
    for part in relative.split("/"):
        current = os.path.join(current, part)
        if os.path.islink(current):
            return True
        if not os.path.lexists(current):
            return False
    return False


def digest_of(path):
    """The SHA-256 of a small regular file, or None when it is absent, not a regular file or too large."""
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.lstat(path).st_size > MAX_FILE:
            return None
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return None


def installed_keys(integration):
    """The integrations the file lists, or None when the file is not in a form this script understands."""
    listed = integration.get("installed_integrations")
    if listed is None:
        default = integration.get("integration", integration.get("default_integration"))
        listed = [default] if default is not None else []
    if not isinstance(listed, list) or len(listed) > 64:
        return None
    keys = []
    for entry in listed:
        if not isinstance(entry, str) or not PLAIN.match(entry):
            return None
        if entry not in keys:
            keys.append(entry)
    return keys


def inspect(project, root):
    version_pinned, manifests = load_reference(root)
    spec = os.path.join(project, ".specify")
    if os.path.islink(spec):
        return ["linked\t.specify"]
    if not os.path.lexists(spec):
        return ["absent"]
    if not os.path.isdir(spec):
        return ["invalid\t.specify is not a folder"]
    if has_link_component(project, ".specify/integration.json"):
        return ["linked\t.specify/integration.json"]
    integration, why = read_json_object(os.path.join(spec, "integration.json"))
    if integration is None:
        return ["invalid\t" + why]
    version = integration.get("version")
    if not isinstance(version, str) or not PLAIN.match(version):
        return ["invalid\tintegration.json has no usable version"]
    keys = installed_keys(integration)
    if keys is None:
        return ["invalid\tintegration.json lists its integrations in a form this script does not understand"]
    out = ["reference\t" + version_pinned, "version\t" + version]
    if version != version_pinned:
        out.append("version-mismatch\t" + version)
        return out
    out.extend("installed\t" + key for key in keys)
    out.extend("unknown\t" + key for key in keys if key not in manifests)
    for key in KEYS:
        paths = sorted(manifests[key])
        links = [path for path in paths if has_link_component(project, path)]
        if links:
            out.extend("linked\t" + path for path in links[:8])
            continue
        if key in keys:
            for path in paths:
                got = digest_of(os.path.join(project, path))
                if got is None:
                    out.append("missing\t" + path)
                elif got != manifests[key][path]:
                    out.append("modified\t" + path)
        else:
            present = [path for path in paths if os.path.lexists(os.path.join(project, path))]
            if present:
                out.append("unlisted-files\t%s\t%s" % (key, present[0]))
            else:
                out.append("to-add\t" + key)
                out.extend("will-write\t%s\t%s" % (key, path) for path in paths)
    return out


def main(argv):
    if len(argv) != 5 or argv[0] != "inspect" or argv[1] != "--reference" or argv[3] != "--project":
        sys.stderr.write("usage: speckit_integration.py inspect --reference ROOT --project DIR\n")
        return 2
    try:
        lines = inspect(argv[4], argv[2])
    except ReferenceError_ as error:
        sys.stderr.write("the factory's own Spec Kit pin cannot be used: %s\n" % error)
        return 1
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
