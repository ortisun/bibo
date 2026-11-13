#!/usr/bin/env python3
"""Make the factory's GitHub App from a manifest generated from the security policy.

GitHub can register an App from a manifest: a JSON document that names the App and its
permissions, posted from a form in the browser of the person who will own it
(https://docs.github.com/apps/sharing-github-apps/registering-a-github-app-from-a-manifest).
This script writes that manifest from `policies/security.yaml`
(`credentials.github_app.permissions_required`), so the App holds exactly the permissions the
factory's own check (`crates/github/src/permissions.rs`, `audit_app`) accepts and nothing more.

The App has no webhook: the manifest has no `hook_attributes` and subscribes to no event. The
factory's first real run starts its job through the API (`factory-cli submit`, `POST /v1/jobs`),
not through a webhook, so nothing needs one.

Commands:

  render [--name NAME] [--org ORG] [--out DIR]
      Write DIR/manifest.json and DIR/create-github-app.html. Open the page in a browser where
      you are signed in to GitHub, check the permissions it lists, and press the button. GitHub
      shows the App it is about to create; press "Create GitHub App". GitHub then sends the
      browser to http://127.0.0.1:8973/created?code=... . Nothing listens there unless you use
      `serve`: copy the code from the address bar and run `convert`. The code works for one hour.

  serve [--name NAME] [--org ORG] [--out DIR] [--port 8973]
      The same page, served on 127.0.0.1, which also catches GitHub's redirect and converts the
      code at once. Stops after one App is made.

  convert CODE [--out DIR]
      Ask GitHub for the new App's id and private key (POST /app-manifests/CODE/conversions,
      which needs no credential: the code is the credential). The key is written to
      DIR/github-app.private-key.pem with mode 0600 and never printed. The webhook secret and the
      client secret GitHub also returns are not kept. Prints the App's id, name and settings page.

  check
      Print the permissions the manifest would ask for, and check them against the forbidden list
      of the policy. Reads nothing but the policy. Exit 1 when they disagree.

DIR defaults to ~/.config/software-factory/github-app. Exit codes: 0 done, 1 failed, 2 wrong usage.
"""

from __future__ import annotations

import argparse
import html
import http.server
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
POLICY = ROOT / "policies" / "security.yaml"
DEFAULT_OUT = Path.home() / ".config" / "software-factory" / "github-app"
DEFAULT_NAME = "software-factory"
DEFAULT_PORT = 8973
LEVELS = {"read", "write"}


class PolicyError(Exception):
    """The policy does not say what the manifest needs."""


def _block(lines: list[str], header: str) -> list[str]:
    """The lines of the block that starts with `header` (indented under it), comments removed."""
    found: list[str] = []
    inside = False
    indent = -1
    for raw in lines:
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        depth = len(line) - len(line.lstrip(" "))
        if not inside:
            if line.strip() == header:
                inside = True
                indent = depth
            continue
        if depth <= indent:
            break
        found.append(line)
    return found


def read_policy(path: Path = POLICY) -> tuple[dict[str, str], list[str]]:
    """The permissions the App needs (name to level) and the permissions it must not hold."""
    lines = path.read_text(encoding="utf-8").splitlines()
    app = _block(_block(lines, "credentials:"), "github_app:")
    if not app:
        raise PolicyError("policies/security.yaml has no credentials.github_app block")
    required: dict[str, str] = {}
    for line in _block(app, "permissions_required:"):
        name, _, level = line.strip().partition(":")
        name, level = name.strip(), level.strip()
        if level not in LEVELS:
            raise PolicyError(f"the permission {name} has the level {level!r}, not read or write")
        required[name] = level
    forbidden = [
        line.strip().removeprefix("- ").strip() for line in _block(app, "permissions_forbidden:")
    ]
    if not required:
        raise PolicyError("credentials.github_app.permissions_required is empty")
    clash = sorted(set(required) & set(forbidden))
    if clash:
        raise PolicyError(f"the policy both requires and forbids: {', '.join(clash)}")
    return required, forbidden


def manifest(name: str, owner_url: str, port: int, permissions: dict[str, str]) -> dict[str, Any]:
    """The manifest GitHub reads. No webhook: no `hook_attributes` and no events."""
    return {
        "name": name,
        "url": owner_url,
        "description": (
            "The software factory's App. It opens draft pull requests and never merges; "
            "every permission comes from policies/security.yaml."
        ),
        "public": False,
        "redirect_url": f"http://127.0.0.1:{port}/created",
        "default_permissions": dict(sorted(permissions.items())),
        "default_events": [],
    }


def page(document: dict[str, Any], org: str | None, state: str) -> str:
    """A page with one button that posts the manifest to GitHub."""
    if org:
        target = f"https://github.com/organizations/{urllib.parse.quote(org)}/settings/apps/new"
    else:
        target = "https://github.com/settings/apps/new"
    action = f"{target}?state={urllib.parse.quote(state)}"
    rows = "\n".join(
        f"<tr><td><code>{html.escape(name)}</code></td><td>{html.escape(level)}</td></tr>"
        for name, level in document["default_permissions"].items()
    )
    return f"""<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Create the factory's GitHub App</title>
<style>body{{font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}
table{{border-collapse:collapse}}td{{border:1px solid #999;padding:.2rem .6rem}}
button{{font-size:1.1rem;padding:.5rem 1rem}}</style></head>
<body>
<h1>Create the factory's GitHub App</h1>
<p>This page sends GitHub a manifest for a private App named
<strong>{html.escape(document["name"])}</strong>{" owned by the organization " + html.escape(org) if org else " owned by your account"}.
GitHub shows you the App before it creates anything.</p>
<p>The App asks for these permissions, which are the ones
<code>policies/security.yaml</code> requires, and no others:</p>
<table>{rows}</table>
<p>It has no webhook and subscribes to no event. It is not public.</p>
<form action="{html.escape(action)}" method="post">
<input type="hidden" name="manifest" value="{html.escape(json.dumps(document))}">
<p><button type="submit">Create the App on GitHub</button></p>
</form>
<p>After you press "Create GitHub App" on GitHub, your browser goes to
<code>{html.escape(document["redirect_url"])}</code>. If nothing answers there, copy the
<code>code</code> from the address bar and run
<code>scripts/github_app_manifest.py convert CODE</code> within the hour.</p>
</body></html>
"""


def write_private(path: Path, text: str) -> None:
    """Write a file only its owner can read."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, 0o600)


def render(name: str, org: str | None, out: Path, port: int) -> tuple[Path, str]:
    """Write the manifest and the page. Returns the page and the state the redirect must carry."""
    required, _ = read_policy()
    owner_url = f"https://github.com/{org}" if org else "https://github.com"
    document = manifest(name, owner_url, port, required)
    state = secrets.token_urlsafe(16)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    (out / "manifest.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    target = out / "create-github-app.html"
    target.write_text(page(document, org, state), encoding="utf-8")
    write_private(out / "state", state + "\n")
    return target, state


def convert(code: str, out: Path) -> dict[str, Any]:
    """Exchange the code for the App's id and key. The key goes to a 0600 file, never to output."""
    if not code or not all(ch.isalnum() or ch in "-_" for ch in code):
        raise ValueError("the code is the letters and digits GitHub put after code= in the address")
    request = urllib.request.Request(
        f"https://api.github.com/app-manifests/{code}/conversions",
        method="POST",
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "software-factory-app-manifest",
        },
        data=b"",
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - fixed https host
        answer: dict[str, Any] = json.loads(response.read().decode("utf-8"))
    pem = answer.get("pem")
    if not isinstance(pem, str) or "PRIVATE KEY" not in pem:
        raise ValueError("GitHub's answer holds no private key")
    key_file = out / "github-app.private-key.pem"
    write_private(key_file, pem)
    facts = {
        "app_id": answer.get("id"),
        "slug": answer.get("slug"),
        "settings": answer.get("html_url"),
        "key_file": str(key_file),
    }
    write_private(out / "app.json", json.dumps(facts, indent=2) + "\n")
    return facts


def report(facts: dict[str, Any]) -> None:
    print(f"The App is made: id {facts['app_id']}, name {facts['slug']}.")
    print(f"Its settings page: {facts['settings']}")
    print(f"Its private key: {facts['key_file']} (mode 600; never share it)")
    print("Next: install it on the fixture repository only (docs/guides/first-real-run.md, step 3), and set")
    print(f"  export FACTORY_E2E_GITHUB_APP_ID={facts['app_id']}")
    print(f"  export FACTORY_E2E_GITHUB_APP_KEY_FILE={facts['key_file']}")


def serve(name: str, org: str | None, out: Path, port: int) -> int:
    target, state = render(name, org, out, port)
    body = target.read_bytes()
    made: list[dict[str, Any]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - the base's name
            return

        def do_GET(self) -> None:  # noqa: N802 - the base's name
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/":
                self._send(200, body)
                return
            if parsed.path != "/created":
                self._send(404, b"Not here.")
                return
            query = urllib.parse.parse_qs(parsed.query)
            if query.get("state", [""])[0] != state:
                self._send(400, b"The state does not match the page this script served.")
                return
            try:
                made.append(convert(query.get("code", [""])[0], out))
            except (ValueError, urllib.error.URLError) as error:
                self._send(502, f"The App could not be fetched from GitHub: {error}".encode())
                return
            self._send(200, b"The App is made. Go back to the terminal.")

        def _send(self, status: int, text: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(text)

    server = http.server.HTTPServer(("127.0.0.1", port), Handler)
    print(f"Open http://127.0.0.1:{port}/ in the browser where you are signed in to GitHub.")
    while not made:
        server.handle_request()
    report(made[0])
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("render", "serve"):
        sub = commands.add_parser(command)
        sub.add_argument("--name", default=DEFAULT_NAME)
        sub.add_argument("--org", default=None)
        sub.add_argument("--out", type=Path, default=DEFAULT_OUT)
        sub.add_argument("--port", type=int, default=DEFAULT_PORT)
    sub = commands.add_parser("convert")
    sub.add_argument("code")
    sub.add_argument("--out", type=Path, default=DEFAULT_OUT)
    commands.add_parser("check")
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            required, forbidden = read_policy()
            for name, level in sorted(required.items()):
                print(f"{name}: {level}")
            print(f"never: {', '.join(forbidden)}")
            return 0
        if args.command == "render":
            target, _ = render(args.name, args.org, args.out, args.port)
            print(f"Open {target} in the browser where you are signed in to GitHub.")
            return 0
        if args.command == "serve":
            return serve(args.name, args.org, args.out, args.port)
        report(convert(args.code, args.out))
        return 0
    except (PolicyError, ValueError, OSError, urllib.error.URLError) as error:
        print(f"github_app_manifest.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
