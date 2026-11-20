#!/usr/bin/env python3
"""Deliberate breaks of the broker and the relay, to show that the tests catch each one.

Run from the repository root:  python3 -I crates/egress/tests/mutations.py [name ...]

For each break the script rewrites one or two places in the sources (it refuses a replacement that
does not match exactly once), runs the tests of the package (the Docker end-to-end tests are left
out, they take minutes and need the images), prints the tests that failed, and puts the sources
back. A break that no test catches is reported as MISSED and the script exits with 1. The sources
are restored even when the run is interrupted, and the script stops if the tree has changes in
crates/egress or apps/egress-sidecar when it starts, so a restore can never lose work.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
CORE = "crates/egress/src/broker/core.rs"
TOKEN = "crates/egress/src/broker/token.rs"
SECRET = "crates/egress/src/http/secret.rs"
SERVER = "crates/egress/src/http/server.rs"
POLICY = "crates/egress/src/relay/policy.rs"
ENGINE = "crates/egress/src/relay/engine.rs"
SHAPE = "crates/egress/src/broker/shape/mod.rs"
RULES = "crates/egress/src/broker/shape/rules.rs"
JSON = "crates/egress/src/broker/shape/json.rs"
HEADERS = "crates/egress/src/broker/shape/headers.rs"

# name -> (what is broken, [(file, old, new), ...])
MUTATIONS = {
    "forward-without-checking-the-token": (
        "any credential of the right shape is accepted as the first token",
        [(CORE, "let id = *state\n        .by_hash\n        .get(&TokenHash::of(presented))\n        .ok_or((None, Refusal::UnknownToken))?;",
          "let id = *state\n        .by_hash\n        .values()\n        .next()\n        .ok_or((None, Refusal::UnknownToken))?;")],
    ),
    "forward-the-provider-request-ids": (
        "the provider's request identifier, which names the broker's account, reaches the sandbox",
        [(SERVER, "    if let Some(seconds) = response\n        .headers()\n        .get(\"retry-after\")",
          "    if let Some(value) = response.headers().get(\"request-id\").and_then(|v| v.to_str().ok()) {\n        out.push((canonical(\"request-id\"), value.to_owned()));\n    }\n    if let Some(seconds) = response\n        .headers()\n        .get(\"retry-after\")")],
    ),
    "leak-the-real-key-in-a-log": (
        "the key prints itself in Debug output, which any log line can carry",
        [(SECRET, 'f.write_str("ProviderKey(<redacted>)")', 'write!(f, "ProviderKey({})", self.0)')],
    ),
    "leak-the-real-key-in-a-stream": (
        "the streaming scrubber lets the key through",
        [(SERVER, "let clean = scrubber.push(&chunk[..n]);", "let clean = chunk[..n].to_vec();"),
         (SERVER, "let _ = wire::write_chunk(client, &scrubber.finish());", "let _ = wire::write_chunk(client, &[]);")],
    ),
    "accept-a-token-for-another-job": (
        "the audience check of the job is dropped",
        [(CORE, "} else if expected_job.is_some_and(|job| job != record.job) {", "} else if false {")],
    ),
    "accept-a-token-for-another-provider": (
        "a token works at any provider's route",
        [(CORE, "                record.providers.contains(&facts.provider),", "                true,")],
    ),
    "ignore-the-cost-ceiling": (
        "reaching the ceiling does not revoke the token and the pre-check passes it",
        [(CORE, "let at_ceiling = cost >= ceiling;", "let at_ceiling = false;"),
         (CORE, "let breach = if usage.cost >= ceiling {", "let breach = if false {")],
    ),
    "ignore-the-request-cap": (
        "the turn cap is never enforced",
        [(CORE, ".max_requests\n            .is_some_and(|max| usage.requests >= max)", ".max_requests\n            .is_some_and(|_max| false)")],
    ),
    "ignore-the-expiry": (
        "a token never expires",
        [(CORE, "} else if *now >= self.expires_at {", "} else if false {")],
    ),
    "revoke-for-job-revokes-one-token": (
        "ending a job leaves tokens of the job alive",
        [(CORE, "for id in ids {\n                revoke_in(&mut state, &id, RevokeReason::JobEnded, now, &mut events);\n            }",
          "for id in ids.into_iter().take(1) {\n                revoke_in(&mut state, &id, RevokeReason::JobEnded, now, &mut events);\n            }")],
    ),
    "store-a-token-in-clear": (
        "the broker keeps the secret itself where it should keep a hash",
        [(TOKEN, "#[derive(Clone, Copy, PartialEq, Eq, Hash)]\npub struct TokenHash([u8; 32]);", "#[derive(Clone, PartialEq, Eq, Hash, Debug)]\npub struct TokenHash(String);"),
         (TOKEN, "        let digest = ring::digest::digest(&ring::digest::SHA256, secret.as_bytes());\n        let mut out = [0_u8; 32];\n        out.copy_from_slice(digest.as_ref());\n        Self(out)", "        Self(secret.to_owned())"),
         (TOKEN, "impl fmt::Debug for TokenHash {\n    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n        f.write_str(\"TokenHash(..)\")\n    }\n}\n", "")],
    ),
    "forward-to-another-host": (
        "the upstream is taken from the Host header of the request",
        [(SERVER, 'let mut url = format!("{}{}", upstream.base, head.path);', 'let mut url = format!("http://{}{}", head.header("host").unwrap_or(""), head.path);')],
    ),
    "forward-the-job-token-upstream": (
        "the job token is passed to the provider in a header",
        [(SERVER, '        .header("user-agent", "factory-model-broker");', '        .header("user-agent", "factory-model-broker")\n        .header("x-forwarded-credential", head.header("x-api-key").unwrap_or(""));')],
    ),
    "forward-the-body-without-the-schema": (
        "the body is read as JSON and forwarded, as it was before finding EGR-1: mcp_servers and server tools reach the provider",
        [(SERVER, "    let mut object = match shape::check_body(wire, &body) {\n        Ok(object) => object,\n        Err(violation) => return refuse_shape(stream, violation),\n    };",
          "    let mut object = match serde_json::from_slice::<Value>(&body) {\n        Ok(Value::Object(object)) => object,\n        _ => return respond_error(stream, 400, \"invalid_request\", &[]),\n    };")],
    ),
    "accept-an-unlisted-field": (
        "a top-level key that the schema does not list is accepted (mcp_servers, container, betas)",
        [(SHAPE, "            None => return Err(rules::classify_key(key)),", "            None => {}")],
    ),
    "accept-an-unlisted-tool-type": (
        "a tool or block of a type the schema does not list is accepted (web_search, web_fetch, mcp)",
        [(RULES, "        return Err(classify_tag(chosen, tagged.unknown));", "        return Ok(());")],
    ),
    "accept-a-repeated-key": (
        "an object that names a key twice is read, the last one winning",
        [(JSON, "            if !seen.insert(key.clone()) {\n                return Err(Violation::DuplicateKey);\n            }", "            seen.insert(key.clone());")],
    ),
    "accept-an-image-by-address": (
        "an image the provider would have to fetch from an address is accepted",
        [(RULES, "            Some(text) if text.len() <= *max && text.starts_with(\"data:image/\") => Ok(()),\n            Some(_) => Err(Violation::RemoteContent),", "            Some(_) => Ok(()),")],
    ),
    "forward-the-beta-header-unchanged": (
        "the sandbox's anthropic-beta list is forwarded as it came, server tool betas included",
        [(HEADERS, "    Ok((!kept.is_empty()).then(|| kept.join(\",\")))", "    Ok(Some(value.to_owned()))")],
    ),
    "do-not-clamp-the-output-limit": (
        "a request may ask for any number of output tokens",
        [(SERVER, "let over = match value.as_u64() {\n                Some(asked) => asked > cap,\n                // A negative, fractional or non-numeric limit is replaced by the cap.\n                None => true,\n            };", "let over = false;")],
    ),
    "openai-request-without-a-cap": (
        "a Responses or Chat request that names no output limit is forwarded without one (RR-1)",
        [(SERVER, "    if !present {\n        object.insert(insert.to_owned(), Value::from(cap));\n        changed = true;\n    }",
          "    if !present && wire == Wire::AnthropicMessages {\n        object.insert(insert.to_owned(), Value::from(cap));\n        changed = true;\n    }")],
    ),
    "accept-a-one-hour-cache-write": (
        "ttl 1h is accepted, and booked at the five-minute rate (RR-2)",
        [("crates/egress/src/broker/shape/anthropic.rs", '("ttl", Rule::Enum(&["5m"])),',
          '("ttl", Rule::Enum(&["5m", "1h"])),')],
    ),
    "relay-allows-the-azure-platform-address": (
        "168.63.129.16 is not in the relay's deny ranges (RR-5)",
        [(POLICY, '    "168.63.129.16/32",\n', "")],
    ),
    "relay-allows-the-ietf-protocol-block": (
        "192.0.0.0/24 is not in the relay's deny ranges (RR-5)",
        [(POLICY, '    "192.0.0.0/24",\n', "")],
    ),
    "relay-allows-site-local-ipv6": (
        "fec0::/10 is not in the relay's deny ranges (RR-5)",
        [(POLICY, '    "fec0::/10",\n', "")],
    ),
    "json-reader-without-a-value-limit": (
        "the strict reader builds a body of millions of values (RR-6)",
        [(JSON, "        if self.values > MAX_VALUES {", "        if false && self.values > MAX_VALUES {")],
    ),
    "broker-attests-a-tool-use-turn": (
        "a stop reason of tool_use is recorded as the end of a turn (RR-14)",
        [("crates/egress/src/http/usage.rs", '        "tool_use" => AnswerEnd::ToolUse,\n        // `max_tokens`',
          '        "tool_use" => AnswerEnd::EndTurn,\n        // `max_tokens`')],
    ),
    "do-not-count-failed-attempts": (
        "a request counts only when the answer was good",
        [(CORE, "        record.usage.requests = record.usage.requests.saturating_add(1);\n        record.in_flight = record.in_flight.saturating_add(1);", "        record.in_flight = record.in_flight.saturating_add(1);")],
    ),
    "sidecar-resolves-a-name-from-the-sandbox": (
        "broker mode resolves a host name before it connects",
        [(ENGINE, "        let host = upstream.ip().to_string();\n", "        let host = upstream.ip().to_string();\n        let _ = self.resolver.resolve(\"attacker.example\");\n")],
    ),
    "sidecar-resolves-before-the-allowlist": (
        "connect mode resolves the name before it checks the list",
        [(ENGINE, "        let target = match policy.check_target(&authority) {", "        let _ = self.resolver.resolve(authority.split(':').next().unwrap_or(\"\"));\n        let target = match policy.check_target(&authority) {")],
    ),
    "sidecar-skips-the-resolved-range-check": (
        "an address in a private range is connected to",
        [(POLICY, "        if answers.iter().any(|ip| is_denied(&self.deny_ranges, *ip)) {", "        if false && answers.iter().any(|ip| is_denied(&self.deny_ranges, *ip)) {")],
    ),
    "sidecar-matches-a-host-by-suffix": (
        "the allowlist accepts any name that ends with a listed host",
        [(POLICY, "            .find(|rule| rule.host == target.host)", "            .find(|rule| target.host.ends_with(&rule.host))")],
    ),
    "sidecar-ignores-the-byte-quota": (
        "the byte quota never runs out",
        [(ENGINE, "            let grant = want.min(self.max.saturating_sub(used));", "            let grant = want;")],
    ),
}


def run_tests() -> tuple[bool, list[str]]:
    """Returns (compiled, failed test names)."""
    proc = subprocess.run(
        ["cargo", "nextest", "run", "-p", "factory-egress", "-p", "factory-egress-sidecar",
         "--no-fail-fast", "-E", "not binary(e2e_docker)"],
        cwd=ROOT, capture_output=True, text=True,
    )
    text = proc.stdout + proc.stderr
    if "could not compile" in text or "error[E" in text:
        return False, []
    failed = sorted(set(re.findall(r"^\s+FAIL \[[^\]]*\] \(\s*\d+/\d+\) (.+)$", text, re.M)))
    return True, failed


def main() -> int:
    wanted = sys.argv[1:] or list(MUTATIONS)
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "crates/egress", "apps/egress-sidecar"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout.strip()
    if dirty:
        print("refusing to run: there are uncommitted changes in the package:\n" + dirty)
        return 2
    missed = []
    for name in wanted:
        what, edits = MUTATIONS[name]
        originals: dict[str, str] = {}
        try:
            for path, old, new in edits:
                file = ROOT / path
                text = file.read_text()
                originals.setdefault(path, text)
                if text.count(old) != 1:
                    print(f"{name}: the text to replace occurs {text.count(old)} times in {path}")
                    return 2
                file.write_text(text.replace(old, new))
            compiled, failed = run_tests()
        finally:
            for path, text in originals.items():
                (ROOT / path).write_text(text)
        if not compiled:
            print(f"BROKEN BUILD  {name}: {what}")
            missed.append(name)
        elif failed:
            print(f"CAUGHT  {name}: {what}")
            for test in failed[:6]:
                print(f"          {test}")
            if len(failed) > 6:
                print(f"          ... and {len(failed) - 6} more")
        else:
            print(f"MISSED  {name}: {what}")
            missed.append(name)
        sys.stdout.flush()
    clean = subprocess.run(
        ["git", "status", "--porcelain", "crates/egress", "apps/egress-sidecar"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout.strip()
    if clean:
        print("the sources were not restored:\n" + clean)
        return 2
    print("all sources restored")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
