"""Deliberate breaks of the GitHub adapter, each of which a test must catch.

    python3 -I crates/github/tests/mutations/run_mutations.py

For each break the script changes one place in the source (the old text must occur exactly once),
runs the tests named for it with `cargo nextest`, and puts the file back. A break is CAUGHT when
the tests fail, MISSED when they pass, and INVALID when the changed source does not compile. The
script exits with 1 if any break is MISSED or INVALID. It leaves the working tree as it found it,
also when it is interrupted, but run it on a clean tree.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
SRC = ROOT / "crates" / "github" / "src"

LEGACY_OLD = """        let Some(presented) = headers.signature_256.as_deref() else {
            return Err(if headers.has_legacy_signature {
                WebhookRejection::LegacySignatureOnly
            } else {
                WebhookRejection::MissingHeader(SIGNATURE_HEADER)
            });
        };"""

# (name, [(file, old, new)], [test filters])
BREAKS = [
    (
        "skip the signature comparison",
        [("webhook.rs", "        bool::from(found)", "        let _ = found;\n        true")],
        ["negative_nt_wh_02", "the_github_verifier_passes_the_webhook_contract"],
    ),
    (
        "accept a delivery that has only the legacy SHA-1 header",
        [
            ("webhook.rs", LEGACY_OLD, '        let presented = headers.signature_256.as_deref().unwrap_or("");'),
            ("webhook.rs", "        if !self.matches(presented, raw_body) {", "        if !headers.has_legacy_signature && !self.matches(presented, raw_body) {"),
        ],
        ["negative_nt_wh_02", "the_github_verifier_passes_the_webhook_contract"],
    ),
    (
        "ignore the replay table",
        [("webhook.rs", "DeliveryOutcome::Duplicate(of) => Replay::Repeat(of),", "DeliveryOutcome::Duplicate(_) => Replay::New(id),")],
        ["a_delivery_is_recorded_once"],
    ),
    (
        "identify a person by the login and not by the numeric id",
        [("parse.rs", "    Ok(GithubActor { id, login })", "    let id = if id == 0 { id } else { u64::try_from(raw.len()).unwrap_or(0) };\n    Ok(GithubActor { id, login })")],
        ["negative_nt_authz_01", "negative_nt_wh_06"],
    ),
    (
        "use an over-broad token without looking",
        [("token.rs", "        if !(covers_only_this_repository && only_what_was_asked) {", "        if false {")],
        ["negative_nt_authz_06"],
    ),
    (
        "skip the head commit in the body tag",
        [("changes.rs", '        format!("{head_sha}:{}", digest.hex().get(..32).unwrap_or_default())', '        let _ = head_sha;\n        format!("{}", digest.hex().get(..32).unwrap_or_default())')],
        ["the_body_tag_covers_the_head_commit"],
    ),
    (
        "report BLOCKED as success",
        [("changes.rs", "        GateOutcome::Blocked => CheckConclusion::ActionRequired,", "        GateOutcome::Blocked => CheckConclusion::Success,")],
        ["never_a_success", "blocked_is_never_success"],
    ),
    (
        "print a token (the token wrapper shows its text)",
        [("token.rs", '        f.write_str("Bearer(<redacted>)")', '        write!(f, "Bearer({})", self.0)')],
        ["a_bearer_and_a_live_token_print_nothing"],
    ),
    (
        "print a header value (the request wrapper shows its headers)",
        [("wire.rs", '            .field(\n                "header_names",\n                &self\n                    .headers\n                    .iter()\n                    .map(|(name, _)| name)\n                    .collect::<Vec<_>>(),\n            )', '            .field("headers", &self.headers)')],
        ["a_request_prints_no_header_value"],
    ),
    (
        "let a stage that may not write get the write credential",
        [("permissions.rs", "    matches!(stage, StageKind::Delivery)", "    let _ = stage;\n    true")],
        ["negative_nt_authz_07"],
    ),
    (
        "open the pull request as a ready one",
        [("changes.rs", '            "draft": true,', '            "draft": false,')],
        ["change_host_contract", "the_source_has_no_merge"],
    ),
    (
        "accept a comment marker written by anyone",
        [("changes.rs", '                && comment["user"]["login"].as_str() == Some(bot.as_str())', "")],
        ["a_marker_pasted_by_someone_else"],
    ),
    (
        "status writer: skip the namespace check on the label",
        [("status.rs", "            .map_err(|_| GitHostError::Rejected(Rejection::LabelNotAllowed))?;", "            .unwrap_or(());")],
        ["negative_nt_stat_01", "passes_the_whole_status_writer_contract"],
    ),
    (
        "status writer: take off every label that is not the new one",
        [("status.rs", "            if !in_namespace || name.eq_ignore_ascii_case(wanted) {", "            if name.eq_ignore_ascii_case(wanted) {")],
        ["negative_nt_stat_01", "passes_the_whole_status_writer_contract"],
    ),
    (
        "status writer: ask for the delivery credential",
        [("token.rs", "            TokenClass::IssueStatus => Ok(PermissionSet::issue_status()),", "            TokenClass::IssueStatus => Ok(PermissionSet::delivery_stage()),")],
        ["negative_nt_stat_02", "passes_the_whole_status_writer_contract"],
    ),
    (
        "status writer: take a marker from any author for the status comment",
        [("status.rs", '            .filter(|comment| comment["user"]["login"].as_str() == Some(bot))', "            .filter(|_| bot.len() < 1000)")],
        ["passes_the_whole_status_writer_contract"],
    ),
    (
        "status writer: overwrite a comment that shows a newer stamp",
        [("status.rs", "            Some(shown) if shown > stamp => CommentWrite::Superseded(reference(canonical.id)),", "            Some(shown) if shown > stamp && bot.is_empty() => {\n                CommentWrite::Superseded(reference(canonical.id))\n            }")],
        ["negative_nt_stat_03", "passes_the_whole_status_writer_contract"],
    ),
    (
        "status writer: post without looking for the comment first, and keep the duplicate",
        [
            ("status.rs", "        let (mut own, truncated) = self.own_comments(&git, issue.number, &bot).await?;", "        let (mut own, truncated) = (Vec::new(), false);"),
            ("status.rs", "                Some(first) if first.id != id => {", "                Some(first) if first.id == 0 && first.id != id => {"),
        ],
        ["negative_nt_stat_03", "passes_the_whole_status_writer_contract"],
    ),
    (
        "status writer: a label that is already gone is an error",
        [("status.rs", "                Err(GitHostError::NotFound) => {}\n                Err(other) => return Err(other),\n            }\n        }\n        Ok(LabelOutcome {", "                Err(other) => return Err(other),\n            }\n        }\n        Ok(LabelOutcome {")],
        ["negative_nt_stat_01"],
    ),
    (
        "status writer: no pause between requests that change something",
        [("status.rs", "                self.sleeper.sleep(MUTATION_PAUSE - waited).await;", "                let _ = waited;")],
        ["negative_nt_stat_04"],
    ),
    (
        "status writer: send the comment text without cleaning it",
        [("status.rs", "        let cleaned = self.outbound.prepare(TextKind::Markdown, comment.body())?;", "        let cleaned = comment.body().to_owned();")],
        ["negative_nt_stat_06", "passes_the_whole_status_writer_contract"],
    ),
    (
        "status writer: read a comment listing that was cut short as no comment",
        [("status.rs", "            if truncated {", "            if false && truncated {")],
        ["negative_nt_stat_03"],
    ),
    (
        "follow a next link to any host",
        [("client.rs", "            match self.base.target_of(&link) {", "            match Some(link.clone()) {")],
        ["a_link_to_another_host_is_never_followed"],
    ),
]


def run(filters):
    command = ["cargo", "nextest", "run", "-p", "factory-github", "--no-fail-fast", *filters]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    outcomes = []
    for name, edits, filters in BREAKS:
        originals = {}
        try:
            for file, old, new in edits:
                path = SRC / file
                originals.setdefault(path, path.read_text())
                text = path.read_text()
                if text.count(old) != 1:
                    raise SystemExit(f"{name}: the text to change occurs {text.count(old)} times in {file}")
                path.write_text(text.replace(old, new))
            code, output = run(filters)
        finally:
            for path, text in originals.items():
                path.write_text(text)
        if code == 0:
            verdict = "MISSED"
        elif "could not compile" in output or "error[E" in output:
            verdict = "INVALID (does not compile)"
        else:
            failed = sorted({line.split()[-1] for line in output.splitlines() if line.strip().startswith("FAIL")})
            verdict = "CAUGHT by " + ", ".join(failed[:3]) + (" ..." if len(failed) > 3 else "")
        outcomes.append((name, verdict))
        print(f"{name}: {verdict}", flush=True)
    bad = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(bad)} of {len(outcomes)} breaks caught")
    sys.exit(1 if bad else 0)


main()
