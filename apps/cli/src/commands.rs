//! The commands: read the arguments, call the API or run the checks, print plain English, and end
//! with one of the exit codes of [`Exit`].

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use factory_composition::commands::{
    APPROVE_BUILD_CODE, APPROVE_DEPENDENCY, ParsedLine, parse_cli, parse_dependency_command,
};
use factory_composition::profile::Profile;
use factory_composition::stage_decisions::{StageFields, StageVerb};
use factory_composition::system::RandomIds;
use factory_ports::clock::IdGenerator;
use serde_json::{Value, json};

use crate::client::{Answer, ApiClient, Base, Unreachable, read_token};
use crate::exit::Exit;
use crate::{probe, render};

const USAGE: &str = "\
usage: factory-cli <command> [options]

  health   --api URL
  submit   --api URL --token-file FILE --repository ID --text-file FILE --source-ref OWNER/NAME#N [--key K]
  status   --api URL --token-file FILE [--gates] JOB
  show-draft  --api URL --token-file FILE [--stage-run ID] JOB
  artifact --api URL --token-file FILE JOB SHA256
  timeline --api URL --token-file FILE JOB
  approve  --api URL --token-file FILE [--key K] JOB STAGE_RUN head=H evidence=sha256:D [reason...]
  reject   --api URL --token-file FILE [--key K] JOB STAGE_RUN reason...
  rework   --api URL --token-file FILE [--key K] JOB STAGE_RUN target=STAGE reason...
  pause | resume | cancel  --api URL --token-file FILE [--key K] JOB reason...
  unblock  --api URL --token-file FILE [--key K] JOB STAGE_RUN reason...
  ack-translation-warning  --api URL --token-file FILE [--key K] JOB STAGE_RUN WARNING reason...
  approve-project-build-code  --api URL --token-file FILE [--key K] [--stage-run ID] JOB PATH SHA256 reason...
  approve-dependency  --api URL --token-file FILE [--key K] [--stage-run ID] JOB NAME VERSION [CHECKSUM] reason...
  approve-build-code  --api URL --token-file FILE [--key K] [--stage-run ID] JOB NAME VERSION [CHECKSUM] reason...
  repository register     --api URL --token-file FILE [--key K] [--wait-seconds N] --installation ID --github-repository ID --name OWNER/NAME [--default-branch BRANCH] [--single-maintainer]
  repository confirm-map  --api URL --token-file FILE [--key K] [--wait-seconds N] REPOSITORY COMMIT reason...
  repository enable       --api URL --token-file FILE [--key K] [--wait-seconds N] REPOSITORY COMMIT [reason...]
  repository disable      --api URL --token-file FILE [--key K] REPOSITORY [reason...]
  repository show         --api URL --token-file FILE REPOSITORY
  repository change       --api URL --token-file FILE REQUEST
  probe    --protected-checkout DIR [--images-catalog FILE] [--profile production|local|test]

The address may also be set in FACTORY_API_URL. The token is read from a file, never from an argument
or the environment. Exit codes: 0 done, 1 not understood, 2 refused, 3 blocked, 4 unreachable.
";

/// The request text is read from a file; this is the most the command reads.
const MAX_TEXT_FILE_BYTES: u64 = 200 * 1024;

struct Parsed {
    options: BTreeMap<String, String>,
    positional: Vec<String>,
}

/// Splits `--name value`, `--name=value` and positional words. Everything after `--` is positional.
fn split(args: &[String], allowed: &[&str]) -> Result<Parsed, String> {
    split_with_switches(args, allowed, &[])
}

/// The same, with some options that are switches: `--name` alone says `true`, and `--name=false`
/// says `false`. A switch never takes the next word.
fn split_with_switches(
    args: &[String],
    allowed: &[&str],
    switches: &[&str],
) -> Result<Parsed, String> {
    let mut options = BTreeMap::new();
    let mut positional = Vec::new();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if word == "--" {
            positional.extend(words.by_ref().cloned());
            break;
        }
        let Some(name) = word.strip_prefix("--") else {
            positional.push(word.clone());
            continue;
        };
        let (name, value) = match name.split_once('=') {
            Some((name, value)) => (name.to_owned(), value.to_owned()),
            None if switches.contains(&name) => (name.to_owned(), "true".to_owned()),
            None => {
                let value = words
                    .next()
                    .ok_or_else(|| format!("--{name} needs a value"))?;
                (name.to_owned(), value.clone())
            }
        };
        if !allowed.contains(&name.as_str()) {
            return Err(format!("--{name} is not an option of this command"));
        }
        if options.insert(name.clone(), value).is_some() {
            return Err(format!("--{name} was given twice"));
        }
    }
    Ok(Parsed {
        options,
        positional,
    })
}

fn is_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn idempotency_key(options: &BTreeMap<String, String>) -> String {
    options.get("key").cloned().unwrap_or_else(|| {
        RandomIds::new().map_or_else(
            |_| "no-random-source".to_owned(),
            |ids| ids.new_uuid().hyphenated().to_string(),
        )
    })
}

struct Context<'a> {
    out: &'a mut dyn Write,
    err: &'a mut dyn Write,
}

impl Context<'_> {
    fn say(&mut self, text: &str) {
        // Whatever reaches the terminal passes here last (API-10).
        let _ = self.out.write_all(render::printable_block(text).as_bytes());
    }

    fn complain(&mut self, text: &str) {
        let _ = writeln!(self.err, "factory-cli: {}", render::printable_block(text));
    }
}

fn client(
    options: &BTreeMap<String, String>,
    env: &dyn Fn(&str) -> Option<String>,
    with_token: bool,
    ctx: &mut Context<'_>,
) -> Result<ApiClient, Exit> {
    let Some(address) = options
        .get("api")
        .cloned()
        .or_else(|| env("FACTORY_API_URL"))
    else {
        ctx.complain("the API address is missing; pass --api or set FACTORY_API_URL");
        return Err(Exit::Failed);
    };
    let base = Base::parse(&address).map_err(|error| {
        ctx.complain(&error.to_string());
        Exit::Failed
    })?;
    let token = if with_token {
        let Some(file) = options.get("token-file") else {
            ctx.complain("the token file is missing; pass --token-file (the token is never read from an argument)");
            return Err(Exit::Failed);
        };
        Some(read_token(Path::new(file)).map_err(|error| {
            ctx.complain(&error.to_string());
            Exit::Failed
        })?)
    } else {
        None
    };
    Ok(ApiClient::new(base, token))
}

/// Prints the outcome of a call and returns its exit.
fn finish(
    result: Result<Answer, Unreachable>,
    ctx: &mut Context<'_>,
    on_success: impl FnOnce(&Value) -> String,
) -> Exit {
    match result {
        Err(unreachable) => {
            ctx.complain(&format!("{unreachable}."));
            Exit::Unreachable
        }
        Ok(answer) => {
            let exit = Exit::of_status(answer.status);
            if exit == Exit::Ok {
                ctx.say(&on_success(&answer.body));
            } else {
                ctx.complain(&render::refusal(answer.status, &answer.body));
            }
            exit
        }
    }
}

fn health(args: &[String], env: &dyn Fn(&str) -> Option<String>, ctx: &mut Context<'_>) -> Exit {
    let parsed = match split(args, &["api"]) {
        Ok(parsed) if parsed.positional.is_empty() => parsed,
        Ok(_) => {
            ctx.complain("health takes no argument but --api");
            return Exit::Failed;
        }
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let client = match client(&parsed.options, env, false, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    match client.get("/healthz") {
        Err(unreachable) => {
            ctx.complain(&format!("{unreachable}."));
            return Exit::Unreachable;
        }
        Ok(answer) if answer.status != 200 => {
            ctx.complain(&render::refusal(answer.status, &answer.body));
            return Exit::of_status(answer.status);
        }
        Ok(_) => ctx.say("The API is running.\n"),
    }
    match client.get("/readyz") {
        Err(unreachable) => {
            ctx.complain(&format!("{unreachable}."));
            Exit::Unreachable
        }
        Ok(answer) => {
            ctx.say(&render::readiness(&answer.body));
            if answer.status == 200 {
                Exit::Ok
            } else {
                Exit::Blocked
            }
        }
    }
}

fn submit(args: &[String], env: &dyn Fn(&str) -> Option<String>, ctx: &mut Context<'_>) -> Exit {
    let allowed = [
        "api",
        "token-file",
        "repository",
        "text-file",
        "key",
        "source-ref",
    ];
    let parsed = match split(args, &allowed) {
        Ok(parsed) if parsed.positional.is_empty() => parsed,
        Ok(_) => {
            ctx.complain("submit takes options only; the text is read from --text-file");
            return Exit::Failed;
        }
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let (Some(repository), Some(text_file), Some(source)) = (
        parsed.options.get("repository"),
        parsed.options.get("text-file"),
        parsed.options.get("source-ref"),
    ) else {
        ctx.complain(
            "submit needs --repository, --text-file and --source-ref (the issue, as owner/name#number): a job is for one issue",
        );
        return Exit::Failed;
    };
    if !is_uuid(repository) {
        ctx.complain("--repository must be the id of a registered repository (a UUID)");
        return Exit::Failed;
    }
    let text = match std::fs::metadata(text_file).and_then(|meta| {
        if meta.len() > MAX_TEXT_FILE_BYTES {
            Err(std::io::Error::other("too large"))
        } else {
            std::fs::read_to_string(text_file)
        }
    }) {
        Ok(text) => text,
        Err(_) => {
            ctx.complain(&format!(
                "{text_file} cannot be read as text of at most {MAX_TEXT_FILE_BYTES} bytes"
            ));
            return Exit::Failed;
        }
    };
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let key = idempotency_key(&parsed.options);
    let body = json!({"repository_id": repository, "text": text, "source_ref": source});
    let shown = key.clone();
    finish(client.post("/v1/jobs", &key, &body), ctx, move |body| {
        render::submitted(body, &shown)
    })
}

fn read_job(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
    suffix: &str,
    show: fn(&Value) -> String,
) -> Exit {
    let parsed = match split(args, &["api", "token-file"]) {
        Ok(parsed) if parsed.positional.len() == 1 && is_uuid(&parsed.positional[0]) => parsed,
        Ok(_) => {
            ctx.complain("this command takes one job id (a UUID)");
            return Exit::Failed;
        }
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let path = format!("/v1/jobs/{}{suffix}", parsed.positional[0]);
    finish(client.get(&path), ctx, show)
}

/// `status`, and with `--gates` the gate reports of the job after it.
fn status(args: &[String], env: &dyn Fn(&str) -> Option<String>, ctx: &mut Context<'_>) -> Exit {
    let with_gates = args.iter().any(|word| word == "--gates");
    let rest: Vec<String> = args
        .iter()
        .filter(|word| *word != "--gates")
        .cloned()
        .collect();
    let exit = read_job(&rest, env, ctx, "", render::job);
    if !with_gates || exit != Exit::Ok {
        return exit;
    }
    read_job(&rest, env, ctx, "/gate-reports", render::gate_reports)
}

/// `show-draft`: the specification draft a person is asked to approve.
fn show_draft(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
) -> Exit {
    let parsed = match split(args, &["api", "token-file", "stage-run"]) {
        Ok(parsed) if parsed.positional.len() == 1 && is_uuid(&parsed.positional[0]) => parsed,
        Ok(_) => {
            ctx.complain("show-draft takes one job id (a UUID)");
            return Exit::Failed;
        }
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let mut path = format!("/v1/jobs/{}/specification-draft", parsed.positional[0]);
    if let Some(stage_run) = parsed.options.get("stage-run") {
        if !is_uuid(stage_run) {
            ctx.complain("--stage-run is a stage run id (a UUID)");
            return Exit::Failed;
        }
        path.push_str(&format!("?stage_run_id={stage_run}"));
    }
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    finish(client.get(&path), ctx, render::draft)
}

/// `artifact`: prints one stored document of a job. The text is untrusted, so it passes the same
/// sanitizer as everything the command prints; a document that is not text is not printed.
fn artifact(args: &[String], env: &dyn Fn(&str) -> Option<String>, ctx: &mut Context<'_>) -> Exit {
    let parsed = match split(args, &["api", "token-file"]) {
        Ok(parsed) if parsed.positional.len() == 2 && is_uuid(&parsed.positional[0]) => parsed,
        Ok(_) => {
            ctx.complain("artifact takes a job id (a UUID) and the SHA-256 of the document");
            return Exit::Failed;
        }
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let hash = parsed.positional[1]
        .strip_prefix("sha256:")
        .unwrap_or(&parsed.positional[1]);
    if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        ctx.complain("the hash is 64 lower case hexadecimal digits");
        return Exit::Failed;
    }
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let path = format!("/v1/jobs/{}/artifacts/{hash}", parsed.positional[0]);
    match client.get_document(&path) {
        Err(unreachable) => {
            ctx.complain(&format!("{unreachable}."));
            Exit::Unreachable
        }
        Ok(document) if document.status == 200 => {
            if document.content_type.starts_with("text/plain") {
                ctx.say(&String::from_utf8_lossy(&document.bytes));
                Exit::Ok
            } else {
                ctx.complain(&format!(
                    "the document is {} bytes of data that is not text; it is not printed",
                    document.bytes.len()
                ));
                Exit::Failed
            }
        }
        Ok(document) => {
            let body = serde_json::from_slice(&document.bytes).unwrap_or(Value::Null);
            ctx.complain(&render::refusal(document.status, &body));
            Exit::of_status(document.status)
        }
    }
}

fn decide(
    verb: &str,
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
) -> Exit {
    let parsed = match split(args, &["api", "token-file", "key"]) {
        Ok(parsed) => parsed,
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let needs_stage_run = matches!(verb, "approve" | "reject" | "rework");
    let words = &parsed.positional;
    let wanted = if needs_stage_run { 2 } else { 1 };
    if words.len() < wanted || !is_uuid(&words[0]) || (needs_stage_run && !is_uuid(&words[1])) {
        ctx.complain(if needs_stage_run {
            "this decision takes a job id and a stage run id (both UUIDs), then the words of the decision"
        } else {
            "this decision takes a job id (a UUID), then the reason"
        });
        return Exit::Failed;
    }
    // The words after the ids are the grammar every channel shares.
    let mut grammar: Vec<&str> = vec![verb];
    grammar.extend(words[wanted..].iter().map(String::as_str));
    let decision = match parse_cli(&grammar) {
        Ok(decision) => decision,
        Err(error) => {
            ctx.complain(&format!("the decision is not valid: {error}"));
            return Exit::Failed;
        }
    };
    // What the API would refuse for a missing word is refused here first, before a request is made.
    let missing = match decision.verb.as_str() {
        "approve" if decision.head.is_none() => Some("approve needs head=<commit>"),
        "approve" if decision.evidence.is_none() => Some("approve needs evidence=<digest>"),
        "rework" if decision.target.is_none() => Some("rework needs target=<STAGE>"),
        _ => None,
    };
    if let Some(why) = missing {
        ctx.complain(why);
        return Exit::Failed;
    }
    let mut body = json!({"verb": decision.verb.as_str(), "reason": decision.reason});
    if needs_stage_run {
        body["stage_run_id"] = json!(words[1]);
    }
    if let Some(head) = &decision.head {
        body["head"] = json!(head.as_str());
    }
    if let Some(evidence) = &decision.evidence {
        body["evidence"] = json!(evidence.as_str());
    }
    if let Some(target) = decision.target {
        body["target"] = json!(target.as_str());
    }
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let key = idempotency_key(&parsed.options);
    let shown = key.clone();
    let path = format!("/v1/jobs/{}/decisions", words[0]);
    finish(client.post(&path, &key, &body), ctx, move |body| {
        render::decided(body, &shown)
    })
}

/// The shortest reason a decision about a stage run carries, in characters (the API's own bound).
const MIN_REASON_CHARS: usize = 10;

/// `unblock`: the operator lets a blocked stage run go again. It sends the stage run and the
/// reason and no fact: the engine reads for itself whether the block is gone.
fn unblock(args: &[String], env: &dyn Fn(&str) -> Option<String>, ctx: &mut Context<'_>) -> Exit {
    let parsed = match split(args, &["api", "token-file", "key"]) {
        Ok(parsed) => parsed,
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let words = &parsed.positional;
    if words.len() < 3 || !is_uuid(&words[0]) || !is_uuid(&words[1]) {
        ctx.complain(
            "unblock takes a job id and a stage run id (both UUIDs), then the reason it can go again",
        );
        return Exit::Failed;
    }
    let reason = words[2..].join(" ");
    // What the API would refuse for a missing reason is refused here first, before a request.
    if reason.chars().count() < MIN_REASON_CHARS {
        ctx.complain("unblock needs a reason of at least 10 characters");
        return Exit::Failed;
    }
    let body = json!({"verb": "unblock", "stage_run_id": words[1], "reason": reason});
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let key = idempotency_key(&parsed.options);
    let shown = key.clone();
    let path = format!("/v1/jobs/{}/decisions", words[0]);
    finish(client.post(&path, &key, &body), ctx, move |body| {
        render::decided(body, &shown)
    })
}

/// `ack-translation-warning`: an approver decides about one open translation warning of the
/// approval request, so that their approval of the pull request can count it. The warning is the
/// number the gate reports list, from 1.
fn ack_translation_warning(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
) -> Exit {
    let parsed = match split(args, &["api", "token-file", "key"]) {
        Ok(parsed) => parsed,
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let words = &parsed.positional;
    let number = words
        .get(2)
        .and_then(|word| word.parse::<u32>().ok())
        .filter(|number| (1..=factory_composition::stage_decisions::MAX_WARNING).contains(number));
    let (Some(number), true) = (
        number,
        words.len() >= 4 && is_uuid(&words[0]) && is_uuid(&words[1]),
    ) else {
        ctx.complain(
            "this decision takes a job id and the approval stage run id (both UUIDs), the number of the warning from 1, and then the reason",
        );
        return Exit::Failed;
    };
    let reason = words[3..].join(" ");
    if reason.chars().count() < MIN_REASON_CHARS {
        ctx.complain("a decision about a warning needs a reason of at least 10 characters");
        return Exit::Failed;
    }
    let body = json!({
        "verb": StageVerb::AckTranslationWarning.as_str(),
        "stage_run_id": words[1],
        "warning": number,
        "reason": reason,
    });
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let key = idempotency_key(&parsed.options);
    let shown = key.clone();
    let url = format!("/v1/jobs/{}/decisions", words[0]);
    finish(client.post(&url, &key, &body), ctx, move |body| {
        render::decided(body, &shown)
    })
}

/// `approve-project-build-code`: a security approver accepts one file of the project's own new
/// build code, with the content they read. The file is a path of the repository and the content is
/// named by the start of its SHA-256 (12 to 64 lower case hex digits, with or without `sha256:`),
/// as the evidence of the blocked stage run shows them (`status --gates` is not needed: the
/// evidence of the stage run lists both).
fn approve_project_build_code(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
) -> Exit {
    let parsed = match split(args, &["api", "token-file", "key", "stage-run"]) {
        Ok(parsed) => parsed,
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let words = &parsed.positional;
    if words.len() < 4 || !is_uuid(&words[0]) {
        ctx.complain(
            "this decision takes a job id (a UUID), the path of the file, the start of the SHA-256 of its content, and then the reason",
        );
        return Exit::Failed;
    }
    let stage_run = parsed.options.get("stage-run");
    if stage_run.is_some_and(|stage_run| !is_uuid(stage_run)) {
        ctx.complain("--stage-run is a stage run id (a UUID)");
        return Exit::Failed;
    }
    let path = words[1].clone();
    let digest = words[2]
        .strip_prefix("sha256:")
        .unwrap_or(&words[2])
        .to_owned();
    // The words are checked with the grammar the API and the worker use, before a request.
    let Ok(job) = factory_domain::ids::JobId::parse(&words[0]) else {
        ctx.complain("the job id is not one");
        return Exit::Failed;
    };
    let probe = StageFields {
        verb: StageVerb::ApproveProjectBuildCode,
        job,
        stage_run: None,
        path: Some(path.clone()),
        digest: Some(digest.clone()),
        index: None,
    };
    if !probe.is_well_formed() {
        ctx.complain("the path is a path inside the repository, and the hash is 12 to 64 lower case hexadecimal digits");
        return Exit::Failed;
    }
    let reason = words[3..].join(" ");
    if reason.chars().count() < MIN_REASON_CHARS {
        ctx.complain("a decision on build code needs a reason of at least 10 characters");
        return Exit::Failed;
    }
    let mut body = json!({
        "verb": StageVerb::ApproveProjectBuildCode.as_str(),
        "path": path,
        "digest": digest,
        "reason": reason,
    });
    if let Some(stage_run) = stage_run {
        body["stage_run_id"] = json!(stage_run);
    }
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let key = idempotency_key(&parsed.options);
    let shown = key.clone();
    let url = format!("/v1/jobs/{}/decisions", words[0]);
    finish(client.post(&url, &key, &body), ctx, move |body| {
        render::decided(body, &shown)
    })
}

/// `approve-dependency` and `approve-build-code`: a decision on a new dependency or on its build
/// code. The words after the job id are read by the one reader of those commands, so the package
/// name, the version and the checksum prefix are the ones every channel accepts.
fn decide_dependency(
    verb: &str,
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
) -> Exit {
    let parsed = match split(args, &["api", "token-file", "key", "stage-run"]) {
        Ok(parsed) => parsed,
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let words = &parsed.positional;
    if words.len() < 3 || !is_uuid(&words[0]) {
        ctx.complain(
            "this decision takes a job id (a UUID), the package name, the version, and then the reason",
        );
        return Exit::Failed;
    }
    if let Some(stage_run) = parsed.options.get("stage-run")
        && !is_uuid(stage_run)
    {
        ctx.complain("--stage-run is a stage run id (a UUID)");
        return Exit::Failed;
    }
    let line = format!("{verb} {}", words[1..].join(" "));
    let command = match parse_dependency_command(&line) {
        Ok(ParsedLine::Command(command)) => command,
        Ok(ParsedLine::NotOurs) => {
            ctx.complain("the decision is not valid");
            return Exit::Failed;
        }
        Err(error) => {
            ctx.complain(&format!("the decision is not valid: {error}"));
            return Exit::Failed;
        }
    };
    // What the API would refuse for a missing reason is refused here first, before a request.
    if command.reason.chars().count() < 10 {
        ctx.complain("a decision on a dependency needs a reason of at least 10 characters");
        return Exit::Failed;
    }
    let mut body = json!({
        "verb": verb,
        "package": command.name,
        "version": command.version,
        "reason": command.reason,
    });
    if let Some(prefix) = &command.checksum_prefix {
        body["checksum"] = json!(prefix);
    }
    if let Some(stage_run) = parsed.options.get("stage-run") {
        body["stage_run_id"] = json!(stage_run);
    }
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let key = idempotency_key(&parsed.options);
    let shown = key.clone();
    let path = format!("/v1/jobs/{}/decisions", words[0]);
    finish(client.post(&path, &key, &body), ctx, move |body| {
        render::decided(body, &shown)
    })
}

fn probe_command(args: &[String], ctx: &mut Context<'_>) -> Exit {
    let parsed = match split(args, &["protected-checkout", "images-catalog", "profile"]) {
        Ok(parsed) if parsed.positional.is_empty() => parsed,
        Ok(_) => {
            ctx.complain("probe takes options only");
            return Exit::Failed;
        }
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let Some(checkout) = parsed.options.get("protected-checkout") else {
        ctx.complain("probe needs --protected-checkout");
        return Exit::Failed;
    };
    let profile = match parsed.options.get("profile").map(String::as_str) {
        None | Some("local") => Profile::Local,
        Some("production") => Profile::Production,
        Some("test") => Profile::Test,
        Some(_) => {
            ctx.complain("--profile is production, local or test");
            return Exit::Failed;
        }
    };
    let result = probe::run(
        profile,
        Path::new(checkout),
        parsed.options.get("images-catalog").map(Path::new),
    );
    for line in &result.lines {
        // FAILED and BLOCKED lines go to standard error, where an operator looks for what went wrong.
        if line.starts_with("OK:") {
            ctx.say(&format!("{line}\n"));
        } else {
            let _ = writeln!(ctx.err, "{}", render::printable_block(line));
        }
    }
    result.exit
}

/// How long a command that asks for a change waits for the worker to apply it, unless told otherwise.
const DEFAULT_WAIT_SECONDS: u64 = 60;
/// The most a person may ask the command to wait. A longer wait is a reason to look at the worker.
const MAX_WAIT_SECONDS: u64 = 600;
/// The pause between two looks at the state of a request.
const POLL: Duration = Duration::from_secs(1);

/// The wait the person asked for, in seconds, or `None` for a word that is not a whole number within
/// the bound.
fn wait_of(options: &BTreeMap<String, String>) -> Option<Duration> {
    let seconds = options
        .get("wait-seconds")
        .map_or(Some(DEFAULT_WAIT_SECONDS), |text| {
            text.parse::<u64>().ok().filter(|n| *n <= MAX_WAIT_SECONDS)
        })?;
    Some(Duration::from_secs(seconds))
}

/// After the API answered `202` to a request to register, confirm or enable: waits, within a bound, for
/// the worker to apply it, then says how it ended (finding REG-2). The API changes nothing itself for
/// these three acts, so the answer to the command is the state of the request and then the repository.
///
/// * applied: the repository is read and printed, exit 0;
/// * refused: the plain sentence for the code, exit 2;
/// * not settled within the bound: the request is recorded, the id is printed and the way to look again,
///   exit 3 (blocked: try later). Nothing was lost; the request is still there.
fn wait_for_request(
    client: &ApiClient,
    accepted: &Answer,
    wait: Duration,
    done: &str,
    key: &str,
    ctx: &mut Context<'_>,
) -> Exit {
    let text = |name: &str| {
        accepted
            .body
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let (Some(request), Some(repository)) = (text("request_id"), text("repository_id")) else {
        ctx.complain("the API answered 202 without the identifiers of the request");
        return Exit::Failed;
    };
    let started = Instant::now();
    loop {
        let state = match client.get(&format!("/v1/repository-changes/{request}")) {
            Err(unreachable) => {
                ctx.complain(&format!("{unreachable}."));
                return Exit::Unreachable;
            }
            Ok(answer) if answer.status != 200 => {
                ctx.complain(&render::refusal(answer.status, &answer.body));
                return Exit::of_status(answer.status);
            }
            Ok(answer) => answer.body,
        };
        match state.get("state").and_then(Value::as_str) {
            Some("applied") => {
                return match client.get(&format!("/v1/repositories/{repository}")) {
                    Err(unreachable) => {
                        ctx.complain(&format!("{unreachable}."));
                        Exit::Unreachable
                    }
                    Ok(answer) if answer.status != 200 => {
                        ctx.complain(&render::refusal(answer.status, &answer.body));
                        Exit::of_status(answer.status)
                    }
                    Ok(answer) => {
                        ctx.say(&render::repository_changed(
                            &json!({"repository": answer.body, "changed": true}),
                            key,
                            done,
                        ));
                        Exit::Ok
                    }
                };
            }
            Some("refused") => {
                let code = state
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("refused");
                ctx.complain(&render::change_refused(code));
                return Exit::Refused;
            }
            _ => {}
        }
        if started.elapsed() >= wait {
            ctx.say(&render::change_pending(
                &request,
                &repository,
                wait.as_secs(),
            ));
            return Exit::Blocked;
        }
        std::thread::sleep(POLL.min(wait.saturating_sub(started.elapsed())));
    }
}

/// `repository change REQUEST`: where a request to register, confirm or enable stands.
fn repository_change_state(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
) -> Exit {
    let parsed = match split(args, &["api", "token-file"]) {
        Ok(parsed) if parsed.positional.len() == 1 && is_uuid(&parsed.positional[0]) => parsed,
        Ok(_) => {
            ctx.complain("repository change takes one request id (a UUID), as a change printed it");
            return Exit::Failed;
        }
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let path = format!("/v1/repository-changes/{}", parsed.positional[0]);
    finish(client.get(&path), ctx, render::change_state)
}

/// `repository`: register a repository, confirm its project map, enable it, disable it, or show it.
///
/// Registering, confirming and enabling are requests that the worker applies (finding REG-2): the
/// command sends the request, waits for the worker within a bound and says how it ended. Disabling
/// is direct.
///
/// Confirming the map is a person's statement. The command says so in what it prints, and it sends
/// the commit and the reason and nothing else: the engine holds no GitHub credential and does not
/// read the repository.
fn repository(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
) -> Exit {
    let Some((subcommand, rest)) = args.split_first() else {
        ctx.complain("repository needs one of register, confirm-map, enable, disable or show");
        return Exit::Failed;
    };
    match subcommand.as_str() {
        "register" => repository_register(rest, env, ctx),
        "confirm-map" => repository_change(rest, env, ctx, RepositoryChange::ConfirmMap),
        "enable" => repository_change(rest, env, ctx, RepositoryChange::Enable),
        "disable" => repository_change(rest, env, ctx, RepositoryChange::Disable),
        "show" => repository_show(rest, env, ctx),
        "change" => repository_change_state(rest, env, ctx),
        other => {
            ctx.complain(&format!(
                "{other:?} is not a repository command; use register, confirm-map, enable, disable or show"
            ));
            Exit::Failed
        }
    }
}

fn repository_register(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
) -> Exit {
    let allowed = [
        "api",
        "token-file",
        "key",
        "installation",
        "github-repository",
        "name",
        "default-branch",
        "single-maintainer",
        "wait-seconds",
    ];
    let parsed = match split_with_switches(args, &allowed, &["single-maintainer"]) {
        Ok(parsed) if parsed.positional.is_empty() => parsed,
        Ok(_) => {
            ctx.complain("repository register takes options only");
            return Exit::Failed;
        }
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let number = |option: &str| {
        parsed
            .options
            .get(option)
            .and_then(|text| text.parse::<u64>().ok())
            .filter(|number| *number > 0)
    };
    let (Some(installation), Some(github_repository), Some(name)) = (
        number("installation"),
        number("github-repository"),
        parsed.options.get("name"),
    ) else {
        ctx.complain(
            "repository register needs --installation (the GitHub App installation id), --github-repository (GitHub's numeric id of the repository) and --name (OWNER/NAME); the two ids are positive whole numbers",
        );
        return Exit::Failed;
    };
    let branch = parsed
        .options
        .get("default-branch")
        .map_or("main", String::as_str);
    // The rule about the enabler (finding REG-6). Strict unless the operator says otherwise, and
    // said here, at registration, because nothing changes it afterwards.
    let single_maintainer = match parsed.options.get("single-maintainer").map(String::as_str) {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => {
            ctx.complain("--single-maintainer is a switch: give it alone, or as =true or =false");
            return Exit::Failed;
        }
    };
    let body = json!({
        "installation_id": installation,
        "github_repository_id": github_repository,
        "full_name": name,
        "default_branch": branch,
        "single_maintainer": single_maintainer,
    });
    let Some(wait) = wait_of(&parsed.options) else {
        ctx.complain("--wait-seconds is a whole number of seconds, at most 600; 0 does not wait");
        return Exit::Failed;
    };
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let key = idempotency_key(&parsed.options);
    request_and_wait(
        &client,
        "/v1/repositories",
        &key,
        &body,
        wait,
        "registered",
        ctx,
    )
}

/// Sends a request that the worker applies, and waits for it.
fn request_and_wait(
    client: &ApiClient,
    path: &str,
    key: &str,
    body: &Value,
    wait: Duration,
    done: &str,
    ctx: &mut Context<'_>,
) -> Exit {
    match client.post(path, key, body) {
        Err(unreachable) => {
            ctx.complain(&format!("{unreachable}."));
            Exit::Unreachable
        }
        Ok(answer) if answer.status != 202 => {
            if Exit::of_status(answer.status) == Exit::Ok {
                // A success that is not the answer this command waits for: say so and do not guess.
                ctx.complain(&format!(
                    "the API answered {}, not 202; the request may not be a request to the worker",
                    answer.status
                ));
                return Exit::Failed;
            }
            ctx.complain(&render::refusal(answer.status, &answer.body));
            Exit::of_status(answer.status)
        }
        Ok(answer) if wait.is_zero() => {
            ctx.say(&render::change_pending(
                answer
                    .body
                    .get("request_id")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                answer
                    .body
                    .get("repository_id")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                0,
            ));
            Exit::Ok
        }
        Ok(answer) => wait_for_request(client, &answer, wait, done, key, ctx),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RepositoryChange {
    ConfirmMap,
    Enable,
    Disable,
}

fn repository_change(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
    change: RepositoryChange,
) -> Exit {
    let parsed = match split(args, &["api", "token-file", "key", "wait-seconds"]) {
        Ok(parsed) => parsed,
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let Some(wait) = wait_of(&parsed.options) else {
        ctx.complain("--wait-seconds is a whole number of seconds, at most 600; 0 does not wait");
        return Exit::Failed;
    };
    let words = &parsed.positional;
    let (path, body, done) = match change {
        RepositoryChange::ConfirmMap => {
            let (Some(id), Some(commit)) = (words.first(), words.get(1)) else {
                ctx.complain(
                    "repository confirm-map takes the repository id (a UUID), the commit that holds the project map, and then the reason you can say the map is right",
                );
                return Exit::Failed;
            };
            let reason = words[2..].join(" ");
            if !is_uuid(id) || !is_commit(commit) {
                ctx.complain(
                    "the repository must be a UUID and the commit 40 lowercase hexadecimal characters",
                );
                return Exit::Failed;
            }
            // What the API would refuse for a short reason is refused here first, before a request.
            if reason.chars().count() < MIN_REASON_CHARS {
                ctx.complain("repository confirm-map needs a reason of at least 10 characters: say what you read to be able to attest the map");
                return Exit::Failed;
            }
            (
                format!("/v1/repositories/{id}/project-map"),
                json!({"commit": commit, "reason": reason}),
                "attested",
            )
        }
        RepositoryChange::Enable => {
            // The commit the person read. The API refuses it when the map was attested again since,
            // so an approval is bound to the map the approver saw.
            let (Some(id), Some(commit)) = (words.first(), words.get(1)) else {
                ctx.complain(
                    "repository enable takes the repository id (a UUID), the commit of the project map you read, and then an optional reason",
                );
                return Exit::Failed;
            };
            if !is_uuid(id) || !is_commit(commit) {
                ctx.complain(
                    "the repository must be a UUID and the commit 40 lowercase hexadecimal characters",
                );
                return Exit::Failed;
            }
            let reason = words[2..].join(" ");
            let mut body = json!({"commit": commit});
            if !reason.is_empty() {
                if reason.chars().count() < MIN_REASON_CHARS {
                    ctx.complain("a reason, when given, has at least 10 characters");
                    return Exit::Failed;
                }
                body["reason"] = json!(reason);
            }
            (format!("/v1/repositories/{id}/enable"), body, "enabled")
        }
        RepositoryChange::Disable => {
            let Some(id) = words.first().filter(|id| is_uuid(id)) else {
                ctx.complain(
                    "this command takes the repository id (a UUID), then an optional reason",
                );
                return Exit::Failed;
            };
            let reason = words[1..].join(" ");
            let body = if reason.is_empty() {
                json!({})
            } else if reason.chars().count() < MIN_REASON_CHARS {
                ctx.complain("a reason, when given, has at least 10 characters");
                return Exit::Failed;
            } else {
                json!({"reason": reason})
            };
            (format!("/v1/repositories/{id}/disable"), body, "disabled")
        }
    };
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let key = idempotency_key(&parsed.options);
    if change != RepositoryChange::Disable {
        // Confirming a map and enabling are requests that the worker applies.
        return request_and_wait(&client, &path, &key, &body, wait, done, ctx);
    }
    let shown = key.clone();
    finish(client.post(&path, &key, &body), ctx, move |body| {
        render::repository_changed(body, &shown, done)
    })
}

fn repository_show(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    ctx: &mut Context<'_>,
) -> Exit {
    let parsed = match split(args, &["api", "token-file"]) {
        Ok(parsed) if parsed.positional.len() == 1 && is_uuid(&parsed.positional[0]) => parsed,
        Ok(_) => {
            ctx.complain("repository show takes one repository id (a UUID)");
            return Exit::Failed;
        }
        Err(why) => {
            ctx.complain(&why);
            return Exit::Failed;
        }
    };
    let client = match client(&parsed.options, env, true, ctx) {
        Ok(client) => client,
        Err(exit) => return exit,
    };
    let path = format!("/v1/repositories/{}", parsed.positional[0]);
    finish(client.get(&path), ctx, render::repository)
}

/// A commit as the API takes it: 40 lowercase hexadecimal characters.
fn is_commit(text: &str) -> bool {
    text.len() == 40 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Runs one command line. `args` excludes the program name.
pub fn run(
    args: &[String],
    env: &dyn Fn(&str) -> Option<String>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Exit {
    let mut ctx = Context { out, err };
    let Some((command, rest)) = args.split_first() else {
        let _ = ctx.err.write_all(USAGE.as_bytes());
        return Exit::Failed;
    };
    match command.as_str() {
        "health" => health(rest, env, &mut ctx),
        "submit" => submit(rest, env, &mut ctx),
        "status" => status(rest, env, &mut ctx),
        "show-draft" => show_draft(rest, env, &mut ctx),
        "artifact" => artifact(rest, env, &mut ctx),
        "timeline" => read_job(rest, env, &mut ctx, "/timeline", render::timeline),
        verb @ ("approve" | "reject" | "rework" | "pause" | "resume" | "cancel") => {
            decide(verb, rest, env, &mut ctx)
        }
        "repository" => repository(rest, env, &mut ctx),
        "unblock" => unblock(rest, env, &mut ctx),
        "approve-project-build-code" => approve_project_build_code(rest, env, &mut ctx),
        "ack-translation-warning" => ack_translation_warning(rest, env, &mut ctx),
        verb @ (APPROVE_DEPENDENCY | APPROVE_BUILD_CODE) => {
            decide_dependency(verb, rest, env, &mut ctx)
        }
        "probe" => probe_command(rest, &mut ctx),
        "help" | "--help" | "-h" => {
            ctx.say(USAGE);
            Exit::Ok
        }
        other => {
            // A verb the factory does not take (merge, deploy, ready, undraft) lands here too.
            ctx.complain(&format!("{other:?} is not a command of the factory"));
            let _ = ctx.err.write_all(USAGE.as_bytes());
            Exit::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn options_and_words_are_split_and_a_double_dash_ends_the_options() {
        let parsed = split(
            &words("--api http://x --key=k JOB -- --not-an-option"),
            &["api", "key"],
        )
        .expect("splits");
        assert_eq!(parsed.options["api"], "http://x");
        assert_eq!(parsed.options["key"], "k");
        assert_eq!(parsed.positional, ["JOB", "--not-an-option"]);
        assert!(split(&words("--nope 1"), &["api"]).is_err());
        assert!(split(&words("--api"), &["api"]).is_err());
        assert!(split(&words("--api a --api b"), &["api"]).is_err());
    }

    #[test]
    fn an_id_is_a_uuid_or_it_is_not_sent() {
        assert!(is_uuid("0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b"));
        for bad in [
            "",
            "../etc/passwd",
            "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6",
            "0190a3b2_7c4d_4e5f_8a6b_1c2d3e4f5a6b",
            "zzzzzzzz-7c4d-4e5f-8a6b-1c2d3e4f5a6b",
        ] {
            assert!(!is_uuid(bad), "{bad}");
        }
    }

    #[test]
    fn a_word_that_is_not_a_command_is_not_run_and_merge_and_deploy_are_among_them() {
        for word in ["merge", "deploy", "ready", "undraft", "delete"] {
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let exit = run(&[word.to_owned()], &|_| None, &mut out, &mut err);
            assert_eq!(exit, Exit::Failed, "{word}");
        }
    }
}
