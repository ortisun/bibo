//! The commands: read the arguments, call the API or run the checks, print plain English, and end
//! with one of the exit codes of [`Exit`].

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use factory_composition::commands::parse_cli;
use factory_composition::profile::Profile;
use factory_composition::system::RandomIds;
use factory_ports::clock::IdGenerator;
use serde_json::{Value, json};

use crate::client::{Answer, ApiClient, Base, Unreachable, read_token};
use crate::exit::Exit;
use crate::{probe, render};

const USAGE: &str = "\
usage: factory-cli <command> [options]

  health   --api URL
  submit   --api URL --token-file FILE --repository ID --text-file FILE [--key K] [--source-ref R]
  status   --api URL --token-file FILE JOB
  timeline --api URL --token-file FILE JOB
  approve  --api URL --token-file FILE [--key K] JOB STAGE_RUN head=H evidence=sha256:D [reason...]
  reject   --api URL --token-file FILE [--key K] JOB STAGE_RUN reason...
  rework   --api URL --token-file FILE [--key K] JOB STAGE_RUN target=STAGE reason...
  pause | resume | cancel  --api URL --token-file FILE [--key K] JOB reason...
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
        let _ = self.out.write_all(text.as_bytes());
    }

    fn complain(&mut self, text: &str) {
        let _ = writeln!(self.err, "factory-cli: {text}");
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
    let (Some(repository), Some(text_file)) = (
        parsed.options.get("repository"),
        parsed.options.get("text-file"),
    ) else {
        ctx.complain("submit needs --repository and --text-file");
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
    let mut body = json!({"repository_id": repository, "text": text});
    if let Some(source) = parsed.options.get("source-ref") {
        body["source_ref"] = json!(source);
    }
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
            let _ = writeln!(ctx.err, "{line}");
        }
    }
    result.exit
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
        "status" => read_job(rest, env, &mut ctx, "", render::job),
        "timeline" => read_job(rest, env, &mut ctx, "/timeline", render::timeline),
        verb @ ("approve" | "reject" | "rework" | "pause" | "resume" | "cancel") => {
            decide(verb, rest, env, &mut ctx)
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
