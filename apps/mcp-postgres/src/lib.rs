//! The configuration and the checks of `factory-mcp-postgres`, kept apart from `main` so they can
//! be tested without a database or a socket.
//!
//! Secrets come from files only. The program takes no password or token in an argument or an
//! environment variable: an argument is visible to every user of the machine (`ps`), and an
//! environment variable is inherited by children and shows up in crash reports.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use factory_domain::redaction::{Registered, RegistryError};
use serde::Deserialize;

/// The usage text, on `--help` and after a usage error.
pub const USAGE: &str = "factory-mcp-postgres: the read-only PostgreSQL MCP server of the software factory (ADR 0021)

USAGE:
  factory-mcp-postgres [--config FILE] [--http ADDR:PORT --token-file FILE [--allow-non-loopback]]

  Without --http it serves MCP over stdio (what Claude Code starts). With --http it serves Streamable HTTP on
  ADDR:PORT at /mcp and requires `Authorization: Bearer <token>`, the token read from --token-file.

  --config FILE          JSON settings (see the README). Without it, the settings come from the environment:
                         FACTORY_MCP_PG_USER (required, normally factory_troubleshooter), FACTORY_MCP_PG_HOST
                         (127.0.0.1), FACTORY_MCP_PG_PORT (5432), FACTORY_MCP_PG_DATABASE (factory), FACTORY_MCP_PG_PASSWORD_FILE,
                         FACTORY_MCP_PG_POLICY_CHECKOUT, FACTORY_MCP_PG_BUDGET_WINDOW_S (3600: the call budget
                         starts again after this many seconds). FACTORY_MCP_PG_CONFIG may name the file instead.
  --http ADDR:PORT       serve Streamable HTTP instead of stdio. A loopback address only, unless
  --allow-non-loopback   is also given.
  --token-file FILE      the bearer token, one line, at least 32 characters, mode 0600. Required with --http.

  Secret files (the password file and the token file) must not be readable by group or others. A password or
  token too short for the redactor to recognise is refused.";

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Options {
    /// `--config`.
    pub config: Option<PathBuf>,
    /// `--http`.
    pub http: Option<SocketAddr>,
    /// `--token-file`.
    pub token_file: Option<PathBuf>,
    /// `--allow-non-loopback`.
    pub allow_non_loopback: bool,
    /// `--help`.
    pub help: bool,
}

/// Parses the arguments after the program name.
///
/// # Errors
/// A sentence saying what is wrong.
pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    let mut options = Options::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => options.config = Some(PathBuf::from(value(&mut args, "--config")?)),
            "--http" => {
                let text = value(&mut args, "--http")?;
                options.http = Some(text.parse().map_err(|_| {
                    format!("--http needs ADDR:PORT, such as 127.0.0.1:8808, not {text:?}")
                })?);
            }
            "--token-file" => {
                options.token_file = Some(PathBuf::from(value(&mut args, "--token-file")?));
            }
            "--allow-non-loopback" => options.allow_non_loopback = true,
            "--help" | "-h" => options.help = true,
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if options.http.is_some() && options.token_file.is_none() {
        return Err(
            "--http needs --token-file: Streamable HTTP is served only behind a bearer token"
                .to_owned(),
        );
    }
    if options.http.is_none() && (options.token_file.is_some() || options.allow_non_loopback) {
        return Err("--token-file and --allow-non-loopback only make sense with --http".to_owned());
    }
    if let Some(address) = options.http {
        check_bind(address, options.allow_non_loopback)?;
    }
    Ok(options)
}

fn value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("{flag} needs a value"))
}

/// Refuses an address that is not loopback unless the caller said so explicitly.
///
/// # Errors
/// A sentence saying why.
pub fn check_bind(address: SocketAddr, allow_non_loopback: bool) -> Result<(), String> {
    if address.ip().is_loopback() || allow_non_loopback {
        Ok(())
    } else {
        Err(format!(
            "{address} is not a loopback address; the database's read access would be reachable from the network. \
             Add --allow-non-loopback if that is intended"
        ))
    }
}

/// The settings, from the JSON file or the environment.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Host, address or Unix socket directory of PostgreSQL.
    #[serde(default = "default_host")]
    pub host: String,
    /// Port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// The login, a member of `factory_observer` only (docs/database/observer-login.sql). Required:
    /// the program does not guess which login to use.
    pub user: String,
    /// The database.
    #[serde(default = "default_database")]
    pub database: String,
    /// A file holding the login's password (mode 0600). None for trust or peer authentication.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// The factory's protected configuration checkout, whose `policies/security.yaml` gives the
    /// redactor its patterns. Without it only the password and the token are redacted.
    #[serde(default)]
    pub policy_checkout: Option<PathBuf>,
    /// The calls the server answers in one budget window (default 300).
    #[serde(default)]
    pub max_calls: Option<u64>,
    /// The budget window in seconds (default 3600): the call budget starts again when it has
    /// passed. One window for the process, whatever session or client the calls come from.
    #[serde(default)]
    pub budget_window_s: Option<u64>,
}

fn default_host() -> String {
    "127.0.0.1".to_owned()
}
fn default_port() -> u16 {
    5432
}
fn default_database() -> String {
    "factory".to_owned()
}

impl Settings {
    /// Parses the JSON settings.
    ///
    /// # Errors
    /// A sentence saying what is wrong.
    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text)
            .map_err(|error| format!("the settings file is not valid: {error}"))
    }

    /// Reads the settings from the environment, through `lookup` (normally `std::env::var`).
    ///
    /// # Errors
    /// A sentence saying what is wrong.
    pub fn from_env(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let port = match lookup("FACTORY_MCP_PG_PORT") {
            Some(text) => text
                .parse()
                .map_err(|_| format!("FACTORY_MCP_PG_PORT is not a port: {text:?}"))?,
            None => default_port(),
        };
        let user = lookup("FACTORY_MCP_PG_USER")
            .filter(|user| !user.is_empty())
            .ok_or(
                "FACTORY_MCP_PG_USER is not set: name the login (normally factory_troubleshooter)",
            )?;
        Ok(Self {
            host: lookup("FACTORY_MCP_PG_HOST").unwrap_or_else(default_host),
            port,
            user,
            database: lookup("FACTORY_MCP_PG_DATABASE").unwrap_or_else(default_database),
            password_file: lookup("FACTORY_MCP_PG_PASSWORD_FILE").map(PathBuf::from),
            policy_checkout: lookup("FACTORY_MCP_PG_POLICY_CHECKOUT").map(PathBuf::from),
            max_calls: None,
            budget_window_s: match lookup("FACTORY_MCP_PG_BUDGET_WINDOW_S") {
                Some(text) => Some(text.parse().map_err(|_| {
                    format!("FACTORY_MCP_PG_BUDGET_WINDOW_S is not a number of seconds: {text:?}")
                })?),
                None => None,
            },
        })
    }
}

/// Reads a secret from a file that only its owner can read. The value is the first line, with
/// the line end removed.
///
/// # Errors
/// A sentence naming the file (never its content).
pub fn read_secret_file(path: &Path, what: &str) -> Result<String, String> {
    let shown = path.display();
    let metadata =
        std::fs::metadata(path).map_err(|_| format!("the {what} file {shown} cannot be read"))?;
    if !metadata.is_file() {
        return Err(format!("the {what} file {shown} is not a regular file"));
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "the {what} file {shown} has mode {:o}; it must not be readable by group or others (chmod 600)",
            mode & 0o777
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|_| format!("the {what} file {shown} cannot be read"))?;
    let secret = text.lines().next().unwrap_or("").trim_end().to_owned();
    if secret.is_empty() {
        return Err(format!("the {what} file {shown} is empty"));
    }
    Ok(secret)
}

/// The shortest bearer token accepted.
pub const MIN_TOKEN_CHARS: usize = 32;

/// Checks a bearer token's length.
///
/// # Errors
/// A sentence saying why.
pub fn check_token(token: &str) -> Result<(), String> {
    if token.chars().count() < MIN_TOKEN_CHARS {
        return Err(format!(
            "the bearer token is shorter than {MIN_TOKEN_CHARS} characters; make one with `openssl rand -hex 32`"
        ));
    }
    Ok(())
}

/// What registering a secret with the redactor gave, as a refusal to start unless the secret is
/// registered (TR-9). A secret shorter than the redactor's minimum for exact values is not
/// registered at all, so it would never be redacted from a result or an error message.
///
/// # Errors
/// A sentence naming the secret (never its value) and the minimum.
pub fn check_registered(
    label: &str,
    registered: Result<Registered, RegistryError>,
) -> Result<(), String> {
    match registered {
        Ok(Registered::Added(_)) => Ok(()),
        Ok(Registered::TooShort) => Err(format!(
            "the {label} is shorter than the redactor's minimum for exact values (secrets.exact_values.min_length \
             of policies/security.yaml, 8 characters by default), so it could not be redacted; use a longer one \
             (`openssl rand -hex 24`)"
        )),
        Err(_) => Err(format!(
            "the {label} cannot be registered with the redactor"
        )),
    }
}

/// Whether an `Authorization` header carries the token, compared in time that does not depend on
/// where the first difference is.
pub fn bearer_matches(header: Option<&str>, token: &str) -> bool {
    let Some(presented) = header.and_then(|value| value.strip_prefix("Bearer ")) else {
        return false;
    };
    let (a, b) = (presented.as_bytes(), token.as_bytes());
    let mut difference = u8::from(a.len() != b.len());
    for (index, byte) in b.iter().enumerate() {
        difference |= byte ^ a.get(index).copied().unwrap_or(0);
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn stdio_is_the_default() {
        assert_eq!(parse_args(args(&[])), Ok(Options::default()));
    }

    #[test]
    fn http_needs_a_token_file() {
        let error = parse_args(args(&["--http", "127.0.0.1:8808"])).expect_err("refused");
        assert!(error.contains("--token-file"), "{error}");
    }

    #[test]
    fn a_non_loopback_address_needs_the_explicit_flag() {
        let refused = parse_args(args(&["--http", "0.0.0.0:8808", "--token-file", "t"]));
        assert!(refused.expect_err("refused").contains("not a loopback"));
        let allowed = parse_args(args(&[
            "--http",
            "0.0.0.0:8808",
            "--token-file",
            "t",
            "--allow-non-loopback",
        ]))
        .expect("allowed");
        assert!(allowed.allow_non_loopback);
        assert!(parse_args(args(&["--http", "[::1]:8808", "--token-file", "t"])).is_ok());
    }

    #[test]
    fn unknown_arguments_and_a_password_flag_are_refused() {
        assert!(parse_args(args(&["--password", "x"])).is_err());
        assert!(parse_args(args(&["--token-file", "t"])).is_err());
    }

    #[test]
    fn settings_have_defaults_and_refuse_unknown_keys() {
        let settings = Settings::from_json(r#"{"user": "observer"}"#).expect("parsed");
        assert_eq!(settings.database, "factory");
        assert_eq!(settings.host, "127.0.0.1");
        assert_eq!(settings.port, 5432);
        assert!(
            Settings::from_json(r#"{"database": "x"}"#).is_err(),
            "the login is required"
        );
        assert!(Settings::from_json(r#"{"user": "observer", "password": "x"}"#).is_err());
    }

    #[test]
    fn settings_from_the_environment() {
        let settings = Settings::from_env(|key| match key {
            "FACTORY_MCP_PG_USER" => Some("observer".to_owned()),
            "FACTORY_MCP_PG_PORT" => Some("6543".to_owned()),
            "FACTORY_MCP_PG_PASSWORD_FILE" => Some("/run/secrets/pg".to_owned()),
            _ => None,
        })
        .expect("parsed");
        assert_eq!(settings.port, 6543);
        assert_eq!(
            settings.password_file,
            Some(PathBuf::from("/run/secrets/pg"))
        );
        assert_eq!(settings.user, "observer");
        assert!(
            Settings::from_env(|_| None).is_err(),
            "the login is required"
        );
        assert!(
            Settings::from_env(|key| match key {
                "FACTORY_MCP_PG_USER" => Some("observer".to_owned()),
                "FACTORY_MCP_PG_PORT" => Some("x".to_owned()),
                _ => None,
            })
            .is_err()
        );
    }

    fn scratch_file(name: &str, mode: u32, content: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("factory-mcp-pg-{}-{name}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("secret");
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(content.as_bytes()).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[test]
    fn secret_files_must_be_private_and_not_empty() {
        let open = scratch_file("open", 0o644, "value-one\n");
        assert!(
            read_secret_file(&open, "token")
                .expect_err("refused")
                .contains("mode 644")
        );
        let private = scratch_file("private", 0o600, "value-two\nignored\n");
        assert_eq!(
            read_secret_file(&private, "token"),
            Ok("value-two".to_owned())
        );
        let empty = scratch_file("empty", 0o600, "\n");
        assert!(read_secret_file(&empty, "token").is_err());
        for path in [open, private, empty] {
            if let Some(dir) = path.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    #[test]
    fn tokens_are_long_and_compared_whole() {
        assert!(check_token("short").is_err());
        let token = "a".repeat(40);
        assert!(check_token(&token).is_ok());
        assert!(bearer_matches(Some(&format!("Bearer {token}")), &token));
        assert!(!bearer_matches(Some(&format!("Bearer {token}x")), &token));
        assert!(!bearer_matches(
            Some(&format!("Bearer {}", &token[1..])),
            &token
        ));
        assert!(!bearer_matches(Some(&format!("bearer {token}")), &token));
        assert!(!bearer_matches(None, &token));
    }

    #[test]
    fn a_secret_too_short_to_redact_is_refused() {
        use factory_domain::redaction::Redactor;
        let redactor = Redactor::builder().build().expect("a redactor");
        let short = check_registered(
            "database_password",
            redactor.register("database_password", "abc"),
        )
        .expect_err("too short");
        assert!(
            short.contains("shorter than the redactor's minimum"),
            "{short}"
        );
        assert!(!short.contains("abc"), "the value is never shown: {short}");
        assert_eq!(
            check_registered(
                "database_password",
                redactor.register("database_password", "long-enough-password-value")
            ),
            Ok(())
        );
    }

    #[test]
    fn the_budget_window_comes_from_the_settings() {
        let settings = Settings::from_env(|key| match key {
            "FACTORY_MCP_PG_USER" => Some("observer".to_owned()),
            "FACTORY_MCP_PG_BUDGET_WINDOW_S" => Some("600".to_owned()),
            _ => None,
        })
        .expect("parsed");
        assert_eq!(settings.budget_window_s, Some(600));
        assert!(
            Settings::from_env(|key| match key {
                "FACTORY_MCP_PG_USER" => Some("observer".to_owned()),
                "FACTORY_MCP_PG_BUDGET_WINDOW_S" => Some("soon".to_owned()),
                _ => None,
            })
            .is_err()
        );
        let parsed =
            Settings::from_json(r#"{"user": "observer", "budget_window_s": 60}"#).expect("parsed");
        assert_eq!(parsed.budget_window_s, Some(60));
    }
}
