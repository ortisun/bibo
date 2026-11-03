//! A deployment on disk for the tests that start the binary: a database with two logins of the
//! right groups, URL files, a provider key file and a configuration file.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::{TestDb, server};

pub fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

pub fn write_private(path: &Path, text: &str) {
    std::fs::write(path, text).expect("write");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("mode");
}

/// Where a deployment is and what it needs the test to know.
pub struct Deployment {
    /// The configuration file.
    pub config_path: PathBuf,
    /// The scratch directory; remove it when done.
    pub dir: PathBuf,
    /// The database; keep it alive while the worker runs.
    pub db: TestDb,
}

/// Makes a deployment. `extra` is given the scratch directory, once it exists, and returns the
/// text appended to the configuration file after the broker table, so a test adds the tables it
/// needs (`github:`, `registry:`, `worker:` and so on) and the files they name. The provider is
/// `anthropic` at `provider_url`, with a key file that holds a value built at run time.
pub async fn deployment(
    profile: &str,
    same_login: bool,
    provider_url: &str,
    listen: &str,
    extra: impl FnOnce(&Path) -> String,
) -> Deployment {
    deployment_in(profile, same_login, provider_url, listen, None, extra).await
}

/// Like [`deployment`], and `protected` names the protected checkout when the test makes its own
/// (the repository itself when it is `None`). `extra` is given the scratch directory, which holds
/// nothing of the checkout.
pub async fn deployment_in(
    profile: &str,
    same_login: bool,
    provider_url: &str,
    listen: &str,
    protected: Option<&Path>,
    extra: impl FnOnce(&Path) -> String,
) -> Deployment {
    let db = server().clone_database().await;
    // A login is a role of the whole server, and tests of one process run at the same time, so the
    // name carries a number that no other call of this process has.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let run = format!(
        "{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let worker = format!("dbtest_prep_w_{run}");
    let engine = if same_login {
        worker.clone()
    } else {
        format!("dbtest_prep_e_{run}")
    };
    // Passwords are made here and never written in source.
    let password = ["pw", "-", &run, "-abcdef"].concat();
    db.run(&format!(
        "CREATE ROLE {worker} LOGIN PASSWORD '{password}' IN ROLE factory_app;"
    ))
    .await;
    if !same_login {
        db.run(&format!(
            "CREATE ROLE {engine} LOGIN PASSWORD '{password}' IN ROLE factory_system;"
        ))
        .await;
    }
    let port = db
        .text("SELECT current_setting('port')")
        .await
        .expect("a port");
    let sockets = db
        .text("SELECT current_setting('unix_socket_directories')")
        .await
        .expect("a socket directory");
    let host = sockets.split(',').next().expect("a host").trim().to_owned();
    let url = |login: &str| {
        format!(
            "host={host} port={port} user={login} password={password} dbname={}",
            db.name
        )
    };
    let dir = repository_root()
        .join("target/prepare-test")
        .join(format!("{profile}-{run}"));
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    write_private(&dir.join("tenant.url"), &url(&worker));
    write_private(&dir.join("system.url"), &url(&engine));
    write_private(
        &dir.join("provider.key"),
        &["provider", "-key-", &"ab".repeat(13)].concat(),
    );
    let extra = extra(&dir);
    let root = repository_root();
    let protected = protected.map_or_else(|| root.clone(), Path::to_path_buf);
    let text = format!(
        "profile: {profile}\n\
         protected_checkout: {protected}\n\
         definitions_root: {root}\n\
         database:\n  tenant: {{ url_file: {dir}/tenant.url, login: {worker} }}\n  system: {{ url_file: {dir}/system.url, login: {engine} }}\n\
         artifacts: {{ root: {dir}/artifacts }}\n\
         sandbox: {{ images_catalog: {root}/infra/sandbox-images/images.json, token_root: {dir}/tokens, workspace_root: {dir}/workspaces, platform: linux/arm64 }}\n\
         broker:\n  listen: '{listen}'\n  upstreams:\n    - {{ provider: anthropic, base_url: '{provider_url}', key_file: {dir}/provider.key }}\n\
         {extra}",
        root = root.display(),
        protected = protected.display(),
        dir = dir.display(),
    );
    let config_path = dir.join("worker.yaml");
    std::fs::write(&config_path, text).expect("the configuration");
    Deployment {
        config_path,
        dir,
        db,
    }
}
