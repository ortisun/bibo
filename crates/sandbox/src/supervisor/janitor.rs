//! The janitor: removes the sandboxes whose attempt is over, found by label.
//!
//! After a crash nothing in memory says what exists, so the janitor asks Docker. Every container
//! and network this supervisor makes carries the marker label, the attempt id and the owner
//! labels of the provider. The janitor lists the objects that carry the marker and all the owner
//! labels, drops the ones whose attempt is in the live list, and removes the rest together with
//! the token directory of each. It never touches an object that lacks the owner labels, so it
//! cannot reach another stack's containers on the same host.
//!
//! A token directory whose sandbox left no Docker object at all cannot be found this way. The
//! agent profile creates its network before it writes the token, so the network is the marker
//! that finds the directory.

use std::collections::BTreeSet;

use factory_domain::ids::AttemptId;
use factory_ports::sandbox::{SandboxError, SandboxId};

use super::cleanup::{Created, remove_all};
use super::{Shared, daemon_error};
use crate::container::docker::NeverCancel;
use crate::container::names::{ATTEMPT_LABEL, KIND_LABEL, Kind, SandboxNames};

/// One object the listing found.
struct Found {
    name: String,
    kind: String,
    attempt: String,
}

fn filters(shared: &Shared) -> Vec<String> {
    let mut args = vec!["--filter".to_owned(), format!("label={KIND_LABEL}")];
    for (key, value) in &shared.config.owner_labels {
        args.push("--filter".to_owned());
        args.push(format!("label={key}={value}"));
    }
    args
}

fn row_format() -> String {
    format!("{{{{.Names}}}}\t{{{{.Label \"{KIND_LABEL}\"}}}}\t{{{{.Label \"{ATTEMPT_LABEL}\"}}}}")
}

fn network_row_format() -> String {
    format!("{{{{.Name}}}}\t{{{{.Label \"{KIND_LABEL}\"}}}}\t{{{{.Label \"{ATTEMPT_LABEL}\"}}}}")
}

fn parse(listing: &[u8]) -> Vec<Found> {
    String::from_utf8_lossy(listing)
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            Some(Found {
                name: parts.next()?.to_owned(),
                kind: parts.next()?.to_owned(),
                attempt: parts.next().unwrap_or("").to_owned(),
            })
        })
        .collect()
}

async fn list(shared: &Shared, noun: &[&str], format: String) -> Result<Vec<Found>, SandboxError> {
    let mut args: Vec<String> = noun.iter().map(|word| (*word).to_owned()).collect();
    args.extend(filters(shared));
    args.extend(["--format".to_owned(), format]);
    let output = shared
        .docker
        .run(args, &NeverCancel)
        .await
        .map_err(daemon_error)?;
    Ok(parse(&output.stdout))
}

/// Removes the sandboxes whose attempt is not in `live`. Idempotent.
pub(crate) async fn sweep(
    shared: &Shared,
    live: &[AttemptId],
) -> Result<Vec<SandboxId>, SandboxError> {
    let mut found = list(shared, &["ps", "--all", "--no-trunc"], row_format()).await?;
    found.extend(
        list(
            shared,
            &["network", "ls", "--no-trunc"],
            network_row_format(),
        )
        .await?,
    );

    let is_live = |attempt: &str| {
        attempt
            .parse::<AttemptId>()
            .is_ok_and(|id| live.contains(&id))
    };
    let mut suffixes = BTreeSet::new();
    let mut removed_sandboxes = Vec::new();
    for object in found.iter().filter(|o| !is_live(&o.attempt)) {
        let Some(suffix) = SandboxNames::suffix_of(&object.name) else {
            continue;
        };
        suffixes.insert(suffix.to_owned());
        if object.kind == Kind::Sandbox.as_str() {
            removed_sandboxes.push(SandboxId::new(object.name.clone()));
        }
    }

    let everything = Created {
        network: true,
        sidecar: true,
        container: true,
        token: true,
    };
    let mut leaked = false;
    for suffix in &suffixes {
        let names = SandboxNames::from_suffix(suffix);
        leaked |= remove_all(shared, &names, everything, false).await;
    }
    if leaked {
        return Err(SandboxError::TeardownFailed { leaked: true });
    }
    removed_sandboxes.sort();
    Ok(removed_sandboxes)
}
