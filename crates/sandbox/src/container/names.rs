//! Names and labels of everything the supervisor creates.
//!
//! One sandbox owns up to three Docker objects (the container, its per-job network and its egress
//! sidecar) and one token directory. They share a suffix, so the janitor can find all four from
//! any one of them without a database:
//!
//! ```text
//! container   sf-<suffix>
//! network     sf-net-<suffix>
//! sidecar     sf-side-<suffix>
//! token dir   <token root>/<suffix>/
//! ```
//!
//! The suffix is `<job>-<attempt>-<random>`, eight lower-case hex characters each. Every object also
//! carries labels, because a name can be guessed and a label filter is how the janitor and the
//! test harness find what is theirs.

use factory_domain::ids::{AttemptId, JobId};
use factory_ports::sandbox::{SandboxProfile, SandboxSpec};

/// Marks an object as made by this supervisor. The value says which kind.
pub const KIND_LABEL: &str = "sf.sandbox";
/// The job id (an attribute name from the observability conventions).
pub const JOB_LABEL: &str = "factory.job_id";
/// The attempt id, read back by the janitor to decide whether the object is an orphan.
pub const ATTEMPT_LABEL: &str = "factory.attempt_id";
/// The profile name.
pub const PROFILE_LABEL: &str = "sf.profile";
/// The sidecar alias the container expects on its network.
pub const SIDECAR_LABEL: &str = "sf.sidecar";
/// The wall-clock limit in milliseconds, which Docker has no field for.
pub const WALL_MS_LABEL: &str = "sf.limit.wall_ms";
/// The workspace and output disk limit in MiB, which Docker has no field for.
pub const DISK_MB_LABEL: &str = "sf.limit.disk_mb";

/// What kind of object a label marks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The sandbox container.
    Sandbox,
    /// The egress sidecar container.
    Sidecar,
    /// The per-job network.
    Network,
}

impl Kind {
    /// The label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Sidecar => "sidecar",
            Self::Network => "network",
        }
    }
}

/// The names of the objects of one sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxNames {
    /// The shared suffix.
    pub suffix: String,
    /// The container name.
    pub container: String,
    /// The network name.
    pub network: String,
    /// The sidecar container name.
    pub sidecar: String,
}

fn eight_hex(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase()
}

impl SandboxNames {
    /// Names for the sandbox of `job` and `attempt`. `random` is a fresh identifier, so two
    /// sandboxes of one attempt never share a name.
    #[must_use]
    pub fn new(job: &JobId, attempt: &AttemptId, random: &str) -> Self {
        let tail: String = random
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<String>()
            .to_ascii_lowercase();
        let suffix = format!(
            "{}-{}-{}",
            eight_hex(&job.to_string()),
            eight_hex(&attempt.to_string()),
            tail
        );
        Self::from_suffix(&suffix)
    }

    /// The names that go with `suffix`.
    #[must_use]
    pub fn from_suffix(suffix: &str) -> Self {
        Self {
            suffix: suffix.to_owned(),
            container: format!("sf-{suffix}"),
            network: format!("sf-net-{suffix}"),
            sidecar: format!("sf-side-{suffix}"),
        }
    }

    /// The suffix inside a container, sidecar or network name made by this supervisor.
    #[must_use]
    pub fn suffix_of(name: &str) -> Option<&str> {
        ["sf-net-", "sf-side-", "sf-"]
            .iter()
            .find_map(|prefix| name.strip_prefix(prefix))
            .filter(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
            })
    }
}

/// The labels every object of a sandbox carries.
#[must_use]
pub fn labels(
    kind: Kind,
    spec: &SandboxSpec,
    sidecar_alias: Option<&str>,
    owner: &[(String, String)],
) -> Vec<(String, String)> {
    let mut all = vec![
        (KIND_LABEL.to_owned(), kind.as_str().to_owned()),
        (JOB_LABEL.to_owned(), spec.job.to_string()),
        (ATTEMPT_LABEL.to_owned(), spec.attempt.to_string()),
        (
            PROFILE_LABEL.to_owned(),
            profile_name(spec.profile).to_owned(),
        ),
        (
            WALL_MS_LABEL.to_owned(),
            spec.limits.wall_clock.as_millis().to_string(),
        ),
        (
            DISK_MB_LABEL.to_owned(),
            spec.limits.workspace_disk_mb.get().to_string(),
        ),
    ];
    if let Some(alias) = sidecar_alias {
        all.push((SIDECAR_LABEL.to_owned(), alias.to_owned()));
    }
    all.extend(owner.iter().cloned());
    all
}

fn profile_name(profile: SandboxProfile) -> &'static str {
    profile.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_names_share_one_suffix_that_can_be_read_back_from_any_of_them() {
        let names = SandboxNames::from_suffix("0a1b2c3d-4e5f6a7b-89abcdef");
        for name in [&names.container, &names.network, &names.sidecar] {
            assert_eq!(
                SandboxNames::suffix_of(name),
                Some("0a1b2c3d-4e5f6a7b-89abcdef"),
                "{name}"
            );
        }
    }

    #[test]
    fn a_name_that_is_not_ours_has_no_suffix() {
        for stranger in [
            "postgres",
            "sf-",
            "sf-not hex",
            "sf-net-",
            "bridge",
            "sf-XYZ",
        ] {
            assert_eq!(SandboxNames::suffix_of(stranger), None, "{stranger}");
        }
    }
}
