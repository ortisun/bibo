//! The contract suite for the `AgentRegistry` port: choosing a version, prompts whose hash is
//! checked, and capability profiles by tag.

use std::future::Future;

use async_trait::async_trait;
use factory_domain::contracts::{AgentManifest, DomainCapabilityProfile};
use factory_domain::values::{SemanticVersion, Slug};
use factory_ports::registry::{AgentId, AgentRegistry, DomainTag, RegistryError, VersionReq};

use super::{Check, Context, Report, check_list, ensure, ensure_eq, ensure_err, run_checks, skip};

/// What the suite needs beyond the `AgentRegistry` port itself.
#[async_trait]
pub trait RegistrySubject: Send + Sync {
    /// The registry under test.
    fn registry(&self) -> &dyn AgentRegistry;

    /// An agent the registry holds in several versions.
    fn agent(&self) -> AgentId;

    /// The versions of that agent, lowest first. There are at least three, and the highest is in
    /// a different major version from the lowest.
    fn versions(&self) -> Vec<SemanticVersion>;

    /// A manifest the registry holds whose prompt file was changed after the manifest was
    /// written, so its hash no longer matches. `None` when the subject cannot make one.
    fn manifest_with_a_changed_prompt(&self) -> Option<AgentManifest>;

    /// A manifest the registry holds whose prompt file is missing. `None` when the subject cannot
    /// make one.
    fn manifest_with_a_missing_prompt(&self) -> Option<AgentManifest>;

    /// A tag that profiles match, and the ids of those profiles in the order the registry must
    /// return them.
    fn profile_tag(&self) -> (DomainTag, Vec<Slug>);
}

/// A check of the registry contract.
pub type RegistryCheck = Check<dyn RegistrySubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: RegistrySubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn RegistrySubject>
    })
    .await
}

/// Every check of the registry contract.
#[must_use]
pub fn checks() -> Vec<RegistryCheck> {
    check_list![dyn RegistrySubject;
        any_version_picks_the_highest,
        an_exact_requirement_picks_that_version,
        a_major_requirement_picks_the_highest_of_that_major,
        an_unknown_agent_and_an_unmatched_requirement_are_different_errors,
        a_prompt_comes_back_with_a_matching_hash,
        a_changed_prompt_is_refused,
        a_missing_prompt_is_not_found,
        profiles_come_back_for_a_tag_in_a_stable_order,
    ]
}

/// No waivers: every check has a defect.
pub const WAIVERS: &[super::Waiver] = &[];

fn versions(subject: &dyn RegistrySubject) -> Result<Vec<SemanticVersion>, String> {
    let found = subject.versions();
    ensure!(
        found.len() >= 3,
        "the subject must hold at least three versions"
    );
    Ok(found)
}

async fn any_version_picks_the_highest(subject: &dyn RegistrySubject) -> Result<(), String> {
    let versions = versions(subject)?;
    let found = subject
        .registry()
        .manifest(&subject.agent(), &VersionReq::Any)
        .ctx("manifest")?;
    ensure_eq!(
        found.version.clone(),
        versions[versions.len() - 1].clone(),
        "the version chosen for Any"
    );
    Ok(())
}

async fn an_exact_requirement_picks_that_version(
    subject: &dyn RegistrySubject,
) -> Result<(), String> {
    let versions = versions(subject)?;
    let wanted = versions[1].clone();
    let found = subject
        .registry()
        .manifest(&subject.agent(), &VersionReq::Exact(wanted.clone()))
        .ctx("manifest")?;
    ensure_eq!(
        found.version.clone(),
        wanted,
        "the version chosen for an exact requirement"
    );
    Ok(())
}

async fn a_major_requirement_picks_the_highest_of_that_major(
    subject: &dyn RegistrySubject,
) -> Result<(), String> {
    let versions = versions(subject)?;
    let major = versions[0].version().major;
    let expected = versions
        .iter()
        .filter(|v| v.version().major == major)
        .max()
        .cloned()
        .ok_or("no version has the lowest major")?;
    let found = subject
        .registry()
        .manifest(&subject.agent(), &VersionReq::SameMajor(major))
        .ctx("manifest")?;
    ensure_eq!(
        found.version.clone(),
        expected,
        "the version chosen for a major requirement"
    );
    Ok(())
}

async fn an_unknown_agent_and_an_unmatched_requirement_are_different_errors(
    subject: &dyn RegistrySubject,
) -> Result<(), String> {
    let ghost = Slug::parse("no-such-agent").ctx("slug")?;
    ensure_err!(
        subject.registry().manifest(&ghost, &VersionReq::Any),
        RegistryError::UnknownAgent,
        "an agent the registry does not hold"
    );
    ensure_err!(
        subject
            .registry()
            .manifest(&subject.agent(), &VersionReq::SameMajor(9999)),
        RegistryError::NoMatchingVersion,
        "a major version the agent does not have"
    );
    Ok(())
}

async fn a_prompt_comes_back_with_a_matching_hash(
    subject: &dyn RegistrySubject,
) -> Result<(), String> {
    let manifest = subject
        .registry()
        .manifest(&subject.agent(), &VersionReq::Any)
        .ctx("manifest")?;
    let prompt = subject.registry().prompt(&manifest).ctx("prompt")?;
    ensure_eq!(
        factory_domain::values::Sha256Digest::of(prompt.text.as_bytes()),
        manifest.prompt.template_sha256.clone(),
        "the hash of the prompt text against the hash in the manifest"
    );
    ensure_eq!(
        prompt.template.clone(),
        manifest.prompt.clone(),
        "the template reference"
    );
    Ok(())
}

async fn a_changed_prompt_is_refused(subject: &dyn RegistrySubject) -> Result<(), String> {
    let Some(manifest) = subject.manifest_with_a_changed_prompt() else {
        skip!("this subject cannot make a manifest whose prompt was changed");
    };
    match subject.registry().prompt(&manifest) {
        Err(RegistryError::PromptHashMismatch { expected, actual }) => {
            ensure_eq!(
                expected,
                manifest.prompt.template_sha256.clone(),
                "the hash the error expects"
            );
            ensure!(
                actual != expected,
                "the actual hash must differ from the expected one"
            );
            Ok(())
        }
        Err(other) => Err(format!(
            "a changed prompt: expected PromptHashMismatch but found {other:?}"
        )),
        Ok(_) => Err("a prompt whose hash does not match its manifest was returned".to_owned()),
    }
}

async fn a_missing_prompt_is_not_found(subject: &dyn RegistrySubject) -> Result<(), String> {
    let Some(manifest) = subject.manifest_with_a_missing_prompt() else {
        skip!("this subject cannot make a manifest whose prompt is missing");
    };
    ensure_err!(
        subject.registry().prompt(&manifest),
        RegistryError::PromptNotFound,
        "a prompt file that is not in the registry"
    );
    Ok(())
}

async fn profiles_come_back_for_a_tag_in_a_stable_order(
    subject: &dyn RegistrySubject,
) -> Result<(), String> {
    let (tag, expected_ids) = subject.profile_tag();
    let found: Vec<DomainCapabilityProfile> = subject
        .registry()
        .profiles_matching(std::slice::from_ref(&tag))
        .ctx("profiles")?;
    let ids: Vec<Slug> = found.iter().map(|profile| profile.id.clone()).collect();
    ensure_eq!(ids, expected_ids, "the profiles that match the tag");
    let again = subject
        .registry()
        .profiles_matching(std::slice::from_ref(&tag))
        .ctx("profiles again")?;
    ensure_eq!(again.len(), found.len(), "profiles on a second call");
    let none = subject
        .registry()
        .profiles_matching(&[Slug::parse("a-tag-nothing-matches").ctx("slug")?])
        .ctx("profiles for an unknown tag")?;
    ensure_eq!(
        none.len(),
        0,
        "profiles for a tag nothing matches (an empty list, not an error)"
    );
    Ok(())
}
