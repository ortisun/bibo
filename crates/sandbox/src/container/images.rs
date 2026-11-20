//! The images the supervisor may run, read from `infra/sandbox-images/images.json`.
//!
//! `images.json` is written by the image build and lists, for each platform, one entry per image
//! with its digest and status. The adapter reads it as data; it never builds or pulls an image.
//! The catalog refuses what the policy refuses:
//!
//! * an entry whose reference is not `name@sha256:<digest>`, or whose `digest` field disagrees
//!   with the digest in the reference (a tag, or a corrupted file);
//! * an image whose `status` is not `ready`. The egress sidecar is a skeleton until its program
//!   exists (`awaiting-binary`), and the adapter reports the job as blocked instead of running a
//!   relay that relays nothing;
//! * a digest that the catalog does not list at all (a request for an unknown image).
//!
//! The file text comes in as a string. Reading the file is the composition root's job.

use std::collections::BTreeMap;

use factory_ports::sandbox::{ImageDigest, SandboxProfile};
use serde_json::Value;

/// The only schema this reader understands.
pub const SCHEMA: &str = "factory-sandbox-images/1";

/// Whether an image may run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageStatus {
    /// Built and tested. May run.
    Ready,
    /// A skeleton that holds no program yet. Never runs.
    AwaitingBinary,
    /// Any other status text. Never runs.
    Other(String),
}

/// One image of the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogImage {
    /// The key in `images.json`, such as `agent`.
    pub key: String,
    /// `name@sha256:digest`: exactly what is run, with `--pull=never`.
    pub reference: ImageDigest,
    /// The manifest digest, `sha256:...`.
    pub digest: String,
    /// Whether it may run.
    pub status: ImageStatus,
    /// The numeric user the image is built for.
    pub uid: u32,
    /// The numeric group.
    pub gid: u32,
    /// The environment the image bakes in, by name and value.
    pub env: Vec<(String, String)>,
    /// The entrypoint, when the image has one (the sidecar's program).
    pub entrypoint: Option<Vec<String>>,
}

/// Why an image was refused. The caller maps it to a [`factory_ports::sandbox::SandboxError`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImageRefusal {
    /// The catalog does not list the image the spec names.
    #[error("the catalog lists no such image")]
    Unknown,
    /// The image is listed but is not ready to run.
    #[error("the image is not ready to run")]
    NotReady,
    /// The spec names a different image than the profile uses.
    #[error("the image does not belong to the profile")]
    WrongProfile,
}

/// Why `images.json` could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CatalogError {
    /// The text is not JSON, or lacks a required field.
    #[error("images.json is malformed: {0}")]
    Malformed(&'static str),
    /// The schema field names another version.
    #[error("images.json has an unknown schema")]
    UnknownSchema,
    /// The file has no block for this platform.
    #[error("images.json has no block for the platform {0}")]
    NoPlatform(String),
    /// An image entry has a reference that is not pinned by digest, or one that disagrees with
    /// its digest field.
    #[error("the image {0} is not pinned by digest")]
    NotPinned(String),
}

/// The images for one platform and which profile uses which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageCatalog {
    platform: String,
    images: BTreeMap<String, CatalogImage>,
    profile_images: BTreeMap<String, String>,
}

fn text<'a>(value: &'a Value, key: &str, what: &'static str) -> Result<&'a str, CatalogError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(CatalogError::Malformed(what))
}

fn parse_image(key: &str, value: &Value) -> Result<CatalogImage, CatalogError> {
    let reference_text = text(value, "reference", "an image has no reference")?;
    let reference =
        ImageDigest::parse(reference_text).map_err(|_| CatalogError::NotPinned(key.to_owned()))?;
    let digest = text(value, "digest", "an image has no digest")?;
    let in_reference = reference_text
        .split_once('@')
        .map(|(_, digest)| digest)
        .unwrap_or_default();
    if in_reference != digest {
        return Err(CatalogError::NotPinned(key.to_owned()));
    }
    let status = match text(value, "status", "an image has no status")? {
        "ready" => ImageStatus::Ready,
        "awaiting-binary" => ImageStatus::AwaitingBinary,
        other => ImageStatus::Other(other.to_owned()),
    };
    let id = |field: &str| {
        value
            .get("user")
            .and_then(|user| user.get(field))
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .ok_or(CatalogError::Malformed("an image has no numeric user"))
    };
    let env = value
        .get("env")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(name, v)| v.as_str().map(|v| (name.clone(), v.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    let entrypoint = value
        .get("entrypoint")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|word| word.as_str().map(str::to_owned))
                .collect()
        });
    Ok(CatalogImage {
        key: key.to_owned(),
        reference,
        digest: digest.to_owned(),
        status,
        uid: id("uid")?,
        gid: id("gid")?,
        env,
        entrypoint,
    })
}

impl ImageCatalog {
    /// Reads the block for `platform` (such as `linux/arm64`) from the text of `images.json`.
    ///
    /// # Errors
    /// [`CatalogError`] for text that is not the expected document, a missing platform, or an
    /// entry that is not pinned by digest.
    pub fn from_json(json: &str, platform: &str) -> Result<Self, CatalogError> {
        let root: Value =
            serde_json::from_str(json).map_err(|_| CatalogError::Malformed("not JSON"))?;
        if root.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
            return Err(CatalogError::UnknownSchema);
        }
        let block = root
            .get("platforms")
            .and_then(|platforms| platforms.get(platform))
            .ok_or_else(|| CatalogError::NoPlatform(platform.to_owned()))?;
        let entries = block
            .get("images")
            .and_then(Value::as_object)
            .ok_or(CatalogError::Malformed("the platform has no images"))?;
        let mut images = BTreeMap::new();
        for (key, value) in entries {
            images.insert(key.clone(), parse_image(key, value)?);
        }
        let profile_images = root
            .get("profile_images")
            .and_then(Value::as_object)
            .ok_or(CatalogError::Malformed("no profile_images"))?
            .iter()
            .filter_map(|(profile, key)| key.as_str().map(|k| (profile.clone(), k.to_owned())))
            .collect();
        Ok(Self {
            platform: platform.to_owned(),
            images,
            profile_images,
        })
    }

    /// The platform this catalog was read for.
    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }

    fn by_key(&self, profile_key: &str) -> Option<&CatalogImage> {
        self.profile_images
            .get(profile_key)
            .and_then(|key| self.images.get(key))
    }

    /// The image `spec_image` must be, for `profile`. Refuses a digest the catalog does not list,
    /// an image that is not ready, and an image that belongs to another profile.
    ///
    /// # Errors
    /// [`ImageRefusal`].
    pub fn check_spec_image(
        &self,
        profile: SandboxProfile,
        spec_image: &ImageDigest,
    ) -> Result<&CatalogImage, ImageRefusal> {
        let listed = self
            .images
            .values()
            .find(|image| image.reference == *spec_image)
            .ok_or(ImageRefusal::Unknown)?;
        let expected = self
            .by_key(image_key(profile))
            .ok_or(ImageRefusal::Unknown)?;
        if listed.reference != expected.reference {
            return Err(ImageRefusal::WrongProfile);
        }
        if listed.status != ImageStatus::Ready {
            return Err(ImageRefusal::NotReady);
        }
        Ok(listed)
    }

    /// The egress sidecar's image, when it is ready to run.
    ///
    /// # Errors
    /// [`ImageRefusal::NotReady`] for the skeleton, [`ImageRefusal::Unknown`] when there is none.
    pub fn sidecar(&self) -> Result<&CatalogImage, ImageRefusal> {
        let image = self.by_key("egress_sidecar").ok_or(ImageRefusal::Unknown)?;
        if image.status == ImageStatus::Ready {
            Ok(image)
        } else {
            Err(ImageRefusal::NotReady)
        }
    }

    /// The reference the profile's image has in this catalog, whatever its status. A composition
    /// root uses it to build a spec.
    #[must_use]
    pub fn reference_for(&self, profile: SandboxProfile) -> Option<&ImageDigest> {
        self.by_key(image_key(profile))
            .map(|image| &image.reference)
    }
}

/// The catalog entry a profile's image is listed under. The troubleshooter runs the agent image
/// (ADR 0021): the same tool, the same hardening, with no repository and other tokens.
fn image_key(profile: SandboxProfile) -> &'static str {
    match profile {
        SandboxProfile::Troubleshooter => SandboxProfile::Agent.as_str(),
        other => other.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DIGEST_C: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn entry(name: &str, digest: &str, status: &str) -> String {
        format!(
            r#"{{"reference":"{name}@{digest}","digest":"{digest}","status":"{status}",
               "user":{{"uid":10001,"gid":10001}},"env":{{"PATH":"/usr/bin"}},"entrypoint":null}}"#
        )
    }

    fn document(sidecar_status: &str) -> String {
        format!(
            r#"{{"schema":"{SCHEMA}",
               "profile_images":{{"agent":"agent","fetch_deps":"verify","verify":"verify","egress_sidecar":"egress-sidecar"}},
               "platforms":{{"linux/arm64":{{"images":{{
                 "agent":{},"verify":{},"egress-sidecar":{}}}}}}}}}"#,
            entry("factory-sandbox/agent", DIGEST_A, "ready"),
            entry("factory-sandbox/verify", DIGEST_B, "ready"),
            entry("factory-sandbox/egress-sidecar", DIGEST_C, sidecar_status),
        )
    }

    fn catalog(sidecar_status: &str) -> ImageCatalog {
        ImageCatalog::from_json(&document(sidecar_status), "linux/arm64").expect("a catalog")
    }

    fn image(name: &str, digest: &str) -> ImageDigest {
        ImageDigest::parse(&format!("{name}@{digest}")).expect("a pinned reference")
    }

    #[test]
    fn each_profile_gets_its_own_listed_ready_image() {
        let catalog = catalog("ready");
        let agent = image("factory-sandbox/agent", DIGEST_A);
        let verify = image("factory-sandbox/verify", DIGEST_B);
        assert!(
            catalog
                .check_spec_image(SandboxProfile::Agent, &agent)
                .is_ok()
        );
        assert!(
            catalog
                .check_spec_image(SandboxProfile::Verify, &verify)
                .is_ok()
        );
        assert!(
            catalog
                .check_spec_image(SandboxProfile::FetchDeps, &verify)
                .is_ok()
        );
    }

    #[test]
    fn a_digest_the_catalog_does_not_list_is_refused() {
        let catalog = catalog("ready");
        let stranger = image(
            "factory-sandbox/agent",
            &format!("sha256:{}", "d".repeat(64)),
        );
        assert_eq!(
            catalog.check_spec_image(SandboxProfile::Agent, &stranger),
            Err(ImageRefusal::Unknown)
        );
    }

    #[test]
    fn an_image_of_another_profile_is_refused() {
        let catalog = catalog("ready");
        let verify = image("factory-sandbox/verify", DIGEST_B);
        assert_eq!(
            catalog.check_spec_image(SandboxProfile::Agent, &verify),
            Err(ImageRefusal::WrongProfile)
        );
    }

    #[test]
    fn the_skeleton_sidecar_is_refused_and_a_ready_one_is_not() {
        assert_eq!(
            catalog("awaiting-binary").sidecar(),
            Err(ImageRefusal::NotReady)
        );
        assert!(catalog("ready").sidecar().is_ok());
    }

    #[test]
    fn a_reference_that_disagrees_with_its_digest_is_refused() {
        let bad = document("ready").replacen(
            &format!("\"digest\":\"{DIGEST_A}\""),
            &format!("\"digest\":\"{DIGEST_C}\""),
            1,
        );
        assert_eq!(
            ImageCatalog::from_json(&bad, "linux/arm64"),
            Err(CatalogError::NotPinned("agent".to_owned()))
        );
    }

    #[test]
    fn a_tag_is_not_a_pinned_reference() {
        let bad = document("ready").replacen(
            &format!("factory-sandbox/agent@{DIGEST_A}"),
            "factory-sandbox/agent:latest",
            1,
        );
        assert_eq!(
            ImageCatalog::from_json(&bad, "linux/arm64"),
            Err(CatalogError::NotPinned("agent".to_owned()))
        );
    }

    #[test]
    fn a_missing_platform_and_an_unknown_schema_are_errors() {
        assert_eq!(
            ImageCatalog::from_json(&document("ready"), "linux/amd64"),
            Err(CatalogError::NoPlatform("linux/amd64".to_owned()))
        );
        let other = document("ready").replace(SCHEMA, "factory-sandbox-images/2");
        assert_eq!(
            ImageCatalog::from_json(&other, "linux/arm64"),
            Err(CatalogError::UnknownSchema)
        );
    }
}
