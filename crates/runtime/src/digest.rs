//! Digests for telemetry: what a log line or a span records in place of text that a tool or a
//! repository chose.
//!
//! The conventions page (section 8) keeps tool arguments, tool output and file names out of
//! telemetry and records a digest instead. The digest is the workspace's own, `Sha256Digest`; this
//! module only cuts or joins its input so that every adapter does it the same way.

use factory_domain::values::Sha256Digest;

/// All 64 hex characters of the SHA-256 of `bytes`. For a span attribute such as
/// `factory.tool_args_sha256`, which the page defines as a hex digest.
pub(crate) fn hex(bytes: &[u8]) -> String {
    Sha256Digest::of(bytes).hex().to_owned()
}

/// The first 12 hex characters of the SHA-256 of the names joined by a line feed. Short enough for a
/// log line, long enough to tell two sets apart, and the same set always gives the same digest.
pub(crate) fn names(names: &[String]) -> String {
    hex(names.join("\n").as_bytes()).chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_the_same_for_the_same_input_and_never_holds_the_input() {
        let one = names(&["alpha-one".to_owned(), "beta-two".to_owned()]);
        assert_eq!(one, names(&["alpha-one".to_owned(), "beta-two".to_owned()]));
        assert_eq!(one.len(), 12);
        assert!(one.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!one.contains("alpha"));
        assert_ne!(one, names(&["alpha-one".to_owned()]));
    }

    #[test]
    fn the_full_digest_is_64_hex_characters() {
        let digest = hex(b"{\"command\":\"ls\"}");
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
