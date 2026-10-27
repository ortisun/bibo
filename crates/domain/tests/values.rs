//! Behaviour of the value types: identifiers, hashes, timestamps, versions, text and counted
//! collections. These tests use only the public API of the crate.

use factory_domain::ids::{JobId, TenantId};
use factory_domain::scope::{CrossTenantAccess, TenantScope};
use factory_domain::values::{
    Bounded, GitSha, HumanText, HumanTitle, MediaType, NonEmptyVec, Sha256Digest, SemanticVersion,
    Slug, Timestamp, UniqueVec, UnitInterval,
};

fn json_error_text<T: serde::de::DeserializeOwned + std::fmt::Debug>(json: &str) -> String {
    serde_json::from_str::<T>(json)
        .expect_err("the document must be rejected")
        .to_string()
}

// ---- slugs ------------------------------------------------------------------------------------

#[test]
fn slug_accepts_machine_safe_identifiers() {
    for ok in ["a", "word-count", "workflow.gate-evaluator", "a_b.c-9", "x0"] {
        assert_eq!(Slug::parse(ok).expect(ok).as_str(), ok);
    }
}

#[test]
fn slug_rejects_everything_the_schema_pattern_rejects() {
    for bad in [
        "",
        "General Software",
        "UPPER",
        "-leading",
        "trailing-",
        ".dot",
        "has space",
        "has/slash",
        "line\nbreak",
        &"a".repeat(65),
    ] {
        assert!(Slug::parse(bad).is_err(), "{bad:?} must be rejected");
    }
    assert!(Slug::parse(&"a".repeat(64)).is_ok());
}

#[test]
fn slug_does_not_accept_a_trailing_newline() {
    // The Python regex used by schemas/validate.sh lets `$` match before a final newline.
    // This crate must not.
    assert!(Slug::parse("abc\n").is_err());
}

#[test]
fn slug_round_trips_through_json() {
    let slug: Slug = serde_json::from_str("\"gate-17\"").unwrap();
    assert_eq!(serde_json::to_string(&slug).unwrap(), "\"gate-17\"");
}

#[test]
fn slug_error_names_the_type_and_shows_a_short_excerpt() {
    let message = Slug::parse(&format!("BAD{}", "x".repeat(500))).unwrap_err().to_string();
    assert!(message.contains("slug"), "{message}");
    assert!(message.len() < 300, "the excerpt must be truncated: {message}");
}

// ---- human text and titles ---------------------------------------------------------------------

#[test]
fn human_title_accepts_sentence_case_titles() {
    for ok in ["Add a JSON output flag", "Run the tests", "abc"] {
        assert!(HumanTitle::parse(ok).is_ok(), "{ok:?}");
    }
}

#[test]
fn human_title_rejects_machine_prefixes_role_stamps_and_pipes() {
    for bad in [
        "TASK-13: Do work",
        "FEAT-042 | BE-AUTH | P1 do work",
        "[AGENT:BACKEND] do work",
        "TASK-13: [AGENT:BACKEND] Do work",
        "Do work [AGENT:BACKEND]",
        "has | pipe",
        "[tag] leading bracket",
    ] {
        assert!(HumanTitle::parse(bad).is_err(), "{bad:?} must be rejected");
    }
}

#[test]
fn human_title_enforces_length_and_trimming_in_characters() {
    assert!(HumanTitle::parse("ab").is_err());
    assert!(HumanTitle::parse(&"a".repeat(101)).is_err());
    assert!(HumanTitle::parse(&"a".repeat(100)).is_ok());
    // 100 characters that take more than 100 bytes are still 100 characters.
    assert!(HumanTitle::parse(&"é".repeat(100)).is_ok());
    assert!(HumanTitle::parse(" padded").is_err());
    assert!(HumanTitle::parse("padded ").is_err());
}

#[test]
fn human_text_needs_ten_characters_and_no_edge_whitespace() {
    assert!(HumanText::parse("Nine char").is_err());
    assert!(HumanText::parse("Ten chars!").is_ok());
    assert!(HumanText::parse(" leading whitespace here").is_err());
    assert!(HumanText::parse("trailing whitespace here\n").is_err());
    assert!(HumanText::parse("Line one.\nLine two.").is_ok());
    assert!(HumanText::parse(&"a".repeat(4001)).is_err());
    assert!(HumanText::parse(&"a".repeat(4000)).is_ok());
}

// ---- digests ------------------------------------------------------------------------------------

#[test]
fn sha256_of_matches_the_published_test_vector() {
    // FIPS 180-2 test vector for "abc".
    let digest = Sha256Digest::of(b"abc");
    assert_eq!(
        digest.to_string(),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_text_form_is_strict() {
    let good = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(Sha256Digest::parse(good).unwrap().to_string(), good);
    for bad in [
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
        "sha256:ba78",
        "sha1:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n",
        "",
    ] {
        assert!(Sha256Digest::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn git_sha_accepts_forty_or_sixty_four_lowercase_hex_characters() {
    assert!(GitSha::parse(&"a".repeat(40)).is_ok());
    assert!(GitSha::parse(&"a".repeat(64)).is_ok());
    for bad in [&"a".repeat(39), &"a".repeat(41), &"A".repeat(40), &"g".repeat(40)] {
        assert!(GitSha::parse(bad).is_err(), "{bad:?}");
    }
}

// ---- media types and versions -----------------------------------------------------------------

#[test]
fn media_type_matches_the_schema_pattern() {
    for ok in ["application/json", "text/markdown", "application/vnd.api+json"] {
        assert!(MediaType::parse(ok).is_ok(), "{ok}");
    }
    for bad in ["json", "Application/JSON", "text/", "/json", "text/plain; charset=utf-8"] {
        assert!(MediaType::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn semantic_version_follows_the_schema_not_the_whole_semver_grammar() {
    for ok in ["0.0.0", "1.2.3", "10.20.30-rc.1", "1.0.0-alpha"] {
        let v = SemanticVersion::parse(ok).expect(ok);
        assert_eq!(v.to_string(), ok);
    }
    for bad in ["1", "1.2", "01.2.3", "1.2.3+build.5", "v1.2.3", "1.2.3-", "1.2.3-a..b", " 1.2.3"] {
        assert!(SemanticVersion::parse(bad).is_err(), "{bad:?}");
    }
}

// ---- timestamps --------------------------------------------------------------------------------

#[test]
fn timestamp_round_trips_the_exact_text() {
    for text in [
        "2026-10-27T08:30:01Z",
        "2026-10-27T08:30:01.5Z",
        "2026-10-27T08:30:01.500Z",
        "2026-10-27T08:30:01.123456789Z",
        "2024-02-29T23:59:59Z",
        "0001-01-01T00:00:00Z",
    ] {
        let parsed = Timestamp::parse(text).expect(text);
        assert_eq!(parsed.to_string(), text);
        let via_json: Timestamp = serde_json::from_str(&format!("\"{text}\"")).unwrap();
        assert_eq!(serde_json::to_string(&via_json).unwrap(), format!("\"{text}\""));
    }
}

#[test]
fn timestamp_rejects_what_the_schema_pattern_rejects() {
    for bad in [
        "2026-10-27 08:30:01Z",
        "2026-10-27T08:30:01",
        "2026-10-27T08:30:01+00:00",
        "2026-10-27T08:30:01z",
        "2026-10-27T08:30:01.Z",
        "2026-10-27T08:30:01.1234567890Z",
        "26-10-27T08:30:01Z",
        "2026-10-27T08:30:01Z\n",
    ] {
        assert!(Timestamp::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn timestamp_also_rejects_impossible_calendar_values_that_the_pattern_allows() {
    for bad in [
        "2026-02-30T00:00:00Z",
        "2025-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-00-10T00:00:00Z",
        "2026-10-27T24:00:00Z",
        "2026-10-27T08:60:00Z",
        "2026-10-27T08:30:60Z",
    ] {
        assert!(Timestamp::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn timestamps_order_by_instant() {
    let early = Timestamp::parse("2026-10-27T08:30:01Z").unwrap();
    let later = Timestamp::parse("2026-10-27T08:30:01.000000001Z").unwrap();
    let latest = Timestamp::parse("2026-10-28T00:00:00Z").unwrap();
    assert!(early < later && later < latest);
    assert_eq!(early.unix_seconds(), 1_793_089_801);
}

// ---- identifiers ------------------------------------------------------------------------------

#[test]
fn identifiers_accept_only_lowercase_hyphenated_uuids() {
    let text = "018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f40";
    let id = JobId::parse(text).unwrap();
    assert_eq!(id.to_string(), text);
    for bad in [
        "018F3A7E-5C1B-7D2E-9A4F-3B6C8D1E2F40",
        "018f3a7e5c1b7d2e9a4f3b6c8d1e2f40",
        "{018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f40}",
        "urn:uuid:018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f40",
        "018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f4",
        "",
    ] {
        assert!(JobId::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn identifiers_of_different_kinds_are_different_types() {
    // This test only compiles if the two ids are distinct types that convert only through
    // the underlying uuid. Passing a JobId where a TenantId is wanted is a compile error.
    fn takes_tenant(_: TenantId) {}
    let job = JobId::parse("018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f40").unwrap();
    takes_tenant(TenantId::from_uuid(job.as_uuid()));
}

#[test]
fn identifier_json_form_is_a_plain_string() {
    let id: JobId = serde_json::from_str("\"018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f40\"").unwrap();
    assert_eq!(
        serde_json::to_string(&id).unwrap(),
        "\"018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f40\""
    );
    assert!(json_error_text::<JobId>("\"nope\"").contains("job id"));
}

// ---- tenant scope -----------------------------------------------------------------------------

#[test]
fn tenant_scope_admits_only_its_own_tenant() {
    let a = TenantId::parse("018f3a00-0000-7000-8000-00000000c001").unwrap();
    let b = TenantId::parse("018f3a00-0000-7000-8000-00000000c002").unwrap();
    let scope = TenantScope::new(a);
    assert_eq!(scope.tenant_id(), a);
    assert!(scope.admits(a));
    assert!(!scope.admits(b));
    assert_eq!(scope.require(a), Ok(()));
    assert_eq!(
        scope.require(b),
        Err(CrossTenantAccess { scope: a, requested: b })
    );
}

// ---- counted collections and bounded numbers ---------------------------------------------------

#[test]
fn non_empty_vec_rejects_an_empty_array_and_keeps_order() {
    let ok: NonEmptyVec<Slug> = serde_json::from_str("[\"b\",\"a\"]").unwrap();
    assert_eq!(ok.len(), 2);
    assert_eq!(serde_json::to_string(&ok).unwrap(), "[\"b\",\"a\"]");
    assert!(json_error_text::<NonEmptyVec<Slug>>("[]").contains("at least 1"));
}

#[test]
fn unique_vec_rejects_duplicates_and_honours_its_minimum() {
    assert!(serde_json::from_str::<UniqueVec<Slug>>("[]").is_ok());
    assert!(json_error_text::<UniqueVec<Slug>>("[\"a\",\"b\",\"a\"]").contains("more than once"));
    assert!(json_error_text::<UniqueVec<Slug, 1>>("[]").contains("at least 1"));
}

#[test]
fn bounded_integers_check_both_ends() {
    type Attempts = Bounded<1, 10>;
    assert_eq!(serde_json::from_str::<Attempts>("1").unwrap().get(), 1);
    assert_eq!(serde_json::from_str::<Attempts>("10").unwrap().get(), 10);
    for bad in ["0", "11", "-1", "1.5", "\"3\"", "null"] {
        assert!(serde_json::from_str::<Attempts>(bad).is_err(), "{bad}");
    }
}

#[test]
fn unit_interval_keeps_integer_and_float_forms_apart_so_documents_round_trip() {
    for text in ["0", "1", "0.5", "0.85", "1.0", "0.0"] {
        let n: UnitInterval = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::to_string(&n).unwrap(), text);
    }
    for bad in ["-0.1", "1.1", "2", "\"0.5\""] {
        assert!(serde_json::from_str::<UnitInterval>(bad).is_err(), "{bad}");
    }
}
