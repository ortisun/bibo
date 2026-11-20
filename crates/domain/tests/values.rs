//! Behaviour of the value types: identifiers, hashes, timestamps, versions, text and counted
//! collections. These tests use only the public API of the crate.

use factory_domain::ids::{JobId, TenantId};
use factory_domain::scope::{CrossTenantAccess, TenantScope};
use factory_domain::values::{
    AggregateVersion, Bounded, ExactInteger, ExactPositiveInt, GitSha, HumanText, HumanTitle,
    LARGEST_EXACT_INTEGER, MediaType, NonEmptyVec, SemanticVersion, Sha256Digest, Slug, Timestamp,
    Traceparent, UniqueVec, UnitInterval,
};

fn json_error_text<T: serde::de::DeserializeOwned + std::fmt::Debug>(json: &str) -> String {
    serde_json::from_str::<T>(json)
        .expect_err("the document must be rejected")
        .to_string()
}

// ---- slugs ------------------------------------------------------------------------------------

#[test]
fn slug_accepts_machine_safe_identifiers() {
    for ok in [
        "a",
        "word-count",
        "workflow.gate-evaluator",
        "a_b.c-9",
        "x0",
    ] {
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
    let message = Slug::parse(&format!("BAD{}", "x".repeat(500)))
        .unwrap_err()
        .to_string();
    assert!(message.contains("slug"), "{message}");
    assert!(
        message.len() < 300,
        "the excerpt must be truncated: {message}"
    );
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
    for bad in [
        &"a".repeat(39),
        &"a".repeat(41),
        &"A".repeat(40),
        &"g".repeat(40),
    ] {
        assert!(GitSha::parse(bad).is_err(), "{bad:?}");
    }
}

// ---- media types and versions -----------------------------------------------------------------

#[test]
fn media_type_matches_the_schema_pattern() {
    for ok in [
        "application/json",
        "text/markdown",
        "application/vnd.api+json",
    ] {
        assert!(MediaType::parse(ok).is_ok(), "{ok}");
    }
    for bad in [
        "json",
        "Application/JSON",
        "text/",
        "/json",
        "text/plain; charset=utf-8",
    ] {
        assert!(MediaType::parse(bad).is_err(), "{bad}");
    }
}

#[test]
fn semantic_version_follows_the_schema_not_the_whole_semver_grammar() {
    for ok in ["0.0.0", "1.2.3", "10.20.30-rc.1", "1.0.0-alpha"] {
        let v = SemanticVersion::parse(ok).expect(ok);
        assert_eq!(v.to_string(), ok);
    }
    for bad in [
        "1",
        "1.2",
        "01.2.3",
        "1.2.3+build.5",
        "v1.2.3",
        "1.2.3-",
        "1.2.3-a..b",
        " 1.2.3",
    ] {
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
        assert_eq!(
            serde_json::to_string(&via_json).unwrap(),
            format!("\"{text}\"")
        );
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

fn hash_of(value: &Timestamp) -> u64 {
    use std::hash::{BuildHasher, BuildHasherDefault, DefaultHasher};
    BuildHasherDefault::<DefaultHasher>::default().hash_one(value)
}

#[test]
fn timestamp_equality_ignores_spelling() {
    // ADR 0011: `10:00:00Z` and `10:00:00.000Z` are one instant written two ways.
    let spellings = [
        "2026-10-27T10:00:00Z",
        "2026-10-27T10:00:00.0Z",
        "2026-10-27T10:00:00.000Z",
        "2026-10-27T10:00:00.000000000Z",
    ];
    let parsed: Vec<Timestamp> = spellings
        .iter()
        .map(|text| Timestamp::parse(text).unwrap())
        .collect();
    for (left, left_text) in parsed.iter().zip(spellings) {
        for (right, right_text) in parsed.iter().zip(spellings) {
            assert_eq!(left, right, "{left_text} and {right_text}");
            assert_eq!(
                hash_of(left),
                hash_of(right),
                "{left_text} and {right_text} hash differently"
            );
            // Neither sorts before the other, and the order is consistent with equality.
            assert_eq!(left.cmp(right), std::cmp::Ordering::Equal);
            assert_eq!(left.partial_cmp(right), Some(std::cmp::Ordering::Equal));
        }
    }
    // The spelling is still kept: only the comparison ignores it.
    assert_eq!(parsed[0].as_text(), "2026-10-27T10:00:00Z");
    assert_eq!(parsed[2].as_text(), "2026-10-27T10:00:00.000Z");
    assert_ne!(parsed[0].as_text(), parsed[2].as_text());

    // A set holds one of them, and a sorted list does not depend on the spelling.
    let set: std::collections::HashSet<Timestamp> = parsed.iter().copied().collect();
    assert_eq!(set.len(), 1);
    let ordered: std::collections::BTreeSet<Timestamp> = parsed.iter().copied().collect();
    assert_eq!(ordered.len(), 1);
}

#[test]
fn timestamps_with_different_instants_stay_different_whatever_the_spelling() {
    // The same digits at different lengths are different instants: `.5` is half a second and
    // `.05` is a twentieth of one.
    let half = Timestamp::parse("2026-10-27T10:00:00.5Z").unwrap();
    let half_long = Timestamp::parse("2026-10-27T10:00:00.500Z").unwrap();
    let twentieth = Timestamp::parse("2026-10-27T10:00:00.05Z").unwrap();
    assert!(
        Timestamp::parse("2026-10-27T10:00:00.5000000001Z").is_err(),
        "ten fraction digits are not allowed"
    );
    let just_over = Timestamp::parse("2026-10-27T10:00:00.500000001Z").unwrap();

    assert_eq!(half, half_long);
    assert!(twentieth < half && twentieth < half_long);
    assert!(half < just_over && half_long < just_over);
    assert_ne!(hash_of(&half), hash_of(&twentieth));

    // Sorting looks at the instant only: the shorter spelling does not always go first.
    let mut stamps = vec![just_over, half_long, twentieth, half];
    stamps.sort();
    assert_eq!(stamps, [twentieth, half_long, half, just_over]);
    assert_eq!(stamps[1].as_text(), "2026-10-27T10:00:00.500Z");
    assert_eq!(stamps[2].as_text(), "2026-10-27T10:00:00.5Z");
}

#[test]
fn equal_timestamps_hash_alike_and_order_alike_over_many_spellings() {
    // Every nanosecond count that has trailing zeros can be written at several lengths.
    for nanos in [
        0_u32,
        500_000_000,
        250_000_000,
        120_000_000,
        100_000_000,
        10_000_000,
        1_000_000,
        100_000,
        10,
        1,
        999_999_999,
    ] {
        let full = format!("{nanos:09}");
        let shortest = full.trim_end_matches('0');
        let mut spellings = Vec::new();
        for digits in shortest.len().max(1)..=9 {
            let fraction = &full[..digits];
            spellings.push(format!("2026-10-27T10:00:01.{fraction}Z"));
        }
        if nanos == 0 {
            spellings.push("2026-10-27T10:00:01Z".to_owned());
        }
        let parsed: Vec<Timestamp> = spellings
            .iter()
            .map(|text| Timestamp::parse(text).unwrap())
            .collect();
        for window in parsed.windows(2) {
            assert_eq!(window[0], window[1], "{spellings:?}");
            assert_eq!(hash_of(&window[0]), hash_of(&window[1]), "{spellings:?}");
            assert_eq!(window[0].cmp(&window[1]), std::cmp::Ordering::Equal);
        }
    }
}

#[test]
fn from_utc_is_the_shortest_spelling() {
    use time::OffsetDateTime;
    let base = OffsetDateTime::from_unix_timestamp(1_793_095_200).unwrap(); // 2026-10-27T10:00:00Z
    for (nanos, expected) in [
        (0_i128, "2026-10-27T10:00:00Z"),
        (500_000_000, "2026-10-27T10:00:00.5Z"),
        (120_000_000, "2026-10-27T10:00:00.12Z"),
        (1_000_000, "2026-10-27T10:00:00.001Z"),
        (1_000, "2026-10-27T10:00:00.000001Z"),
        (1, "2026-10-27T10:00:00.000000001Z"),
        (999_999_999, "2026-10-27T10:00:00.999999999Z"),
    ] {
        let instant = base + time::Duration::nanoseconds(i64::try_from(nanos).unwrap());
        let stamp = Timestamp::from_utc(instant);
        assert_eq!(stamp.as_text(), expected);
        // No value the factory builds ends in a zero digit of the fraction.
        let text = stamp.as_text();
        let without_zone = text.strip_suffix('Z').unwrap();
        if let Some((_, fraction)) = without_zone.split_once('.') {
            assert!(!fraction.ends_with('0'), "{text} has a trailing zero");
        }
    }
    // Two values for the same instant that the factory built are byte-identical.
    let once = Timestamp::from_utc(base + time::Duration::milliseconds(250));
    let twice = Timestamp::from_utc(base + time::Duration::microseconds(250_000));
    assert_eq!(once.as_text(), twice.as_text());
}

#[test]
fn from_utc_agrees_with_a_parsed_timestamp_of_the_same_instant() {
    // A timestamp from a document with a long spelling equals the one the factory builds.
    let parsed = Timestamp::parse("2026-10-27T10:00:00.250000Z").unwrap();
    let built = Timestamp::from_utc(parsed.to_utc());
    assert_eq!(parsed, built);
    assert_eq!(hash_of(&parsed), hash_of(&built));
    assert_ne!(parsed.as_text(), built.as_text());
    assert_eq!(built.as_text(), "2026-10-27T10:00:00.25Z");
}

// ---- integers that a ledger hash can hold ---------------------------------------------------------

#[test]
fn the_largest_exact_integer_is_two_to_the_53_minus_one() {
    // ADR 0011: RFC 8785 writes every number as a 64-bit float, which holds this one exactly and
    // rounds the next.
    assert_eq!(LARGEST_EXACT_INTEGER, 9_007_199_254_740_991);
    assert_eq!(LARGEST_EXACT_INTEGER, (1_i64 << 53) - 1);
    #[allow(clippy::cast_precision_loss)]
    let as_float = LARGEST_EXACT_INTEGER as f64;
    assert_eq!(as_float as i64, LARGEST_EXACT_INTEGER);
    assert_eq!((as_float + 1.0) as i64, LARGEST_EXACT_INTEGER + 1);
    // One more is where a float starts to skip: 2^53 + 1 is not a float.
    #[allow(clippy::cast_precision_loss)]
    let skipped = (LARGEST_EXACT_INTEGER + 2) as f64;
    assert_eq!(skipped as i64, LARGEST_EXACT_INTEGER + 1);
}

#[test]
fn an_exact_integer_accepts_the_whole_range_and_refuses_the_next_number() {
    for ok in [-LARGEST_EXACT_INTEGER, -1, 0, 1, 42, LARGEST_EXACT_INTEGER] {
        assert_eq!(ExactInteger::new(ok).unwrap().get(), ok);
    }
    for bad in [
        LARGEST_EXACT_INTEGER + 1,
        -LARGEST_EXACT_INTEGER - 1,
        i64::MAX,
        i64::MIN,
    ] {
        let error = ExactInteger::new(bad).unwrap_err().to_string();
        assert!(
            error.contains("use a whole number from -9007199254740991 to 9007199254740991"),
            "{bad}: {error}"
        );
    }
}

#[test]
fn an_exact_positive_integer_starts_at_one_and_stops_at_the_largest_exact_integer() {
    assert!(ExactPositiveInt::new(0).is_err());
    assert!(ExactPositiveInt::new(-1).is_err());
    assert_eq!(ExactPositiveInt::new(1).unwrap().get(), 1);
    assert_eq!(
        ExactPositiveInt::new(LARGEST_EXACT_INTEGER).unwrap().get(),
        LARGEST_EXACT_INTEGER
    );
    let error = ExactPositiveInt::new(LARGEST_EXACT_INTEGER + 1)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("use a whole number from 1 to 9007199254740991"),
        "{error}"
    );
}

#[test]
fn an_exact_integer_is_refused_when_a_document_is_read() {
    // The value is checked when it is built from a document, so a number that a hash would round
    // never gets as far as the hash.
    assert_eq!(
        serde_json::from_str::<ExactInteger>("9007199254740991")
            .unwrap()
            .get(),
        LARGEST_EXACT_INTEGER
    );
    let error = json_error_text::<ExactInteger>("9007199254740992");
    assert!(error.contains("9007199254740992"), "{error}");
    let error = json_error_text::<ExactInteger>("-9007199254740992");
    assert!(error.contains("-9007199254740992"), "{error}");
    // A fraction is not a whole number, whatever its size.
    assert!(serde_json::from_str::<ExactInteger>("5.0").is_err());
    assert!(serde_json::from_str::<ExactInteger>("1e3").is_err());
    // It writes back as the number it was.
    let written = serde_json::to_string(&ExactInteger::new(-7).unwrap()).unwrap();
    assert_eq!(written, "-7");
}

// ---- the trace context of a job ---------------------------------------------------------------

#[test]
fn traceparent_for_job_uses_the_job_uuid_as_trace_id_and_the_documented_span_id() {
    // ADR 0013: the trace id is the 32 hex characters of the job's UUID, the span id is the first
    // 16 hex characters of SHA-256("factory.job" + the job id), and the flags are `01`. The
    // expected text was computed with `printf 'factory.job<job id>' | shasum -a 256`, not with
    // this crate.
    let job = JobId::parse("018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f40").unwrap();
    assert_eq!(
        Traceparent::for_job(job).as_str(),
        "00-018f3a7e5c1b7d2e9a4f3b6c8d1e2f40-f7e4b2ec5e23fd8a-01"
    );
    let other = JobId::parse("018f3a7e-b033-7d21-9f6e-5b8c0d1e2f32").unwrap();
    assert_eq!(
        Traceparent::for_job(other).as_str(),
        "00-018f3a7eb0337d219f6e5b8c0d1e2f32-15f80c3cc8af35f0-01"
    );
}

#[test]
fn traceparent_for_job_matches_the_w3c_pattern_and_reads_back() {
    let pattern = regex::Regex::new(Traceparent::PATTERN).unwrap();
    for n in [
        1_u128,
        2,
        0xabcd,
        u128::MAX,
        0x018f_3a7e_5c1b_7d2e_9a4f_3b6c_8d1e_2f40,
    ] {
        let job = JobId::from_uuid(uuid::Uuid::from_u128(n));
        let made = Traceparent::for_job(job);
        assert!(pattern.is_match(made.as_str()), "{made}");
        assert_eq!(Traceparent::parse(made.as_str()).as_ref(), Ok(&made));
        // The pieces: version 00, a trace id that is the job's UUID without hyphens, sampled.
        let parts: Vec<&str> = made.as_str().split('-').collect();
        assert_eq!(parts[0], "00");
        assert_eq!(parts[1], job.as_uuid().simple().to_string());
        assert_eq!(parts[2].len(), 16);
        assert_eq!(parts[3], "01");
    }
}

#[test]
fn traceparent_for_job_is_the_same_for_the_same_job_and_differs_between_jobs() {
    let a = JobId::from_uuid(uuid::Uuid::from_u128(7));
    let b = JobId::from_uuid(uuid::Uuid::from_u128(8));
    assert_eq!(Traceparent::for_job(a), Traceparent::for_job(a));
    assert_ne!(Traceparent::for_job(a), Traceparent::for_job(b));
    // Both the trace id and the span id depend on the job.
    let (left, right) = (Traceparent::for_job(a), Traceparent::for_job(b));
    let part = |t: &Traceparent, i: usize| t.as_str().split('-').nth(i).unwrap().to_owned();
    assert_ne!(part(&left, 1), part(&right, 1));
    assert_ne!(part(&left, 2), part(&right, 2));
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
        Err(CrossTenantAccess {
            scope: a,
            requested: b
        })
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
fn aggregate_versions_start_at_one_and_only_count_up() {
    // ADR 0007: mutable rows carry a version, and a write names the version it read.
    let first = AggregateVersion::FIRST;
    assert_eq!(first.get(), 1);
    let second = first.next().unwrap();
    assert_eq!(second.get(), 2);
    assert!(first < second);
    assert!(AggregateVersion::new(i64::MAX).unwrap().next().is_err());
    assert!(AggregateVersion::new(0).is_err());
    assert!(AggregateVersion::new(-1).is_err());
    assert_eq!(serde_json::to_string(&second).unwrap(), "2");
    assert_eq!(
        serde_json::from_str::<AggregateVersion>("7").unwrap().get(),
        7
    );
    assert!(json_error_text::<AggregateVersion>("0").contains("at least 1"));
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
