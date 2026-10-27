use super::*;

fn canaries() -> CanarySet {
    CanarySet::generate_with(&mut FxRng::from_seed(42))
}

/// Hex written without the encoder under test.
fn reference_hex(text: &str, upper: bool) -> String {
    text.bytes()
        .map(|b| {
            if upper {
                format!("{b:02X}")
            } else {
                format!("{b:02x}")
            }
        })
        .collect()
}

/// Percent-encoding written without the encoder under test.
fn reference_percent(text: &str, every_byte: bool, lower: bool, plus_for_space: bool) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        let unreserved = b.is_ascii_alphanumeric() || b"-._~".contains(&b);
        if plus_for_space && b == b' ' {
            out.push('+');
        } else if unreserved && !every_byte {
            out.push(char::from(b));
        } else if lower {
            out.push_str(&format!("%{b:02x}"));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A JSON string body written by serde_json, which shares no code with the encoder under test.
fn reference_json(text: &str) -> String {
    let quoted = serde_json::to_string(text).unwrap();
    quoted[1..quoted.len() - 1].to_owned()
}

/// The spelling of `value` in `form`, built independently where an independent builder exists.
/// For the "inside a larger message" forms the leak is the base64 of a whole message.
fn leak(value: &str, form: Form) -> String {
    let b64 = |bytes: &[u8], alphabet, padded| base64_encode(bytes, alphabet, padded);
    let inside = |alphabet, offset: usize| {
        let mut message = vec![b'.'; offset];
        message.extend_from_slice(value.as_bytes());
        message.extend_from_slice(b" and some bytes that follow");
        b64(&message, alphabet, true)
    };
    match form {
        Form::Raw => value.to_owned(),
        Form::Base64Std => b64(value.as_bytes(), Base64Alphabet::Standard, true),
        Form::Base64StdNoPad => b64(value.as_bytes(), Base64Alphabet::Standard, false),
        Form::Base64Url => b64(value.as_bytes(), Base64Alphabet::UrlSafe, true),
        Form::Base64UrlNoPad => b64(value.as_bytes(), Base64Alphabet::UrlSafe, false),
        Form::Base64StdInside0 => inside(Base64Alphabet::Standard, 0),
        Form::Base64StdInside1 => inside(Base64Alphabet::Standard, 1),
        Form::Base64StdInside2 => inside(Base64Alphabet::Standard, 2),
        Form::Base64UrlInside0 => inside(Base64Alphabet::UrlSafe, 0),
        Form::Base64UrlInside1 => inside(Base64Alphabet::UrlSafe, 1),
        Form::Base64UrlInside2 => inside(Base64Alphabet::UrlSafe, 2),
        Form::HexLower => reference_hex(value, false),
        Form::HexUpper => reference_hex(value, true),
        Form::PercentUpper => reference_percent(value, false, false, false),
        Form::PercentLower => reference_percent(value, false, true, false),
        Form::PercentFormPlus => reference_percent(value, false, false, true),
        Form::PercentEveryByte => reference_percent(value, true, false, false),
        Form::JsonEscaped => reference_json(value),
        Form::JsonEscapedSlash => reference_json(value).replace('/', "\\/"),
        Form::JsonEscapedTwice => reference_json(&reference_json(value)),
        Form::Fragment => unreachable!("a fragment is not a spelling of the whole value"),
    }
}

fn is_inside(form: Form) -> bool {
    matches!(
        form,
        Form::Base64StdInside0
            | Form::Base64StdInside1
            | Form::Base64StdInside2
            | Form::Base64UrlInside0
            | Form::Base64UrlInside1
            | Form::Base64UrlInside2
    )
}

/// The form the sweeper reports for a leak: the first form whose spelling is the same bytes.
fn reported_form(value: &str, form: Form) -> Form {
    Form::ALL
        .into_iter()
        .find(|f| f.encode(value) == form.encode(value))
        .unwrap()
}

#[test]
fn generated_canaries_have_the_documented_shapes() {
    let set = canaries();
    assert_eq!(set.len(), 8);

    let token = set.get(CanaryKind::GithubInstallationToken).value();
    assert!(token.starts_with("ghs_") && token.len() == 40, "{token}");
    assert!(token[4..].bytes().all(|b| b.is_ascii_alphanumeric()));

    let key = set.get(CanaryKind::AppPrivateKey).value();
    let lines: Vec<&str> = key.lines().collect();
    assert_eq!(lines.len(), 8);
    assert!(lines[0].starts_with("-----BEGIN ") && lines[0].ends_with(" KEY-----"));
    assert!(lines[7].starts_with("-----END ") && lines[7].ends_with(" KEY-----"));
    assert!(lines[1..7].iter().all(|l| l.len() == 64));

    let webhook = set.get(CanaryKind::WebhookSecret).value();
    assert_eq!(webhook.len(), 64);
    assert!(webhook.bytes().all(|b| b.is_ascii_hexdigit()));

    let model = set.get(CanaryKind::ModelApiKey).value();
    assert!(
        model.starts_with("sk-ant-") && model.len() == 7 + 40,
        "{model}"
    );

    let job = set.get(CanaryKind::JobToken).value();
    assert!(job.starts_with("sfjt_") && job.len() == 5 + 40, "{job}");

    let password = set.get(CanaryKind::DatabasePassword).value();
    assert!(password.starts_with("CANARY-") && password.len() == 24);

    assert!(
        set.get(CanaryKind::HoldoutString)
            .value()
            .starts_with("CANARY-HOLDOUT-")
    );
    assert!(
        set.get(CanaryKind::SecondTenantString)
            .value()
            .starts_with("CANARY-TENANT-B-")
    );
    assert!(set.iter().all(Canary::has_marker));
}

#[test]
fn the_database_password_needs_every_kind_of_escaping() {
    // Over a few seeds, the password must differ from its percent and JSON spellings, or those
    // forms would be tested against a value they leave alone.
    for seed in 0..8 {
        let set = CanarySet::generate_with(&mut FxRng::from_seed(seed));
        let value = set.get(CanaryKind::DatabasePassword).value();
        let specials = value.chars().any(|c| "!@#%&*+=/?:;".contains(c));
        assert!(specials, "seed {seed}: {value}");
    }
    // At least one seed in a small range puts a quote or backslash in, so the form is exercised.
    assert!((0..16).any(|seed| {
        let set = CanarySet::generate_with(&mut FxRng::from_seed(seed));
        let value = set.get(CanaryKind::DatabasePassword).value();
        value != reference_json(value)
    }));
}

#[test]
fn two_runs_make_different_canaries_and_a_seed_repeats() {
    let a = CanarySet::generate();
    let b = CanarySet::generate();
    assert_ne!(
        a.get(CanaryKind::JobToken).value(),
        b.get(CanaryKind::JobToken).value()
    );
    let c = CanarySet::generate_with(&mut FxRng::from_seed(5));
    let d = CanarySet::generate_with(&mut FxRng::from_seed(5));
    assert_eq!(
        c.get(CanaryKind::JobToken).value(),
        d.get(CanaryKind::JobToken).value()
    );
}

#[test]
fn debug_and_hit_output_never_contain_the_secret() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    for canary in set.iter() {
        let shown = format!("{canary:?}");
        assert!(
            !shown.contains(canary.value()),
            "Debug printed a secret: {shown}"
        );
        assert!(shown.contains(&canary.fingerprint()));
        let hits = sweeper.scan("log", canary.value().as_bytes());
        let hit = hits.iter().find(|h| h.canary == canary.label()).unwrap();
        let text = format!("{hit} {hit:?}");
        assert!(!text.contains(canary.value()), "a hit printed a secret");
    }
}

#[test]
fn canary_sweeper_finds_encoded_forms() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    for canary in set.iter() {
        let value = canary.value();
        for form in Form::ALL {
            let spelling = leak(value, form);
            if !is_inside(form) {
                // The independent builder and the sweeper's own encoder must agree, or the
                // test below would only prove that the sweeper finds its own output.
                assert_eq!(
                    Some(spelling.clone().into_bytes()),
                    form.encode(value),
                    "{} / {form}: the independent spelling differs from the sweeper's",
                    canary.label()
                );
            }
            let sink = format!("{}:{form}", canary.label());
            let text = format!("line one\n[2026-10-27] note {spelling} end\nline three\n");
            let hits = sweeper.scan(&sink, text.as_bytes());
            let expected = reported_form(value, form);
            assert!(
                hits.iter()
                    .any(|h| h.canary == canary.label() && h.form == expected),
                "{} leaked as {form} was not reported as {expected}; hits: {hits:?}",
                canary.label()
            );
        }
    }
}

#[test]
fn every_form_is_distinct_from_raw_for_at_least_one_canary() {
    // If a form always equals the raw text it is never exercised. Each of these must change at
    // least one canary, or its test above proves nothing.
    let set = canaries();
    for form in Form::ALL {
        if form == Form::Raw {
            continue;
        }
        let differs = set
            .iter()
            .any(|c| form.encode(c.value()) != Form::Raw.encode(c.value()));
        assert!(differs, "{form} never differs from the raw text");
    }
    // The three percent styles and the JSON styles that need a special character.
    let key = set.get(CanaryKind::AppPrivateKey).value();
    assert_ne!(Form::JsonEscaped.encode(key), Form::Raw.encode(key));
    assert_ne!(
        Form::JsonEscapedSlash.encode(key),
        Form::JsonEscaped.encode(key)
    );
    assert_ne!(
        Form::PercentUpper.encode(key),
        Form::PercentLower.encode(key)
    );
    assert_ne!(
        Form::PercentFormPlus.encode(key),
        Form::PercentUpper.encode(key)
    );
}

#[test]
fn canary_sweeper_finds_a_canary_split_across_chunk_boundaries() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    for canary in set.iter() {
        let value = canary.value();
        for form in Form::ALL {
            let spelling = format!("<<{}>>", leak(value, form));
            let bytes = spelling.as_bytes();
            // The private key is long, so cut it at a handful of places; the others at every one.
            let cuts: Vec<usize> = if canary.kind() == CanaryKind::AppPrivateKey {
                vec![1, bytes.len() / 3, bytes.len() / 2, bytes.len() - 1]
            } else {
                (1..bytes.len()).collect()
            };
            for cut in cuts {
                let hits = sweeper.scan_chunks("stream", [&bytes[..cut], &bytes[cut..]]);
                assert!(
                    hits.iter().any(|h| h.canary == canary.label()),
                    "{} as {form}, cut at {cut}: not found",
                    canary.label()
                );
            }
        }
    }
}

#[test]
fn a_canary_written_one_byte_at_a_time_is_found() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    for kind in [
        CanaryKind::GithubInstallationToken,
        CanaryKind::WebhookSecret,
        CanaryKind::JobToken,
    ] {
        let canary = set.get(kind);
        for form in [
            Form::Raw,
            Form::Base64Std,
            Form::HexLower,
            Form::JsonEscaped,
        ] {
            let spelling = leak(canary.value(), form);
            let mut stream = sweeper.stream("stdout");
            for byte in spelling.as_bytes() {
                stream.push(std::slice::from_ref(byte));
            }
            let hits = stream.finish();
            assert!(
                hits.iter().any(|h| h.canary == canary.label()),
                "{} as {form}, one byte at a time: not found",
                canary.label()
            );
        }
    }
}

#[test]
fn colour_codes_and_zero_width_characters_do_not_hide_a_canary() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    for kind in [
        CanaryKind::GithubInstallationToken,
        CanaryKind::ModelApiKey,
        CanaryKind::JobToken,
        CanaryKind::DatabasePassword,
    ] {
        let canary = set.get(kind);
        for filler in ["\u{1b}[31m", "\u{1b}[0m", "\u{200b}", "\u{1b}]0;title\u{7}"] {
            let mut woven = String::new();
            for c in canary.value().chars() {
                woven.push(c);
                woven.push_str(filler);
            }
            let hits = sweeper.scan("tty", woven.as_bytes());
            let hit = hits
                .iter()
                .find(|h| h.canary == canary.label())
                .unwrap_or_else(|| panic!("{} woven with {filler:?} not found", canary.label()));
            assert_eq!(hit.view, View::Stripped, "the raw bytes do not hold it");
            assert_eq!(hit.form, Form::Raw);

            // The same, with a chunk boundary through the middle of an escape sequence.
            let bytes = woven.as_bytes();
            for cut in [3, bytes.len() / 2, bytes.len() - 2] {
                let hits = sweeper.scan_chunks("tty", [&bytes[..cut], &bytes[cut..]]);
                assert!(hits.iter().any(|h| h.canary == canary.label()));
            }
        }
    }
}

#[test]
fn a_clean_run_reports_clean() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let token = set.get(CanaryKind::GithubInstallationToken).value();
    // Things that look like the canaries but are not. None carries the marker, which a clean run
    // must not contain.
    let other_token = format!("ghs_{}", "a".repeat(36));
    let lowercase = token.to_lowercase();
    let near_misses = [
        "ordinary log line with the word password and a token = abc",
        &other_token,
        &lowercase,
        "canary in lower case is just a word",
        "Zm9vYmFy and 666f6f626172 and %66%6f%6f",
        "",
    ];
    let mut report = SweepReport::default();
    for (i, text) in near_misses.iter().enumerate() {
        report
            .hits
            .extend(sweeper.scan(&format!("sink-{i}"), text.as_bytes()));
        report.sinks_scanned += 1;
    }
    report.assert_clean();
    assert!(report.is_clean());
}

#[test]
fn a_truncated_leak_is_reported_as_a_fragment_and_a_full_one_is_not_reported_twice() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let token = set.get(CanaryKind::GithubInstallationToken).value();

    let hits = sweeper.scan("log", format!("cut at twelve: {}", &token[..12]).as_bytes());
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].form, Form::Fragment);

    let hits = sweeper.scan("log", format!("whole: {token}").as_bytes());
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].form, Form::Raw);

    // A token with its last character changed is no longer the canary, but it still carries the
    // marker, so it is reported as a fragment and a clean run cannot contain it.
    let mut changed_last = token.to_owned();
    changed_last.pop();
    changed_last.push('#');
    let hits = sweeper.scan("log", changed_last.as_bytes());
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].form, Form::Fragment);

    let off = Sweeper::new(&set).with_marker_scan(false);
    assert!(off.scan("log", &token.as_bytes()[..12]).is_empty());
}

#[test]
fn a_canary_seen_twice_in_one_sink_is_one_hit_with_the_first_offset() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let token = set.get(CanaryKind::JobToken).value();
    let text = format!("0123456789{token}...{token}");
    let hits = sweeper.scan("log", text.as_bytes());
    let found: Vec<_> = hits.iter().filter(|h| h.canary == "job_token").collect();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].offset, 10);
}

#[test]
fn offsets_are_counted_from_the_start_of_the_stream_across_chunks() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let token = set.get(CanaryKind::WebhookSecret).value();
    let first = "x".repeat(5000);
    let second = format!("yy{token}");
    let hits = sweeper.scan_chunks("log", [first.as_bytes(), second.as_bytes()]);
    let hit = hits.iter().find(|h| h.canary == "webhook_secret").unwrap();
    assert_eq!(hit.offset, 5002);
}

#[test]
fn a_weaker_sweeper_misses_what_the_full_sweeper_finds() {
    // Deliberate break. Take the hexadecimal and the standard base64 forms away and the same
    // leaks go unseen. If the sweeper's forms did no work, this test would fail.
    let set = canaries();
    let full = Sweeper::new(&set);
    let weak = Sweeper::new(&set).without_forms(&[
        Form::HexLower,
        Form::Base64Std,
        Form::Base64StdNoPad,
        Form::Base64StdInside0,
        Form::Base64StdInside1,
        Form::Base64StdInside2,
    ]);
    assert!(weak.needle_count() < full.needle_count());
    let canary = set.get(CanaryKind::GithubInstallationToken);
    for form in [Form::HexLower, Form::Base64Std] {
        let text = leak(canary.value(), form);
        assert!(
            full.scan("log", text.as_bytes())
                .iter()
                .any(|h| h.canary == canary.label()),
            "the full sweeper must find {form}"
        );
        assert!(
            !weak
                .scan("log", text.as_bytes())
                .iter()
                .any(|h| h.canary == canary.label() && h.form != Form::Fragment),
            "the weak sweeper must miss {form}"
        );
    }
}

#[test]
fn scanning_each_chunk_alone_misses_a_split_canary() {
    // Deliberate break for the streaming design: a per-chunk scan cannot see a canary that is cut
    // in two, which is why the sweeper keeps state between chunks.
    let set = canaries();
    let sweeper = Sweeper::new(&set).with_marker_scan(false);
    let token = set.get(CanaryKind::GithubInstallationToken).value();
    let (left, right) = token.as_bytes().split_at(20);
    assert!(sweeper.scan("a", left).is_empty());
    assert!(sweeper.scan("b", right).is_empty());
    assert_eq!(sweeper.scan_chunks("stream", [left, right]).len(), 1);
}

#[test]
fn registered_values_are_searched_and_short_ones_are_not() {
    let set = canaries().with(Canary::custom("minted", "ghs_registered_by_the_test_0001"));
    let sweeper = Sweeper::new(&set);
    let hits = sweeper.scan("log", b"here: ghs_registered_by_the_test_0001");
    assert!(
        hits.iter()
            .any(|h| h.canary == "minted" && h.kind == CanaryKind::Custom)
    );

    let short = CanarySet::generate_with(&mut FxRng::from_seed(1));
    let short = CanarySet {
        canaries: vec![Canary::custom("tiny", "abc")],
    }
    .with(short.get(CanaryKind::JobToken).clone());
    let sweeper = Sweeper::new(&short);
    assert!(sweeper.scan("log", b"abc abc abc").is_empty());
}

#[test]
fn kinds_round_trip_through_their_template_names() {
    for kind in CanaryKind::GENERATED {
        assert_eq!(CanaryKind::from_name(kind.name()), Some(kind));
    }
    assert_eq!(CanaryKind::from_name("custom"), None);
    assert_eq!(CanaryKind::from_name("nonsense"), None);
}

#[test]
fn the_private_key_header_is_not_spelled_out_in_this_source_tree() {
    // The repository's secret scan flags a private key header. The generator builds it from
    // parts, and this test reads the generator's own source to keep it that way.
    let source = include_str!("../canary.rs");
    let header = format!("{}{}", "-----BEGIN ", "PRIVATE KEY-----");
    assert!(
        !source.contains(&header),
        "canary.rs spells out a private key header"
    );
}
