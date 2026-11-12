//! Tests of the JUnit XML reader.
//!
//! The four samples below are HAND-WRITTEN from knowledge of what pytest, jest-junit,
//! go-junit-report and Maven Surefire write. They were NOT recorded from those tools, which do
//! not run in this repository's test environment. They show that the reader accepts the shape
//! each tool is known to produce, and they prove nothing about a particular version of a tool.

use super::*;
use proptest::prelude::*;

/// Hand-written in the shape of `pytest --junitxml`. NOT recorded from pytest.
const PYTEST: &str = r#"<?xml version="1.0" encoding="utf-8"?><testsuites><testsuite name="pytest" errors="0" failures="1" skipped="1" tests="4" time="0.052" timestamp="2026-11-11T09:12:44.512345+00:00" hostname="verify"><testcase classname="tests.test_word_count" name="test_fr_001_counts_a_line" time="0.001" /><testcase classname="tests.test_word_count" name="test_counts_words[one two-2]" time="0.001" /><testcase classname="tests.test_word_count" name="test_fr_002_empty_input" time="0.002"><failure message="assert 1 == 0&#10; +  where 1 = count(&apos;&apos;)">def test_fr_002_empty_input():
&gt;       assert count("") == 0
E       assert 1 == 0
E        +  where 1 = count('')

tests/test_word_count.py:14: AssertionError</failure></testcase><testcase classname="tests.test_word_count" name="test_slow_file" time="0.000"><skipped type="pytest.skip" message="needs a large file">/workspace/tests/test_word_count.py:18: needs a large file</skipped></testcase></testsuite></testsuites>
"#;

/// Hand-written in the shape of jest-junit with its default templates. NOT recorded from Jest.
const JEST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="jest tests" tests="4" failures="1" errors="0" time="1.234">
  <testsuite name="word count" errors="0" failures="1" skipped="1" timestamp="2026-11-11T09:12:44" time="0.812" tests="3">
    <testcase classname="word count FR-001 counts a line" name="word count FR-001 counts a line" time="0.003">
    </testcase>
    <testcase classname="word count counts nothing" name="word count counts nothing" time="0.004">
      <failure>Error: expect(received).toBe(expected) // Object.is equality

Expected: 0
Received: 1
    at Object.&lt;anonymous&gt; (/workspace/test/count.test.js:12:23)</failure>
    </testcase>
    <testcase classname="word count reads a large file" name="word count reads a large file" time="0">
      <skipped/>
    </testcase>
  </testsuite>
  <testsuite name="command line" errors="0" failures="0" skipped="0" timestamp="2026-11-11T09:12:45" time="0.401" tests="1">
    <testcase classname="command line prints the count" name="command line prints the count" time="0.021">
    </testcase>
  </testsuite>
</testsuites>
"#;

/// Hand-written in the shape of go-junit-report version 2. NOT recorded from the tool.
const GO: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites tests=\"5\" failures=\"2\" skipped=\"1\">\n\t<testsuite name=\"example.com/wordcount\" tests=\"5\" failures=\"2\" errors=\"0\" id=\"0\" hostname=\"verify\" skipped=\"1\" time=\"0.005\" timestamp=\"2026-11-11T09:12:44Z\">\n\t\t<properties>\n\t\t\t<property name=\"go.version\" value=\"go1.25.3 linux/arm64\"></property>\n\t\t</properties>\n\t\t<testcase name=\"TestFR_001_CountsALine\" classname=\"example.com/wordcount\" time=\"0.000\"></testcase>\n\t\t<testcase name=\"TestCount\" classname=\"example.com/wordcount\" time=\"0.000\">\n\t\t\t<failure message=\"Failed\"></failure>\n\t\t</testcase>\n\t\t<testcase name=\"TestCount/one_word\" classname=\"example.com/wordcount\" time=\"0.000\"></testcase>\n\t\t<testcase name=\"TestCount/empty_input\" classname=\"example.com/wordcount\" time=\"0.000\">\n\t\t\t<failure message=\"Failed\"><![CDATA[    count_test.go:21: count(\"\") = 1, want 0]]></failure>\n\t\t</testcase>\n\t\t<testcase name=\"TestLargeFile\" classname=\"example.com/wordcount\" time=\"0.000\">\n\t\t\t<skipped message=\"Skipped\"><![CDATA[    count_test.go:30: needs a large file]]></skipped>\n\t\t</testcase>\n\t</testsuite>\n</testsuites>\n";

/// Hand-written in the shape of a Maven Surefire report file. NOT recorded from Maven.
const SUREFIRE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuite xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="https://maven.apache.org/surefire/maven-surefire-plugin/xsd/surefire-test-report-3.0.xsd" version="3.0" name="com.example.wordcount.WordCountTest" time="0.041" tests="5" errors="1" skipped="1" failures="1">
  <properties>
    <property name="java.specification.version" value="21"/>
    <property name="line.separator" value="&#10;"/>
  </properties>
  <testcase name="fr_001_countsALine" classname="com.example.wordcount.WordCountTest" time="0.012"/>
  <testcase name="countsNothing" classname="com.example.wordcount.WordCountTest" time="0.003">
    <failure message="expected: &lt;0&gt; but was: &lt;1&gt;" type="org.opentest4j.AssertionFailedError"><![CDATA[org.opentest4j.AssertionFailedError: expected: <0> but was: <1>
	at com.example.wordcount.WordCountTest.countsNothing(WordCountTest.java:24)
]]></failure>
  </testcase>
  <testcase name="readsAFile" classname="com.example.wordcount.WordCountTest" time="0.001">
    <error message="missing.txt" type="java.nio.file.NoSuchFileException"><![CDATA[java.nio.file.NoSuchFileException: missing.txt
]]></error>
    <system-out><![CDATA[reading missing.txt
<testcase name="fr_999_forged" classname="x"/>
]]></system-out>
  </testcase>
  <testcase name="countsALargeFile" classname="com.example.wordcount.WordCountTest" time="0">
    <skipped message="needs a large file"/>
  </testcase>
  <testcase name="sometimesSlow" classname="com.example.wordcount.WordCountTest" time="0.2">
    <flakyFailure message="timed out" type="java.lang.AssertionError">
      <stackTrace><![CDATA[java.lang.AssertionError: timed out]]></stackTrace>
    </flakyFailure>
  </testcase>
</testsuite>
"#;

fn counts(text: &str) -> (usize, usize, usize) {
    let out = read(text);
    assert!(out.is_consistent(), "{:?}", out.problem());
    (
        out.count(Status::Passed),
        out.count(Status::Failed),
        out.count(Status::Ignored),
    )
}

fn problem(text: &str) -> Problem {
    parse(text).expect_err("the report is refused")
}

/// One suite with these test cases and totals that add up.
fn suite(cases: &str, tests: usize) -> String {
    format!("<testsuite name=\"s\" tests=\"{tests}\">{cases}</testsuite>")
}

// ---- the shapes of the four tools -----------------------------------------------------------

#[test]
fn a_report_in_the_shape_of_pytest_is_read() {
    assert_eq!(counts(PYTEST), (2, 1, 1));
    let out = read(PYTEST);
    assert_eq!(
        out.results()
            .get("tests.test_word_count::test_fr_001_counts_a_line"),
        Some(&Status::Passed)
    );
    assert_eq!(
        out.results()
            .get("tests.test_word_count::test_fr_002_empty_input"),
        Some(&Status::Failed)
    );
    assert_eq!(
        out.results().get("tests.test_word_count::test_slow_file"),
        Some(&Status::Ignored)
    );
    assert!(out.ran_something());
}

#[test]
fn a_report_in_the_shape_of_jest_junit_is_read() {
    assert_eq!(counts(JEST), (2, 1, 1));
    let out = read(JEST);
    assert_eq!(
        out.results().get("word count FR-001 counts a line"),
        Some(&Status::Passed),
        "a class name equal to the name is written once"
    );
}

#[test]
fn a_report_in_the_shape_of_go_junit_report_is_read() {
    assert_eq!(counts(GO), (2, 2, 1));
    let out = read(GO);
    assert_eq!(
        out.results()
            .get("example.com/wordcount::TestCount/empty_input"),
        Some(&Status::Failed)
    );
}

#[test]
fn a_report_in_the_shape_of_surefire_is_read() {
    assert_eq!(counts(SUREFIRE), (2, 2, 1));
    let out = read(SUREFIRE);
    assert_eq!(
        out.results()
            .get("com.example.wordcount.WordCountTest::readsAFile"),
        Some(&Status::Failed),
        "an error is a failed test"
    );
    assert_eq!(
        out.results()
            .get("com.example.wordcount.WordCountTest::sometimesSlow"),
        Some(&Status::Passed),
        "a flaky failure that passed on a rerun is not a failure child"
    );
    assert!(
        !out.results().keys().any(|id| id.contains("forged")),
        "a test case written inside captured output is text"
    );
}

// ---- what a test case is ---------------------------------------------------------------------

#[test]
fn a_test_case_is_named_by_its_class_name_and_its_name() {
    let text = suite(
        "<testcase classname='a.B' name='one'/><testcase name='two'/><testcase classname='' name='three'/><testcase classname=' same ' name='same'/>",
        4,
    );
    let out = read(&text);
    assert!(out.is_consistent(), "{:?}", out.problem());
    assert_eq!(
        out.ids(Status::Passed),
        ["a.B::one", "same", "three", "two"]
    );
}

#[test]
fn references_in_a_name_are_replaced_and_control_characters_become_spaces() {
    let text = suite(
        "<testcase classname=\"a&amp;b\" name=\"x &lt;1&gt; &#65;&#x42;&#10;&quot;q&quot; &apos;s&apos;\"/>",
        1,
    );
    let out = read(&text);
    assert_eq!(out.ids(Status::Passed), ["a&b::x <1> AB \"q\" 's'"]);
}

#[test]
fn a_report_with_no_test_case_or_only_skipped_ones_shows_nothing_ran() {
    let none = read("<testsuites></testsuites>");
    assert!(none.is_consistent());
    assert!(!none.ran_something());
    let empty_suite = read("<testsuite name='s' tests='0'/>");
    assert!(empty_suite.is_consistent());
    assert!(!empty_suite.ran_something());
    let skipped = read(&suite("<testcase name='a'><skipped/></testcase>", 1));
    assert!(skipped.is_consistent());
    assert!(!skipped.ran_something());
}

#[test]
fn nested_suites_may_count_their_own_cases_or_all_the_cases_below_them() {
    let inner = "<testsuite name='in' tests='2' failures='1'><testcase name='b'/><testcase name='c'><failure/></testcase></testsuite>";
    let own = format!(
        "<testsuite name='out' tests='1' failures='0'><testcase name='a'/>{inner}</testsuite>"
    );
    assert_eq!(counts(&own), (2, 1, 0));
    let all = format!(
        "<testsuite name='out' tests='3' failures='1'><testcase name='a'/>{inner}</testsuite>"
    );
    assert_eq!(counts(&all), (2, 1, 0));
    let neither = format!(
        "<testsuite name='out' tests='2' failures='1'><testcase name='a'/>{inner}</testsuite>"
    );
    assert_eq!(problem(&neither), Problem::Totals);
}

// ---- reports that are refused ----------------------------------------------------------------

#[test]
fn an_empty_report_is_refused() {
    for text in [
        "",
        "  \n\t",
        "\u{feff}",
        "<!-- nothing -->",
        "<?xml version=\"1.0\"?>\n",
    ] {
        assert_eq!(problem(text), Problem::Empty, "{text:?}");
    }
}

#[test]
fn a_truncated_report_is_refused_wherever_it_is_cut() {
    for end in 1..PYTEST.trim_end().len() {
        if !PYTEST.is_char_boundary(end) {
            continue;
        }
        let cut = &PYTEST[..end];
        assert!(
            parse(cut).is_err(),
            "the report cut after {end} bytes was accepted"
        );
    }
    assert_eq!(
        problem("<testsuite name='s' tests='1'><testcase name='a'/>"),
        Problem::Truncated
    );
    assert_eq!(
        problem("<testsuite name='s' tests='1'><testcase name='a"),
        Problem::Truncated
    );
    assert_eq!(
        problem("<testsuite name='s' tests='0'><!-- open"),
        Problem::Truncated
    );
    assert_eq!(
        problem("<testsuite name='s' tests='0'><system-out><![CDATA[open"),
        Problem::Truncated
    );
}

#[test]
fn malformed_xml_is_refused() {
    for text in [
        "not xml at all",
        "<testsuite name='s' tests='0'></testsuites>",
        "<testsuite name='s' tests='0'></testsuite></testsuite>",
        "<testsuite name='s' tests='0'/><testsuite name='t' tests='0'/>",
        "<testsuite name='s' tests='0'/> trailing text",
        "leading text <testsuite name='s' tests='0'/>",
        "<testsuite name='s' name='t' tests='0'/>",
        "<testsuite name=s tests='0'/>",
        "<testsuite name='s'tests='0'/>",
        "<testsuite name='a<b' tests='0'/>",
        "<testsuite tests='0'>< testcase/></testsuite>",
        "<testsuite tests='0'><1x/></testsuite>",
        "<testsuite tests='0'></ testsuite>",
        "<![CDATA[x]]><testsuite tests='0'/>",
    ] {
        assert_eq!(problem(text), Problem::Malformed, "{text}");
    }
}

#[test]
fn a_document_type_an_entity_declaration_and_a_processing_instruction_are_refused() {
    let billion_laughs = "<?xml version=\"1.0\"?>\n<!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;\">]>\n<testsuite name='&lol2;' tests='0'/>";
    assert_eq!(problem(billion_laughs), Problem::Declaration);
    let external = "<!DOCTYPE x [<!ENTITY xxe SYSTEM \"file:///run/factory/job-token\">]><testsuite name='&xxe;' tests='0'/>";
    assert_eq!(problem(external), Problem::Declaration);
    assert_eq!(
        problem("<testsuite tests='0'><?php echo 1 ?></testsuite>"),
        Problem::Declaration
    );
    assert_eq!(
        problem("<!-- c --><?xml version=\"1.0\"?><testsuite tests='0'/>"),
        Problem::Declaration,
        "the XML declaration is accepted only as the very first thing"
    );
    assert_eq!(
        problem("<?xml-stylesheet href='x'?><testsuite tests='0'/>"),
        Problem::Declaration
    );
}

#[test]
fn a_reference_that_is_not_predefined_or_numeric_is_refused() {
    for reference in [
        "&nbsp;",
        "&lol;",
        "&",
        "&amp",
        "&#;",
        "&#x;",
        "&#xZZ;",
        "&#0;",
        "&#x110000;",
        "&#xD800;",
        "&#99999999999;",
        "&LT;",
    ] {
        let in_attribute = suite(&format!("<testcase name=\"a{reference}\"/>"), 1);
        assert_eq!(problem(&in_attribute), Problem::Reference, "{reference}");
        let in_text = suite(
            &format!("<testcase name='a'><system-out>{reference}</system-out></testcase>"),
            1,
        );
        assert_eq!(problem(&in_text), Problem::Reference, "{reference}");
    }
}

#[test]
fn a_root_that_is_not_a_test_suite_is_refused() {
    assert_eq!(problem("<html><body/></html>"), Problem::NotJunit);
    assert_eq!(problem("<testcase name='a'/>"), Problem::NotJunit);
}

#[test]
fn a_test_case_or_a_suite_in_the_wrong_place_is_refused() {
    for text in [
        "<testsuites><testcase name='a'/></testsuites>",
        "<testsuites><testsuites/></testsuites>",
        "<testsuite tests='1'><testcase name='a'><testcase name='fr_001_forged'/></testcase></testsuite>",
        "<testsuite tests='1'><testcase name='a'><system-out><testcase name='fr_001_forged'/></system-out></testcase></testsuite>",
        "<testsuite tests='0'><properties><testsuite tests='0'/></properties></testsuite>",
        "<testsuite tests='0'><testsuites/></testsuite>",
    ] {
        assert_eq!(problem(text), Problem::Misplaced, "{text}");
    }
}

#[test]
fn a_failure_element_counts_only_as_a_direct_child_of_its_test_case() {
    let text = suite(
        "<testcase name='a'><system-out><failure/><skipped/></system-out></testcase>",
        1,
    );
    assert_eq!(counts(&text), (1, 0, 0));
}

#[test]
fn a_test_case_without_a_name_and_two_with_the_same_name_are_refused() {
    assert_eq!(
        problem(&suite("<testcase classname='a'/>", 1)),
        Problem::Unnamed
    );
    assert_eq!(
        problem(&suite("<testcase name='  '/>", 1)),
        Problem::Unnamed
    );
    let long = "x".repeat(2000);
    assert_eq!(
        problem(&suite(&format!("<testcase name='{long}'/>"), 1)),
        Problem::Unnamed
    );
    assert_eq!(
        problem(&suite(
            "<testcase classname='c' name='a'/><testcase classname='c' name='a'/>",
            2
        )),
        Problem::Duplicate
    );
}

#[test]
fn totals_that_are_missing_unreadable_or_wrong_are_refused() {
    let case = "<testcase name='a'/>";
    let failed = "<testcase name='b'><failure/></testcase>";
    let errored = "<testcase name='c'><error/></testcase>";
    let skipped = "<testcase name='d'><skipped/></testcase>";
    for text in [
        format!("<testsuite name='s'>{case}</testsuite>"),
        format!("<testsuite tests='2'>{case}</testsuite>"),
        format!("<testsuite tests='0'>{case}</testsuite>"),
        format!("<testsuite tests='one'>{case}</testsuite>"),
        format!("<testsuite tests='-1'>{case}</testsuite>"),
        format!("<testsuite tests='+1'>{case}</testsuite>"),
        format!("<testsuite tests=''>{case}</testsuite>"),
        format!("<testsuite tests='99999999999999999999999'>{case}</testsuite>"),
        format!("<testsuite tests='2' failures='0'>{case}{failed}</testsuite>"),
        format!("<testsuite tests='2' failures='2'>{case}{failed}</testsuite>"),
        format!("<testsuite tests='2' errors='0'>{case}{errored}</testsuite>"),
        format!("<testsuite tests='2' failures='1'>{case}{errored}</testsuite>"),
        format!("<testsuite tests='2' skipped='0'>{case}{skipped}</testsuite>"),
        format!("<testsuite tests='1' skipped='1'>{case}</testsuite>"),
        format!("<testsuites tests='7'><testsuite tests='1'>{case}</testsuite></testsuites>"),
        format!("<testsuites failures='1'><testsuite tests='1'>{case}</testsuite></testsuites>"),
        "<testsuite tests='0' errors='1'></testsuite>".to_owned(),
    ] {
        assert_eq!(problem(&text), Problem::Totals, "{text}");
    }
    let good = format!(
        "<testsuites tests='4' failures='1' errors='1'><testsuite tests='4' failures='1' errors='1' skipped='1'>{case}{failed}{errored}{skipped}</testsuite></testsuites>"
    );
    assert_eq!(counts(&good), (1, 2, 1));
}

#[test]
fn the_bounds_on_size_depth_and_number_of_cases_hold() {
    let large = format!(
        "<testsuite tests='0'><system-out>{}</system-out></testsuite>",
        "x".repeat(MAX_BYTES)
    );
    assert_eq!(problem(&large), Problem::TooLarge);

    let deep = format!(
        "<testsuite tests='0'>{}{}</testsuite>",
        "<a>".repeat(MAX_DEPTH),
        "</a>".repeat(MAX_DEPTH)
    );
    assert_eq!(problem(&deep), Problem::TooDeep);
    let deep_enough = format!(
        "<testsuite tests='0'>{}{}</testsuite>",
        "<a>".repeat(MAX_DEPTH - 1),
        "</a>".repeat(MAX_DEPTH - 1)
    );
    assert_eq!(counts(&deep_enough), (0, 0, 0));

    let mut many = String::with_capacity(40 * (MAX_CASES + 1));
    for index in 0..=MAX_CASES {
        many.push_str(&format!("<testcase name='t{index}'/>"));
    }
    assert_eq!(problem(&suite(&many, MAX_CASES + 1)), Problem::TooManyCases);

    let attributes: String = (0..=MAX_ATTRIBUTES).map(|n| format!(" a{n}='x'")).collect();
    assert_eq!(
        problem(&format!("<testsuite tests='0'{attributes}/>")),
        Problem::Malformed
    );
}

#[test]
fn every_problem_has_its_own_sentence() {
    let all = [
        Problem::Empty,
        Problem::TooLarge,
        Problem::Truncated,
        Problem::Malformed,
        Problem::Declaration,
        Problem::Reference,
        Problem::TooDeep,
        Problem::TooManyCases,
        Problem::NotJunit,
        Problem::Misplaced,
        Problem::Unnamed,
        Problem::Duplicate,
        Problem::Totals,
    ];
    let sentences: std::collections::BTreeSet<&str> =
        all.iter().map(|problem| problem.sentence()).collect();
    assert_eq!(sentences.len(), all.len());
    assert_eq!(
        read("").problem(),
        Some(Problem::Empty.sentence()),
        "a refused report carries the sentence"
    );
}

// ---- properties ------------------------------------------------------------------------------

/// Text that looks like pieces of a JUnit report, to reach deeper than random bytes do.
fn xml_piece() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("<testsuites>".to_owned()),
        Just("</testsuites>".to_owned()),
        Just("<testsuite tests='1'>".to_owned()),
        Just("<testsuite".to_owned()),
        Just("</testsuite>".to_owned()),
        Just("<testcase name='a'>".to_owned()),
        Just("<testcase name='b'/>".to_owned()),
        Just("</testcase>".to_owned()),
        Just("<failure/>".to_owned()),
        Just("<skipped>".to_owned()),
        Just("<![CDATA[".to_owned()),
        Just("]]>".to_owned()),
        Just("<!--".to_owned()),
        Just("-->".to_owned()),
        Just("<?xml version='1.0'?>".to_owned()),
        Just("<!DOCTYPE x>".to_owned()),
        Just("&amp;".to_owned()),
        Just("&#x".to_owned()),
        Just("&".to_owned()),
        Just(";".to_owned()),
        Just("<".to_owned()),
        Just(">".to_owned()),
        Just("/>".to_owned()),
        Just("</".to_owned()),
        Just("='".to_owned()),
        Just("\"".to_owned()),
        Just(" tests=\"2\"".to_owned()),
        Just(" ".to_owned()),
        "\\PC{0,8}",
    ]
}

/// One generated test case: how it ended (0 passed, 1 failed, 2 error, 3 skipped) and a name
/// with characters that must be escaped.
fn generated_case() -> impl Strategy<Value = (u8, String)> {
    (0u8..4, "[a-zA-Z0-9_ <>&'\"\\[\\]é-]{0,12}")
}

fn escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

proptest! {
    #[test]
    fn arbitrary_bytes_never_make_the_reader_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let text = String::from_utf8_lossy(&bytes);
        let out = read(&text);
        prop_assert_eq!(out.is_consistent(), out.problem().is_none());
    }

    #[test]
    fn text_made_of_xml_pieces_never_makes_the_reader_panic(pieces in proptest::collection::vec(xml_piece(), 0..40)) {
        let _ = read(&pieces.concat());
    }

    #[test]
    fn a_real_shaped_report_with_one_byte_changed_never_makes_the_reader_panic(
        at in 0usize..SUREFIRE.len(),
        byte in any::<u8>(),
    ) {
        let mut bytes = SUREFIRE.as_bytes().to_vec();
        bytes[at] = byte;
        let _ = read(&String::from_utf8_lossy(&bytes));
    }

    #[test]
    fn a_generated_report_reads_back_with_the_counts_it_was_made_from(
        suites in proptest::collection::vec(proptest::collection::vec(generated_case(), 0..8), 0..5),
        with_root in any::<bool>(),
    ) {
        let (mut passed, mut failed, mut ignored) = (0usize, 0usize, 0usize);
        let mut body = String::new();
        let mut total = 0usize;
        for (suite_index, cases) in suites.iter().enumerate() {
            let (mut failures, mut errors, mut skips) = (0, 0, 0);
            let mut listed = String::new();
            for (case_index, (kind, name)) in cases.iter().enumerate() {
                let child = match kind {
                    0 => { passed += 1; "" }
                    1 => { failed += 1; failures += 1; "<failure message=\"no\">a &lt; b</failure>" }
                    2 => { failed += 1; errors += 1; "<error><![CDATA[<testcase name='x'/>]]></error>" }
                    _ => { ignored += 1; skips += 1; "<skipped/>" }
                };
                listed.push_str(&format!(
                    "<testcase classname=\"suite{suite_index}.Class\" name=\"case{case_index} {}\" time=\"0.1\">{child}<system-out>printed &amp; escaped</system-out></testcase>\n",
                    escaped(name)
                ));
            }
            total += cases.len();
            body.push_str(&format!(
                "<testsuite name=\"suite{suite_index}\" tests=\"{}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skips}\">\n<properties><property name=\"k\" value=\"v\"/></properties>\n{listed}</testsuite>\n",
                cases.len()
            ));
        }
        let text = if with_root || suites.len() != 1 {
            format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites tests=\"{total}\">\n{body}</testsuites>\n")
        } else {
            body
        };
        prop_assert_eq!(counts(&text), (passed, failed, ignored));
    }
}
