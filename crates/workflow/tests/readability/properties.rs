//! Properties of the gate over generated text: it never panics, it gives the same answer twice,
//! quoted and code text is exempt, and a title it accepts is a title the schema accepts.

use factory_domain::values::HumanTitle;
use factory_workflow::gates::readability::{
    Artifact, Catalog, DocumentType, Finding, Options, ReadabilityGate, ReviewerPolicy, RuleId,
    Severity, check,
};
use proptest::prelude::*;

use super::readability_gate_tests::context;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 256,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Pieces that the rules look for, so that random combinations reach every rule.
const FRAGMENTS: &[&str] = &[
    "`",
    "``",
    "```",
    "\n",
    "\r\n",
    "\n\n",
    "[",
    "]",
    "](",
    "(",
    ")",
    "\"",
    "\u{201c}",
    "\u{201d}",
    "|",
    "#",
    "## ",
    "> ",
    "- ",
    "1. ",
    "**",
    "http://x.y/z",
    "https://",
    "AB",
    "DCF",
    "WACC",
    "feat(x): ",
    "WI-1: ",
    "T-028 | ",
    "[AGENT:X]",
    "AGENT-",
    "Retries: 2",
    "Assigned agent: x",
    "0198f3c2-7a41-7c3e-9b0d-2f6a8e4c1d55",
    "O jogo deve salvar o progresso",
    "The game must",
    "Why this matters",
    "Verification",
    "Acceptance criteria",
    "What needs to change",
    "Great news",
    "feel free to",
    "é",
    "ã",
    "ç",
    " ",
    "  ",
    "\t",
    "\u{0}",
    "\u{feff}",
    "\u{2028}",
    "\u{85}",
    "😀",
    ".",
    "!",
    "?",
    ":",
    ";",
    ",",
    "…",
    "'",
    "’",
    "s",
    "a",
    "word",
    "Word",
    "WORD",
    "Fix",
    "stuff",
    "part 3",
    "file A",
    "Agent task complete",
];

fn hostile() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => proptest::collection::vec(proptest::sample::select(FRAGMENTS), 0..60)
            .prop_map(|parts| parts.concat()),
        1 => any::<String>(),
        1 => proptest::collection::vec(any::<char>(), 0..400).prop_map(|c| c.into_iter().collect()),
    ]
}

fn doc_type() -> impl Strategy<Value = Option<DocumentType>> {
    proptest::sample::select(vec![
        None,
        Some(DocumentType::HowTo),
        Some(DocumentType::Tutorial),
        Some(DocumentType::Reference),
        Some(DocumentType::Explanation),
        Some(DocumentType::Adr),
        Some(DocumentType::Changelog),
    ])
}

fn artifacts<'a>(title: &'a str, body: &'a str, doc: Option<DocumentType>) -> Vec<Artifact<'a>> {
    let mut all = vec![
        Artifact::title(title),
        Artifact::request(title, body),
        Artifact::task(title, body),
        Artifact::pull_request(title, body),
    ];
    if let Some(doc) = doc {
        all.push(Artifact::documentation(title, doc, body));
    }
    all
}

fn is_blocking_title_rule(finding: &Finding) -> bool {
    finding.severity == Severity::Block
        && matches!(
            finding.rule,
            RuleId::TitleSchemaShape
                | RuleId::TitleOpaquePrefix
                | RuleId::TitleMachineLabel
                | RuleId::TitleVague
        )
}

proptest! {
    #![proptest_config(config())]

    /// Total and panic-free on hostile input, and the report is always a valid one.
    #[test]
    fn readability_never_panics_and_always_reports(
        title in hostile(),
        body in hostile(),
        doc in doc_type(),
    ) {
        let gate = ReadabilityGate::new(Options::new());
        let ctx = context(ReviewerPolicy::Optional);
        let list = artifacts(&title, &body, doc);
        let report = gate.evaluate(&list, &ctx);
        prop_assert!(report.is_ok(), "{report:?}");
        // A rule gives at most one finding for each artifact, so a report cannot grow with the text.
        let catalog = Catalog::embedded().unwrap();
        let findings = check(&catalog, &Options::new(), &list).unwrap();
        prop_assert!(findings.len() <= RuleId::ALL.len() * list.len());
    }

    /// The same text gets the same findings and the same report.
    #[test]
    fn readability_is_idempotent(title in hostile(), body in hostile(), doc in doc_type()) {
        let catalog = Catalog::embedded().unwrap();
        let options = Options::new();
        let list = artifacts(&title, &body, doc);
        let first = check(&catalog, &options, &list).unwrap();
        let second = check(&catalog, &options, &list).unwrap();
        prop_assert_eq!(&first, &second);
        let gate = ReadabilityGate::new(options);
        let ctx = context(ReviewerPolicy::Optional);
        prop_assert_eq!(
            gate.evaluate(&list, &ctx).unwrap(),
            gate.evaluate(&list, &ctx).unwrap()
        );
        // The text is only borrowed, so it is what it was.
        prop_assert_eq!(list[0].title_text(), title.as_str());
        prop_assert_eq!(list[1].body_text(), body.as_str());
    }

    /// Portuguese inside quotation marks, a block quotation, inline code or a fence is exempt from
    /// the English check, whatever English surrounds it.
    #[test]
    fn english_check_exempts_quoted_and_code_text(
        sentence in proptest::sample::select(vec![
            "O jogo deve salvar o progresso do jogador mesmo sem conexão",
            "Quando a conexão voltar o progresso salvo deve ser enviado ao servidor",
            "Quem esquece a senha hoje precisa falar com o suporte",
            "O importador deve mostrar uma mensagem clara quando o arquivo for rejeitado",
        ]),
        wrapper in 0_usize..4,
        before in proptest::sample::select(vec![
            "The label stays as the requester wrote it.",
            "Keep the text of the next line as it is.",
            "",
        ]),
        after in proptest::sample::select(vec![
            "That is all the change needs.",
            "The rest of the screen is unchanged.",
            "",
        ]),
    ) {
        let wrapped = match wrapper {
            0 => format!("{before} The text is \"{sentence}\" in the source. {after}"),
            1 => format!("{before}\n\n> {sentence}.\n\n{after}"),
            2 => format!("{before} The text is `{sentence}` in the source. {after}"),
            _ => format!("{before}\n\n```\n{sentence}.\n```\n\n{after}"),
        };
        let catalog = Catalog::embedded().unwrap();
        let list = [Artifact::request("Keep the label of the save button", &wrapped)];
        let findings = check(&catalog, &Options::new(), &list).unwrap();
        prop_assert!(
            findings.iter().all(|f| f.rule != RuleId::TextNotEnglish),
            "{wrapped:?}: {findings:?}"
        );
        // The same sentence as plain prose is flagged, so the exemption is what made the difference.
        let plain = format!("{before} {sentence}. {after}");
        let list = [Artifact::request("Keep the label of the save button", &plain)];
        let findings = check(&catalog, &Options::new(), &list).unwrap();
        prop_assert!(findings.iter().any(|f| f.rule == RuleId::TextNotEnglish), "{plain:?}");
    }

    /// An abbreviation inside code or quotation marks is not an unexpanded abbreviation.
    #[test]
    fn abbreviation_check_exempts_quoted_and_code_text(
        letters in "[A-Z]{2,5}",
        quoted in proptest::bool::ANY,
    ) {
        let catalog = Catalog::embedded().unwrap();
        let lists = catalog.lists();
        prop_assume!(
            !lists.acronym_allowlist.contains(&letters)
                && !lists.not_abbreviation_words.contains(&letters)
        );
        let marked = if quoted { format!("\"{letters}\"") } else { format!("`{letters}`") };
        let body = format!("The report shows the value called {marked} for each holding.");
        let list = [Artifact::request("Show the value of each holding", &body)];
        let findings = check(&catalog, &Options::new(), &list).unwrap();
        prop_assert!(
            findings.iter().all(|f| f.rule != RuleId::TextAbbreviationUnexpanded),
            "{body:?}"
        );
        let bare = format!("The report shows the value called {letters} for each holding.");
        let list = [Artifact::request("Show the value of each holding", &bare)];
        let findings = check(&catalog, &Options::new(), &list).unwrap();
        prop_assert!(
            findings.iter().any(|f| f.rule == RuleId::TextAbbreviationUnexpanded),
            "{bare:?}"
        );
    }

    /// A title that no blocking title rule refuses is a title the contract schemas accept, so the
    /// gate never lets a title through that schema validation would reject later.
    #[test]
    fn a_title_the_gate_accepts_is_accepted_by_the_schema(title in hostile()) {
        let catalog = Catalog::embedded().unwrap();
        let findings = check(&catalog, &Options::new(), &[Artifact::title(&title)]).unwrap();
        if !findings.iter().any(is_blocking_title_rule) {
            prop_assert!(HumanTitle::parse(&title).is_ok(), "{title:?}");
        }
    }
}

/// Checks one hostile body of the largest size, as a task, a pull request and a how-to guide.
fn finishes_on(unit: &str) {
    let catalog = Catalog::embedded().expect("the catalog loads");
    // A quarter of the limit of one run (1 MiB). A rule that searched again for each of the
    // hundred thousand marks in this text would need ten billion steps and the test would hang.
    let body = unit.repeat((1 << 18) / unit.len().max(1));
    for artifact in [
        Artifact::task("Add password reset support", &body),
        Artifact::pull_request("Add password reset support", &body),
        Artifact::documentation("How the export pages work", DocumentType::HowTo, &body),
    ] {
        let findings = check(&catalog, &Options::new(), &[artifact]).expect("within the limit");
        assert!(findings.len() <= RuleId::ALL.len(), "{unit:?}");
    }
}

/// Hostile text of the largest size finishes. A rule that searched again from the start for each
/// opening mark would take minutes on these, and the test would not return.
macro_rules! hostile {
    ($($name:ident: $unit:expr,)+) => {
        $(
            #[test]
            fn $name() {
                finishes_on($unit);
            }
        )+
    };
}

hostile! {
    readability_hostile_link_openers_finish: "](",
    readability_hostile_open_brackets_finish: "[",
    readability_hostile_close_brackets_finish: "]",
    readability_hostile_double_quotes_finish: "\"",
    readability_hostile_backticks_finish: "`",
    readability_hostile_double_backticks_finish: "``",
    readability_hostile_open_parentheses_finish: "(",
    readability_hostile_url_starts_finish: "http",
    readability_hostile_urls_finish: "https://",
    readability_hostile_abbreviations_finish: "AB (",
    readability_hostile_capitals_finish: "A",
    readability_hostile_uuid_like_text_finish: "0123456789abcdef-",
    readability_hostile_fences_finish: "\n```\n",
    readability_hostile_quote_lines_finish: "\n> ",
    readability_hostile_list_items_finish: "\n- ",
    readability_hostile_sentences_finish: ". ",
    readability_hostile_portuguese_letters_finish: "ã ",
    readability_hostile_words_finish: "x ",
    readability_hostile_pipes_finish: "|",
    readability_hostile_hashes_finish: "#",
    readability_hostile_curly_open_quotes_finish: "\u{201c}",
    readability_hostile_curly_close_quotes_finish: "\u{201d}",
    readability_hostile_code_and_quotes_finish: "`a`\"b\" ",
}

#[test]
fn readability_a_title_of_the_largest_size_finishes() {
    let catalog = Catalog::embedded().expect("the catalog loads");
    let title = "x".repeat((1 << 20) - 128);
    let findings =
        check(&catalog, &Options::new(), &[Artifact::title(&title)]).expect("within the limit");
    assert!(findings.iter().any(|f| f.rule == RuleId::TitleSchemaShape));
}
