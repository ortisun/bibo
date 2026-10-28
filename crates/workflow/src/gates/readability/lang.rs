//! Deciding, without a model, that a piece of text is not English.
//!
//! The only language the master prompt names is Portuguese, so that is the one this detector is
//! required to recognise (`deterministic_language_detection` in the catalog). Text in any other
//! language is left to the reviewer, who can only warn.
//!
//! The method is a count of function words. Function words are the short words that every
//! sentence needs (articles, prepositions, pronouns, auxiliaries), so they are frequent in real
//! prose and give little room for a false match. Each word of the text is looked up in two
//! lists, one of Portuguese words that are not also English and one of English words, and a text
//! is Portuguese when the Portuguese points are at least three and beat the English ones.
//!
//! * A word of the Portuguese list is worth two points. A word that is also an English word and
//!   is just as common there (`a`, `as`, `me`) is not counted at all. A word that exists in
//!   English but is far more common in Portuguese (`o`, `os`, `e`, `do`, `no`, `com`) is worth
//!   one point.
//! * A word with `ã`, `õ` or `ç`, which English does not use, is worth two points. A word with
//!   another accent is worth one.
//! * An English function word is worth two points against.
//!
//! Three points mean that one sentence needs either two Portuguese function words or a word with
//! a Portuguese letter and a function word. One loan word such as `coyote time` or a name such
//! as `Selic` does not reach three. The method uses no clock, no file and no randomness, so the
//! same text always gets the same answer. The corpus is the specification at the boundary.

/// Portuguese words that English does not use.
fn portuguese_strong(word: &str) -> bool {
    matches!(
        word,
        "de" | "da"
            | "das"
            | "dos"
            | "em"
            | "um"
            | "uma"
            | "uns"
            | "umas"
            | "para"
            | "por"
            | "pelo"
            | "pela"
            | "pelos"
            | "pelas"
            | "que"
            | "quem"
            | "qual"
            | "quais"
            | "quando"
            | "onde"
            | "como"
            | "porque"
            | "não"
            | "nao"
            | "nem"
            | "mas"
            | "mais"
            | "menos"
            | "muito"
            | "muita"
            | "muitos"
            | "muitas"
            | "também"
            | "já"
            | "ainda"
            | "só"
            | "ele"
            | "ela"
            | "eles"
            | "elas"
            | "nós"
            | "você"
            | "vocês"
            | "eu"
            | "meu"
            | "minha"
            | "meus"
            | "minhas"
            | "seu"
            | "sua"
            | "seus"
            | "suas"
            | "nosso"
            | "nossa"
            | "isso"
            | "isto"
            | "esse"
            | "essa"
            | "esses"
            | "essas"
            | "este"
            | "esta"
            | "estes"
            | "estas"
            | "aquele"
            | "aquela"
            | "ao"
            | "aos"
            | "à"
            | "às"
            | "na"
            | "nas"
            | "nos"
            | "num"
            | "numa"
            | "deve"
            | "devem"
            | "deverá"
            | "deveria"
            | "precisa"
            | "precisam"
            | "quero"
            | "quer"
            | "pode"
            | "podem"
            | "são"
            | "está"
            | "estão"
            | "foi"
            | "foram"
            | "ser"
            | "sido"
            | "tem"
            | "têm"
            | "há"
            | "sem"
            | "sobre"
            | "entre"
            | "depois"
            | "antes"
            | "até"
            | "após"
            | "durante"
            | "mesmo"
            | "mesma"
            | "cada"
            | "todo"
            | "toda"
            | "todos"
            | "todas"
            | "outro"
            | "outra"
            | "outros"
            | "outras"
            | "apenas"
            | "somente"
            | "sempre"
            | "nunca"
            | "aqui"
            | "lá"
            | "então"
            | "porém"
            | "contudo"
            | "enquanto"
            | "ou"
            | "se"
            | "seja"
            | "sejam"
            | "usem"
            | "pra"
    )
}

/// Portuguese words that are much more common in Portuguese than in English, but exist in both.
fn portuguese_weak(word: &str) -> bool {
    matches!(word, "o" | "os" | "e" | "do" | "no" | "com")
}

/// English function words.
fn english_strong(word: &str) -> bool {
    matches!(
        word,
        "the"
            | "and"
            | "of"
            | "to"
            | "is"
            | "are"
            | "was"
            | "were"
            | "be"
            | "been"
            | "with"
            | "for"
            | "that"
            | "this"
            | "these"
            | "those"
            | "which"
            | "when"
            | "will"
            | "would"
            | "must"
            | "should"
            | "can"
            | "could"
            | "not"
            | "or"
            | "if"
            | "but"
            | "we"
            | "you"
            | "they"
            | "it"
            | "its"
            | "from"
            | "into"
            | "after"
            | "before"
            | "than"
            | "then"
            | "there"
            | "their"
            | "each"
            | "every"
            | "has"
            | "have"
            | "had"
            | "does"
            | "did"
            | "in"
            | "on"
            | "at"
            | "by"
            | "an"
            | "i"
            | "my"
            | "your"
            | "our"
            | "also"
            | "only"
            | "any"
            | "all"
    )
}

/// Points for Portuguese and for English in one word, which is already in lower case and has no
/// punctuation around it.
fn points(word: &str) -> (u32, u32) {
    let accent = if word.contains(['ã', 'õ', 'ç']) {
        2
    } else if word.contains(['á', 'é', 'í', 'ó', 'ú', 'â', 'ê', 'ô', 'à']) {
        1
    } else {
        0
    };
    let listed = if portuguese_strong(word) {
        2
    } else {
        u32::from(portuguese_weak(word))
    };
    (listed.max(accent), if english_strong(word) { 2 } else { 0 })
}

/// True when the text is Portuguese by the count of function words.
pub(super) fn is_portuguese(text: &str) -> bool {
    let (mut portuguese, mut english) = (0_u32, 0_u32);
    for token in text.split_whitespace() {
        let word = token
            .trim_matches(|c: char| !c.is_alphanumeric())
            .to_lowercase();
        let (pt, en) = points(&word);
        portuguese = portuguese.saturating_add(pt);
        english = english.saturating_add(en);
    }
    portuguese >= 3 && portuguese > english
}

#[cfg(test)]
mod tests {
    use super::is_portuguese;

    #[test]
    fn portuguese_sentences_are_recognised() {
        for text in [
            "O jogo deve salvar o progresso do jogador mesmo sem conexão.",
            "Corrigir movimento do personagem em rampas",
            "Quando o personagem sobe uma rampa suave, ele perde velocidade.",
            "Quem esquece a senha hoje precisa falar com o suporte.",
        ] {
            assert!(is_portuguese(text), "{text}");
        }
    }

    #[test]
    fn english_sentences_and_loan_words_are_not() {
        for text in [
            "The importer must reject files larger than 10 MB.",
            "Keep the names IPCA and Selic as they are, because they are the terms the team uses.",
            "Use the same coyote time of 0.1 seconds.",
            "Do not touch the movement of the enemies in the app.",
            "",
        ] {
            assert!(!is_portuguese(text), "{text}");
        }
    }
}
