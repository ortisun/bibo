//! The license rule for dependencies.
//!
//! The allow list is the owner-approved one in `deny.toml` (`supply_chain.licenses` of the
//! security policy says the list lives there, so there is one place to read it and one place to
//! change it). [`LicensePolicy::owner_approved`] carries a copy, and a test of this package reads
//! `deny.toml` and fails if the two differ.
//!
//! A license that is not on the list is denied, and so is one that is unknown or cannot be read.
//! GPL, LGPL and AGPL are not on the list, so they are denied without a rule of their own. An
//! `OR` expression passes only through an alternative that is on the list, an `AND` expression
//! needs every part on the list, and a `WITH` exception passes only when the whole phrase (such
//! as `Apache-2.0 WITH LLVM-exception`) is on the list. The old `MIT/Apache-2.0` spelling reads
//! as `OR`.

/// The longest expression read.
const MAX_LEN: usize = 256;
/// The deepest nesting of parentheses read.
const MAX_DEPTH: usize = 8;

/// Why a license is not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// No license is declared.
    Unknown,
    /// A license, or a part of the expression, is not on the list.
    NotListed,
    /// The expression cannot be read.
    Unreadable,
}

impl Denial {
    /// A phrase for a message.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Unknown => "declares no license",
            Self::NotListed => "has a license that is not on the allow list",
            Self::Unreadable => "has a license expression that cannot be read",
        }
    }
}

/// The licenses a dependency may have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicensePolicy {
    allowed: Vec<String>,
}

impl LicensePolicy {
    /// The list the owner approved, equal to `licenses.allow` of `deny.toml`.
    #[must_use]
    pub fn owner_approved() -> Self {
        Self::of(&[
            "MIT",
            "Apache-2.0",
            "Unicode-3.0",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "ISC",
            "Zlib",
            "0BSD",
            "CC0-1.0",
            "MIT-0",
            "CDLA-Permissive-2.0",
        ])
    }

    /// A list of the given identifiers.
    #[must_use]
    pub fn of(ids: &[&str]) -> Self {
        Self {
            allowed: ids.iter().map(|id| (*id).to_owned()).collect(),
        }
    }

    /// The identifiers, in the order given.
    #[must_use]
    pub fn allowed(&self) -> &[String] {
        &self.allowed
    }

    /// Judges a license expression. `None` is an unknown license.
    ///
    /// # Errors
    /// The [`Denial`] that says why the license is not accepted.
    pub fn check(&self, expression: Option<&str>) -> Result<(), Denial> {
        let text = expression.map(str::trim).filter(|text| !text.is_empty());
        let Some(text) = text else {
            return Err(Denial::Unknown);
        };
        if text.len() > MAX_LEN {
            return Err(Denial::Unreadable);
        }
        let tokens = tokenize(text).ok_or(Denial::Unreadable)?;
        let mut parser = Parser {
            tokens: &tokens,
            at: 0,
            policy: self,
        };
        let accepted = parser.expression(0)?;
        if parser.at != tokens.len() {
            return Err(Denial::Unreadable);
        }
        if accepted {
            Ok(())
        } else {
            Err(Denial::NotListed)
        }
    }

    fn listed(&self, id: &str) -> bool {
        self.allowed
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(id))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Open,
    Close,
    Or,
    And,
    With,
    Id(String),
}

fn tokenize(text: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut word = String::new();
    let flush = |word: &mut String, tokens: &mut Vec<Token>| {
        if word.is_empty() {
            return;
        }
        let token = match word.to_ascii_uppercase().as_str() {
            "OR" => Token::Or,
            "AND" => Token::And,
            "WITH" => Token::With,
            _ => Token::Id(std::mem::take(word)),
        };
        word.clear();
        tokens.push(token);
    };
    for c in text.chars() {
        match c {
            '(' | ')' | '/' | ' ' | '\t' => {
                flush(&mut word, &mut tokens);
                match c {
                    '(' => tokens.push(Token::Open),
                    ')' => tokens.push(Token::Close),
                    '/' => tokens.push(Token::Or),
                    _ => {}
                }
            }
            c if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | ':') => word.push(c),
            _ => return None,
        }
    }
    flush(&mut word, &mut tokens);
    Some(tokens)
}

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    policy: &'a LicensePolicy,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    /// `term (OR term)*`: true when any alternative is accepted.
    fn expression(&mut self, depth: usize) -> Result<bool, Denial> {
        let mut accepted = self.term(depth)?;
        while self.peek() == Some(&Token::Or) {
            self.at += 1;
            let next = self.term(depth)?;
            accepted = accepted || next;
        }
        Ok(accepted)
    }

    /// `factor (AND factor)*`: true when every part is accepted.
    fn term(&mut self, depth: usize) -> Result<bool, Denial> {
        let mut accepted = self.factor(depth)?;
        while self.peek() == Some(&Token::And) {
            self.at += 1;
            let next = self.factor(depth)?;
            accepted = accepted && next;
        }
        Ok(accepted)
    }

    fn factor(&mut self, depth: usize) -> Result<bool, Denial> {
        match self.tokens.get(self.at) {
            Some(Token::Open) => {
                if depth >= MAX_DEPTH {
                    return Err(Denial::Unreadable);
                }
                self.at += 1;
                let inner = self.expression(depth + 1)?;
                if self.peek() != Some(&Token::Close) {
                    return Err(Denial::Unreadable);
                }
                self.at += 1;
                Ok(inner)
            }
            Some(Token::Id(id)) => {
                let id = id.clone();
                self.at += 1;
                if self.peek() == Some(&Token::With) {
                    self.at += 1;
                    let Some(Token::Id(exception)) = self.tokens.get(self.at) else {
                        return Err(Denial::Unreadable);
                    };
                    let phrase = format!("{id} WITH {exception}");
                    self.at += 1;
                    return Ok(self.policy.listed(&phrase));
                }
                Ok(self.policy.listed(&id))
            }
            _ => Err(Denial::Unreadable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(text: &str) -> Result<(), Denial> {
        LicensePolicy::owner_approved().check(Some(text))
    }

    #[test]
    fn every_listed_license_is_accepted() {
        for id in LicensePolicy::owner_approved().allowed() {
            assert_eq!(check(id), Ok(()), "{id}");
        }
        assert_eq!(
            check("mit"),
            Ok(()),
            "identifiers are compared without regard to case"
        );
    }

    #[test]
    fn licenses_off_the_list_are_denied() {
        for text in [
            "MPL-2.0",
            "GPL-3.0-only",
            "LGPL-2.1-or-later",
            "AGPL-3.0",
            "GPL-2.0+",
            "Apache-1.1",
        ] {
            assert_eq!(check(text), Err(Denial::NotListed), "{text}");
        }
    }

    #[test]
    fn an_unknown_or_missing_license_is_denied() {
        assert_eq!(
            LicensePolicy::owner_approved().check(None),
            Err(Denial::Unknown)
        );
        assert_eq!(
            LicensePolicy::owner_approved().check(Some("  ")),
            Err(Denial::Unknown)
        );
    }

    #[test]
    fn an_or_expression_passes_only_through_an_alternative_on_the_list() {
        assert_eq!(check("MIT OR Apache-2.0"), Ok(()));
        assert_eq!(check("MIT/Apache-2.0"), Ok(()));
        // r-efi: used under MIT or Apache-2.0, never under the LGPL option.
        assert_eq!(check("MIT OR Apache-2.0 OR LGPL-2.1-or-later"), Ok(()));
        assert_eq!(
            check("LGPL-2.1-or-later OR GPL-3.0"),
            Err(Denial::NotListed)
        );
    }

    #[test]
    fn an_and_expression_needs_every_part_on_the_list() {
        assert_eq!(check("MIT AND Unicode-3.0"), Ok(()));
        assert_eq!(check("MIT AND GPL-3.0-only"), Err(Denial::NotListed));
        assert_eq!(check("(MIT OR GPL-3.0) AND ISC"), Ok(()));
        assert_eq!(check("MIT OR (GPL-3.0 AND ISC)"), Ok(()));
        assert_eq!(
            check("GPL-3.0 OR (MPL-2.0 AND ISC)"),
            Err(Denial::NotListed)
        );
    }

    #[test]
    fn an_exception_passes_only_when_the_whole_phrase_is_listed() {
        assert_eq!(
            check("Apache-2.0 WITH LLVM-exception"),
            Err(Denial::NotListed)
        );
        assert_eq!(
            LicensePolicy::of(&["Apache-2.0 WITH LLVM-exception"])
                .check(Some("Apache-2.0 WITH LLVM-exception")),
            Ok(())
        );
        assert_eq!(check("Apache-2.0 WITH LLVM-exception OR MIT"), Ok(()));
    }

    #[test]
    fn an_expression_that_cannot_be_read_is_denied_and_never_accepted() {
        for text in [
            "MIT OR",
            "(MIT",
            "MIT)",
            "OR MIT",
            "MIT; rm -rf /",
            "MIT AND",
            "WITH",
            "MIT WITH",
        ] {
            assert_eq!(check(text), Err(Denial::Unreadable), "{text}");
        }
        let deep = format!("{}MIT{}", "(".repeat(20), ")".repeat(20));
        assert_eq!(check(&deep), Err(Denial::Unreadable));
        assert_eq!(check(&"MIT OR ".repeat(100)), Err(Denial::Unreadable));
    }
}
