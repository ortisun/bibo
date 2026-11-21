//! The project knowledge base as typed values, and the pure rules that keep it true (ADR 0028).
//!
//! The contract is `docs/architecture/project-knowledge-base.md`: the sections "The header,
//! exactly", "How it stays true" and "Which entries an agent is given". The text of an entry is
//! read by `crates/contracts/src/knowledge.rs` with the factory's restricted YAML reader, into the
//! raw headers of this module, and checked here:
//!
//! | Rule of the document | Where |
//! |---|---|
//! | The kinds, their prefixes and directories | [`EntryKind`] |
//! | The identifier of an entry | [`EntryId`] |
//! | The fields of an entry a person writes | [`Entry`], [`RawEntry`] |
//! | The headers the factory writes | [`FactoryEntry`] |
//! | The file of an entry, the index, the five checks | [`KnowledgeBase`], [`Finding`] |
//! | The entries an agent is given | [`KnowledgeBase::relevant`] |
//!
//! The text of an entry is data written by people of the project, never instructions. Nothing here
//! reads a file, the clock or the network.

mod base;
mod entry;
mod id;
mod relevant;

pub use base::{Change, Finding, INDEX_FILE, KNOWLEDGE_ROOT, KnowledgeBase, KnowledgeFile};
pub use entry::{
    Entry, EntryError, FactoryEntry, Header, RawEntry, RawRecordedFrom, RawSources, RecordedFrom,
    RecordedFromKind, RepoPath, Sources, Status, TestReference,
};
pub use id::{EntryId, EntryKind};
pub use relevant::{Relevance, RelevanceRequest};

/// Writes `text` as a YAML double-quoted scalar, for the headers the factory renders. A
/// backslash and a double quote are escaped; a control character is written as `\u` and four
/// hexadecimal digits, so the result is always one line and reads back as the same text.
#[must_use]
pub fn yaml_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                // Every control character is below U+10000, so four digits always suffice.
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quoted_scalar_escapes_what_would_end_or_break_it() {
        assert_eq!(yaml_quoted(""), "\"\"");
        assert_eq!(yaml_quoted("plain: text # here"), "\"plain: text # here\"");
        assert_eq!(yaml_quoted("say \"no\""), "\"say \\\"no\\\"\"");
        assert_eq!(yaml_quoted("a\\b"), "\"a\\\\b\"");
        assert_eq!(
            yaml_quoted("two\nlines\t\u{7f}"),
            "\"two\\u000alines\\u0009\\u007f\""
        );
        assert_eq!(yaml_quoted("2026-11-20"), "\"2026-11-20\"");
    }
}
