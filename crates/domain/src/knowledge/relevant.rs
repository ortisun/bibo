//! Which entries an agent is given, chosen by code from the links (ADR 0028, Decision 4).
//!
//! The rule is the section "Which entries an agent is given" of
//! `docs/architecture/project-knowledge-base.md`. No model takes part in the choice.

use std::collections::BTreeSet;

use super::base::KnowledgeBase;
use super::entry::{Entry, RepoPath, Status};
use super::id::EntryId;

/// What the stage knows about the task when it chooses the entries.
#[derive(Debug, Clone, Copy)]
pub struct RelevanceRequest<'a> {
    /// The specifications of the job.
    pub specifications: &'a [RepoPath],
    /// The paths the task owns. A path that ends in `/` is a directory.
    pub owned_paths: &'a [RepoPath],
    /// The terms the request uses.
    pub terms: &'a [String],
}

/// The entries an agent is given, in the order of their identifiers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Relevance {
    /// Steps 1 and 2: the entries the specifications, the paths or the terms name.
    pub direct: Vec<EntryId>,
    /// Step 3: the entries those link to, one link out. The stage drops these first when it cuts
    /// the block to its size.
    pub linked: Vec<EntryId>,
}

impl KnowledgeBase {
    /// The entries of the knowledge base an agent of this task is given. Retired entries are
    /// never given. Only the six kinds people write are chosen: the numbers of the process are not
    /// knowledge about the product.
    pub fn relevant(&self, request: RelevanceRequest<'_>) -> Relevance {
        let terms: BTreeSet<String> = request
            .terms
            .iter()
            .map(|term| term.trim().to_lowercase())
            .filter(|term| !term.is_empty())
            .collect();
        let known = self.by_id();
        let live = |entry: &&Entry| entry.status != Status::Retired;
        let entries: Vec<&Entry> = known
            .values()
            .filter_map(|file| file.header.as_entry())
            .filter(live)
            .collect();

        let names_a_specification = |entry: &Entry| {
            entry.sources.specifications.iter().any(|path| {
                request
                    .specifications
                    .iter()
                    .any(|spec| spec.overlaps(path))
            })
        };
        let touches_an_owned_path = |entry: &Entry| {
            entry
                .sources
                .code
                .iter()
                .any(|path| request.owned_paths.iter().any(|owned| owned.overlaps(path)))
        };
        let names_a_term = |entry: &Entry| terms.contains(&entry.title.to_lowercase());

        let direct: BTreeSet<&EntryId> = entries
            .iter()
            .filter(|entry| {
                names_a_specification(entry) || touches_an_owned_path(entry) || names_a_term(entry)
            })
            .map(|entry| &entry.id)
            .collect();
        let linked: BTreeSet<&EntryId> = entries
            .iter()
            .filter(|entry| direct.contains(&entry.id))
            .flat_map(|entry| entry.links.iter())
            .filter(|id| !direct.contains(id))
            .filter(|id| {
                known
                    .get(id)
                    .and_then(|file| file.header.as_entry())
                    .is_some_and(|entry| live(&entry))
            })
            .collect();
        Relevance {
            direct: direct.into_iter().cloned().collect(),
            linked: linked.into_iter().cloned().collect(),
        }
    }
}

#[cfg(test)]
mod tests;
