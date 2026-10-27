//! The registry of the factory's own secret values.
//!
//! Every secret that the factory loads or issues is registered here: job tokens, the webhook
//! secret, database and broker credentials, installation tokens as they are minted. The registry
//! turns each value into the byte strings it can appear as (see `encodings`) and keeps them in an
//! automaton that finds all of them at once. An exact value is stronger than any pattern: it
//! needs no word boundary, no particular format, and it finds the value inside a longer word.
//!
//! The registry lives in memory only. It is rebuilt when a value is added or forgotten, and the
//! streams that are already running keep the snapshot they started with.
//!
//! A value that has several lines, such as a private key, is registered whole and line by line,
//! because a log often prints one line at a time. A value with white space at its ends is
//! registered with and without it, because a file read from disk usually ends in a newline that
//! the program using it removes.
//!
//! The memory that held a value is overwritten when the value is forgotten or the registry is
//! dropped. This is a best effort: the language has no guarantee that a compiler keeps such a
//! write, and the crate may not use `unsafe` code or a zeroizing crate.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::automaton::Automaton;
use super::core::Core;
use super::encodings::forms;
use super::error::RegistryError;
use super::patterns::is_valid_id;
use super::terminal::strip;

/// A handle to a registered secret, used to forget it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecretHandle(u64);

/// The result of registering a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// The secret is registered. Registering the same label and value again gives the same
    /// handle.
    Added(SecretHandle),
    /// The secret is shorter than the minimum, so it is not registered. The caller should treat
    /// this as a warning: a secret that short cannot be told apart from ordinary text.
    TooShort,
}

/// Overwrites a buffer. See the note at the top of the module.
fn wipe(bytes: &mut [u8]) {
    bytes.iter_mut().for_each(|b| *b = 0);
    std::hint::black_box(&*bytes);
}

/// What a running stream searches with: the automata for the registry as it was at one moment.
#[derive(Debug)]
pub(super) struct Snapshot {
    raw: Automaton,
    /// The automaton for the terminal view, when it differs from the raw one.
    terminal: Option<Automaton>,
    labels: Vec<Arc<str>>,
}

impl Snapshot {
    pub(super) fn empty() -> Self {
        Self {
            raw: Automaton::build(std::iter::empty()),
            terminal: None,
            labels: Vec::new(),
        }
    }

    pub(super) fn raw(&self) -> &Automaton {
        &self.raw
    }

    pub(super) fn terminal(&self) -> &Automaton {
        self.terminal.as_ref().unwrap_or(&self.raw)
    }

    pub(super) fn label(&self, index: u32) -> &str {
        self.labels
            .get(index as usize)
            .map_or("registered", |l| l.as_ref())
    }

    /// The length of the longest search string, which is how far back a match can start.
    pub(super) fn longest(&self) -> usize {
        self.raw.longest().max(self.terminal().longest())
    }
}

struct Entry {
    handle: u64,
    label: Arc<str>,
    value: Vec<u8>,
    needles: Vec<Vec<u8>>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        wipe(&mut self.value);
        for needle in &mut self.needles {
            wipe(needle);
        }
    }
}

pub(super) struct Registry {
    entries: Vec<Entry>,
    next_handle: u64,
    needle_bytes: usize,
    snapshot: Arc<Snapshot>,
}

impl Registry {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_handle: 1,
            needle_bytes: 0,
            snapshot: Arc::new(Snapshot::empty()),
        }
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(&self.snapshot)
    }

    pub(super) fn register(
        &mut self,
        core: &Core,
        label: &str,
        value: &[u8],
    ) -> Result<Registered, RegistryError> {
        if !is_valid_id(label) {
            return Err(RegistryError::InvalidLabel {
                label: label.to_owned(),
            });
        }
        if value.len() < core.min_len {
            return Ok(Registered::TooShort);
        }
        let max_len = core.limits.max_value_len;
        if value.len() > max_len {
            return Err(RegistryError::ValueTooLong { max: max_len });
        }
        if let Some(existing) = self
            .entries
            .iter()
            .find(|e| e.label.as_ref() == label && e.value == value)
        {
            return Ok(Registered::Added(SecretHandle(existing.handle)));
        }
        let max_values = core.limits.max_registry_values;
        if self.entries.len() >= max_values {
            return Err(RegistryError::TooManyValues { max: max_values });
        }
        let needles: Vec<Vec<u8>> = needles_for(value, core).into_iter().collect();
        let added: usize = needles.iter().map(Vec::len).sum();
        let max_bytes = core.limits.max_registry_bytes;
        if self.needle_bytes.saturating_add(added) > max_bytes {
            return Err(RegistryError::TooLarge { max: max_bytes });
        }
        let handle = self.next_handle;
        self.next_handle += 1;
        self.needle_bytes += added;
        self.entries.push(Entry {
            handle,
            label: Arc::from(label),
            value: value.to_vec(),
            needles,
        });
        self.rebuild(core.min_len);
        Ok(Registered::Added(SecretHandle(handle)))
    }

    pub(super) fn forget(&mut self, core: &Core, handle: SecretHandle) -> bool {
        let Some(at) = self.entries.iter().position(|e| e.handle == handle.0) else {
            return false;
        };
        let removed = self.entries.remove(at);
        self.needle_bytes = self
            .needle_bytes
            .saturating_sub(removed.needles.iter().map(Vec::len).sum());
        drop(removed);
        self.rebuild(core.min_len);
        true
    }

    fn rebuild(&mut self, min_len: usize) {
        let mut labels: Vec<Arc<str>> = Vec::new();
        let mut index: BTreeMap<Arc<str>, u32> = BTreeMap::new();
        let mut pairs: Vec<(&[u8], u32)> = Vec::new();
        for entry in &self.entries {
            let label = *index.entry(Arc::clone(&entry.label)).or_insert_with(|| {
                labels.push(Arc::clone(&entry.label));
                u32::try_from(labels.len() - 1).unwrap_or(u32::MAX)
            });
            pairs.extend(entry.needles.iter().map(|n| (n.as_slice(), label)));
        }
        let raw = Automaton::build(pairs.iter().copied());

        // The same strings as the terminal view sees them: escape sequences and invisible
        // characters taken out. When that changes none of them, the raw automaton serves both.
        let mut changed = false;
        let mut stripped: Vec<(Vec<u8>, u32)> = Vec::with_capacity(pairs.len());
        for (needle, label) in &pairs {
            let plain = strip(needle);
            if plain.as_slice() != *needle {
                changed = true;
            }
            if plain.len() >= min_len {
                stripped.push((plain, *label));
            } else {
                changed = true;
            }
        }
        let terminal =
            changed.then(|| Automaton::build(stripped.iter().map(|(n, l)| (n.as_slice(), *l))));
        for (plain, _) in &mut stripped {
            wipe(plain);
        }
        self.snapshot = Arc::new(Snapshot {
            raw,
            terminal,
            labels,
        });
    }
}

/// Every string a value can show up as: the value, its trimmed form, each of its lines, each
/// in every encoding of the policy. Strings shorter than the minimum are left out, because a
/// short string matches by accident.
fn needles_for(value: &[u8], core: &Core) -> BTreeSet<Vec<u8>> {
    let mut candidates: BTreeSet<&[u8]> = BTreeSet::new();
    candidates.insert(value);
    candidates.insert(value.trim_ascii());
    let lines: Vec<&[u8]> = value
        .split(|b| *b == b'\n')
        .map(<[u8]>::trim_ascii)
        .filter(|line| !line.is_empty())
        .collect();
    if lines.len() > 1 {
        candidates.extend(lines);
    }
    let mut needles = BTreeSet::new();
    for candidate in candidates {
        if candidate.len() < core.min_len {
            continue;
        }
        for form in forms(candidate, &core.encodings) {
            if form.len() >= core.min_len {
                needles.insert(form);
            }
        }
    }
    needles
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::redaction::config::{FlagHandling, Limits};
    use crate::redaction::encodings::Encoding;
    use crate::redaction::patterns::PatternSet;

    fn core() -> Core {
        Core {
            patterns: PatternSet::compile(&[], None).unwrap(),
            flagged: FlagHandling::ReportOnly,
            limits: Limits::default(),
            min_len: 8,
            encodings: Encoding::ALL.to_vec(),
        }
    }

    fn find_all(snapshot: &Snapshot, text: &[u8]) -> Vec<String> {
        let ac = snapshot.raw();
        let mut state = 0;
        let mut found = Vec::new();
        for &b in text {
            state = ac.step(state, b);
            for (label, _) in ac.matches(state) {
                found.push(snapshot.label(label).to_owned());
            }
        }
        found
    }

    #[test]
    fn a_registered_value_is_found_and_a_forgotten_one_is_not() {
        let core = core();
        let mut registry = Registry::new();
        let Registered::Added(handle) = registry
            .register(&core, "job_token", b"abcdefghijkl")
            .unwrap()
        else {
            panic!("registered");
        };
        assert_eq!(
            find_all(&registry.snapshot(), b"x abcdefghijkl y"),
            vec!["job_token"]
        );
        assert!(registry.forget(&core, handle));
        assert!(find_all(&registry.snapshot(), b"x abcdefghijkl y").is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn a_snapshot_taken_earlier_does_not_change() {
        let core = core();
        let mut registry = Registry::new();
        let before = registry.snapshot();
        registry.register(&core, "a", b"abcdefghijkl").unwrap();
        assert!(find_all(&before, b"abcdefghijkl").is_empty());
        assert!(!find_all(&registry.snapshot(), b"abcdefghijkl").is_empty());
    }

    #[test]
    fn the_terminal_automaton_is_separate_only_when_a_value_has_invisible_text_in_it() {
        let core = core();
        let mut registry = Registry::new();
        registry.register(&core, "a", b"abcdefghijkl").unwrap();
        assert!(registry.snapshot().terminal.is_none());
        registry
            .register(&core, "b", "pass\u{200d}word-123".as_bytes())
            .unwrap();
        let snapshot = registry.snapshot();
        let terminal = snapshot.terminal.as_ref().expect("a separate automaton");
        // The stripped text of the second value is a search string of the terminal automaton.
        let mut state = 0;
        let mut hits = 0;
        for &b in b"xx password-123 xx" {
            state = terminal.step(state, b);
            hits += terminal.matches(state).count();
        }
        assert_eq!(hits, 1);
    }

    #[test]
    fn the_limits_are_checked_before_anything_is_stored() {
        let mut core = core();
        core.limits.max_registry_bytes = 100;
        let mut registry = Registry::new();
        assert!(matches!(
            registry.register(&core, "a", &[b'x'; 64]),
            Err(RegistryError::TooLarge { .. })
        ));
        assert_eq!(registry.len(), 0);
    }
}
