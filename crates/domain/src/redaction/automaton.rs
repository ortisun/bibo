//! Finds many byte strings in a stream at once, one byte at a time.
//!
//! This is the Aho-Corasick automaton. The registry of exact secret values turns into several
//! hundred byte strings (each value in each encoding), and the redactor has to find any of them
//! in a stream without keeping the stream. The automaton holds one number between bytes, its
//! state, so a match split across two chunks is found as if the chunks were one. The cost per byte
//! is constant on average, whatever the number of strings.
//!
//! The strings are stored as a trie. Each node keeps its first child and its next sibling, which
//! costs about 28 bytes per node and a short walk per step. The root has a table of 256 entries,
//! because it is where most steps start.
//!
//! The automaton is built once and never changed, so it can be shared between threads.

const ROOT: u32 = 0;
const NONE: u32 = u32::MAX;

/// A position in the automaton. `ROOT` (0) is where a stream starts.
pub(super) type State = u32;

#[derive(Debug, Clone)]
struct Node {
    first_child: u32,
    next_sibling: u32,
    byte: u8,
    /// The node for the longest proper suffix of this node's string that is also in the trie.
    fail: u32,
    /// The length of this node's string.
    depth: u32,
    /// The first string that ends exactly here, or `NONE`.
    out_head: u32,
    /// The nearest node along the failure links that has a string ending in it, or `NONE`.
    dict: u32,
}

#[derive(Debug, Clone)]
struct Output {
    label: u32,
    len: u32,
    next: u32,
}

/// The automaton for a fixed set of strings.
///
/// The trie spells out every string, and the strings are secrets, so the automaton is never
/// printed (its `Debug` shows sizes only) and its bytes are overwritten when it is dropped. The
/// overwrite is a best effort; see the note in `registry`.
pub(super) struct Automaton {
    nodes: Vec<Node>,
    outputs: Vec<Output>,
    root_next: Vec<u32>,
    longest: usize,
}

impl std::fmt::Debug for Automaton {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Automaton")
            .field("nodes", &self.nodes.len())
            .field("longest", &self.longest)
            .finish()
    }
}

impl Drop for Automaton {
    fn drop(&mut self) {
        for node in &mut self.nodes {
            node.byte = 0;
        }
        std::hint::black_box(&self.nodes);
    }
}

impl Automaton {
    /// Builds the automaton for these strings. Each carries a label that comes back with its
    /// matches. An empty string is ignored. Two strings may be equal; both are reported.
    pub(super) fn build<'a>(needles: impl IntoIterator<Item = (&'a [u8], u32)>) -> Self {
        let mut automaton = Self {
            nodes: vec![Node {
                first_child: NONE,
                next_sibling: NONE,
                byte: 0,
                fail: ROOT,
                depth: 0,
                out_head: NONE,
                dict: NONE,
            }],
            outputs: Vec::new(),
            root_next: vec![NONE; 256],
            longest: 0,
        };
        for (needle, label) in needles {
            automaton.insert(needle, label);
        }
        automaton.link_failures();
        automaton.fill_root_table();
        automaton
    }

    fn node(&self, at: u32) -> Option<&Node> {
        self.nodes.get(at as usize)
    }

    fn node_mut(&mut self, at: u32) -> Option<&mut Node> {
        self.nodes.get_mut(at as usize)
    }

    /// The child of `at` for `byte`, found by walking the sibling list. Used while building.
    fn child_by_walk(&self, at: u32, byte: u8) -> u32 {
        let mut child = self.node(at).map_or(NONE, |n| n.first_child);
        while child != NONE {
            match self.node(child) {
                Some(n) if n.byte == byte => return child,
                Some(n) => child = n.next_sibling,
                None => return NONE,
            }
        }
        NONE
    }

    fn insert(&mut self, needle: &[u8], label: u32) {
        if needle.is_empty() {
            return;
        }
        let mut at = ROOT;
        for (i, &byte) in needle.iter().enumerate() {
            let existing = self.child_by_walk(at, byte);
            at = if existing != NONE {
                existing
            } else {
                let created = u32::try_from(self.nodes.len()).unwrap_or(NONE);
                let first = self.node(at).map_or(NONE, |n| n.first_child);
                self.nodes.push(Node {
                    first_child: NONE,
                    next_sibling: first,
                    byte,
                    fail: ROOT,
                    depth: u32::try_from(i + 1).unwrap_or(u32::MAX),
                    out_head: NONE,
                    dict: NONE,
                });
                if let Some(parent) = self.node_mut(at) {
                    parent.first_child = created;
                }
                created
            };
        }
        let len = u32::try_from(needle.len()).unwrap_or(u32::MAX);
        let next = self.node(at).map_or(NONE, |n| n.out_head);
        let output = u32::try_from(self.outputs.len()).unwrap_or(NONE);
        self.outputs.push(Output { label, len, next });
        if let Some(node) = self.node_mut(at) {
            node.out_head = output;
        }
        self.longest = self.longest.max(needle.len());
    }

    /// Sets the failure and dictionary links, level by level.
    fn link_failures(&mut self) {
        let mut queue: Vec<u32> = Vec::new();
        let mut child = self.node(ROOT).map_or(NONE, |n| n.first_child);
        while child != NONE {
            queue.push(child);
            child = self.node(child).map_or(NONE, |n| n.next_sibling);
        }
        let mut head = 0;
        while let Some(&parent) = queue.get(head) {
            head += 1;
            let mut child = self.node(parent).map_or(NONE, |n| n.first_child);
            while child != NONE {
                let (byte, next_sibling) = self
                    .node(child)
                    .map_or((0, NONE), |n| (n.byte, n.next_sibling));
                let mut candidate = self.node(parent).map_or(ROOT, |n| n.fail);
                let fail = loop {
                    let found = self.child_by_walk(candidate, byte);
                    if found != NONE {
                        break found;
                    }
                    if candidate == ROOT {
                        break ROOT;
                    }
                    candidate = self.node(candidate).map_or(ROOT, |n| n.fail);
                };
                let dict = match self.node(fail) {
                    Some(n) if n.out_head != NONE => fail,
                    Some(n) => n.dict,
                    None => NONE,
                };
                if let Some(node) = self.node_mut(child) {
                    node.fail = fail;
                    node.dict = dict;
                }
                queue.push(child);
                child = next_sibling;
            }
        }
    }

    fn fill_root_table(&mut self) {
        let mut child = self.node(ROOT).map_or(NONE, |n| n.first_child);
        while child != NONE {
            let (byte, next) = self
                .node(child)
                .map_or((0, NONE), |n| (n.byte, n.next_sibling));
            if let Some(slot) = self.root_next.get_mut(usize::from(byte)) {
                *slot = child;
            }
            child = next;
        }
    }

    /// True when there is nothing to find.
    pub(super) fn is_empty(&self) -> bool {
        self.outputs.is_empty()
    }

    /// The length of the longest string.
    pub(super) fn longest(&self) -> usize {
        self.longest
    }

    fn child(&self, at: u32, byte: u8) -> u32 {
        if at == ROOT {
            self.root_next
                .get(usize::from(byte))
                .copied()
                .unwrap_or(NONE)
        } else {
            self.child_by_walk(at, byte)
        }
    }

    /// The state after reading `byte` in `state`.
    pub(super) fn step(&self, mut state: State, byte: u8) -> State {
        loop {
            let next = self.child(state, byte);
            if next != NONE {
                return next;
            }
            if state == ROOT {
                return ROOT;
            }
            state = self.node(state).map_or(ROOT, |n| n.fail);
        }
    }

    /// How many of the last bytes read are a prefix of some string. A match that ends later
    /// cannot start before this many bytes back.
    pub(super) fn depth(&self, state: State) -> u32 {
        self.node(state).map_or(0, |n| n.depth)
    }

    /// The strings that end at the byte just read: their labels and lengths, longest last.
    pub(super) fn matches(&self, state: State) -> Matches<'_> {
        Matches {
            automaton: self,
            node: state,
            output: self.node(state).map_or(NONE, |n| n.out_head),
        }
    }
}

/// The strings that end at one position.
pub(super) struct Matches<'a> {
    automaton: &'a Automaton,
    node: u32,
    output: u32,
}

impl Iterator for Matches<'_> {
    type Item = (u32, u32);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.output != NONE {
                let out = self.automaton.outputs.get(self.output as usize)?;
                self.output = out.next;
                return Some((out.label, out.len));
            }
            let dict = self.automaton.node(self.node)?.dict;
            if dict == NONE {
                return None;
            }
            self.node = dict;
            self.output = self.automaton.node(dict).map_or(NONE, |n| n.out_head);
        }
    }
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

    /// Every match as (end offset exclusive, length, label), found by running the automaton.
    fn run(automaton: &Automaton, haystack: &[u8]) -> Vec<(usize, u32, u32)> {
        let mut found = Vec::new();
        let mut state = ROOT;
        for (i, &byte) in haystack.iter().enumerate() {
            state = automaton.step(state, byte);
            for (label, len) in automaton.matches(state) {
                found.push((i + 1, len, label));
            }
        }
        found.sort_unstable();
        found
    }

    /// The same matches found the slow, obvious way.
    fn naive(needles: &[(&[u8], u32)], haystack: &[u8]) -> Vec<(usize, u32, u32)> {
        let mut found = Vec::new();
        for (needle, label) in needles {
            if needle.is_empty() {
                continue;
            }
            for end in needle.len()..=haystack.len() {
                if &haystack[end - needle.len()..end] == *needle {
                    found.push((end, needle.len() as u32, *label));
                }
            }
        }
        found.sort_unstable();
        found
    }

    #[test]
    fn finds_a_single_string() {
        let a = Automaton::build([(b"secret".as_slice(), 7)]);
        assert_eq!(run(&a, b"a secret here"), vec![(8, 6, 7)]);
    }

    #[test]
    fn finds_overlapping_strings_that_end_together_or_apart() {
        let needles: Vec<(&[u8], u32)> = vec![(b"he", 0), (b"she", 1), (b"his", 2), (b"hers", 3)];
        let a = Automaton::build(needles.iter().copied());
        assert_eq!(run(&a, b"ushers"), naive(&needles, b"ushers"));
        // "she" and "he" end at the same byte; both are reported.
        let found = run(&a, b"ushers");
        assert!(found.contains(&(4, 3, 1)));
        assert!(found.contains(&(4, 2, 0)));
        assert!(found.contains(&(6, 4, 3)));
    }

    #[test]
    fn a_string_inside_a_longer_one_is_reported_too() {
        let needles: Vec<(&[u8], u32)> = vec![(b"abcdefgh", 0), (b"cdef", 1)];
        let a = Automaton::build(needles.iter().copied());
        assert_eq!(run(&a, b"xxabcdefghxx"), naive(&needles, b"xxabcdefghxx"));
    }

    #[test]
    fn equal_strings_with_two_labels_are_both_reported() {
        let a = Automaton::build([(b"samesame".as_slice(), 1), (b"samesame".as_slice(), 2)]);
        let found = run(&a, b"samesame");
        assert_eq!(found, vec![(8, 8, 1), (8, 8, 2)]);
    }

    #[test]
    fn no_strings_find_nothing() {
        let a = Automaton::build(std::iter::empty());
        assert!(a.is_empty());
        assert!(run(&a, b"anything at all").is_empty());
        let b = Automaton::build([(b"".as_slice(), 0)]);
        assert!(b.is_empty());
    }

    #[test]
    fn binary_bytes_are_ordinary_bytes() {
        let needle: &[u8] = &[0x00, 0xff, 0x80, 0x00, 0xff];
        let a = Automaton::build([(needle, 0)]);
        assert_eq!(
            run(&a, &[1, 0x00, 0xff, 0x80, 0x00, 0xff, 2]),
            vec![(6, 5, 0)]
        );
    }

    #[test]
    fn a_match_split_across_two_reads_is_found() {
        // The automaton is fed one byte at a time, so a chunk boundary does not exist for it.
        let a = Automaton::build([(b"abcdefgh".as_slice(), 0)]);
        let mut state = ROOT;
        for &byte in b"xxabcd" {
            state = a.step(state, byte);
        }
        assert_eq!(a.matches(state).count(), 0);
        assert_eq!(a.depth(state), 4);
        for &byte in b"efgh" {
            state = a.step(state, byte);
        }
        assert_eq!(a.matches(state).collect::<Vec<_>>(), vec![(0, 8)]);
    }

    #[test]
    fn depth_is_the_length_of_the_partial_match() {
        let a = Automaton::build([(b"abcab".as_slice(), 0)]);
        let mut state = ROOT;
        let mut depths = Vec::new();
        for &byte in b"xabcabcab" {
            state = a.step(state, byte);
            depths.push(a.depth(state));
        }
        assert_eq!(depths, vec![0, 1, 2, 3, 4, 5, 3, 4, 5]);
    }

    #[test]
    fn a_long_string_is_found() {
        let needle: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let a = Automaton::build([(needle.as_slice(), 9)]);
        let mut haystack = vec![0u8; 5];
        haystack.extend_from_slice(&needle);
        assert_eq!(run(&a, &haystack), vec![(20_005, 20_000, 9)]);
        assert_eq!(a.longest(), 20_000);
    }

    #[test]
    fn agrees_with_the_obvious_search_on_many_random_inputs() {
        // A small alphabet makes overlaps, repeats and failure links common.
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..300 {
            let count = 1 + (next() % 6) as usize;
            let owned: Vec<(Vec<u8>, u32)> = (0..count)
                .map(|i| {
                    let len = 1 + (next() % 7) as usize;
                    let bytes = (0..len).map(|_| b'a' + (next() % 3) as u8).collect();
                    (bytes, i as u32)
                })
                .collect();
            let needles: Vec<(&[u8], u32)> =
                owned.iter().map(|(b, l)| (b.as_slice(), *l)).collect();
            let haystack: Vec<u8> = (0..(next() % 60) as usize)
                .map(|_| b'a' + (next() % 3) as u8)
                .collect();
            let a = Automaton::build(needles.iter().copied());
            assert_eq!(
                run(&a, &haystack),
                naive(&needles, &haystack),
                "needles {needles:?}, haystack {haystack:?}"
            );
        }
    }
}
