//! Looking for secrets in a stream of bytes, one view of the stream at a time.
//!
//! # Two views
//!
//! The same bytes are read twice. The raw view is the bytes as they come. The terminal view is
//! the bytes with escape sequences and invisible characters taken out (see `terminal`). Each view
//! has its own scanner, and each scanner reports the spans of the original text that hold a
//! secret. A span in the terminal view runs from the original offset of its first byte to the
//! original offset of its last, so everything inside it, noise included, is covered.
//!
//! # Two ways of looking
//!
//! * The registry of exact values is searched with an automaton, byte by byte. The automaton
//!   keeps one number between bytes, so a value cut by a chunk boundary is found.
//! * The patterns of the policy are regular expressions, and the `regex` crate needs the whole
//!   text it searches. The scanner keeps a window of the view and searches it in blocks. A block
//!   covers [`BLOCK`] bytes of match starts, and the search reads [`LOOKAHEAD`] bytes beyond them
//!   so a match can run past the block. Block and look-ahead are measured in bytes of the view,
//!   so they depend only on the stream and never on how it was cut into chunks. That is what
//!   makes the result the same for every chunking.
//!
//! # Matches longer than the look-ahead
//!
//! A match that reaches the end of what the search could read might go on. Such a match is not
//! closed. It stays open and takes the following bytes up to the first white space or control
//! byte, so a long token is covered to its end whatever the look-ahead. A private key block that
//! has begun stays open until its end line. If the stream ends first, it is closed at the end of
//! the stream. This is the fail-closed choice: it never leaves the tail of a secret in the text.
//!
//! While a match is open, the bytes from its start on are held back by the caller (see the
//! watermark below), and the caller refuses the stream when it holds back more than its limit.
//!
//! # The watermark
//!
//! After each step a scanner can say the offset before which no span it has not yet reported can
//! start. The caller releases the text before the lowest watermark of the two scanners.

use std::cmp::Reverse;

use super::automaton::State;
use super::core::Core;
use super::patterns::{is_run_byte, shannon_bits_per_byte};
use super::registry::Snapshot;
use super::report::{FindingSource, Severity};
use super::terminal::Terminal;

/// How many bytes of a view a block of the pattern search accepts match starts from.
pub(super) const BLOCK: u64 = 4096;
/// How many bytes beyond a block the pattern search reads.
pub(super) const LOOKAHEAD: u64 = 4096;

const ARMOR_HEADER: &[u8] = b"-----BEGIN ";
const FOOTER_START: &[u8] = b"-----END ";
const FOOTER_DASHES: &[u8] = b"-----";

fn ix(n: u64) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

/// A stretch of the original text that holds a secret or a flag.
///
/// When spans are merged, the merged span covers all of them and is named by the one that sorts
/// first (see [`Span::key`]). `named_start` and `named_end` are the extent of that one, so the
/// choice of the name does not depend on the order in which the spans were merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Span {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) source: FindingSource,
    pub(super) label: u32,
    pub(super) severity: Severity,
    named_start: u64,
    named_end: u64,
}

impl Span {
    pub(super) const fn new(
        start: u64,
        end: u64,
        source: FindingSource,
        label: u32,
        severity: Severity,
    ) -> Self {
        Self {
            start,
            end,
            source,
            label,
            severity,
            named_start: start,
            named_end: end,
        }
    }

    /// The order in which spans that overlap are named: the earlier start, then the longer span,
    /// then a secret before a flag, then a registered value before a pattern before the entropy
    /// heuristic, then the order of the policy.
    pub(super) fn key(&self) -> (u64, Reverse<u64>, Severity, FindingSource, u32) {
        (
            self.named_start,
            Reverse(self.named_end),
            self.severity,
            self.source,
            self.label,
        )
    }

    /// The span that covers both, named by whichever sorts first.
    pub(super) fn merged_with(&self, other: &Span) -> Span {
        let winner = if other.key() < self.key() {
            other
        } else {
            self
        };
        Span {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
            ..*winner
        }
    }
}

/// What a scanner reads its settings and secrets from.
pub(super) struct Context<'a> {
    pub(super) core: &'a Core,
    pub(super) snapshot: &'a Snapshot,
}

// ---- Original offsets of the bytes of a view -------------------------------------------------

/// Maps the position of a byte in a view to its offset in the original text. A view that has
/// had bytes taken out is shifted by the number of bytes taken out before it. The map stores the
/// places where that shift changes.
#[derive(Debug, Default)]
struct OriginMap {
    /// (first view position with this shift, the shift)
    shifts: Vec<(u64, u64)>,
}

impl OriginMap {
    fn record(&mut self, view: u64, origin: u64) {
        let shift = origin.saturating_sub(view);
        if self.shifts.last().map_or(0, |s| s.1) != shift {
            self.shifts.push((view, shift));
        }
    }

    fn origin(&self, view: u64) -> u64 {
        let at = self.shifts.partition_point(|s| s.0 <= view);
        let shift = at
            .checked_sub(1)
            .and_then(|i| self.shifts.get(i))
            .map_or(0, |s| s.1);
        view.saturating_add(shift)
    }

    /// Forgets the shifts that no position at or after `view` needs.
    fn forget_before(&mut self, view: u64) {
        let at = self.shifts.partition_point(|s| s.0 <= view);
        if at > 1 {
            self.shifts.drain(..at - 1);
        }
    }
}

// ---- The window of the pattern search --------------------------------------------------------

// No `Debug`: the window holds recent input, which may hold a secret not yet replaced.
struct Window {
    bytes: Vec<u8>,
    /// The view position of `bytes[0]`.
    base: u64,
    /// Match starts before this position have been looked at.
    processed: u64,
    /// For each pattern, the first position at which its next match may start.
    resume: Vec<u64>,
    resume_entropy: u64,
}

impl Window {
    fn end(&self) -> u64 {
        self.base + self.bytes.len() as u64
    }

    fn byte(&self, view: u64) -> Option<u8> {
        let at = usize::try_from(view.checked_sub(self.base)?).ok()?;
        self.bytes.get(at).copied()
    }

    /// Drops what the next block no longer needs: everything before the byte that precedes the
    /// first unprocessed position. That byte stays so that `\b` at a block start sees it.
    fn trim(&mut self) {
        let keep_from = self.processed.saturating_sub(1).max(self.base);
        let drop = ix(keep_from - self.base).min(self.bytes.len());
        if drop > 0 {
            self.bytes.drain(..drop);
            self.base += drop as u64;
        }
    }
}

// ---- Matches that are still open -------------------------------------------------------------

/// What a match of the pattern search is cut by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Pattern(usize),
    Entropy,
}

/// Finds the end line of an armored block (a private key, for example) in a stream: the text
/// `-----END `, a label, then `-----`, then any further dashes.
#[derive(Debug, Clone, Copy)]
struct Footer {
    stage: u8,
    matched: usize,
}

/// The state after reading `byte` while matching `needle`, given how much of it matched so far.
fn next_match_state(needle: &[u8], matched: usize, byte: u8) -> usize {
    let mut k = matched;
    loop {
        if needle.get(k) == Some(&byte) {
            return k + 1;
        }
        if k == 0 {
            return 0;
        }
        // The longest proper prefix of needle[..k] that is also its suffix.
        k = (0..k)
            .rev()
            .find(|&j| needle.get(..j) == needle.get(k - j..k))
            .unwrap_or(0);
    }
}

impl Footer {
    const fn new() -> Self {
        Self {
            stage: 0,
            matched: 0,
        }
    }

    /// Reads one byte. True when the block ended before this byte, so the byte is not part of it.
    fn step(&mut self, byte: u8) -> bool {
        match self.stage {
            0 => {
                self.matched = next_match_state(FOOTER_START, self.matched, byte);
                if self.matched == FOOTER_START.len() {
                    self.stage = 1;
                    self.matched = 0;
                }
                false
            }
            1 => {
                self.matched = next_match_state(FOOTER_DASHES, self.matched, byte);
                if self.matched == FOOTER_DASHES.len() {
                    self.stage = 2;
                }
                false
            }
            _ => byte != b'-',
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Close {
    /// Ends before the first white space or control byte.
    Whitespace,
    /// Ends after the end line of an armored block.
    Footer(Footer),
}

#[derive(Debug)]
struct Open {
    slot: Slot,
    source: FindingSource,
    label: u32,
    severity: Severity,
    start_origin: u64,
    start_view: u64,
    /// The next view position to look at.
    pos: u64,
    close: Close,
}

// ---- The scanner of one view -----------------------------------------------------------------

// No `Debug`, for the same reason as the window.
pub(super) struct ViewScanner {
    /// The reader of the terminal view; `None` for the raw view.
    terminal: Option<Terminal>,
    ac_state: State,
    /// How many bytes of the view have been read.
    count: u64,
    map: OriginMap,
    win: Window,
    open: Vec<Open>,
}

impl ViewScanner {
    pub(super) fn new(terminal_view: bool, core: &Core) -> Self {
        Self {
            terminal: terminal_view.then(Terminal::new),
            ac_state: 0,
            count: 0,
            map: OriginMap::default(),
            win: Window {
                bytes: Vec::new(),
                base: 0,
                processed: 0,
                resume: vec![0; core.patterns.patterns.len()],
                resume_entropy: 0,
            },
            open: Vec::new(),
        }
    }

    fn origin(&self, view: u64) -> u64 {
        if self.terminal.is_some() {
            self.map.origin(view)
        } else {
            view
        }
    }

    fn registry_span(&self, view_start: u64, end_origin: u64, label: u32) -> Span {
        Span::new(
            self.origin(view_start),
            end_origin,
            FindingSource::Registry,
            label,
            Severity::Blocking,
        )
    }

    /// Reads bytes of the original stream. `at` is the offset of the first one.
    pub(super) fn feed(&mut self, ctx: &Context<'_>, bytes: &[u8], at: u64, spans: &mut Vec<Span>) {
        if self.terminal.is_none() {
            self.feed_raw(ctx, bytes, spans);
        } else {
            for (offset, &byte) in (at..).zip(bytes) {
                let visible = match self.terminal.as_mut() {
                    Some(terminal) => terminal.step(byte, offset),
                    None => break,
                };
                for (view_byte, origin) in visible.iter() {
                    self.push_view_byte(ctx, view_byte, origin, spans);
                }
            }
        }
        self.run_ready_blocks(ctx, spans);
    }

    fn feed_raw(&mut self, ctx: &Context<'_>, bytes: &[u8], spans: &mut Vec<Span>) {
        self.win.bytes.extend_from_slice(bytes);
        let automaton = ctx.snapshot.raw();
        if !automaton.is_empty() {
            for (i, &byte) in bytes.iter().enumerate() {
                self.ac_state = automaton.step(self.ac_state, byte);
                let end = self.count + i as u64 + 1;
                for (label, len) in automaton.matches(self.ac_state) {
                    spans.push(self.registry_span(end.saturating_sub(u64::from(len)), end, label));
                }
            }
        }
        self.count += bytes.len() as u64;
    }

    /// Takes one byte of the terminal view.
    fn push_view_byte(&mut self, ctx: &Context<'_>, byte: u8, origin: u64, spans: &mut Vec<Span>) {
        let view = self.count;
        self.map.record(view, origin);
        self.count += 1;
        self.win.bytes.push(byte);
        let automaton = ctx.snapshot.terminal();
        if automaton.is_empty() {
            return;
        }
        self.ac_state = automaton.step(self.ac_state, byte);
        for (label, len) in automaton.matches(self.ac_state) {
            let first = (view + 1).saturating_sub(u64::from(len));
            spans.push(self.registry_span(first, origin + 1, label));
        }
    }

    fn run_ready_blocks(&mut self, ctx: &Context<'_>, spans: &mut Vec<Span>) {
        while self.win.end().saturating_sub(self.win.processed) >= BLOCK + LOOKAHEAD {
            self.run_block(ctx, false, spans);
        }
    }

    /// Ends the stream: releases what the reader held back, searches what is left and closes the
    /// matches that are still open.
    pub(super) fn finish(&mut self, ctx: &Context<'_>, spans: &mut Vec<Span>) {
        let released = self.terminal.as_mut().map(Terminal::finish);
        if let Some(visible) = released {
            for (byte, origin) in visible.iter() {
                self.push_view_byte(ctx, byte, origin, spans);
            }
        }
        self.run_ready_blocks(ctx, spans);
        self.run_block(ctx, true, spans);
    }

    /// The offset before which no span that has not been reported yet can start.
    pub(super) fn watermark(&self, ctx: &Context<'_>, consumed: u64) -> u64 {
        let mut mark = consumed;
        if let Some(held) = self.terminal.as_ref().and_then(Terminal::first_held_offset) {
            mark = mark.min(held);
        }
        let automaton = if self.terminal.is_some() {
            ctx.snapshot.terminal()
        } else {
            ctx.snapshot.raw()
        };
        let depth = u64::from(automaton.depth(self.ac_state));
        if depth > 0 {
            mark = mark.min(self.origin(self.count.saturating_sub(depth)));
        }
        if self.win.processed < self.win.end() {
            mark = mark.min(self.origin(self.win.processed));
        }
        for open in &self.open {
            mark = mark.min(open.start_origin);
        }
        mark
    }

    /// Looks at the next block of the window. At the end of the stream the block is everything
    /// that is left, and it closes all open matches.
    fn run_block(&mut self, ctx: &Context<'_>, last: bool, spans: &mut Vec<Span>) {
        let start = self.win.processed;
        let available = self.win.end();
        let block_end = if last { available } else { start + BLOCK };
        let limit = if last {
            available
        } else {
            block_end + LOOKAHEAD
        };
        self.extend_open(limit, last, spans);
        if block_end > start {
            self.search(ctx, start, block_end, limit, last, spans);
        }
        self.win.processed = block_end.max(start);
        self.win.trim();
        let floor = self
            .count
            .saturating_sub(ctx.snapshot.longest() as u64)
            .min(self.win.base);
        self.map.forget_before(floor);
    }

    /// Lets the open matches take the bytes that follow them, up to `limit`.
    fn extend_open(&mut self, limit: u64, last: bool, spans: &mut Vec<Span>) {
        if self.open.is_empty() {
            return;
        }
        for mut open in std::mem::take(&mut self.open) {
            let mut pos = open.pos;
            let mut end = None;
            while pos < limit {
                let Some(byte) = self.win.byte(pos) else {
                    break;
                };
                let stop = match &mut open.close {
                    Close::Whitespace => byte <= b' ',
                    Close::Footer(footer) => footer.step(byte),
                };
                if stop {
                    end = Some(pos);
                    break;
                }
                pos += 1;
            }
            if end.is_none() && last {
                end = Some(pos);
            }
            match end {
                Some(end) => {
                    if end > open.start_view {
                        spans.push(Span::new(
                            open.start_origin,
                            self.origin(end - 1) + 1,
                            open.source,
                            open.label,
                            open.severity,
                        ));
                    }
                    self.unblock(open.slot, end);
                }
                None => {
                    open.pos = pos;
                    self.open.push(open);
                }
            }
        }
    }

    fn unblock(&mut self, slot: Slot, resume_at: u64) {
        match slot {
            Slot::Pattern(i) => {
                if let Some(r) = self.win.resume.get_mut(i) {
                    *r = resume_at;
                }
            }
            Slot::Entropy => self.win.resume_entropy = resume_at,
        }
    }

    /// Searches the patterns and the entropy heuristic over the positions `start..block_end`,
    /// reading as far as `limit`.
    fn search(
        &mut self,
        ctx: &Context<'_>,
        start: u64,
        block_end: u64,
        limit: u64,
        last: bool,
        spans: &mut Vec<Span>,
    ) {
        let bytes = std::mem::take(&mut self.win.bytes);
        let base = self.win.base;
        let hay_base = start.saturating_sub(1).max(base);
        let hay = bytes
            .get(ix(hay_base - base)..ix(limit.saturating_sub(base)))
            .unwrap_or(&[]);
        let patterns = &ctx.core.patterns;

        let first = ix(start - hay_base);
        for i in patterns.matching(hay, first) {
            let Some(pattern) = patterns.patterns.get(i) else {
                continue;
            };
            let mut pos = self.win.resume.get(i).copied().unwrap_or(0).max(start);
            let mut blocked = false;
            while pos < block_end {
                let Some(found) = pattern.regex.find_at(hay, ix(pos - hay_base)) else {
                    pos = block_end;
                    break;
                };
                let s = hay_base + found.start() as u64;
                let e = hay_base + found.end() as u64;
                if s >= block_end {
                    pos = block_end;
                    break;
                }
                if e <= s {
                    pos = s + 1;
                    continue;
                }
                let hit = Hit {
                    slot: Slot::Pattern(i),
                    source: FindingSource::Pattern,
                    label: u32::try_from(i).unwrap_or(u32::MAX),
                    severity: pattern.severity,
                    start: s,
                    end: e,
                };
                match self.on_match(ctx, &hit, hay, hay_base, limit, last, spans) {
                    Some(next) => pos = next,
                    None => {
                        blocked = true;
                        break;
                    }
                }
            }
            if let Some(r) = self.win.resume.get_mut(i) {
                *r = if blocked {
                    u64::MAX
                } else {
                    pos.max(block_end)
                };
            }
        }

        if let Some(rule) = patterns.entropy {
            let mut i = self.win.resume_entropy.max(start);
            let mut blocked = false;
            while i < block_end {
                let at = ix(i - hay_base);
                let byte = hay.get(at).copied().unwrap_or(0);
                let after_run_byte = at > 0 && hay.get(at - 1).is_some_and(|&b| is_run_byte(b));
                if !is_run_byte(byte) || after_run_byte {
                    i += 1;
                    continue;
                }
                let mut end = i;
                while end < limit && hay.get(ix(end - hay_base)).is_some_and(|&b| is_run_byte(b)) {
                    end += 1;
                }
                let run = hay.get(at..ix(end - hay_base)).unwrap_or(&[]);
                if run.len() >= rule.min_length && shannon_bits_per_byte(run) >= rule.min_bits {
                    let hit = Hit {
                        slot: Slot::Entropy,
                        source: FindingSource::Entropy,
                        label: 0,
                        severity: rule.severity,
                        start: i,
                        end,
                    };
                    match self.on_match(ctx, &hit, hay, hay_base, limit, last, spans) {
                        Some(next) => i = next.max(end),
                        None => {
                            blocked = true;
                            break;
                        }
                    }
                } else {
                    i = end;
                }
            }
            self.win.resume_entropy = if blocked { u64::MAX } else { i.max(block_end) };
        }
        self.win.bytes = bytes;
    }

    /// Turns one match into a span, or opens it when it may go on past what was read. Returns
    /// where the search for the next match of the same kind may start, or `None` when the match
    /// was left open.
    #[allow(clippy::too_many_arguments)]
    fn on_match(
        &mut self,
        ctx: &Context<'_>,
        hit: &Hit,
        hay: &[u8],
        hay_base: u64,
        limit: u64,
        last: bool,
        spans: &mut Vec<Span>,
    ) -> Option<u64> {
        if !ctx.core.replaces(hit.severity) {
            // A flag that is only reported. It is as long as the match, because nothing is cut.
            self.push_hit_span(hit, hit.end, spans);
            return Some(hit.end);
        }
        let header_at = ix(hit.start - hay_base);
        let armored = matches!(hit.slot, Slot::Pattern(_))
            && hay.get(header_at..header_at + ARMOR_HEADER.len()) == Some(ARMOR_HEADER);
        if armored {
            let mut footer = Footer::new();
            let mut pos = hit.end;
            while pos < limit {
                let byte = hay.get(ix(pos - hay_base)).copied().unwrap_or(0);
                if footer.step(byte) {
                    self.push_hit_span(hit, pos, spans);
                    return Some(pos);
                }
                pos += 1;
            }
            if last {
                self.push_hit_span(hit, limit, spans);
                return Some(limit);
            }
            self.open_hit(hit, limit, Close::Footer(footer));
            return None;
        }
        if !last && hit.end >= limit {
            self.open_hit(hit, hit.end, Close::Whitespace);
            return None;
        }
        self.push_hit_span(hit, hit.end, spans);
        Some(hit.end)
    }

    fn push_hit_span(&self, hit: &Hit, end_view: u64, spans: &mut Vec<Span>) {
        spans.push(Span::new(
            self.origin(hit.start),
            self.origin(end_view - 1) + 1,
            hit.source,
            hit.label,
            hit.severity,
        ));
    }

    fn open_hit(&mut self, hit: &Hit, pos: u64, close: Close) {
        self.open.push(Open {
            slot: hit.slot,
            source: hit.source,
            label: hit.label,
            severity: hit.severity,
            start_origin: self.origin(hit.start),
            start_view: hit.start,
            pos,
            close,
        });
    }
}

/// One match, in positions of the view.
struct Hit {
    slot: Slot,
    source: FindingSource,
    label: u32,
    severity: Severity,
    start: u64,
    end: u64,
}

// ---- Both views ------------------------------------------------------------------------------

// No `Debug`, for the same reason as the window.
pub(super) struct Engine {
    raw: ViewScanner,
    terminal: ViewScanner,
    /// How many bytes of the original stream have been read.
    consumed: u64,
}

impl Engine {
    pub(super) fn new(core: &Core) -> Self {
        Self {
            raw: ViewScanner::new(false, core),
            terminal: ViewScanner::new(true, core),
            consumed: 0,
        }
    }

    pub(super) fn consumed(&self) -> u64 {
        self.consumed
    }

    pub(super) fn feed(&mut self, ctx: &Context<'_>, bytes: &[u8], spans: &mut Vec<Span>) {
        self.raw.feed(ctx, bytes, self.consumed, spans);
        self.terminal.feed(ctx, bytes, self.consumed, spans);
        self.consumed += bytes.len() as u64;
    }

    pub(super) fn finish(&mut self, ctx: &Context<'_>, spans: &mut Vec<Span>) {
        self.raw.finish(ctx, spans);
        self.terminal.finish(ctx, spans);
    }

    pub(super) fn watermark(&self, ctx: &Context<'_>) -> u64 {
        self.raw
            .watermark(ctx, self.consumed)
            .min(self.terminal.watermark(ctx, self.consumed))
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

    #[test]
    fn the_origin_map_counts_the_bytes_taken_out() {
        let mut map = OriginMap::default();
        // View positions 0..3 are original 0..3; two bytes are taken out; 3..6 are original 5..8.
        for (view, origin) in [(0, 0), (1, 1), (2, 2), (3, 5), (4, 6), (5, 7)] {
            map.record(view, origin);
        }
        assert_eq!(map.shifts.len(), 1);
        assert_eq!(map.origin(2), 2);
        assert_eq!(map.origin(3), 5);
        assert_eq!(map.origin(5), 7);
        map.forget_before(4);
        assert_eq!(map.origin(5), 7);
    }

    #[test]
    fn the_footer_is_found_however_many_dashes_it_has() {
        for text in [
            &b"abc\n-----END RSA PRIVATE KEY-----\nrest"[..],
            b"abc\n------END RSA PRIVATE KEY------\nrest",
            b"-----END X-----\nrest",
        ] {
            let mut footer = Footer::new();
            let end = text.iter().position(|&b| footer.step(b)).unwrap();
            assert_eq!(&text[end..], b"\nrest", "{}", String::from_utf8_lossy(text));
        }
    }

    #[test]
    fn a_match_of_the_footer_start_survives_a_false_start() {
        // "-----END" is read, then a dash restarts the match. The dashes overlap.
        assert_eq!(next_match_state(b"-----END ", 5, b'-'), 5);
        assert_eq!(next_match_state(b"-----END ", 3, b'x'), 0);
        assert_eq!(next_match_state(b"-----END ", 8, b' '), 9);
    }

    #[test]
    fn spans_that_cover_the_same_text_are_named_by_the_policy_order() {
        let span = |severity, source, label| Span::new(4, 9, source, label, severity);
        let earlier_in_policy = span(Severity::Blocking, FindingSource::Pattern, 2);
        let later = span(Severity::Blocking, FindingSource::Pattern, 5);
        let flag = span(Severity::Flag, FindingSource::Pattern, 0);
        let registry = span(Severity::Blocking, FindingSource::Registry, 9);
        assert!(registry.key() < earlier_in_policy.key());
        assert!(earlier_in_policy.key() < later.key());
        assert!(later.key() < flag.key(), "a secret is named before a flag");
        let longer = Span::new(4, 20, FindingSource::Pattern, 5, Severity::Blocking);
        assert!(
            longer.key() < earlier_in_policy.key(),
            "a longer span first"
        );
    }
}
