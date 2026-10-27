//! Merging the spans the scanners report, and writing the text with the secrets taken out.
//!
//! The two scanners and the several detectors report spans in the order they find them, and the
//! spans overlap: the same token matches two patterns and both views, and a registered value sits
//! inside a token that a pattern also matches. The sink merges spans that overlap into one and
//! replaces each merged span with one marker, `[REDACTED:<id>]`. Spans that only touch stay
//! separate. A merged span is named by the span in it that starts first, then the longest, then
//! the order of the policy, so the name never depends on the order of discovery.
//!
//! A marker holds the identifier and nothing else. The policy does not allow a fingerprint of
//! the secret in it, and a fingerprint of a low-entropy secret such as a password would let a
//! reader of the log confirm a guess.
//!
//! The text is released in order. The caller tells the sink the offset before which no more
//! spans can start (the watermark). Everything before it that is not inside a span is written
//! out. A span is written as its marker once the watermark is past its end, because until then a
//! later span could still overlap it.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::core::Core;
use super::error::RedactionError;
use super::registry::Snapshot;
use super::report::{Finding, FindingSource, MAX_LISTED_FINDINGS, Report, Severity};
use super::scan::Span;

/// What the sink does with the text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode {
    /// Keeps the text it has not released and writes the redacted text.
    Rewrite,
    /// Keeps no text and collects the final spans, for a caller that has the whole input.
    Collect,
    /// Keeps no text and no spans. Only the report.
    Discard,
}

/// Finds the name of a span for the marker and the report.
#[derive(Debug, Clone)]
pub(super) struct Names {
    pub(super) core: Arc<Core>,
    pub(super) snapshot: Arc<Snapshot>,
}

impl Names {
    pub(super) fn of(&self, source: FindingSource, label: u32) -> String {
        match source {
            FindingSource::Pattern => self
                .core
                .patterns
                .patterns
                .get(label as usize)
                .map_or("pattern", |p| p.id.as_ref())
                .to_owned(),
            FindingSource::Entropy => "entropy".to_owned(),
            FindingSource::Registry => self.snapshot.label(label).to_owned(),
        }
    }
}

type FindingKey = (u64, u64, Severity, FindingSource, u32);

#[derive(Debug, Default)]
struct ReportBuilder {
    replaced: u64,
    findings: BTreeSet<FindingKey>,
    ids: BTreeSet<(FindingSource, u32)>,
    blocking: bool,
    flagged: bool,
}

impl ReportBuilder {
    fn note(&mut self, span: &Span) {
        match span.severity {
            Severity::Blocking => self.blocking = true,
            Severity::Flag => self.flagged = true,
        }
        self.ids.insert((span.source, span.label));
        self.findings
            .insert((span.start, span.end, span.severity, span.source, span.label));
        if self.findings.len() > MAX_LISTED_FINDINGS {
            self.findings.pop_last();
        }
    }

    fn build(&self, names: &Names) -> Report {
        let mut findings: Vec<Finding> = self
            .findings
            .iter()
            .map(|&(start, end, severity, source, label)| Finding {
                start,
                end,
                id: names.of(source, label),
                source,
                severity,
            })
            .collect();
        findings.sort();
        Report {
            replaced: self.replaced,
            findings,
            ids: self
                .ids
                .iter()
                .map(|&(source, label)| names.of(source, label))
                .collect(),
            blocking: self.blocking,
            flagged: self.flagged,
        }
    }
}

// No `Debug`: the sink holds input that has not been checked yet.
pub(super) struct Sink {
    mode: Mode,
    names: Names,
    /// The text that has been read and not released, from `head`.
    pending: Vec<u8>,
    head: usize,
    /// Everything before this offset has been released or is inside a span that has.
    frontier: u64,
    /// Spans to replace that are not final yet: sorted by start, disjoint.
    spans: Vec<Span>,
    /// Final spans, in order (collect mode).
    done: Vec<Span>,
    report: ReportBuilder,
    broken: bool,
}

impl Sink {
    pub(super) fn new(mode: Mode, names: Names) -> Self {
        Self {
            mode,
            names,
            pending: Vec::new(),
            head: 0,
            frontier: 0,
            spans: Vec::new(),
            done: Vec::new(),
            report: ReportBuilder::default(),
            broken: false,
        }
    }

    pub(super) fn names(&self) -> &Names {
        &self.names
    }

    /// Overwrites the text that was held back, which may hold a secret that was never released.
    /// A best effort, as noted in `registry`.
    fn wipe(&mut self) {
        self.pending.fill(0);
        std::hint::black_box(&self.pending);
    }

    /// How many bytes are held back.
    pub(super) fn pending_len(&self) -> usize {
        self.pending.len() - self.head
    }

    pub(super) fn has_blocking(&self) -> bool {
        self.report.blocking
    }

    /// Takes the next bytes of the stream. Only the rewriting sink keeps them.
    pub(super) fn append(&mut self, bytes: &[u8]) {
        if self.mode == Mode::Rewrite {
            self.pending.extend_from_slice(bytes);
        }
    }

    /// Takes a span found by a scanner. `replace` says whether it is taken out of the text or
    /// only reported.
    pub(super) fn insert(&mut self, span: Span, replace: bool) {
        if span.end <= span.start {
            return;
        }
        self.report.note(&span);
        if !replace {
            return;
        }
        if span.start < self.frontier {
            // The text before the frontier has been released. A span that starts there means
            // the watermark was wrong. The caller must drop the content.
            self.broken = true;
            return;
        }
        let first = self.spans.partition_point(|s| s.end <= span.start);
        let mut merged = span;
        let mut next = first;
        while let Some(other) = self.spans.get(next) {
            if other.start >= merged.end {
                break;
            }
            merged = merged.merged_with(other);
            next += 1;
        }
        self.spans.splice(first..next, [merged]);
    }

    /// Releases the text before `watermark`, with the spans that end by then replaced.
    ///
    /// # Errors
    /// [`RedactionError::Internal`] when a span began before text that was already released.
    pub(super) fn advance(
        &mut self,
        watermark: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), RedactionError> {
        if self.broken {
            return Err(RedactionError::Internal);
        }
        let final_count = self.spans.iter().take_while(|s| s.end <= watermark).count();
        let finals: Vec<Span> = self.spans.drain(..final_count).collect();
        for span in finals {
            match self.mode {
                Mode::Rewrite => {
                    self.release_until(span.start, out)?;
                    out.extend_from_slice(b"[REDACTED:");
                    out.extend_from_slice(self.names.of(span.source, span.label).as_bytes());
                    out.push(b']');
                    self.skip_until(span.end)?;
                }
                Mode::Collect => self.done.push(span),
                Mode::Discard => {}
            }
            self.report.replaced += 1;
            self.frontier = self.frontier.max(span.end);
        }
        let limit = self
            .spans
            .first()
            .map_or(watermark, |s| s.start.min(watermark));
        if limit > self.frontier {
            if self.mode == Mode::Rewrite {
                self.release_until(limit, out)?;
            }
            self.frontier = limit;
        }
        Ok(())
    }

    /// The end, in `pending`, of the held text that runs up to `offset`.
    fn held_end(&self, offset: u64) -> Result<usize, RedactionError> {
        usize::try_from(offset.saturating_sub(self.frontier))
            .ok()
            .and_then(|count| self.head.checked_add(count))
            .ok_or(RedactionError::Internal)
    }

    /// Copies the held text up to `offset` to `out`.
    fn release_until(&mut self, offset: u64, out: &mut Vec<u8>) -> Result<(), RedactionError> {
        let end = self.held_end(offset)?;
        let held = self
            .pending
            .get(self.head..end)
            .ok_or(RedactionError::Internal)?;
        out.extend_from_slice(held);
        self.head = end;
        self.frontier = offset.max(self.frontier);
        self.compact();
        Ok(())
    }

    /// Drops the held text up to `offset` without writing it.
    fn skip_until(&mut self, offset: u64) -> Result<(), RedactionError> {
        let end = self.held_end(offset)?;
        let held = self
            .pending
            .get_mut(self.head..end)
            .ok_or(RedactionError::Internal)?;
        held.fill(0);
        self.head = end;
        self.frontier = offset.max(self.frontier);
        self.compact();
        Ok(())
    }

    fn compact(&mut self) {
        if self.head >= 16 * 1024 && self.head * 2 >= self.pending.len() {
            self.pending.drain(..self.head);
            self.head = 0;
        }
    }

    /// The report so far.
    pub(super) fn report(&self) -> Report {
        self.report.build(&self.names)
    }

    /// The final spans of collect mode.
    pub(super) fn take_done(&mut self) -> Vec<Span> {
        std::mem::take(&mut self.done)
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        self.wipe();
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
    use crate::redaction::config::PatternAction;
    use crate::redaction::config::PatternSpec;
    use crate::redaction::config::{FlagHandling, Limits};
    use crate::redaction::encodings::Encoding;
    use crate::redaction::patterns::PatternSet;

    fn names() -> Names {
        let core = Core {
            patterns: PatternSet::compile(
                &[
                    PatternSpec::new("first", "FIRSTFIRST", PatternAction::Block),
                    PatternSpec::new("second", "SECONDSECOND", PatternAction::Block),
                ],
                None,
            )
            .unwrap(),
            flagged: FlagHandling::ReportOnly,
            limits: Limits::default(),
            min_len: 8,
            encodings: Encoding::ALL.to_vec(),
        };
        Names {
            core: Arc::new(core),
            snapshot: Arc::new(Snapshot::empty()),
        }
    }

    fn pattern(label: u32, start: u64, end: u64) -> Span {
        Span::new(
            start,
            end,
            FindingSource::Pattern,
            label,
            Severity::Blocking,
        )
    }

    fn rewrite(text: &[u8], spans: &[Span]) -> Vec<u8> {
        let mut sink = Sink::new(Mode::Rewrite, names());
        sink.append(text);
        for s in spans {
            sink.insert(*s, true);
        }
        let mut out = Vec::new();
        sink.advance(text.len() as u64, &mut out).unwrap();
        out
    }

    #[test]
    fn overlapping_spans_become_one_and_touching_spans_do_not() {
        let text = b"0123456789abcdefghij";
        assert_eq!(
            rewrite(text, &[pattern(0, 2, 8), pattern(1, 5, 12)]),
            b"01[REDACTED:first]cdefghij"
        );
        assert_eq!(
            rewrite(text, &[pattern(0, 2, 8), pattern(1, 8, 12)]),
            b"01[REDACTED:first][REDACTED:second]cdefghij"
        );
    }

    #[test]
    fn the_order_in_which_spans_arrive_does_not_change_the_result() {
        let text = b"0123456789abcdefghij";
        let spans = [
            pattern(1, 5, 12),
            pattern(0, 2, 8),
            pattern(1, 10, 15),
            pattern(0, 2, 8),
        ];
        let reference = rewrite(text, &spans);
        let mut shuffled = spans;
        for rotation in 0..spans.len() {
            shuffled.rotate_left(rotation);
            assert_eq!(rewrite(text, &shuffled), reference, "rotation {rotation}");
        }
        assert_eq!(reference, b"01[REDACTED:first]fghij");
    }

    #[test]
    fn text_is_released_only_up_to_the_watermark_and_a_span_only_when_it_is_final() {
        let mut sink = Sink::new(Mode::Rewrite, names());
        let mut out = Vec::new();
        sink.append(b"0123456789");
        sink.insert(pattern(0, 4, 8), true);
        sink.advance(6, &mut out).unwrap();
        // The span is not past the watermark, so only the text before it is out.
        assert_eq!(out, b"0123");
        assert_eq!(sink.pending_len(), 6);
        sink.advance(9, &mut out).unwrap();
        assert_eq!(out, b"0123[REDACTED:first]8");
    }

    #[test]
    fn a_span_that_starts_before_released_text_is_an_internal_error() {
        let mut sink = Sink::new(Mode::Rewrite, names());
        let mut out = Vec::new();
        sink.append(b"0123456789");
        sink.advance(6, &mut out).unwrap();
        sink.insert(pattern(0, 2, 8), true);
        assert_eq!(sink.advance(10, &mut out), Err(RedactionError::Internal));
    }

    #[test]
    fn flags_that_are_only_reported_do_not_touch_the_text_or_merge_with_secrets() {
        let mut sink = Sink::new(Mode::Rewrite, names());
        let mut out = Vec::new();
        sink.append(b"0123456789");
        let flag = Span::new(0, 10, FindingSource::Pattern, 0, Severity::Flag);
        sink.insert(flag, false);
        sink.insert(pattern(1, 4, 8), true);
        sink.advance(10, &mut out).unwrap();
        assert_eq!(out, b"0123[REDACTED:second]89");
        let report = sink.report();
        assert!(report.has_blocking() && report.has_flagged());
        assert_eq!(report.findings().len(), 2);
    }

    #[test]
    fn the_report_lists_at_most_the_first_sixty_four_findings_by_position() {
        let mut sink = Sink::new(Mode::Discard, names());
        for i in (0..200u64).rev() {
            sink.insert(pattern(0, i * 10, i * 10 + 5), true);
        }
        let report = sink.report();
        assert_eq!(report.findings().len(), MAX_LISTED_FINDINGS);
        assert_eq!(report.findings()[0].start, 0);
        assert_eq!(report.findings()[63].start, 630);
    }
}
