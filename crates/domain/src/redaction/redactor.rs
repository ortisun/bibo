//! The redactor: the one component every sink uses to keep secrets out of what it stores or
//! sends.
//!
//! See the module documentation of `redaction` for what it does and does not promise.

use std::borrow::Cow;
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use super::config::{EntropySpec, FlagHandling, Limits, PatternAction, PatternSpec};
use super::core::Core;
use super::encodings::Encoding;
use super::error::{BuildError, RedactionError, RegistryError};
use super::patterns::PatternSet;
use super::registry::{Registered, Registry, SecretHandle, Snapshot};
use super::report::Report;
use super::scan::{BLOCK, Context, Engine, LOOKAHEAD, Span};
use super::sink::{Mode, Names, Sink};

/// How many bytes of a chunk are taken in one step. A step never holds more than this on top
/// of what the stream is holding back.
const SEGMENT: usize = 8192;

/// The least a pending limit can be. A stream always holds back about one block and its
/// look-ahead, so a smaller limit would refuse every stream.
const MIN_PENDING_LIMIT: usize = 3 * ((BLOCK + LOOKAHEAD) as usize);

/// The output of [`Redactor::redact`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted<'a> {
    /// The text with every secret replaced. Borrowed, not copied, when nothing was replaced.
    pub output: Cow<'a, [u8]>,
    /// What was found.
    pub report: Report,
}

/// The output of [`Redactor::redact_str`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedStr<'a> {
    /// The text with every secret replaced. Borrowed, not copied, when nothing was replaced.
    pub output: Cow<'a, str>,
    /// What was found.
    pub report: Report,
}

/// Builds a [`Redactor`].
///
/// With no settings the redactor has no pattern and registers exact values in every encoding,
/// from eight bytes up. The composition root passes the patterns of `policies/security.yaml`.
#[derive(Debug, Clone)]
pub struct RedactorBuilder {
    patterns: Vec<PatternSpec>,
    entropy: Option<EntropySpec>,
    min_len: usize,
    encodings: Vec<Encoding>,
    flagged: FlagHandling,
    limits: Limits,
}

impl RedactorBuilder {
    fn new() -> Self {
        Self {
            patterns: Vec::new(),
            entropy: None,
            min_len: 8,
            encodings: Encoding::ALL.to_vec(),
            flagged: FlagHandling::ReportOnly,
            limits: Limits::default(),
        }
    }

    /// Adds one pattern. Patterns are tried in the order they are added, and that order decides
    /// the name of a marker when two patterns match the same text.
    #[must_use]
    pub fn pattern(mut self, id: &str, regex: &str, action: PatternAction) -> Self {
        self.patterns.push(PatternSpec::new(id, regex, action));
        self
    }

    /// Adds patterns, in order.
    #[must_use]
    pub fn patterns(mut self, specs: impl IntoIterator<Item = PatternSpec>) -> Self {
        self.patterns.extend(specs);
        self
    }

    /// Turns the entropy heuristic on.
    #[must_use]
    pub fn entropy(mut self, spec: EntropySpec) -> Self {
        self.entropy = Some(spec);
        self
    }

    /// The shortest secret that is registered, in bytes. The policy says 8.
    #[must_use]
    pub fn exact_value_min_len(mut self, min_len: usize) -> Self {
        self.min_len = min_len;
        self
    }

    /// The encodings in which registered secrets are looked for. The policy lists all of them.
    #[must_use]
    pub fn encodings(mut self, encodings: &[Encoding]) -> Self {
        self.encodings = encodings.to_vec();
        self
    }

    /// What to do with matches whose action is `flag`.
    #[must_use]
    pub fn flagged(mut self, handling: FlagHandling) -> Self {
        self.flagged = handling;
        self
    }

    /// The size limits.
    #[must_use]
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Compiles the patterns and builds the redactor. Nothing is read from a file or the
    /// environment.
    ///
    /// # Errors
    /// A [`BuildError`] when a pattern or the entropy settings cannot be used.
    pub fn build(self) -> Result<Redactor, BuildError> {
        let patterns = PatternSet::compile(&self.patterns, self.entropy)?;
        let limits = Limits {
            max_pending_bytes: self.limits.max_pending_bytes.max(MIN_PENDING_LIMIT),
            ..self.limits
        };
        Ok(Redactor {
            inner: Arc::new(Inner {
                core: Arc::new(Core {
                    patterns,
                    flagged: self.flagged,
                    limits,
                    min_len: self.min_len.max(1),
                    encodings: self.encodings,
                }),
                registry: RwLock::new(Registry::new()),
            }),
        })
    }
}

struct Inner {
    core: Arc<Core>,
    registry: RwLock<Registry>,
}

/// Removes secrets from text and says whether text holds one.
///
/// One redactor serves every sink. It is cheap to clone: clones share the patterns and the
/// registry, and it can be used from many threads at once.
#[derive(Clone)]
pub struct Redactor {
    inner: Arc<Inner>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Redactor")
            .field("patterns", &self.inner.core.patterns.patterns.len())
            .field("registered_secrets", &self.registered_count())
            .finish()
    }
}

impl Redactor {
    /// Starts a builder.
    #[must_use]
    pub fn builder() -> RedactorBuilder {
        RedactorBuilder::new()
    }

    /// The identifiers of the patterns, in the order they were given.
    #[must_use]
    pub fn pattern_ids(&self) -> Vec<String> {
        self.inner
            .core
            .patterns
            .patterns
            .iter()
            .map(|p| p.id.to_string())
            .collect()
    }

    /// Registers a secret value of the factory so that it is found in every encoding. `label`
    /// names it in the marker `[REDACTED:<label>]`; several secrets may share a label.
    ///
    /// A stream sees the secrets that were registered before it started. A value that was
    /// already written out is not recalled.
    ///
    /// # Errors
    /// A [`RegistryError`] when the label or the value cannot be used.
    pub fn register(
        &self,
        label: &str,
        value: impl AsRef<[u8]>,
    ) -> Result<Registered, RegistryError> {
        let mut registry = self
            .inner
            .registry
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        registry.register(&self.inner.core, label, value.as_ref())
    }

    /// Forgets a registered secret, for example a job token after the job ended. True when the
    /// handle was still registered.
    pub fn forget(&self, handle: SecretHandle) -> bool {
        let mut registry = self
            .inner
            .registry
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        registry.forget(&self.inner.core, handle)
    }

    /// How many secrets are registered.
    #[must_use]
    pub fn registered_count(&self) -> usize {
        self.inner
            .registry
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        self.inner
            .registry
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .snapshot()
    }

    fn pipeline(&self, mode: Mode) -> Pipeline {
        Pipeline::new(Arc::clone(&self.inner.core), self.snapshot(), mode)
    }

    fn check_size(&self, len: usize) -> Result<(), RedactionError> {
        let max = self.inner.core.limits.max_input_bytes;
        if len > max {
            Err(RedactionError::InputTooLarge { max })
        } else {
            Ok(())
        }
    }

    /// Replaces every secret in `input` with a marker and reports what it found.
    ///
    /// The text is returned as it came, borrowed, when it holds nothing to replace.
    ///
    /// # Errors
    /// A [`RedactionError`]. The caller must then drop the content: the policy says raw text is
    /// never written because the redactor failed.
    pub fn redact<'a>(&self, input: &'a [u8]) -> Result<Redacted<'a>, RedactionError> {
        self.check_size(input.len())?;
        let (report, spans, names) = self.collect(input)?;
        if spans.is_empty() {
            return Ok(Redacted {
                output: Cow::Borrowed(input),
                report,
            });
        }
        let edits: Vec<(usize, usize, String)> = spans
            .iter()
            .map(|s| {
                (
                    usize::try_from(s.start).unwrap_or(usize::MAX),
                    usize::try_from(s.end).unwrap_or(usize::MAX),
                    names.of(s.source, s.label),
                )
            })
            .collect();
        let output = splice(input, &edits)?;
        Ok(Redacted {
            output: Cow::Owned(output),
            report,
        })
    }

    /// Replaces every secret in `input`, as [`Redactor::redact`] does, for text. A replaced
    /// span never cuts a character in two, so the result is valid text.
    ///
    /// # Errors
    /// A [`RedactionError`]; the caller must then drop the content.
    pub fn redact_str<'a>(&self, input: &'a str) -> Result<RedactedStr<'a>, RedactionError> {
        self.check_size(input.len())?;
        let (report, spans, names) = self.collect(input.as_bytes())?;
        if spans.is_empty() {
            return Ok(RedactedStr {
                output: Cow::Borrowed(input),
                report,
            });
        }
        let mut edits: Vec<(usize, usize, String)> = Vec::with_capacity(spans.len());
        for span in &spans {
            let mut start = usize::try_from(span.start).unwrap_or(usize::MAX);
            let mut end = usize::try_from(span.end).unwrap_or(usize::MAX);
            while start > 0 && !input.is_char_boundary(start) {
                start -= 1;
            }
            while end < input.len() && !input.is_char_boundary(end) {
                end += 1;
            }
            edits.push((start, end, names.of(span.source, span.label)));
        }
        let output = String::from_utf8(splice(input.as_bytes(), &edits)?)
            .map_err(|_| RedactionError::Internal)?;
        Ok(RedactedStr {
            output: Cow::Owned(output),
            report,
        })
    }

    fn collect(&self, input: &[u8]) -> Result<(Report, Vec<Span>, Names), RedactionError> {
        let mut pipeline = self.pipeline(Mode::Collect);
        let mut unused = Vec::new();
        pipeline.push(input, &mut unused)?;
        pipeline.finish(&mut unused)?;
        let report = pipeline.sink.report();
        let spans = pipeline.sink.take_done();
        Ok((report, spans, pipeline.sink.names().clone()))
    }

    /// Reports what `input` holds, without producing the redacted text.
    ///
    /// # Errors
    /// A [`RedactionError`].
    pub fn scan(&self, input: &[u8]) -> Result<Report, RedactionError> {
        self.check_size(input.len())?;
        let mut pipeline = self.pipeline(Mode::Discard);
        let mut unused = Vec::new();
        pipeline.push(input, &mut unused)?;
        pipeline.finish(&mut unused)?;
        Ok(pipeline.sink.report())
    }

    /// True when `input` holds a secret: a registered value, in any encoding, or a match of a
    /// pattern whose action is block. A flag does not count. This is the check for a sink that
    /// refuses to publish: the pull request text, an artifact, a domain event.
    ///
    /// # Errors
    /// A [`RedactionError`]. The caller must then refuse the content as well.
    pub fn contains_secret(&self, input: &[u8]) -> Result<bool, RedactionError> {
        self.check_size(input.len())?;
        let mut pipeline = self.pipeline(Mode::Discard);
        let mut unused = Vec::new();
        for segment in input.chunks(SEGMENT) {
            pipeline.push(segment, &mut unused)?;
            if pipeline.sink.has_blocking() {
                return Ok(true);
            }
        }
        pipeline.finish(&mut unused)?;
        Ok(pipeline.sink.has_blocking())
    }

    /// Starts redacting a stream. The stream sees the secrets registered before this call.
    #[must_use]
    pub fn stream(&self) -> RedactStream {
        RedactStream {
            pipeline: self.pipeline(Mode::Rewrite),
        }
    }

    /// Starts scanning a stream, such as an artifact too large to hold. It keeps no text.
    #[must_use]
    pub fn scan_stream(&self) -> ScanStream {
        ScanStream {
            pipeline: self.pipeline(Mode::Discard),
        }
    }
}

/// Writes `input` with each `(start, end)` range replaced by its marker. The ranges are in
/// order. A range that starts inside the previous one is part of it.
fn splice(input: &[u8], edits: &[(usize, usize, String)]) -> Result<Vec<u8>, RedactionError> {
    let mut out = Vec::with_capacity(input.len() + 64);
    let mut at = 0usize;
    for (start, end, name) in edits {
        let (start, end) = (*start, (*end).min(input.len()));
        if start >= at {
            out.extend_from_slice(input.get(at..start).ok_or(RedactionError::Internal)?);
            out.extend_from_slice(b"[REDACTED:");
            out.extend_from_slice(name.as_bytes());
            out.push(b']');
        }
        at = at.max(end);
    }
    out.extend_from_slice(input.get(at..).ok_or(RedactionError::Internal)?);
    Ok(out)
}

/// The scanners and the sink for one input or stream.
struct Pipeline {
    core: Arc<Core>,
    snapshot: Arc<Snapshot>,
    engine: Engine,
    sink: Sink,
    scratch: Vec<Span>,
    failed: bool,
}

impl Pipeline {
    fn new(core: Arc<Core>, snapshot: Arc<Snapshot>, mode: Mode) -> Self {
        let names = Names {
            core: Arc::clone(&core),
            snapshot: Arc::clone(&snapshot),
        };
        Self {
            engine: Engine::new(&core),
            sink: Sink::new(mode, names),
            core,
            snapshot,
            scratch: Vec::new(),
            failed: false,
        }
    }

    fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), RedactionError> {
        if self.failed {
            return Err(RedactionError::StreamFailed);
        }
        for segment in chunk.chunks(SEGMENT) {
            if let Err(e) = self.step(segment, out) {
                self.failed = true;
                return Err(e);
            }
        }
        Ok(())
    }

    fn step(&mut self, segment: &[u8], out: &mut Vec<u8>) -> Result<(), RedactionError> {
        self.sink.append(segment);
        let ctx = Context {
            core: &self.core,
            snapshot: &self.snapshot,
        };
        self.engine.feed(&ctx, segment, &mut self.scratch);
        for span in self.scratch.drain(..) {
            self.sink.insert(span, self.core.replaces(span.severity));
        }
        self.sink.advance(self.engine.watermark(&ctx), out)?;
        let max = self.core.limits.max_pending_bytes;
        if self.sink.pending_len() > max {
            return Err(RedactionError::PendingTooLarge { max });
        }
        Ok(())
    }

    fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), RedactionError> {
        if self.failed {
            return Err(RedactionError::StreamFailed);
        }
        self.failed = true;
        let ctx = Context {
            core: &self.core,
            snapshot: &self.snapshot,
        };
        self.engine.finish(&ctx, &mut self.scratch);
        for span in self.scratch.drain(..) {
            self.sink.insert(span, self.core.replaces(span.severity));
        }
        self.sink.advance(self.engine.consumed(), out)
    }
}

/// A redaction in progress over a stream.
///
/// Push the chunks in order. The output of each push is whatever text is now certain; the rest
/// is held back, a few KiB at most for ordinary text, until later bytes show whether it is part
/// of a secret. [`RedactStream::finish`] releases the rest. The output is the same whatever the
/// chunks were.
pub struct RedactStream {
    pipeline: Pipeline,
}

impl fmt::Debug for RedactStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedactStream")
            .field("pending_bytes", &self.pending_bytes())
            .field("failed", &self.pipeline.failed)
            .finish()
    }
}

impl RedactStream {
    /// Feeds a chunk. Output that is ready is appended to `out`.
    ///
    /// # Errors
    /// A [`RedactionError`]. The stream accepts nothing more, and the caller must drop the
    /// content.
    pub fn push(&mut self, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), RedactionError> {
        self.pipeline.push(chunk, out)
    }

    /// Ends the stream, appends the rest of the output to `out` and reports what was found.
    ///
    /// # Errors
    /// A [`RedactionError`]; the caller must drop the content.
    pub fn finish(mut self, out: &mut Vec<u8>) -> Result<Report, RedactionError> {
        self.pipeline.finish(out)?;
        Ok(self.pipeline.sink.report())
    }

    /// How many bytes of the stream are held back now.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.pipeline.sink.pending_len()
    }
}

/// A scan in progress over a stream. It keeps no text, so it can check an artifact of any size.
pub struct ScanStream {
    pipeline: Pipeline,
}

impl fmt::Debug for ScanStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanStream")
            .field("blocking", &self.has_blocking())
            .finish()
    }
}

impl ScanStream {
    /// Feeds a chunk.
    ///
    /// # Errors
    /// A [`RedactionError`]; the stream accepts nothing more.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), RedactionError> {
        let mut unused = Vec::new();
        self.pipeline.push(chunk, &mut unused)
    }

    /// True when a secret has been found in what was pushed so far. A caller that only needs to
    /// refuse may stop at the first chunk that makes this true.
    #[must_use]
    pub fn has_blocking(&self) -> bool {
        self.pipeline.sink.has_blocking()
    }

    /// Ends the stream and reports what was found.
    ///
    /// # Errors
    /// A [`RedactionError`].
    pub fn finish(mut self) -> Result<Report, RedactionError> {
        let mut unused = Vec::new();
        self.pipeline.finish(&mut unused)?;
        Ok(self.pipeline.sink.report())
    }
}
