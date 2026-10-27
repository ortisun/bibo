//! FX-CANARY: fake secrets made at run time, and a sweeper that finds them anywhere.
//!
//! # Canaries
//!
//! A canary is a fake secret in a real format: a GitHub installation token, a private key block,
//! a webhook secret, a model API key, a database password, a job token, plus a holdout string and
//! a string that belongs to a second tenant. Each is generated when the test runs, so nothing in
//! the repository or its history is a secret, and each carries a recognisable marker (`CANARY`,
//! or `ca4a41` where only hexadecimal digits are allowed) so a person reading a leak knows it is
//! a fake.
//!
//! The values are never printed. `Debug` shows the kind, the label and a short fingerprint, and a
//! [`Hit`] names the canary and the sink, not the secret.
//!
//! # The sweeper
//!
//! The [`Sweeper`] looks for every canary in every spelling a leak can take (see [`Form`]):
//! the raw text; base64 and base64url with and without padding, and base64 of a larger message
//! that merely contains the canary (three byte alignments); hexadecimal; four percent-encoded
//! styles; and three JSON-escaped styles. It looks in two views of the same bytes: the raw bytes,
//! and the bytes with terminal colour codes and zero-width characters removed. It keeps its state
//! between chunks, so a canary cut in half by a chunk boundary is still found.
//!
//! A canary marker with no full match is reported as a [`Form::Fragment`]: a truncated or mangled
//! leak.
//!
//! The sweeper has to be proven before it is trusted. The tests in this file and in
//! [`sinks`](super::sinks) plant a canary in every form and in every sink kind and require a hit,
//! and require a clean report when nothing was planted.

use std::collections::BTreeSet;
use std::fmt;

use super::digest::sha256;
use super::encoding::{
    Base64Alphabet, ControlStripper, JsonStyle, PercentStyle, base64_encode, base64_interior,
    hex_encode, json_escape, percent_encode,
};
use super::rng::{ALPHANUMERIC, BASE64, FxRng, HEX_LOWER, URL_SAFE};

/// The text every generated canary contains, in capitals.
pub const MARKER: &str = "CANARY";
/// The marker for canaries that may hold only hexadecimal digits (`canary` in leetspeak).
pub const HEX_MARKER: &str = "ca4a41";
/// A form shorter than this is not searched for, because a short string matches by accident.
/// The policy uses the same floor for its exact-value registry (`secrets.exact_values.min_length`).
pub const MIN_NEEDLE_LEN: usize = 8;

/// What a canary imitates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanaryKind {
    /// `ghs_` and 36 letters and digits.
    GithubInstallationToken,
    /// A multi-line private key block.
    AppPrivateKey,
    /// 64 hexadecimal digits.
    WebhookSecret,
    /// `sk-ant-` and 40 more characters.
    ModelApiKey,
    /// A password with punctuation, quotes and a backslash, so every escaping form differs.
    DatabasePassword,
    /// `sfjt_` and 40 more characters.
    JobToken,
    /// A string planted in a held-out evaluation file.
    HoldoutString,
    /// A string that belongs to a second tenant.
    SecondTenantString,
    /// A value registered by a test, such as a token the fake GitHub server minted.
    Custom,
}

impl CanaryKind {
    /// The kinds [`CanarySet::generate`] makes, in order.
    pub const GENERATED: [CanaryKind; 8] = [
        CanaryKind::GithubInstallationToken,
        CanaryKind::AppPrivateKey,
        CanaryKind::WebhookSecret,
        CanaryKind::ModelApiKey,
        CanaryKind::DatabasePassword,
        CanaryKind::JobToken,
        CanaryKind::HoldoutString,
        CanaryKind::SecondTenantString,
    ];

    /// The name used in templates (`@@CANARY:<name>@@`), reports and labels.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            CanaryKind::GithubInstallationToken => "github_installation_token",
            CanaryKind::AppPrivateKey => "app_private_key",
            CanaryKind::WebhookSecret => "webhook_secret",
            CanaryKind::ModelApiKey => "model_api_key",
            CanaryKind::DatabasePassword => "database_password",
            CanaryKind::JobToken => "job_token",
            CanaryKind::HoldoutString => "holdout_string",
            CanaryKind::SecondTenantString => "second_tenant_string",
            CanaryKind::Custom => "custom",
        }
    }

    /// The kind with this template name, if any. `custom` is not a template name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<CanaryKind> {
        CanaryKind::GENERATED.into_iter().find(|k| k.name() == name)
    }
}

/// One fake secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Canary {
    kind: CanaryKind,
    label: String,
    value: String,
}

impl Canary {
    /// Makes a canary of `kind` in its real format.
    ///
    /// # Panics
    /// Panics when `kind` is [`CanaryKind::Custom`], which has no format to generate. Use
    /// [`Canary::custom`].
    #[must_use]
    pub fn generate(kind: CanaryKind, rng: &mut FxRng) -> Self {
        let value = match kind {
            CanaryKind::GithubInstallationToken => {
                format!("ghs_{MARKER}{}", rng.string_from(ALPHANUMERIC, 30))
            }
            CanaryKind::AppPrivateKey => private_key_block(rng),
            CanaryKind::WebhookSecret => {
                format!("{HEX_MARKER}{}", rng.string_from(HEX_LOWER, 58))
            }
            CanaryKind::ModelApiKey => {
                format!("sk-ant-{MARKER}{}", rng.string_from(URL_SAFE, 34))
            }
            CanaryKind::DatabasePassword => {
                // Punctuation that needs percent-encoding, a quote and a backslash that need JSON
                // escaping, and a slash that some JSON encoders escape.
                const PASSWORD: &[u8] =
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#%&*+=/?:;\"\\";
                format!("{MARKER}-{}", rng.string_from(PASSWORD, 17))
            }
            CanaryKind::JobToken => format!("sfjt_{MARKER}{}", rng.string_from(URL_SAFE, 34)),
            CanaryKind::HoldoutString => {
                format!("{MARKER}-HOLDOUT-{}", rng.string_from(HEX_LOWER, 16))
            }
            CanaryKind::SecondTenantString => {
                format!("{MARKER}-TENANT-B-{}", rng.string_from(HEX_LOWER, 16))
            }
            CanaryKind::Custom => panic!("a custom canary has no format; use Canary::custom"),
        };
        Self {
            kind,
            label: kind.name().to_owned(),
            value,
        }
    }

    /// Registers a value a test already has, such as a token the fake server minted, so the
    /// sweeper looks for it too. Do not register a real secret: the value would reach the test
    /// output if the sweep fails, and a real secret in a test run is a defect in the test.
    #[must_use]
    pub fn custom(label: &str, value: &str) -> Self {
        Self {
            kind: CanaryKind::Custom,
            label: label.to_owned(),
            value: value.to_owned(),
        }
    }

    /// What this canary imitates.
    #[must_use]
    pub fn kind(&self) -> CanaryKind {
        self.kind
    }

    /// A short name for reports.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The fake secret itself. Test code that plants it in a sink calls this. Nothing prints it.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Eight hexadecimal digits of the SHA-256 of the value. Two reports about the same canary
    /// show the same fingerprint, and the fingerprint reveals nothing about the value.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        hex_encode(&sha256(self.value.as_bytes())[..4], false)
    }

    /// True when the value holds the run-time marker. Every generated canary does.
    #[must_use]
    pub fn has_marker(&self) -> bool {
        self.value.contains(MARKER) || self.value.contains(HEX_MARKER)
    }
}

impl fmt::Debug for Canary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Canary({}, {}, len {}, fp {})",
            self.kind.name(),
            self.label,
            self.value.len(),
            self.fingerprint()
        )
    }
}

/// The header and footer of a PEM block are built from parts so that this source file never holds
/// the contiguous text that the repository's secret scan looks for.
fn private_key_block(rng: &mut FxRng) -> String {
    const LABEL: &str = "PRIVATE KEY";
    let mut block = format!("-----BEGIN {LABEL}-----\n");
    for line in 0..6 {
        let body = if line == 0 {
            format!("{MARKER}{}", rng.string_from(BASE64, 58))
        } else {
            rng.string_from(BASE64, 64)
        };
        block.push_str(&body);
        block.push('\n');
    }
    block.push_str(&format!("-----END {LABEL}-----"));
    block
}

/// A full set of canaries for one test run.
#[derive(Debug, Clone)]
pub struct CanarySet {
    canaries: Vec<Canary>,
}

impl CanarySet {
    /// One canary of every generated kind, from a fresh random source.
    #[must_use]
    pub fn generate() -> Self {
        Self::generate_with(&mut FxRng::from_entropy())
    }

    /// One canary of every generated kind, from the given source. The same seed gives the same set.
    #[must_use]
    pub fn generate_with(rng: &mut FxRng) -> Self {
        Self {
            canaries: CanaryKind::GENERATED
                .into_iter()
                .map(|kind| Canary::generate(kind, rng))
                .collect(),
        }
    }

    /// The canary of this generated kind.
    ///
    /// # Panics
    /// Panics for [`CanaryKind::Custom`]; ask for a custom canary by label with [`Self::by_label`].
    #[must_use]
    pub fn get(&self, kind: CanaryKind) -> &Canary {
        self.canaries
            .iter()
            .find(|c| c.kind == kind)
            .unwrap_or_else(|| panic!("the set has no canary of kind {}", kind.name()))
    }

    /// The canary with this label.
    #[must_use]
    pub fn by_label(&self, label: &str) -> Option<&Canary> {
        self.canaries.iter().find(|c| c.label == label)
    }

    /// Adds a registered value to the set.
    #[must_use]
    pub fn with(mut self, canary: Canary) -> Self {
        self.canaries.push(canary);
        self
    }

    /// Every canary, in order.
    pub fn iter(&self) -> impl Iterator<Item = &Canary> {
        self.canaries.iter()
    }

    /// The number of canaries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.canaries.len()
    }

    /// True for a set with no canary.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.canaries.is_empty()
    }
}

/// A spelling in which a leaked secret can appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Form {
    /// The value as written.
    Raw,
    /// Standard base64 with padding.
    Base64Std,
    /// Standard base64 without padding.
    Base64StdNoPad,
    /// URL-safe base64 with padding.
    Base64Url,
    /// URL-safe base64 without padding.
    Base64UrlNoPad,
    /// Standard base64 of a larger message, with the value at byte offset 0 modulo 3.
    Base64StdInside0,
    /// As above, offset 1 modulo 3.
    Base64StdInside1,
    /// As above, offset 2 modulo 3.
    Base64StdInside2,
    /// URL-safe base64 of a larger message, offset 0 modulo 3.
    Base64UrlInside0,
    /// As above, offset 1 modulo 3.
    Base64UrlInside1,
    /// As above, offset 2 modulo 3.
    Base64UrlInside2,
    /// Lowercase hexadecimal.
    HexLower,
    /// Uppercase hexadecimal.
    HexUpper,
    /// Percent-encoding with uppercase digits, as a URL builder writes it.
    PercentUpper,
    /// Percent-encoding with lowercase digits.
    PercentLower,
    /// Form encoding, where a space is `+`.
    PercentFormPlus,
    /// Every byte percent-encoded, letters and digits too.
    PercentEveryByte,
    /// Escaped for a JSON string.
    JsonEscaped,
    /// Escaped for a JSON string by an encoder that also escapes `/`.
    JsonEscapedSlash,
    /// Escaped for a JSON string that sits inside another JSON string.
    JsonEscapedTwice,
    /// Only the marker was found: a truncated or mangled leak.
    Fragment,
}

impl Form {
    /// Every form that is a spelling of the full value, in the order the sweeper tries them.
    pub const ALL: [Form; 20] = [
        Form::Raw,
        Form::Base64Std,
        Form::Base64StdNoPad,
        Form::Base64Url,
        Form::Base64UrlNoPad,
        Form::Base64StdInside0,
        Form::Base64StdInside1,
        Form::Base64StdInside2,
        Form::Base64UrlInside0,
        Form::Base64UrlInside1,
        Form::Base64UrlInside2,
        Form::HexLower,
        Form::HexUpper,
        Form::PercentUpper,
        Form::PercentLower,
        Form::PercentFormPlus,
        Form::PercentEveryByte,
        Form::JsonEscaped,
        Form::JsonEscapedSlash,
        Form::JsonEscapedTwice,
    ];

    /// The name used in reports.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Form::Raw => "raw",
            Form::Base64Std => "base64",
            Form::Base64StdNoPad => "base64_no_pad",
            Form::Base64Url => "base64url",
            Form::Base64UrlNoPad => "base64url_no_pad",
            Form::Base64StdInside0 => "base64_inside_0",
            Form::Base64StdInside1 => "base64_inside_1",
            Form::Base64StdInside2 => "base64_inside_2",
            Form::Base64UrlInside0 => "base64url_inside_0",
            Form::Base64UrlInside1 => "base64url_inside_1",
            Form::Base64UrlInside2 => "base64url_inside_2",
            Form::HexLower => "hex_lower",
            Form::HexUpper => "hex_upper",
            Form::PercentUpper => "percent_upper",
            Form::PercentLower => "percent_lower",
            Form::PercentFormPlus => "percent_form_plus",
            Form::PercentEveryByte => "percent_every_byte",
            Form::JsonEscaped => "json_escaped",
            Form::JsonEscapedSlash => "json_escaped_slash",
            Form::JsonEscapedTwice => "json_escaped_twice",
            Form::Fragment => "fragment",
        }
    }

    /// The bytes of `value` written in this form, or `None` for [`Form::Fragment`].
    #[must_use]
    pub fn encode(self, value: &str) -> Option<Vec<u8>> {
        let bytes = value.as_bytes();
        let text = match self {
            Form::Raw => return Some(bytes.to_vec()),
            Form::Base64Std => base64_encode(bytes, Base64Alphabet::Standard, true),
            Form::Base64StdNoPad => base64_encode(bytes, Base64Alphabet::Standard, false),
            Form::Base64Url => base64_encode(bytes, Base64Alphabet::UrlSafe, true),
            Form::Base64UrlNoPad => base64_encode(bytes, Base64Alphabet::UrlSafe, false),
            Form::Base64StdInside0 => base64_interior(bytes, Base64Alphabet::Standard, 0),
            Form::Base64StdInside1 => base64_interior(bytes, Base64Alphabet::Standard, 1),
            Form::Base64StdInside2 => base64_interior(bytes, Base64Alphabet::Standard, 2),
            Form::Base64UrlInside0 => base64_interior(bytes, Base64Alphabet::UrlSafe, 0),
            Form::Base64UrlInside1 => base64_interior(bytes, Base64Alphabet::UrlSafe, 1),
            Form::Base64UrlInside2 => base64_interior(bytes, Base64Alphabet::UrlSafe, 2),
            Form::HexLower => hex_encode(bytes, false),
            Form::HexUpper => hex_encode(bytes, true),
            Form::PercentUpper => percent_encode(bytes, PercentStyle::Upper),
            Form::PercentLower => percent_encode(bytes, PercentStyle::Lower),
            Form::PercentFormPlus => percent_encode(bytes, PercentStyle::FormPlus),
            Form::PercentEveryByte => percent_encode(bytes, PercentStyle::EveryByte),
            Form::JsonEscaped => json_escape(value, JsonStyle::Minimal),
            Form::JsonEscapedSlash => json_escape(value, JsonStyle::EscapedSlash),
            Form::JsonEscapedTwice => {
                json_escape(&json_escape(value, JsonStyle::Minimal), JsonStyle::Minimal)
            }
            Form::Fragment => return None,
        };
        Some(text.into_bytes())
    }
}

impl fmt::Display for Form {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Which view of the bytes held the match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum View {
    /// The bytes as they came.
    Raw,
    /// The bytes with terminal control sequences and invisible characters removed.
    Stripped,
}

impl View {
    fn name(self) -> &'static str {
        match self {
            View::Raw => "raw",
            View::Stripped => "stripped",
        }
    }
}

/// One canary found in one sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The sink the bytes came from.
    pub sink: String,
    /// The label of the canary.
    pub canary: String,
    /// What the canary imitates.
    pub kind: CanaryKind,
    /// The spelling that matched.
    pub form: Form,
    /// The view that held it.
    pub view: View,
    /// The byte offset of the match in that view, counted from the start of the sink.
    pub offset: usize,
}

impl fmt::Display for Hit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "canary {} ({}) found in sink {} as {} in the {} view at byte {}",
            self.canary,
            self.kind.name(),
            self.sink,
            self.form,
            self.view.name(),
            self.offset
        )
    }
}

#[derive(Debug, Clone)]
struct Needle {
    label: String,
    kind: CanaryKind,
    form: Form,
    bytes: Vec<u8>,
}

/// Looks for canaries.
#[derive(Debug, Clone)]
pub struct Sweeper {
    needles: Vec<Needle>,
    longest: usize,
    marker_scan: bool,
}

impl Sweeper {
    /// A sweeper for every canary in the set, in every form.
    #[must_use]
    pub fn new(canaries: &CanarySet) -> Self {
        let mut sweeper = Self {
            needles: Vec::new(),
            longest: MARKER.len(),
            marker_scan: true,
        };
        for canary in canaries.iter() {
            sweeper.add(canary);
        }
        sweeper
    }

    /// Also looks for this canary, for example a token minted during the test.
    pub fn add(&mut self, canary: &Canary) {
        for form in Form::ALL {
            let Some(bytes) = form.encode(canary.value()) else {
                continue;
            };
            if bytes.len() < MIN_NEEDLE_LEN {
                continue;
            }
            // Two forms that spell the value the same way are one needle, labelled with the
            // simpler form, so a plain leak is reported as `raw`.
            if self
                .needles
                .iter()
                .any(|n| n.label == canary.label() && n.bytes == bytes)
            {
                continue;
            }
            self.longest = self.longest.max(bytes.len());
            self.needles.push(Needle {
                label: canary.label().to_owned(),
                kind: canary.kind(),
                form,
                bytes,
            });
        }
    }

    /// A sweeper that does not know the given forms. Tests use this to show that a weaker sweeper
    /// would miss a leak, which proves the strong one is doing the work.
    #[must_use]
    pub fn without_forms(mut self, forms: &[Form]) -> Self {
        self.needles.retain(|n| !forms.contains(&n.form));
        self
    }

    /// Switches the marker-only check on or off. It is on by default.
    #[must_use]
    pub fn with_marker_scan(mut self, on: bool) -> Self {
        self.marker_scan = on;
        self
    }

    /// How many distinct byte strings the sweeper searches for.
    #[must_use]
    pub fn needle_count(&self) -> usize {
        self.needles.len()
    }

    /// Looks in one buffer.
    #[must_use]
    pub fn scan(&self, sink: &str, data: &[u8]) -> Vec<Hit> {
        self.scan_chunks(sink, [data])
    }

    /// Looks in a stream that arrived in these chunks, as if they were one buffer.
    #[must_use]
    pub fn scan_chunks<'a>(
        &self,
        sink: &str,
        chunks: impl IntoIterator<Item = &'a [u8]>,
    ) -> Vec<Hit> {
        let mut stream = self.stream(sink);
        for chunk in chunks {
            stream.push(chunk);
        }
        stream.finish()
    }

    /// Starts a stream scan. Feed it chunks with [`StreamSweep::push`] and end it with
    /// [`StreamSweep::finish`].
    #[must_use]
    pub fn stream(&self, sink: &str) -> StreamSweep<'_> {
        StreamSweep {
            sweeper: self,
            sink: sink.to_owned(),
            raw: ViewBuffer::default(),
            stripped: ViewBuffer::default(),
            stripper: ControlStripper::new(),
            found: BTreeSet::new(),
            hits: Vec::new(),
            marker_at: None,
        }
    }
}

#[derive(Debug, Default)]
struct ViewBuffer {
    /// The unscanned tail of an earlier chunk, then the new chunk.
    buffer: Vec<u8>,
    /// How many bytes of this view were dropped from the front of `buffer`.
    dropped: usize,
}

/// A scan in progress over a stream of chunks.
#[derive(Debug)]
pub struct StreamSweep<'a> {
    sweeper: &'a Sweeper,
    sink: String,
    raw: ViewBuffer,
    stripped: ViewBuffer,
    stripper: ControlStripper,
    found: BTreeSet<usize>,
    hits: Vec<Hit>,
    marker_at: Option<(View, usize)>,
}

impl StreamSweep<'_> {
    /// Adds the next chunk of the stream.
    pub fn push(&mut self, chunk: &[u8]) {
        let old = self.raw.buffer.len();
        self.raw.buffer.extend_from_slice(chunk);
        self.scan_view(View::Raw, old);
        let old = self.stripped.buffer.len();
        self.stripper.push(chunk, &mut self.stripped.buffer);
        self.scan_view(View::Stripped, old);
    }

    /// Ends the stream and returns what was found, in the order it was found.
    #[must_use]
    pub fn finish(mut self) -> Vec<Hit> {
        let old = self.stripped.buffer.len();
        self.stripper.finish(&mut self.stripped.buffer);
        self.scan_view(View::Stripped, old);
        if self.sweeper.marker_scan
            && self.hits.is_empty()
            && let Some((view, offset)) = self.marker_at
        {
            self.hits.push(Hit {
                sink: self.sink.clone(),
                canary: "marker".to_owned(),
                kind: CanaryKind::Custom,
                form: Form::Fragment,
                view,
                offset,
            });
        }
        self.hits
    }

    /// Searches the bytes added since the last scan. `old_len` is how many bytes of `buffer` were
    /// already searched. A match that was not there before must end in the new bytes, so the
    /// search starts `needle length - 1` bytes before them.
    fn scan_view(&mut self, view: View, old_len: usize) {
        let buffer = match view {
            View::Raw => &mut self.raw,
            View::Stripped => &mut self.stripped,
        };
        for (index, needle) in self.sweeper.needles.iter().enumerate() {
            if self.found.contains(&index) {
                continue;
            }
            let from = old_len.saturating_sub(needle.bytes.len() - 1);
            if let Some(at) = find(&buffer.buffer[from..], &needle.bytes) {
                self.found.insert(index);
                self.hits.push(Hit {
                    sink: self.sink.clone(),
                    canary: needle.label.clone(),
                    kind: needle.kind,
                    form: needle.form,
                    view,
                    offset: buffer.dropped + from + at,
                });
            }
        }
        if self.sweeper.marker_scan && self.marker_at.is_none() {
            let from = old_len.saturating_sub(MARKER.len() - 1);
            if let Some(at) = find(&buffer.buffer[from..], MARKER.as_bytes()) {
                self.marker_at = Some((view, buffer.dropped + from + at));
            }
        }
        // Keep the last bytes that could be the start of a match that the next chunk finishes.
        let keep = self.sweeper.longest.saturating_sub(1);
        if buffer.buffer.len() > keep {
            let cut = buffer.buffer.len() - keep;
            buffer.buffer.drain(..cut);
            buffer.dropped += cut;
        }
    }
}

/// The offset of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let (&first, rest) = needle.split_first()?;
    let mut from = 0;
    while let Some(position) = haystack[from..].iter().position(|&b| b == first) {
        let start = from + position;
        let end = start + needle.len();
        if end > haystack.len() {
            return None;
        }
        if &haystack[start + 1..end] == rest {
            return Some(start);
        }
        from = start + 1;
    }
    None
}

/// What a sweep of many sinks found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Every hit, in sink order.
    pub hits: Vec<Hit>,
    /// How many sinks were searched.
    pub sinks_scanned: usize,
    /// How many bytes were searched, counting each sink once.
    pub bytes_scanned: usize,
}

impl SweepReport {
    /// True when nothing was found.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.hits.is_empty()
    }

    /// True when a canary of this kind was found anywhere.
    #[must_use]
    pub fn found(&self, kind: CanaryKind) -> bool {
        self.hits.iter().any(|h| h.kind == kind)
    }

    /// The hits in one sink.
    #[must_use]
    pub fn in_sink(&self, sink: &str) -> Vec<&Hit> {
        self.hits.iter().filter(|h| h.sink == sink).collect()
    }

    /// Fails the test, listing every hit without its value, when anything was found.
    ///
    /// # Panics
    /// Panics when the report is not clean.
    pub fn assert_clean(&self) {
        assert!(
            self.is_clean(),
            "the canary sweep found {} leak(s) in {} sink(s):\n{}",
            self.hits.len(),
            self.sinks_scanned,
            self.hits
                .iter()
                .map(|h| format!("  {h}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

#[cfg(test)]
mod tests;
