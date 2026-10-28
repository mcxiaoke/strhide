//! Host file format adapters: one [`HostAdapter`] implementation per carrier.
//!
//! Each adapter knows how to:
//!
//! - recognize its container format ([`HostAdapter::detect`]);
//! - list the injection strategies it supports;
//! - **inject** a UBE envelope into a fresh copy of the carrier
//!   ([`HostAdapter::inject`]);
//! - **locate** an envelope in an existing carrier ([`HostAdapter::locate`]);
//! - **strip** the envelope and restore the original bytes
//!   ([`HostAdapter::strip`]);
//! - answer how much data each strategy can hold
//!   ([`HostAdapter::strategy_capacities`]).
//!
//! The [`crate::structure::engine`] never parses a container itself — it calls into the
//! adapter trait. Adapters live in submodules:
//!
//! - [`png`], [`jpeg`], [`mp4`], [`heif`], [`zip`], [`pdf`], [`pe`], [`wav`],
//!   [`webp`], [`mkv`] — the ten supported carriers.
//! - [`eof`] — the universal fallback strategy (append after EOF) shared by
//!   every carrier when its primary strategy does not fit.
//! - [`pe_codebits`], [`pe_slack`] — sub-strategies of the PE adapter.

pub mod ebml;
pub mod eof;
pub mod heif;
pub mod io;
pub mod isobmff;
pub mod jpeg;
pub mod mkv;
pub mod mp4;
pub mod pdf;
pub mod pe;
#[cfg(feature = "structure-pe")]
pub mod pe_codebits;
pub mod pe_layout;
pub mod pe_slack;
pub mod png;
pub mod riff;
pub mod wav;
pub mod webp;
pub mod zip;

pub use heif::HeifAdapter;
pub use jpeg::JpegAdapter;
pub use mkv::MkvAdapter;
pub use mp4::Mp4Adapter;
pub use pdf::PdfAdapter;
pub use pe::PeAdapter;
pub use png::PngAdapter;
pub use wav::WavAdapter;
pub use webp::WebpAdapter;
pub use zip::ZipAdapter;

use crate::errors::StrHideError;
use crate::structure::envelope::EnvelopeHeader;
use serde::Serialize;
use std::io::{Read, Seek, Write};

/// Combination trait: anything that is both [`Read`] and [`Seek`]. Auto-implemented
/// for all types that satisfy both bounds.
pub trait SeekRead: Read + Seek {}
impl<T: Read + Seek> SeekRead for T {}

/// Combination trait: anything that is both [`Write`] and [`Seek`].
pub trait SeekWrite: Write + Seek {}
impl<T: Write + Seek> SeekWrite for T {}

/// Combination trait: anything that is [`Read`], [`Write`], and [`Seek`].
pub trait SeekReadWrite: Read + Write + Seek {}
impl<T: Read + Write + Seek> SeekReadWrite for T {}

/// Context for determining the physical trailer offset in the carrier.
pub struct TrailerCtx<'a> {
    pub actual_ube_offset: u64,
    pub ube_total_size: u64,
    pub inject_offset: u64,
    pub inject_size: u64,
    pub strategy: &'a str,
}

/// Context passed to [`HostAdapter::finalize`] for carrier-specific post-write adjustments.
pub struct FinalizeCtx<'a> {
    pub ube_offset: u64,
    pub ube_total_size: u64,
    pub inject_offset: u64,
    pub inject_size: u64,
    pub strategy: &'a str,
}

/// Capacity and availability of one injection strategy for a carrier.
///
/// Produced by [`HostAdapter::strategy_capacities`]. The vector returned by an
/// adapter is ordered by **recommended priority**, matching the order in which
/// the auto strategy prefers them.
#[derive(Debug, Clone, Serialize)]
pub struct StrategyCapacity {
    pub strategy: String,
    /// Exact maximum UBE envelope size in bytes, when it can be stated as a
    /// single number. `None` means the strategy is unbounded (the file grows)
    /// or the limit is carrier-dependent (see [`limit`](Self::limit)).
    pub capacity_bytes: Option<u64>,
    /// Whether the strategy is structurally usable for the carrier right now.
    /// For a static query (`reader == None`) this is the format's capability,
    /// not the current carrier's.
    pub available: bool,
    /// Concise human-readable limit, e.g. `≤ 2,147,483,647 B (2 GiB - 1)` or
    /// `carrier-dependent (.text density + zero slack)`.
    pub limit: String,
    /// Optional detail: channel behavior, retry/fallback hints, slack needs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl StrategyCapacity {
    /// Render human-readable limit string according to language context.
    pub fn render_limit(&self, ctx: crate::core::i18n::RenderCtx) -> String {
        match ctx.lang {
            crate::core::i18n::Lang::En => self.limit.clone(),
            crate::core::i18n::Lang::Zh => {
                if self.limit == "unlimited (file grows)" {
                    "无上限 (文件增长)".to_string()
                } else {
                    self.limit.clone()
                }
            }
        }
    }

    /// Helper constructor for strategies that append data and grow the file without an architectural upper bound.
    pub fn unbounded_growth(strategy: &str, note: &str) -> Self {
        Self {
            strategy: strategy.into(),
            capacity_bytes: None,
            available: true,
            limit: "unlimited (file grows)".into(),
            note: Some(note.into()),
        }
    }
}

/// Formats a byte count with thousands separators (`2147483647` →
/// `2,147,483,647`). Shared by the adapters' `limit` strings and the CLI.
pub fn format_bytes(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

pub trait HostAdapter: Send + Sync {
    fn format_name(&self) -> &'static str;
    fn detect(&self, reader: &mut dyn SeekRead) -> bool;
    fn supported_strategies(&self) -> Vec<&'static str>;
    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str;

    /// Reports the capacity of each supported strategy, in recommended
    /// priority order.
    ///
    /// `reader == None` answers "what does this format support?" (used by the
    /// static `list` table): constants only, carrier-dependent limits stay
    /// unspecified. `reader == Some(_)` answers "what can THIS carrier hold?"
    /// (used by `inspect`): carrier-dependent strategies are measured.
    ///
    /// The default implementation reports every strategy as available with an
    /// unknown capacity; adapters override it with their real limits.
    fn strategy_capacities(&self, _reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        self.supported_strategies()
            .into_iter()
            .map(|s| StrategyCapacity {
                strategy: s.to_string(),
                capacity_bytes: None,
                available: true,
                limit: "unknown".into(),
                note: None,
            })
            .collect()
    }

    /// Injects UBE data into host stream, writing the resulting container to out.
    /// Returns (inject_offset, inject_size, patch_offset, orig_patch_val).
    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<(u64, u64, u32, u32), StrHideError>;

    /// Whether `strategy` embeds the envelope in a scattered (non-contiguous)
    /// form. For scattered strategies (currently only `pe_codebits`), `inject`
    /// has already written the final envelope bytes, so the engine must not
    /// patch the header/trailer at file offsets; the envelope is read back
    /// through `open_ube_reader` instead.
    fn is_scattered_strategy(&self, _strategy: &str) -> bool {
        false
    }

    /// Locates embedded UBE envelope in the carrier stream.
    /// Returns (ube_offset, ube_total_size, strategy_name).
    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError>;

    /// Strips embedded data and restores original carrier bits.
    ///
    /// Coordinate convention: `header.patch_offset` (when non-zero) is an
    /// offset in the **stego** stream (post-injection). The default
    /// implementation writes the restored patch value at
    /// `patch_offset - inject_size` in `out`, i.e. translated into the
    /// stripped stream's coordinates. Adapters that emit a non-zero
    /// `patch_offset` (ZIP at `eocd_pos + 16 + ube_size`, RIFF at offset 4)
    /// may override this with an equivalent streaming implementation.
    fn strip(
        &self,
        stego_in: &mut dyn SeekRead,
        out: &mut dyn SeekWrite,
        header: &EnvelopeHeader,
    ) -> Result<(), StrHideError> {
        // Universal 100% loss-free reverse slicing & patch rollback
        use std::io::SeekFrom;

        stego_in.seek(SeekFrom::Start(0))?;
        crate::structure::adapters::io::copy_exact(stego_in, out, header.inject_offset)?;

        // Skip injected bytes
        let inject_end = header
            .inject_offset
            .checked_add(header.inject_size)
            .ok_or_else(|| {
                StrHideError::CorruptedData(format!(
                    "Injected region [{}, {}] overflows u64 offsets",
                    header.inject_offset, header.inject_size
                ))
            })?;
        stego_in.seek(SeekFrom::Start(inject_end))?;
        crate::structure::adapters::io::copy_stream(stego_in, out)?;

        // Restore original patched value if applicable.
        //
        // `out` is the stripped stream (stego minus the `inject_size` bytes at
        // `inject_offset`), so a stego-coordinate `patch_offset` maps to
        // `patch_offset - inject_size` here — the same translation the
        // ZIP-specific override performs. Sentinel: 0 means "no patch"; a
        // genuine patch offset is always >= 4 (RIFF patches its size field at
        // offset 4, ZIP writes at `eocd_pos + 16 + ube_size`), so a patch at
        // absolute offset 0 is unreachable in the protocol. RIFF never pairs
        // the offset-4 patch with a zero original value either: `riff_inject`
        // rejects carriers whose declared RIFF size is 0 via its boundary
        // check.
        if header.patch_offset != 0 {
            let out_patch_pos = if (header.patch_offset as u64) < header.inject_offset {
                header.patch_offset as u64
            } else if (header.patch_offset as u64) >= inject_end {
                (header.patch_offset as u64)
                    .checked_sub(header.inject_size)
                    .ok_or_else(|| StrHideError::CorruptedData("patch_offset underflow".into()))?
            } else {
                return Err(StrHideError::CorruptedData(
                    "patch_offset falls inside the injected region".into(),
                ));
            };
            out.seek(SeekFrom::Start(out_patch_pos))?;
            out.write_all(&header.orig_patch_val.to_le_bytes())?;
        }

        Ok(())
    }

    /// Verifies host container structure integrity.
    fn verify_structure(&self, stego_in: &mut dyn SeekRead)
    -> Result<(bool, String), StrHideError>;

    /// Password-independent structural scan for containers that only a strhide
    /// envelope would produce (oversized private chunks, COM segments, uuid
    /// boxes, PE overlays). Stealth envelopes written with an unknown password
    /// are invisible to magic-based `locate`; this heuristic lets the engine
    /// warn about a probable pre-existing envelope before a second injection
    /// stacks another one on top. Default: no opinion.
    fn suspicious_structures(&self, _stego_in: &mut dyn SeekRead) -> Vec<String> {
        Vec::new()
    }

    /// Opens a virtual SeekRead stream over the embedded UBE envelope data.
    ///
    /// For standard contiguous envelopes (PNG, ZIP, PDF, MP4, PE, EOF), this
    /// is simply a bounded slice starting at `ube_offset` of `ube_total_size` bytes.
    /// Format adapters with fragmented/chained segments (e.g. JPEG APPn/COM
    /// multi-segment chains) override this to provide a continuous virtual UBE
    /// stream that transparently bridges across segment boundaries.
    fn open_ube_reader<'a>(
        &self,
        carrier: &'a mut dyn SeekRead,
        ube_offset: u64,
        ube_total_size: u64,
        _strategy: &str,
    ) -> Result<Box<dyn SeekRead + 'a>, StrHideError> {
        Ok(Box::new(SubStream::new(
            carrier,
            ube_offset,
            ube_total_size,
        )?))
    }

    /// Format-specific offset adjustment between `inject_offset` and the real start of the UBE.
    ///
    /// For formats where the UBE is wrapped in a container header (PNG private chunk header,
    /// ISO-BMFF uuid box header, JPEG APP marker, PDF object header), this returns the header length.
    /// Default: `0` (contiguous injection starting immediately at `inject_offset`).
    fn envelope_offset_delta(
        &self,
        _carrier: &mut dyn SeekRead,
        _strategy: &str,
        _ube_size: u64,
    ) -> Result<u64, StrHideError> {
        Ok(0)
    }

    /// Calculate the physical carrier offset where the 24-byte envelope trailer should be written.
    ///
    /// Default: contiguous trailer at `actual_ube_offset + ube_total_size - 24`.
    fn trailer_offset(&self, ctx: &TrailerCtx) -> u64 {
        ctx.actual_ube_offset + ctx.ube_total_size - 24
    }

    /// Format-specific post-write finalization (e.g. updating chunk CRCs).
    ///
    /// Called after the envelope header and trailer have been written into the carrier.
    fn finalize(
        &self,
        _carrier: &mut dyn SeekReadWrite,
        _ctx: &FinalizeCtx,
    ) -> Result<(), StrHideError> {
        Ok(())
    }

    /// Format-specific note describing how and where the hidden data was embedded.
    ///
    /// Default: `None`.
    fn strategy_note(&self, _strategy: &str, _fallback: bool) -> Option<String> {
        None
    }
}

/// A zero-copy segmented bounded slice of a [`SeekRead`] stream.
/// Can represent either a single contiguous slice or a chain of segments
/// (e.g. JPEG APPn multi-segment chains).
pub struct SegmentedSubStream<'a> {
    inner: &'a mut dyn SeekRead,
    segments: Vec<(u64, u64)>,
    total_size: u64,
    logical_pos: u64,
}

pub type SubStream<'a> = SegmentedSubStream<'a>;

impl<'a> SegmentedSubStream<'a> {
    /// Create a single-segment bounded sub-stream starting at `base_offset`.
    pub fn new(
        inner: &'a mut dyn SeekRead,
        base_offset: u64,
        total_size: u64,
    ) -> Result<Self, StrHideError> {
        Self::from_segments(inner, vec![(base_offset, total_size)], total_size)
    }

    /// Create a multi-segment chained virtual sub-stream across multiple `(start, len)` segment slices.
    pub fn from_segments(
        inner: &'a mut dyn SeekRead,
        segments: Vec<(u64, u64)>,
        total_size: u64,
    ) -> Result<Self, StrHideError> {
        let mut stream = Self {
            inner,
            segments,
            total_size,
            logical_pos: 0,
        };
        stream.sync_inner_seek()?;
        Ok(stream)
    }

    fn sync_inner_seek(&mut self) -> Result<(), StrHideError> {
        use std::io::SeekFrom;
        if self.logical_pos >= self.total_size {
            return Ok(());
        }
        let mut rem = self.logical_pos;
        for &(start, len) in &self.segments {
            if rem < len {
                self.inner.seek(SeekFrom::Start(start + rem))?;
                return Ok(());
            }
            rem -= len;
        }
        Ok(())
    }
}

impl Read for SegmentedSubStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::SeekFrom;
        if self.logical_pos >= self.total_size || buf.is_empty() {
            return Ok(0);
        }

        let mut rem = self.logical_pos;
        let mut target_seg = None;
        for &(start, len) in &self.segments {
            if rem < len {
                target_seg = Some((start, len, rem));
                break;
            }
            rem -= len;
        }

        let (seg_start, seg_len, offset_in_seg) = match target_seg {
            Some(s) => s,
            None => return Ok(0),
        };

        let seg_remaining = seg_len - offset_in_seg;
        let total_remaining = self.total_size - self.logical_pos;
        let to_read = std::cmp::min(
            buf.len() as u64,
            std::cmp::min(seg_remaining, total_remaining),
        ) as usize;

        self.inner
            .seek(SeekFrom::Start(seg_start + offset_in_seg))?;
        let n = self.inner.read(&mut buf[..to_read])?;
        self.logical_pos += n as u64;
        Ok(n)
    }
}

impl Seek for SegmentedSubStream<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::io::SeekFrom;
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::Current(p) => self.logical_pos as i64 + p,
            SeekFrom::End(p) => self.total_size as i64 + p,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid seek to negative position",
            ));
        }
        self.logical_pos = new_pos as u64;
        self.sync_inner_seek()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(self.logical_pos)
    }
}
