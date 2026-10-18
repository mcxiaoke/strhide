//! Host file format adapters for strhide.

pub mod eof;
pub mod jpeg;
pub mod mp4;
pub mod pdf;
pub mod pe;
pub mod pe_codebits;
pub mod png;
pub mod zip;

use crate::envelope::EnvelopeHeader;
use crate::errors::StrHideError;
use std::io::{Read, Seek, Write};

pub trait SeekRead: Read + Seek {}
impl<T: Read + Seek> SeekRead for T {}

pub trait SeekWrite: Write + Seek {}
impl<T: Write + Seek> SeekWrite for T {}

pub trait HostAdapter: Send + Sync {
    fn format_name(&self) -> &'static str;
    fn detect(&self, reader: &mut dyn SeekRead) -> bool;
    fn supported_strategies(&self) -> Vec<&'static str>;
    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str;

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
    /// `patch_offset` (currently only ZIP) may override this with an
    /// equivalent streaming implementation.
    fn strip(
        &self,
        stego_in: &mut dyn SeekRead,
        out: &mut dyn SeekWrite,
        header: &EnvelopeHeader,
    ) -> Result<(), StrHideError> {
        // Universal 100% loss-free reverse slicing & patch rollback
        use std::io::SeekFrom;

        stego_in.seek(SeekFrom::Start(0))?;
        let mut remaining = header.inject_offset;
        let mut buf = [0u8; 64 * 1024];

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            let n = stego_in.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
        }

        // Skip injected bytes
        stego_in.seek(SeekFrom::Start(header.inject_offset + header.inject_size))?;
        loop {
            let n = stego_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        // Restore original patched value if applicable.
        //
        // `out` is the stripped stream (stego minus the `inject_size` bytes at
        // `inject_offset`), so a stego-coordinate `patch_offset` maps to
        // `patch_offset - inject_size` here — the same translation the
        // ZIP-specific override performs. Sentinel: 0 means "no patch"; a
        // genuine patch offset is always >= 16 (ZIP writes it at
        // eocd_pos + 16 + ube_size), so a patch at absolute offset 0 is
        // unreachable in the protocol.
        if header.patch_offset != 0 {
            debug_assert!(
                header.patch_offset as u64 >= header.inject_offset + header.inject_size,
                "patch_offset must point past the injected region"
            );
            let out_patch_pos = (header.patch_offset as u64)
                .checked_sub(header.inject_size)
                .ok_or_else(|| {
                    StrHideError::CorruptedData("patch_offset precedes the injected region".into())
                })?;
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
}

/// A zero-copy bounded slice of a SeekRead stream.
pub struct SubStream<'a> {
    inner: &'a mut dyn SeekRead,
    base_offset: u64,
    total_size: u64,
    pos: u64,
}

impl<'a> SubStream<'a> {
    pub fn new(
        inner: &'a mut dyn SeekRead,
        base_offset: u64,
        total_size: u64,
    ) -> Result<Self, StrHideError> {
        use std::io::SeekFrom;
        inner.seek(SeekFrom::Start(base_offset))?;
        Ok(Self {
            inner,
            base_offset,
            total_size,
            pos: 0,
        })
    }
}

impl Read for SubStream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.total_size {
            return Ok(0);
        }
        let remaining = self.total_size - self.pos;
        let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        let n = self.inner.read(&mut buf[..to_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SubStream<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        use std::io::SeekFrom;
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::Current(p) => self.pos as i64 + p,
            SeekFrom::End(p) => self.total_size as i64 + p,
        };
        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid seek to negative position",
            ));
        }
        let new_pos = new_pos as u64;
        self.inner
            .seek(SeekFrom::Start(self.base_offset + new_pos))?;
        self.pos = new_pos;
        Ok(self.pos)
    }
}
