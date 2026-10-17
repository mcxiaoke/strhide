//! Host file format adapters for strhide.

pub mod eof;
pub mod jpeg;
pub mod mp4;
pub mod pdf;
pub mod pe;
pub mod png;
pub mod zip;

use std::io::{Read, Seek, Write};
use crate::envelope::EnvelopeHeader;
use crate::errors::StrHideError;

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

    /// Locates embedded UBE envelope in the carrier stream.
    /// Returns (ube_offset, ube_total_size, strategy_name).
    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError>;

    /// Strips embedded data and restores original carrier bits.
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

        // Restore original patched value if applicable
        if header.patch_offset > 0 {
            out.seek(SeekFrom::Start(header.patch_offset as u64))?;
            out.write_all(&header.orig_patch_val.to_le_bytes())?;
        }

        Ok(())
    }

    /// Verifies host container structure integrity.
    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError>;

    /// Password-independent structural scan for containers that only a strhide
    /// envelope would produce (oversized private chunks, COM segments, uuid
    /// boxes, PE overlays). Stealth envelopes written with an unknown password
    /// are invisible to magic-based `locate`; this heuristic lets the engine
    /// warn about a probable pre-existing envelope before a second injection
    /// stacks another one on top. Default: no opinion.
    fn suspicious_structures(&self, _stego_in: &mut dyn SeekRead) -> Vec<String> {
        Vec::new()
    }
}
