//! Raw deflate stream compression and decompression for strhide payloads.

use crate::errors::StrHideError;
use flate2::{Compression, read::DeflateDecoder, write::DeflateEncoder};
use std::io::{Read, Write};

/// readable. `level` is validated by the caller
/// ([`crate::params::LocalParams::validate`]).
/// Returns (raw_size, compressed_size).
pub fn compress_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    level: u32,
) -> Result<(u64, u64), StrHideError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level));
    let mut buf = [0u8; 64 * 1024];
    let mut raw_size: u64 = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        raw_size += n as u64;
        encoder.write_all(&buf[..n])?;
    }

    let compressed = encoder.finish()?;
    let comp_size = compressed.len() as u64;
    writer.write_all(&compressed)?;

    Ok((raw_size, comp_size))
}

/// Payloads at or below this size are deflated in full.
///
/// The worst case for a small payload is bounded (measured ~18 ms for 1 MiB of
/// incompressible data at level 6), and keeping the historical path means small
/// envelopes stay byte-identical after the sampling gate was introduced.
pub(crate) const COMPRESSION_PROBE_MIN_BYTES: usize = 1024 * 1024;

/// Number of evenly spaced segments [`probe_compressibility`] samples.
const COMPRESSION_PROBE_SEGMENTS: usize = 8;

/// Bytes per probe segment; 8 × 32 KiB = 256 KiB sampled from a large payload.
const COMPRESSION_PROBE_SEGMENT_BYTES: usize = 32 * 1024;

/// Deflate a fixed, evenly spaced sample of a large payload.
///
/// Deflating incompressible data is the expensive case (~17 ms per MiB at
/// level 6) and the output is then discarded because it saves less than 2%.
/// Rather than compressing the whole payload to learn that, this compresses
/// [`COMPRESSION_PROBE_SEGMENTS`] × [`COMPRESSION_PROBE_SEGMENT_BYTES`] and
/// returns the sample's `(raw, compressed)` sizes, so the caller can apply the
/// same [`crate::params::CompressionStrategy::should_compress`] rule that
/// governs the full pass. The written flag therefore always describes the
/// bytes actually kept.
///
/// Segments span head to tail instead of sampling only a prefix: a
/// compressible region at the end must be seen (a random prefix followed by a
/// compressible suffix reads as ratio 1.0003 from the prefix alone, but 0.3385
/// when the tail is included).
pub(crate) fn probe_compressibility(
    payload: &[u8],
    level: u32,
) -> Result<(u64, u64), StrHideError> {
    // A real check, not a debug_assert: release builds would otherwise underflow
    // `span` and slice out of bounds if a future caller passes a short payload.
    if payload.len() <= COMPRESSION_PROBE_MIN_BYTES {
        return Err(StrHideError::InvalidArgument(format!(
            "compression probe needs more than {} bytes, got {}",
            COMPRESSION_PROBE_MIN_BYTES,
            payload.len()
        )));
    }
    const SAMPLE_BYTES: usize = COMPRESSION_PROBE_SEGMENTS * COMPRESSION_PROBE_SEGMENT_BYTES;

    let mut sample = Vec::with_capacity(SAMPLE_BYTES);
    let span = payload.len() - COMPRESSION_PROBE_SEGMENT_BYTES;
    for i in 0..COMPRESSION_PROBE_SEGMENTS {
        let start = span * i / (COMPRESSION_PROBE_SEGMENTS - 1);
        sample.extend_from_slice(&payload[start..start + COMPRESSION_PROBE_SEGMENT_BYTES]);
    }

    let mut out = Vec::new();
    let mut reader = &sample[..];
    compress_stream(&mut reader, &mut out, level)
}

/// Decompress in_stream using raw deflate.
///
/// `limit` bounds the decompressed size: the declared `raw_size` from the
/// (AEAD-protected) metadata. A crafted carrier could otherwise expand a few
/// kilobytes into gigabytes — an 8 MiB run of zeros compresses to ~8 KiB —
/// and make `read` allocate far more memory than the carrier size suggests.
/// Returns total decompressed size.
pub fn decompress_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> Result<u64, StrHideError> {
    let mut decoder = DeflateDecoder::new(reader);
    let mut buf = [0u8; 64 * 1024];
    let mut total_decompressed: u64 = 0;

    loop {
        let n = decoder.read(&mut buf).map_err(|e| {
            StrHideError::CorruptedData(format!("Deflate decompression error: {e}"))
        })?;
        if n == 0 {
            break;
        }
        let next_total = total_decompressed.saturating_add(n as u64);
        if next_total > limit {
            return Err(StrHideError::CorruptedData(format!(
                "Decompressed payload exceeds the declared size ({limit} bytes); refusing to expand further"
            )));
        }
        writer.write_all(&buf[..n])?;
        total_decompressed = next_total;
    }

    Ok(total_decompressed)
}
