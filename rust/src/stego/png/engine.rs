//! Spatial domain steganographic embedding and extraction engine (PNG).
//!
//! Uses content-adaptive distortion costs (e.g. HILL) to isolate complex texture
//! and noisy regions, completely avoiding smooth areas.
//!
//! # Embedding operation
//!
//! Bits are written by **ternary `±1` matching**: a slot whose LSB must change
//! moves to `val + 1` or `val - 1`, whichever is cheaper and legal, instead of
//! having its LSB replaced. Both directions flip the LSB, so the payload bit is
//! still the slot's parity and extraction is unchanged.
//!
//! The move is constrained to the pixel's **eight-value class** (`val & 0xF8`):
//! the engine ranks candidates under the safe rule
//! ([`crate::stego::coding::spatial_move_safe`]), where class positions `r = 0`
//! and `r = 7` are not candidates at all, `r = 1` may only move up and `r = 6`
//! only down, so no modified pixel ever lands on a boundary residue. The
//! constraint exists because the extractor rebuilds the slot ranking from a
//! cost map computed on the *stego* image, so the ranking must be reproducible:
//! HILL masks its input with `0xF8`, and a class-internal `±1` leaves that
//! masked value untouched. Unrestricted matching would change it and
//! desynchronise the ranking.
//!
//! Why this is not just LSB replacement with extra steps: replacement always
//! moves a slot in the direction of the target bit, so every value pair
//! `(2k, 2k+1)` is equalised — the exact signature chi-square and SPA look for.
//! Here the four interior class positions (`r = 2..=5`, half of every class)
//! can move either way, so probability mass crosses pair boundaries and the
//! pairs are no longer individually flat. Direction choice is further biased
//! towards the local mean by
//! [`crate::stego::traits::PngCostModel::direction_costs`].

use std::io::{Cursor, Read, Write};

use crate::core::control::{Control, Stage};
use crate::core::media::MediaInfo;
use crate::core::payload::Payload;
use crc32fast::Hasher as Crc32;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::{Compress, Compression, FlushCompress, Status};
use rayon::prelude::*;

use crate::errors::StrHideError;
use crate::stego::coding::{
    Move, StcTrellis, hamming_embed_ternary, hamming_extract_bytes, spatial_move_safe,
    write_bit_ternary,
};
use crate::stego::envelope::{Freshness, build_plaintext, encrypt_with_aad, unpack_envelope_parts};
use crate::stego::format::{body_keys, derive_master};
pub use crate::stego::header::{
    FeatureWord, HEADER_LEN_MASK, HEADER_LEN_MAX, HEADER_V2_ESCAPE_H, V2_TOTAL_HEADER_SLOTS,
    decode_header_word, encode_header_word,
};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::params::SafetyPolicy;
use crate::stego::prng::{permute_indices, permute_prefix};
use crate::stego::traits::PngCostModel;
use crate::stego::{PngParams, StegoCapacityInfo, StegoCodec};

/// Inclusive range of pixel values the spatial engine may embed into.
///
/// The bounds are the class-interior rule: from a value in `[8, 247]` at least
/// one of `val ± 1` stays inside the same eight-value class, and no move can
/// reach 0 or 255. Both the writer and the extractor must use this range
/// verbatim; it is exported so tests can assert against the same constant
/// instead of re-typing the bounds.
pub const SPATIAL_ELIGIBLE_MIN: u8 = 8;
pub const SPATIAL_ELIGIBLE_MAX: u8 = 247;

// ---------------------------------------------------------------------------
// Envelope header layout (32 bytes = 256 slots)
// ---------------------------------------------------------------------------
//
// [0..16) salt, [16..28) nonce, [28..32) the flags+length word. The layout and
// its bit allocation live in [`crate::stego::header`], shared with the JPEG
// engine so both carriers describe their codec identically.

/// Decoded raw image representation.
#[derive(Debug, Clone)]
pub struct RawImage {
    pub width: u32,
    pub height: u32,
    pub channels: usize,
    pub pixels: Vec<u8>,
    /// Every chunk captured at decode time, in file order (IHDR first, IEND
    /// last). Re-encoded as-is so ancillary metadata -- iCCP, gAMA, sRGB,
    /// pHYs, tEXt, zTXt, eXIf, bKGD, ... -- survives an embed round-trip
    /// instead of being silently dropped. The original IDAT run is collapsed
    /// into single empty placeholder entries marking where the re-compressed
    /// data belongs (see `idat_sizes`).
    pub chunks: Vec<PngChunk>,
    /// Body length of each original IDAT chunk, in file order. When
    /// non-empty, the re-compressed stream is split back into the same number
    /// of IDAT chunks so the chunk sequence is preserved end to end.
    pub idat_sizes: Vec<usize>,
    /// Per-row filter type recorded at decode time. Encoding re-applies the
    /// same filter to the (LSB-modified) pixels, which keeps the IDAT close
    /// to the original size instead of forcing filter 0 on every row.
    pub row_filters: Vec<u8>,
    /// What the source IDAT stream said about its own deflate settings, used
    /// to pick a re-compression level that lands near the original size.
    /// `None` for hand-built images and for streams whose zlib header is not a
    /// plain deflate header without a preset dictionary.
    pub idat_info: Option<IdatInfo>,
    /// Bytes that followed the IEND chunk in the source file, copied back
    /// verbatim. Some producers append signatures or vendor trailers there; the
    /// decoder stops at IEND, so without this field a re-encode silently
    /// truncated them and the "format preserving" promise broke.
    pub tail: Vec<u8>,
}

/// Self-description carried by the two-byte zlib header of the IDAT stream.
///
/// A PNG writer's zlib level is not recoverable from the compressed bytes, but
/// `FLEVEL` narrows it to four buckets, and the original IDAT *length* is the
/// real target: re-compressing a level-9 carrier at the default level 6 grew
/// one real sample by 4.2%, and re-compressing a level-1 carrier at level 6
/// shrank another by 28% -- both are far larger size changes than the payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdatInfo {
    /// `FLEVEL` bits of the zlib header: 0 = fastest .. 3 = maximum.
    pub flevel: u8,
    /// Total IDAT body bytes in the source file.
    pub orig_len: usize,
}

/// One PNG chunk captured verbatim (type + body, CRC recomputed on write).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PngChunk {
    pub ty: [u8; 4],
    pub data: Vec<u8>,
}

/// Decode raw pixels from a PNG image file.
pub fn decode_png(data: &[u8]) -> Result<RawImage, StrHideError> {
    if data.len() < 8 || &data[..8] != b"\x89PNG\r\n\x1a\n" {
        return Err(StrHideError::UnsupportedFormat(
            "Carrier is not a valid PNG image".into(),
        ));
    }

    let mut pos = 8usize;
    let mut width: u32 = 0;
    let mut height: u32 = 0;
    let mut bit_depth: u8 = 0;
    let mut color_type: u8 = 0;
    let mut idat: Vec<u8> = Vec::new();
    let mut chunks: Vec<PngChunk> = Vec::new();
    let mut idat_sizes: Vec<usize> = Vec::new();
    let mut tail: Vec<u8> = Vec::new();

    while pos + 8 <= data.len() {
        let len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let ty = &data[pos + 4..pos + 8];
        let body_start = pos + 8;
        let body_end = body_start
            .checked_add(len)
            .ok_or_else(|| StrHideError::CorruptedData("PNG chunk length overflow".into()))?;

        if body_end + 4 > data.len() {
            return Err(StrHideError::CorruptedData("Unexpected EOF in PNG".into()));
        }

        let body = &data[body_start..body_end];
        match ty {
            b"IHDR" => {
                if len < 13 {
                    return Err(StrHideError::CorruptedData("Truncated IHDR".into()));
                }
                width = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                height = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                bit_depth = body[8];
                color_type = body[9];
                if body[12] != 0 {
                    return Err(StrHideError::UnsupportedFormat(
                        "Interlaced PNG (Adam7) is not supported for content-adaptive pixel steganography; please use non-interlaced PNG or use 'strhide write' for structural hiding"
                            .into(),
                    ));
                }
                chunks.push(PngChunk {
                    ty: *b"IHDR",
                    data: body.to_vec(),
                });
            }
            b"acTL" => {
                return Err(StrHideError::UnsupportedFormat(
                    "Animated PNG (APNG) is not supported for content-adaptive pixel steganography; please use static PNG or use 'strhide write' for structural hiding".into(),
                ));
            }
            b"PLTE" => {
                return Err(StrHideError::UnsupportedFormat(
                    "Indexed/palette PNG is not supported for content-adaptive pixel steganography; please use RGB/RGBA/Grayscale PNG".into(),
                ));
            }
            b"IDAT" => {
                idat.extend_from_slice(body);
                // Placeholder marking where the re-compressed IDAT belongs;
                // `encode_png` fills it with the fresh compressed data.
                chunks.push(PngChunk {
                    ty: *b"IDAT",
                    data: Vec::new(),
                });
                idat_sizes.push(len);
            }
            b"IEND" => {
                chunks.push(PngChunk {
                    ty: *b"IEND",
                    data: Vec::new(),
                });
                // Everything past the IEND chunk (its 4-byte CRC included) is
                // not chunk data. Keep it so `encode_png` can put it back.
                let after = body_end + 4;
                if after < data.len() {
                    tail = data[after..].to_vec();
                }
                break;
            }
            _ => {
                // Capture every other chunk verbatim (metadata, color
                // management, EXIF, ...) so the re-encoded carrier keeps it.
                chunks.push(PngChunk {
                    ty: [ty[0], ty[1], ty[2], ty[3]],
                    data: body.to_vec(),
                });
            }
        }
        pos = body_end + 4; // Skip CRC
    }

    if bit_depth != 8 || width == 0 || height == 0 || idat.is_empty() {
        return Err(StrHideError::UnsupportedFormat(
            "Only 8-bit non-interlaced PNG images are supported".into(),
        ));
    }

    let channels: usize = match color_type {
        0 => 1, // Grayscale
        2 => 3, // RGB
        3 => {
            return Err(StrHideError::UnsupportedFormat(
                "Indexed/palette PNG is not supported for content-adaptive pixel steganography; please use RGB/RGBA/Grayscale PNG".into(),
            ));
        }
        4 => 2, // Grayscale + Alpha
        6 => 4, // RGBA
        _ => {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Unsupported PNG color type {color_type}"
            )));
        }
    };

    let bpp = channels;
    let stride = width as usize * bpp;

    // A carrier is untrusted input and `stride * height` is exactly how many
    // bytes a valid image produces, so bound the inflate by IHDR instead of
    // letting flate2 fill a Vec with however much the stream expands to
    // (a few hundred KiB of IDAT can decode to gigabytes).
    let expected = stride
        .checked_mul(height as usize)
        .and_then(|v| v.checked_add(height as usize))
        .ok_or_else(|| StrHideError::CorruptedData("PNG dimensions overflow usize".into()))?;

    // Decompress IDAT stream
    let mut z = ZlibDecoder::new(Cursor::new(&idat)).take(expected as u64 + 1);
    let mut raw = Vec::new();
    z.read_to_end(&mut raw)
        .map_err(|e| StrHideError::CorruptedData(format!("Invalid IDAT stream: {e}")))?;

    if raw.len() < expected {
        return Err(StrHideError::CorruptedData(
            "Decompressed IDAT is truncated".into(),
        ));
    }
    if raw.len() != expected {
        return Err(StrHideError::CorruptedData(format!(
            "Decompressed IDAT is {} bytes, but IHDR declares {}; refusing to expand further",
            raw.len(),
            expected
        )));
    }

    // Unfilter rows
    let mut out: Vec<u8> = Vec::with_capacity(stride * height as usize);
    let mut prev = vec![0u8; stride];
    let mut rp = 0usize;
    let mut row_filters: Vec<u8> = Vec::with_capacity(height as usize);

    for _ in 0..height {
        let filter = raw[rp];
        rp += 1;
        let line = &raw[rp..rp + stride];
        rp += stride;

        let mut recon = vec![0u8; stride];
        for i in 0..stride {
            let a = if i >= bpp { recon[i - bpp] } else { 0 };
            let b = prev[i];
            let c = if i >= bpp { prev[i - bpp] } else { 0 };
            recon[i] = match filter {
                0 => line[i],
                1 => line[i].wrapping_add(a),
                2 => line[i].wrapping_add(b),
                3 => line[i].wrapping_add(((a as u16 + b as u16) / 2) as u8),
                4 => line[i].wrapping_add(paeth(a, b, c)),
                _ => {
                    return Err(StrHideError::CorruptedData(
                        "Invalid PNG filter type".into(),
                    ));
                }
            };
        }
        row_filters.push(filter);
        out.extend_from_slice(&recon);
        prev = recon;
    }

    Ok(RawImage {
        width,
        height,
        channels,
        pixels: out,
        chunks,
        idat_sizes,
        row_filters,
        idat_info: idat_info_of(&idat),
        tail,
    })
}

/// Read the zlib header of the IDAT stream, if it is a plain deflate stream.
///
/// `CMF & 0x0F == 8` is "deflate with a 32 KiB window" and `FLG & 0x20 == 0`
/// means no preset dictionary -- both are what a PNG file must contain, so a
/// mismatch means the stream is not something this encoder should imitate.
fn idat_info_of(idat: &[u8]) -> Option<IdatInfo> {
    if idat.len() < 2 || (idat[0] & 0x0F) != 8 || (idat[1] & 0x20) != 0 {
        return None;
    }
    Some(IdatInfo {
        flevel: (idat[1] >> 6) & 3,
        orig_len: idat.len(),
    })
}

/// Maximum Rayon worker threads allocated for parallel Deflate compression.
const MAX_DEFLATE_WORKERS: usize = 8;

/// Minimum scanlines payload (in bytes) to trigger multi-threaded parallel Deflate.
/// Below 2 MB, the single-thread path avoids thread pool dispatch overhead.
const MIN_PARALLEL_SCANLINE_BYTES: usize = 2 * 1024 * 1024;

/// Computes the standard RFC 1950 Adler-32 checksum in blocked chunks.
fn compute_adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

/// Compress an uncompressed data slice into a raw Deflate byte stream without zlib framing.
/// Non-terminal chunks are flushed with `SyncFlush` to force byte-boundary alignment.
/// The terminal chunk is finished with `Finish` to set the `BFINAL=1` flag.
fn compress_raw_deflate_chunk(
    data: &[u8],
    level: u32,
    is_last: bool,
) -> Result<Vec<u8>, StrHideError> {
    let mut compressor = Compress::new(Compression::new(level), false);
    let mut out = Vec::with_capacity(data.len() / 2);
    let mut buf = [0u8; 65536];

    let mut in_pos = 0;
    while in_pos < data.len() {
        let before_in = compressor.total_in() as usize;
        let before_out = compressor.total_out() as usize;
        compressor
            .compress(&data[in_pos..], &mut buf, FlushCompress::None)
            .map_err(|e| StrHideError::General(format!("Deflate compression failure: {e}")))?;
        let consumed = compressor.total_in() as usize - before_in;
        let produced = compressor.total_out() as usize - before_out;
        in_pos += consumed;
        out.extend_from_slice(&buf[..produced]);
    }

    let flush = if is_last {
        FlushCompress::Finish
    } else {
        FlushCompress::Sync
    };

    loop {
        let before_out = compressor.total_out() as usize;
        let status = compressor
            .compress(&[], &mut buf, flush)
            .map_err(|e| StrHideError::General(format!("Deflate flush failure: {e}")))?;
        let produced = compressor.total_out() as usize - before_out;
        out.extend_from_slice(&buf[..produced]);

        if is_last && status == Status::StreamEnd {
            break;
        }
        if !is_last && (produced == 0 || status == Status::StreamEnd) {
            break;
        }
    }

    Ok(out)
}

/// Compress filtered PNG scanlines into an RFC 1950 compliant zlib datastream.
/// Uses Rayon parallel multi-chunk Deflate for large images, falling back to single-thread
/// for small payloads or single-core execution environments.
fn compress_scanlines_zlib(
    filtered: &[u8],
    row_len: usize,
    height: usize,
    level: u32,
) -> Result<Vec<u8>, StrHideError> {
    let num_threads = rayon::current_num_threads().clamp(1, MAX_DEFLATE_WORKERS);

    if num_threads <= 1 || filtered.len() < MIN_PARALLEL_SCANLINE_BYTES || height < num_threads {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(filtered)?;
        return encoder.finish().map_err(Into::into);
    }

    // Split strictly along row boundaries
    let rows_per_chunk = height.div_ceil(num_threads);
    let mut chunk_ranges = Vec::with_capacity(num_threads);
    let mut current_row = 0;
    while current_row < height {
        let end_row = (current_row + rows_per_chunk).min(height);
        let start_byte = current_row * row_len;
        let end_byte = end_row * row_len;
        chunk_ranges.push(&filtered[start_byte..end_byte]);
        current_row = end_row;
    }

    let n = chunk_ranges.len();
    let compressed_chunks: Result<Vec<Vec<u8>>, StrHideError> = chunk_ranges
        .into_par_iter()
        .enumerate()
        .map(|(i, chunk)| {
            let is_last = i + 1 == n;
            compress_raw_deflate_chunk(chunk, level, is_last)
        })
        .collect();
    let compressed_chunks = compressed_chunks?;

    let adler = compute_adler32(filtered);

    // RFC 1950 zlib header
    let cmf = 0x78u8;
    let flg = match level {
        1 => 0x01u8,
        2..=5 => 0x5Eu8,
        6..=8 => 0x9Cu8,
        _ => 0xDAu8,
    };
    let total_len = 2 + compressed_chunks.iter().map(|c| c.len()).sum::<usize>() + 4;
    let mut out = Vec::with_capacity(total_len);
    out.push(cmf);
    out.push(flg);
    for c in compressed_chunks {
        out.extend_from_slice(&c);
    }
    out.extend_from_slice(&adler.to_be_bytes());

    Ok(out)
}

/// Encode raw pixels into a PNG byte stream.
///
/// Container fidelity: the chunk sequence captured by [`decode_png`] is
/// replayed verbatim (IHDR, ancillary metadata, IEND -- in the original
/// order), and only the IDAT run is replaced. Per-row filter types recorded
/// at decode time are re-applied to the (possibly LSB-modified) pixels, so
/// the re-filtered scanlines stay as compressible as the original instead of
/// collapsing to filter 0. When the original split its IDAT run into several
/// chunks, the re-compressed stream is split at the same boundaries, so the
/// chunk sequence survives end to end.
///
/// The zlib level is not recoverable from the stream, so it is *estimated*:
/// evenly spaced sample bands are compressed at each candidate level and the
/// level whose extrapolated size lands closest to the original IDAT length wins
/// (see `choose_deflate_level`). Filter preservation plus level matching is
/// what keeps the size near the original; before level matching, a level-9
/// carrier grew 4.2% and a level-1 carrier shrank 28% on a payload of a few KB.
///
/// A `RawImage` without captured chunks (hand-built, e.g. in tests) is
/// encoded as a fresh minimal IHDR/IDAT/IEND stream with filter 0 rows.
pub fn encode_png(image: &RawImage) -> Result<Vec<u8>, StrHideError> {
    let mut out = Vec::new();
    // Signature
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let stride = image.width as usize * image.channels;
    let height = image.height as usize;

    // Filtered scanlines: re-apply each row's original filter type to the
    // current pixels. Filtered = recon - predictor, all wrapping.
    let mut filtered = Vec::with_capacity((stride + 1) * height);
    let zero_row = vec![0u8; stride];
    for (y, row) in image.pixels.chunks_exact(stride).enumerate() {
        let prev: &[u8] = if y == 0 {
            &zero_row
        } else {
            &image.pixels[(y - 1) * stride..y * stride]
        };
        let filter = image.row_filters.get(y).copied().unwrap_or(0);
        filtered.push(filter);
        filtered.extend_from_slice(&filter_row(prev, row, filter, image.channels));
    }

    let (level, probe) = choose_deflate_level(&filtered, stride + 1, height, image.idat_info);
    let compressed_idat = compress_scanlines_zlib(&filtered, stride + 1, height, level)?;

    if let Some(info) = image.idat_info {
        let delta = (compressed_idat.len() as f64 - info.orig_len as f64) * 100.0
            / info.orig_len.max(1) as f64;
        trace(&format!(
            "idat orig={} final={} delta={delta:+.2}% level={level} flevel={} probe_l1={} probe_l6={}",
            info.orig_len,
            compressed_idat.len(),
            info.flevel,
            probe[0],
            probe[1],
        ));
    }

    if image.chunks.is_empty() {
        // Hand-built RawImage: synthesize a minimal stream.
        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&image.width.to_be_bytes());
        ihdr.extend_from_slice(&image.height.to_be_bytes());
        ihdr.push(8); // Bit depth
        let color_type = match image.channels {
            1 => 0, // Grayscale
            2 => 4, // Grayscale + Alpha
            3 => 2, // RGB
            4 => 6, // RGBA
            _ => {
                return Err(StrHideError::UnsupportedFormat(
                    "Unsupported channels".into(),
                ));
            }
        };
        ihdr.push(color_type);
        ihdr.push(0); // Compression (deflate)
        ihdr.push(0); // Filter (standard)
        ihdr.push(0); // Interlace (none)
        write_chunk(&mut out, b"IHDR", &ihdr);
        write_chunk(&mut out, b"IDAT", &compressed_idat);
        write_chunk(&mut out, b"IEND", &[]);
        out.extend_from_slice(&image.tail);
        return Ok(out);
    }

    // Split the re-compressed stream at the original IDAT boundaries so the
    // chunk count matches the source. The last original boundary absorbs
    // whatever remains; if the stream runs out early the trailing
    // placeholders simply carry no extra chunk.
    let mut pieces: Vec<&[u8]> = Vec::new();
    if image.idat_sizes.is_empty() {
        pieces.push(&compressed_idat[..]);
    } else {
        let mut off = 0usize;
        for (i, &sz) in image.idat_sizes.iter().enumerate() {
            if off >= compressed_idat.len() {
                break;
            }
            let end = if i + 1 == image.idat_sizes.len() {
                compressed_idat.len()
            } else {
                (off + sz).min(compressed_idat.len())
            };
            pieces.push(&compressed_idat[off..end]);
            off = end;
        }
        if pieces.is_empty() {
            pieces.push(&compressed_idat[..]);
        }
    }

    // Replay the captured chunk sequence in file order, substituting the
    // fresh IDAT pieces for the original IDAT run.
    let mut idat_written = false;
    let mut saw_iend = false;
    for chunk in &image.chunks {
        if &chunk.ty == b"IDAT" {
            if !idat_written {
                idat_written = true;
                for piece in &pieces {
                    write_chunk(&mut out, b"IDAT", piece);
                }
            }
            continue;
        }
        if &chunk.ty == b"IEND" {
            saw_iend = true;
        }
        write_chunk(&mut out, &chunk.ty, &chunk.data);
    }
    if !idat_written {
        // No IDAT placeholder at all (malformed source): still emit the data.
        for piece in &pieces {
            write_chunk(&mut out, b"IDAT", piece);
        }
    }
    if !saw_iend {
        // Truncated source without IEND: still emit a well-formed file.
        write_chunk(&mut out, b"IEND", &[]);
    }
    // Producer-appended trailer (signature, vendor index, ...) goes back after
    // IEND exactly where it was found.
    out.extend_from_slice(&image.tail);

    Ok(out)
}

// ---------------------------------------------------------------------------
// Re-compression level selection
// ---------------------------------------------------------------------------

/// Level used for the "fast / low compression" family of carriers. Tools that
/// save PNGs without tuning land here or on [`DEFLATE_LEVEL_DEFAULT`].
const DEFLATE_LEVEL_FAST: u32 = 1;

/// The default level (`flate2::Compression::default()` is level 6) and the
/// level almost every ordinary writer (XnConvert, ImageMagick, libpng) uses.
const DEFLATE_LEVEL_DEFAULT: u32 = 6;

/// Number of row bands the level probe compresses.
///
/// Three bands left a 15-30% error on real images (a 14.8 MP wallpaper put its
/// sky at the top and its detail at the bottom), which is enough to pick the
/// wrong level. Twenty-four evenly spaced bands keep the projection within ~2%
/// of the full-stream size on the whole corpus, at roughly 8-25% of the
/// scanlines -- still far cheaper than a second full compression.
const PROBE_BANDS: usize = 24;

/// Pick the zlib level whose projected IDAT size is closest to the original.
///
/// Exact level recovery is impossible, and `FLEVEL` is not a reliable stand-in
/// either: a real 14.8 MP sample declares `FLEVEL=2` yet sits closest to level
/// 9, and another declares `FLEVEL=0` while even level 1 comes out 12% smaller
/// than the source. So the decision is measured on the actual scanlines: evenly
/// spaced row bands are deflated at each candidate level and the projection is
/// compared against the source IDAT length.
///
/// Only levels 1 and 6 are candidates. Level 9 would match zopfli-style
/// carriers a few percent better but costs ~8x the time (measured on this
/// machine: 4.65 s -> 36.66 s for a 58 MB scanline stream), which is not worth
/// a 2-4 point size delta.
///
/// Returns the chosen level and the two projected sizes, in `[fast, default]`
/// order, for tracing.
fn choose_deflate_level(
    filtered: &[u8],
    row_len: usize,
    height: usize,
    info: Option<IdatInfo>,
) -> (u32, [usize; 2]) {
    let default_level = Compression::default().level();
    let Some(info) = info else {
        return (default_level, [0, 0]);
    };
    if height == 0 || row_len == 0 || filtered.len() < row_len * height {
        return (default_level, [0, 0]);
    }

    // `PROBE_BANDS` bands of `band` rows, first band at the top and last at the
    // bottom. Images too short for that are probed whole.
    let band = (height / (PROBE_BANDS * 4)).clamp(2, 16).min(height);
    let mut sample = Vec::new();
    if PROBE_BANDS * band >= height {
        sample.extend_from_slice(&filtered[..height * row_len]);
    } else {
        let step = (height - band) / (PROBE_BANDS - 1);
        for i in 0..PROBE_BANDS {
            let from = i * step;
            let to = from + band;
            sample.extend_from_slice(&filtered[from * row_len..to * row_len]);
        }
    }
    if sample.is_empty() {
        return (default_level, [0, 0]);
    }
    let scale = filtered.len() as f64 / sample.len() as f64;

    let est_fast = deflate_len(&sample, DEFLATE_LEVEL_FAST) as f64 * scale;
    let est_default = deflate_len(&sample, DEFLATE_LEVEL_DEFAULT) as f64 * scale;
    let orig = info.orig_len as f64;
    let err_fast = (est_fast - orig).abs();
    let err_default = (est_default - orig).abs();
    // On a tie keep the default level so behaviour stays where it was.
    let level = if err_default <= err_fast {
        DEFLATE_LEVEL_DEFAULT
    } else {
        DEFLATE_LEVEL_FAST
    };
    (
        level,
        [est_fast.round() as usize, est_default.round() as usize],
    )
}

/// Deflate `data` at `level` and report the compressed length.
fn deflate_len(data: &[u8], level: u32) -> usize {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
    // Writing into a `Vec` cannot fail; the length is all the probe needs.
    if encoder.write_all(data).is_err() {
        return usize::MAX;
    }
    encoder.finish().map(|v| v.len()).unwrap_or(usize::MAX)
}

/// Optional tracing enabled with `STRHIDE_STEGO_TRACE=1`.
///
/// Deliberately stderr-only and off by default, mirroring the JPEG engine's
/// `[stego]` lines; the `[png]` prefix says which carrier produced the line.
#[inline(always)]
fn trace(_msg: &str) {}

/// Apply PNG filter `filter` to one reconstructed scanline (`cur`), given
/// the previous reconstructed row (`prev`). Inverse of the unfilter step in
/// [`decode_png`]; all arithmetic wraps, exactly like the decoder's.
fn filter_row(prev: &[u8], cur: &[u8], filter: u8, bpp: usize) -> Vec<u8> {
    let mut out = vec![0u8; cur.len()];
    for i in 0..cur.len() {
        let a = if i >= bpp { cur[i - bpp] } else { 0 };
        let b = prev[i];
        let c = if i >= bpp { prev[i - bpp] } else { 0 };
        out[i] = match filter {
            0 => cur[i],
            1 => cur[i].wrapping_sub(a),
            2 => cur[i].wrapping_sub(b),
            3 => cur[i].wrapping_sub(((a as u16 + b as u16) / 2) as u8),
            4 => cur[i].wrapping_sub(paeth(a, b, c)),
            // Unknown types never survive decode (rejected there); treat as
            // None so encoding stays total.
            _ => cur[i],
        };
    }
    out
}

fn write_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);

    let mut crc = Crc32::new();
    crc.update(chunk_type);
    crc.update(data);
    out.extend_from_slice(&crc.finalize().to_be_bytes());
}

fn paeth(a: u8, b: u8, c: u8) -> u8 {
    let a16 = a as i16;
    let b16 = b as i16;
    let c16 = c as i16;
    let p = a16 + b16 - c16;
    let pa = (p - a16).abs();
    let pb = (p - b16).abs();
    let pc = (p - c16).abs();
    if pa <= pb && pa <= pc {
        a
    } else if pb <= pc {
        b
    } else {
        c
    }
}

// ---------------------------------------------------------------------------
// Slot plan: the single source of truth for "which pixels carry what"
// ---------------------------------------------------------------------------

/// Slots reserved for the 32-byte base header (salt | nonce | length word).
const HEADER_SLOTS: usize = 256;

/// Channel the base header and the feature word are written into: green for
/// colour images (least visible), channel 0 for grayscale / gray+alpha.
///
/// The body may use more channels ([`ChannelMode`]); the header never does, so
/// its slot set does not depend on the body's mode. That is required: the
/// feature word carries the mode, and it cannot be read before the header.
fn embed_channel(image: &RawImage) -> usize {
    if image.channels >= 3 { 1 } else { 0 }
}

/// Which pixel channels the payload body may be written into.
///
/// The embedder chooses the mode from capacity need and records it in the
/// feature word, so the extractor never guesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelMode {
    /// Green (or the carrier's only channel): the single-channel layout.
    Green = 0,
    /// Red, green and blue. Alpha is never touched.
    Rgb = 1,
}

impl ChannelMode {
    /// Wire value -> mode. Unknown values are rejected: a carrier claiming a
    /// mode this build cannot reproduce must read as "no payload here".
    fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(ChannelMode::Green),
            1 => Some(ChannelMode::Rgb),
            _ => None,
        }
    }

    /// The channels this mode writes, for a carrier with `channels` components.
    fn channels(self, channels: usize) -> &'static [usize] {
        const GREEN: [usize; 1] = [1];
        const GRAY: [usize; 1] = [0];
        const RGB: [usize; 3] = [0, 1, 2];
        match self {
            ChannelMode::Green if channels >= 3 => &GREEN,
            ChannelMode::Green => &GRAY,
            ChannelMode::Rgb => &RGB,
        }
    }

    /// False when the mode needs channels the carrier does not have.
    fn available(self, channels: usize) -> bool {
        match self {
            ChannelMode::Green => true,
            ChannelMode::Rgb => channels >= 3,
        }
    }

    /// Human-readable name for diagnostics.
    fn name(self) -> &'static str {
        match self {
            ChannelMode::Green => "green",
            ChannelMode::Rgb => "rgb",
        }
    }
}

/// The carrier's slot layout: candidates, header assignment, body pool.
///
/// Embed, extract and capacity-probe all need exactly this decision, and three
/// hand-copied versions of it had already drifted: the probe derived its header
/// permutation from `(None, None)` while the embedder used the caller's
/// password and domain. Since the 512 header/feature slots are removed from the
/// body pool, a probe with different credentials excludes *different* pixels and
/// reports a capacity the writer cannot reach.
struct SlotPlan {
    /// Body candidates: cost-ranked, after the smooth-pixel exclusion, in
    /// ranking order. Never used to place the header.
    candidates: Vec<usize>,
    /// Header layout: the eligible pixels in keyed order. The first 512 entries
    /// are the header (256) and feature-word (256) slots.
    ///
    /// This vector is a pure function of the carrier's pixels, the credentials
    /// and the format profile -- **not** of any cost map. That is what lets the
    /// extractor read the header (and therefore the algorithm id inside the
    /// feature word) before it knows which cost model wrote the carrier.
    permuted: Vec<usize>,
    /// `used_by_header[px]`: the pixel is one of those 512 slots.
    used_by_header: Vec<bool>,
}

/// Pixels eligible to carry the header channel, in ascending pixel order.
///
/// Eligibility is the class-interior test on the header channel: `val` in
/// `[8, 247]` so at least one of `val ± 1` stays inside the same eight-value
/// class. Deliberately **cost-free** -- see [`SlotPlan::permuted`].
fn header_pool(image: &RawImage) -> Vec<usize> {
    let total_pixels = image.width as usize * image.height as usize;
    let channel_offset = embed_channel(image);
    (0..total_pixels)
        .filter(|&idx| {
            let val = image.pixels[idx * image.channels + channel_offset];
            (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val)
        })
        .collect()
}

/// The keyed header layout, computed without a cost model.
///
/// Both ends call this: the writer to place the header and the feature word, the
/// reader to find them before it has resolved an algorithm.
fn header_layout(
    image: &RawImage,
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
) -> Vec<usize> {
    let mut slots = header_pool(image);
    let seed =
        crate::stego::envelope::derive_header_perm_seed_with_profile(password, domain, spatial);
    permute_prefix(&mut slots, V2_TOTAL_HEADER_SLOTS, &seed);
    slots
}

impl SlotPlan {
    /// Rank the body candidates and apply the keyed header layout.
    ///
    /// `password` / `domain` key the header permutation, so they must be the
    /// credentials the embedder will use — they change which pixels the header
    /// occupies and therefore the body capacity.
    fn build(
        image: &RawImage,
        costs: &[f64],
        params: &PngParams,
        password: Option<&str>,
        domain: Option<&str>,
        spatial: &crate::stego::format::PngFormatProfile,
    ) -> Result<Self, StrHideError> {
        let total_pixels = image.width as usize * image.height as usize;
        if costs.len() != total_pixels {
            return Err(StrHideError::General("Cost map dimension mismatch".into()));
        }
        let channel_offset = embed_channel(image);

        // Eligible pixels: the class must be interior, i.e. `val` must sit in
        // [8, 247] so that at least one of `val ± 1` stays inside the same
        // eight-value class. That keeps three invariants the extractor relies on:
        // 1. `val & 0xF8` never changes, so the HILL cost map is bit-identical;
        // 2. modified values stay in [7, 248], never reaching 0/255 (no clipping);
        // 3. eligibility itself is class-based, so both ends derive the same set.
        //
        // Ranking order is a *total* order: (cost bits, pixel index). HILL costs
        // are non-negative finite values, so their bit patterns sort exactly
        // like the values, and the index reproduces the tie-breaking the
        // previous stable `sort_by` produced -- which matters because flat areas
        // give thousands of exactly equal costs (`1 / epsilon`). A total order
        // is what allows `select_nth_unstable` below to stay bit-identical to a
        // full sort.
        let mut ranked: Vec<(u64, usize)> = (0..total_pixels)
            .filter(|&idx| {
                let val = image.pixels[idx * image.channels + channel_offset];
                (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val)
            })
            .map(|idx| (costs[idx].to_bits(), idx))
            .collect();

        // Exclude the smoothest fraction (e.g. 30%). Only the kept prefix is
        // needed, so partition first (O(n)) and sort just that prefix; the
        // candidate list grows ~3x when the body spans three channels.
        let allowed_count =
            ((ranked.len() as f64) * (1.0 - params.exclusion_percentile.clamp(0.0, 0.9))) as usize;
        if allowed_count < ranked.len() {
            ranked.select_nth_unstable(allowed_count);
            ranked.truncate(allowed_count);
        }
        ranked.sort_unstable();
        let candidates: Vec<usize> = ranked.into_iter().map(|(_, px)| px).collect();

        // The header is placed from the cost-free layout, so a reader can find
        // it without knowing the algorithm.
        let permuted = header_layout(image, password, domain, spatial);

        let mut used_by_header = vec![false; total_pixels];
        for &s in permuted.iter().take(V2_TOTAL_HEADER_SLOTS) {
            used_by_header[s] = true;
        }

        Ok(Self {
            candidates,
            permuted,
            used_by_header,
        })
    }

    /// True when there are enough candidates for the header *and* the feature
    /// word.
    fn header_fits(&self) -> bool {
        self.permuted.len() >= V2_TOTAL_HEADER_SLOTS
    }

    /// The 256 slots carrying salt | nonce | length word.
    ///
    /// Callers must have checked [`Self::header_fits`] (or, for the extractor's
    /// first read, that there are at least [`HEADER_SLOTS`]).
    fn header_slots(&self) -> &[usize] {
        &self.permuted[..HEADER_SLOTS]
    }

    /// The 256 slots carrying the [`FeatureWord`].
    fn feature_slots(&self) -> &[usize] {
        &self.permuted[HEADER_SLOTS..V2_TOTAL_HEADER_SLOTS]
    }

    /// Visit every body slot in ranking order.
    ///
    /// A slot is a **byte offset** into `image.pixels` (`pixel * channels +
    /// channel`). Expressing slots as offsets is what makes multi-channel
    /// embedding possible without a second index space, and it reduces to the
    /// historical `pixel` index when only one channel is in play. Slots come
    /// out pixel by pixel in cost order and, inside a pixel, in ascending
    /// channel order -- exactly the `(cost, channel, pixel)` total order,
    /// without materialising a second sort.
    ///
    /// Restrictions, shared by embed / extract / probe:
    /// - the pixel already passed header-channel eligibility and the
    ///   smooth-area exclusion, so one ranking serves both header and body;
    /// - the header's 512 pixels keep their header channel reserved for the
    ///   header (the body may still use their other channels: a class-internal
    ///   `±1` leaves `val & 0xF8` untouched, so the cost map the header is
    ///   ranked on is bit-identical before and after embedding);
    /// - the considered channel's own value must be class-interior and, under
    ///   the safe `class_rule == 1`, sit in `val % 8 ∈ [1, 6]`, which removes
    ///   the r=0/7 boundary deficit (P0-B).
    fn for_each_body_slot(
        &self,
        image: &RawImage,
        class_rule: u8,
        mode: ChannelMode,
        mut visit: impl FnMut(usize),
    ) {
        let channels = image.channels;
        let header_channel = embed_channel(image);
        let used = mode.channels(channels);
        for &px in &self.candidates {
            let reserved = self.used_by_header[px];
            for &c in used {
                if reserved && c == header_channel {
                    continue;
                }
                let slot = px * channels + c;
                let val = image.pixels[slot];
                if !(SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val) {
                    continue;
                }
                if class_rule == 1 && !(1..=6).contains(&(val % 8)) {
                    continue;
                }
                visit(slot);
            }
        }
    }

    /// Number of body slots available under `mode` / `class_rule`.
    fn count_body_slots(&self, image: &RawImage, class_rule: u8, mode: ChannelMode) -> usize {
        let mut n = 0usize;
        self.for_each_body_slot(image, class_rule, mode, |_| n += 1);
        n
    }

    /// The first `limit` body slots under `mode` / `class_rule`, in ranking order.
    fn body_slots_upto(
        &self,
        image: &RawImage,
        class_rule: u8,
        mode: ChannelMode,
        limit: usize,
    ) -> Vec<usize> {
        let max_possible = self
            .candidates
            .len()
            .saturating_mul(mode.channels(image.channels).len());
        let mut out = Vec::with_capacity(limit.min(max_possible));
        if limit == 0 {
            return out;
        }
        let mut taken = 0usize;
        self.for_each_body_slot(image, class_rule, mode, |slot| {
            if taken < limit {
                out.push(slot);
                taken += 1;
            }
        });
        out
    }
}

// ---------------------------------------------------------------------------
// Embedding & Extraction
// ---------------------------------------------------------------------------

/// Embed a payload into a PNG carrier with content-adaptive spatial steganography.
///
/// The complete expert entry: format identity, cost model, tuning parameters
/// and salt/nonce source are all explicit. `secret` is the resolved credential
/// (explicit password, else the profile's private stego secret, else `None` for
/// the official public constant); `domain` isolates the HKDF derivation.
/// `Freshness::Seeded` makes the output byte-identical for the same carrier,
/// payload, secret and seed. `safety` is the capacity policy the embed is
/// checked against.
#[allow(clippy::too_many_arguments)]
pub fn embed_png<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<Vec<u8>, StrHideError> {
    embed_png_with_stats(
        carrier_bytes,
        payload,
        password,
        domain,
        spatial,
        cost_model,
        params,
        safety,
        freshness,
        control,
    )
    .map(|(bytes, _)| bytes)
}

/// Embed a payload into a PNG carrier and return both modified bytes and embed statistics.
#[allow(clippy::too_many_arguments)]
pub fn embed_png_with_stats<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<(Vec<u8>, crate::stego::EmbedStats), StrHideError> {
    let payload = payload.into();
    params.validate()?;
    control.stage(Stage::Decode);
    let mut image = decode_png(carrier_bytes)?;
    // Checkpoint after the decode: on a 50 MP carrier this alone is seconds.
    control.check()?;
    control.stage(Stage::CostMap);
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    // Frame the payload and derive the per-carrier keys. The ciphertext itself
    // is produced further down: the finished 64-byte header is its associated
    // data, so it cannot exist until codec/h/u are settled.
    let suite = spatial.body.default_suite();
    let plaintext = build_plaintext(&payload)?;
    // The spatial writer makes a single pass, so the attempt index is always 0.
    // Seeded runs bind the derivation to this (cover, payload) pair so a
    // replay on different inputs can never reuse a (key, nonce) pair.
    let fresh_binding = Freshness::seeded_binding(carrier_bytes, payload.as_bytes());
    let salt = freshness.salt(0, &fresh_binding);
    let nonce = freshness.nonce(0, &fresh_binding);
    let master = derive_master(suite, password.unwrap_or(spatial.fallback_secret), &salt)?;
    let (enc_key, perm_seed) = body_keys(spatial.body, &master, &salt, domain);
    let ciphertext_len = plaintext.len() + suite.tag_len();

    // Quantise the hyperparameters to their wire-exact forms *before* any
    // use, and run the whole embed on them: the feature word can only carry
    // `epsilon` as a power of two and `sigma` at `f32` precision, so the
    // extractor can only ever reproduce these forms. The prober quantises
    // the same way, so advertised capacity and embedding pool agree.
    let params = params.wire_quantized();
    let eps_k = FeatureWord::quantize_epsilon(params.epsilon);

    // Compute distortion cost map
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, &params);
    // Checkpoint after the cost map: the second big fixed cost of an embed.
    control.check()?;
    control.stage(Stage::Solve);

    let channel_offset = embed_channel(&image);

    let plan = SlotPlan::build(&image, &costs, &params, password, domain, spatial)?;
    if !plan.header_fits() {
        return Err(StrHideError::General(format!(
            "Carrier capacity insufficient: available {} slots, minimum header requires {} slots",
            plan.permuted.len(),
            V2_TOTAL_HEADER_SLOTS
        )));
    }
    let header_slots = plan.header_slots();
    let feature_slots = plan.feature_slots();

    let ciphertext_bits = ciphertext_len * 8;

    // Single-channel body pool first. Small payloads therefore keep the exact
    // layout (and byte-for-byte output) they had before multi-channel existed.
    let pool_green = plan.count_body_slots(&image, 1, ChannelMode::Green);

    // Safety enforcement policy check
    if safety.is_enforced() {
        let bpp_limit = safety.level.bpp_limit();
        let bpp_bits = (total_pixels as f64 * bpp_limit).floor() as usize;
        // Deliberately the single-channel pool: the tier is expressed in bits
        // per *pixel*, and a three-channel pool would loosen the ratio bound
        // without any calibration for the extra channels.
        let ratio_bits = (pool_green as f64 / safety.level.target_ratio()).floor() as usize;
        let recommended_max_bytes =
            (bpp_bits.min(ratio_bits) / 8).saturating_sub(crate::stego::envelope::BODY_OVERHEAD);

        if payload.len() > recommended_max_bytes {
            let payload_bpp = (payload.len() * 8) as f64 / total_pixels as f64;
            return Err(StrHideError::General(format!(
                "Payload ({} bytes, bpp {:.4}) exceeds safety threshold ({} bytes, bpp <= {:.2}) for tier '{}'",
                payload.len(),
                payload_bpp,
                recommended_max_bytes,
                bpp_limit,
                safety.level.as_str(),
            )));
        }
    }

    // Resolve matrix-coding strategy: Auto adaptively picks STC group size (u=3, 2, or 1)
    let (resolved_codec, resolved_u) = match params.codec {
        StegoCodec::Auto => crate::stego::coding::auto_select_codec(pool_green, ciphertext_bits),
        StegoCodec::Stc if params.stc_u == 0 => {
            crate::stego::coding::auto_select_codec(pool_green, ciphertext_bits)
        }
        StegoCodec::Stc => (StegoCodec::Stc, params.stc_u),
        StegoCodec::Hamming => (StegoCodec::Hamming, 0),
    };

    // The slot count follows from the payload and the codec, never from the
    // pool, so `u` does not have to be re-resolved when the mode grows.
    let needed_body_slots = crate::stego::coding::slots_for_codec(
        ciphertext_bits,
        resolved_codec,
        params.stc_h,
        resolved_u,
    )?;

    // Pick the smallest channel mode that fits. `Rgb` only adds slots, so the
    // single-channel layout is used whenever it is sufficient.
    let (mode, pool_max) = if needed_body_slots <= pool_green {
        (ChannelMode::Green, pool_green)
    } else if image.channels >= 3 {
        let pool_rgb = plan.count_body_slots(&image, 1, ChannelMode::Rgb);
        if needed_body_slots <= pool_rgb {
            (ChannelMode::Rgb, pool_rgb)
        } else {
            return Err(StrHideError::General(format!(
                "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{} {})",
                needed_body_slots,
                resolved_codec.describe(params.stc_h, resolved_u),
                pool_rgb,
                cost_model.id(),
                ChannelMode::Rgb.name(),
            )));
        }
    } else {
        return Err(StrHideError::General(format!(
            "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{})",
            needed_body_slots,
            resolved_codec.describe(params.stc_h, resolved_u),
            pool_green,
            cost_model.id(),
        )));
    };
    trace(&format!(
        "plan pool_green={pool_green} pool_max={pool_max} needed={needed_body_slots} mode={:?}",
        mode
    ));

    // Header word1 encodes total_len with HEADER_V2_ESCAPE_H (15) for stc_h
    let total_len = (crate::stego::envelope::HEADER_OVERHEAD + ciphertext_len) as u32;
    if total_len > HEADER_LEN_MAX {
        return Err(StrHideError::General(format!(
            "Envelope of {total_len} bytes exceeds the {HEADER_LEN_MAX}-byte header length field"
        )));
    }
    let header_word = encode_header_word(total_len, resolved_codec, HEADER_V2_ESCAPE_H, resolved_u);
    let mut header_bytes = Vec::with_capacity(32);
    header_bytes.extend_from_slice(&salt); // Salt (16B)
    header_bytes.extend_from_slice(&nonce); // Nonce (12B)
    header_bytes.extend_from_slice(&header_word.to_be_bytes());

    // The hyperparameters were quantised to wire-exact forms at the top of
    // this function, so what the feature word records is exactly what the
    // embedder computed with.
    let fw = FeatureWord {
        version: 3,
        codec: resolved_codec,
        u: resolved_u,
        h: params.stc_h,
        // Self-describing: the extractor rebuilds the body pool from this and
        // nothing else, so a write here would desynchronise the two ends.
        channel_mode: mode as u8,
        class_rule: 1, // Safe [1, 6] non-boundary
        // `params.validate()` guarantees odd windows <= 63, well inside the
        // 10-bit wire field.
        p1_window: params.p1_window as u16,
        p2_window: params.p2_window as u16,
        neg_log2_epsilon: eps_k,
        exclusion_permille: (params.exclusion_percentile.clamp(0.0, 0.9) * 1000.0) as u16,
        // The carrier has to name its own cost model: the extractor reads the
        // header before it knows which algorithm wrote the body, so there is no
        // out-of-band channel to rely on. A model without a wire id would
        // produce a carrier nobody (including this build) could read back.
        algorithm_id: crate::stego::png::registry::spatial_wire_id(cost_model.id())
            .ok_or_else(|| {
                StrHideError::General(format!(
                    "PNG cost model '{}' has no wire id; a carrier written with it could not be extracted",
                    cost_model.id()
                ))
            })?,
        sigma: params
            .algorithm_options
            .get("sigma")
            .copied()
            .unwrap_or(1.0) as f32,
        kernel_id: 0, // the built-in KB kernel; custom kernels need matching configs
    };
    let feature_bytes = fw.encode();

    // Encrypt last: the whole 64-byte header (32B base header + 32B feature
    // word) is the AEAD's associated data, so a tampered codec/h/u fails the
    // tag instead of steering the decoder somewhere else.
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(&header_bytes);
    aad.extend_from_slice(&feature_bytes);
    let ciphertext_body = encrypt_with_aad(suite, &enc_key, &nonce, &aad, &plaintext)?;

    // Phase 2: Keyed permutation of body slots.
    let stc_seed =
        crate::stego::envelope::derive_stc_seed_with_label(&perm_seed, &salt, spatial.stc_label);

    let mut body_slots = plan.body_slots_upto(&image, 1, mode, needed_body_slots);
    debug_assert_eq!(body_slots.len(), needed_body_slots, "pool counted above");
    permute_indices(&mut body_slots, &perm_seed);

    // Asymmetric per-direction costs. Embed-side only: ranking never sees them,
    // so the extractor does not have to reproduce them.
    //
    // The model prices only the requested slots, so the working set stays
    // payload-sized instead of materializing full-plane maps per channel.
    // Header slots are already pixel indices on the header channel; body
    // slots are byte offsets and become pixel indices per channel.
    let mut header_rp = vec![0.0f64; V2_TOTAL_HEADER_SLOTS];
    let mut header_rm = vec![0.0f64; V2_TOTAL_HEADER_SLOTS];
    let mut body_rp = vec![0.0f64; needed_body_slots];
    let mut body_rm = vec![0.0f64; needed_body_slots];
    let header_px: Vec<usize> = header_slots
        .iter()
        .chain(feature_slots.iter())
        .copied()
        .collect();
    for &channel in mode.channels(image.channels) {
        // Body pixel indices for this channel, in body-slot order (the
        // per-channel subset stays at its body-slot position).
        let body_px: Vec<usize> = body_slots
            .iter()
            .filter(|&&slot| slot % image.channels == channel)
            .map(|&slot| slot / image.channels)
            .collect();
        let (header_plus, header_minus) = if channel == channel_offset {
            cost_model.direction_costs(
                &costs,
                &image.pixels,
                w,
                h,
                image.channels,
                channel,
                &header_px,
            )
        } else {
            (Vec::new(), Vec::new())
        };
        let (body_plus, body_minus) = cost_model.direction_costs(
            &costs,
            &image.pixels,
            w,
            h,
            image.channels,
            channel,
            &body_px,
        );
        if channel == channel_offset {
            if header_plus.len() != header_px.len() || header_minus.len() != header_px.len() {
                return Err(StrHideError::General(
                    "Direction cost vector dimension mismatch".into(),
                ));
            }
            for (i, (&rp, &rm)) in header_plus.iter().zip(header_minus.iter()).enumerate() {
                header_rp[i] = rp;
                header_rm[i] = rm;
            }
        }
        if body_plus.len() != body_px.len() || body_minus.len() != body_px.len() {
            return Err(StrHideError::General(
                "Direction cost vector dimension mismatch".into(),
            ));
        }
        let mut k = 0usize;
        for (i, &slot) in body_slots.iter().enumerate() {
            if slot % image.channels == channel {
                body_rp[i] = body_plus[k];
                body_rm[i] = body_minus[k];
                k += 1;
            }
        }
    }

    let mut modified_slots = 0;

    // Embed Phase 1a: 32-byte header word1 (256 slots)
    for (byte_i, &b) in header_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let bit_index = byte_i * 8 + bit_i;
            let byte_idx = header_slots[bit_index] * image.channels + channel_offset;
            let prev = image.pixels[byte_idx];
            write_bit_ternary(
                &mut image.pixels[byte_idx],
                target_bit,
                header_rp[bit_index],
                header_rm[bit_index],
            );
            if image.pixels[byte_idx] != prev {
                modified_slots += 1;
            }
        }
    }

    // Embed Phase 1b: 32-byte feature word (256 slots)
    for (byte_i, &b) in feature_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let bit_index = HEADER_SLOTS + byte_i * 8 + bit_i;
            let byte_idx = feature_slots[byte_i * 8 + bit_i] * image.channels + channel_offset;
            let prev = image.pixels[byte_idx];
            write_bit_ternary(
                &mut image.pixels[byte_idx],
                target_bit,
                header_rp[bit_index],
                header_rm[bit_index],
            );
            if image.pixels[byte_idx] != prev {
                modified_slots += 1;
            }
        }
    }

    // Embed Phase 2: Ciphertext body. Slots are byte offsets, so the write is
    // a direct `pixels[slot]` -- no channel arithmetic left to get wrong.
    let mut slot_vals: Vec<u8> = body_slots.iter().map(|&slot| image.pixels[slot]).collect();
    let moves: Vec<Move> = slot_vals.iter().map(|&v| spatial_move_safe(v)).collect();
    match resolved_codec {
        StegoCodec::Hamming => {
            hamming_embed_ternary(
                &mut slot_vals,
                &moves,
                &body_rp,
                &body_rm,
                &ciphertext_body,
                crate::stego::coding::DEFAULT_HAMMING_K,
            )?;
        }
        StegoCodec::Stc | StegoCodec::Auto => {
            let trellis = StcTrellis::from_seed_grouped(stc_seed, params.stc_h, resolved_u)?;
            trellis.embed(&mut slot_vals, &moves, &body_rp, &body_rm, &ciphertext_body)?;
        }
    }

    for (i, &slot) in body_slots.iter().enumerate() {
        if image.pixels[slot] != slot_vals[i] {
            modified_slots += 1;
        }
        image.pixels[slot] = slot_vals[i];
    }

    control.stage(Stage::Encode);
    let encoded = encode_png(&image)?;
    let stats = crate::stego::EmbedStats {
        modified_slots,
        total_candidate_slots: total_pixels,
    };
    Ok((encoded, stats))
}

/// Extract a payload from a PNG carrier with content-adaptive spatial steganography.
///
/// The complete expert entry. The carrier declares its cost model in the
/// feature word, so `cost_model` is only a hint; `params` must repeat the
/// embed-time filter windows because the body slot ranking is recomputed from
/// the cost map.
pub fn extract_png(
    carrier_bytes: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    control.stage(Stage::Decode);
    let image = decode_png(carrier_bytes)?;
    control.check()?;
    let w = image.width as usize;
    let h = image.height as usize;
    let channel_offset = embed_channel(&image);

    // Read the header *before* touching any cost model.
    //
    // The header layout is a pure function of the pixels, the credentials and
    // the format profile, so the carrier can tell us which algorithm wrote the
    // body. That is the whole point of placing the header without a cost map:
    // the model is named inside the feature word, and reading the feature word
    // must not require already knowing the model.
    let header_layout = header_layout(&image, password, domain, spatial);
    if header_layout.len() < HEADER_SLOTS {
        return Err(StrHideError::NoHiddenData(
            "Carrier has insufficient capacity for stego header".into(),
        ));
    }
    let header_slots = &header_layout[..HEADER_SLOTS];

    // Read Phase 1: 32-byte Header ([16B Salt][12B Nonce][4B Total Len])
    let mut header_bytes = [0u8; 32];
    for byte_i in 0..32 {
        let mut b = 0u8;
        for bit_i in 0..8 {
            let slot = header_slots[byte_i * 8 + bit_i];
            let val = image.pixels[slot * image.channels + channel_offset];
            b = (b << 1) | (val & 1);
        }
        header_bytes[byte_i] = b;
    }

    let salt = &header_bytes[..16];
    let (total_len, _raw_codec_id, raw_stc_h) = {
        let word = u32::from_be_bytes([
            header_bytes[28],
            header_bytes[29],
            header_bytes[30],
            header_bytes[31],
        ]);
        let (len, codec_id, stc_h) = decode_header_word(word);
        (len as usize, codec_id, stc_h)
    };

    // A total length below the smallest envelope the writer can produce is
    // indistinguishable from noise, so it is rejected here rather than
    // allocating for a payload that cannot exist.
    if !(crate::stego::envelope::MIN_ENVELOPE_LEN..=HEADER_LEN_MAX as usize).contains(&total_len) {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());

    // Every carrier this build writes uses the v2 header. A different `h` field
    // means the header landed on the wrong slots, i.e. wrong password or no
    // payload -- report it exactly like an AEAD failure.
    if raw_stc_h != HEADER_V2_ESCAPE_H || header_layout.len() < V2_TOTAL_HEADER_SLOTS {
        return Err(no_hidden());
    }

    let feature_slots = &header_layout[HEADER_SLOTS..V2_TOTAL_HEADER_SLOTS];
    let mut feature_bytes = [0u8; 32];
    for byte_i in 0..32 {
        let mut b = 0u8;
        for bit_i in 0..8 {
            let slot = feature_slots[byte_i * 8 + bit_i];
            let val = image.pixels[slot * image.channels + channel_offset];
            b = (b << 1) | (val & 1);
        }
        feature_bytes[byte_i] = b;
    }

    let fw = FeatureWord::decode(&feature_bytes).map_err(|_| no_hidden())?;

    // The carrier names its cost model. An id this build does not know means a
    // carrier written by a newer tool -- reported exactly like "no payload",
    // because guessing a model would silently decode noise.
    let resolved = crate::stego::png::registry::spatial_model_from_wire_id(fw.algorithm_id)
        .ok_or_else(no_hidden)?;
    if resolved.id() != cost_model.id() {
        // The carrier is authoritative; the caller's choice is only a hint.
        trace(&format!(
            "carrier declares '{}', caller asked for '{}': using the carrier's",
            resolved.id(),
            cost_model.id()
        ));
    }

    // The carrier is self-describing about every hyperparameter that shapes
    // the cost map: exclusion percentile, HILL's windows and epsilon, and the
    // sigma model option. Whatever the caller configured is a hint only --
    // the wire values are what the embedder actually computed with.
    let mut effective_params = params.clone();
    effective_params.exclusion_percentile = (fw.exclusion_permille as f64) / 1000.0;
    effective_params.p1_window = fw.p1_window as usize;
    effective_params.p2_window = fw.p2_window as usize;
    effective_params.epsilon = fw.epsilon();
    if resolved.id() == "suniward" {
        effective_params
            .algorithm_options
            .insert("sigma".to_string(), fw.sigma as f64);
    }

    // Distortion cost map of the declared model. Identical to what the embedder
    // computed, because header/feature pixels never leave their eight-value
    // class, so the map is bit-identical on the stego.
    let costs = resolved.compute_cost(&image.pixels, w, h, image.channels, &effective_params);
    control.check()?;
    // Body ranking needs costs; the header layout inside this plan is the same
    // cost-free one read above, so the two cannot disagree.
    let plan = SlotPlan::build(&image, &costs, &effective_params, password, domain, spatial)?;
    debug_assert_eq!(
        plan.permuted.get(..V2_TOTAL_HEADER_SLOTS),
        Some(&header_layout[..V2_TOTAL_HEADER_SLOTS]),
        "the header layout must not depend on the cost map"
    );

    // The body's channel mode arrives in the feature word. An unknown value, or
    // one the carrier cannot support, means the header landed on the wrong
    // slots -- folded into the same generic failure as an AEAD reject.
    let mode = ChannelMode::from_wire(fw.channel_mode).ok_or_else(no_hidden)?;
    if !mode.available(image.channels) {
        return Err(no_hidden());
    }

    let ciphertext_len = total_len - crate::stego::envelope::HEADER_OVERHEAD;
    let ciphertext_bits = ciphertext_len * 8;
    let needed_body_slots =
        crate::stego::coding::slots_for_codec(ciphertext_bits, fw.codec, fw.h, fw.u)?;

    // Reject untrusted/bogus header total_len before allocating body slots.
    let pool = plan.count_body_slots(&image, fw.class_rule, mode);
    if needed_body_slots > pool {
        return Err(no_hidden());
    }

    let master = derive_master(
        spatial.body.default_suite(),
        password.unwrap_or(spatial.fallback_secret),
        salt,
    )?;
    let (enc_key, perm_seed) = body_keys(spatial.body, &master, salt, domain);

    let mut body_slots = plan.body_slots_upto(&image, fw.class_rule, mode, needed_body_slots);
    trace(&format!(
        "extract mode={:?} class_rule={} total_len={total_len} needed={needed_body_slots} pool={}",
        mode,
        fw.class_rule,
        body_slots.len()
    ));
    // Short pool == the carrier is smaller than the header claims: no payload.
    if body_slots.len() < needed_body_slots {
        return Err(no_hidden());
    }
    permute_indices(&mut body_slots, &perm_seed);

    let slot_vals: Vec<u8> = body_slots.iter().map(|&slot| image.pixels[slot]).collect();

    let ciphertext = match fw.codec {
        StegoCodec::Hamming => hamming_extract_bytes(
            &slot_vals,
            ciphertext_len,
            crate::stego::coding::DEFAULT_HAMMING_K,
        )?,
        StegoCodec::Stc | StegoCodec::Auto => {
            let stc_seed = crate::stego::envelope::derive_stc_seed_with_label(
                &perm_seed,
                salt,
                spatial.stc_label,
            );
            let trellis = StcTrellis::from_seed_grouped(stc_seed, fw.h, fw.u)?;
            trellis.extract(&slot_vals, ciphertext_bits)
        }
    };

    let nonce: [u8; crate::stego::envelope::NONCE_LEN] = header_bytes
        [crate::stego::envelope::SALT_LEN..crate::stego::envelope::HEADER_OVERHEAD]
        .try_into()
        .map_err(|_| no_hidden())?;
    let mut aad = Vec::with_capacity(64);
    aad.extend_from_slice(&header_bytes);
    aad.extend_from_slice(&feature_bytes);
    unpack_envelope_parts(
        spatial.body.default_suite(),
        &enc_key,
        &nonce,
        &aad,
        &ciphertext,
    )
}

/// Inspect PNG for stego header and self-describing metadata without decoding body.
pub fn inspect_png(
    carrier_bytes: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let image = match decode_png(carrier_bytes) {
        Ok(img) => img,
        Err(e) => {
            return Ok(StegoHeaderInfo {
                format: "PNG".into(),
                has_hidden_data: false,
                algorithm: None,
                codec: None,
                envelope_len: None,
                payload_len: None,
                media_info: None,
                note: Some(format!("Decode failed: {e}")),
            });
        }
    };
    control.check()?;
    let media_info = Some(MediaInfo::new(image.width, image.height));
    let mut empty_info = StegoHeaderInfo::empty("PNG");
    empty_info.media_info = media_info;

    let channel_offset = embed_channel(&image);
    let header_layout = header_layout(&image, password, domain, spatial);
    if header_layout.len() < V2_TOTAL_HEADER_SLOTS {
        return Ok(empty_info);
    }
    let header_slots = &header_layout[..HEADER_SLOTS];

    // Read Phase 1: 32-byte Header ([16B Salt][12B Nonce][4B Total Len])
    let mut header_bytes = [0u8; 32];
    for byte_i in 0..32 {
        let mut b = 0u8;
        for bit_i in 0..8 {
            let slot = header_slots[byte_i * 8 + bit_i];
            let val = image.pixels[slot * image.channels + channel_offset];
            b = (b << 1) | (val & 1);
        }
        header_bytes[byte_i] = b;
    }

    let (total_len, raw_stc_h) = {
        let word = u32::from_be_bytes([
            header_bytes[28],
            header_bytes[29],
            header_bytes[30],
            header_bytes[31],
        ]);
        let (len, _codec_id, stc_h) = decode_header_word(word);
        (len as usize, stc_h)
    };

    if !(crate::stego::envelope::MIN_ENVELOPE_LEN..=HEADER_LEN_MAX as usize).contains(&total_len) {
        return Ok(empty_info);
    }
    if raw_stc_h != HEADER_V2_ESCAPE_H {
        return Ok(empty_info);
    }

    let feature_slots = &header_layout[HEADER_SLOTS..V2_TOTAL_HEADER_SLOTS];
    let mut feature_bytes = [0u8; 32];
    for byte_i in 0..32 {
        let mut b = 0u8;
        for bit_i in 0..8 {
            let slot = feature_slots[byte_i * 8 + bit_i];
            let val = image.pixels[slot * image.channels + channel_offset];
            b = (b << 1) | (val & 1);
        }
        feature_bytes[byte_i] = b;
    }

    let Ok(fw) = FeatureWord::decode(&feature_bytes) else {
        return Ok(empty_info);
    };

    let algo_name = crate::stego::png::registry::spatial_model_from_wire_id(fw.algorithm_id)
        .map(|m| m.id().to_string())
        .unwrap_or_else(|| format!("Unknown(0x{:02x})", fw.algorithm_id));

    Ok(StegoHeaderInfo {
        format: "PNG".into(),
        has_hidden_data: true,
        algorithm: Some(algo_name),
        codec: Some(format!("{:?} (h={}, u={})", fw.codec, fw.h, fw.u)),
        envelope_len: Some(total_len),
        payload_len: None,
        media_info,
        note: None,
    })
}

/// Three-level diagnostic verification for PNG carriers.
pub fn verify_png(
    carrier_bytes: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    _limits: &crate::stego::params::ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    control.check()?;
    let mut levels = Vec::new();

    // Level 1: Container & Decode
    let image = match decode_png(carrier_bytes) {
        Ok(img) => {
            levels.push(VerifyLevel::pass(
                1,
                format!(
                    "PNG structure valid ({}x{}, {} channels)",
                    img.width, img.height, img.channels
                ),
            ));
            img
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(1, "PNG structure decode", e.to_string()));
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                "Skipped due to level 1 failure",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "Skipped due to level 1 failure",
            ));
            return Ok(StegoVerifyResult::new("PNG", levels));
        }
    };
    let _ = image;
    control.check()?;

    // Level 2: Stego Header & FeatureWord
    let header_info = inspect_png(carrier_bytes, password, domain, spatial, control)?;
    if !header_info.has_hidden_data {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            "No valid stego header or FeatureWord found (or wrong password)",
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "No stego header to extract payload from",
        ));
        return Ok(StegoVerifyResult::new("PNG", levels));
    }
    levels.push(VerifyLevel::pass(
        2,
        format!(
            "Stego header valid (algorithm: {}, codec: {}, envelope: {} B)",
            header_info.algorithm.as_deref().unwrap_or("unknown"),
            header_info.codec.as_deref().unwrap_or("unknown"),
            header_info.envelope_len.unwrap_or(0),
        ),
    ));
    control.check()?;

    // Level 3: Payload Decryption & AEAD Authenticity
    let model = crate::stego::options::SpatialAlgorithm::default().model();
    let params = crate::stego::params::PngParams::default();
    match extract_png(
        carrier_bytes,
        password,
        domain,
        spatial,
        &*model,
        &params,
        control,
    ) {
        Ok(payload) => {
            let desc = match payload.name() {
                Some(name) => format!(
                    "Payload decrypted & verified ({} bytes, filename: '{}')",
                    payload.len(),
                    name
                ),
                None => format!(
                    "Payload decrypted & verified ({} bytes, raw/text)",
                    payload.len()
                ),
            };
            levels.push(VerifyLevel::pass(3, desc));
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                format!("Decryption or authentication failed: {e}"),
            ));
        }
    }

    Ok(StegoVerifyResult::new("PNG", levels))
}

/// Probe the embedding capacity of a PNG carrier.
///
/// The complete expert entry: `safety_level` picks the tier `recommended_max_bytes`
/// is derived from; `secret`/`domain` key the header-slot permutation, which
/// decides which pixels are available to the payload.
#[allow(clippy::too_many_arguments)]
pub fn probe_png_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety_level: crate::stego::SafetyLevel,
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    params.validate()?;
    // Probe with the same wire-quantised hyperparameters the embedder will
    // use, so the advertised capacity matches the pool embedding sees.
    let params = params.wire_quantized();
    control.stage(Stage::Decode);
    let image = decode_png(carrier_bytes)?;
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    control.stage(Stage::CostMap);
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, &params);
    control.check()?;

    let plan = SlotPlan::build(&image, &costs, &params, password, domain, spatial)?;

    // Two pool sizes, for two different questions:
    // - `available_body_slots` answers "how much can the writer actually
    //   reach?", which is the three-channel pool when the carrier has one;
    // - `ratio_slots` feeds the safety tier's `slots / bits` bound, which was
    //   calibrated on single-channel carriers. Reporting the tripled pool there
    //   would silently raise the recommended payload without any evidence that
    //   three channels are equally safe, so it keeps the single-channel base.
    let header_fits = plan.header_fits();
    let pool_green = if header_fits {
        plan.count_body_slots(&image, 1, ChannelMode::Green)
    } else {
        0
    };
    let available_body_slots = match (header_fits, image.channels >= 3) {
        (false, _) => 0,
        (true, true) => plan.count_body_slots(&image, 1, ChannelMode::Rgb),
        (true, false) => pool_green,
    };
    let ratio_slots = pool_green;

    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    // The two codecs buy different payload per slot, and the difference is
    // real (measured: a carrier that cannot hold 33 KB under Hamming holds it
    // under STC). Reporting one codec's figure for the other would misstate the
    // capability in whichever direction the user is asking about, so the number
    // follows `params.codec`.
    let max_ciphertext_bytes = match params.codec {
        StegoCodec::Hamming => {
            crate::stego::coding::max_payload_bytes(available_body_slots, hamming_k)
        }
        StegoCodec::Stc if params.stc_u > 0 => {
            // `u * (bits + h - 1) = slots` -> `bits = slots/u - (h - 1)`.
            let trellis = StcTrellis::from_seed_grouped(0, params.stc_h, params.stc_u)?;
            trellis.message_bits(available_body_slots) / 8
        }
        StegoCodec::Stc | StegoCodec::Auto => {
            // In Auto mode (or STC with auto u), maximum raw capacity reaches up to STC u=1,
            // as the encoder adaptively drops to u=1 when large payloads are embedded.
            let trellis = StcTrellis::from_seed_grouped(0, params.stc_h, 1)?;
            trellis.message_bits(available_body_slots) / 8
        }
    };
    // Only the body-borne overhead comes off here: salt/nonce already paid for
    // by the 256 header slots. Subtracting MIN_ENVELOPE_LEN under-reported the
    // capacity by exactly 28 bytes (measured on real carriers).
    let max_raw_payload_bytes =
        max_ciphertext_bytes.saturating_sub(crate::stego::envelope::BODY_OVERHEAD);

    // Recommended capacity bounded by safety tier bpp budget and candidate slot ratio r
    let bpp_bits = (total_pixels as f64 * safety_level.bpp_limit()).floor() as usize;
    let ratio_bits = (ratio_slots as f64 / safety_level.target_ratio()).floor() as usize;
    let target_bits = bpp_bits.min(ratio_bits);
    let recommended_max_bytes =
        (target_bits / 8).saturating_sub(crate::stego::envelope::BODY_OVERHEAD);

    Ok(StegoCapacityInfo {
        format: "PNG".into(),
        algorithm: cost_model.id().into(),
        total_elements: total_pixels,
        available_slots: available_body_slots,
        max_raw_payload_bytes,
        // The spatial codec has no Huffman-table hazard, so its ceiling is
        // always the geometric one.
        max_raw_is_grouped: false,
        recommended_max_bytes,
        estimated_change_rate: match params.codec {
            StegoCodec::Hamming => crate::stego::coding::expected_change_rate(hamming_k),
            StegoCodec::Stc if params.stc_u > 0 => {
                crate::stego::coding::expected_stc_change_rate(params.stc_u)
            }
            StegoCodec::Stc | StegoCodec::Auto => crate::stego::coding::expected_stc_change_rate(3),
        },
        safety_level: safety_level.as_str().into(),
        safety_bpp_limit: safety_level.bpp_limit(),
        is_estimated: false,
        media_info: Some(MediaInfo::new(image.width, image.height)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::params::PngParams;
    use crate::stego::png::cost::HillCostModel;

    #[allow(clippy::too_many_arguments)]
    fn embed_png(
        carrier_bytes: &[u8],
        payload: &[u8],
        password: Option<&str>,
        domain: Option<&str>,
        spatial: &crate::stego::format::PngFormatProfile,
        cost_model: &dyn PngCostModel,
        params: &PngParams,
        safety: SafetyPolicy,
        freshness: Freshness,
        control: &Control<'_>,
    ) -> Result<Vec<u8>, StrHideError> {
        super::embed_png(
            carrier_bytes,
            payload,
            password,
            domain,
            spatial,
            cost_model,
            params,
            safety,
            freshness,
            control,
        )
    }

    fn extract_png(
        carrier_bytes: &[u8],
        password: Option<&str>,
        domain: Option<&str>,
        spatial: &crate::stego::format::PngFormatProfile,
        cost_model: &dyn PngCostModel,
        params: &PngParams,
        control: &Control<'_>,
    ) -> Result<Vec<u8>, StrHideError> {
        super::extract_png(
            carrier_bytes,
            password,
            domain,
            spatial,
            cost_model,
            params,
            control,
        )
        .map(Payload::into_bytes)
    }

    /// Craft a PNG: IHDR + ancillary chunks + one IDAT + IEND, with the
    /// given per-row filters applied to `pixels` (RGB, 8-bit).
    fn craft_png(
        width: u32,
        height: u32,
        pixels: &[u8],
        row_filters: &[u8],
        ancillary: &[(&[u8; 4], &[u8])],
        idat_parts: usize,
    ) -> Vec<u8> {
        craft_png_at_level(
            width,
            height,
            pixels,
            row_filters,
            ancillary,
            idat_parts,
            Compression::default().level(),
        )
    }

    /// [`craft_png`] with an explicit zlib level, so the level-matching path
    /// can be exercised against carriers written the way real tools write them.
    fn craft_png_at_level(
        width: u32,
        height: u32,
        pixels: &[u8],
        row_filters: &[u8],
        ancillary: &[(&[u8; 4], &[u8])],
        idat_parts: usize,
        level: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        let mut ihdr = Vec::with_capacity(13);
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.push(8); // bit depth
        ihdr.push(2); // color type: RGB
        ihdr.push(0); // compression
        ihdr.push(0); // filter method
        ihdr.push(0); // interlace
        write_chunk(&mut out, b"IHDR", &ihdr);
        for (ty, body) in ancillary {
            write_chunk(&mut out, ty, body);
        }
        let stride = width as usize * 3;
        let zero_row = vec![0u8; stride];
        let mut filtered = Vec::with_capacity((stride + 1) * height as usize);
        for (y, row) in pixels.chunks_exact(stride).enumerate() {
            let prev: &[u8] = if y == 0 {
                &zero_row
            } else {
                &pixels[(y - 1) * stride..y * stride]
            };
            filtered.push(row_filters[y]);
            filtered.extend_from_slice(&filter_row(prev, row, row_filters[y], 3));
        }
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
        encoder.write_all(&filtered).expect("deflate");
        let idat = encoder.finish().expect("deflate finish");
        // Split the compressed stream into `idat_parts` IDAT chunks.
        let parts = idat_parts.max(1);
        let chunk_len = idat.len().div_ceil(parts);
        for piece in idat.chunks(chunk_len.max(1)) {
            write_chunk(&mut out, b"IDAT", piece);
        }
        write_chunk(&mut out, b"IEND", &[]);
        out
    }

    /// Vertical gradient (constant along x): the ideal case for filter 2.
    fn gradient_pixels(w: usize, h: usize) -> Vec<u8> {
        let mut px = vec![0u8; w * h * 3];
        for y in 0..h {
            let v = (y * 4) as u8;
            for x in 0..w {
                let i = (y * w + x) * 3;
                px[i] = v;
                px[i + 1] = v;
                px[i + 2] = v;
            }
        }
        px
    }

    /// Row-correlated noisy image: each row continues the previous one plus a
    /// small deterministic jitter. Filter 2 removes the row trend; filter 0
    /// has to entropy-code the full 0..250 spread -- the situation where
    /// forcing filter 0 inflates the IDAT.
    fn row_correlated_pixels(w: usize, h: usize) -> Vec<u8> {
        let mut px = vec![0u8; w * h * 3];
        for y in 0..h {
            for x in 0..w {
                let i = (y * w + x) * 3;
                let base = (x * 5 + y * 3) % 251;
                let jitter = (x * 31 + y * 17) % 7;
                let v = (base + jitter) as u8;
                px[i] = v;
                px[i + 1] = v;
                px[i + 2] = v;
            }
        }
        px
    }

    fn chunk_types(img: &RawImage) -> Vec<[u8; 4]> {
        img.chunks.iter().map(|c| c.ty).collect()
    }

    #[test]
    fn decode_captures_ancillary_chunks_and_row_filters() {
        let (w, h) = (16usize, 16usize);
        let pixels = gradient_pixels(w, h);
        let bkgd = [0u8, 0, 0, 0, 0, 0]; // bKGD body for RGB
        let text = b"Comment\0crafted-for-test".to_vec();
        let gama = 45455u32.to_be_bytes();
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![2u8; h], // filter 2 (Up) everywhere
            &[(b"bKGD", &bkgd), (b"gAMA", &gama), (b"tEXt", &text)],
            1,
        );

        let img = decode_png(&png).expect("decode");
        assert_eq!(
            chunk_types(&img),
            vec![*b"IHDR", *b"bKGD", *b"gAMA", *b"tEXt", *b"IDAT", *b"IEND"]
        );
        assert_eq!(img.row_filters, vec![2u8; h]);
        assert_eq!(img.pixels, pixels, "pixels must decode identically");
    }

    #[test]
    fn reencode_replays_chunks_and_filters() {
        let (w, h) = (16usize, 16usize);
        let pixels = gradient_pixels(w, h);
        let text = b"Comment\0crafted-for-test".to_vec();
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![2u8; h],
            &[(b"tEXt", &text)],
            1,
        );

        let img = decode_png(&png).expect("decode");
        let re = encode_png(&img).expect("encode");
        let img2 = decode_png(&re).expect("re-decode");
        assert_eq!(chunk_types(&img), chunk_types(&img2));
        assert_eq!(
            img.chunks, img2.chunks,
            "chunk bodies must be byte-identical"
        );
        assert_eq!(img2.row_filters, vec![2u8; h]);
        assert_eq!(img2.pixels, pixels);
    }

    #[test]
    fn filter_preservation_keeps_idat_small() {
        // The regression that motivated chunk/filter passthrough: a smooth
        // carrier re-encoded with filter 0 on every row inflated by ~23% on
        // the real corpus sample.
        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![2u8; h],
            &[(b"tEXt", b"Comment\0noise".as_slice())],
            1,
        );

        let img = decode_png(&png).expect("decode");
        let preserved = encode_png(&img).expect("encode");

        // Same image, but with the recorded filters discarded (old behaviour).
        let mut flat = img.clone();
        flat.row_filters = Vec::new();
        let filter0 = encode_png(&flat).expect("encode");

        assert!(
            preserved.len() < filter0.len(),
            "preserved filters must not inflate: {} vs {} bytes",
            preserved.len(),
            filter0.len()
        );
        assert_eq!(
            decode_png(&preserved).expect("decode").pixels,
            pixels,
            "pixels must survive the filtered re-encode"
        );
    }

    /// v3 feature word: hyperparameters the extractor does not have to be
    /// told about — non-default HILL windows, a non-power-of-two epsilon and
    /// a non-default S-UNIWARD sigma must round-trip through the carrier
    /// alone. Under v2 this silently returned `NoHiddenData` because the
    /// extractor rebuilt the ranking with its own defaults.
    #[test]
    fn nondefault_hyperparameters_roundtrip_via_feature_word() {
        let (w, h) = (96usize, 96usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let payload = b"v3-hyperparameters";

        let hill_params = PngParams {
            p1_window: 5,
            p2_window: 7,
            // not a power of two: must be quantised on both ends
            epsilon: 1e-8,
            ..PngParams::default()
        };
        let stego = embed_png(
            &png,
            payload,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &hill_params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed with non-default HILL parameters");
        // The extractor passes *defaults*: the carrier is authoritative.
        let extracted = extract_png(
            &stego,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &PngParams::default(),
            &Control::none(),
        )
        .expect("extract rebuilds the ranking from the feature word");
        assert_eq!(extracted, payload);

        let mut suniward_params = PngParams::default();
        suniward_params
            .algorithm_options
            .insert("sigma".to_string(), 0.8);
        let stego = embed_png(
            &png,
            payload,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &crate::stego::png::cost::SuniwardCostModel,
            &suniward_params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed with non-default sigma");
        let extracted = extract_png(
            &stego,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &crate::stego::png::cost::SuniwardCostModel,
            &PngParams::default(),
            &Control::none(),
        )
        .expect("extract rebuilds sigma from the feature word");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn embed_extract_roundtrip_preserves_container() {
        let (w, h) = (64usize, 64usize);
        let pixels = row_correlated_pixels(w, h);
        let text = b"Comment\0roundtrip".to_vec();
        let exif = vec![0x45u8, 0x78, 0x69, 0x66, 0x00, 0x00]; // fake eXIf body
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![2u8; h],
            &[(b"tEXt", &text), (b"eXIf", &exif)],
            1,
        );

        let payload = b"container-fidelity-payload";
        let params = PngParams::default();
        let stego = embed_png(
            &png,
            payload,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed");
        let extracted = extract_png(
            &stego,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("extract");
        assert_eq!(extracted, payload);

        let before = decode_png(&png).expect("decode");
        let after = decode_png(&stego).expect("decode stego");
        assert_eq!(chunk_types(&before), chunk_types(&after));
        assert_eq!(
            before.chunks, after.chunks,
            "every ancillary chunk must survive embedding"
        );
        // Only LSBs may move (in any channel position the engine touches).
        let changed = before
            .pixels
            .iter()
            .zip(after.pixels.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(changed > 0, "embedding must modify the carrier");
        for (a, b) in before.pixels.iter().zip(after.pixels.iter()) {
            assert!(
                a.abs_diff(*b) <= 1,
                "a write moves a pixel by at most one: {a} -> {b}"
            );
            assert_eq!(
                a & 0xF8,
                b & 0xF8,
                "a write must stay inside the eight-value class: {a} -> {b}"
            );
        }
    }

    #[test]
    fn stc_codec_roundtrips_and_stays_in_class() {
        let (w, h) = (96usize, 96usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![2u8; h],
            &[(b"tEXt", b"Comment\x00stc".as_slice())],
            1,
        );

        let payload = b"stc-roundtrip-payload";
        let params = PngParams {
            codec: StegoCodec::Stc,
            stc_h: 8,
            ..PngParams::default()
        };
        let stego = embed_png(
            &png,
            payload,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed");

        // The codec travels in the header, so an extractor configured with Hamming
        // must still read the carrier correctly via header self-description.
        let extract_params = PngParams {
            codec: StegoCodec::Hamming,
            ..PngParams::default()
        };
        let extracted = extract_png(
            &stego,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &extract_params,
            &Control::none(),
        )
        .expect("extract");
        assert_eq!(extracted, payload, "STC must be self-describing");

        // Same selftest as the Hamming path: +/-1 inside the class, never more.
        let before = decode_png(&png).expect("decode");
        let after = decode_png(&stego).expect("decode stego");
        assert!(
            before.chunks == after.chunks,
            "container must survive STC embedding"
        );
        let changed = before
            .pixels
            .iter()
            .zip(after.pixels.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(changed > 0, "embedding must modify the carrier");
        for (a, b) in before.pixels.iter().zip(after.pixels.iter()) {
            assert!(a.abs_diff(*b) <= 1, "move too large: {a} -> {b}");
            assert_eq!(a & 0xF8, b & 0xF8, "class left: {a} -> {b}");
        }
    }

    #[test]
    fn hamming_and_stc_headers_differ_only_in_the_flag_bits() {
        // The length field is shared by both codecs, so a reader that ignores
        // the flags still sees the right length -- that is what makes the
        // change backwards compatible with pre-existing carriers.
        for (codec, stc_h) in [(StegoCodec::Hamming, 0u8), (StegoCodec::Stc, 8)] {
            let word = encode_header_word(1234, codec, stc_h, 1);
            let (len, codec_id, h) = decode_header_word(word);
            assert_eq!(len, 1234, "{codec:?}: length must round-trip");
            assert_eq!(codec_id, codec.id());
            assert_eq!(h, if codec == StegoCodec::Hamming { 0 } else { 8 });
        }
        // Pre-existing carriers have zeros in every flag bit.
        let legacy = encode_header_word(1234, StegoCodec::Hamming, 0, 1);
        assert_eq!(legacy, 1234, "a legacy header is the bare length");
    }

    #[test]
    fn bytes_after_iend_survive_a_round_trip() {
        // Producers append signatures or vendor trailers after IEND. The
        // decoder stops at IEND, so before `RawImage::tail` existed a re-encode
        // silently truncated them -- a lie for a format-preserving tool.
        let (w, h) = (32usize, 32usize);
        let pixels = row_correlated_pixels(w, h);
        let mut png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let trailer = b"\x00STRHIDE-TRAILER\xff\x00".to_vec();
        png.extend_from_slice(&trailer);

        let decoded = decode_png(&png).expect("decode");
        assert_eq!(decoded.tail, trailer, "decoder must keep the trailer");
        let reencoded = encode_png(&decoded).expect("encode");
        assert!(reencoded.ends_with(&trailer), "re-encode must put it back");

        let payload = b"tail-preserved-payload";
        let params = PngParams::default();
        let stego = embed_png(
            &png,
            payload,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Seeded([0x21; 32]),
            &Control::none(),
        )
        .expect("embed");
        assert!(
            stego.ends_with(&trailer),
            "the stego carrier must keep the trailer too"
        );
        let extracted = extract_png(
            &stego,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("extract");
        assert_eq!(extracted, payload);
    }

    #[test]
    fn handbuilt_image_without_chunks_still_encodes() {
        let img = RawImage {
            width: 4,
            height: 4,
            channels: 3,
            pixels: vec![10u8; 4 * 4 * 3],
            chunks: Vec::new(),
            idat_sizes: Vec::new(),
            row_filters: Vec::new(),
            idat_info: None,
            tail: Vec::new(),
        };
        let png = encode_png(&img).expect("encode");
        let decoded = decode_png(&png).expect("decode");
        assert_eq!(decoded.pixels, img.pixels);
        assert!(decoded.row_filters.iter().all(|&f| f == 0));
    }

    #[test]
    fn multi_idat_chunking_is_preserved() {
        // A carrier whose IDAT run is split into several chunks (typical for
        // large encoders, e.g. 32 KiB per IDAT) must keep the same chunk
        // count after an embed round-trip.
        let (w, h) = (96usize, 96usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![2u8; h],
            &[(b"tEXt", b"Comment\x00split".as_slice())],
            4,
        );

        let img = decode_png(&png).expect("decode");
        let orig_idat_count = chunk_types(&img).iter().filter(|&&t| t == *b"IDAT").count();
        assert_eq!(orig_idat_count, 4, "crafted carrier must have 4 IDATs");
        assert_eq!(img.idat_sizes.len(), 4);

        let re = encode_png(&img).expect("encode");
        let img2 = decode_png(&re).expect("re-decode");
        assert_eq!(chunk_types(&img), chunk_types(&img2));
        assert_eq!(img2.pixels, pixels);
        assert_eq!(
            img2.idat_sizes.len(),
            4,
            "IDAT chunk count must survive re-encoding"
        );

        // And through a full embed/extract round-trip.
        let params = PngParams::default();
        let stego = embed_png(
            &png,
            b"split-idat",
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed");
        let after = decode_png(&stego).expect("decode stego");
        assert_eq!(
            after.idat_sizes.len(),
            4,
            "embedding must not collapse the IDAT run"
        );
        let extracted = extract_png(
            &stego,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("extract");
        assert_eq!(extracted, b"split-idat");
    }

    /// Group size `u` must be self-describing and must actually change fewer
    /// pixels per bit: two independent properties that a whole-matrix change can
    /// break in opposite directions.
    #[test]
    fn stc_group_sizes_roundtrip_and_trade_capacity_for_fewer_changes() {
        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![2u8; h],
            &[(b"tEXt", b"Comment\x00stc-groups".as_slice())],
            1,
        );
        let payload = b"stc-group-roundtrip-payload-2026";
        let bits = payload.len() * 8;

        let mut change_rates = Vec::new();
        let mut capacities = Vec::new();
        for stc_u in [1u8, 2, 3] {
            let params = PngParams {
                codec: StegoCodec::Stc,
                stc_h: 8,
                stc_u,
                ..PngParams::default()
            };
            // Seeded, not random: the salt drives the slot permutation and the
            // trellis columns, so a random draw left the change counts (and
            // this test's outcome) to luck. Same inputs now give the same file.
            let stego = embed_png(
                &png,
                payload,
                Some("pw"),
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &HillCostModel,
                &params,
                SafetyPolicy::default(),
                Freshness::Seeded([0x5A; 32]),
                &Control::none(),
            )
            .unwrap_or_else(|e| panic!("u={stc_u}: embed failed: {e}"));

            // The extractor still defaults to Hamming: `u` and `h` must arrive
            // through the header.
            let extracted = extract_png(
                &stego,
                Some("pw"),
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &HillCostModel,
                &PngParams::default(),
                &Control::none(),
            )
            .unwrap_or_else(|e| panic!("u={stc_u}: extract failed: {e}"));
            assert_eq!(extracted, payload, "u={stc_u}: must be self-describing");

            let before = decode_png(&png).expect("decode");
            let after = decode_png(&stego).expect("decode stego");
            let changed = before
                .pixels
                .iter()
                .zip(after.pixels.iter())
                .filter(|(a, b)| a != b)
                .count();
            for (a, b) in before.pixels.iter().zip(after.pixels.iter()) {
                assert!(a.abs_diff(*b) <= 1, "u={stc_u}: move too large: {a} -> {b}");
                assert_eq!(a & 0xF8, b & 0xF8, "u={stc_u}: class left: {a} -> {b}");
            }
            change_rates.push(changed as f64 / bits as f64);

            let cap = probe_png_capacity(
                &png,
                &HillCostModel,
                &params,
                crate::stego::SafetyLevel::High,
                Some("pw"),
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &Control::none(),
            )
            .expect("capacity probe");
            capacities.push(cap.max_raw_payload_bytes);
        }

        // u=2 vs u=3 differ by only a few percent on this payload, too fine to
        // pin down here -- that comparison lives in the trellis test
        // (`coding::stc::tests::larger_groups_lower_the_change_rate`).
        assert!(
            change_rates[1] < change_rates[0] * 0.85,
            "u=2 must cut the change count per bit: {change_rates:?}"
        );
        assert!(
            change_rates[2] < change_rates[0] * 0.85,
            "u=3 must cut the change count per bit: {change_rates:?}"
        );
        assert!(
            capacities[0] > capacities[1] && capacities[1] > capacities[2],
            "capacity must fall as u grows: {capacities:?}"
        );
    }

    #[test]
    fn auto_codec_adaptive_selection_roundtrips() {
        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);

        let auto_params = PngParams::default();
        assert_eq!(auto_params.codec, StegoCodec::Auto);

        // Light payload: automatically selects STC u=3
        let light_payload = b"short-auto-payload";
        let stego_light = embed_png(
            &png,
            light_payload,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &auto_params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed light");
        let rec_light = extract_png(
            &stego_light,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &PngParams::default(),
            &Control::none(),
        )
        .expect("extract light");
        assert_eq!(rec_light, light_payload);

        // Verify that capacity probe reports recommended bytes anchored to high-stealth
        let cap = probe_png_capacity(
            &png,
            &HillCostModel,
            &auto_params,
            crate::stego::SafetyLevel::High,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &Control::none(),
        )
        .expect("probe");
        assert!(cap.recommended_max_bytes > 0);
        assert!(cap.recommended_max_bytes <= cap.max_raw_payload_bytes / 2);
    }

    /// The probe's answer must be reachable by the embedder: they have to agree
    /// on the slot plan, including the credential-keyed header permutation.
    /// This is the regression guard for the drift between the two.
    #[test]
    fn probe_capacity_is_reachable_by_embed() {
        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let params = PngParams::default();

        for password in [None, Some("pw"), Some("a-completely-different-password")] {
            let cap = probe_png_capacity(
                &png,
                &HillCostModel,
                &params,
                crate::stego::SafetyLevel::Balanced,
                password,
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &Control::none(),
            )
            .expect("probe");
            assert!(cap.max_raw_payload_bytes > 0);
            let payload = vec![0x5Au8; cap.max_raw_payload_bytes];
            embed_png(
                &png,
                &payload,
                password,
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &HillCostModel,
                &params,
                SafetyPolicy::default(),
                Freshness::Random,
                &Control::none(),
            )
            .unwrap_or_else(|e| {
                panic!(
                    "password {password:?}: probe reported {} bytes fit but embed failed: {e}",
                    payload.len()
                )
            });
        }
    }

    #[test]
    fn spatial_stego_domain_isolation_e2e() {
        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);

        let params = PngParams::default();
        let payload = b"cross-domain-isolation-test";

        // Embed under domain "finance.sec"
        let stego = embed_png(
            &png,
            payload,
            Some("shared-pwd"),
            Some("finance.sec"),
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed with domain");

        // Extract with matching domain succeeds
        let recovered = extract_png(
            &stego,
            Some("shared-pwd"),
            Some("finance.sec"),
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("extract with same domain");
        assert_eq!(recovered, payload);

        // Extract with default domain (None) fails
        let err_default = extract_png(
            &stego,
            Some("shared-pwd"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        );
        assert!(
            matches!(err_default, Err(StrHideError::NoHiddenData(_))),
            "extracting with default domain must fail as NoHiddenData"
        );

        // Extract with different domain fails
        let err_other = extract_png(
            &stego,
            Some("shared-pwd"),
            Some("hr.records"),
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        );
        assert!(
            matches!(err_other, Err(StrHideError::NoHiddenData(_))),
            "extracting with different domain must fail as NoHiddenData"
        );
    }

    #[test]
    fn safety_tier_probe_and_enforcement() {
        use crate::stego::params::{SafetyEnforcement, SafetyLevel};

        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);

        let cap_paranoid = probe_png_capacity(
            &png,
            &HillCostModel,
            &PngParams::default(),
            SafetyLevel::Paranoid,
            Some("test-pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &Control::none(),
        )
        .expect("probe paranoid");
        let cap_high = probe_png_capacity(
            &png,
            &HillCostModel,
            &PngParams::default(),
            SafetyLevel::High,
            Some("test-pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &Control::none(),
        )
        .expect("probe high");
        let cap_balanced = probe_png_capacity(
            &png,
            &HillCostModel,
            &PngParams::default(),
            SafetyLevel::Balanced,
            Some("test-pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &Control::none(),
        )
        .expect("probe balanced");

        assert!(
            cap_paranoid.recommended_max_bytes <= cap_high.recommended_max_bytes,
            "Paranoid <= High"
        );
        assert!(
            cap_high.recommended_max_bytes <= cap_balanced.recommended_max_bytes,
            "High <= Balanced"
        );

        // Test enforcement: the policy is a call argument now, not a params field.
        let enforced = SafetyPolicy {
            level: SafetyLevel::Paranoid,
            enforcement: SafetyEnforcement::Enforced,
        };

        // Oversize for Paranoid
        let large_payload = vec![0x42; cap_balanced.recommended_max_bytes];
        let res = embed_png(
            &png,
            &large_payload,
            Some("test-pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &PngParams::default(),
            enforced,
            Freshness::Random,
            &Control::none(),
        );
        assert!(
            res.is_err(),
            "Enforced safety policy must reject oversized payload"
        );

        // Same payload with Advisory succeeds
        let ok_res = embed_png(
            &png,
            &large_payload,
            Some("test-pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &PngParams::default(),
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        );
        assert!(
            ok_res.is_ok(),
            "Advisory safety policy must not block embedding"
        );
    }

    /// Incompressible bytes: the envelope deflates the payload, so a repeated
    /// byte pattern would shrink to a fraction of its size and never exercise
    /// the capacity ceiling.
    fn noise_payload(len: usize) -> Vec<u8> {
        let mut s = 0x1234_5678u32;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            out.push((s & 0xFF) as u8);
        }
        out
    }

    /// The zlib header is captured at decode time: `FLEVEL` and the IDAT total.
    ///
    /// The end-to-end size behaviour is not asserted here because the writer's
    /// deflate backend (miniz) does not reproduce another tool's level 1 byte
    /// count -- on a synthetic fixture it can be twice as good as zlib's. The
    /// decision is covered by [`level_choice_follows_the_measured_size`], and
    /// the real-corpus effect is measured separately.
    #[test]
    fn decode_captures_the_zlib_header() {
        let (w, h) = (32usize, 32usize);
        let pixels = row_correlated_pixels(w, h);
        for (level, flevel) in [(1u32, 0u8), (6, 2), (9, 3)] {
            let png = craft_png_at_level(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1, level);
            let img = decode_png(&png).expect("decode");
            let info = img.idat_info.expect("idat header must be captured");
            assert_eq!(
                info.flevel, flevel,
                "level {level} must map to FLEVEL {flevel}"
            );
            assert_eq!(info.orig_len, img.idat_sizes.iter().sum::<usize>());
        }
        // A hand-built image carries no hint and must encode at the default.
        let handbuilt = RawImage {
            width: 4,
            height: 4,
            channels: 3,
            pixels: vec![10u8; 4 * 4 * 3],
            chunks: Vec::new(),
            idat_sizes: Vec::new(),
            row_filters: Vec::new(),
            idat_info: None,
            tail: Vec::new(),
        };
        assert!(!encode_png(&handbuilt).expect("encode").is_empty());
    }

    /// The level decision itself: whichever candidate matches the source length
    /// wins, and a carrier without an `IdatInfo` keeps the default level.
    #[test]
    fn level_choice_follows_the_measured_size() {
        // Repetitive text-like rows: level 1 and level 6 differ by a lot, which
        // is what makes the two candidates distinguishable at all.
        let (row_len, height) = (48usize, 48usize);
        let mut data = Vec::new();
        for y in 0..height {
            for x in 0..row_len {
                data.push(((x * 7 + y * 3) % 61 + 40) as u8);
            }
        }
        let fast = deflate_len(&data, 1);
        let default = deflate_len(&data, 6);
        assert!(fast > default, "fixture must separate the two levels");

        let pick = |orig: usize| {
            choose_deflate_level(
                &data,
                row_len,
                height,
                Some(IdatInfo {
                    flevel: 0,
                    orig_len: orig,
                }),
            )
            .0
        };
        assert_eq!(pick(fast), 1, "a fast-compressed source must pick level 1");
        assert_eq!(pick(default), 6, "a default-compressed source must pick 6");

        // No header hint: default level, no probing.
        let (level, projected) = choose_deflate_level(&data, row_len, height, None);
        assert_eq!(level, Compression::default().level());
        assert_eq!(projected, [0, 0]);
    }

    /// A payload that fits one channel must keep the historical layout: only
    /// green changes. This is what makes the single-channel path bit-compatible
    /// with everything measured before multi-channel existed.
    #[test]
    fn single_channel_mode_leaves_red_and_blue_untouched() {
        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let params = PngParams::default();
        let payload = b"single-channel-layout";
        let stego = embed_png(
            &png,
            payload,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed");
        let back = extract_png(
            &stego,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("extract");
        assert_eq!(back, payload);

        let before = decode_png(&png).expect("decode");
        let after = decode_png(&stego).expect("decode stego");
        let mut per_channel = [0usize; 3];
        for (i, (a, b)) in before.pixels.iter().zip(after.pixels.iter()).enumerate() {
            if a != b {
                per_channel[i % 3] += 1;
            }
        }
        assert!(per_channel[1] > 0, "green must carry the payload");
        assert_eq!(
            (per_channel[0], per_channel[2]),
            (0, 0),
            "a small payload must not touch red/blue: {per_channel:?}"
        );
    }

    /// Exceeding the single-channel pool must switch to RGB, round-trip, and
    /// actually use the extra channels.
    #[test]
    fn three_channel_mode_roundtrips_at_full_capacity() {
        let (w, h) = (192usize, 192usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let params = PngParams::default();
        let cap = probe_png_capacity(
            &png,
            &HillCostModel,
            &params,
            crate::stego::SafetyLevel::Balanced,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &Control::none(),
        )
        .expect("probe");

        // The probe reports the three-channel ceiling, so this payload can only
        // fit with `ChannelMode::Rgb`.
        let payload = noise_payload(cap.max_raw_payload_bytes);
        let stego = embed_png(
            &png,
            &payload,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed at the reported ceiling");
        let back = extract_png(
            &stego,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("extract");
        assert_eq!(back, payload, "three-channel payload must round-trip");

        let before = decode_png(&png).expect("decode");
        let after = decode_png(&stego).expect("decode stego");
        let mut per_channel = [0usize; 3];
        for (i, (a, b)) in before.pixels.iter().zip(after.pixels.iter()).enumerate() {
            if a == b {
                continue;
            }
            assert!(a.abs_diff(*b) <= 1, "move too large: {a} -> {b}");
            assert_eq!(a & 0xF8, b & 0xF8, "class left: {a} -> {b}");
            per_channel[i % 3] += 1;
        }
        assert!(
            per_channel.iter().all(|&n| n > 0),
            "three-channel mode must write all three channels: {per_channel:?}"
        );
    }

    #[test]
    fn unknown_channel_modes_are_rejected() {
        assert_eq!(ChannelMode::from_wire(0), Some(ChannelMode::Green));
        assert_eq!(ChannelMode::from_wire(1), Some(ChannelMode::Rgb));
        for bad in [2u8, 3, 255] {
            assert!(
                ChannelMode::from_wire(bad).is_none(),
                "{bad} must be rejected"
            );
        }
        assert!(
            ChannelMode::Green.available(1),
            "grayscale supports green mode"
        );
        assert!(
            !ChannelMode::Rgb.available(2),
            "gray+alpha has no third channel"
        );
        assert_eq!(ChannelMode::Green.channels(1), &[0usize]);
        assert_eq!(ChannelMode::Green.channels(4), &[1usize]);
        assert_eq!(ChannelMode::Rgb.channels(3), &[0usize, 1, 2]);
    }

    /// The `(cost bits, pixel)` total order plus `select_nth_unstable` must be
    /// exactly what the previous stable `sort_by` produced -- including the
    /// flat regions, where thousands of costs are exactly `1 / epsilon` and the
    /// tie-breaking order is load-bearing.
    #[test]
    fn slot_ranking_matches_the_stable_sort_it_replaced() {
        let (w, h) = (64usize, 64usize);
        // Half gradient, half constant: the constant half ties on cost.
        let mut pixels = gradient_pixels(w, h);
        for y in h / 2..h {
            for x in 0..w {
                let i = (y * w + x) * 3;
                pixels[i..i + 3].fill(120);
            }
        }
        let png = craft_png(w as u32, h as u32, &pixels, &vec![0u8; h], &[], 1);
        let img = decode_png(&png).expect("decode");
        let params = PngParams::default();
        let costs = HillCostModel.compute_cost(&img.pixels, w, h, 3, &params);
        let plan = SlotPlan::build(
            &img,
            &costs,
            &params,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
        )
        .expect("plan");

        let mut eligible: Vec<usize> = (0..w * h)
            .filter(|&i| {
                (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&img.pixels[i * 3 + 1])
            })
            .collect();
        eligible.sort_by(|&a, &b| {
            costs[a]
                .partial_cmp(&costs[b])
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let allowed = ((eligible.len() as f64)
            * (1.0 - params.exclusion_percentile.clamp(0.0, 0.9))) as usize;
        assert_eq!(
            plan.candidates,
            eligible[..allowed].to_vec(),
            "selection must be identical to the stable sort"
        );
        assert!(
            costs[plan.candidates[0]].to_bits() == costs[plan.candidates[1]].to_bits(),
            "this fixture must contain cost ties for the assertion to mean anything"
        );
    }

    #[test]
    fn private_png_format_bidirectional_isolation() {
        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let payload = b"private-spatial-dialect-content-2026";
        let params = PngParams::default();

        let private_spatial = crate::stego::format::PngFormatProfile {
            fallback_secret: "private-secret-key-12345",
            domain_label: b"private-domain-label",
            hpos_salt: b"private-hpos-salt-xyz",
            hpos_label: b"private-hpos-label-xyz",
            stc_label: b"private-stc-label-xyz",
            body: &crate::stego::format::DEFAULT_JPEG_FORMAT,
        };

        // 1. Embed with private dialect
        let stego_bytes = embed_png(
            &png,
            payload,
            None,
            None,
            &private_spatial,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed with private profile");

        // 2. Extract with same private dialect -> Success
        let extracted = extract_png(
            &stego_bytes,
            None,
            None,
            &private_spatial,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("extract with matching private profile");
        assert_eq!(extracted, payload);

        // 3. Extract with official dialect -> Fail with NoHiddenData
        let official_err = extract_png(
            &stego_bytes,
            None,
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        );
        assert!(
            matches!(official_err, Err(StrHideError::NoHiddenData(_))),
            "official reader must see private stego as NoHiddenData, got {official_err:?}"
        );

        // 4. Official embed read by private reader -> Fail
        let official_stego = embed_png(
            &png,
            payload,
            None,
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            SafetyPolicy::default(),
            Freshness::Random,
            &Control::none(),
        )
        .expect("official embed");

        let private_err = extract_png(
            &official_stego,
            None,
            None,
            &private_spatial,
            &HillCostModel,
            &params,
            &Control::none(),
        );
        assert!(
            matches!(private_err, Err(StrHideError::NoHiddenData(_))),
            "private reader must see official stego as NoHiddenData, got {private_err:?}"
        );
    }
}
