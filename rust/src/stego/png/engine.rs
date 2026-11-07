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

use crate::crypto::{CipherSuiteId, Credential};
use crate::errors::StrHideError;
use crate::stego::coding::{
    Move, StcTrellis, hamming_embed_ternary, hamming_extract_bytes, spatial_move_safe,
    write_bit_ternary,
};
use crate::stego::envelope::{
    Freshness, build_plaintext, build_v4_aad, encrypt_v4_with_aad, unpack_v4_envelope_parts,
};
use crate::stego::format::{derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, HEADER_LEN_MAX, MAX_EXT_BYTES,
    PNG_AUDIO_BASE_HEADER_BYTES, PNG_AUDIO_BASE_SLOTS, SpatialHeaderV4, TLV_CRITICAL, Tlv,
    encode_extension_for_write, parse_extension, quantize_epsilon_k,
};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::params::{ExtractParams, SafetyPolicy};
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

/// `format_id` written into the V4 content envelope for PNG carriers.
const PNG_FORMAT_ID: u8 = 1;

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
    /// IHDR bit depth. The engine accepts only 8; kept for pre-salt derivation.
    pub bit_depth: u8,
    /// IHDR colour type (0/2/4/6). Part of the immutable carrier identity.
    pub color_type: u8,
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
    let mut saw_iend = false;
    let mut saw_ihdr = false;
    let mut saw_plte = false;

    while pos + 8 <= data.len() {
        let len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let ty = &data[pos + 4..pos + 8];
        let body_start = pos + 8;
        let body_end = body_start
            .checked_add(len)
            .ok_or_else(|| StrHideError::CorruptedData("PNG chunk length overflow".into()))?;

        if len > MAX_CHUNK_BYTES {
            return Err(StrHideError::CorruptedData(format!(
                "PNG chunk '{}' at byte {pos} declares {len} bytes, above the {MAX_CHUNK_BYTES}-byte ceiling",
                String::from_utf8_lossy(ty)
            )));
        }
        if body_end + 4 > data.len() {
            return Err(StrHideError::CorruptedData("Unexpected EOF in PNG".into()));
        }
        // Chunk types are ASCII letters by specification; anything else means
        // the length field or the type field is already garbage.
        if !ty.iter().all(u8::is_ascii_alphabetic) {
            return Err(StrHideError::CorruptedData(format!(
                "PNG chunk at byte {pos} has a non-alphabetic type field"
            )));
        }
        // IHDR is required, exactly 13 bytes, and must come first: `pixel
        // format` decisions below read width/height/colour type out of it, and
        // a later IHDR would silently overwrite them after data was collected.
        if ty == b"IHDR" {
            if saw_ihdr || pos != 8 {
                return Err(StrHideError::CorruptedData(
                    "PNG IHDR must be the first and only image header".into(),
                ));
            }
            if len != 13 {
                return Err(StrHideError::CorruptedData(format!(
                    "PNG IHDR is {len} bytes, expected 13"
                )));
            }
            saw_ihdr = true;
        } else if !saw_ihdr {
            return Err(StrHideError::CorruptedData(
                "PNG chunk found before IHDR".into(),
            ));
        }

        let body = &data[body_start..body_end];
        // Verify every chunk's CRC before trusting it. Ignoring the field let a
        // corrupt or tampered carrier through, and because `png_pre_salt` feeds
        // `chunk.ty`/`chunk.data` into the KDF salt, the embedder then derived a
        // different locator key and emitted a carrier whose identity had
        // silently changed. `write_chunk` recomputes the CRC from the same
        // `ty || body`, so a legal carrier still round-trips byte for byte.
        let stored_crc = u32::from_be_bytes([
            data[body_end],
            data[body_end + 1],
            data[body_end + 2],
            data[body_end + 3],
        ]);
        let mut crc = Crc32::new();
        crc.update(ty);
        crc.update(body);
        if crc.finalize() != stored_crc {
            return Err(StrHideError::CorruptedData(format!(
                "PNG chunk '{}' at byte {pos} failed its CRC-32 check; the file is corrupt or was modified after it was written",
                String::from_utf8_lossy(ty)
            )));
        }
        match ty {
            b"IHDR" => {
                width = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                height = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                bit_depth = body[8];
                color_type = body[9];
                // Both methods are fixed by the specification; a file that
                // says otherwise is not one this decoder can reproduce.
                if body[10] != 0 || body[11] != 0 {
                    return Err(StrHideError::UnsupportedFormat(format!(
                        "PNG declares compression method {} / filter method {}, only 0/0 exists",
                        body[10], body[11]
                    )));
                }
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
                if saw_plte {
                    return Err(StrHideError::CorruptedData(
                        "Multiple PLTE chunks in PNG".into(),
                    ));
                }
                saw_plte = true;
                if color_type == 0 || color_type == 4 {
                    return Err(StrHideError::CorruptedData(
                        "PNG PLTE chunk is forbidden for grayscale colour types (0 and 4)".into(),
                    ));
                }
                if !len.is_multiple_of(3) || len == 0 || len > 256 * 3 {
                    return Err(StrHideError::CorruptedData(format!(
                        "PNG PLTE chunk length {len} is invalid; must be 3..=768 and divisible by 3"
                    )));
                }
                if color_type == 3 {
                    return Err(StrHideError::UnsupportedFormat(
                        "Indexed/palette PNG is not supported for content-adaptive pixel steganography; please use RGB/RGBA/Grayscale PNG".into(),
                    ));
                }
                // A truecolour PNG may carry PLTE as a *suggested* palette; it
                // is optional metadata, not an indexed colour table, so keep it
                // verbatim instead of refusing an otherwise valid carrier.
                chunks.push(PngChunk {
                    ty: *b"PLTE",
                    data: body.to_vec(),
                });
            }
            b"tRNS" => {
                // For colour types 0 and 2 the chunk is a transparent *colour
                // key*, not an alpha channel: every pixel equal to that value
                // becomes fully transparent. Class-internal `±1` embedding would
                // move such a pixel off the key, making a transparent background
                // opaque (or a solid pixel transparent) — visible damage in a
                // tool that promises the image keeps its appearance. RGBA and
                // grayscale+alpha carry real alpha and are unaffected.
                if color_type == 0 || color_type == 2 {
                    return Err(StrHideError::UnsupportedFormat(
                        "PNG uses a tRNS transparent colour key (colour type 0/2), which ±1 pixel embedding would make visible; please use RGBA or grayscale+alpha, or 'strhide write' for structural hiding"
                            .into(),
                    ));
                }
                chunks.push(PngChunk {
                    ty: *b"tRNS",
                    data: body.to_vec(),
                });
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
                    let tail_len = data.len() - after;
                    const MAX_TAIL_BYTES: usize = 16 * 1024 * 1024;
                    if tail_len > MAX_TAIL_BYTES {
                        return Err(StrHideError::CorruptedData(format!(
                            "PNG trailer of {tail_len} bytes exceeds the {MAX_TAIL_BYTES}-byte safety ceiling"
                        )));
                    }
                    tail = data[after..].to_vec();
                }
                saw_iend = true;
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
        pos = body_end + 4; // Skip the CRC, already verified above
    }

    if !saw_iend {
        // Re-encoding requires an existing IEND chunk to preserve format structure.
        // Carriers missing IEND cannot be reproduced losslessly and must be rejected.
        return Err(StrHideError::CorruptedData(
            "PNG is missing its IEND chunk; re-encoding it could not be lossless. Repair the file, or use 'strhide write' for structural hiding".into(),
        ));
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
    let total_pixels = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| StrHideError::CorruptedData("PNG dimensions overflow usize".into()))?;
    if total_pixels > MAX_PNG_PIXELS {
        return Err(StrHideError::UnsupportedFormat(format!(
            "PNG dimensions {width}x{height} exceed the {MAX_PNG_PIXELS}-pixel content-stego limit"
        )));
    }
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
        bit_depth,
        color_type,
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

/// Upper bound on the pixels a content-domain PNG carrier may have.
///
/// The decode alone is `width * height * channels` bytes, and every cost model
/// keeps several full-image `f64` planes on top of it (HILL alone is ~48 B per
/// pixel). Without this check a valid-but-hostile PNG whose IHDR declares
/// 32768×32768 makes `inspect`/`embed`/`extract` allocate tens of GiB and abort
/// the process. 64 MP admits 8K RGBA (33 MP) with headroom while keeping the
/// worst case bounded.
const MAX_PNG_PIXELS: usize = 64 * 1024 * 1024;

/// Whole-pipeline working-set ceiling for a spatial carrier, deliberately the
/// same value the JPEG engine uses.
///
/// The 64 MP pixel cap alone does not bound memory: HILL keeps six full-image
/// `f64` planes (~3 GiB at that size), and the trellis keeps one bitmap word per
/// state per element, which on a 64 MP RGB carrier with the three-channel pool
/// reaches tens of GiB. Without a budget, a large payload aborted the process
/// (`panic = "abort"`) instead of returning an error.
const MAX_PIPELINE_BYTES: u64 = 8 << 30;
/// Bytes that exist for every spatial embed regardless of payload: the decoded
/// image (up to 4 B/px), the six cost planes (48 B/px), the candidate list and
/// the per-pixel header mask (9 B/px).
const PIPELINE_BYTES_PER_PIXEL: u64 = 4 + 48 + 9;
/// Per body slot: slot values, the move table, the two direction-cost rows and
/// the body index. The trellis bitmap is charged separately.
const PIPELINE_BYTES_PER_SLOT: u64 = 24;
const PIPELINE_FIXED_BYTES: u64 = 64 << 20;

fn pipeline_base_bytes(total_pixels: usize) -> u64 {
    PIPELINE_FIXED_BYTES.saturating_add(total_pixels as u64 * PIPELINE_BYTES_PER_PIXEL)
}

/// Bytes of per-slot state, including the trellis bitmap when the STC codec runs.
fn pipeline_bytes_per_slot(trellis_h: Option<u8>) -> u64 {
    let bitmap = trellis_h.map_or(0, crate::stego::coding::backtrack_bytes_per_slot);
    PIPELINE_BYTES_PER_SLOT.saturating_add(bitmap)
}

fn check_pipeline_budget(
    total_pixels: usize,
    body_n: usize,
    trellis_h: Option<u8>,
) -> Result<(), StrHideError> {
    let total = pipeline_base_bytes(total_pixels)
        .saturating_add(body_n as u64 * pipeline_bytes_per_slot(trellis_h));
    if total > MAX_PIPELINE_BYTES {
        return Err(StrHideError::PayloadTooLarge(format!(
            "PNG carrier is too large for this payload: it needs about {} MiB of working memory and the {} MiB budget would be exceeded (use the Hamming codec, a smaller --stc-h, or a smaller payload)",
            total >> 20,
            MAX_PIPELINE_BYTES >> 20
        )));
    }
    Ok(())
}

/// Body slots whose working set still fits the pipeline budget.
///
/// Used by the capacity probe (via [`body_payload_fits`]) so the advertised
/// `max_raw_payload_bytes` never exceeds what the embedder's
/// [`check_pipeline_budget`] will accept.
fn max_body_slots_within_pipeline(total_pixels: usize, trellis_h: Option<u8>) -> usize {
    let remaining = MAX_PIPELINE_BYTES.saturating_sub(pipeline_base_bytes(total_pixels));
    usize::try_from(remaining / pipeline_bytes_per_slot(trellis_h)).unwrap_or(usize::MAX)
}

/// Payload ceiling the safety tier recommends for a spatial carrier.
///
/// Shared by the embed-time enforcement and the capacity probe, so the number
/// the probe advertises is exactly the number the writer accepts. `ratio_slots`
/// is deliberately the single-channel (green) pool: the tier is expressed in
/// bits per *pixel*, and a three-channel pool would loosen the ratio bound
/// without any calibration for the extra channels.
fn recommended_bytes_for(
    total_pixels: usize,
    ratio_slots: usize,
    level: crate::params::SafetyLevel,
) -> usize {
    let bpp_bits = (total_pixels as f64 * level.bpp_limit()).floor() as usize;
    let ratio_bits = (ratio_slots as f64 / level.target_ratio()).floor() as usize;
    (bpp_bits.min(ratio_bits) / 8).saturating_sub(crate::stego::envelope::BODY_OVERHEAD)
}

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
/// Large images are split into a fixed number of row-aligned Deflate chunks
/// (executed on whatever Rayon threads exist) so the produced bytes do not
/// depend on the host's core count: `Freshness::Seeded` promises a
/// byte-identical result, and a chunk boundary is a stream boundary.
fn compress_scanlines_zlib(
    filtered: &[u8],
    row_len: usize,
    height: usize,
    level: u32,
) -> Result<Vec<u8>, StrHideError> {
    let num_threads = MAX_DEFLATE_WORKERS;

    if filtered.len() < MIN_PARALLEL_SCANLINE_BYTES || height < num_threads {
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
        trace(format_args!(
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
        write_chunk(&mut out, b"IHDR", &ihdr)?;
        write_chunk(&mut out, b"IDAT", &compressed_idat)?;
        write_chunk(&mut out, b"IEND", &[])?;
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
                    write_chunk(&mut out, b"IDAT", piece)?;
                }
            }
            continue;
        }
        if &chunk.ty == b"IEND" {
            saw_iend = true;
        }
        write_chunk(&mut out, &chunk.ty, &chunk.data)?;
    }
    if !idat_written {
        // No IDAT placeholder at all (malformed source): still emit the data.
        for piece in &pieces {
            write_chunk(&mut out, b"IDAT", piece)?;
        }
    }
    if !saw_iend {
        // Truncated source without IEND: still emit a well-formed file.
        write_chunk(&mut out, b"IEND", &[])?;
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

/// No-op tracer hook using `format_args!` to avoid eager heap allocation.
#[inline(always)]
fn trace(_args: std::fmt::Arguments<'_>) {}

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

/// Longest chunk body a carrier may carry, in bytes.
///
/// The PNG length field is a `u32`, so anything larger cannot be expressed at
/// all; 256 MiB is a much tighter bound that still leaves room for huge IDAT
/// runs while keeping a corrupt length from driving a giant allocation.
const MAX_CHUNK_BYTES: usize = 256 * 1024 * 1024;

fn write_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) -> Result<(), StrHideError> {
    // A chunk over 4 GiB used to be truncated by `as u32`, writing a length
    // field that disagreed with the bytes that followed.
    let len = u32::try_from(data.len()).map_err(|_| {
        StrHideError::General(format!(
            "PNG chunk '{}' is {} bytes, more than the format's 4 GiB length field",
            String::from_utf8_lossy(chunk_type),
            data.len()
        ))
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);

    let mut crc = Crc32::new();
    crc.update(chunk_type);
    crc.update(data);
    out.extend_from_slice(&crc.finalize().to_be_bytes());
    Ok(())
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
pub(crate) enum ChannelMode {
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
    /// Header layout: the eligible pixels in keyed order. The first
    /// `header_slots` entries carry the 64-byte base header and the optional
    /// extension area.
    ///
    /// This vector is a pure function of the carrier's pixels and the locator
    /// seed -- **not** of any cost map. That is what lets the extractor read
    /// the header (and therefore the algorithm id inside it) before it knows
    /// which cost model wrote the carrier.
    permuted: Vec<usize>,
    /// Number of leading `permuted` entries reserved for header + extension.
    header_slots: usize,
    /// `used_by_header[px]`: the pixel is one of those header slots.
    used_by_header: Vec<bool>,
}

/// Wire form of the smooth-area exclusion: permille in `0..=900`.
///
/// The base header stores `exclusion_permille`, and both ends must cut the
/// candidate list with the same integer, so the percentile never enters the
/// arithmetic. `(k / 1000.0) * 1000.0` round-trips exactly for every
/// `k in 0..=900`, so re-quantising the header value is lossless.
fn exclusion_permille(percentile: f64) -> u16 {
    (percentile.clamp(0.0, 0.9) * 1000.0) as u16
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

/// Carrier identity mixed into the L1 PBKDF2 salt.
///
/// Both ends compute this from the decoded image only: dimensions, colour
/// layout and the **critical**-chunk stream. `IDAT` is excluded (it is what the
/// embedder rewrites) and so is every ancillary chunk.
///
/// Only critical chunks may take part (first letter uppercase per the PNG
/// spec: `IHDR`, `PLTE`, `IEND`). They are exactly what defines the pixels; the
/// ancillary ones (`tEXt`, `zTXt`, `iTXt`, `tIME`, `eXIf`, `iCCP`, `gAMA`,
/// `sRGB`, `pHYs`, our own `prIv`, ...) are metadata that other tools rewrite
/// at will. Hashing those used to mean that adding one `tEXt` chunk after an
/// embed -- exiftool, an optimiser, an editor's "save as" -- re-derived the
/// locator keys and turned the payload into unrecoverable garbage
/// (`No valid payload found`). A carrier is identified by its pixels, not by
/// its tags.
///
/// A standard `IHDR`/`IDAT`/`IEND` file hashes identically under the old and
/// new rule, so payloads written before this change stay readable as long as
/// their metadata was not touched.
pub fn png_pre_salt(
    image: &RawImage,
    spatial: &crate::stego::format::PngFormatProfile,
) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    let mut meta = Sha256::new();
    for chunk in &image.chunks {
        // IDAT is rewritten by the embedder; `prIv` carries the envelope itself.
        if chunk.ty == *b"IDAT" || chunk.ty == *b"prIv" {
            continue;
        }
        // Ancillary chunk: metadata, not image identity (see the doc comment).
        if chunk.ty[0].is_ascii_lowercase() {
            continue;
        }
        meta.update(chunk.ty);
        meta.update((chunk.data.len() as u32).to_be_bytes());
        meta.update(&chunk.data);
    }
    let meta: [u8; 32] = meta.finalize().into();

    let mut out = Sha256::new();
    out.update(spatial.hpos_salt);
    out.update(b"png-v4");
    out.update((image.width as u64).to_be_bytes());
    out.update((image.height as u64).to_be_bytes());
    out.update([image.bit_depth, image.color_type, image.channels as u8]);
    out.update(meta);
    out.finalize().into()
}

/// The keyed header layout, computed without a cost model.
///
/// `locate_seed` comes from L2; `ext_len` extends the permuted prefix by eight
/// slots per extension byte. `permute_prefix` is prefix-stable, so the first
/// 512 slots are identical whether or not the extension area is known — that
/// is what lets the reader decode the base header before it learns `ext_len`.
fn header_layout(image: &RawImage, locate_seed: &[u8; 32], ext_len: usize) -> Vec<usize> {
    let mut slots = header_pool(image);
    let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
    permute_prefix(&mut slots, header_slots, locate_seed);
    slots
}

/// Read `byte_count` bytes (MSB first) from the given pixel slots.
///
/// Callers guarantee `slots.len() == 8 * byte_count`; the base header path
/// always has 512 slots and the extension path is sized from `ext_len`.
fn read_slot_bytes(image: &RawImage, slots: &[usize], byte_count: usize) -> Vec<u8> {
    let channel_offset = embed_channel(image);
    let mut bytes = Vec::with_capacity(byte_count);
    for byte_i in 0..byte_count {
        let mut b = 0u8;
        for bit_i in 0..8 {
            let slot = slots[byte_i * 8 + bit_i];
            let val = image.pixels[slot * image.channels + channel_offset];
            b = (b << 1) | (val & 1);
        }
        bytes.push(b);
    }
    bytes
}

impl SlotPlan {
    /// Rank the body candidates and apply the keyed header layout.
    ///
    /// `locate_seed` keys the header permutation and `ext_len` reserves the
    /// extension slots, so the plan must be built from exactly the inputs the
    /// writer will use — they change which pixels the header occupies and
    /// therefore the body capacity.
    fn build(
        image: &RawImage,
        costs: &[f64],
        locate_seed: &[u8; 32],
        ext_len: usize,
        exclusion_permille: u16,
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
        //
        // The cut is integer arithmetic on the *wire* permille, not on the
        // float percentile: `(len * (1000 - k)) / 1000` is exactly reproducible
        // by any reader, whereas `len * (1.0 - k / 1000.0)` rounds in the last
        // bit and can land one element short (k = 900, len = 1000 gives 99
        // instead of 100). Extraction must rebuild the same candidate list, so
        // this formula is part of the wire format, not an implementation detail.
        let allowed_count = ranked.len() * (1000 - exclusion_permille as usize) / 1000;
        if allowed_count < ranked.len() {
            ranked.select_nth_unstable(allowed_count);
            ranked.truncate(allowed_count);
        }
        ranked.sort_unstable();
        let candidates: Vec<usize> = ranked.into_iter().map(|(_, px)| px).collect();

        // The header is placed from the cost-free layout, so a reader can find
        // it without knowing the algorithm.
        let header_slots = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
        let permuted = header_layout(image, locate_seed, ext_len);

        let mut used_by_header = vec![false; total_pixels];
        for &s in permuted.iter().take(header_slots) {
            used_by_header[s] = true;
        }

        Ok(Self {
            candidates,
            permuted,
            header_slots,
            used_by_header,
        })
    }

    /// True when there are enough candidates for the base header *and* the
    /// extension area reserved by the plan.
    fn header_fits(&self) -> bool {
        self.permuted.len() >= self.header_slots
    }

    /// The [`PNG_AUDIO_BASE_SLOTS`] slots carrying the 64-byte base header.
    ///
    /// Callers must have checked [`Self::header_fits`].
    fn base_header_slots(&self) -> &[usize] {
        &self.permuted[..PNG_AUDIO_BASE_SLOTS]
    }

    /// Slots `PNG_AUDIO_BASE_SLOTS .. header_slots` carrying the extension TLV
    /// bytes, eight bit-slots per byte.
    fn extension_slots(&self) -> &[usize] {
        &self.permuted[PNG_AUDIO_BASE_SLOTS..self.header_slots]
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
        mut visit: impl FnMut(usize) -> bool,
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
                if !visit(slot) {
                    return;
                }
            }
        }
    }

    /// Number of body slots available under `mode` / `class_rule`.
    fn count_body_slots(&self, image: &RawImage, class_rule: u8, mode: ChannelMode) -> usize {
        let mut n = 0usize;
        self.for_each_body_slot(image, class_rule, mode, |_| {
            n += 1;
            true
        });
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
        self.for_each_body_slot(image, class_rule, mode, |slot| {
            out.push(slot);
            out.len() < limit
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
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
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
        cred,
        domain,
        suite_id,
        extensions,
        spatial,
        cost_model,
        params,
        safety,
        freshness,
        control,
    )
    .map(|(bytes, _, _)| bytes)
}

/// Embed a payload into a PNG carrier and return modified bytes, embed statistics, and capacity info.
#[allow(clippy::too_many_arguments)]
pub(crate) fn embed_png_with_stats<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    safety: SafetyPolicy,
    freshness: Freshness,
    control: &Control<'_>,
) -> Result<(Vec<u8>, crate::stego::EmbedStats, StegoCapacityInfo), StrHideError> {
    let payload = payload.into();
    params.validate()?;
    let suite = CipherSuiteId::from_u16(suite_id).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!("Unknown content cipher suite id {suite_id}"))
    })?;
    let extension = encode_extension_for_write(extensions)?;
    if extension.len() > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area is {} bytes, the maximum is {MAX_EXT_BYTES}",
            extension.len()
        )));
    }
    control.stage(Stage::Decode);
    let mut image = decode_png(carrier_bytes)?;
    // Checkpoint after the decode: on a 50 MP carrier this alone is seconds.
    control.check()?;
    control.stage(Stage::CostMap);
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    log::info!(
        target: "stego::png",
        "embed_png: image {}x{} ({} px), payload {} B",
        w, h, total_pixels, payload.as_bytes().len()
    );

    // Frame the payload and derive the per-carrier keys. The ciphertext itself
    // is produced further down: the finished base header plus extension area is
    // its associated data, so it cannot exist until codec/h/u are settled.
    let plaintext = build_plaintext(&payload)?;
    let cipher = spatial.cipher;
    let pre_salt = png_pre_salt(&image, spatial);
    let master = derive_locator_master(cred, domain, cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    // Seeded runs bind salt/nonce to the cover, payload, format, version and
    // extension area, so a replay on different inputs can never reuse a
    // (key, nonce) pair.
    let fresh_binding =
        Freshness::seeded_binding(carrier_bytes, payload.as_bytes(), PNG_FORMAT_ID, &extension);
    let salt = freshness.salt(0, &fresh_binding);
    let nonce = freshness.nonce(0, &fresh_binding);
    let session = derive_l3_session_keys(cipher, suite, &master, &salt, domain)?;
    let ext_len = extension.len();
    let ciphertext_len = plaintext.len() + suite.tag_len();

    // Quantise the hyperparameters to their wire-exact forms *before* any
    // use, and run the whole embed on them: the feature word can only carry
    // `epsilon` as a power of two and `sigma` at `f32` precision, so the
    // extractor can only ever reproduce these forms. The prober quantises
    // the same way, so advertised capacity and embedding pool agree.
    let params = params.wire_quantized();
    let eps_k = quantize_epsilon_k(params.epsilon);

    // Compute distortion cost map
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, &params);
    // Checkpoint after the cost map: the second big fixed cost of an embed.
    control.check()?;
    control.stage(Stage::Solve);

    let channel_offset = embed_channel(&image);

    let plan = SlotPlan::build(
        &image,
        &costs,
        &locator.locate_seed,
        ext_len,
        exclusion_permille(params.exclusion_percentile),
    )?;
    let (capacity_info, pool_green, pool_rgb) =
        build_png_capacity_with_pools(&image, &plan, &params, cost_model.id(), safety.level)?;
    if !plan.header_fits() {
        return Err(StrHideError::General(format!(
            "Carrier capacity insufficient: available {} slots, minimum header requires {} slots",
            plan.permuted.len(),
            plan.header_slots
        )));
    }
    let header_slots = plan.base_header_slots();
    let extension_slots = plan.extension_slots();

    let ciphertext_bits = ciphertext_len * 8;

    // Single-channel body pool first. Small payloads therefore keep the exact
    // layout (and byte-for-byte output) they had before multi-channel existed.
    // Safety enforcement policy check
    if safety.is_enforced() {
        let recommended_max_bytes = recommended_bytes_for(total_pixels, pool_green, safety.level);

        if payload.len() > recommended_max_bytes {
            return Err(StrHideError::SafetyThreshold {
                tier: safety.level,
                required_bytes: payload.len(),
                available_bytes: recommended_max_bytes,
            });
        }
    }

    // Resolve matrix-coding strategy and channel mode together.
    //
    // `Auto` (and STC with `stc_u = 0`) picks the group size from a slot pool,
    // but the pool that actually carries the body depends on that group size:
    // once the payload no longer fits one channel, the body moves to `Rgb`.
    // Resolving `u` against `pool_green` and then switching to `Rgb` kept the
    // degraded `u = 1` chosen for a pool that is never used, which is plain
    // parity coding with no cost-model optimisation. Re-resolve against the
    // pool the body will live in.
    let (resolved_codec, resolved_u, mode, pool_max) = 'resolve: {
        if matches!(params.codec, StegoCodec::Auto)
            || (params.codec == StegoCodec::Stc && params.stc_u == 0)
        {
            let (codec, u) = crate::stego::coding::auto_select_codec(pool_green, ciphertext_bits);
            let needed =
                crate::stego::coding::slots_for_codec(ciphertext_bits, codec, params.stc_h, u)?;
            if needed <= pool_green {
                break 'resolve (codec, u, ChannelMode::Green, pool_green);
            }
            let Some(pool_rgb) = pool_rgb else {
                return Err(StrHideError::PayloadTooLarge(format!(
                    "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{})",
                    needed,
                    codec.describe(params.stc_h, u),
                    pool_green,
                    cost_model.id(),
                )));
            };
            let (codec, u) = crate::stego::coding::auto_select_codec(pool_rgb, ciphertext_bits);
            let rgb_needed =
                crate::stego::coding::slots_for_codec(ciphertext_bits, codec, params.stc_h, u)?;
            if rgb_needed <= pool_rgb {
                break 'resolve (codec, u, ChannelMode::Rgb, pool_rgb);
            }
            return Err(StrHideError::PayloadTooLarge(format!(
                "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{} {})",
                rgb_needed,
                codec.describe(params.stc_h, u),
                pool_rgb,
                cost_model.id(),
                ChannelMode::Rgb.name(),
            )));
        }

        let (codec, u) = match params.codec {
            StegoCodec::Stc => (StegoCodec::Stc, params.stc_u),
            StegoCodec::Hamming => (StegoCodec::Hamming, 0),
            StegoCodec::Auto => unreachable!("handled above"),
        };
        let needed =
            crate::stego::coding::slots_for_codec(ciphertext_bits, codec, params.stc_h, u)?;
        if needed <= pool_green {
            break 'resolve (codec, u, ChannelMode::Green, pool_green);
        }
        if let Some(pool_rgb) = pool_rgb {
            if needed <= pool_rgb {
                break 'resolve (codec, u, ChannelMode::Rgb, pool_rgb);
            }
            return Err(StrHideError::PayloadTooLarge(format!(
                "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{} {})",
                needed,
                codec.describe(params.stc_h, u),
                pool_rgb,
                cost_model.id(),
                ChannelMode::Rgb.name(),
            )));
        }
        return Err(StrHideError::PayloadTooLarge(format!(
            "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{})",
            needed,
            codec.describe(params.stc_h, u),
            pool_green,
            cost_model.id(),
        )));
    };

    trace(format_args!(
        "plan pool_green={pool_green} pool_max={pool_max} mode={mode:?} codec={resolved_codec:?} u={resolved_u}"
    ));

    // Recompute the slot count from the resolved codec for the solve phase.
    let needed_body_slots = crate::stego::coding::slots_for_codec(
        ciphertext_bits,
        resolved_codec,
        params.stc_h,
        resolved_u,
    )?;

    // Refuse before the solve allocates anything: the trellis keeps one word per
    // state per element, so a large payload on a large carrier is a multi-GiB
    // allocation, and with `panic = "abort"` an OOM is a process kill rather
    // than an error the user can act on.
    check_pipeline_budget(
        total_pixels,
        needed_body_slots,
        match resolved_codec {
            StegoCodec::Hamming => None,
            _ => Some(params.stc_h),
        },
    )?;

    // V4 base header: `body_len` is the AEAD ciphertext length including the
    // tag, with no per-format padding adjustment.
    if ciphertext_len > HEADER_LEN_MAX as usize {
        return Err(StrHideError::General(format!(
            "Envelope of {ciphertext_len} bytes exceeds the {HEADER_LEN_MAX}-byte header length field"
        )));
    }
    let algorithm_id = crate::stego::png::registry::spatial_wire_id(cost_model.id()).ok_or_else(
        || {
            StrHideError::General(format!(
                "PNG cost model '{}' has no wire id; a carrier written with it could not be extracted",
                cost_model.id()
            ))
        },
    )?;
    let sigma = if cost_model.id() == "mipod" {
        params
            .algorithm_options
            .get("alpha")
            .copied()
            .unwrap_or(0.20)
            .clamp(0.01, 0.90) as f32
    } else {
        params
            .algorithm_options
            .get("sigma")
            .copied()
            .unwrap_or(1.0) as f32
    };
    let flags = {
        let mut flags = 0u8;
        if !extension.is_empty() {
            flags |= FLAG_EXT_PRESENT;
        }
        if extensions.iter().any(Tlv::is_critical) {
            flags |= FLAG_EXT_CRITICAL;
        }
        flags
    };
    let (codec_id, wire_h, wire_u) = match resolved_codec {
        StegoCodec::Hamming => (0u8, 0u8, 0u8),
        StegoCodec::Stc | StegoCodec::Auto => (1u8, params.stc_h, resolved_u),
    };
    let header = SpatialHeaderV4 {
        salt,
        nonce,
        body_len: ciphertext_len as u32,
        version: CONTENT_ENVELOPE_VERSION,
        flags,
        format_id: PNG_FORMAT_ID,
        algorithm_id,
        suite_id: suite.as_u16(),
        codec_id,
        stc_h: wire_h,
        stc_u: wire_u,
        // Self-describing: the extractor rebuilds the body pool from this and
        // nothing else, so a write here would desynchronise the two ends.
        channel_mode: mode as u8,
        class_rule: 1, // Safe [1, 6] non-boundary
        p1_window: params.p1_window as u16,
        p2_window: params.p2_window as u16,
        neg_log2_epsilon: eps_k,
        exclusion_permille: exclusion_permille(params.exclusion_percentile),
        sigma,
        kernel_id: 0, // the built-in KB kernel; custom kernels need matching configs
        ext_len: ext_len as u16,
    };
    let header_bytes = header.encode();
    let aad = build_v4_aad(PNG_FORMAT_ID, &header_bytes, &extension);

    // Encrypt last: the whole base header plus extension area is the AEAD's
    // associated data, so a tampered field fails the tag instead of steering
    // the decoder somewhere else.
    let ciphertext_body = encrypt_v4_with_aad(suite, &session.enc_key, &nonce, &aad, &plaintext)?;

    // Phase 2: Keyed permutation of body slots.
    let perm_seed = session.perm_seed;
    let stc_seed = session.stc_seed;

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
    let mut header_rp = vec![0.0f64; plan.header_slots];
    let mut header_rm = vec![0.0f64; plan.header_slots];
    let mut body_rp = vec![0.0f64; needed_body_slots];
    let mut body_rm = vec![0.0f64; needed_body_slots];
    let header_px: Vec<usize> = header_slots
        .iter()
        .chain(extension_slots.iter())
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

    // Embed Phase 1: 64-byte base header (512 slots), then the optional
    // extension area (8 slots per byte) from the same keyed permutation.
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
    for (byte_i, &b) in extension.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let bit_index = PNG_AUDIO_BASE_SLOTS + byte_i * 8 + bit_i;
            let byte_idx = extension_slots[byte_i * 8 + bit_i] * image.channels + channel_offset;
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
    Ok((encoded, stats, capacity_info))
}

/// Extract a payload from a PNG carrier with content-adaptive spatial steganography.
///
/// The complete expert entry. The carrier declares its cost model in the
/// feature word, so `cost_model` is only a hint; `params` must repeat the
/// embed-time filter windows because the body slot ranking is recomputed from
/// the cost map.
#[allow(clippy::too_many_arguments)]
pub fn extract_png(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    control.stage(Stage::Decode);
    let image = decode_png(carrier_bytes)?;
    control.check()?;
    extract_png_image(
        &image, cred, domain, spatial, cost_model, params, limits, control,
    )
}

/// L1/L2 outputs shared by extract, inspect and verify.
///
/// `verify` needs the locator keys for its header level *and* for its payload
/// level; deriving them twice paid the 200k-iteration L1 twice for one user
/// request. This value is derived once and passed down.
struct PngKeys {
    master: [u8; 32],
    locator: crate::stego::format::HeaderLocatorKeys,
}

/// Derive the per-carrier L1 master and L2 locator keys.
fn png_keys(
    image: &RawImage,
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
) -> Result<PngKeys, StrHideError> {
    let cipher = spatial.cipher;
    let pre_salt = png_pre_salt(image, spatial);
    let master = derive_locator_master(cred, domain, cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    Ok(PngKeys { master, locator })
}

/// Whether a policy is willing to pay the fixed V4 L1 cost.
fn l1_allowed(cred: &Credential<'_>, limits: &ExtractParams) -> bool {
    !matches!(cred, Credential::Password(_))
        || limits.max_pbkdf2_iterations >= crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
}

/// Body of [`extract_png`] for an already-decoded image.
///
/// `verify_png` decodes once and reuses the pixels across all three levels
/// instead of running the full PNG decode three times.
#[allow(clippy::too_many_arguments)]
fn extract_png_image(
    image: &RawImage,
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    // Refuse a policy that cannot pay the one fixed L1 cost before running it.
    if !l1_allowed(&cred, limits) {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }
    let keys = png_keys(image, cred, domain, spatial)?;
    extract_png_with_keys(
        image, &keys, domain, spatial, cost_model, params, limits, control,
    )
}

/// Extraction over a pre-derived L1/L2 key set.
#[allow(clippy::too_many_arguments)]
fn extract_png_with_keys(
    image: &RawImage,
    keys: &PngKeys,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    cost_model: &dyn PngCostModel,
    params: &PngParams,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    params.validate()?;
    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());
    let PngKeys { master, locator } = *keys;

    let w = image.width as usize;
    let h = image.height as usize;
    let cipher = spatial.cipher;
    let carrier_slots = header_pool(image).len();
    if carrier_slots < PNG_AUDIO_BASE_SLOTS {
        return Err(no_hidden());
    }

    // Read the 64-byte base header from the first 512 keyed slots. The
    // prefix is stable, so this is the same permutation the writer used.
    let base_layout = header_layout(image, &locator.locate_seed, 0);
    let base_bytes: [u8; PNG_AUDIO_BASE_HEADER_BYTES] =
        read_slot_bytes(image, &base_layout[..PNG_AUDIO_BASE_SLOTS], 64)
            .try_into()
            .map_err(|_| no_hidden())?;
    let header = SpatialHeaderV4::decode(&base_bytes, PNG_FORMAT_ID).map_err(|_| no_hidden())?;

    let ext_len = header.ext_len as usize;
    let header_slot_count = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
    if header_slot_count > carrier_slots {
        return Err(no_hidden());
    }
    let full_layout = header_layout(image, &locator.locate_seed, ext_len);
    let extension = read_slot_bytes(
        image,
        &full_layout[PNG_AUDIO_BASE_SLOTS..header_slot_count],
        ext_len,
    );

    // The extension area is authenticated by the AAD, but its structure must
    // be sane first: an unknown critical TLV is fatal, non-critical ones are
    // ignored. `validate_ext_critical` also cross-checks the flags.
    header
        .validate_ext_critical(&extension)
        .map_err(|_| no_hidden())?;
    let records = parse_extension(&extension).map_err(|_| no_hidden())?;
    if records
        .iter()
        .any(|(type_id, _)| type_id & TLV_CRITICAL != 0)
    {
        return Err(no_hidden());
    }

    // Policy checks run after the base header and extension are decoded but
    // before any body slot is computed or allocated.
    limits
        .validate_header(
            header.suite_id,
            header.body_len,
            header_slot_count,
            carrier_slots,
        )
        .map_err(|_| no_hidden())?;

    // The carrier names its cost model. An id this build does not know means a
    // carrier written by a newer tool -- reported exactly like "no payload",
    // because guessing a model would silently decode noise.
    let resolved = crate::stego::png::registry::spatial_model_from_wire_id(header.algorithm_id)
        .ok_or_else(no_hidden)?;
    if resolved.id() != cost_model.id() {
        // The carrier is authoritative; the caller's choice is only a hint.
        trace(format_args!(
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
    effective_params.exclusion_percentile = (header.exclusion_permille as f64) / 1000.0;
    effective_params.p1_window = header.p1_window as usize;
    effective_params.p2_window = header.p2_window as usize;
    effective_params.epsilon = 2f64.powi(-(header.neg_log2_epsilon as i32));
    if resolved.id() == "suniward" {
        effective_params
            .algorithm_options
            .insert("sigma".to_string(), header.sigma as f64);
    } else if resolved.id() == "mipod" {
        effective_params
            .algorithm_options
            .insert("alpha".to_string(), (header.sigma as f64).clamp(0.01, 0.90));
    }
    effective_params.validate()?;

    // Distortion cost map of the declared model. Identical to what the embedder
    // computed, because header/feature pixels never leave their eight-value
    // class, so the map is bit-identical on the stego.
    let costs = resolved.compute_cost(&image.pixels, w, h, image.channels, &effective_params);
    control.check()?;
    // Body ranking needs costs; the header layout inside this plan is the same
    // cost-free one read above, so the two cannot disagree.
    let plan = SlotPlan::build(
        image,
        &costs,
        &locator.locate_seed,
        ext_len,
        header.exclusion_permille,
    )?;
    debug_assert_eq!(
        plan.permuted.get(..PNG_AUDIO_BASE_SLOTS),
        Some(&base_layout[..PNG_AUDIO_BASE_SLOTS]),
        "the header layout must not depend on the cost map"
    );

    // The body's channel mode arrives in the header. An unknown value, or one
    // the carrier cannot support, means the header landed on the wrong slots --
    // folded into the same generic failure as an AEAD reject.
    let mode = ChannelMode::from_wire(header.channel_mode).ok_or_else(no_hidden)?;
    if !mode.available(image.channels) {
        return Err(no_hidden());
    }
    let codec = match header.codec_id {
        0 => StegoCodec::Hamming,
        1 => StegoCodec::Stc,
        _ => return Err(no_hidden()),
    };
    let suite = CipherSuiteId::from_u16(header.suite_id).ok_or_else(no_hidden)?;
    if !limits.allows_suite(header.suite_id) {
        return Err(no_hidden());
    }

    // `body_len` is the AEAD ciphertext length including the 16-byte tag.
    let ciphertext_len = header.body_len as usize;
    let ciphertext_bits = ciphertext_len * 8;
    let needed_body_slots =
        crate::stego::coding::slots_for_codec(ciphertext_bits, codec, header.stc_h, header.stc_u)
            .map_err(|_| no_hidden())?;

    // Same budget the writer applies: a header claiming a payload this large
    // would otherwise have the reader allocate its way into an OOM abort before
    // it ever gets to reject the carrier.
    check_pipeline_budget(
        image.width as usize * image.height as usize,
        needed_body_slots,
        match codec {
            StegoCodec::Hamming => None,
            _ => Some(header.stc_h),
        },
    )
    .map_err(|_| no_hidden())?;

    // `body_slots_upto` stops as soon as `needed_body_slots` are collected and
    // its length check below rejects short pools, so a separate full-image
    // `count_body_slots` pass only doubled the scan without changing the
    // verdict.
    let mut body_slots = plan.body_slots_upto(image, header.class_rule, mode, needed_body_slots);
    trace(format_args!(
        "extract mode={:?} class_rule={} body_len={ciphertext_len} needed={needed_body_slots} pool={}",
        mode,
        header.class_rule,
        body_slots.len()
    ));
    // Short pool == the carrier is smaller than the header claims: no payload.
    if body_slots.len() < needed_body_slots {
        return Err(no_hidden());
    }
    let session = derive_l3_session_keys(cipher, suite, &master, &header.salt, domain)
        .map_err(|_| no_hidden())?;
    permute_indices(&mut body_slots, &session.perm_seed);

    let slot_vals: Vec<u8> = body_slots.iter().map(|&slot| image.pixels[slot]).collect();

    let ciphertext = match codec {
        StegoCodec::Hamming => hamming_extract_bytes(
            &slot_vals,
            ciphertext_len,
            crate::stego::coding::DEFAULT_HAMMING_K,
        )
        .map_err(|_| no_hidden())?,
        StegoCodec::Stc | StegoCodec::Auto => {
            let trellis =
                StcTrellis::from_seed_grouped(session.stc_seed, header.stc_h, header.stc_u)
                    .map_err(|_| no_hidden())?;
            trellis.extract(&slot_vals, ciphertext_bits)
        }
    };

    let aad = build_v4_aad(PNG_FORMAT_ID, &base_bytes, &extension);
    // AEAD failure (and every structural failure before it) already collapsed
    // to `NoHiddenData` inside the envelope code. Once the tag verifies the
    // carrier is provably ours, so a broken frame / oversized payload must
    // surface as `CorruptedData` / capacity instead of "no payload here".
    unpack_v4_envelope_parts(
        suite,
        &session.enc_key,
        &header.nonce,
        &aad,
        &ciphertext,
        limits,
    )
}

/// Inspect PNG for stego header and self-describing metadata without decoding body.
pub(crate) fn inspect_png(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    limits: &ExtractParams,
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
    inspect_png_image(&image, cred, domain, spatial, limits, control)
}

/// Header inspection for an already-decoded image.
///
/// `verify_png` and `inspect_png` share this so the PNG decode runs once.
fn inspect_png_image(
    image: &RawImage,
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    if !l1_allowed(&cred, limits) {
        let mut empty = StegoHeaderInfo::empty("PNG");
        empty.media_info = Some(MediaInfo::new(image.width, image.height));
        return Ok(empty);
    }
    let keys = png_keys(image, cred, domain, spatial)?;
    inspect_png_with_keys(image, &keys, limits, control)
}

/// Header inspection over a pre-derived L1/L2 key set.
fn inspect_png_with_keys(
    image: &RawImage,
    keys: &PngKeys,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let media_info = Some(MediaInfo::new(image.width, image.height));
    let mut empty_info = StegoHeaderInfo::empty("PNG");
    empty_info.media_info = media_info;

    let locator = &keys.locator;
    let carrier_slots = header_pool(image).len();
    if carrier_slots < PNG_AUDIO_BASE_SLOTS {
        return Ok(empty_info);
    }

    let base_layout = header_layout(image, &locator.locate_seed, 0);
    let base_bytes: [u8; PNG_AUDIO_BASE_HEADER_BYTES] = match read_slot_bytes(
        image,
        &base_layout[..PNG_AUDIO_BASE_SLOTS],
        64,
    )
    .try_into()
    {
        Ok(bytes) => bytes,
        Err(_) => {
            // The pool length was checked above, so a short read means the
            // slot mapping disagrees with the image — an anomaly, not the
            // "no header here" answer every clean PNG gives below.
            log::debug!(
                target: "stego::inspect",
                "png header slots could not be read (pool {} slots, need {})",
                carrier_slots,
                PNG_AUDIO_BASE_SLOTS
            );
            empty_info.note = Some(format!(
                "Header slots could not be read: pool has {carrier_slots} slots, the header needs {PNG_AUDIO_BASE_SLOTS}"
            ));
            return Ok(empty_info);
        }
    };
    let Ok(header) = SpatialHeaderV4::decode(&base_bytes, PNG_FORMAT_ID) else {
        return Ok(empty_info);
    };

    let ext_len = header.ext_len as usize;
    let header_slot_count = PNG_AUDIO_BASE_SLOTS + 8 * ext_len;
    if header_slot_count > carrier_slots {
        return Ok(empty_info);
    }
    let full_layout = header_layout(image, &locator.locate_seed, ext_len);
    let extension = read_slot_bytes(
        image,
        &full_layout[PNG_AUDIO_BASE_SLOTS..header_slot_count],
        ext_len,
    );
    if header.validate_ext_critical(&extension).is_err() {
        return Ok(empty_info);
    }
    if parse_extension(&extension)
        .map(|records| records.iter().any(|(t, _)| t & TLV_CRITICAL != 0))
        .unwrap_or(true)
    {
        return Ok(empty_info);
    }
    if limits
        .validate_header(
            header.suite_id,
            header.body_len,
            header_slot_count,
            carrier_slots,
        )
        .is_err()
    {
        return Ok(empty_info);
    }

    let algo_name = crate::stego::png::registry::spatial_model_from_wire_id(header.algorithm_id)
        .map(|m| m.id().to_string())
        .unwrap_or_else(|| format!("Unknown(0x{:02x})", header.algorithm_id));
    let codec = match header.codec_id {
        0 => "Hamming".to_string(),
        1 => format!("Stc (h={}, u={})", header.stc_h, header.stc_u),
        other => format!("Unknown({other})"),
    };

    Ok(StegoHeaderInfo {
        format: "PNG".into(),
        has_hidden_data: true,
        algorithm: Some(algo_name),
        codec: Some(codec),
        envelope_len: Some(header.body_len as usize),
        payload_len: None,
        media_info,
        note: None,
    })
}

/// Three-level diagnostic verification for PNG carriers.
pub(crate) fn verify_png(
    carrier_bytes: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    spatial: &crate::stego::format::PngFormatProfile,
    limits: &ExtractParams,
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
    control.check()?;

    // The L1 cost is fixed by V4; a policy that cannot pay it must fail before
    // the header read so the report says "policy", not "wrong password".
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
    {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            format!(
                "PBKDF2 iteration limit {} is below the V4 L1 cost {}",
                limits.max_pbkdf2_iterations,
                crate::crypto::CONTENT_L1_PBKDF2_ITERATIONS
            ),
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "Skipped due to level 2 policy failure",
        ));
        return Ok(StegoVerifyResult::new("PNG", levels));
    }

    // Level 2 and 3 share one L1/L2 derivation: `verify` is one user request,
    // so it must not pay the 200k-iteration L1 twice (plan M-14).
    let keys = png_keys(&image, cred, domain, spatial)?;
    let header_info = inspect_png_with_keys(&image, &keys, limits, control)?;
    if !header_info.has_hidden_data {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            "No valid V4 stego header found (or wrong password)",
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
    match extract_png_with_keys(
        &image, &keys, domain, spatial, &*model, &params, limits, control,
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

/// Would the embedder accept `raw_bytes` on the green or RGB body pool?
///
/// This mirrors the codec/`u` resolution in [`embed_png_with_stats`] exactly:
/// `Auto` (and `Stc` with `stc_u = 0`) re-resolve the group size against each
/// candidate pool, while fixed codecs use the configured group size. Capacity
/// probing and embedding therefore share one accounting rule instead of the
/// probe assuming `u = 1` and the writer using whatever the pool resolves to.
///
/// `total_pixels` feeds the same pipeline-memory budget the embedder enforces
/// in [`check_pipeline_budget`]: a payload whose slots fit the pool but whose
/// working set would exceed [`MAX_PIPELINE_BYTES`] is reported as not fitting,
/// so the probe never advertises a size the writer must refuse.
fn body_payload_fits(
    params: &PngParams,
    pool_green: usize,
    pool_rgb: Option<usize>,
    raw_bytes: usize,
    total_pixels: usize,
) -> Result<bool, StrHideError> {
    let ciphertext_bytes = raw_bytes.saturating_add(crate::stego::envelope::BODY_OVERHEAD);
    let Some(bits) = ciphertext_bytes.checked_mul(8) else {
        return Ok(false);
    };
    for pool in std::iter::once(pool_green).chain(pool_rgb) {
        if pool == 0 {
            continue;
        }
        let (codec, u) = if matches!(params.codec, StegoCodec::Auto)
            || (params.codec == StegoCodec::Stc && params.stc_u == 0)
        {
            crate::stego::coding::auto_select_codec(pool, bits)
        } else {
            match params.codec {
                StegoCodec::Stc => (StegoCodec::Stc, params.stc_u),
                StegoCodec::Hamming => (StegoCodec::Hamming, 0),
                StegoCodec::Auto => unreachable!("handled above"),
            }
        };
        let slots = crate::stego::coding::slots_for_codec(bits, codec, params.stc_h, u)?;
        if slots > pool {
            continue;
        }
        // Same budget rule as the embedder: the trellis bitmap is only
        // charged when the STC codec runs (Hamming has no trellis).
        let trellis_h = match codec {
            StegoCodec::Hamming => None,
            _ => Some(params.stc_h),
        };
        if slots <= max_body_slots_within_pipeline(total_pixels, trellis_h) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Largest raw payload the writer accepts on the given body pools.
///
/// Binary search over `body_payload_fits`, so it uses the *same* slot
/// accounting as the embedder. The previous closed-form inverse assumed
/// `u = 1` and overshot by a few bytes whenever the pool resolved a larger
/// group size or a codec whose warm-up rows do not invert exactly.
fn max_raw_payload_for_pools(
    params: &PngParams,
    pool_green: usize,
    pool_rgb: Option<usize>,
    total_pixels: usize,
) -> Result<usize, StrHideError> {
    let largest_pool = pool_green.max(pool_rgb.unwrap_or(0));
    if largest_pool == 0 {
        return Ok(0);
    }
    // Even the densest codec (Hamming) needs more than one slot per byte of
    // ciphertext, so `8 * slots` is a safe, generous upper bound.
    let mut lo = 0usize;
    let mut hi = largest_pool.saturating_mul(8);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if body_payload_fits(params, pool_green, pool_rgb, mid, total_pixels)? {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Ok(lo)
}

/// Construct the capacity metadata directly from an already computed [`SlotPlan`].
///
/// Shared between embedding and probing so that embedding never has to decode
/// the carrier or recompute the distortion cost map a second time to report capacity.
fn build_png_capacity_with_pools(
    image: &RawImage,
    plan: &SlotPlan,
    params: &PngParams,
    cost_model_id: &str,
    safety_level: crate::stego::SafetyLevel,
) -> Result<(StegoCapacityInfo, usize, Option<usize>), StrHideError> {
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    let header_fits = plan.header_fits();
    let pool_green = if header_fits {
        plan.count_body_slots(image, 1, ChannelMode::Green)
    } else {
        0
    };
    let pool_rgb = (header_fits && image.channels >= 3)
        .then(|| plan.count_body_slots(image, 1, ChannelMode::Rgb));
    let available_body_slots = match pool_rgb {
        Some(rgb) => rgb,
        None => pool_green,
    };
    let ratio_slots = pool_green;

    let max_raw_payload_bytes =
        max_raw_payload_for_pools(params, pool_green, pool_rgb, total_pixels)?;

    let recommended_max_bytes = recommended_bytes_for(total_pixels, ratio_slots, safety_level);
    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    let tier_limits = crate::params::SafetyLevel::ALL
        .map(|level| recommended_bytes_for(total_pixels, ratio_slots, level));

    let info = StegoCapacityInfo {
        format: "PNG".into(),
        algorithm: cost_model_id.into(),
        total_elements: total_pixels,
        available_slots: available_body_slots,
        max_raw_payload_bytes,
        max_raw_is_grouped: false,
        recommended_max_bytes,
        tier_limits,
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
    };
    Ok((info, pool_green, pool_rgb))
}

fn build_png_capacity_info(
    image: &RawImage,
    plan: &SlotPlan,
    params: &PngParams,
    cost_model_id: &str,
    safety_level: crate::stego::SafetyLevel,
) -> Result<StegoCapacityInfo, StrHideError> {
    build_png_capacity_with_pools(image, plan, params, cost_model_id, safety_level)
        .map(|(info, _, _)| info)
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
    cred: Credential<'_>,
    domain: Option<&str>,
    extensions: &[Tlv],
    spatial: &crate::stego::format::PngFormatProfile,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    params.validate()?;
    // Probe with the same wire-quantised hyperparameters the embedder will
    // use, so the advertised capacity matches the pool embedding sees.
    let params = params.wire_quantized();
    let extension = encode_extension_for_write(extensions)?;
    if extension.len() > MAX_EXT_BYTES {
        return Err(StrHideError::General(format!(
            "Extension area is {} bytes, the maximum is {MAX_EXT_BYTES}",
            extension.len()
        )));
    }
    control.stage(Stage::Decode);
    let image = decode_png(carrier_bytes)?;

    control.stage(Stage::CostMap);
    let costs = cost_model.compute_cost(
        &image.pixels,
        image.width as usize,
        image.height as usize,
        image.channels,
        &params,
    );
    control.check()?;

    // Same credential, carrier identity and extension area as the writer: the
    // header permutation (and therefore the body pool) must match exactly.
    let cipher = spatial.cipher;
    let pre_salt = png_pre_salt(&image, spatial);
    let master = derive_locator_master(cred, domain, cipher, &pre_salt)?;
    let locator = derive_l2_locator_keys(&master, cipher, b"strhide-v4-hdr-magic", domain)?;
    let plan = SlotPlan::build(
        &image,
        &costs,
        &locator.locate_seed,
        extension.len(),
        exclusion_permille(params.exclusion_percentile),
    )?;
    build_png_capacity_info(&image, &plan, &params, cost_model.id(), safety_level)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::params::PngParams;
    use crate::stego::png::cost::HillCostModel;

    #[test]
    fn trace_call_sites_do_not_format_eagerly() {
        // Verifies trace call sites pass `format_args!` rather than allocating eagerly with `format!`.
        let source = include_str!("engine.rs");
        // Split so this test's own source does not contain the needle.
        let eager_pattern = concat!("trace", "(&format!(");
        assert!(
            !source.contains(eager_pattern),
            "trace must receive format_args!, not an eagerly formatted String"
        );
    }

    /// Test-side credential shim: the pre-V4 tests pass `None` to mean the
    /// profile's public fallback secret, which V4 expresses as a password
    /// credential.
    fn test_cred<'a>(password: Option<&'a str>) -> Credential<'a> {
        match password {
            Some(password) => Credential::Password(password),
            None => Credential::Password(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        }
    }

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
            test_cred(password),
            domain,
            crate::stego::format::OFFICIAL_PNG_CIPHER
                .default_suite
                .as_u16(),
            &[],
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
            test_cred(password),
            domain,
            spatial,
            cost_model,
            params,
            &ExtractParams::default(),
            control,
        )
        .map(Payload::into_bytes)
    }

    #[allow(clippy::too_many_arguments)]
    fn probe_png_capacity(
        carrier_bytes: &[u8],
        cost_model: &dyn PngCostModel,
        params: &PngParams,
        safety_level: crate::stego::SafetyLevel,
        password: Option<&str>,
        domain: Option<&str>,
        spatial: &crate::stego::format::PngFormatProfile,
        control: &Control<'_>,
    ) -> Result<StegoCapacityInfo, StrHideError> {
        super::probe_png_capacity(
            carrier_bytes,
            cost_model,
            params,
            safety_level,
            test_cred(password),
            domain,
            &[],
            spatial,
            control,
        )
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
        write_chunk(&mut out, b"IHDR", &ihdr).expect("IHDR");
        for (ty, body) in ancillary {
            write_chunk(&mut out, ty, body).expect("ancillary chunk");
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
            write_chunk(&mut out, b"IDAT", piece).expect("IDAT");
        }
        write_chunk(&mut out, b"IEND", &[]).expect("IEND");
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

        let hill_params = PngParams::default()
            .with_p1_window(5)
            .with_p2_window(7)
            // not a power of two: must be quantised on both ends
            .with_epsilon(1e-8);
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
    fn out_of_range_sigma_is_rejected_before_embedding() {
        // `sigma` is stored in the feature word as an f32. NaN, infinities and
        // values outside the supported range used to be written as-is, which
        // made the cost map unusable or made extraction read a different
        // number, so embedding succeeded but the payload could never be read.
        let mut params = PngParams::default();
        for bad in [
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            -1.0,
            1e300,
            0.05,
            11.0,
        ] {
            params.algorithm_options.insert("sigma".to_string(), bad);
            let err = params.validate().unwrap_err();
            assert!(
                err.to_string().contains("'sigma'"),
                "sigma={bad} must name the parameter: {err}"
            );
        }

        let (w, h) = (64usize, 64usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let payload = b"sigma-boundary";
        for sigma in [0.1, 1.0, 10.0] {
            let mut legal = PngParams::default();
            legal.algorithm_options.insert("sigma".to_string(), sigma);
            let stego = embed_png(
                &png,
                payload,
                None,
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &crate::stego::png::cost::SuniwardCostModel,
                &legal,
                SafetyPolicy::default(),
                Freshness::Random,
                &Control::none(),
            )
            .unwrap_or_else(|e| panic!("sigma={sigma} must embed: {e}"));
            let extracted = extract_png(
                &stego,
                None,
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &crate::stego::png::cost::SuniwardCostModel,
                &PngParams::default(),
                &Control::none(),
            )
            .unwrap_or_else(|e| panic!("sigma={sigma} must extract: {e}"));
            assert_eq!(extracted, payload, "sigma={sigma} must round-trip");
        }
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
        let params = PngParams::default()
            .with_codec(StegoCodec::Stc)
            .with_stc_h(8);
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
        let extract_params = PngParams::default().with_codec(StegoCodec::Hamming);
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
    fn exclusion_rate_off_the_permille_grid_roundtrips() {
        // The feature word can only carry integer permille, so the embedder has
        // to rank candidates with the same quantised rate the extractor will
        // reconstruct. Before the fix, 0.0123 wrote 12 permille but ranked with
        // 0.0123, and the payload became silently unreadable.
        let (w, h) = (96usize, 96usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let payload = b"permille-quantised-roundtrip";
        let params = PngParams::default().with_exclusion_percentile(0.0123);
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
            &PngParams::default(),
            &Control::none(),
        )
        .expect("extract");
        assert_eq!(extracted, payload, "the wire value must round-trip");
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
    fn decode_rejects_a_chunk_whose_crc_no_longer_matches() {
        let img = RawImage {
            width: 4,
            height: 4,
            channels: 3,
            bit_depth: 8,
            color_type: 2,
            pixels: vec![10u8; 4 * 4 * 3],
            chunks: Vec::new(),
            idat_sizes: Vec::new(),
            row_filters: Vec::new(),
            idat_info: None,
            tail: Vec::new(),
        };
        let png = encode_png(&img).expect("encode");
        assert!(
            decode_png(&png).is_ok(),
            "the untouched carrier must decode"
        );

        // Flip one bit inside the IDAT body and leave its CRC alone -- exactly
        // what a truncated download or a byte-level tamper looks like.
        let mut pos = 8usize;
        let mut tampered = None;
        while pos + 12 <= png.len() {
            let len =
                u32::from_be_bytes([png[pos], png[pos + 1], png[pos + 2], png[pos + 3]]) as usize;
            if &png[pos + 4..pos + 8] == b"IDAT" && len > 0 {
                let mut copy = png.clone();
                copy[pos + 8] ^= 0x01;
                tampered = Some(copy);
                break;
            }
            pos += 12 + len;
        }
        let tampered = tampered.expect("the encoder must emit a non-empty IDAT");
        assert!(matches!(
            decode_png(&tampered),
            Err(StrHideError::CorruptedData(_))
        ));
    }

    #[test]
    fn decode_rejects_structurally_impossible_chunks() {
        let sig: &[u8] = b"\x89PNG\r\n\x1a\n";

        // 1) A chunk before IHDR. `decode_png` reads width/height out of the
        //    header, so anything earlier means the stream is not a PNG.
        let mut out_of_order = Vec::from(sig);
        let text = PngChunk {
            ty: *b"tEXt",
            data: b"k\0v".to_vec(),
        };
        write_chunk(&mut out_of_order, &text.ty, &text.data).unwrap();
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&4u32.to_be_bytes());
        ihdr.extend_from_slice(&4u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        write_chunk(&mut out_of_order, b"IHDR", &ihdr).unwrap();
        assert!(matches!(
            decode_png(&out_of_order),
            Err(StrHideError::CorruptedData(_))
        ));

        // 2) IHDR with a 14-byte body.
        let mut long_ihdr = Vec::from(sig);
        let mut body = ihdr.clone();
        body.push(0);
        write_chunk(&mut long_ihdr, b"IHDR", &body).unwrap();
        assert!(matches!(
            decode_png(&long_ihdr),
            Err(StrHideError::CorruptedData(_))
        ));

        // 3) A compression method other than 0.
        let mut bad_method = Vec::from(sig);
        let mut body = ihdr.clone();
        body[10] = 1;
        write_chunk(&mut bad_method, b"IHDR", &body).unwrap();
        assert!(matches!(
            decode_png(&bad_method),
            Err(StrHideError::UnsupportedFormat(_))
        ));

        // 4) A declared length over the ceiling is rejected from the header
        //    alone, without waiting for (or allocating) the body.
        let mut huge = Vec::from(sig);
        huge.extend_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
        huge.extend_from_slice(b"IDAT");
        assert!(matches!(
            decode_png(&huge),
            Err(StrHideError::CorruptedData(_))
        ));

        // 5) A non-alphabetic chunk type.
        let mut bad_type = Vec::from(sig);
        bad_type.extend_from_slice(&0u32.to_be_bytes());
        bad_type.extend_from_slice(b"IH1R");
        bad_type.extend_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(
            decode_png(&bad_type),
            Err(StrHideError::CorruptedData(_))
        ));
    }

    #[test]
    fn handbuilt_image_without_chunks_still_encodes() {
        let img = RawImage {
            width: 4,
            height: 4,
            channels: 3,
            bit_depth: 8,
            color_type: 2,
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
            let params = PngParams::default()
                .with_codec(StegoCodec::Stc)
                .with_stc_h(8)
                .with_stc_u(stc_u);
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

    /// Colour types 0/2 use `tRNS` as a transparent colour key: every pixel
    /// equal to the key is fully transparent, so a class-internal `±1` on one of
    /// them makes it opaque. The engine used to keep the chunk verbatim and embed
    /// anyway, i.e. visibly damage a carrier it promised to preserve.
    #[test]
    fn trns_colour_key_is_refused() {
        let (w, h) = (32usize, 32usize);
        let pixels = vec![0x80u8; w * h * 3];
        // Six bytes: the RGB triple that is fully transparent.
        let key = [0u8, 0x80, 0, 0x80, 0, 0x80];
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![0u8; h],
            &[(b"tRNS", &key)],
            1,
        );

        match decode_png(&png) {
            Ok(_) => panic!("a tRNS colour key must be refused, not embedded into"),
            Err(StrHideError::UnsupportedFormat(msg)) => {
                assert!(msg.contains("tRNS"), "error must name the chunk: {msg}");
            }
            Err(other) => panic!("unexpected error kind: {other}"),
        }
    }

    /// The budget must be checked before trellis allocation: 64 MP RGB with
    /// a 1.5e8-slot body would allocate tens of GiB for bitmap alone.
    /// The spatial cap (`MAX_PNG_PIXELS`) alone does not bound it.
    #[test]
    fn pipeline_budget_rejects_oversized_trellis_work() {
        let total_pixels = 64 * 1024 * 1024;

        assert!(check_pipeline_budget(total_pixels, 1_000_000, Some(8)).is_ok());
        assert!(
            check_pipeline_budget(total_pixels, 150_000_000, Some(8)).is_err(),
            "a 1.5e8-slot STC solve must be refused, not attempted"
        );
        // The same slot count is affordable for Hamming: no bitmap.
        assert!(check_pipeline_budget(total_pixels, 50_000_000, None).is_ok());

        let stc = max_body_slots_within_pipeline(total_pixels, Some(8));
        let hamming = max_body_slots_within_pipeline(total_pixels, None);
        assert!(stc < 150_000_000);
        assert!(
            stc < hamming,
            "the bitmap must cost slots: {stc} vs {hamming}"
        );
    }

    /// Verifies that probe `max_raw_payload_bytes` never exceeds what the pipeline budget accepts.
    #[test]
    fn probe_capacity_never_exceeds_pipeline_budget() {
        let params = PngParams::default();
        let total_pixels = 8192 * 7680; // 62,914,560
        let pool_green = 40_000_000usize;
        let pool_rgb = Some(99_082_944usize); // test carrier pool size

        // The exact size the pre-fix probe advertised: slots fit the pool, but
        // the STC working set does not fit the budget.
        assert!(
            !body_payload_fits(&params, pool_green, pool_rgb, 12_385_345, total_pixels)
                .expect("fits check"),
            "a payload whose solve needs ~9 GiB must not be advertised"
        );

        let max = max_raw_payload_for_pools(&params, pool_green, pool_rgb, total_pixels)
            .expect("max raw payload");
        assert!(max > 0, "the carrier still holds a large payload: {max}");
        assert!(max < 12_385_345, "budget clamps the advertised max: {max}");

        // The advertised maximum must pass the same budget gate the embedder
        // enforces, under the same codec/u resolution.
        let bits = (max + crate::stego::envelope::BODY_OVERHEAD) * 8;
        let (codec, u) = crate::stego::coding::auto_select_codec(99_082_944, bits);
        let slots =
            crate::stego::coding::slots_for_codec(bits, codec, params.stc_h, u).expect("slots");
        let trellis_h = match codec {
            StegoCodec::Hamming => None,
            _ => Some(params.stc_h),
        };
        check_pipeline_budget(total_pixels, slots, trellis_h)
            .expect("advertised maximum must pass the embedder's budget gate");
    }

    /// G1 regression for small carriers: the budget clamp must not shrink a
    /// carrier whose working set is far below the budget (pool-limited, not
    /// budget-limited).
    #[test]
    fn probe_capacity_stays_pool_limited_below_the_budget() {
        let params = PngParams::default();
        let total_pixels = 600 * 600;
        let pool_green = 100_000usize;
        let pool_rgb = Some(250_000usize);

        let max = max_raw_payload_for_pools(&params, pool_green, pool_rgb, total_pixels)
            .expect("max raw payload");
        assert!(max > 0);
        assert!(body_payload_fits(&params, pool_green, pool_rgb, max, total_pixels).expect("fits"));
        assert!(
            !body_payload_fits(&params, pool_green, pool_rgb, max + 1, total_pixels).expect("fits"),
            "max + 1 must not fit, by definition of the binary search"
        );
    }

    /// Verifies that IDAT-only recompression preserves payload readability.
    #[test]
    fn idat_only_recompression_keeps_payload_readable() {
        let (w, h) = (96usize, 96usize);
        let pixels = row_correlated_pixels(w, h);
        let text = b"Comment\0keep-me".to_vec();
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![2u8; h],
            &[(b"tEXt", &text)],
            1,
        );
        let params = PngParams::default();
        let payload = b"re-encode me".to_vec();

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
        .expect("embed");

        let img = decode_png(&stego).expect("decode stego");
        let reencoded = encode_png(&img).expect("IDAT-only recompression");
        let out = extract_png(
            &reencoded,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("payload must survive an IDAT-only recompression");
        assert_eq!(out, payload);
    }

    /// Verifies that ancillary chunk changes (e.g. metadata edits via exiftool/tinypng)
    /// leave the stego payload intact and readable.
    #[test]
    fn ancillary_chunk_change_keeps_payload_readable() {
        let (w, h) = (96usize, 96usize);
        let pixels = row_correlated_pixels(w, h);
        let text = b"Comment\0original".to_vec();
        let png = craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![2u8; h],
            &[(b"tEXt", &text)],
            1,
        );
        let params = PngParams::default();
        let payload = b"metadata-independent".to_vec();

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
        .expect("embed");

        let mut img = decode_png(&stego).expect("decode stego");
        // Same pixels, same geometry: only the metadata stream changes.
        let chunk = img
            .chunks
            .iter_mut()
            .find(|c| c.ty == *b"tEXt")
            .expect("tEXt chunk present");
        chunk.data = b"Comment\0edited-afterwards".to_vec();
        // Something an ICC-aware tool might also add while it is there.
        img.chunks.push(PngChunk {
            ty: *b"iCCP",
            data: b"profile\0\0fake-icc".to_vec(),
        });
        let reencoded = encode_png(&img).expect("re-encode");

        let out = extract_png(
            &reencoded,
            Some("pw"),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            &Control::none(),
        )
        .expect("metadata edits must not destroy the payload");
        assert_eq!(out, payload);
    }

    /// The narrowed salt still has to bind something: geometry and palette are
    /// part of the carrier's identity, so changing them must break locators.
    #[test]
    fn pre_salt_ignores_ancillary_chunks_but_binds_geometry_and_palette() {
        let (w, h) = (16usize, 16usize);
        let pixels = row_correlated_pixels(w, h);
        let base = decode_png(&craft_png(
            w as u32,
            h as u32,
            &pixels,
            &vec![0u8; h],
            &[(b"tEXt", b"K\0v")],
            1,
        ))
        .expect("decode");
        let spatial = crate::stego::format::OFFICIAL_PNG_FORMAT;
        let reference = png_pre_salt(&base, &spatial);

        // 1. Metadata only: same salt.
        let mut metadata_edit = base.clone();
        metadata_edit
            .chunks
            .iter_mut()
            .find(|c| c.ty == *b"tEXt")
            .expect("tEXt")
            .data = b"K\0different".to_vec();
        metadata_edit.chunks.push(PngChunk {
            ty: *b"tIME",
            data: vec![7, 230, 11, 7, 12, 0, 0],
        });
        assert_eq!(png_pre_salt(&metadata_edit, &spatial), reference);

        // 2. Geometry: different salt, or the locator would survive a crop.
        let mut resized = base.clone();
        resized.width -= 1;
        assert_ne!(png_pre_salt(&resized, &spatial), reference);

        // 3. Palette: different salt.
        let mut repalettised = base.clone();
        repalettised.chunks.insert(
            1,
            PngChunk {
                ty: *b"PLTE",
                data: vec![0, 0, 0, 255, 255, 255],
            },
        );
        assert_ne!(png_pre_salt(&repalettised, &spatial), reference);
    }

    /// The tier table is what hosts read instead of re-deriving the budget, so
    /// it has to agree with `recommended_max_bytes` for the probed tier and be
    /// ordered strictest-to-loosest. The Tauri capacity card used to keep its
    /// own copy of these formulas and drifted (it matched `info.format` against
    /// "hevc"/"mp4", which no engine ever reports).
    #[test]
    fn tier_limits_agree_with_probe_and_are_monotonic() {
        use crate::stego::SafetyLevel;

        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let params = PngParams::default();

        for level in SafetyLevel::ALL {
            let cap = probe_png_capacity(
                &png,
                &HillCostModel,
                &params,
                level,
                Some("pw"),
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &Control::none(),
            )
            .expect("probe");

            assert_eq!(
                cap.tier_limit(level),
                cap.recommended_max_bytes,
                "probed tier {level:?} must match its slot in the table"
            );
            assert!(
                cap.tier_limit(SafetyLevel::Paranoid) <= cap.tier_limit(SafetyLevel::High)
                    && cap.tier_limit(SafetyLevel::High) <= cap.tier_limit(SafetyLevel::Balanced),
                "tiers must widen from paranoid to balanced: {:?}",
                cap.tier_limits
            );
        }
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
            // Noise does not compress, so this exercises the raw boundary that
            // the capacity accounting claims. The probe and the embedder now
            // share `body_payload_fits`, so the value must be exactly reachable.
            let payload = noise_payload(cap.max_raw_payload_bytes);
            let stego = embed_png(
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
            let extracted = extract_png(
                &stego,
                password,
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &HillCostModel,
                &params,
                &Control::none(),
            )
            .expect("payload at the advertised capacity must be readable");
            assert_eq!(extracted, payload);

            let over = noise_payload(cap.max_raw_payload_bytes + 1);
            let rejected = embed_png(
                &png,
                &over,
                password,
                None,
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &HillCostModel,
                &params,
                SafetyPolicy::default(),
                Freshness::Random,
                &Control::none(),
            );
            assert!(
                rejected.is_err(),
                "password {password:?}: capacity+1 must not fit"
            );
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
        let enforced = SafetyPolicy::default()
            .with_level(SafetyLevel::Paranoid)
            .with_enforcement(SafetyEnforcement::Enforced);

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
            bit_depth: 8,
            color_type: 2,
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

    /// Verifies that RGB body slots filter each channel while sharing the candidate pool.
    #[test]
    fn rgb_body_slots_filter_each_channel_but_share_the_green_candidate_pool() {
        let image = RawImage {
            width: 4,
            height: 1,
            channels: 3,
            bit_depth: 8,
            color_type: 2,
            pixels: vec![
                0, 100, 100, // R ineligible, B eligible
                100, 0, 100, // green ineligible: whole pixel is not a candidate
                100, 100, 0, // R eligible, B ineligible
                0, 0, 0, // nothing eligible
            ],
            chunks: Vec::new(),
            idat_sizes: Vec::new(),
            row_filters: vec![0],
            idat_info: None,
            tail: Vec::new(),
        };

        // Pixel 1 carries legal R/B values but fails the green precondition,
        // so it never enters the candidate pool (the reported "miss").
        assert_eq!(header_pool(&image), vec![0, 2]);

        let costs = vec![0.0; image.width as usize];
        let seed = [7u8; 32];
        // permutation id 0, then exclusion permille 0 (keep every candidate).
        let plan = SlotPlan::build(&image, &costs, &seed, 0, 0).expect("plan");
        assert_eq!(plan.candidates, vec![0, 2]);

        // Both candidates are header pixels, so their green slots are
        // reserved; only the per-channel-eligible R/B slots remain.
        let slots = plan.body_slots_upto(&image, 0, ChannelMode::Rgb, usize::MAX);
        assert_eq!(slots, vec![2, 6], "only the eligible R/B slots are used");
        for slot in slots {
            assert!(
                (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&image.pixels[slot]),
                "every body slot must stay class-interior"
            );
        }
    }

    /// The smooth-area cut is integer arithmetic on the wire permille.
    ///
    /// `WIRE_SPEC_CONTENT §13.11.3` fixes `allowed = n * (1000 - p) / 1000`.
    /// The previous `n * (1.0 - p/1000.0)` rounds in the last bit and lands one
    /// element short exactly when the true quotient is an integer: with
    /// `p = 900‰` and `n = 1000` it selects 99 candidates instead of 100, so a
    /// reader following the spec would rebuild a different body pool.
    #[test]
    fn exclusion_cut_uses_integer_arithmetic() {
        let w = 1000usize;
        let image = RawImage {
            width: w as u32,
            height: 1,
            bit_depth: 8,
            color_type: 0,
            channels: 1,
            pixels: vec![128u8; w],
            chunks: Vec::new(),
            idat_sizes: Vec::new(),
            row_filters: Vec::new(),
            idat_info: None,
            tail: Vec::new(),
        };
        let costs = vec![0.0f64; w];
        let seed = [9u8; 32];

        // 900‰ excluded, 1000 eligible -> 100 candidates (not 99).
        let plan = SlotPlan::build(&image, &costs, &seed, 0, 900).expect("plan");
        assert_eq!(plan.candidates.len(), 100);

        // Degenerate end: nothing excluded keeps every eligible pixel.
        let plan = SlotPlan::build(&image, &costs, &seed, 0, 0).expect("plan");
        assert_eq!(plan.candidates.len(), 1000);

        // The helper is the inverse of the header field, for every value it can carry.
        for permille in 0..=900u16 {
            assert_eq!(exclusion_permille(f64::from(permille) / 1000.0), permille);
        }
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
        let pre_salt = png_pre_salt(&img, &crate::stego::format::OFFICIAL_PNG_FORMAT);
        let master = derive_locator_master(
            Credential::Password(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
            None,
            &crate::stego::format::OFFICIAL_PNG_CIPHER,
            &pre_salt,
        )
        .expect("master");
        let locator = derive_l2_locator_keys(
            &master,
            &crate::stego::format::OFFICIAL_PNG_CIPHER,
            b"strhide-v4-hdr-magic",
            None,
        )
        .expect("locator");
        let plan = SlotPlan::build(
            &img,
            &costs,
            &locator.locate_seed,
            0,
            exclusion_permille(params.exclusion_percentile),
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
        let allowed = eligible.len()
            * (1000 - exclusion_permille(params.exclusion_percentile) as usize)
            / 1000;
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

        // A private build changes *every* derivation label, exactly as
        // `WIRE_SPEC_CONTENT §13.11` promises. `hpos_salt` alone would leave the KDF
        // labels official, which is what the old profile shape did.
        const PRIVATE_CIPHER: crate::stego::format::WireCipherProfile =
            crate::stego::format::WireCipherProfile {
                domain_label: b"private-domain-label",
                hpos_label: b"private-hpos-label-xyz",
                enc_label: b"private-enc-label",
                perm_label: b"private-perm-label",
                stc_label: b"private-stc-label-xyz",
                default_suite: crate::crypto::CipherSuiteId::Aes256Gcm,
            };
        let private_spatial = crate::stego::format::PngFormatProfile {
            hpos_salt: b"private-hpos-salt-xyz",
            cipher: &PRIVATE_CIPHER,
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

    #[test]
    fn embed_capacity_matches_probed_capacity() {
        let (w, h) = (96usize, 96usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let params = PngParams::default();
        let spatial = crate::stego::format::OFFICIAL_PNG_FORMAT;
        let cost_model = HillCostModel;

        let probed = probe_png_capacity(
            &png,
            &cost_model,
            &params,
            crate::stego::SafetyLevel::High,
            Some("pw"),
            None,
            &spatial,
            &Control::none(),
        )
        .expect("probe capacity");

        let (_stego, stats, embedded_cap) = embed_png_with_stats(
            &png,
            b"test payload",
            test_cred(Some("pw")),
            None,
            crate::stego::format::OFFICIAL_PNG_CIPHER
                .default_suite
                .as_u16(),
            &[],
            &spatial,
            &cost_model,
            &params,
            SafetyPolicy::default()
                .with_level(crate::stego::SafetyLevel::High)
                .with_enforcement(crate::stego::SafetyEnforcement::Advisory),
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed with stats");

        assert_eq!(embedded_cap.format, probed.format);
        assert_eq!(embedded_cap.algorithm, probed.algorithm);
        assert_eq!(embedded_cap.total_elements, probed.total_elements);
        assert_eq!(embedded_cap.available_slots, probed.available_slots);
        assert_eq!(
            embedded_cap.max_raw_payload_bytes,
            probed.max_raw_payload_bytes
        );
        assert_eq!(
            embedded_cap.recommended_max_bytes,
            probed.recommended_max_bytes
        );
        assert_eq!(embedded_cap.tier_limits, probed.tier_limits);
        assert_eq!(stats.total_candidate_slots, probed.total_elements);
    }

    // -----------------------------------------------------------------
    // V4 envelope: negative paths
    // -----------------------------------------------------------------

    fn v4_cred(password: &str) -> Credential<'_> {
        Credential::Password(password)
    }

    fn base_header_slots_for(image: &RawImage, password: &str) -> Vec<usize> {
        let spatial = crate::stego::format::OFFICIAL_PNG_FORMAT;
        let pre_salt = png_pre_salt(image, &spatial);
        let master = derive_locator_master(
            v4_cred(password),
            None,
            &crate::stego::format::OFFICIAL_PNG_CIPHER,
            &pre_salt,
        )
        .expect("master");
        let locator = derive_l2_locator_keys(
            &master,
            &crate::stego::format::OFFICIAL_PNG_CIPHER,
            b"strhide-v4-hdr-magic",
            None,
        )
        .expect("locator");
        header_layout(image, &locator.locate_seed, 0)[..PNG_AUDIO_BASE_SLOTS].to_vec()
    }

    fn rewrite_base_header(image: &mut RawImage, slots: &[usize], bytes: &[u8; 64]) {
        let channel = embed_channel(image);
        for byte_i in 0..64 {
            for bit_i in 0..8 {
                let bit = (bytes[byte_i] >> (7 - bit_i)) & 1;
                let idx = slots[byte_i * 8 + bit_i] * image.channels + channel;
                image.pixels[idx] = (image.pixels[idx] & 0xfe) | bit;
            }
        }
    }

    fn extract_with(
        carrier: &[u8],
        password: &str,
        limits: &ExtractParams,
    ) -> Result<Vec<u8>, StrHideError> {
        super::extract_png(
            carrier,
            v4_cred(password),
            None,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &PngParams::default(),
            limits,
            &Control::none(),
        )
        .map(Payload::into_bytes)
    }

    #[test]
    fn v4_extension_roundtrip_and_unknown_critical_are_rejected() {
        let (w, h) = (96usize, 96usize);
        let png = craft_png(
            w as u32,
            h as u32,
            &row_correlated_pixels(w, h),
            &vec![2u8; h],
            &[],
            1,
        );
        let params = PngParams::default();
        let safety = SafetyPolicy::default()
            .with_level(crate::stego::SafetyLevel::High)
            .with_enforcement(crate::stego::SafetyEnforcement::Advisory);

        // Non-critical unknown TLV: ignored, payload still readable.
        let ext = [Tlv {
            type_id: 0x02,
            value: vec![1, 2, 3],
        }];
        let stego = super::embed_png(
            &png,
            b"extension payload",
            v4_cred("pw"),
            None,
            crate::stego::format::OFFICIAL_PNG_CIPHER
                .default_suite
                .as_u16(),
            &ext,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            safety,
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed with non-critical extension");
        let got = extract_with(&stego, "pw", &ExtractParams::default()).expect("extract");
        assert_eq!(got, b"extension payload");

        // Unknown critical TLV: the writer refuses it outright, because V4
        // defines no critical extension and every reader (this one included)
        // folds an unknown critical tag into `NoHiddenData`.
        let critical = [Tlv {
            type_id: 0x81,
            value: vec![9],
        }];
        let err = super::embed_png(
            &png,
            b"critical extension payload",
            v4_cred("pw"),
            None,
            crate::stego::format::OFFICIAL_PNG_CIPHER
                .default_suite
                .as_u16(),
            &critical,
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            safety,
            Freshness::Random,
            &Control::none(),
        )
        .unwrap_err();
        assert!(matches!(err, StrHideError::General(_)), "{err:?}");

        // A hostile writer bypasses that check; the reader must still refuse.
        let forged = forge_header_area(&stego, &[0x81, 0x01, 9]);
        assert!(
            matches!(
                extract_with(&forged, "pw", &ExtractParams::default()),
                Err(StrHideError::NoHiddenData(_))
            ),
            "an unknown critical TLV must fail closed"
        );
    }

    /// Rewrite a PNG carrier's base header and extension area so it declares
    /// the given (critical) TLV bytes, the way a writer that ignored the
    /// fail-closed validation would have produced it.
    fn forge_header_area(stego: &[u8], extension: &[u8]) -> Vec<u8> {
        use crate::stego::header::{
            CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, SpatialHeaderV4,
        };

        let mut image = decode_png(stego).expect("decode");
        let spatial = &crate::stego::format::OFFICIAL_PNG_FORMAT;
        let keys = png_keys(&image, v4_cred("pw"), None, spatial).expect("keys");
        let header = SpatialHeaderV4 {
            salt: [1u8; 16],
            nonce: [2u8; 12],
            body_len: 64,
            version: CONTENT_ENVELOPE_VERSION,
            flags: FLAG_EXT_PRESENT | FLAG_EXT_CRITICAL,
            format_id: PNG_FORMAT_ID,
            algorithm_id: 1,
            suite_id: 1,
            codec_id: 1,
            stc_h: 8,
            stc_u: 1,
            channel_mode: 0,
            class_rule: 1,
            p1_window: 3,
            p2_window: 15,
            neg_log2_epsilon: 23,
            exclusion_permille: 300,
            sigma: 1.0,
            kernel_id: 0,
            ext_len: extension.len() as u16,
        };
        let layout = header_layout(&image, &keys.locator.locate_seed, extension.len());
        let channel = embed_channel(&image);
        let bytes = header.encode();
        for (i, slot) in layout[..PNG_AUDIO_BASE_SLOTS].iter().enumerate() {
            let bit = (bytes[i / 8] >> (7 - (i % 8))) & 1;
            set_parity(&mut image.pixels[slot * image.channels + channel], bit);
        }
        for (i, slot) in layout[PNG_AUDIO_BASE_SLOTS..PNG_AUDIO_BASE_SLOTS + 8 * extension.len()]
            .iter()
            .enumerate()
        {
            let bit = (extension[i / 8] >> (7 - (i % 8))) & 1;
            set_parity(&mut image.pixels[slot * image.channels + channel], bit);
        }
        encode_png(&image).expect("encode")
    }

    /// Force the low bit of `value` without crossing the class-interior rule.
    fn set_parity(value: &mut u8, bit: u8) {
        if (*value & 1) != bit {
            *value ^= 1;
        }
    }

    #[test]
    fn v4_unknown_suite_and_low_pbkdf2_policy_fail_closed() {
        let (w, h) = (96usize, 96usize);
        let png = craft_png(
            w as u32,
            h as u32,
            &row_correlated_pixels(w, h),
            &vec![2u8; h],
            &[],
            1,
        );
        let params = PngParams::default();
        let safety = SafetyPolicy::default()
            .with_level(crate::stego::SafetyLevel::High)
            .with_enforcement(crate::stego::SafetyEnforcement::Advisory);
        assert!(matches!(
            super::embed_png(
                &png,
                b"x",
                v4_cred("pw"),
                None,
                999,
                &[],
                &crate::stego::format::OFFICIAL_PNG_FORMAT,
                &HillCostModel,
                &params,
                safety,
                Freshness::Random,
                &Control::none(),
            ),
            Err(StrHideError::UnsupportedVersion(_))
        ));

        let stego = super::embed_png(
            &png,
            b"policy",
            v4_cred("pw"),
            None,
            crate::stego::format::OFFICIAL_PNG_CIPHER
                .default_suite
                .as_u16(),
            &[],
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            safety,
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed");
        let strict = ExtractParams::default().with_max_pbkdf2_iterations(100_000);
        assert!(
            matches!(
                extract_with(&stego, "pw", &strict),
                Err(StrHideError::NoHiddenData(_))
            ),
            "a policy below the fixed V4 L1 cost must fail before PBKDF2"
        );
    }

    #[test]
    fn v4_header_crc_and_aead_reject_tampering() {
        let (w, h) = (96usize, 96usize);
        let png = craft_png(
            w as u32,
            h as u32,
            &row_correlated_pixels(w, h),
            &vec![2u8; h],
            &[],
            1,
        );
        let params = PngParams::default();
        let safety = SafetyPolicy::default()
            .with_level(crate::stego::SafetyLevel::High)
            .with_enforcement(crate::stego::SafetyEnforcement::Advisory);
        let stego = super::embed_png(
            &png,
            b"tamper",
            v4_cred("pw"),
            None,
            crate::stego::format::OFFICIAL_PNG_CIPHER
                .default_suite
                .as_u16(),
            &[],
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            safety,
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed");

        let mut image = decode_png(&stego).expect("decode");
        let slots = base_header_slots_for(&image, "pw");
        let mut header_bytes: [u8; 64] = read_slot_bytes(&image, &slots, 64)
            .try_into()
            .expect("64 bytes");
        let mut header = SpatialHeaderV4::decode(&header_bytes, PNG_FORMAT_ID).expect("header");

        // 1) Flip a byte without recomputing the CRC: caught before body slots.
        header_bytes[32] ^= 0x01; // version
        rewrite_base_header(&mut image, &slots, &header_bytes);
        let tampered_crc = encode_png(&image).expect("encode");
        assert!(matches!(
            extract_with(&tampered_crc, "pw", &ExtractParams::default()),
            Err(StrHideError::NoHiddenData(_))
        ));

        // 2) Flip an authenticated field and recompute the CRC: only the AEAD
        //    tag can catch it, and it must look like "no payload".
        header.salt[0] ^= 0x01;
        let forged = header.encode();
        rewrite_base_header(&mut image, &slots, &forged);
        let tampered_aead = encode_png(&image).expect("encode");
        assert!(matches!(
            extract_with(&tampered_aead, "pw", &ExtractParams::default()),
            Err(StrHideError::NoHiddenData(_))
        ));
    }

    #[test]
    fn v4_forged_body_len_is_rejected_before_body_allocation() {
        let (w, h) = (96usize, 96usize);
        let png = craft_png(
            w as u32,
            h as u32,
            &row_correlated_pixels(w, h),
            &vec![2u8; h],
            &[],
            1,
        );
        let params = PngParams::default();
        let safety = SafetyPolicy::default()
            .with_level(crate::stego::SafetyLevel::High)
            .with_enforcement(crate::stego::SafetyEnforcement::Advisory);
        let stego = super::embed_png(
            &png,
            b"body_len",
            v4_cred("pw"),
            None,
            crate::stego::format::OFFICIAL_PNG_CIPHER
                .default_suite
                .as_u16(),
            &[],
            &crate::stego::format::OFFICIAL_PNG_FORMAT,
            &HillCostModel,
            &params,
            safety,
            Freshness::Random,
            &Control::none(),
        )
        .expect("embed");

        let mut image = decode_png(&stego).expect("decode");
        let slots = base_header_slots_for(&image, "pw");
        let header_bytes: [u8; 64] = read_slot_bytes(&image, &slots, 64)
            .try_into()
            .expect("64 bytes");
        let header = SpatialHeaderV4::decode(&header_bytes, PNG_FORMAT_ID).expect("header");

        for forged_len in [0u32, 21, 0x03ff_ffff] {
            let mut forged = header;
            forged.body_len = forged_len;
            rewrite_base_header(&mut image, &slots, &forged.encode());
            let carrier = encode_png(&image).expect("encode");
            assert!(
                matches!(
                    extract_with(&carrier, "pw", &ExtractParams::default()),
                    Err(StrHideError::NoHiddenData(_))
                ),
                "body_len={forged_len} must not be accepted"
            );
        }
    }

    #[test]
    fn v4_truncated_or_tiny_carriers_report_no_payload() {
        let tiny = craft_png(8, 8, &[120u8; 8 * 8 * 3], &[0u8; 8], &[], 1);
        assert!(matches!(
            extract_with(&tiny, "pw", &ExtractParams::default()),
            Err(StrHideError::NoHiddenData(_))
        ));
    }
}
