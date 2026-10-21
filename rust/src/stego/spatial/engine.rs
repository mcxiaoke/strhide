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
//! from the class floor only `+1` is legal, from the ceiling only `-1`, in
//! between both are. That constraint exists because the extractor rebuilds the
//! slot ranking from a cost map computed on the *stego* image, so the ranking
//! must be reproducible: HILL masks its input with `0xF8`, and a class-internal
//! `±1` leaves that masked value untouched. Unrestricted matching would change
//! it and desynchronise the ranking.
//!
//! Why this is not just LSB replacement with extra steps: replacement always
//! moves a slot in the direction of the target bit, so every value pair
//! `(2k, 2k+1)` is equalised — the exact signature chi-square and SPA look for.
//! Here six of every eight values can move either way, so probability mass
//! crosses pair boundaries and the pairs are no longer individually flat.
//! Direction choice is further biased towards the local mean by
//! [`crate::stego::traits::SpatialCostModel::direction_costs`].

use std::io::{Cursor, Read, Write};

use crc32fast::Hasher as Crc32;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

use crate::errors::StrHideError;
use crate::stego::coding::{
    Move, StcTrellis, hamming_embed_ternary, hamming_extract_bytes, spatial_move_safe,
    write_bit_ternary,
};
use crate::stego::envelope::{pack_envelope_ext, unpack_envelope_with_key};
pub use crate::stego::header::{
    FeatureWord, HEADER_LEN_MASK, HEADER_LEN_MAX, HEADER_V2_ESCAPE_H, V2_TOTAL_HEADER_SLOTS,
    decode_header_word, encode_header_word,
};
use crate::stego::prng::permute_indices;
use crate::stego::traits::SpatialCostModel;
use crate::stego::{SpatialParams, StegoCapacityInfo, StegoCodec};

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

/// Slots needed to carry `bits` payload bits under `codec`.
///
/// STC with group size `u` needs `u * (bits + h - 1)` slots: `bits + h - 1`
/// syndrome rows, each fed by `u` elements, plus the trellis warm-up. `u = 1`
/// is roughly one slot per bit; Hamming k=3 needs 2.33.
fn slots_for(bits: usize, codec: StegoCodec, stc_h: u8, stc_u: u8) -> Result<usize, StrHideError> {
    match codec {
        StegoCodec::Hamming => Ok(crate::stego::coding::required_slots(
            bits,
            crate::stego::coding::DEFAULT_HAMMING_K,
        )),
        StegoCodec::Stc | StegoCodec::Auto => {
            let u = if stc_u == 0 { 1 } else { stc_u };
            let t = StcTrellis::from_seed_grouped(0, stc_h, u)?;
            Ok(t.slots_for(bits))
        }
    }
}

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

    // Decompress IDAT stream
    let mut z = ZlibDecoder::new(Cursor::new(&idat));
    let mut raw = Vec::new();
    z.read_to_end(&mut raw)?;

    let expected = stride * height as usize + height as usize;
    if raw.len() < expected {
        return Err(StrHideError::CorruptedData(
            "Decompressed IDAT is truncated".into(),
        ));
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
    })
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
/// The zlib level is not recoverable from the stream, so
/// `Compression::default()` is used; filter preservation is what keeps the
/// size near the original.
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

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&filtered)?;
    let compressed_idat = encoder.finish()?;

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

    Ok(out)
}

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
// Embedding & Extraction
// ---------------------------------------------------------------------------

/// Embed secret payload into PNG carrier using content-adaptive spatial steganography.
pub fn embed_spatial(
    carrier_bytes: &[u8],
    payload: &[u8],
    password: Option<&str>,
    cost_model: &dyn SpatialCostModel,
    params: &SpatialParams,
) -> Result<Vec<u8>, StrHideError> {
    let mut image = decode_png(carrier_bytes)?;
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    // Pack payload into stealth micro-envelope
    let (envelope, perm_seed) = pack_envelope_ext(payload, password)?;

    // Compute distortion cost map
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, params);
    if costs.len() != total_pixels {
        return Err(StrHideError::General("Cost map dimension mismatch".into()));
    }

    // Channel to embed in (Green channel for RGB, channel 0 for grayscale/RGBA luminance)
    let channel_offset = if image.channels >= 3 { 1 } else { 0 };

    // Eligible pixels: the class must be interior, i.e. `val` must sit in
    // [8, 247] so that at least one of `val ± 1` stays inside the same
    // eight-value class. That keeps three invariants the extractor relies on:
    // 1. `val & 0xF8` never changes, so the HILL cost map is bit-identical;
    // 2. modified values stay in [7, 248], never reaching 0/255 (no clipping);
    // 3. eligibility itself is class-based, so both ends derive the same set.
    let mut eligible_pixels: Vec<usize> = (0..total_pixels)
        .filter(|&idx| {
            let val = image.pixels[idx * image.channels + channel_offset];
            (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val)
        })
        .collect();

    // Rank pixels by cost: lowest cost (most complex/noisy) first
    eligible_pixels.sort_by(|&a, &b| {
        costs[a]
            .partial_cmp(&costs[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Exclude the smoothest fraction (e.g. 30%)
    let allowed_count = ((eligible_pixels.len() as f64)
        * (1.0 - params.exclusion_percentile.clamp(0.0, 0.9))) as usize;
    let candidate_pixels = &eligible_pixels[..allowed_count];

    if candidate_pixels.len() < V2_TOTAL_HEADER_SLOTS {
        return Err(StrHideError::General(format!(
            "Carrier capacity insufficient: available {} slots, minimum header requires {} slots",
            candidate_pixels.len(),
            V2_TOTAL_HEADER_SLOTS
        )));
    }

    // Phase 1: Keyed candidate set permutation for header slots (Legacy rule: [8, 247], 30% exclusion)
    let header_seed = crate::stego::envelope::derive_header_perm_seed(password);
    let mut permuted_candidates = candidate_pixels.to_vec();
    permute_indices(&mut permuted_candidates, &header_seed);

    let header_slots = &permuted_candidates[..256];
    let feature_slots = &permuted_candidates[256..V2_TOTAL_HEADER_SLOTS];

    let is_header = {
        let mut v = vec![false; total_pixels];
        for &s in &permuted_candidates[..V2_TOTAL_HEADER_SLOTS] {
            v[s] = true;
        }
        v
    };

    // Body slots: under safe non-boundary rule (class_rule=1), restrict candidates to
    // val % 8 in [1, 6] to completely eliminate the r=0/7 boundary deficit (P0-B).
    let body_candidates: Vec<usize> = candidate_pixels
        .iter()
        .copied()
        .filter(|&s| {
            let val = image.pixels[s * image.channels + channel_offset];
            (1..=6).contains(&(val % 8)) && !is_header[s]
        })
        .collect();

    let ciphertext_body = &envelope[28..];
    let ciphertext_bits = ciphertext_body.len() * 8;

    // Resolve matrix-coding strategy: Auto adaptively picks STC group size (u=3, 2, or 1)
    let (resolved_codec, resolved_u) = match params.codec {
        StegoCodec::Auto => {
            crate::stego::coding::auto_select_codec(body_candidates.len(), ciphertext_bits)
        }
        StegoCodec::Stc if params.stc_u == 0 => {
            crate::stego::coding::auto_select_codec(body_candidates.len(), ciphertext_bits)
        }
        StegoCodec::Stc => (StegoCodec::Stc, params.stc_u),
        StegoCodec::Hamming => (StegoCodec::Hamming, 0),
    };

    let needed_body_slots = slots_for(ciphertext_bits, resolved_codec, params.stc_h, resolved_u)?;

    if needed_body_slots > body_candidates.len() {
        return Err(StrHideError::General(format!(
            "Carrier capacity exceeded: needed {} body slots ({}), available {} slots (strategy: spatial-{})",
            needed_body_slots,
            resolved_codec.describe(params.stc_h, resolved_u),
            body_candidates.len(),
            cost_model.id(),
        )));
    }

    // Header word1 encodes total_len with HEADER_V2_ESCAPE_H (15) for stc_h
    let total_len = envelope.len() as u32;
    if total_len > HEADER_LEN_MAX {
        return Err(StrHideError::General(format!(
            "Envelope of {total_len} bytes exceeds the {HEADER_LEN_MAX}-byte header length field"
        )));
    }
    let header_word = encode_header_word(total_len, resolved_codec, HEADER_V2_ESCAPE_H, resolved_u);
    let mut header_bytes = Vec::with_capacity(32);
    header_bytes.extend_from_slice(&envelope[..28]); // Salt (16B) + Nonce (12B)
    header_bytes.extend_from_slice(&header_word.to_be_bytes());

    let fw = FeatureWord {
        version: 2,
        codec: resolved_codec,
        u: resolved_u,
        h: params.stc_h,
        channel_mode: 0,
        class_rule: 1, // Safe [1, 6] non-boundary
        kdf_id: 0,     // PBKDF2 100k
        eligible_min: SPATIAL_ELIGIBLE_MIN,
        eligible_max: SPATIAL_ELIGIBLE_MAX,
        exclusion_permille: (params.exclusion_percentile.clamp(0.0, 0.9) * 1000.0) as u16,
    };
    let feature_bytes = fw.encode();

    // Phase 2: Keyed permutation of body slots using PBKDF2 salt-derived seed from pack_envelope_ext
    let salt = &envelope[..16];
    let stc_seed = crate::stego::envelope::derive_stc_seed(&perm_seed, salt);

    let mut body_slots = body_candidates[..needed_body_slots].to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    // Asymmetric per-direction costs. Embed-side only: ranking never sees them.
    let (rho_plus, rho_minus) =
        cost_model.direction_costs(&costs, &image.pixels, w, h, image.channels, channel_offset);
    if rho_plus.len() != total_pixels || rho_minus.len() != total_pixels {
        return Err(StrHideError::General(
            "Direction cost map dimension mismatch".into(),
        ));
    }

    // Embed Phase 1a: 32-byte header word1 (256 slots)
    for (byte_i, &b) in header_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let slot = header_slots[byte_i * 8 + bit_i];
            let byte_idx = slot * image.channels + channel_offset;
            write_bit_ternary(
                &mut image.pixels[byte_idx],
                target_bit,
                rho_plus[slot],
                rho_minus[slot],
            );
        }
    }

    // Embed Phase 1b: 32-byte feature word (256 slots)
    for (byte_i, &b) in feature_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let slot = feature_slots[byte_i * 8 + bit_i];
            let byte_idx = slot * image.channels + channel_offset;
            write_bit_ternary(
                &mut image.pixels[byte_idx],
                target_bit,
                rho_plus[slot],
                rho_minus[slot],
            );
        }
    }

    // Embed Phase 2: Ciphertext body.
    let mut slot_vals: Vec<u8> = body_slots
        .iter()
        .map(|&slot| image.pixels[slot * image.channels + channel_offset])
        .collect();
    let moves: Vec<Move> = slot_vals.iter().map(|&v| spatial_move_safe(v)).collect();
    let rp: Vec<f64> = body_slots.iter().map(|&s| rho_plus[s]).collect();
    let rm: Vec<f64> = body_slots.iter().map(|&s| rho_minus[s]).collect();
    match resolved_codec {
        StegoCodec::Hamming => {
            hamming_embed_ternary(
                &mut slot_vals,
                &moves,
                &rp,
                &rm,
                ciphertext_body,
                crate::stego::coding::DEFAULT_HAMMING_K,
            )?;
        }
        StegoCodec::Stc | StegoCodec::Auto => {
            let trellis = StcTrellis::from_seed_grouped(stc_seed, params.stc_h, resolved_u)?;
            trellis.embed(&mut slot_vals, &moves, &rp, &rm, ciphertext_body)?;
        }
    }

    for (i, &slot) in body_slots.iter().enumerate() {
        image.pixels[slot * image.channels + channel_offset] = slot_vals[i];
    }

    encode_png(&image)
}

/// Extract secret payload from PNG carrier using content-adaptive spatial steganography.
pub fn extract_spatial(
    carrier_bytes: &[u8],
    password: Option<&str>,
    cost_model: &dyn SpatialCostModel,
    params: &SpatialParams,
) -> Result<Vec<u8>, StrHideError> {
    let image = decode_png(carrier_bytes)?;
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    // Compute distortion cost map (identical to embedding)
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, params);
    if costs.len() != total_pixels {
        return Err(StrHideError::General("Cost map dimension mismatch".into()));
    }

    let channel_offset = if image.channels >= 3 { 1 } else { 0 };

    // Filter eligible pixels with the identical class-interior condition
    let mut eligible_pixels: Vec<usize> = (0..total_pixels)
        .filter(|&idx| {
            let val = image.pixels[idx * image.channels + channel_offset];
            (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val)
        })
        .collect();

    // Rank pixels by cost: lowest cost first
    eligible_pixels.sort_by(|&a, &b| {
        costs[a]
            .partial_cmp(&costs[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let allowed_count = ((eligible_pixels.len() as f64)
        * (1.0 - params.exclusion_percentile.clamp(0.0, 0.9))) as usize;
    let candidate_pixels = &eligible_pixels[..allowed_count];

    if candidate_pixels.len() < 256 {
        return Err(StrHideError::NoHiddenData(
            "Carrier has insufficient capacity for stego header".into(),
        ));
    }

    // Phase 1: Keyed full candidate set permutation for header slots
    let header_seed = crate::stego::envelope::derive_header_perm_seed(password);
    let mut permuted_candidates = candidate_pixels.to_vec();
    permute_indices(&mut permuted_candidates, &header_seed);

    let header_slots = &permuted_candidates[..256];

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
    let (total_len, raw_codec_id, raw_stc_h) = {
        let word = u32::from_be_bytes([
            header_bytes[28],
            header_bytes[29],
            header_bytes[30],
            header_bytes[31],
        ]);
        let (len, codec_id, stc_h) = decode_header_word(word);
        (len as usize, codec_id, stc_h)
    };

    if !(49..=HEADER_LEN_MAX as usize).contains(&total_len) {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    let no_hidden = || StrHideError::NoHiddenData("No valid payload found".into());

    let (codec, stc_h, stc_u, body_candidates) = if raw_stc_h == HEADER_V2_ESCAPE_H {
        // v2 branch
        if permuted_candidates.len() < V2_TOTAL_HEADER_SLOTS {
            return Err(no_hidden());
        }
        let feature_slots = &permuted_candidates[256..V2_TOTAL_HEADER_SLOTS];
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
        let is_header = {
            let mut v = vec![false; total_pixels];
            for &s in &permuted_candidates[..V2_TOTAL_HEADER_SLOTS] {
                v[s] = true;
            }
            v
        };
        let body_cands: Vec<usize> = if fw.class_rule == 1 {
            candidate_pixels
                .iter()
                .copied()
                .filter(|&s| {
                    let val = image.pixels[s * image.channels + channel_offset];
                    (1..=6).contains(&(val % 8)) && !is_header[s]
                })
                .collect()
        } else {
            candidate_pixels
                .iter()
                .copied()
                .filter(|&s| !is_header[s])
                .collect()
        };
        (fw.codec, fw.h, fw.u, body_cands)
    } else {
        // v1 legacy branch
        let (codec, stc_u) =
            crate::stego::header::codec_from_header_id(raw_codec_id).map_err(|_| no_hidden())?;
        if codec == StegoCodec::Stc {
            crate::stego::coding::validate_stc_h(raw_stc_h).map_err(|_| no_hidden())?;
            crate::stego::coding::validate_stc_u(stc_u).map_err(|_| no_hidden())?;
        }
        let is_header = {
            let mut v = vec![false; total_pixels];
            for &s in header_slots {
                v[s] = true;
            }
            v
        };
        let body_cands: Vec<usize> = candidate_pixels
            .iter()
            .copied()
            .filter(|&s| !is_header[s])
            .collect();
        (codec, raw_stc_h, stc_u, body_cands)
    };

    if !(49..=HEADER_LEN_MAX as usize).contains(&total_len) {
        // Deliberately generic: a wrong secret lands the header on the wrong
        // slots, and a distinct message ("invalid size") would tell an attacker
        // that *an envelope exists here but the layout is wrong*, which is an
        // oracle the AEAD path deliberately does not provide.
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    let ciphertext_len = total_len - 28;
    let ciphertext_bits = ciphertext_len * 8;
    let needed_body_slots = slots_for(ciphertext_bits, codec, stc_h, stc_u)?;

    if needed_body_slots > body_candidates.len() {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    // Phase 2: Keyed permutation of body slots using PBKDF2 salt-derived seed
    let (key_bytes, perm_seed) = crate::stego::envelope::derive_keys(
        password.unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        salt,
    );

    let mut body_slots = body_candidates[..needed_body_slots].to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    let slot_vals: Vec<u8> = body_slots
        .iter()
        .map(|&slot| image.pixels[slot * image.channels + channel_offset])
        .collect();

    let ciphertext_body = match codec {
        StegoCodec::Hamming => hamming_extract_bytes(
            &slot_vals,
            ciphertext_len,
            crate::stego::coding::DEFAULT_HAMMING_K,
        )?,
        StegoCodec::Stc | StegoCodec::Auto => {
            let stc_seed = crate::stego::envelope::derive_stc_seed(&perm_seed, salt);
            let trellis = StcTrellis::from_seed_grouped(stc_seed, stc_h, stc_u)?;
            trellis.extract(&slot_vals, ciphertext_bits)
        }
    };

    let mut full_envelope = Vec::with_capacity(total_len);
    full_envelope.extend_from_slice(&header_bytes[..28]); // Salt + Nonce
    full_envelope.extend_from_slice(&ciphertext_body);

    unpack_envelope_with_key(&full_envelope, &key_bytes)
}

/// Probe capacity of PNG carrier for spatial content-adaptive steganography.
pub fn probe_spatial_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn SpatialCostModel,
    params: &SpatialParams,
) -> Result<StegoCapacityInfo, StrHideError> {
    let image = decode_png(carrier_bytes)?;
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, params);
    if costs.len() != total_pixels {
        return Err(StrHideError::General("Cost map dimension mismatch".into()));
    }

    let channel_offset = if image.channels >= 3 { 1 } else { 0 };
    let mut eligible_pixels: Vec<usize> = (0..total_pixels)
        .filter(|&idx| {
            let val = image.pixels[idx * image.channels + channel_offset];
            (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val)
        })
        .collect();

    eligible_pixels.sort_by(|&a, &b| {
        costs[a]
            .partial_cmp(&costs[b])
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let allowed_count = ((eligible_pixels.len() as f64)
        * (1.0 - params.exclusion_percentile.clamp(0.0, 0.9))) as usize;
    let candidate_pixels = &eligible_pixels[..allowed_count];

    let available_body_slots = if candidate_pixels.len() < V2_TOTAL_HEADER_SLOTS {
        0
    } else {
        let header_seed = crate::stego::envelope::derive_header_perm_seed(None);
        let mut permuted_candidates = candidate_pixels.to_vec();
        permute_indices(&mut permuted_candidates, &header_seed);

        let is_header = {
            let mut v = vec![false; total_pixels];
            for &s in &permuted_candidates[..V2_TOTAL_HEADER_SLOTS] {
                v[s] = true;
            }
            v
        };

        candidate_pixels
            .iter()
            .copied()
            .filter(|&s| {
                let val = image.pixels[s * image.channels + channel_offset];
                (1..=6).contains(&(val % 8)) && !is_header[s]
            })
            .count()
    };
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
    // The recommendation is anchored to the high-stealth regime (r >= 4.5, flips/bit ~0.23,
    // risk spike <= 7.5%), ensuring the payload lands in the clean STC u=3 / Hamming-clean band
    // rather than naive max/2.
    let recommended_max_bytes =
        crate::stego::coding::recommended_payload_bytes(available_body_slots);

    Ok(StegoCapacityInfo {
        format: "PNG".into(),
        algorithm: cost_model.id().into(),
        total_elements: total_pixels,
        available_slots: available_body_slots,
        max_raw_payload_bytes,
        recommended_max_bytes,
        estimated_change_rate: match params.codec {
            StegoCodec::Hamming => crate::stego::coding::expected_change_rate(hamming_k),
            StegoCodec::Stc if params.stc_u > 0 => {
                crate::stego::coding::expected_stc_change_rate(params.stc_u)
            }
            StegoCodec::Stc | StegoCodec::Auto => crate::stego::coding::expected_stc_change_rate(3),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::params::SpatialParams;
    use crate::stego::spatial::cost::HillCostModel;

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
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
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
        let params = SpatialParams::default();
        let stego =
            embed_spatial(&png, payload, Some("pw"), &HillCostModel, &params).expect("embed");
        let extracted =
            extract_spatial(&stego, Some("pw"), &HillCostModel, &params).expect("extract");
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
        let params = SpatialParams {
            codec: StegoCodec::Stc,
            stc_h: 8,
            ..SpatialParams::default()
        };
        let stego =
            embed_spatial(&png, payload, Some("pw"), &HillCostModel, &params).expect("embed");

        // The codec travels in the header, so an extractor configured with Hamming
        // must still read the carrier correctly via header self-description.
        let extract_params = SpatialParams {
            codec: StegoCodec::Hamming,
            ..SpatialParams::default()
        };
        let extracted =
            extract_spatial(&stego, Some("pw"), &HillCostModel, &extract_params).expect("extract");
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
    fn handbuilt_image_without_chunks_still_encodes() {
        let img = RawImage {
            width: 4,
            height: 4,
            channels: 3,
            pixels: vec![10u8; 4 * 4 * 3],
            chunks: Vec::new(),
            idat_sizes: Vec::new(),
            row_filters: Vec::new(),
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
        let params = SpatialParams::default();
        let stego =
            embed_spatial(&png, b"split-idat", Some("pw"), &HillCostModel, &params).expect("embed");
        let after = decode_png(&stego).expect("decode stego");
        assert_eq!(
            after.idat_sizes.len(),
            4,
            "embedding must not collapse the IDAT run"
        );
        let extracted =
            extract_spatial(&stego, Some("pw"), &HillCostModel, &params).expect("extract");
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
            let params = SpatialParams {
                codec: StegoCodec::Stc,
                stc_h: 8,
                stc_u,
                ..SpatialParams::default()
            };
            let stego = embed_spatial(&png, payload, Some("pw"), &HillCostModel, &params)
                .unwrap_or_else(|e| panic!("u={stc_u}: embed failed: {e}"));

            // The extractor still defaults to Hamming: `u` and `h` must arrive
            // through the header.
            let extracted = extract_spatial(
                &stego,
                Some("pw"),
                &HillCostModel,
                &SpatialParams::default(),
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

            let cap =
                probe_spatial_capacity(&png, &HillCostModel, &params).expect("capacity probe");
            capacities.push(cap.max_raw_payload_bytes);
        }

        // Only the large gap is asserted here: the salt is random per embed, so
        // the trellis seed (and therefore the exact change count) differs run
        // to run. u=2 vs u=3 differ by ~6% on this payload, which a single
        // sample cannot resolve -- that comparison lives in the deterministic
        // trellis test (`coding::stc::tests::larger_groups_lower_the_change_rate`).
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

        let auto_params = SpatialParams::default();
        assert_eq!(auto_params.codec, StegoCodec::Auto);

        // Light payload: automatically selects STC u=3
        let light_payload = b"short-auto-payload";
        let stego_light = embed_spatial(
            &png,
            light_payload,
            Some("pw"),
            &HillCostModel,
            &auto_params,
        )
        .expect("embed light");
        let rec_light = extract_spatial(
            &stego_light,
            Some("pw"),
            &HillCostModel,
            &SpatialParams::default(),
        )
        .expect("extract light");
        assert_eq!(rec_light, light_payload);

        // Verify that capacity probe reports recommended bytes anchored to high-stealth
        let cap = probe_spatial_capacity(&png, &HillCostModel, &auto_params).expect("probe");
        assert!(cap.recommended_max_bytes > 0);
        assert!(cap.recommended_max_bytes <= cap.max_raw_payload_bytes / 2);
    }
}
