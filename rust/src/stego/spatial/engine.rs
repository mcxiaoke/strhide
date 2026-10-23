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
use crate::stego::envelope::{
    build_plaintext, encrypt_with_aad, random_nonce, random_salt, unpack_envelope_parts,
};
use crate::stego::format::{body_keys, derive_master};
pub use crate::stego::header::{
    FeatureWord, HEADER_LEN_MASK, HEADER_LEN_MAX, HEADER_V2_ESCAPE_H, V2_TOTAL_HEADER_SLOTS,
    decode_header_word, encode_header_word,
};
use crate::stego::prng::{permute_indices, permute_prefix};
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
// Slot plan: the single source of truth for "which pixels carry what"
// ---------------------------------------------------------------------------

/// Slots reserved for the 32-byte base header (salt | nonce | length word).
const HEADER_SLOTS: usize = 256;

/// Channel the spatial codec writes into: green for colour images (least
/// visible), channel 0 for grayscale / gray+alpha.
fn embed_channel(image: &RawImage) -> usize {
    if image.channels >= 3 { 1 } else { 0 }
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
    /// Cost-ranked candidates after the smooth-pixel exclusion, in ranking order.
    candidates: Vec<usize>,
    /// `candidates` in keyed header order; the first 512 entries are the header
    /// (256) and feature-word (256) slots.
    permuted: Vec<usize>,
    /// `used_by_header[px]`: the pixel is one of those 512 slots.
    used_by_header: Vec<bool>,
}

impl SlotPlan {
    /// Rank the candidates and apply the keyed header permutation.
    ///
    /// `password` / `domain` key the permutation, so they must be the
    /// credentials the embedder will use — they change which pixels the header
    /// occupies and therefore the body capacity.
    fn build(
        image: &RawImage,
        costs: &[f64],
        params: &SpatialParams,
        password: Option<&str>,
        domain: Option<&str>,
        spatial: &crate::stego::format::SpatialFormatProfile,
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
        let mut candidates: Vec<usize> = (0..total_pixels)
            .filter(|&idx| {
                let val = image.pixels[idx * image.channels + channel_offset];
                (SPATIAL_ELIGIBLE_MIN..=SPATIAL_ELIGIBLE_MAX).contains(&val)
            })
            .collect();

        // Rank pixels by cost: lowest cost (most complex/noisy) first
        candidates.sort_by(|&a, &b| {
            costs[a]
                .partial_cmp(&costs[b])
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Exclude the smoothest fraction (e.g. 30%)
        let allowed_count = ((candidates.len() as f64)
            * (1.0 - params.exclusion_percentile.clamp(0.0, 0.9)))
            as usize;
        candidates.truncate(allowed_count);

        // Keyed candidate-set permutation for the header slots (legacy rule:
        // [8, 247] eligibility, 30% exclusion).
        let header_seed =
            crate::stego::envelope::derive_header_perm_seed_with_profile(password, domain, spatial);
        let mut permuted = candidates.clone();
        permute_prefix(&mut permuted, V2_TOTAL_HEADER_SLOTS, &header_seed);

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

    /// Pixels left for the payload body: candidates outside the header set,
    /// further restricted by the wire `class_rule`.
    ///
    /// Under the safe non-boundary rule (`class_rule == 1`) only `val % 8` in
    /// [1, 6] may move, which eliminates the r=0/7 boundary deficit (P0-B).
    fn body_candidates(&self, image: &RawImage, class_rule: u8) -> Vec<usize> {
        let channel_offset = embed_channel(image);
        self.candidates
            .iter()
            .copied()
            .filter(|&s| !self.used_by_header[s])
            .filter(|&s| {
                if class_rule != 1 {
                    return true;
                }
                let val = image.pixels[s * image.channels + channel_offset];
                (1..=6).contains(&(val % 8))
            })
            .collect()
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
    domain: Option<&str>,
    cost_model: &dyn SpatialCostModel,
    params: &SpatialParams,
) -> Result<Vec<u8>, StrHideError> {
    embed_spatial_with_profile(
        carrier_bytes,
        payload,
        password,
        domain,
        &crate::stego::format::OFFICIAL_SPATIAL,
        cost_model,
        params,
    )
}

/// [`embed_spatial`] with an explicit [`SpatialFormatProfile`].
pub fn embed_spatial_with_profile(
    carrier_bytes: &[u8],
    payload: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::SpatialFormatProfile,
    cost_model: &dyn SpatialCostModel,
    params: &SpatialParams,
) -> Result<Vec<u8>, StrHideError> {
    let mut image = decode_png(carrier_bytes)?;
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    // Frame the payload and derive the per-carrier keys. The ciphertext itself
    // is produced further down: the finished 64-byte header is its associated
    // data, so it cannot exist until codec/h/u are settled.
    let suite = spatial.body.default_suite();
    let plaintext = build_plaintext(payload)?;
    let salt = random_salt();
    let nonce = random_nonce();
    let master = derive_master(suite, password.unwrap_or(spatial.fallback_secret), &salt)?;
    let (enc_key, perm_seed) = body_keys(spatial.body, &master, &salt, domain);
    let ciphertext_len = plaintext.len() + suite.tag_len();

    // Compute distortion cost map
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, params);

    let channel_offset = embed_channel(&image);

    let plan = SlotPlan::build(&image, &costs, params, password, domain, spatial)?;
    if !plan.header_fits() {
        return Err(StrHideError::General(format!(
            "Carrier capacity insufficient: available {} slots, minimum header requires {} slots",
            plan.permuted.len(),
            V2_TOTAL_HEADER_SLOTS
        )));
    }
    let header_slots = plan.header_slots();
    let feature_slots = plan.feature_slots();
    let body_candidates = plan.body_candidates(&image, 1);

    let ciphertext_bits = ciphertext_len * 8;

    // Safety enforcement policy check
    if params.safety_enforcement == crate::stego::params::SafetyEnforcement::Enforced {
        let bpp_limit = params.safety_level.bpp_limit();
        let bpp_bits = (total_pixels as f64 * bpp_limit).floor() as usize;
        let ratio_bits =
            (body_candidates.len() as f64 / params.safety_level.target_ratio()).floor() as usize;
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
                params.safety_level.as_str(),
            )));
        }
    }

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

    let needed_body_slots = crate::stego::coding::slots_for_codec(
        ciphertext_bits,
        resolved_codec,
        params.stc_h,
        resolved_u,
    )?;

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
                &ciphertext_body,
                crate::stego::coding::DEFAULT_HAMMING_K,
            )?;
        }
        StegoCodec::Stc | StegoCodec::Auto => {
            let trellis = StcTrellis::from_seed_grouped(stc_seed, params.stc_h, resolved_u)?;
            trellis.embed(&mut slot_vals, &moves, &rp, &rm, &ciphertext_body)?;
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
    domain: Option<&str>,
    cost_model: &dyn SpatialCostModel,
    params: &SpatialParams,
) -> Result<Vec<u8>, StrHideError> {
    extract_spatial_with_profile(
        carrier_bytes,
        password,
        domain,
        &crate::stego::format::OFFICIAL_SPATIAL,
        cost_model,
        params,
    )
}

/// [`extract_spatial`] with an explicit [`SpatialFormatProfile`].
pub fn extract_spatial_with_profile(
    carrier_bytes: &[u8],
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::SpatialFormatProfile,
    cost_model: &dyn SpatialCostModel,
    params: &SpatialParams,
) -> Result<Vec<u8>, StrHideError> {
    let image = decode_png(carrier_bytes)?;
    let w = image.width as usize;
    let h = image.height as usize;

    // Compute distortion cost map (identical to embedding)
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, params);

    let channel_offset = embed_channel(&image);

    // The header permutation must be the one the embedder used: same password,
    // same domain, same ranking rule.
    let plan = SlotPlan::build(&image, &costs, params, password, domain, spatial)?;
    if plan.permuted.len() < HEADER_SLOTS {
        return Err(StrHideError::NoHiddenData(
            "Carrier has insufficient capacity for stego header".into(),
        ));
    }
    let header_slots = plan.header_slots();

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
    if raw_stc_h != HEADER_V2_ESCAPE_H || !plan.header_fits() {
        return Err(no_hidden());
    }

    let feature_slots = plan.feature_slots();
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
    let body_candidates = plan.body_candidates(&image, fw.class_rule);

    let ciphertext_len = total_len - crate::stego::envelope::HEADER_OVERHEAD;
    let ciphertext_bits = ciphertext_len * 8;
    let needed_body_slots =
        crate::stego::coding::slots_for_codec(ciphertext_bits, fw.codec, fw.h, fw.u)?;
    if needed_body_slots > body_candidates.len() {
        return Err(no_hidden());
    }

    let master = derive_master(
        spatial.body.default_suite(),
        password.unwrap_or(spatial.fallback_secret),
        salt,
    )?;
    let (enc_key, perm_seed) = body_keys(spatial.body, &master, salt, domain);

    let mut body_slots = body_candidates[..needed_body_slots].to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    let slot_vals: Vec<u8> = body_slots
        .iter()
        .map(|&slot| image.pixels[slot * image.channels + channel_offset])
        .collect();

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

/// Probe capacity of PNG carrier for spatial content-adaptive steganography.
pub fn probe_spatial_capacity(
    carrier_bytes: &[u8],
    cost_model: &dyn SpatialCostModel,
    params: &SpatialParams,
    safety_level: crate::stego::SafetyLevel,
    password: Option<&str>,
    domain: Option<&str>,
) -> Result<StegoCapacityInfo, StrHideError> {
    probe_spatial_capacity_with_profile(
        carrier_bytes,
        cost_model,
        params,
        safety_level,
        password,
        domain,
        &crate::stego::format::OFFICIAL_SPATIAL,
    )
}

/// [`probe_spatial_capacity`] with an explicit [`SpatialFormatProfile`].
pub fn probe_spatial_capacity_with_profile(
    carrier_bytes: &[u8],
    cost_model: &dyn SpatialCostModel,
    params: &SpatialParams,
    safety_level: crate::stego::SafetyLevel,
    password: Option<&str>,
    domain: Option<&str>,
    spatial: &crate::stego::format::SpatialFormatProfile,
) -> Result<StegoCapacityInfo, StrHideError> {
    let image = decode_png(carrier_bytes)?;
    let w = image.width as usize;
    let h = image.height as usize;
    let total_pixels = w * h;

    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, params);

    let plan = SlotPlan::build(&image, &costs, params, password, domain, spatial)?;

    let available_body_slots = if plan.header_fits() {
        // The embedder always writes `class_rule = 1`, so the capacity it can
        // actually reach is the rule-1 body pool.
        plan.body_candidates(&image, 1).len()
    } else {
        0
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

    // Recommended capacity bounded by safety tier bpp budget and candidate slot ratio r
    let bpp_bits = (total_pixels as f64 * safety_level.bpp_limit()).floor() as usize;
    let ratio_bits = (available_body_slots as f64 / safety_level.target_ratio()).floor() as usize;
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
            embed_spatial(&png, payload, Some("pw"), None, &HillCostModel, &params).expect("embed");
        let extracted =
            extract_spatial(&stego, Some("pw"), None, &HillCostModel, &params).expect("extract");
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
            embed_spatial(&png, payload, Some("pw"), None, &HillCostModel, &params).expect("embed");

        // The codec travels in the header, so an extractor configured with Hamming
        // must still read the carrier correctly via header self-description.
        let extract_params = SpatialParams {
            codec: StegoCodec::Hamming,
            ..SpatialParams::default()
        };
        let extracted = extract_spatial(&stego, Some("pw"), None, &HillCostModel, &extract_params)
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
        let stego = embed_spatial(
            &png,
            b"split-idat",
            Some("pw"),
            None,
            &HillCostModel,
            &params,
        )
        .expect("embed");
        let after = decode_png(&stego).expect("decode stego");
        assert_eq!(
            after.idat_sizes.len(),
            4,
            "embedding must not collapse the IDAT run"
        );
        let extracted =
            extract_spatial(&stego, Some("pw"), None, &HillCostModel, &params).expect("extract");
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
            let stego = embed_spatial(&png, payload, Some("pw"), None, &HillCostModel, &params)
                .unwrap_or_else(|e| panic!("u={stc_u}: embed failed: {e}"));

            // The extractor still defaults to Hamming: `u` and `h` must arrive
            // through the header.
            let extracted = extract_spatial(
                &stego,
                Some("pw"),
                None,
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

            let cap = probe_spatial_capacity(
                &png,
                &HillCostModel,
                &params,
                crate::stego::SafetyLevel::High,
                Some("pw"),
                None,
            )
            .expect("capacity probe");
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
            None,
            &HillCostModel,
            &auto_params,
        )
        .expect("embed light");
        let rec_light = extract_spatial(
            &stego_light,
            Some("pw"),
            None,
            &HillCostModel,
            &SpatialParams::default(),
        )
        .expect("extract light");
        assert_eq!(rec_light, light_payload);

        // Verify that capacity probe reports recommended bytes anchored to high-stealth
        let cap = probe_spatial_capacity(
            &png,
            &HillCostModel,
            &auto_params,
            auto_params.safety_level,
            Some("pw"),
            None,
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
        let params = SpatialParams::default();

        for password in [None, Some("pw"), Some("a-completely-different-password")] {
            let cap = probe_spatial_capacity(
                &png,
                &HillCostModel,
                &params,
                crate::stego::SafetyLevel::Balanced,
                password,
                None,
            )
            .expect("probe");
            assert!(cap.max_raw_payload_bytes > 0);
            let payload = vec![0x5Au8; cap.max_raw_payload_bytes];
            embed_spatial(&png, &payload, password, None, &HillCostModel, &params).unwrap_or_else(
                |e| {
                    panic!(
                        "password {password:?}: probe reported {} bytes fit but embed failed: {e}",
                        payload.len()
                    )
                },
            );
        }
    }

    #[test]
    fn spatial_stego_domain_isolation_e2e() {
        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);

        let params = SpatialParams::default();
        let payload = b"cross-domain-isolation-test";

        // Embed under domain "finance.sec"
        let stego = embed_spatial(
            &png,
            payload,
            Some("shared-pwd"),
            Some("finance.sec"),
            &HillCostModel,
            &params,
        )
        .expect("embed with domain");

        // Extract with matching domain succeeds
        let recovered = extract_spatial(
            &stego,
            Some("shared-pwd"),
            Some("finance.sec"),
            &HillCostModel,
            &params,
        )
        .expect("extract with same domain");
        assert_eq!(recovered, payload);

        // Extract with default domain (None) fails
        let err_default =
            extract_spatial(&stego, Some("shared-pwd"), None, &HillCostModel, &params);
        assert!(
            matches!(err_default, Err(StrHideError::NoHiddenData(_))),
            "extracting with default domain must fail as NoHiddenData"
        );

        // Extract with different domain fails
        let err_other = extract_spatial(
            &stego,
            Some("shared-pwd"),
            Some("hr.records"),
            &HillCostModel,
            &params,
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

        let cap_paranoid = probe_spatial_capacity(
            &png,
            &HillCostModel,
            &SpatialParams::default(),
            SafetyLevel::Paranoid,
            Some("test-pw"),
            None,
        )
        .expect("probe paranoid");
        let cap_high = probe_spatial_capacity(
            &png,
            &HillCostModel,
            &SpatialParams::default(),
            SafetyLevel::High,
            Some("test-pw"),
            None,
        )
        .expect("probe high");
        let cap_balanced = probe_spatial_capacity(
            &png,
            &HillCostModel,
            &SpatialParams::default(),
            SafetyLevel::Balanced,
            Some("test-pw"),
            None,
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

        // Test enforcement
        let mut enforced_params = SpatialParams {
            safety_level: SafetyLevel::Paranoid,
            safety_enforcement: SafetyEnforcement::Enforced,
            ..SpatialParams::default()
        };

        // Oversize for Paranoid
        let large_payload = vec![0x42; cap_balanced.recommended_max_bytes];
        let res = embed_spatial(
            &png,
            &large_payload,
            Some("test-pw"),
            None,
            &HillCostModel,
            &enforced_params,
        );
        assert!(
            res.is_err(),
            "Enforced safety policy must reject oversized payload"
        );

        // Same payload with Advisory succeeds
        enforced_params.safety_enforcement = SafetyEnforcement::Advisory;
        let ok_res = embed_spatial(
            &png,
            &large_payload,
            Some("test-pw"),
            None,
            &HillCostModel,
            &enforced_params,
        );
        assert!(
            ok_res.is_ok(),
            "Advisory safety policy must not block embedding"
        );
    }

    #[test]
    fn private_spatial_profile_bidirectional_isolation() {
        let (w, h) = (128usize, 128usize);
        let pixels = row_correlated_pixels(w, h);
        let png = craft_png(w as u32, h as u32, &pixels, &vec![2u8; h], &[], 1);
        let payload = b"private-spatial-dialect-content-2026";
        let params = SpatialParams::default();

        let private_spatial = crate::stego::format::SpatialFormatProfile {
            fallback_secret: "private-secret-key-12345",
            domain_label: b"private-domain-label",
            hpos_salt: b"private-hpos-salt-xyz",
            hpos_label: b"private-hpos-label-xyz",
            stc_label: b"private-stc-label-xyz",
            body: &crate::stego::format::DEFAULT_FORMAT,
        };

        // 1. Embed with private dialect
        let stego_bytes = embed_spatial_with_profile(
            &png,
            payload,
            None,
            None,
            &private_spatial,
            &HillCostModel,
            &params,
        )
        .expect("embed with private profile");

        // 2. Extract with same private dialect -> Success
        let extracted = extract_spatial_with_profile(
            &stego_bytes,
            None,
            None,
            &private_spatial,
            &HillCostModel,
            &params,
        )
        .expect("extract with matching private profile");
        assert_eq!(extracted, payload);

        // 3. Extract with official dialect -> Fail with NoHiddenData
        let official_err = extract_spatial(&stego_bytes, None, None, &HillCostModel, &params);
        assert!(
            matches!(official_err, Err(StrHideError::NoHiddenData(_))),
            "official reader must see private stego as NoHiddenData, got {official_err:?}"
        );

        // 4. Official embed read by private reader -> Fail
        let official_stego = embed_spatial(&png, payload, None, None, &HillCostModel, &params)
            .expect("official embed");

        let private_err = extract_spatial_with_profile(
            &official_stego,
            None,
            None,
            &private_spatial,
            &HillCostModel,
            &params,
        );
        assert!(
            matches!(private_err, Err(StrHideError::NoHiddenData(_))),
            "private reader must see official stego as NoHiddenData, got {private_err:?}"
        );
    }
}
