//! Spatial domain steganographic embedding and extraction engine (PNG).
//!
//! Uses content-adaptive distortion costs (e.g. HILL) to isolate complex texture
//! and noisy regions, completely avoiding smooth areas.
//!
//! # Embedding operation
//!
//! Bits are written by **LSB replacement** (`val & 0xFE | bit`, i.e. `val ^= 1`
//! when the bit differs), *not* LSB matching. This is a deliberate constraint,
//! not an oversight: the extractor rebuilds the slot ranking from a cost map
//! computed on the stego image, so every modification must leave that cost map
//! bit-identical. Replacement keeps `val & 0xFE` invariant, which makes the
//! masked-value cost map reproducible at extraction time; a random `±1` choice
//! (true LSB matching) would change `val & 0xFE` for half of the modified
//! pixels and desynchronise the ranking.
//!
//! Consequence, stated plainly: replacement is the operation that chi-square
//! and sample-pair (SPA) detectors target. Detection resistance here comes only
//! from the low modification rate of content-adaptive placement, never from the
//! modification rule. A true `±1` rule requires first making slot selection
//! independent of the exact cost ordering (e.g. block-level selection), which
//! this engine does not do.

use std::io::{Cursor, Read, Write};

use crc32fast::Hasher as Crc32;
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

use crate::errors::StrHideError;
use crate::stego::StegoCapacityInfo;
use crate::stego::envelope::{pack_envelope, unpack_envelope};
use crate::stego::params::SpatialParams;
use crate::stego::prng::permute_indices;
use crate::stego::traits::SpatialCostModel;

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
    let envelope = pack_envelope(payload, password)?;

    // Compute distortion cost map
    let costs = cost_model.compute_cost(&image.pixels, w, h, image.channels, params);
    if costs.len() != total_pixels {
        return Err(StrHideError::General("Cost map dimension mismatch".into()));
    }

    // Channel to embed in (Green channel for RGB, channel 0 for grayscale/RGBA luminance)
    let channel_offset = if image.channels >= 3 { 1 } else { 0 };

    // Filter eligible pixels: exclude boundary/saturation pixels (0 and 255).
    // In LSB replacement, restricting to [2, 253] ensures:
    // 1. Modified values remain in [2, 253], never hitting 0 or 255.
    // 2. High 7 bits (val & 0xFE) remain in [2, 252], strictly invariant under LSB flips.
    // 3. Extractor generates the identical candidate set without synchronization issues.
    let mut eligible_pixels: Vec<usize> = (0..total_pixels)
        .filter(|&idx| {
            let val = image.pixels[idx * image.channels + channel_offset];
            (2..=253).contains(&val)
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

    if candidate_pixels.len() < 256 {
        return Err(StrHideError::General(format!(
            "Carrier capacity insufficient: available {} slots, minimum header requires 256 slots",
            candidate_pixels.len()
        )));
    }

    // Phase 1: Keyed full candidate set permutation for header slots
    let header_seed = crate::stego::envelope::derive_header_perm_seed(password);
    let mut permuted_candidates = candidate_pixels.to_vec();
    permute_indices(&mut permuted_candidates, &header_seed);

    let header_slots = &permuted_candidates[..256];

    // Body slots must keep HILL's cost ordering. The header takes a keyed
    // random 256 slots out of the candidate set (so the header position is not
    // a public "top-256 cheapest" fingerprint), and the body then uses the
    // cheapest slots that remain `needed_body_slots` of them, in cost order.
    //
    // Selecting the body as `permuted_candidates[256..]` (as an earlier version
    // did) was equivalent to a random subset of the candidate set, which threw
    // away the minimal-distortion premise of HILL: measured at 50% load, the
    // median HILL cost of modified pixels was ~4.3x the cost of the cheapest
    // equivalent slots.
    let is_header = {
        let mut v = vec![false; total_pixels];
        for &s in header_slots {
            v[s] = true;
        }
        v
    };
    let body_candidates: Vec<usize> = candidate_pixels
        .iter()
        .copied()
        .filter(|&s| !is_header[s])
        .collect();

    // Header is 32 bytes = 256 bits: [16B Salt][12B Nonce][4B Total Envelope Len]
    let total_len = envelope.len() as u32;
    let mut header_bytes = Vec::with_capacity(32);
    header_bytes.extend_from_slice(&envelope[..28]); // Salt (16B) + Nonce (12B)
    header_bytes.extend_from_slice(&total_len.to_be_bytes());

    let ciphertext_body = &envelope[28..];
    let ciphertext_bits = ciphertext_body.len() * 8;
    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    let needed_body_slots = crate::stego::coding::required_slots(ciphertext_bits, hamming_k);

    if needed_body_slots > body_candidates.len() {
        return Err(StrHideError::General(format!(
            "Carrier capacity exceeded: needed {} body slots (Hamming k={}), available {} slots (strategy: spatial-{})",
            needed_body_slots,
            hamming_k,
            body_candidates.len(),
            cost_model.id(),
        )));
    }

    // Phase 2: Keyed permutation of body slots using PBKDF2 salt-derived seed
    let salt = &envelope[..16];
    let (_, perm_seed) = crate::stego::envelope::derive_keys(
        password.unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        salt,
    );

    let mut body_slots = body_candidates[..needed_body_slots].to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    // Embed Phase 1: 32-byte header using direct LSB replacement
    for (byte_i, &b) in header_bytes.iter().enumerate() {
        for bit_i in 0..8 {
            let target_bit = (b >> (7 - bit_i)) & 1;
            let slot = header_slots[byte_i * 8 + bit_i];
            let byte_idx = slot * image.channels + channel_offset;
            embed_lsb(&mut image.pixels[byte_idx], target_bit);
        }
    }

    // Embed Phase 2: Ciphertext body using (7, 3) Hamming matrix embedding
    let mut slot_vals: Vec<u8> = body_slots
        .iter()
        .map(|&slot| image.pixels[slot * image.channels + channel_offset])
        .collect();
    let mut slot_refs: Vec<&mut u8> = slot_vals.iter_mut().collect();
    crate::stego::coding::hamming_embed_bytes(&mut slot_refs, ciphertext_body, hamming_k)?;

    for (i, &slot) in body_slots.iter().enumerate() {
        image.pixels[slot * image.channels + channel_offset] = slot_vals[i];
    }

    encode_png(&image)
}

/// Write `target_bit` into the LSB of `val` by replacement.
///
/// `val & 0xFE` is preserved by construction, which is what keeps the HILL cost
/// map (computed on `val & 0xFE`) identical between embed and extract.
fn embed_lsb(val: &mut u8, target_bit: u8) {
    if (*val & 1) != target_bit {
        *val ^= 1;
    }
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

    // Filter eligible pixels with identical boundary condition [2, 253]
    let mut eligible_pixels: Vec<usize> = (0..total_pixels)
        .filter(|&idx| {
            let val = image.pixels[idx * image.channels + channel_offset];
            (2..=253).contains(&val)
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

    // Body slots must keep HILL's cost ordering. The header takes a keyed
    // random 256 slots out of the candidate set (so the header position is not
    // a public "top-256 cheapest" fingerprint), and the body then uses the
    // cheapest slots that remain `needed_body_slots` of them, in cost order.
    //
    // Selecting the body as `permuted_candidates[256..]` (as an earlier version
    // did) was equivalent to a random subset of the candidate set, which threw
    // away the minimal-distortion premise of HILL: measured at 50% load, the
    // median HILL cost of modified pixels was ~4.3x the cost of the cheapest
    // equivalent slots.
    let is_header = {
        let mut v = vec![false; total_pixels];
        for &s in header_slots {
            v[s] = true;
        }
        v
    };
    let body_candidates: Vec<usize> = candidate_pixels
        .iter()
        .copied()
        .filter(|&s| !is_header[s])
        .collect();

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
    let total_len = u32::from_be_bytes([
        header_bytes[28],
        header_bytes[29],
        header_bytes[30],
        header_bytes[31],
    ]) as usize;

    if !(49..=64 * 1024 * 1024).contains(&total_len) {
        // Deliberately generic: a wrong secret lands the header on the wrong
        // slots, and a distinct message ("invalid size") would tell an attacker
        // that *an envelope exists here but the layout is wrong*, which is an
        // oracle the AEAD path deliberately does not provide.
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    let ciphertext_len = total_len - 28;
    let ciphertext_bits = ciphertext_len * 8;
    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    let needed_body_slots = crate::stego::coding::required_slots(ciphertext_bits, hamming_k);

    if needed_body_slots > body_candidates.len() {
        return Err(StrHideError::NoHiddenData("No valid payload found".into()));
    }

    // Phase 2: Keyed permutation of body slots using PBKDF2 salt-derived seed
    let (_, perm_seed) = crate::stego::envelope::derive_keys(
        password.unwrap_or(crate::stego::envelope::PUBLIC_DEFAULT_SECRET),
        salt,
    );

    let mut body_slots = body_candidates[..needed_body_slots].to_vec();
    permute_indices(&mut body_slots, &perm_seed);

    let slot_vals: Vec<u8> = body_slots
        .iter()
        .map(|&slot| image.pixels[slot * image.channels + channel_offset])
        .collect();

    let ciphertext_body =
        crate::stego::coding::hamming_extract_bytes(&slot_vals, ciphertext_len, hamming_k)?;

    let mut full_envelope = Vec::with_capacity(total_len);
    full_envelope.extend_from_slice(&header_bytes[..28]); // Salt + Nonce
    full_envelope.extend_from_slice(&ciphertext_body);

    unpack_envelope(&full_envelope, password)
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
    let eligible_count = (0..total_pixels)
        .filter(|&idx| {
            let val = image.pixels[idx * image.channels + channel_offset];
            (2..=253).contains(&val)
        })
        .count();

    let allowed_count =
        ((eligible_count as f64) * (1.0 - params.exclusion_percentile.clamp(0.0, 0.9))) as usize;

    let header_slots = 256;
    let available_body_slots = allowed_count.saturating_sub(header_slots);
    let hamming_k = crate::stego::coding::DEFAULT_HAMMING_K;
    let max_ciphertext_bytes =
        crate::stego::coding::max_payload_bytes(available_body_slots, hamming_k);
    // Only the body-borne overhead comes off here: salt/nonce already paid for
    // by the 256 header slots. Subtracting MIN_ENVELOPE_LEN under-reported the
    // capacity by exactly 28 bytes (measured on real carriers).
    let max_raw_payload_bytes =
        max_ciphertext_bytes.saturating_sub(crate::stego::envelope::BODY_OVERHEAD);
    let recommended_max_bytes = max_raw_payload_bytes / 2;

    Ok(StegoCapacityInfo {
        format: "PNG".into(),
        algorithm: cost_model.id().into(),
        total_elements: total_pixels,
        available_slots: available_body_slots,
        max_raw_payload_bytes,
        recommended_max_bytes,
        estimated_change_rate: crate::stego::coding::expected_change_rate(hamming_k),
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
            assert!(a ^ b <= 1, "only LSBs may change: {a} -> {b}");
        }
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
}
