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
pub struct RawImage {
    pub width: u32,
    pub height: u32,
    pub channels: usize,
    pub pixels: Vec<u8>,
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
            }
            b"IEND" => break,
            _ => {}
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
        out.extend_from_slice(&recon);
        prev = recon;
    }

    Ok(RawImage {
        width,
        height,
        channels,
        pixels: out,
    })
}

/// Encode raw pixels into a valid standard PNG byte stream (filter 0, compressed IDAT).
pub fn encode_png(image: &RawImage) -> Result<Vec<u8>, StrHideError> {
    let mut out = Vec::new();
    // Signature
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    // IHDR chunk
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

    // IDAT chunk with filter 0 prepended to each row
    let stride = image.width as usize * image.channels;
    let mut filtered = Vec::with_capacity((stride + 1) * image.height as usize);
    for row in image.pixels.chunks_exact(stride) {
        filtered.push(0); // Filter 0 (None)
        filtered.extend_from_slice(row);
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&filtered)?;
    let compressed_idat = encoder.finish()?;
    write_chunk(&mut out, b"IDAT", &compressed_idat);

    // IEND chunk
    write_chunk(&mut out, b"IEND", &[]);

    Ok(out)
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
    })
}
