//! PNG container codec: chunk parsing, scanline (de)filtering and re-encoding.
//!
//! This module owns the byte-level container: it decodes a PNG into raw
//! pixels plus the chunk sequence needed to reproduce the file, and re-encodes
//! that representation with only the IDAT run replaced. The embedding engine
//! in [`super::engine`] treats it as a pure codec.

use std::io::{Cursor, Read, Write};

use crc32fast::Hasher as Crc32;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::{Compress, Compression, FlushCompress, Status};
use rayon::prelude::*;

use crate::errors::StrHideError;

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
pub(super) fn choose_deflate_level(
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
pub(super) fn deflate_len(data: &[u8], level: u32) -> usize {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));
    // Writing into a `Vec` cannot fail; the length is all the probe needs.
    if encoder.write_all(data).is_err() {
        return usize::MAX;
    }
    encoder.finish().map(|v| v.len()).unwrap_or(usize::MAX)
}

/// No-op tracer hook using `format_args!` to avoid eager heap allocation.
#[inline(always)]
pub(super) fn trace(_args: std::fmt::Arguments<'_>) {}

/// Apply PNG filter `filter` to one reconstructed scanline (`cur`), given
/// the previous reconstructed row (`prev`). Inverse of the unfilter step in
/// [`decode_png`]; all arithmetic wraps, exactly like the decoder's.
pub(super) fn filter_row(prev: &[u8], cur: &[u8], filter: u8, bpp: usize) -> Vec<u8> {
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

pub(super) fn write_chunk(
    out: &mut Vec<u8>,
    chunk_type: &[u8; 4],
    data: &[u8],
) -> Result<(), StrHideError> {
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
