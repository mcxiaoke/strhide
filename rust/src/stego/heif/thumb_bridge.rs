#![cfg(feature = "content-heif-bridge")]

//! Content-domain bridge steganography for HEIF/HEIC containers.
//!
//! Bridges embedded JPEG thumbnails or uncompressed auxiliary items within ISO BMFF containers
//! to existing content-adaptive steganography engines (`stego::jpeg` and `stego::png`).
//!
//! The primary HEVC/AVIF photo stream remains 100% bit-exact and untouched.

use std::convert::TryInto;

use crate::core::control::Control;
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::StegoCapacityInfo;
use crate::stego::jpeg;
use crate::stego::options::{BridgeOptions, StegoTuning};
use crate::stego::params::ExtractParams;
use crate::stego::png;

/// Kind of bridge carrier target located in the HEIF container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeTargetKind {
    /// Independent item with `item_type == b"jpeg"`.
    DirectJpeg { item_id: u32 },
    /// Independent item with `item_type == b"unci"` (uncompressed spatial item).
    DirectSpatial { item_id: u32 },
    /// Embedded JPEG stream within an Exif metadata item.
    ExifJpeg {
        exif_item_id: u32,
        /// File offset of the TIFF Tag 0x0202 (JPEGInterchangeFormatLength) value field, if present.
        tag_0202_file_offset: Option<usize>,
        /// Is the TIFF header little-endian (true) or big-endian (false).
        is_little_endian: bool,
    },
    /// Direct container-level JPEG fallback.
    ContainerJpegFallback,
}

/// A located bridge carrier target with its byte range in the HEIF file.
#[derive(Debug, Clone)]
pub struct BridgeTarget {
    pub kind: BridgeTargetKind,
    pub file_offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone)]
struct IsobmffExtent {
    offset: u64,
    offset_pos: usize,
    offset_sz: usize,
    length: u64,
    length_pos: usize,
    length_sz: usize,
}

#[derive(Debug, Clone)]
struct IsobmffItem {
    item_id: u32,
    item_type: [u8; 4],
    construction_method: u8,
    base_offset: u64,
    base_offset_pos: usize,
    base_offset_sz: usize,
    extents: Vec<IsobmffExtent>,
}

#[derive(Debug, Clone)]
struct IsobmffMeta {
    items: Vec<IsobmffItem>,
    top_boxes: Vec<(usize, usize, [u8; 4])>, // (offset, size, fourcc)
    /// `pitm` primary item id, when the file declares one. The bridge must
    /// never rewrite the primary image (module contract: it stays bit-exact).
    primary_item_id: Option<u32>,
    /// Item ids referenced as thumbnails (`iref` boxes of type `thmb`). When
    /// present these are the preferred bridge targets.
    thumbnail_ids: Vec<u32>,
}

/// Embed payload into an embedded JPEG or uncompressed carrier within a HEIF container.
pub fn embed_heif_bridge<'a>(
    carrier_bytes: &[u8],
    payload: impl Into<Payload<'a>>,
    bridge: &BridgeOptions<'_>,
    control: &Control<'_>,
) -> Result<Vec<u8>, StrHideError> {
    let payload = payload.into();
    let target = find_bridge_target(carrier_bytes)?;
    let carrier_slice = &carrier_bytes[target.file_offset..target.file_offset + target.length];
    let tuning = bridge.tuning.resolve();

    let mut jpeg_params = tuning.jpeg_params.clone();
    jpeg_params.deterministic = bridge.freshness.is_seeded();
    let secret = bridge.resolved_secret(bridge.dialect);
    let domain = bridge.resolved_domain(bridge.dialect);

    let anon_payload;
    let eff_payload = if bridge.no_filename && payload.name().is_some() {
        anon_payload = Payload::bytes(payload.as_bytes());
        &anon_payload
    } else {
        &payload
    };

    match target.kind {
        BridgeTargetKind::DirectJpeg { .. }
        | BridgeTargetKind::ExifJpeg { .. }
        | BridgeTargetKind::ContainerJpegFallback => {
            let stego_bytes = jpeg::embed_jpeg(
                carrier_slice,
                eff_payload,
                secret,
                domain,
                bridge.dialect.jpeg_format(),
                &jpeg_params,
                bridge.safety,
                &*tuning.jpeg_model,
                bridge.freshness,
                control,
            )?;
            reconstruct_heif(carrier_bytes, &target, &stego_bytes)
        }
        BridgeTargetKind::DirectSpatial { .. } => {
            let stego_bytes = png::embed_png(
                carrier_slice,
                eff_payload,
                secret,
                domain,
                bridge.dialect.png_format(),
                &*tuning.png_model,
                &tuning.png_params,
                bridge.safety,
                bridge.freshness,
                control,
            )?;
            reconstruct_heif(carrier_bytes, &target, &stego_bytes)
        }
    }
}

/// Extract payload from an embedded JPEG or uncompressed carrier within a HEIF container.
///
/// `limits` is the read-side policy (which suites to try, how much KDF work to
/// allow). It is not part of [`BridgeOptions`] because nothing on the write side
/// has an equivalent.
pub fn extract_heif_bridge(
    carrier_bytes: &[u8],
    bridge: &BridgeOptions<'_>,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let target = match find_bridge_target(carrier_bytes) {
        Ok(t) => t,
        Err(_) => {
            return Err(StrHideError::NoHiddenData(
                "No bridgeable carrier found in HEIF container".into(),
            ));
        }
    };
    let carrier_slice = &carrier_bytes[target.file_offset..target.file_offset + target.length];
    // The carrier is self-describing, so the read path always resolves the
    // default tuning; `BridgeOptions::tuning` only shapes what is written.
    let tuning = StegoTuning::Auto.resolve();
    let secret = bridge.resolved_secret(bridge.dialect);
    let domain = bridge.resolved_domain(bridge.dialect);

    match target.kind {
        BridgeTargetKind::DirectJpeg { .. }
        | BridgeTargetKind::ExifJpeg { .. }
        | BridgeTargetKind::ContainerJpegFallback => jpeg::extract_jpeg(
            carrier_slice,
            secret,
            domain,
            bridge.dialect.jpeg_format(),
            limits,
            control,
        ),
        BridgeTargetKind::DirectSpatial { .. } => png::extract_png(
            carrier_slice,
            secret,
            domain,
            bridge.dialect.png_format(),
            &*tuning.png_model,
            &tuning.png_params,
            control,
        ),
    }
}

/// Probe capacity of the bridgeable carrier within a HEIF container.
pub fn probe_heif_bridge_capacity(
    carrier_bytes: &[u8],
    bridge: &BridgeOptions<'_>,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    let target = find_bridge_target(carrier_bytes)?;
    let carrier_slice = &carrier_bytes[target.file_offset..target.file_offset + target.length];
    let tuning = bridge.tuning.resolve();
    let secret = bridge.resolved_secret(bridge.dialect);
    let domain = bridge.resolved_domain(bridge.dialect);

    match target.kind {
        BridgeTargetKind::DirectJpeg { .. }
        | BridgeTargetKind::ExifJpeg { .. }
        | BridgeTargetKind::ContainerJpegFallback => {
            let mut info = jpeg::probe_jpeg_capacity(
                carrier_slice,
                &*tuning.jpeg_model,
                &tuning.jpeg_params,
                bridge.safety.level,
                bridge.dialect.jpeg_format(),
                control,
            )?;
            info.format = "HEIF (JPEG Thumbnail Bridge)".into();
            Ok(info)
        }
        BridgeTargetKind::DirectSpatial { .. } => {
            let mut info = png::probe_png_capacity(
                carrier_slice,
                &*tuning.png_model,
                &tuning.png_params,
                bridge.safety.level,
                secret,
                domain,
                bridge.dialect.png_format(),
                control,
            )?;
            info.format = "HEIF (Uncompressed Item Bridge)".into();
            Ok(info)
        }
    }
}

/// Reconstruct the HEIF container with modified carrier bytes and patch iloc / mdat offsets.
fn reconstruct_heif(
    original: &[u8],
    target: &BridgeTarget,
    new_carrier: &[u8],
) -> Result<Vec<u8>, StrHideError> {
    let delta = (new_carrier.len() as i64) - (target.length as i64);

    if delta == 0 {
        let mut out = original.to_vec();
        out[target.file_offset..target.file_offset + target.length].copy_from_slice(new_carrier);
        return Ok(out);
    }

    // Assemble new byte buffer
    let mut out = Vec::with_capacity((original.len() as i64 + delta) as usize);
    out.extend_from_slice(&original[..target.file_offset]);
    out.extend_from_slice(new_carrier);
    out.extend_from_slice(&original[target.file_offset + target.length..]);

    // 1. If Exif TIFF Tag 0x0202 is present, patch its 4-byte value
    if let BridgeTargetKind::ExifJpeg {
        tag_0202_file_offset: Some(tag_pos),
        is_little_endian,
        ..
    } = target.kind
    {
        // Tag pos is within the Exif header, before the modified JPEG content
        if tag_pos + 4 <= out.len() && tag_pos < target.file_offset {
            let new_len_u32 = new_carrier.len() as u32;
            let val_bytes = if is_little_endian {
                new_len_u32.to_le_bytes()
            } else {
                new_len_u32.to_be_bytes()
            };
            out[tag_pos..tag_pos + 4].copy_from_slice(&val_bytes);
        }
    }

    // 2. Parse ISOBMFF meta and patch iloc and top boxes
    let isobmff = parse_isobmff(original)?;

    let target_end_orig = (target.file_offset + target.length) as u64;
    let target_start = target.file_offset as u64;

    // The extent that physically contains the replaced region: only its
    // declared length may change, by exactly one delta. The old code patched
    // *every* extent of the target item (adding delta N times on multi-extent
    // items) and never identified a host item for the container fallback,
    // leaving its iloc length stale while the bytes had already moved
    // (audit 2026-10-24 5.2, review 2026-10-25 M9).

    for item in &isobmff.items {
        // Is this the item containing the target?
        let is_target_item = match target.kind {
            BridgeTargetKind::DirectJpeg { item_id } => item.item_id == item_id,
            BridgeTargetKind::DirectSpatial { item_id } => item.item_id == item_id,
            BridgeTargetKind::ExifJpeg { exif_item_id, .. } => item.item_id == exif_item_id,
            // The container fallback has no item id: the host is whatever
            // file-offset item's extent physically covers the target region.
            BridgeTargetKind::ContainerJpegFallback => {
                host_extent(item, target_start, target_end_orig).is_some()
            }
        };

        if is_target_item {
            let Some(host) = host_extent(item, target_start, target_end_orig) else {
                return Err(StrHideError::Rejection(format!(
                    "bridge target at offset {} is not covered by a single file-offset \
                     extent of item {}",
                    target.file_offset, item.item_id
                )));
            };
            if host.length_sz > 0 && host.length_pos + host.length_sz <= out.len() {
                let new_extent_len = ((host.length as i64) + delta).max(0) as u64;
                patch_uint(&mut out, host.length_pos, host.length_sz, new_extent_len)?;
            }
            // The host item's own later extents move with the shift, exactly
            // like other items' extents do below.
            for ext in &item.extents {
                if ext.offset_pos == host.offset_pos && ext.length_pos == host.length_pos {
                    continue;
                }
                let abs_off = item.base_offset.saturating_add(ext.offset);
                if abs_off >= target_end_orig && ext.offset_sz > 0 {
                    let new_ext_off = ((ext.offset as i64) + delta).max(0) as u64;
                    patch_uint(&mut out, ext.offset_pos, ext.offset_sz, new_ext_off)?;
                }
            }
        } else if item.construction_method == 0 {
            // Check if item or extents fall after the modified region
            if item.base_offset_sz > 0 && item.base_offset >= target_end_orig {
                let new_base = ((item.base_offset as i64) + delta).max(0) as u64;
                patch_uint(
                    &mut out,
                    item.base_offset_pos,
                    item.base_offset_sz,
                    new_base,
                )?;
            } else {
                for ext in &item.extents {
                    let abs_off = item.base_offset + ext.offset;
                    if abs_off >= target_end_orig && ext.offset_sz > 0 {
                        let new_ext_off = ((ext.offset as i64) + delta).max(0) as u64;
                        patch_uint(&mut out, ext.offset_pos, ext.offset_sz, new_ext_off)?;
                    }
                }
            }
        }
    }

    // 3. Patch top-level box sizes (e.g. mdat containing the modified region)
    for &(box_off, box_sz, _box_fcc) in &isobmff.top_boxes {
        let box_end = box_off + box_sz;
        if box_off <= target.file_offset && target.file_offset < box_end && box_sz >= 8 {
            let new_box_sz = ((box_sz as i64) + delta).max(0) as usize;
            let sz_32 = u32::from_be_bytes(original[box_off..box_off + 4].try_into().unwrap());
            if sz_32 == 1 && box_sz >= 16 {
                // 64-bit large box
                let new_sz_u64 = new_box_sz as u64;
                out[box_off + 8..box_off + 16].copy_from_slice(&new_sz_u64.to_be_bytes());
            } else if sz_32 > 0 {
                // 32-bit box
                let new_sz_u32 = new_box_sz as u32;
                out[box_off..box_off + 4].copy_from_slice(&new_sz_u32.to_be_bytes());
            }
        }
    }

    Ok(out)
}

/// The extent of `item` (file-offset construction only) that physically
/// contains `[target_start, target_end)`.
fn host_extent(item: &IsobmffItem, target_start: u64, target_end: u64) -> Option<&IsobmffExtent> {
    if item.construction_method != 0 {
        return None;
    }
    item.extents.iter().find(|e| {
        let start = item.base_offset.saturating_add(e.offset);
        start <= target_start && target_end <= start.saturating_add(e.length)
    })
}

fn patch_uint(buf: &mut [u8], pos: usize, size: usize, val: u64) -> Result<(), StrHideError> {
    if pos + size > buf.len() {
        return Err(StrHideError::CorruptedData(
            "Out of bounds patch in iloc".into(),
        ));
    }
    match size {
        1 => buf[pos] = val as u8,
        2 => buf[pos..pos + 2].copy_from_slice(&(val as u16).to_be_bytes()),
        4 => buf[pos..pos + 4].copy_from_slice(&(val as u32).to_be_bytes()),
        8 => buf[pos..pos + 8].copy_from_slice(&val.to_be_bytes()),
        _ => {
            return Err(StrHideError::CorruptedData(format!(
                "Unsupported integer size {}",
                size
            )));
        }
    }
    Ok(())
}

fn read_uint(buf: &[u8], pos: usize, size: usize) -> Result<u64, StrHideError> {
    if pos + size > buf.len() {
        return Err(StrHideError::CorruptedData(
            "Out of bounds read in iloc".into(),
        ));
    }
    let val = match size {
        0 => 0,
        1 => buf[pos] as u64,
        2 => u16::from_be_bytes(buf[pos..pos + 2].try_into().unwrap()) as u64,
        4 => u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()) as u64,
        8 => u64::from_be_bytes(buf[pos..pos + 8].try_into().unwrap()),
        _ => {
            return Err(StrHideError::CorruptedData(format!(
                "Unsupported integer size {}",
                size
            )));
        }
    };
    Ok(val)
}

/// Locate the best bridgeable carrier target in the HEIF file.
///
/// The primary image (`pitm`) is never a candidate — the module contract
/// keeps it bit-exact (audit 2026-10-24 5.3). Items referenced as
/// thumbnails (`iref`/`thmb`) are preferred; without `iref` any declared
/// non-primary JPEG item qualifies. `unci` (uncompressed) items are not
/// supported: the spatial engine requires a PNG container, so the old
/// branch handed it raw pixels it would reject on the first byte
/// (audit 2026-10-24 5.5).
pub fn find_bridge_target(data: &[u8]) -> Result<BridgeTarget, StrHideError> {
    let isobmff = parse_isobmff(data).map_err(|e| {
        StrHideError::UnsupportedFormat(format!("Failed to parse ISO BMFF structure: {}", e))
    })?;

    // Priority 1: JPEG items. Thumbnail-referenced ones win; any other
    // declared non-primary JPEG item is the fallback within this priority.
    let mut non_thumb_jpeg = None;
    for item in &isobmff.items {
        if &item.item_type == b"jpeg" && !item.extents.is_empty() {
            if isobmff.primary_item_id == Some(item.item_id) {
                continue; // the primary image stays bit-exact
            }
            let ext = &item.extents[0];
            let Some(start) = item
                .base_offset
                .checked_add(ext.offset)
                .and_then(|v| usize::try_from(v).ok())
            else {
                continue;
            };
            let Some(len) = usize::try_from(ext.length).ok() else {
                continue;
            };
            let Some(end) = start.checked_add(len) else {
                continue;
            };
            if end <= data.len() && len >= 64 && &data[start..start + 2] == b"\xFF\xD8" {
                let target = BridgeTarget {
                    kind: BridgeTargetKind::DirectJpeg {
                        item_id: item.item_id,
                    },
                    file_offset: start,
                    length: len,
                };
                if isobmff.thumbnail_ids.contains(&item.item_id) {
                    return Ok(target);
                }
                if non_thumb_jpeg.is_none() {
                    non_thumb_jpeg = Some(target);
                }
            }
        }
    }
    if let Some(target) = non_thumb_jpeg {
        return Ok(target);
    }

    // Priority 2: Embedded JPEG inside an Exif metadata item
    for item in &isobmff.items {
        if &item.item_type == b"Exif" && !item.extents.is_empty() {
            let ext = &item.extents[0];
            let Some(exif_start) = item
                .base_offset
                .checked_add(ext.offset)
                .and_then(|v| usize::try_from(v).ok())
            else {
                continue;
            };
            let Some(exif_len) = usize::try_from(ext.length).ok() else {
                continue;
            };
            let Some(end) = exif_start.checked_add(exif_len) else {
                continue;
            };
            if end <= data.len() {
                let exif_slice = &data[exif_start..exif_start + exif_len];
                if let Some(target) = parse_exif_embedded_jpeg(exif_slice, exif_start, item.item_id)
                {
                    return Ok(target);
                }
            }
        }
    }

    // Priority 3: Fallback scan for standalone embedded JPEG (>= 4096 bytes)
    if let Some(target) = fallback_scan_jpeg(data) {
        return Ok(target);
    }

    Err(StrHideError::UnsupportedFormat(
        "No bridgeable image carrier (JPEG thumbnail or uncompressed item) found in HEIF container"
            .into(),
    ))
}

/// Parse an Exif item data block to locate embedded JPEG thumbnail stream.
fn parse_exif_embedded_jpeg(
    exif_slice: &[u8],
    exif_file_offset: usize,
    exif_item_id: u32,
) -> Option<BridgeTarget> {
    // Look for TIFF header (b"II*\0" or b"MM\0*")
    let mut tiff_pos = None;
    for i in 0..exif_slice.len().saturating_sub(4) {
        if &exif_slice[i..i + 4] == b"II*\x00" || &exif_slice[i..i + 4] == b"MM\x00*" {
            tiff_pos = Some(i);
            break;
        }
    }

    if let Some(t_pos) = tiff_pos {
        let is_le = &exif_slice[t_pos..t_pos + 2] == b"II";
        let tiff_buf = &exif_slice[t_pos..];

        // Read IFD0 offset
        if tiff_buf.len() >= 8 {
            let ifd0_off = if is_le {
                u32::from_le_bytes(tiff_buf[4..8].try_into().unwrap()) as usize
            } else {
                u32::from_be_bytes(tiff_buf[4..8].try_into().unwrap()) as usize
            };

            if ifd0_off + 2 <= tiff_buf.len() {
                let cnt0 = if is_le {
                    u16::from_le_bytes(tiff_buf[ifd0_off..ifd0_off + 2].try_into().unwrap())
                        as usize
                } else {
                    u16::from_be_bytes(tiff_buf[ifd0_off..ifd0_off + 2].try_into().unwrap())
                        as usize
                };
                let next_ifd_pos = ifd0_off + 2 + cnt0 * 12;

                if next_ifd_pos + 4 <= tiff_buf.len() {
                    let ifd1_off = if is_le {
                        u32::from_le_bytes(
                            tiff_buf[next_ifd_pos..next_ifd_pos + 4].try_into().unwrap(),
                        ) as usize
                    } else {
                        u32::from_be_bytes(
                            tiff_buf[next_ifd_pos..next_ifd_pos + 4].try_into().unwrap(),
                        ) as usize
                    };

                    if ifd1_off > 0 && ifd1_off + 2 <= tiff_buf.len() {
                        let cnt1 = if is_le {
                            u16::from_le_bytes(tiff_buf[ifd1_off..ifd1_off + 2].try_into().unwrap())
                                as usize
                        } else {
                            u16::from_be_bytes(tiff_buf[ifd1_off..ifd1_off + 2].try_into().unwrap())
                                as usize
                        };

                        let mut tag_0201_val = None;
                        let mut tag_0202_val = None;
                        let mut tag_0202_pos = None;

                        for idx in 0..cnt1 {
                            let ep = ifd1_off + 2 + idx * 12;
                            if ep + 12 > tiff_buf.len() {
                                break;
                            }
                            let tag = if is_le {
                                u16::from_le_bytes(tiff_buf[ep..ep + 2].try_into().unwrap())
                            } else {
                                u16::from_be_bytes(tiff_buf[ep..ep + 2].try_into().unwrap())
                            };
                            let val = if is_le {
                                u32::from_le_bytes(tiff_buf[ep + 8..ep + 12].try_into().unwrap())
                            } else {
                                u32::from_be_bytes(tiff_buf[ep + 8..ep + 12].try_into().unwrap())
                            };

                            if tag == 0x0201 {
                                tag_0201_val = Some(val as usize);
                            } else if tag == 0x0202 {
                                tag_0202_val = Some(val as usize);
                                tag_0202_pos = Some(exif_file_offset + t_pos + ep + 8);
                            }
                        }

                        if let (Some(rel_off), Some(len)) = (tag_0201_val, tag_0202_val)
                            && rel_off + len <= tiff_buf.len()
                            && len >= 64
                            && &tiff_buf[rel_off..rel_off + 2] == b"\xFF\xD8"
                        {
                            return Some(BridgeTarget {
                                kind: BridgeTargetKind::ExifJpeg {
                                    exif_item_id,
                                    tag_0202_file_offset: tag_0202_pos,
                                    is_little_endian: is_le,
                                },
                                file_offset: exif_file_offset + t_pos + rel_off,
                                length: len,
                            });
                        }
                    }
                }
            }
        }
    }

    // Fallback within Exif: scan for valid JPEGs and pick the largest one >= 4096 bytes
    let mut best_jpeg: Option<(usize, usize)> = None;
    let mut p = 0;
    while p + 4 <= exif_slice.len() {
        if &exif_slice[p..p + 2] == b"\xFF\xD8" && exif_slice[p + 2] == 0xFF {
            // Check valid JPEG marker
            let marker = exif_slice[p + 3];
            if matches!(marker, 0xE0..=0xEF | 0xDB | 0xC0..=0xC4) {
                // Find matching EOI
                let mut eoi_pos = None;
                let mut search_p = p + 4;
                while search_p + 2 <= exif_slice.len() {
                    if &exif_slice[search_p..search_p + 2] == b"\xFF\xD9" {
                        eoi_pos = Some(search_p + 2);
                        break;
                    }
                    search_p += 1;
                }
                if let Some(end) = eoi_pos {
                    let len = end - p;
                    if len >= 4096 && best_jpeg.is_none_or(|(_, best_len)| len > best_len) {
                        best_jpeg = Some((p, len));
                    }
                    p = end;
                    continue;
                }
            }
        }
        p += 1;
    }

    best_jpeg.map(|(rel_off, len)| BridgeTarget {
        kind: BridgeTargetKind::ExifJpeg {
            exif_item_id,
            tag_0202_file_offset: None,
            is_little_endian: true,
        },
        file_offset: exif_file_offset + rel_off,
        length: len,
    })
}

/// Fallback scanner for a standalone valid JPEG in the whole container.
fn fallback_scan_jpeg(data: &[u8]) -> Option<BridgeTarget> {
    let mut best_jpeg: Option<(usize, usize)> = None;
    let mut p = 0;
    while p + 4 <= data.len() {
        if &data[p..p + 2] == b"\xFF\xD8" && data[p + 2] == 0xFF {
            let marker = data[p + 3];
            if matches!(marker, 0xE0..=0xEF | 0xDB | 0xC0..=0xC4) {
                let mut search_p = p + 4;
                let mut eoi_pos = None;
                while search_p + 2 <= data.len() {
                    if &data[search_p..search_p + 2] == b"\xFF\xD9" {
                        eoi_pos = Some(search_p + 2);
                        break;
                    }
                    search_p += 1;
                }
                if let Some(end) = eoi_pos {
                    let len = end - p;
                    if len >= 4096 && best_jpeg.is_none_or(|(_, best_len)| len > best_len) {
                        best_jpeg = Some((p, len));
                    }
                    p = end;
                    continue;
                }
            }
        }
        p += 1;
    }

    best_jpeg.map(|(file_offset, length)| BridgeTarget {
        kind: BridgeTargetKind::ContainerJpegFallback,
        file_offset,
        length,
    })
}

/// Lightweight ISO BMFF parser for meta box, iinf, and iloc.
fn parse_isobmff(data: &[u8]) -> Result<IsobmffMeta, StrHideError> {
    let mut top_boxes = Vec::new();
    let mut pos = 0usize;
    let mut meta_span = None;

    while pos + 8 <= data.len() {
        let (bsize, bhdr) = read_box_header(data, pos)?;
        if bsize == 0 || pos + bsize > data.len() {
            break;
        }
        let fcc: [u8; 4] = data[pos + 4..pos + 8].try_into().unwrap();
        top_boxes.push((pos, bsize, fcc));
        if &fcc == b"meta" {
            meta_span = Some((pos, bsize, bhdr));
        }
        pos += bsize;
    }

    let (meta_off, meta_sz, meta_hdr) = meta_span
        .ok_or_else(|| StrHideError::CorruptedData("No meta box found in HEIF container".into()))?;

    // Subboxes start after the box header (8 bytes, or 16 for a `largesize`
    // box) plus the 4-byte fullbox version/flags. Assuming 8 put the walk 8
    // bytes into the first child for a large `meta`.
    let meta_body_start = meta_off + meta_hdr + 4;
    let meta_end = meta_off + meta_sz;
    let mut mpos = meta_body_start;

    let mut iinf_span = None;
    let mut iloc_span = None;
    let mut pitm_span = None;
    let mut iref_span = None;

    while mpos + 8 <= meta_end {
        let (sb_sz, _) = read_box_header(data, mpos)?;
        if sb_sz == 0 || mpos + sb_sz > meta_end {
            break;
        }
        let sfcc = &data[mpos + 4..mpos + 8];
        if sfcc == b"iinf" {
            iinf_span = Some((mpos, sb_sz));
        } else if sfcc == b"iloc" {
            iloc_span = Some((mpos, sb_sz));
        } else if sfcc == b"pitm" {
            pitm_span = Some((mpos, sb_sz));
        } else if sfcc == b"iref" {
            iref_span = Some((mpos, sb_sz));
        }
        mpos += sb_sz;
    }

    let (iinf_off, iinf_sz) =
        iinf_span.ok_or_else(|| StrHideError::CorruptedData("No iinf box found in meta".into()))?;
    let (iloc_off, iloc_sz) =
        iloc_span.ok_or_else(|| StrHideError::CorruptedData("No iloc box found in meta".into()))?;

    // Parse iinf items: item_id -> item_type
    let mut items_map = std::collections::BTreeMap::<u32, [u8; 4]>::new();
    let iinf_buf = &data[iinf_off..iinf_off + iinf_sz];
    if iinf_buf.len() >= 14 {
        let iver = iinf_buf[8];
        let mut ipos = if iver == 0 { 14 } else { 16 };
        while ipos + 8 <= iinf_buf.len() {
            let (infe_sz, _) = read_box_header(iinf_buf, ipos)?;
            if infe_sz == 0 || ipos + infe_sz > iinf_buf.len() {
                break;
            }
            if &iinf_buf[ipos + 4..ipos + 8] == b"infe" && infe_sz >= 16 {
                let infe_ver = iinf_buf[ipos + 8];
                if infe_ver == 2 && infe_sz >= 20 {
                    let id = u16::from_be_bytes(iinf_buf[ipos + 12..ipos + 14].try_into().unwrap())
                        as u32;
                    let itype: [u8; 4] = iinf_buf[ipos + 16..ipos + 20].try_into().unwrap();
                    items_map.insert(id, itype);
                } else if infe_ver == 3 && infe_sz >= 22 {
                    // v3: item_ID(32) at +12..16, protection(16) at +16..18,
                    // item_type(32) at +18..22. The old code read +20..24 --
                    // two bytes into the item name -- so every v3 item_type
                    // was garbage and all directed lookups fell through to the
                    // full-file fallback scan (audit 2026-10-24 5.1). The
                    // smallest legal v3 box that carries a type is 22 bytes
                    // (23 with the name's NUL).
                    let id = u32::from_be_bytes(iinf_buf[ipos + 12..ipos + 16].try_into().unwrap());
                    let itype: [u8; 4] = iinf_buf[ipos + 18..ipos + 22].try_into().unwrap();
                    items_map.insert(id, itype);
                }
            }
            ipos += infe_sz;
        }
    }

    // Parse iloc items
    let mut items = Vec::new();
    let iloc_buf = &data[iloc_off..iloc_off + iloc_sz];
    if iloc_buf.len() >= 16 {
        let iloc_ver = iloc_buf[8];
        let off_sz = ((iloc_buf[12] >> 4) & 0x0F) as usize;
        let len_sz = (iloc_buf[12] & 0x0F) as usize;
        let base_sz = ((iloc_buf[13] >> 4) & 0x0F) as usize;
        let idx_sz = if iloc_ver >= 1 {
            (iloc_buf[13] & 0x0F) as usize
        } else {
            0
        };
        let id_sz = if iloc_ver < 2 { 2 } else { 4 };

        // v2+ stores a 32-bit item count at +14..18; the old `>= 16` guard
        // let a 16- or 17-byte box through and the read panicked
        // (audit 2026-10-24 5.4).
        let item_cnt = if iloc_ver < 2 {
            if iloc_buf.len() < 16 {
                return Err(StrHideError::CorruptedData(
                    "iloc item-count field truncated".into(),
                ));
            }
            u16::from_be_bytes(iloc_buf[14..16].try_into().unwrap()) as usize
        } else {
            if iloc_buf.len() < 18 {
                return Err(StrHideError::CorruptedData(
                    "iloc v2 item-count field truncated".into(),
                ));
            }
            u32::from_be_bytes(iloc_buf[14..18].try_into().unwrap()) as usize
        };

        // All-zero extent size fields make the extent loop below advance zero
        // bytes per iteration -- the same zero-progress DoS shape fixed in
        // heif_boxes (audit 2026-10-24 4.2); `read_uint(_, _, 0)` would
        // happily spin 65535 times here.
        if off_sz + len_sz + idx_sz == 0 {
            return Err(StrHideError::CorruptedData(
                "iloc extent sizes are all zero; extents carry no data".into(),
            ));
        }

        let mut pos = if iloc_ver < 2 { 16 } else { 18 };

        for _ in 0..item_cnt {
            if pos + id_sz > iloc_buf.len() {
                break;
            }
            let item_id = if id_sz == 2 {
                u16::from_be_bytes(iloc_buf[pos..pos + 2].try_into().unwrap()) as u32
            } else {
                u32::from_be_bytes(iloc_buf[pos..pos + 4].try_into().unwrap())
            };
            pos += id_sz;

            let construction_method = if iloc_ver >= 1 {
                if pos + 2 > iloc_buf.len() {
                    break;
                }
                let cm =
                    (u16::from_be_bytes(iloc_buf[pos..pos + 2].try_into().unwrap()) & 0x0F) as u8;
                pos += 2;
                cm
            } else {
                0
            };

            pos += 2; // skip data_reference_index

            let base_offset_pos = iloc_off + pos;
            let base_offset = read_uint(iloc_buf, pos, base_sz)?;
            pos += base_sz;

            if pos + 2 > iloc_buf.len() {
                break;
            }
            let extent_cnt =
                u16::from_be_bytes(iloc_buf[pos..pos + 2].try_into().unwrap()) as usize;
            pos += 2;

            let mut extents = Vec::with_capacity(extent_cnt);

            for _ in 0..extent_cnt {
                pos += idx_sz;
                let extent_offset_pos = iloc_off + pos;
                let extent_offset = read_uint(iloc_buf, pos, off_sz)?;
                pos += off_sz;

                let extent_length_pos = iloc_off + pos;
                let extent_length = read_uint(iloc_buf, pos, len_sz)?;
                pos += len_sz;

                extents.push(IsobmffExtent {
                    offset: extent_offset,
                    offset_pos: extent_offset_pos,
                    offset_sz: off_sz,
                    length: extent_length,
                    length_pos: extent_length_pos,
                    length_sz: len_sz,
                });
            }

            let item_type = items_map.get(&item_id).copied().unwrap_or([0u8; 4]);

            items.push(IsobmffItem {
                item_id,
                item_type,
                construction_method,
                base_offset,
                base_offset_pos,
                base_offset_sz: base_sz,
                extents,
            });
        }
    }

    let (primary_item_id, thumbnail_ids) = parse_pitm_and_iref(data, pitm_span, iref_span);

    Ok(IsobmffMeta {
        items,
        top_boxes,
        primary_item_id,
        thumbnail_ids,
    })
}

/// Parse `pitm` (primary item id) and `iref`/`thmb` (thumbnail references)
/// out of the meta box. Both are best-effort: an absent or malformed box
/// simply leaves the corresponding field empty, and the target selection
/// below degrades to the historical behaviour.
fn parse_pitm_and_iref(
    data: &[u8],
    pitm_span: Option<(usize, usize)>,
    iref_span: Option<(usize, usize)>,
) -> (Option<u32>, Vec<u32>) {
    let mut primary_item_id = None;
    if let Some((off, sz)) = pitm_span {
        let b = &data[off..(off + sz).min(data.len())];
        // Fullbox: 8 header + 4 version/flags, then item_ID (u16 v0 / u32 v1).
        match b.get(8) {
            Some(0) if b.len() >= 14 => {
                primary_item_id = Some(u16::from_be_bytes(b[12..14].try_into().unwrap()) as u32);
            }
            Some(1..) if b.len() >= 16 => {
                primary_item_id = Some(u32::from_be_bytes(b[12..16].try_into().unwrap()));
            }
            _ => {}
        }
    }

    let mut thumbnail_ids = Vec::new();
    if let Some((off, sz)) = iref_span {
        let b = &data[off..(off + sz).min(data.len())];
        let id_sz = match b.get(8) {
            Some(0) => 2usize,
            Some(1..) => 4,
            None => 0,
        };
        let read_id = |q: usize| -> Option<u32> {
            if id_sz == 2 && q + 2 <= b.len() {
                Some(u16::from_be_bytes(b[q..q + 2].try_into().unwrap()) as u32)
            } else if id_sz == 4 && q + 4 <= b.len() {
                Some(u32::from_be_bytes(b[q..q + 4].try_into().unwrap()))
            } else {
                None
            }
        };
        // Walk the typed reference sub-boxes (thmb/cdsc/...): from_item_ID,
        // reference_count, then that many to_item_IDs.
        let mut p = 12usize;
        while p + 8 <= b.len() {
            let sub_sz = u32::from_be_bytes(b[p..p + 4].try_into().unwrap()) as usize;
            if sub_sz < 8 || p + sub_sz > b.len() {
                break;
            }
            let ref_type = &b[p + 4..p + 8];
            let mut q = p + 8;
            if let Some(from_id) = read_id(q) {
                q += id_sz;
                if q + 2 <= b.len() {
                    let cnt = u16::from_be_bytes(b[q..q + 2].try_into().unwrap()) as usize;
                    if ref_type == b"thmb" {
                        thumbnail_ids.push(from_id);
                    }
                    let _ = cnt; // to_item_IDs are not needed for targeting
                }
            }
            p += sub_sz;
        }
    }

    (primary_item_id, thumbnail_ids)
}

fn read_box_header(bytes: &[u8], pos: usize) -> Result<(usize, usize), StrHideError> {
    if pos + 8 > bytes.len() {
        return Err(StrHideError::CorruptedData(
            "Truncated box header in ISO BMFF".into(),
        ));
    }
    let size_32 = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    if size_32 == 1 {
        if pos + 16 > bytes.len() {
            return Err(StrHideError::CorruptedData("Truncated 64-bit box".into()));
        }
        let size_64 = u64::from_be_bytes(bytes[pos + 8..pos + 16].try_into().unwrap()) as usize;
        Ok((size_64, 16))
    } else if size_32 == 0 {
        Ok((bytes.len() - pos, 8))
    } else {
        Ok((size_32, 8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(offset: u64, length: u64, tag: usize) -> IsobmffExtent {
        IsobmffExtent {
            offset,
            offset_pos: tag * 100,
            offset_sz: 4,
            length,
            length_pos: tag * 100 + 8,
            length_sz: 4,
        }
    }

    /// The host-extent selection that drives the iloc length patch: the
    /// extent that physically covers the replaced region, on file-offset
    /// items only. A multi-extent item must select exactly the covering
    /// extent -- the old code added the length delta to every extent,
    /// corrupting the declared total (audit 2026-10-24 5.2) -- and idat
    /// construction can never host the bridge target (review 2026-10-25 M9).
    #[test]
    fn host_extent_selects_the_covering_extent() {
        let item = IsobmffItem {
            item_id: 5,
            item_type: *b"Exif",
            construction_method: 0,
            base_offset: 1000,
            base_offset_pos: 0,
            base_offset_sz: 4,
            extents: vec![ext(0, 500, 0), ext(500, 800, 1)],
        };
        // Inside the second extent [1500, 2300): absolute target 1600..1900.
        let host = host_extent(&item, 1600, 1900).expect("second extent covers it");
        assert_eq!(host.offset, 500);
        // Partially straddling two extents selects nothing: patching either
        // one alone would be wrong, and the caller must refuse the target.
        assert!(host_extent(&item, 1400, 1600).is_none());
        // Outside every extent: no host (the container fallback then treats
        // this item as a non-target and shifts only what follows the region).
        assert!(host_extent(&item, 2600, 2700).is_none());

        let mut idat = item.clone();
        idat.construction_method = 1;
        assert!(
            host_extent(&idat, 1600, 1900).is_none(),
            "idat construction is not a file offset and cannot host"
        );
    }

    /// Minimal HEIF container helpers for the targeting tests below.
    fn mk_box(fcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + payload.len());
        b.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        b.extend_from_slice(fcc);
        b.extend_from_slice(payload);
        b
    }

    fn mk_fullbox(ver: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![ver, 0, 0, 0];
        v.extend_from_slice(body);
        v
    }

    /// Build a HEIF with two JPEG items (`primary_id` names the `pitm`
    /// primary) plus an optional `iref`/`thmb` declaring `thumb_id` a
    /// thumbnail. Returns the file bytes.
    fn build_two_jpeg_heif(primary_id: u16, thumb_id: Option<u16>) -> Vec<u8> {
        let mut jpeg_a = vec![0xFF, 0xD8];
        jpeg_a.extend(std::iter::repeat_n(0x11u8, 62)); // 64 bytes
        let mut jpeg_b = vec![0xFF, 0xD8];
        jpeg_b.extend(std::iter::repeat_n(0x22u8, 62));

        let mk_infe = |id: u16| {
            let mut body = vec![2u8, 0, 0, 0]; // infe version 2
            body.extend_from_slice(&id.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes()); // protection
            body.extend_from_slice(b"jpeg");
            mk_box(b"infe", &body)
        };
        let mut iinf_body = mk_fullbox(0, &2u16.to_be_bytes()); // entry count
        iinf_body.extend_from_slice(&mk_infe(1));
        iinf_body.extend_from_slice(&mk_infe(2));
        let iinf = mk_box(b"iinf", &iinf_body);
        let pitm = mk_box(b"pitm", &mk_fullbox(0, &primary_id.to_be_bytes()));

        // iref/thmb: from_item_ID = thumb_id, one to_item (the primary).
        let iref = thumb_id.map(|t| {
            let mut body = mk_fullbox(0, &[]); // iref version 0 (16-bit ids)
            let mut thmb_body = Vec::new();
            thmb_body.extend_from_slice(&t.to_be_bytes());
            thmb_body.extend_from_slice(&1u16.to_be_bytes()); // reference count
            thmb_body.extend_from_slice(&primary_id.to_be_bytes());
            body.extend_from_slice(&mk_box(b"thmb", &thmb_body));
            mk_box(b"iref", &body)
        });

        // iloc v0 with 4-byte offset/length fields, no base offset.
        let mut iloc_body = mk_fullbox(0, &[]);
        iloc_body.push(0x44); // offset_size=4, length_size=4
        iloc_body.push(0x00); // base_offset_size=0
        iloc_body.extend_from_slice(&2u16.to_be_bytes());
        // The two extents' file offsets depend on the sizes of everything
        // before mdat, which are fixed once iinf/pitm/iloc/iref sizes are
        // known; iloc itself is a fixed 8 + 2*14 bytes, so compute in order.
        let iloc_len = 8 + 8 + 2 * (2 + 2 + 2 + 4 + 4);
        let mut meta_body_len = pitm.len() + iinf.len() + iloc_len;
        if let Some(ref r) = iref {
            meta_body_len += r.len();
        }
        let ftyp_len = 8 + 8;
        // meta box = 8 header + 4 fullbox version/flags + body; mdat = 8 header.
        let mdat_data_start = ftyp_len + 8 + 4 + meta_body_len + 8;
        let off_a = mdat_data_start as u32;
        let off_b = (mdat_data_start + jpeg_a.len()) as u32;
        for (id, off) in [(1u16, off_a), (2u16, off_b)] {
            iloc_body.extend_from_slice(&id.to_be_bytes());
            iloc_body.extend_from_slice(&0u16.to_be_bytes()); // data ref
            iloc_body.extend_from_slice(&1u16.to_be_bytes()); // extent count
            iloc_body.extend_from_slice(&off.to_be_bytes());
            iloc_body.extend_from_slice(&(jpeg_a.len() as u32).to_be_bytes());
        }
        assert_eq!(iloc_body.len() + 8, iloc_len);
        let iloc = mk_box(b"iloc", &iloc_body);

        let mut meta_payload = mk_fullbox(0, &[]);
        meta_payload.extend_from_slice(&pitm);
        meta_payload.extend_from_slice(&iinf);
        if let Some(ref r) = iref {
            meta_payload.extend_from_slice(r);
        }
        meta_payload.extend_from_slice(&iloc);
        let meta = mk_box(b"meta", &meta_payload);

        let mut file = Vec::new();
        file.extend_from_slice(&mk_box(b"ftyp", b"mif1\0\0\0\0"));
        file.extend_from_slice(&meta);
        file.extend_from_slice(&mk_box(
            b"mdat",
            &[jpeg_a.as_slice(), jpeg_b.as_slice()].concat(),
        ));
        file
    }

    /// The bridge must never pick the `pitm` primary image, and must prefer
    /// an `iref`/`thmb`-declared thumbnail when one exists (audit
    /// 2026-10-24 5.3).
    #[test]
    fn bridge_target_skips_primary_and_prefers_thumbnail() {
        // Primary is item 1, thumbnail reference names item 2: item 2 wins.
        let file = build_two_jpeg_heif(1, Some(2));
        let target = find_bridge_target(&file).expect("thumbnail item is bridgeable");
        match target.kind {
            BridgeTargetKind::DirectJpeg { item_id } => assert_eq!(item_id, 2),
            other => panic!("expected DirectJpeg, got {other:?}"),
        }

        // Without iref the primary is still excluded; the remaining JPEG
        // item (2) is the target.
        let file = build_two_jpeg_heif(1, None);
        let target = find_bridge_target(&file).expect("non-primary item is bridgeable");
        match target.kind {
            BridgeTargetKind::DirectJpeg { item_id } => assert_eq!(item_id, 2),
            other => panic!("expected DirectJpeg, got {other:?}"),
        }

        // Swap: primary is item 2 (the second extent), so the target must
        // flip to item 1.
        let file = build_two_jpeg_heif(2, Some(1));
        let target = find_bridge_target(&file).expect("non-primary item is bridgeable");
        match target.kind {
            BridgeTargetKind::DirectJpeg { item_id } => assert_eq!(item_id, 1),
            other => panic!("expected DirectJpeg, got {other:?}"),
        }
    }

    /// A `meta` box using the 64-bit `largesize` form has a 16-byte header; the
    /// walk used to assume 8 and started 8 bytes into the first child, so every
    /// span was garbage and the bridge fell back to the full-file JPEG scan.
    #[test]
    fn large_size_meta_box_still_parses() {
        fn mk_large_box(fcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
            let mut b = Vec::with_capacity(16 + payload.len());
            b.extend_from_slice(&1u32.to_be_bytes());
            b.extend_from_slice(fcc);
            b.extend_from_slice(&((16 + payload.len()) as u64).to_be_bytes());
            b.extend_from_slice(payload);
            b
        }

        let mut infe_body = vec![2u8, 0, 0, 0]; // infe version 2
        infe_body.extend_from_slice(&1u16.to_be_bytes()); // item_ID
        infe_body.extend_from_slice(&0u16.to_be_bytes()); // protection
        infe_body.extend_from_slice(b"jpeg");
        let infe = mk_box(b"infe", &infe_body);

        let mut iinf_body = mk_fullbox(0, &1u16.to_be_bytes()); // entry count
        iinf_body.extend_from_slice(&infe);
        let iinf = mk_box(b"iinf", &iinf_body);

        let mut iloc_body = mk_fullbox(0, &[]);
        iloc_body.push(0x44); // offset_size=4, length_size=4
        iloc_body.push(0x00); // base_offset_size=0
        iloc_body.extend_from_slice(&1u16.to_be_bytes()); // item count
        iloc_body.extend_from_slice(&1u16.to_be_bytes()); // item_ID
        iloc_body.extend_from_slice(&0u16.to_be_bytes()); // data_reference_index
        iloc_body.extend_from_slice(&1u16.to_be_bytes()); // extent count
        iloc_body.extend_from_slice(&100u32.to_be_bytes()); // extent offset
        iloc_body.extend_from_slice(&8u32.to_be_bytes()); // extent length
        let iloc = mk_box(b"iloc", &iloc_body);

        let mut meta_body = mk_fullbox(0, &[]);
        meta_body.extend_from_slice(&iinf);
        meta_body.extend_from_slice(&iloc);
        let meta = mk_large_box(b"meta", &meta_body);

        let mut file = mk_box(b"ftyp", b"heic    ");
        file.extend_from_slice(&meta);

        let parsed = parse_isobmff(&file).expect("large-size meta must parse");
        assert_eq!(parsed.items.len(), 1, "the iloc item must be found");
        assert_eq!(parsed.items[0].item_id, 1);
        assert_eq!(parsed.items[0].item_type, *b"jpeg");
        assert_eq!(parsed.items[0].extents.len(), 1);
        assert_eq!(parsed.items[0].extents[0].offset, 100);
        assert_eq!(parsed.items[0].extents[0].length, 8);
    }
}
