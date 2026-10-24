//! Content-domain bridge steganography for HEIF/HEIC containers.
//!
//! Bridges embedded JPEG thumbnails or uncompressed auxiliary items within ISO BMFF containers
//! to existing content-adaptive steganography engines (`stego::jpeg` and `stego::spatial`).
//!
//! The primary HEVC/AVIF photo stream remains 100% bit-exact and untouched.

use std::convert::TryInto;

use crate::errors::StrHideError;
use crate::params::Profile;
use crate::stego::StegoCapacityInfo;
use crate::stego::jpeg;
use crate::stego::params::StegoOptions;
use crate::stego::registry::CostModelRegistry;
use crate::stego::spatial;

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
}

/// Embed payload into an embedded JPEG or uncompressed carrier within a HEIF container.
pub fn embed_heif_bridge(
    carrier_bytes: &[u8],
    payload: &[u8],
    options: &StegoOptions,
    profile: &Profile,
) -> Result<Vec<u8>, StrHideError> {
    let target = find_bridge_target(carrier_bytes)?;
    let carrier_slice = &carrier_bytes[target.file_offset..target.file_offset + target.length];

    let secret = options.secret(profile);
    let domain = options.domain(profile);

    let mut jpeg_params = options.jpeg_params.clone();
    jpeg_params.safety_level = options.safety_level;
    jpeg_params.safety_enforcement = options.safety_enforcement;
    jpeg_params.deterministic = options.freshness.is_seeded();

    let mut spatial_params = options.spatial_params.clone();
    spatial_params.safety_level = options.safety_level;
    spatial_params.safety_enforcement = options.safety_enforcement;

    match target.kind {
        BridgeTargetKind::DirectJpeg { .. }
        | BridgeTargetKind::ExifJpeg { .. }
        | BridgeTargetKind::ContainerJpegFallback => {
            let model = CostModelRegistry::get_jpeg_model(options.algorithm.as_deref())
                .ok_or_else(|| {
                    StrHideError::General(format!(
                        "Unknown or incompatible JPEG stego algorithm: {:?}",
                        options.algorithm
                    ))
                })?;
            let stego_bytes = jpeg::embed_jpeg_with_freshness(
                carrier_slice,
                payload,
                secret,
                domain,
                profile.format_profile(),
                &jpeg_params,
                &*model,
                options.freshness,
            )?;
            reconstruct_heif(carrier_bytes, &target, &stego_bytes)
        }
        BridgeTargetKind::DirectSpatial { .. } => {
            let model = CostModelRegistry::get_spatial_model(options.algorithm.as_deref())
                .ok_or_else(|| {
                    StrHideError::General(format!(
                        "Unknown or incompatible spatial stego algorithm: {:?}",
                        options.algorithm
                    ))
                })?;
            let stego_bytes = spatial::embed_spatial_with_profile_and_freshness(
                carrier_slice,
                payload,
                secret,
                domain,
                profile.spatial_profile(),
                &*model,
                &spatial_params,
                options.freshness,
            )?;
            reconstruct_heif(carrier_bytes, &target, &stego_bytes)
        }
    }
}

/// Extract payload from an embedded JPEG or uncompressed carrier within a HEIF container.
pub fn extract_heif_bridge(
    carrier_bytes: &[u8],
    options: &StegoOptions,
    profile: &Profile,
) -> Result<Vec<u8>, StrHideError> {
    let target = match find_bridge_target(carrier_bytes) {
        Ok(t) => t,
        Err(_) => {
            return Err(StrHideError::NoHiddenData(
                "No bridgeable carrier found in HEIF container".into(),
            ));
        }
    };
    let carrier_slice = &carrier_bytes[target.file_offset..target.file_offset + target.length];

    let secret = options.secret(profile);
    let domain = options.domain(profile);

    match target.kind {
        BridgeTargetKind::DirectJpeg { .. }
        | BridgeTargetKind::ExifJpeg { .. }
        | BridgeTargetKind::ContainerJpegFallback => jpeg::extract_jpeg(
            carrier_slice,
            secret,
            domain,
            profile.format_profile(),
            &options.extract_params,
        ),
        BridgeTargetKind::DirectSpatial { .. } => {
            let model = CostModelRegistry::get_spatial_model(options.algorithm.as_deref())
                .ok_or_else(|| {
                    StrHideError::General(format!(
                        "Unknown or incompatible spatial stego algorithm: {:?}",
                        options.algorithm
                    ))
                })?;
            spatial::extract_spatial_with_profile(
                carrier_slice,
                secret,
                domain,
                profile.spatial_profile(),
                &*model,
                &options.spatial_params,
            )
        }
    }
}

/// Probe capacity of the bridgeable carrier within a HEIF container.
pub fn probe_heif_bridge_capacity(
    carrier_bytes: &[u8],
    options: &StegoOptions,
    profile: &Profile,
) -> Result<StegoCapacityInfo, StrHideError> {
    let target = find_bridge_target(carrier_bytes)?;
    let carrier_slice = &carrier_bytes[target.file_offset..target.file_offset + target.length];

    let secret = options.secret(profile);
    let domain = options.domain(profile);

    match target.kind {
        BridgeTargetKind::DirectJpeg { .. }
        | BridgeTargetKind::ExifJpeg { .. }
        | BridgeTargetKind::ContainerJpegFallback => {
            let model = CostModelRegistry::get_jpeg_model(options.algorithm.as_deref())
                .ok_or_else(|| {
                    StrHideError::General(format!(
                        "Unknown or incompatible JPEG stego algorithm: {:?}",
                        options.algorithm
                    ))
                })?;
            let mut info = jpeg::probe_capacity_with_format(
                carrier_slice,
                &*model,
                &options.jpeg_params,
                options.safety_level,
                profile.format_profile(),
            )?;
            info.format = "HEIF (JPEG Thumbnail Bridge)".into();
            Ok(info)
        }
        BridgeTargetKind::DirectSpatial { .. } => {
            let model = CostModelRegistry::get_spatial_model(options.algorithm.as_deref())
                .ok_or_else(|| {
                    StrHideError::General(format!(
                        "Unknown or incompatible spatial stego algorithm: {:?}",
                        options.algorithm
                    ))
                })?;
            let mut info = spatial::probe_spatial_capacity_with_profile(
                carrier_slice,
                &*model,
                &options.spatial_params,
                options.safety_level,
                secret,
                domain,
                profile.spatial_profile(),
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

    for item in &isobmff.items {
        // Is this the item containing the target?
        let is_target_item = match target.kind {
            BridgeTargetKind::DirectJpeg { item_id } => item.item_id == item_id,
            BridgeTargetKind::DirectSpatial { item_id } => item.item_id == item_id,
            BridgeTargetKind::ExifJpeg { exif_item_id, .. } => item.item_id == exif_item_id,
            BridgeTargetKind::ContainerJpegFallback => false,
        };

        if is_target_item {
            // Update extent length for this item
            for ext in &item.extents {
                if ext.length_sz > 0 && ext.length_pos + ext.length_sz <= out.len() {
                    let new_extent_len = ((ext.length as i64) + delta).max(0) as u64;
                    patch_uint(&mut out, ext.length_pos, ext.length_sz, new_extent_len)?;
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
pub fn find_bridge_target(data: &[u8]) -> Result<BridgeTarget, StrHideError> {
    let isobmff = parse_isobmff(data).map_err(|e| {
        StrHideError::UnsupportedFormat(format!("Failed to parse ISO BMFF structure: {}", e))
    })?;

    // Priority 1: Independent item_type == b"jpeg"
    for item in &isobmff.items {
        if &item.item_type == b"jpeg" && !item.extents.is_empty() {
            let ext = &item.extents[0];
            let start = (item.base_offset + ext.offset) as usize;
            let len = ext.length as usize;
            if start + len <= data.len() && len >= 64 && &data[start..start + 2] == b"\xFF\xD8" {
                return Ok(BridgeTarget {
                    kind: BridgeTargetKind::DirectJpeg {
                        item_id: item.item_id,
                    },
                    file_offset: start,
                    length: len,
                });
            }
        }
    }

    // Priority 2: Independent item_type == b"unci" (uncompressed spatial item)
    for item in &isobmff.items {
        if &item.item_type == b"unci" && !item.extents.is_empty() {
            let ext = &item.extents[0];
            let start = (item.base_offset + ext.offset) as usize;
            let len = ext.length as usize;
            if start + len <= data.len() && len >= 64 {
                return Ok(BridgeTarget {
                    kind: BridgeTargetKind::DirectSpatial {
                        item_id: item.item_id,
                    },
                    file_offset: start,
                    length: len,
                });
            }
        }
    }

    // Priority 3: Embedded JPEG inside an Exif metadata item
    for item in &isobmff.items {
        if &item.item_type == b"Exif" && !item.extents.is_empty() {
            let ext = &item.extents[0];
            let exif_start = (item.base_offset + ext.offset) as usize;
            let exif_len = ext.length as usize;
            if exif_start + exif_len <= data.len() {
                let exif_slice = &data[exif_start..exif_start + exif_len];
                if let Some(target) = parse_exif_embedded_jpeg(exif_slice, exif_start, item.item_id)
                {
                    return Ok(target);
                }
            }
        }
    }

    // Priority 4: Fallback scan for standalone embedded JPEG (>= 4096 bytes)
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
        let (bsize, _) = read_box_header(data, pos)?;
        if bsize == 0 || pos + bsize > data.len() {
            break;
        }
        let fcc: [u8; 4] = data[pos + 4..pos + 8].try_into().unwrap();
        top_boxes.push((pos, bsize, fcc));
        if &fcc == b"meta" {
            meta_span = Some((pos, bsize));
        }
        pos += bsize;
    }

    let (meta_off, meta_sz) = meta_span
        .ok_or_else(|| StrHideError::CorruptedData("No meta box found in HEIF container".into()))?;

    // Parse subboxes inside meta (skip 8-byte box header + 4-byte fullbox flags)
    let meta_body_start = meta_off + 12;
    let meta_end = meta_off + meta_sz;
    let mut mpos = meta_body_start;

    let mut iinf_span = None;
    let mut iloc_span = None;

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
                } else if infe_ver == 3 && infe_sz >= 24 {
                    let id = u32::from_be_bytes(iinf_buf[ipos + 12..ipos + 16].try_into().unwrap());
                    let itype: [u8; 4] = iinf_buf[ipos + 20..ipos + 24].try_into().unwrap();
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

        let item_cnt = if iloc_ver < 2 {
            u16::from_be_bytes(iloc_buf[14..16].try_into().unwrap()) as usize
        } else {
            u32::from_be_bytes(iloc_buf[14..18].try_into().unwrap()) as usize
        };

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

    Ok(IsobmffMeta { items, top_boxes })
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
