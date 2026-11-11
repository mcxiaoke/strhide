//! Inspection: report the stego header without decrypting the body.
//!
//! Two entry shapes share the same header reader: an in-memory carrier (HEIC,
//! Annex-B, MKV) and a streamed MP4 file, where only moov and the sample
//! prefixes are read so peak memory stays bounded on multi-gigabyte video.

use crate::core::control::Control;
use crate::core::crypto::{CipherSuiteId, Credential};
use crate::core::media::MediaInfo;
use crate::errors::StrHideError;
use crate::stego::format::HevcFormatProfile;
use crate::stego::hevc::slot::{CabacRecorder, RecordMode};
use crate::stego::hevc::sniff::{HevcCarrierKind, NAL_SPS_NUT, sniff_hevc_carrier};
use crate::stego::hevc::superblock::{
    HEVC_SUPERBLOCK_BYTES, HEVC_SUPERBLOCK_MIN_SLOTS, HEVC_SUPERBLOCK_POOL_SLOTS,
};
use crate::stego::options::StegoHeaderInfo;
use crate::stego::params::ExtractParams;
use rusty_h265::Decoder;
use rusty_h265::ctu::Ablate;

use super::capacity::{extract_hevc_dimensions, sps_dimensions};
use super::extract::{HevcHeaderRead, read_hevc_header_v4};
use super::record::record_carrier_state;
use super::scan::{
    Capture, CarrierRecord, DigestInputs, SlotSink, absorb_recorder, drain_frames, is_irap,
    owned_parameter_sets, picture_band,
};
use super::support::{
    StopCondition, check_l1_floor, legacy_credential, nal_header_fields, nal_rbsp,
};

/// Inspect HEVC carrier for steganographic header using an already recorded carrier state.
#[allow(clippy::too_many_arguments)]
fn inspect_hevc_record(
    carrier: &[u8],
    kind: HevcCarrierKind,
    record: &CarrierRecord,
    media_info: Option<MediaInfo>,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let media_info = media_info.or_else(|| {
        let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
        if width > 0 && height > 0 {
            Some(MediaInfo::new(width, height))
        } else {
            None
        }
    });
    let mut empty_info = StegoHeaderInfo::empty(kind.label());
    empty_info.media_info = media_info;

    if check_l1_floor(&cred, limits).is_err() {
        log::debug!(
            target: "stego::inspect",
            "hevc inspect skipped: level-1 key derivation exceeds the configured PBKDF2 budget"
        );
        return Ok(empty_info);
    }
    let header = match read_hevc_header_v4(carrier, record, cred, domain, fmt, limits) {
        Ok(Some(header)) => header,
        // "No header here" is the normal answer for a clean carrier and must
        // stay silent; only a failure to *read* one is worth a record.
        Ok(None) => return Ok(empty_info),
        Err(e) => {
            log::debug!(
                target: "stego::inspect",
                "hevc header read failed for {}: {e}",
                kind.label()
            );
            return Ok(empty_info);
        }
    };

    Ok(hevc_header_info(kind, &header, media_info).unwrap_or(empty_info))
}

/// Header report shared by `inspect` and `verify`.
pub(super) fn hevc_header_info(
    kind: HevcCarrierKind,
    header: &HevcHeaderRead,
    media_info: Option<MediaInfo>,
) -> Option<StegoHeaderInfo> {
    let _suite = CipherSuiteId::from_u16(header.sb.suite_id)?;
    // Plaintext length is unknowable prior to decryption due to variable compression,
    // optional filename micro-headers, and AEAD overhead. Report `None` until decrypted.
    Some(StegoHeaderInfo {
        format: kind.label().to_string(),
        has_hidden_data: true,
        algorithm: Some("HEVC-CABAC-InPlace".into()),
        codec: Some(format!("STC (h=7, u={})", header.sb.stc_u)),
        envelope_len: Some(
            HEVC_SUPERBLOCK_BYTES + header.extension.len() + header.sb.body_len as usize,
        ),
        payload_len: None,
        media_info,
        note: None,
    })
}

/// Inspect HEVC carrier for steganographic header.
#[allow(dead_code)]
pub(crate) fn inspect_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    inspect_hevc_v4(
        carrier,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware inspection with explicit policy limits.
pub(crate) fn inspect_hevc_v4(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    control.check()?;
    let kind = match sniff_hevc_carrier(carrier) {
        Some(k) => k,
        None => return Ok(StegoHeaderInfo::empty("HEVC")),
    };

    let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
    let media_info = if width > 0 && height > 0 {
        Some(MediaInfo::new(width, height))
    } else {
        None
    };
    let mut empty_info = StegoHeaderInfo::empty(kind.label());
    empty_info.media_info = media_info;

    let record = match record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    ) {
        Ok(r) => r,
        Err(e) => {
            // Reaching a carrier that sniffs as HEVC and then fails to record
            // its structure is a parse failure, not "nothing hidden".
            log::debug!(
                target: "stego::inspect",
                "hevc carrier record failed for {}: {e}",
                kind.label()
            );
            return Ok(empty_info);
        }
    };
    inspect_hevc_record(
        carrier, kind, &record, media_info, cred, domain, fmt, limits, control,
    )
}

/// Prefix of a sample the streaming has-inter probe reads. Every VCL NAL that
/// identifies a picture sits at or near the sample start (AUD/SEI prefixes are
/// a few hundred bytes), so 1 MiB is enough without materialising a 64 MiB
/// sample just to classify it.
const HAS_INTER_PREFIX_BYTES: usize = 1024 * 1024;

/// Does the sample prefix contain a non-IRAP VCL NAL?
///
/// Walks the length-prefixed NALs exactly like `collect_sample_slice_spans`
/// (VCL only, forbidden bit clear, non-zero temporal id) but stops at the first
/// incomplete NAL instead of rejecting the prefix as truncated.
pub(super) fn sample_prefix_has_inter(prefix: &[u8], length_size: usize) -> bool {
    if !(1..=4).contains(&length_size) {
        return false;
    }
    let mut pos = 0usize;
    while pos + length_size <= prefix.len() {
        let nal_len = match length_size {
            1 => prefix[pos] as usize,
            2 => u16::from_be_bytes([prefix[pos], prefix[pos + 1]]) as usize,
            3 => {
                ((prefix[pos] as usize) << 16)
                    | ((prefix[pos + 1] as usize) << 8)
                    | prefix[pos + 2] as usize
            }
            _ => u32::from_be_bytes([
                prefix[pos],
                prefix[pos + 1],
                prefix[pos + 2],
                prefix[pos + 3],
            ]) as usize,
        };
        let nal_start = pos + length_size;
        if nal_start + 2 > prefix.len() {
            return false;
        }
        let b0 = prefix[nal_start];
        let b1 = prefix[nal_start + 1];
        let nal_type = (b0 >> 1) & 0x3F;
        if nal_type <= 31 && (b0 & 0x80) == 0 && (b1 & 0x07) > 0 && !is_irap(nal_type) {
            return true;
        }
        let Some(nal_end) = nal_start.checked_add(nal_len) else {
            return false;
        };
        if nal_end > prefix.len() {
            return false;
        }
        pos = nal_end;
    }
    false
}

/// Stream-inspect an MP4 carrier directly from disk using Seek + Read, so peak
/// memory stays bounded by the `moov` (<= 32 MiB) plus one sample
/// (<= `MAX_HEVC_SAMPLE_BYTES`) even for multi-gigabyte video files.
#[allow(dead_code)]
pub(crate) fn inspect_hevc_mp4_file(
    carrier_path: &std::path::Path,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    inspect_hevc_mp4_file_v4(
        carrier_path,
        legacy_credential(secret)?,
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware streaming MP4 inspection with explicit policy limits.
pub(crate) fn inspect_hevc_mp4_file_v4(
    carrier_path: &std::path::Path,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    use std::io::{Read, Seek, SeekFrom};
    control.check()?;

    let mut file = std::fs::File::open(carrier_path)?;
    let file_len = file.metadata()?.len() as usize;

    let mut pos: u64 = 0;
    let mut moov_box: Option<(u64, usize)> = None;
    while pos + 8 <= file_len as u64 {
        file.seek(SeekFrom::Start(pos))?;
        let mut header = [0u8; 8];
        if file.read_exact(&mut header).is_err() {
            break;
        }
        let size32 = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        let tag = [header[4], header[5], header[6], header[7]];
        let (header_len, total_size) = if size32 == 1 {
            let mut s64 = [0u8; 8];
            if file.read_exact(&mut s64).is_err() {
                break;
            }
            (16u64, u64::from_be_bytes(s64))
        } else if size32 == 0 {
            (8u64, (file_len as u64) - pos)
        } else {
            (8u64, size32 as u64)
        };
        if total_size < header_len
            || pos
                .checked_add(total_size)
                .is_none_or(|e| e > file_len as u64)
        {
            break;
        }
        if &tag == b"moov" {
            moov_box = Some((pos, total_size as usize));
            break;
        }
        pos += total_size;
    }

    let (moov_pos, moov_size) = match moov_box {
        Some(b) => b,
        None => return Ok(StegoHeaderInfo::empty("MP4/HEVC")),
    };

    if moov_size > 32 * 1024 * 1024 {
        return Err(StrHideError::UnsupportedFormat(
            "MP4 moov box exceeds 32 MiB".into(),
        ));
    }

    file.seek(SeekFrom::Start(moov_pos))?;
    let mut moov_bytes = vec![0u8; moov_size];
    file.read_exact(&mut moov_bytes)?;

    let target = match crate::stego::hevc::mp4_boxes::parse_moov_target(&moov_bytes, file_len) {
        Ok(t) => t,
        Err(e) => {
            // The moov box was located and read; failing to parse its targets
            // is a malformed container, not an empty carrier.
            log::debug!(
                target: "stego::inspect",
                "mp4 moov target parse failed: {e}"
            );
            return Ok(StegoHeaderInfo::empty("MP4/HEVC"));
        }
    };

    let mut media_info = None;
    for ps in &target.parameter_sets {
        if ps.len() > 2
            && (ps[0] >> 1) & 0x3F == NAL_SPS_NUT
            && let Some(dims) = sps_dimensions(&nal_rbsp(ps))
        {
            let base = MediaInfo::new(dims.0, dims.1);
            media_info = Some(match (target.fps, target.duration_secs) {
                (Some(fps), Some(sec)) if sec > 0.0 => {
                    let bps = (file_len as f64 * 8.0) / sec;
                    base.with_video(
                        fps as f32,
                        (sec * 1000.0).round() as u64,
                        bps.round() as u64,
                    )
                }
                _ => base,
            });
            break;
        }
    }

    let mut empty_info = StegoHeaderInfo::empty("MP4/HEVC");
    empty_info.media_info = media_info;

    // Detect if this MP4 stream contains inter-coded frames (P/B). When has_inter is true,
    // IDR/IRAP frames are excluded from the superblock pool to protect prediction stability.
    let mut has_inter = false;
    for &(sample_offset, sample_size) in &target.samples {
        if sample_size < target.length_size + 2 || sample_offset + sample_size > file_len {
            continue;
        }
        // Same ceiling as `parse_mp4_targets`: samples the byte-level path
        // skips must not influence `has_inter` here either.
        if sample_size <= crate::stego::hevc::mp4_boxes::MAX_HEVC_SAMPLE_BYTES {
            let prefix_len = sample_size.min(HAS_INTER_PREFIX_BYTES);
            let mut hdr_buf = vec![0u8; prefix_len];
            if file.seek(SeekFrom::Start(sample_offset as u64)).is_ok()
                && file.read_exact(&mut hdr_buf).is_ok()
                && sample_prefix_has_inter(&hdr_buf, target.length_size)
            {
                has_inter = true;
                break;
            }
        }
    }

    let mut decoder = Decoder::new();
    decoder.skip_loop_filters = true;
    decoder.ablate = Ablate {
        mc: true,
        intra: true,
        residual: true,
    };
    for ps in &target.parameter_sets {
        let _ = decoder.push_nal(ps, None);
    }
    let parameter_sets = owned_parameter_sets(&target.parameter_sets);

    let mut sink = SlotSink::new(Capture::Bits);
    let mut recorded_slices = 0usize;
    let mut slice_idx = 0usize;

    for &(sample_offset, sample_size) in &target.samples {
        control.check()?;
        if sample_size < 4 || sample_offset + sample_size > file_len {
            continue;
        }
        if sample_size > crate::stego::hevc::mp4_boxes::MAX_HEVC_SAMPLE_BYTES {
            // Same ceiling the byte-level recorder applies, so the slot pool is
            // rebuilt from the same set of samples.
            continue;
        }
        file.seek(SeekFrom::Start(sample_offset as u64))?;
        let mut sample_buf = vec![0u8; sample_size];
        if file.read_exact(&mut sample_buf).is_err() {
            continue;
        }

        let mut spans = Vec::new();
        if crate::stego::hevc::mp4_boxes::collect_sample_slice_spans(
            &sample_buf,
            0,
            sample_size,
            target.length_size,
            &mut spans,
        )
        .is_err()
        {
            continue;
        }

        for span in spans {
            let slice_bytes = &sample_buf[span.start..span.end()];
            if slice_bytes.len() < 2 {
                continue;
            }
            let (nal_type, _, _) = nal_header_fields(slice_bytes);
            let Some(band) = picture_band(nal_type, has_inter) else {
                let _ = decoder.push_nal(slice_bytes, None);
                drain_frames(&mut decoder);
                continue;
            };

            let mut recorder = CabacRecorder::with_slice_mode(slice_idx, band, RecordMode::Slots);
            let decoded = decoder.decode_nal_with_observer(slice_bytes, &mut recorder);
            drain_frames(&mut decoder);
            if decoded.is_ok() && !recorder.substreams.is_empty() {
                let rbsp = nal_rbsp(slice_bytes);
                if absorb_recorder(&mut recorder, &rbsp, &mut sink) {
                    recorded_slices += 1;
                    slice_idx += 1;
                    let current_slots = sink.counts[0] + sink.counts[1];
                    if current_slots >= HEVC_SUPERBLOCK_POOL_SLOTS {
                        break;
                    }
                }
            }
        }

        let current_slots = sink.counts[0] + sink.counts[1];
        if current_slots >= HEVC_SUPERBLOCK_POOL_SLOTS {
            break;
        }
    }

    let total_slots = sink.counts[0] + sink.counts[1];
    if total_slots < HEVC_SUPERBLOCK_MIN_SLOTS {
        return Ok(empty_info);
    }

    let SlotSink {
        counts,
        band_bits,
        raw_bits,
        raw_slots,
        slice_slot_ranges,
        ..
    } = sink;
    let band0_len = counts[0];
    let [band0_bits, band1_bits] = band_bits;
    let bands = vec![0..band0_len, band0_len..total_slots];

    let record = CarrierRecord {
        slice_contexts: Vec::new(),
        all_slots: raw_slots,
        band_bits: [band0_bits.bytes, band1_bits.bytes],
        bands,
        pictures: target.picture_count,
        band_pictures: [target.picture_count, 0],
        digest_inputs: DigestInputs::ParameterSets { parameter_sets },
        recorded_slices,
        raw_bits: raw_bits.bytes,
        slice_slot_ranges,
        capacity_band_counts: None,
    };

    inspect_hevc_record(
        &[],
        HevcCarrierKind::Mp4Container,
        &record,
        media_info,
        cred,
        domain,
        fmt,
        limits,
        control,
    )
}
