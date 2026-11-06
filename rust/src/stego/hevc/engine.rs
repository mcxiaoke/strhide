//! HEVC / H.265 In-place CABAC Bypass Steganography Engine (Scheme C).
//!
//! Provides zero bitrate expansion (Δ = 0), content-adaptive distortion-minimized
//! steganographic embedding and extraction directly within H.265/HEVC bitstreams.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

use crate::core::control::{Control, Event, Stage};
use crate::core::crypto::{CONTENT_L1_PBKDF2_ITERATIONS, CipherSuiteId, Credential};
use crate::core::media::MediaInfo;
use crate::core::payload::Payload;
use crate::errors::StrHideError;
use crate::stego::coding::{Move, StcTrellis};
use crate::stego::envelope::{
    BODY_OVERHEAD, Freshness, PUBLIC_DEFAULT_SECRET, build_plaintext, build_v4_aad,
    encrypt_v4_with_aad, unpack_v4_envelope_parts,
};
use crate::stego::format::{
    HevcFormatProfile, derive_l2_locator_keys, derive_l3_session_keys, derive_locator_master,
};
use crate::stego::header::{
    CONTENT_ENVELOPE_VERSION, FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT, TLV_CRITICAL, Tlv,
    encode_extension_for_write, parse_extension, validate_ext_critical_flag,
};
use crate::stego::hevc::bitstream::{compute_hevc_cover_digest, parse_annex_b_spans, rbsp_to_nal};
use crate::stego::hevc::heif_boxes::parse_heif_targets;
use crate::stego::hevc::mkv_boxes::{parse_mkv_targets, refresh_mkv_crcs};
use crate::stego::hevc::mp4_boxes::parse_mp4_targets;
use crate::stego::hevc::slot::{BinOp, CabacRecorder, RecordMode, StegoSlot, SubstreamRecord};
use crate::stego::hevc::sniff::{
    HevcCarrierKind, NAL_RADL_N, NAL_RASL_N, NAL_RASL_R, NAL_SPS_NUT, NAL_STSA_N, NAL_TRAIL_N,
    NAL_TSA_N, sniff_hevc_carrier,
};
use crate::stego::options::{StegoHeaderInfo, StegoVerifyResult, VerifyLevel};
use crate::stego::params::ExtractParams;
use crate::stego::{SafetyLevel, SafetyPolicy, StegoCapacityInfo};
use oxideav_h265::cabac::ContextModel;
use oxideav_h265::encoder::bitwriter::BitWriter;
use oxideav_h265::encoder::cabac::CabacEncoder;
use rayon::prelude::*;
use rusty_h265::Decoder;
use rusty_h265::ctu::Ablate;
use rusty_h265::observer::ENCODER_CONTEXTS;
use rusty_h265::ps::parse_sps;

/// The three header fields the writer needs back, read straight off the 2-byte
/// NAL header (§7.3.1.2). The decoder hands us the same stream but not the
/// envelope, and the span table only covers Annex-B carriers.
fn nal_header_fields(nal: &[u8]) -> (u8, u8, u8) {
    if nal.len() < 2 {
        return (0, 0, 0);
    }
    let (b0, b1) = (nal[0], nal[1]);
    (
        (b0 >> 1) & 0x3F,
        ((b0 & 0x01) << 5) | (b1 >> 3),
        (b1 & 0x07).saturating_sub(1),
    )
}

/// RBSP payload of a NAL unit (§7.4.2 emulation prevention removal).
///
/// The decoder applies exactly this transform before CABAC, so the substream
/// byte offsets in the journal index the buffer this returns.
fn nal_rbsp(nal: &[u8]) -> Vec<u8> {
    if nal.len() < 2 {
        return Vec::new();
    }
    rusty_h265::nal::unescape(&nal[2..]).data
}

/// Fixed seed for the capacity probe's trellis. Only `slots_for` is used
/// (which depends on `h`/`u`, not the seed), so any value works.
const CAPACITY_PROBE_SEED: u64 = 0x5465_676f;

/// Maximum number of STC re-solves while settling the flip set. Each round
/// either drops the slots that disturbed an emulation-prevention (EPB) window,
/// drops a substream whose journal does not replay the cover, or gives up, so
/// the loop always makes progress. Healthy carriers settle in one round.
const MAX_EMBED_ROUNDS: usize = 24;

/// Extra cost added to a slot excluded by an earlier round. It must lift the
/// slot strictly above its own legal cost: a legal high-displacement slot
/// already costs `HIGH_DISPLACEMENT_PENALTY + l2_cost`, so reusing the bare
/// penalty here made excluded slots *cheaper* and the trellis preferred them.
const FORBIDDEN_SLOT_SURCHARGE: f64 = 1e9;

/// Fixed 32-byte HEVC superblock.
pub const HEVC_SUPERBLOCK_BYTES: usize = 32;
/// Number of initial carrier slots that form the Superblock candidate pool.
pub const HEVC_SUPERBLOCK_POOL_SLOTS: usize = 2048;
/// Base header slots of the 32-byte Superblock under STC h=7, u=2.
pub const HEVC_SUPERBLOCK_MIN_SLOTS: usize = 524;

/// Format id bound into the V4 AAD (JPEG = 4, HEVC = 5).
pub const HEVC_FORMAT_ID: u8 = 5;

/// Legacy `Option<&str>` credential mapping used by the pre-V4 entry points.
fn legacy_credential(secret: Option<&str>) -> Credential<'_> {
    match secret.filter(|s| !s.is_empty()) {
        Some(s) => Credential::Password(s),
        None => Credential::Password(PUBLIC_DEFAULT_SECRET),
    }
}

/// Refuse a password-mode L1 below the fixed V4 work factor before the KDF runs.
///
/// A caller that lowers `max_pbkdf2_iterations` is asking the extractor to run
/// a cheaper (weaker) L1 than the writer used; every such carrier is simply
/// unreadable, so the answer is `NoHiddenData` without paying any KDF cost.
fn check_l1_floor(cred: &Credential<'_>, limits: &ExtractParams) -> Result<(), StrHideError> {
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < CONTENT_L1_PBKDF2_ITERATIONS
    {
        return Err(StrHideError::NoHiddenData(
            "No valid payload found (L1 work factor below the V4 floor)".into(),
        ));
    }
    Ok(())
}

/// Upper bound of the HEVC V4 extension area.
pub const HEVC_MAX_EXT_BYTES: usize = 64;

/// Largest header slot pool the HEVC locator may use.
pub const HEVC_HEADER_SLOTS_MAX: usize = 2048;

/// STC height of the HEVC extension area.
pub const HEVC_EXT_STC_H: u8 = 7;

/// STC group size of the HEVC extension area.
pub const HEVC_EXT_STC_U: u8 = 2;

/// Slots used by `ext_len` extension bytes under STC `h=7, u=2`.
pub fn hevc_extension_slots(ext_len: usize) -> usize {
    if ext_len == 0 {
        0
    } else {
        HEVC_EXT_STC_U as usize * (8 * ext_len + HEVC_EXT_STC_H as usize - 1)
    }
}

/// CRC scope of the 32-byte HEVC V4 superblock.
const HEVC_V4_CRC_SPAN: usize = 28;

/// 32-byte content header of an HEVC carrier.
///
/// `format_id = 5`, `total_windows = 1` and `stc_h` (from
/// [`HevcFormatProfile`]) are implied by the carrier and bound through the AAD
/// prefix; they are not stored.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HevcSuperblockV4 {
    /// L2-derived 4-byte magic.
    pub magic: [u8; 4],
    /// `(major << 4) | minor`.
    pub version: u8,
    /// `EXT_PRESENT` / `EXT_CRITICAL`.
    pub flags: u8,
    /// Trellis width of the body (1..=64).
    pub stc_u: u8,
    /// Recorded candidate slices in the primary window (>= 1).
    pub window_slices: u16,
    /// Extension TLV byte count (0..=64).
    pub ext_len: u8,
    /// AEAD suite id.
    pub suite_id: u16,
    /// Ciphertext length including the tag.
    pub body_len: u32,
    /// AEAD nonce; also the HEVC session-salt input.
    pub nonce: [u8; 12],
}

impl HevcSuperblockV4 {
    /// Serialize the superblock, including CRC32-IEEE over `bytes[0..28]`.
    pub fn encode(&self) -> [u8; HEVC_SUPERBLOCK_BYTES] {
        let mut out = [0u8; HEVC_SUPERBLOCK_BYTES];
        out[0..4].copy_from_slice(&self.magic);
        out[4] = self.version;
        out[5] = self.flags;
        out[6] = self.stc_u;
        out[7..9].copy_from_slice(&self.window_slices.to_be_bytes());
        out[9] = self.ext_len;
        out[10..12].copy_from_slice(&self.suite_id.to_be_bytes());
        out[12..16].copy_from_slice(&self.body_len.to_be_bytes());
        out[16..28].copy_from_slice(&self.nonce);
        let crc = crc32fast::hash(&out[..HEVC_V4_CRC_SPAN]);
        out[HEVC_V4_CRC_SPAN..].copy_from_slice(&crc.to_be_bytes());
        out
    }

    /// Parse and validate an HEVC V4 superblock for the expected magic.
    pub fn decode(
        bytes: &[u8; HEVC_SUPERBLOCK_BYTES],
        expected_magic: [u8; 4],
    ) -> Result<Self, StrHideError> {
        use crate::stego::header::{FLAG_EXT_CRITICAL, FLAG_EXT_PRESENT};

        let magic: [u8; 4] = bytes[0..4].try_into().expect("4-byte magic");
        let version = bytes[4];
        let flags = bytes[5];
        let stc_u = bytes[6];
        let window_slices = u16::from_be_bytes(bytes[7..9].try_into().expect("2-byte slices"));
        let ext_len = bytes[9];
        let suite_id = u16::from_be_bytes(bytes[10..12].try_into().expect("2-byte suite"));
        let body_len = u32::from_be_bytes(bytes[12..16].try_into().expect("4-byte body_len"));
        let nonce = bytes[16..28].try_into().expect("12-byte nonce slice");

        let (major, minor) = (version >> 4, version & 0x0F);
        if major != 4 {
            return Err(StrHideError::UnsupportedVersion(format!(
                "HEVC content envelope major version {major}.{minor} is not supported"
            )));
        }
        if magic != expected_magic {
            return Err(StrHideError::CorruptedData(
                "HEVC content magic does not match the locator seed".into(),
            ));
        }
        if flags & !(FLAG_EXT_PRESENT | FLAG_EXT_CRITICAL) != 0 {
            return Err(StrHideError::CorruptedData(format!(
                "HEVC content envelope flags {flags:#04x} use reserved bits"
            )));
        }
        if flags & FLAG_EXT_PRESENT != (ext_len > 0) as u8 {
            return Err(StrHideError::CorruptedData(
                "HEVC EXT_PRESENT does not match ext_len".into(),
            ));
        }
        if !(1..=64).contains(&stc_u) {
            return Err(StrHideError::CorruptedData(format!(
                "HEVC content stc_u {stc_u} is outside 1..=64"
            )));
        }
        if window_slices == 0 {
            return Err(StrHideError::CorruptedData(
                "HEVC content window_slices must be at least 1".into(),
            ));
        }
        if ext_len as usize > HEVC_MAX_EXT_BYTES {
            return Err(StrHideError::CorruptedData(format!(
                "HEVC content ext_len {ext_len} is above {HEVC_MAX_EXT_BYTES}"
            )));
        }
        if crate::crypto::CipherSuiteId::from_u16(suite_id).is_none() {
            return Err(StrHideError::UnsupportedVersion(format!(
                "Unknown HEVC content cipher suite id {suite_id}"
            )));
        }
        let body_overhead = crate::stego::envelope::BODY_OVERHEAD as u32;
        let body_max = crate::stego::header::HEADER_LEN_MAX;
        if body_len < body_overhead || body_len > body_max {
            return Err(StrHideError::CorruptedData(format!(
                "HEVC content body_len {body_len} is outside {body_overhead}..={body_max}"
            )));
        }

        let expected_crc = u32::from_be_bytes(bytes[28..32].try_into().expect("4-byte crc"));
        let actual_crc = crc32fast::hash(&bytes[..HEVC_V4_CRC_SPAN]);
        if actual_crc != expected_crc {
            return Err(StrHideError::CorruptedData(format!(
                "HEVC content header CRC mismatch: stored {expected_crc:08x}, computed {actual_crc:08x}"
            )));
        }

        Ok(Self {
            magic,
            version,
            flags,
            stc_u,
            window_slices,
            ext_len,
            suite_id,
            body_len,
            nonce,
        })
    }

    /// Whether the extension area is present.
    pub fn ext_present(&self) -> bool {
        self.flags & crate::stego::header::FLAG_EXT_PRESENT != 0
    }

    /// Whether at least one extension TLV is critical.
    pub fn ext_critical(&self) -> bool {
        self.flags & crate::stego::header::FLAG_EXT_CRITICAL != 0
    }
}

/// Early-exit stopping condition for streaming NAL decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopCondition {
    /// Full scan (for probe_hevc_capacity).
    All,
    /// Stop as soon as at least `min_slots` are accumulated (for Superblock probing).
    MinSlots(usize),
    /// Stop after `target` recorded slices (for window extraction).
    TargetSlices(usize),
    /// Stop as soon as at least `target` slots are accumulated (for window embedding).
    TargetSlots(usize),
}

/// Keyed slot permutation of the header area.
///
/// The first `HEVC_SUPERBLOCK_MIN_SLOTS` slots carry the base header; the
/// following `hevc_extension_slots(ext_len)` slots carry the extension TLV
/// area. Both are the *prefix* of one permutation driven by the L2
/// `locate_seed`, so the extractor reads the base first and can extend to the
/// continuation slots only after learning `ext_len` from it.
pub fn superblock_positions(
    pool_size: usize,
    locate_seed: &[u8; 32],
    ext_len: usize,
) -> Vec<usize> {
    let count = HEVC_SUPERBLOCK_MIN_SLOTS + hevc_extension_slots(ext_len);
    debug_assert!(count <= pool_size, "header area fits the candidate pool");
    keyed_positions(pool_size, count, locate_seed)
}

/// Keyed permutation prefix over `0..len`: `(start + i * stride) mod len`.
///
/// `stride` is derived from the credential-bound seed and is coprime with
/// `len`, so each requested prefix is distinct. Element `i` never depends on
/// `count`, which keeps the header permutation prefix-stable in the same way
/// [`band_positions`] keeps the body permutation stable.
fn keyed_positions(len: usize, count: usize, seed: &[u8; 32]) -> Vec<usize> {
    let count = count.min(len);
    let mut out = Vec::with_capacity(count);
    if len == 0 {
        return out;
    }
    let (start, stride) = keyed_band_params(len, seed, 0);
    for i in 0..count {
        out.push(((start as u64 + i as u64 * stride as u64) % len as u64) as usize);
    }
    out
}

/// Start and stride of a keyed band permutation, derived from `perm_seed`.
///
/// `band_start` (not the band's ordinal) perturbs the derivation, so inserting
/// an empty band never shifts the mapping of a later band.
fn keyed_band_params(len: usize, perm_seed: &[u8; 32], band_start: usize) -> (usize, usize) {
    // Fold the 32-byte key sequentially through SplitMix64. (A plain XOR of
    // the four words cancels repeated blocks, so a low-entropy or patterned
    // seed could collapse to the same permutation.)
    let mut seed = 0x243F_6A88_85A3_08D3u64;
    for chunk in perm_seed.as_chunks::<8>().0 {
        seed = splitmix64(seed ^ u64::from_le_bytes(*chunk));
    }
    seed ^= (band_start as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let start = (splitmix64(seed) % len as u64) as usize;
    let mut stride = (splitmix64(seed ^ 0xA5A5_5A5A_3C3C_C3C3) % len as u64) as usize;
    stride = stride.max(1);
    while gcd_usize(stride, len) != 1 {
        stride += 1;
        if stride >= len {
            stride = 1;
            break;
        }
    }
    (start, stride)
}

/// SplitMix64 finalizer: a cheap, well-distributed 64-bit mixer.
fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Partition non-Superblock slots within the window into Band 0 and Band 1 stream indices.
fn get_body_slot_indices(
    total_slots: usize,
    pool_size: usize,
    sb_positions: &[usize],
    slice_slot_ranges: &[(usize, u8)],
) -> (Vec<usize>, Vec<usize>) {
    let pool_limit = pool_size.min(total_slots);
    let mut is_sb_small = vec![false; pool_limit];
    for &pos in sb_positions {
        if pos < pool_limit {
            is_sb_small[pos] = true;
        }
    }
    let mut band0 = Vec::new();
    let mut band1 = Vec::new();
    let mut current_slot = 0usize;
    for &(count, band) in slice_slot_ranges {
        let end_slot = (current_slot + count).min(total_slots);
        if current_slot >= end_slot {
            current_slot += count;
            continue;
        }
        let target = if band == 0 { &mut band0 } else { &mut band1 };
        if current_slot < pool_limit {
            let prefix_end = end_slot.min(pool_limit);
            for (offset, &is_sb) in is_sb_small[current_slot..prefix_end].iter().enumerate() {
                if !is_sb {
                    target.push(current_slot + offset);
                }
            }
            if end_slot > pool_limit {
                target.extend(pool_limit..end_slot);
            }
        } else {
            target.extend(current_slot..end_slot);
        }
        current_slot += count;
    }
    (band0, band1)
}

/// Where a flipped bypass bin landed in the codeword:
/// `(global slot index, first affected RBSP byte, last affected RBSP byte)`.
type SlotBitTrace = (usize, usize, usize);

/// A disturbed emulation-prevention window: the RBSP byte that starts the
/// `00 00 xx<=3` triple, plus the trace of every flipped slot in that slice.
type EpbConflict = (usize, Vec<SlotBitTrace>);

/// Header slots of a carrier with `ext_len` extension bytes.
fn hevc_header_slots(ext_len: usize) -> usize {
    HEVC_SUPERBLOCK_MIN_SLOTS + hevc_extension_slots(ext_len)
}

/// Slots the writer must decode before it can place the header and body.
///
/// The floor is `HEVC_SUPERBLOCK_POOL_SLOTS`, the same upper bound the reader
/// records in its first pass. Both sides derive the keyed header permutation
/// from `recorded_slots.min(POOL_SLOTS)`, so a smaller write window would move
/// the header to different slot positions and make the carrier unreadable.
fn hevc_window_target_slots(hdr_slots: usize, desired_body_slots: usize) -> usize {
    (hdr_slots + desired_body_slots + 128).max(HEVC_SUPERBLOCK_POOL_SLOTS)
}

/// Serialize the extension area and enforce the HEVC upper bound.
fn extension_len(extensions: &[Tlv]) -> Result<usize, StrHideError> {
    let len = encode_extension_for_write(extensions)?.len();
    if len > HEVC_MAX_EXT_BYTES {
        return Err(StrHideError::UnsupportedFormat(format!(
            "HEVC extension area is {len} bytes, maximum is {HEVC_MAX_EXT_BYTES}"
        )));
    }
    Ok(len)
}

/// L3 session salt: domain-separated SHA-256 of the header nonce.
fn hevc_session_salt(nonce: &[u8; 12]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"strhide-hevc-session-v4");
    hasher.update(nonce);
    hasher.finalize().into()
}

fn has_critical_tlv(extensions: &[Tlv]) -> bool {
    extensions.iter().any(Tlv::is_critical)
}

/// Critical-bit check over raw tag bytes read back from the extension area.
fn tags_have_critical(tags: &[u8]) -> bool {
    tags.iter().any(|tag| tag & TLV_CRITICAL != 0)
}

/// Maximum plaintext payload bytes a carrier can hold.
///
/// This is the single capacity formula shared by `probe` and `embed`:
///
/// ```text
/// hdr_slots   = HEVC_SUPERBLOCK_MIN_SLOTS + hevc_extension_slots(ext_len)
/// body_slots  = total_slots - hdr_slots
/// max_body    = message_bits(body_slots) / 8
/// max_payload = max_body - BODY_OVERHEAD
/// ```
///
/// `hevc_extension_slots(ext_len) = u * (8 * ext_len + h - 1)` with `h=7, u=2`,
/// so the extension slots scale with the *message bits* (`8 * ext_len`), not
/// with `ext_len` alone.
///
/// `body_len` on the wire is the AEAD ciphertext length *including the tag*,
/// so `BODY_OVERHEAD` (4-byte length + flags + tag) is the whole bookkeeping
/// cost. There is no separate `fmt.header_bytes + 1` or `HEVC_TAG_BYTES`
/// subtraction anymore.
fn hevc_max_raw_payload(
    total_slots: usize,
    ext_len: usize,
    fmt: &HevcFormatProfile,
) -> Result<usize, StrHideError> {
    let hdr_slots = hevc_header_slots(ext_len);
    if total_slots < hdr_slots {
        return Ok(0);
    }
    let trellis = StcTrellis::from_seed_grouped(CAPACITY_PROBE_SEED, fmt.stc_h, fmt.stc_u)?;
    let body_slots = total_slots - hdr_slots;
    let available_bits = trellis.message_bits(body_slots);
    Ok((available_bits / 8).saturating_sub(BODY_OVERHEAD))
}

/// Capacity probe: maximum embeddable payload size in bytes, without extensions.
pub fn probe_hevc_capacity(carrier: &[u8], fmt: &HevcFormatProfile) -> Result<usize, StrHideError> {
    probe_hevc_capacity_ext(carrier, &[], fmt)
}

/// Capacity probe with the same extension area the writer will use.
///
/// The `ext_len` is the decisive part of `probe == embed`: a probe that ignores
/// the extension slots advertises bytes the writer cannot place.
pub fn probe_hevc_capacity_ext(
    carrier: &[u8],
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
) -> Result<usize, StrHideError> {
    sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    let ext_len = extension_len(extensions)?;
    let total_slots = scan_hevc_slot_count(carrier)?;
    hevc_max_raw_payload(total_slots, ext_len, fmt)
}

/// Cropped output geometry of an SPS in luma samples (§7.4.3.2.1).
///
/// `rusty_h265` reports the coded size plus the conformance-window offsets in
/// chroma units; the crop is scaled by `SubWidthC`/`SubHeightC` (Table 6-1).
/// For 4:2:0 — every carrier this engine accepts — that is 2/2.
fn sps_dimensions(rbsp: &[u8]) -> Option<(u32, u32)> {
    let sps = parse_sps(rbsp).ok()?;
    let (sub_w, sub_h): (u32, u32) = match sps.chroma_format_idc {
        1 => (2, 2),
        2 => (2, 1),
        _ => (1, 1),
    };
    let crop_w = sub_w.saturating_mul(sps.conf_win[0].saturating_add(sps.conf_win[1]));
    let crop_h = sub_h.saturating_mul(sps.conf_win[2].saturating_add(sps.conf_win[3]));
    Some((
        sps.width.saturating_sub(crop_w),
        sps.height.saturating_sub(crop_h),
    ))
}

/// Extracts the picture dimensions `(width, height)` in luma samples from the carrier's SPS.
pub fn extract_hevc_dimensions(carrier: &[u8]) -> Result<(u32, u32), StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    match kind {
        HevcCarrierKind::HeifContainer => {
            let target = parse_heif_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("HEIF parse error: {e}")))?;
            if let Some(dims) = target.dimensions {
                return Ok(dims);
            }
            for ps in &target.parameter_sets {
                if ps.len() > 2
                    && (ps[0] >> 1) & 0x3F == NAL_SPS_NUT
                    && let Some(dims) = sps_dimensions(&nal_rbsp(ps))
                {
                    return Ok(dims);
                }
            }
        }
        HevcCarrierKind::AnnexBStream => {
            let spans = parse_annex_b_spans(carrier);
            for span in &spans {
                if span.nal_type == NAL_SPS_NUT {
                    let end = span.end_offset().min(carrier.len());
                    let nal = &carrier[span.header_offset..end];
                    if nal.len() > 2
                        && let Some(dims) = sps_dimensions(&nal_rbsp(nal))
                    {
                        return Ok(dims);
                    }
                }
            }
        }
        // MP4 and MKV both carry the authoritative SPS in their
        // `HEVCDecoderConfigurationRecord`, so they share this arm.
        HevcCarrierKind::Mp4Container | HevcCarrierKind::MkvContainer => {
            let parameter_sets = match kind {
                HevcCarrierKind::MkvContainer => {
                    crate::stego::hevc::mkv_boxes::parse_mkv_parameter_sets(carrier).map_err(
                        |e| StrHideError::UnsupportedFormat(format!("MKV parse error: {e}")),
                    )?
                }
                _ => {
                    parse_mp4_targets(carrier)
                        .map_err(|e| {
                            StrHideError::UnsupportedFormat(format!("MP4/MOV parse error: {e}"))
                        })?
                        .parameter_sets
                }
            };
            // The sample entries carry no size of their own that can be
            // trusted (they duplicate the SPS, and some writers leave them
            // wrong); the `hvcC` SPS is the same one the decoder will use.
            for ps in &parameter_sets {
                if ps.len() > 2
                    && (ps[0] >> 1) & 0x3F == NAL_SPS_NUT
                    && let Some(dims) = sps_dimensions(&nal_rbsp(ps))
                {
                    return Ok(dims);
                }
            }
        }
    }

    Err(StrHideError::General(
        "No valid SPS found in HEVC carrier".into(),
    ))
}

/// Full capacity probe returning structured [`StegoCapacityInfo`], with recommended
/// payload capacity scaled by the caller's [`SafetyLevel`] and carrier dimensions.
///
/// If `exact` is false, carriers with >150 selectable slices employ fast 20%
/// sample-weighted estimation to deliver sub-second probe responses.
pub fn probe_hevc_capacity_info(
    carrier: &[u8],
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    safety_level: SafetyLevel,
    exact: bool,
    control: &Control<'_>,
) -> Result<StegoCapacityInfo, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    let ext_len = extension_len(extensions)?;
    control.stage(Stage::Decode);
    let pool = probe_hevc_pool(carrier, kind, exact, control)?;
    // The pool scan is the long part of an exact probe; report before the
    // (cheap) summary is built so a cancellation lands after the scan, not
    // silently in the middle of it.
    control.check()?;
    build_hevc_capacity_info(carrier, kind, fmt, &pool, ext_len, safety_level)
}

fn count_absorbed_slots(recorder: &mut CabacRecorder, rbsp: &[u8]) -> usize {
    let is_multi_sub = recorder.substreams.len() > 1;
    let mut excluded = std::collections::HashSet::new();
    if is_multi_sub {
        for sub in &recorder.substreams {
            if sub.rbsp_byte_start <= sub.rbsp_byte_end && sub.rbsp_byte_end <= rbsp.len() {
                let sub_data = &rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end];
                if sub_data
                    .windows(3)
                    .any(|w| w[0] == 0 && w[1] == 0 && w[2] <= 3)
                {
                    excluded.insert(sub.substream_idx);
                }
            }
        }
    }
    if is_multi_sub && !excluded.is_empty() {
        recorder
            .slots
            .iter()
            .filter(|s| !excluded.contains(&(s.substream_idx as usize)))
            .count()
    } else {
        recorder.slots.len()
    }
}

fn probe_hevc_pool(
    carrier: &[u8],
    kind: HevcCarrierKind,
    exact: bool,
    control: &Control<'_>,
) -> Result<PoolProfile, StrHideError> {
    if kind != HevcCarrierKind::Mp4Container || exact {
        let record =
            record_carrier_state(carrier, kind, Capture::Count, StopCondition::All, control)?;
        return Ok(PoolProfile::from_record(&record));
    }

    let target = parse_mp4_targets(carrier)
        .map_err(|e| StrHideError::UnsupportedFormat(format!("MP4/MOV parse error: {e}")))?;

    let mut decoder = Decoder::new();
    decoder.skip_loop_filters = true;
    decoder.ablate = Ablate {
        mc: true,
        intra: true,
        residual: true,
    };

    let mut decode_error: Option<String> = None;
    for ps in &target.parameter_sets {
        if let Err(e) = decoder.push_nal(ps, None) {
            decode_error.get_or_insert_with(|| format!("parameter set: {e}"));
        }
    }

    let mut candidates = Vec::with_capacity(target.slice_spans.len());
    for span in &target.slice_spans {
        if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
            candidates.push(cand);
        }
    }

    let has_inter = candidates.iter().any(|c| !is_irap(c.nal_type));

    // Pictures and per-band picture counts are exact and free: slice headers are
    // not decoded, only `first_slice_segment_in_pic_flag` is read.
    let (pictures, band_pictures) = count_pictures(carrier, kind, &candidates, has_inter);
    let mut band_total_bytes = [0usize; 2];
    let mut selectable = 0usize;
    for cand in &candidates {
        let band = picture_band(cand.nal_type, has_inter);
        if let Some(b) = band {
            band_total_bytes[b as usize] += cand.span.len();
            selectable += 1;
        }
    }

    // 150 pictures or fewer: full scan (0% estimation error, fast enough)
    if selectable <= 150 {
        let record =
            record_carrier_state(carrier, kind, Capture::Count, StopCondition::All, control)?;
        return Ok(PoolProfile::from_record(&record));
    }

    // Sample 20%, clamped to [150, 1000]
    let sample_limit = ((selectable as f64 * 0.20).round() as usize).clamp(150, 1000);
    let mut recorded_slices = 0usize;
    let mut band_recorded_slots = [0usize; 2];
    let mut band_sampled_bytes = [0usize; 2];

    control.stage_sized(Stage::Decode, sample_limit as u64);

    for (c_idx, cand) in candidates.iter().enumerate() {
        if c_idx % 16 == 0 {
            control.check()?;
            control.report(Event::progress(
                Stage::Decode,
                recorded_slices as u64,
                Some(sample_limit as u64),
            ));
        }
        let slice_bytes = &carrier[cand.span.clone()];
        if slice_bytes.len() < 2 {
            continue;
        }
        let Some(band) = picture_band(cand.nal_type, has_inter) else {
            if let Err(e) = decoder.push_nal(slice_bytes, None) {
                decode_error.get_or_insert_with(|| e.to_string());
            }
            drain_frames(&mut decoder);
            continue;
        };

        if recorded_slices >= sample_limit {
            break;
        }

        let mut recorder = CabacRecorder::with_slice_capacity(
            recorded_slices,
            band,
            RecordMode::Slots,
            slice_bytes.len(),
        );
        let decoded = decoder.decode_nal_with_observer(slice_bytes, &mut recorder);
        drain_frames(&mut decoder);

        match decoded {
            Err(e) => {
                decode_error.get_or_insert_with(|| e.to_string());
            }
            Ok(_) if recorder.substreams.is_empty() => {}
            Ok(_) => {
                let absorbed = if recorder.substreams.len() > 1 {
                    let rbsp = nal_rbsp(slice_bytes);
                    count_absorbed_slots(&mut recorder, &rbsp)
                } else {
                    count_absorbed_slots(&mut recorder, &[])
                };
                band_recorded_slots[band as usize] += absorbed;
                band_sampled_bytes[band as usize] += cand.span.len();
                recorded_slices += 1;
            }
        }
    }

    if recorded_slices == 0
        && let Some(reason) = decode_error
    {
        return Err(StrHideError::UnsupportedFormat(format!(
            "HEVC carrier could not be decoded: {reason}"
        )));
    }

    // Scale each band by its own byte ratio: the two bands have very different
    // slot densities (a reference picture carries 2-3x the residual of a
    // non-reference one), so a single global ratio would bias the estimate.
    let mut band_slots = [0usize; 2];
    for b in 0..2 {
        band_slots[b] = if band_sampled_bytes[b] > 0 {
            ((band_recorded_slots[b] as f64 / band_sampled_bytes[b] as f64)
                * band_total_bytes[b] as f64)
                .round() as usize
        } else {
            0
        };
    }

    Ok(PoolProfile {
        total_slots: band_slots[0] + band_slots[1],
        band_slots,
        band_pictures,
        pictures,
        is_estimated: true,
    })
}

/// Slots per modification of the payload budget: one payload bit occupies
/// `stc_u = 2` slots and about a quarter of the selected slots get flipped, so
/// one flip corresponds to four slots. Used to turn "flips per reference
/// picture" into a slot budget.
const SLOTS_PER_REF_FLIP: usize = 4;

/// Helper to construct [`StegoCapacityInfo`] from the recorded pool geometry.
///
/// Two different policies meet here, because a still picture and a video do not
/// distort the same way:
///
/// * **Still carrier** (one picture): the payload is bounded by
///   `min(bpp_limit * pixels, slots / target_ratio)`, the still-image anchors
///   calibrated on DIV2K.
/// * **Video** (more than one picture): those anchors do not work. `bpp * pixels`
///   ignores length (it pinned every 1080p video to 25.3 KiB), and
///   `slots / target_ratio` bounds the fraction of the *pool*, while the real
///   damage comes from flips in pictures that later pictures predict from. The
///   budget is therefore spent on the drift ladder: a fraction of the
///   drift-free band, plus a fixed number of flips per reference picture.
pub(crate) fn build_hevc_capacity_info(
    carrier: &[u8],
    kind: HevcCarrierKind,
    fmt: &HevcFormatProfile,
    pool: &PoolProfile,
    ext_len: usize,
    safety_level: SafetyLevel,
) -> Result<StegoCapacityInfo, StrHideError> {
    let format_name = kind.label();

    let total_slots = pool.total_slots;
    let trellis = StcTrellis::from_seed_grouped(CAPACITY_PROBE_SEED, fmt.stc_h, fmt.stc_u)?;
    let hdr_slots = hevc_header_slots(ext_len);

    let max_raw_payload_bytes = hevc_max_raw_payload(total_slots, ext_len, fmt)?;

    // Extract picture dimensions from SPS to derive the true element count.
    // That count is pixels times pictures: the per-frame version was the bug
    // that made a 13.6 s video and a 6.4 s video recommend the same 25.3 KiB.
    let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
    let picture_count = pool.pictures.max(1);
    let total_pixels = (width as usize) * (height as usize);
    let total_elements = if total_pixels > 0 {
        total_pixels.saturating_mul(picture_count)
    } else {
        total_slots
    };

    // Usable slots the tier's drift ladder allows, for one tier. Written once so
    // the probe's recommendation and the `[paranoid, high, balanced]` table the
    // GUI reads cannot drift apart.
    let target_bits_for = |level: SafetyLevel| -> usize {
        if picture_count > 1 {
            let budget = level.video_budget();
            let non_ref_slots =
                (pool.band_slots[0] as f64 * budget.non_ref_fraction).floor() as usize;
            let ref_slots = budget
                .ref_flips_per_picture
                .saturating_mul(pool.band_pictures[1])
                .saturating_mul(SLOTS_PER_REF_FLIP)
                .min(pool.band_slots[1]);
            let ladder_slots = non_ref_slots.saturating_add(ref_slots);
            // The writer's own gate (see `embed_hevc_patches_with_factor`) sizes
            // the stream window as `body_needed * (1 / non_ref_fraction)`, so it
            // only accepts `body_needed <= (total - SUPERBLOCK) * non_ref_fraction`.
            // Without this clamp the ladder alone could advertise a payload the
            // embedder then rejected: on an all-I/P stream every slot sits in the
            // reference band, so `ref_slots` alone is a large promise the gate
            // never honours.
            let gate_slots = ((total_slots.saturating_sub(hdr_slots) as f64)
                * budget.non_ref_fraction)
                .floor() as usize;
            trellis.message_bits(ladder_slots.min(gate_slots))
        } else {
            let bpp_bits = (total_elements as f64 * level.bpp_limit()).floor() as usize;
            let ratio_bits = (total_slots as f64 / level.target_ratio()).floor() as usize;
            bpp_bits.min(ratio_bits)
        }
    };
    let recommended_for = |level: SafetyLevel| -> usize {
        (target_bits_for(level) / 8)
            .saturating_sub(BODY_OVERHEAD)
            .min(max_raw_payload_bytes)
    };
    let recommended_max_bytes = recommended_for(safety_level);
    let tier_limits = SafetyLevel::ALL.map(recommended_for);

    let media_info = if width > 0 && height > 0 {
        let base = MediaInfo::new(width, height);
        let video = if kind == HevcCarrierKind::Mp4Container {
            parse_mp4_targets(carrier).ok().and_then(|target| {
                let fps = target.fps?;
                let sec = target.duration_secs?;
                let bps = if sec > 0.0 {
                    (carrier.len() as f64 * 8.0) / sec
                } else {
                    0.0
                };
                Some((fps, sec, bps))
            })
        } else {
            None
        };
        Some(match video {
            Some((fps, sec, bps)) => base.with_video(
                fps as f32,
                (sec * 1000.0).round() as u64,
                bps.round() as u64,
            ),
            None => base,
        })
    } else {
        None
    };

    Ok(StegoCapacityInfo {
        format: format_name.into(),
        algorithm: "HEVC-CABAC-InPlace".into(),
        total_elements,
        available_slots: total_slots,
        max_raw_payload_bytes,
        max_raw_is_grouped: false,
        recommended_max_bytes,
        tier_limits,
        estimated_change_rate: 0.25,
        safety_level: safety_level.as_str().into(),
        safety_bpp_limit: safety_level.bpp_limit(),
        is_estimated: pool.is_estimated,
        media_info,
    })
}

/// Refuse a payload that is above the enforced safety tier.
///
/// Takes plain numbers instead of a [`StegoCapacityInfo`] so the policy decision
/// is unit-testable without a carrier: the bug this guards against was passing
/// only `SafetyLevel` down the call chain, which silently dropped
/// `SafetyEnforcement::Enforced` and made `--enforce-safety` a no-op for every
/// HEVC carrier.
fn enforce_safety(
    payload_len: usize,
    recommended_max_bytes: usize,
    _max_raw_payload_bytes: usize,
    safety: SafetyPolicy,
) -> Result<(), StrHideError> {
    if !safety.is_enforced() || payload_len <= recommended_max_bytes {
        return Ok(());
    }
    Err(StrHideError::SafetyThreshold {
        tier: safety.level,
        required_bytes: payload_len,
        available_bytes: recommended_max_bytes,
    })
}

/// Embed a payload into an HEVC/HEIC carrier using content-adaptive sign-bit steganography.
///
/// The complete expert entry. `secret` is the resolved credential (explicit
/// password, else the profile's private stego secret, else `None` for the
/// official public constant); `domain` isolates the HKDF derivation; `fmt` is
/// the wire-format identity; `freshness` supplies the nonce (`Seeded` makes
/// the output reproducible for the same inputs); `safety` is the full policy,
/// so `Enforced` blocks an over-tier payload instead of only warning.
/// An in-place modification patch for an HEVC carrier: `(byte_range, replacement_nal_bytes)`.
pub type HevcCarrierPatch = (std::ops::Range<usize>, Vec<u8>);

/// Check that every patch fits the carrier it will be applied to.
///
/// The patch list is produced by the HEVC scanner itself, so a mismatch here
/// means an engine invariant broke. Validating before the copy keeps that
/// internal failure a normal error instead of a slice-index panic, which
/// `panic = "abort"` would turn into process termination.
fn validate_hevc_patches(
    carrier_len: usize,
    patches: &[HevcCarrierPatch],
) -> Result<(), StrHideError> {
    for (index, (span, re_nal)) in patches.iter().enumerate() {
        if span.start > span.end || span.end > carrier_len || re_nal.len() != span.len() {
            return Err(StrHideError::General(format!(
                "HEVC patch {index} does not fit the carrier: span {span:?}, {} replacement bytes, carrier {carrier_len} bytes",
                re_nal.len()
            )));
        }
    }
    Ok(())
}

/// Apply in-place NAL patches to a mutable carrier buffer.
///
/// Panics on a patch whose span falls outside `carrier` or whose replacement
/// length differs from the span length; callers that build patches dynamically
/// must verify them first (`validate_hevc_patches`). The production embed path
/// does exactly that, so this panic is reachable only for direct misuse.
pub fn apply_hevc_patches(carrier: &mut [u8], patches: &[HevcCarrierPatch]) {
    for (span, re_nal) in patches {
        debug_assert!(
            span.start <= span.end && span.end <= carrier.len() && re_nal.len() == span.len(),
            "HEVC patch {span:?} does not fit the {} byte carrier",
            carrier.len()
        );
        carrier[span.clone()].copy_from_slice(re_nal);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_with_info(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<(Vec<u8>, StegoCapacityInfo, crate::stego::EmbedStats), StrHideError> {
    embed_hevc_with_info_v4(
        carrier,
        payload,
        legacy_credential(secret),
        domain,
        fmt.cipher.default_suite.as_u16(),
        &[],
        fmt,
        freshness,
        safety,
        control,
    )
}

/// Credential-aware embed with the full V4 options.
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_with_info_v4(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<(Vec<u8>, StegoCapacityInfo, crate::stego::EmbedStats), StrHideError> {
    let (patches, capacity_info, stats) = embed_hevc_patches_v4(
        carrier, payload, cred, domain, suite_id, extensions, fmt, freshness, safety, control,
    )?;
    let mut out_carrier = carrier.to_vec();
    validate_hevc_patches(out_carrier.len(), &patches)?;
    apply_hevc_patches(&mut out_carrier, &patches);

    // A Matroska muxer covers every finalised element with a CRC-32; the
    // patches above invalidate any checksum that covers a modified block.
    // Refresh here, on the single in-memory entry every caller reaches, so a
    // direct library user gets the same valid file as `MkvEngine` did.
    if sniff_hevc_carrier(carrier) == Some(HevcCarrierKind::MkvContainer) {
        refresh_mkv_crcs(carrier, &mut out_carrier).map_err(|e| {
            StrHideError::CorruptedData(format!("MKV checksum refresh failed: {e}"))
        })?;
    }

    Ok((out_carrier, capacity_info, stats))
}

/// Embed a payload into an HEVC carrier and return in-place NAL delta patches.
///
/// This avoids cloning or mutating the entire carrier in memory, allowing zero-heap-overhead
/// streaming commit to disk via `commit_carrier_patches`.
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_patches(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    embed_hevc_patches_with_factor(
        carrier, payload, secret, domain, fmt, freshness, safety, control, 1.0,
    )
}

/// Credential-aware patch embed with the full V4 options.
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_patches_v4(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    embed_hevc_patches_with_factor_v4(
        carrier, payload, cred, domain, suite_id, extensions, fmt, freshness, safety, control, 1.0,
    )
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_patches_with_factor(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
    window_factor: f64,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    embed_hevc_patches_with_factor_v4(
        carrier,
        payload,
        legacy_credential(secret),
        domain,
        fmt.cipher.default_suite.as_u16(),
        &[],
        fmt,
        freshness,
        safety,
        control,
        window_factor,
    )
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn embed_hevc_patches_with_factor_v4(
    carrier: &[u8],
    payload: &Payload<'_>,
    cred: Credential<'_>,
    domain: Option<&str>,
    suite_id: u16,
    extensions: &[Tlv],
    fmt: &HevcFormatProfile,
    freshness: Freshness,
    safety: SafetyPolicy,
    control: &Control<'_>,
    window_factor: f64,
) -> Result<
    (
        Vec<HevcCarrierPatch>,
        StegoCapacityInfo,
        crate::stego::EmbedStats,
    ),
    StrHideError,
> {
    if payload.is_empty() {
        return Err(StrHideError::General("Cannot embed empty payload".into()));
    }
    let suite = CipherSuiteId::from_u16(suite_id).ok_or_else(|| {
        StrHideError::UnsupportedVersion(format!("Unknown content cipher suite id {suite_id}"))
    })?;
    let ext_len = extension_len(extensions)?;
    let extension = encode_extension_for_write(extensions)?;

    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. Calculate required capacity and stream window
    let plaintext = build_plaintext(payload)?;
    let body_msg_len = plaintext.len() + suite.tag_len();
    let body_needed_slots = StcTrellis::slots_for_params(body_msg_len * 8, fmt.stc_h, fmt.stc_u);
    let hdr_slots = hevc_header_slots(ext_len);
    let non_ref_fraction = safety.level.video_budget().non_ref_fraction;
    let factor = if window_factor > 1.0 {
        window_factor
    } else if kind == HevcCarrierKind::HeifContainer {
        1.0
    } else {
        (1.0 / non_ref_fraction).max(1.0)
    };
    let desired_body_slots = ((body_needed_slots as f64) * factor).ceil() as usize;
    // The writer must decode at least as many slots as the reader's first pass
    // (`StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS)`). Both sides derive
    // the header permutation from `pool_size = recorded_slots.min(POOL_SLOTS)`;
    // a smaller write window would place the header over a different pool size
    // and make small payloads unreadable on large carriers.
    let target_slots = hevc_window_target_slots(hdr_slots, desired_body_slots);

    control.stage(Stage::Decode);
    // MP4 keeps the sampled probe as the capacity contract; every other
    // container reports exact slots, so the window pass can count the rest of
    // the carrier itself and skip the second full decode.
    let exact_capacity = kind != HevcCarrierKind::Mp4Container;
    let record = if exact_capacity {
        record_carrier_state_with_capacity(
            carrier,
            kind,
            Capture::Full,
            StopCondition::TargetSlots(target_slots),
            control,
        )?
    } else {
        record_carrier_state(
            carrier,
            kind,
            Capture::Full,
            StopCondition::TargetSlots(target_slots),
            control,
        )?
    };
    control.check()?;
    control.stage(Stage::Solve);
    let pool = PoolProfile::from_record(&record);
    // Capacity is a property of the whole carrier, not of the write window:
    // `TargetSlots` deliberately stops recording once the payload needs are
    // met, so building the report from `pool` under-reports by the ratio of
    // carrier capacity to the window (measured 112x on a 12 MB MKV). Reuse the
    // same pool the probe uses instead of inventing a second estimator.
    //
    // A record whose slot count stayed below `target_slots` cannot have hit the
    // early stop, so it already covers the whole carrier and needs no second
    // decode pass. The same is true when the recording pass kept counting after
    // the stop (`capacity_band_counts` is whole-carrier by construction).
    let capacity_pool;
    let capacity_source =
        if record.capacity_band_counts.is_some() || record.total_slots() < target_slots {
            &pool
        } else {
            capacity_pool = probe_hevc_pool(carrier, kind, false, control)?;
            &capacity_pool
        };
    let capacity_info =
        build_hevc_capacity_info(carrier, kind, fmt, capacity_source, ext_len, safety.level)?;

    enforce_safety(
        payload.len(),
        capacity_info.recommended_max_bytes,
        capacity_info.max_raw_payload_bytes,
        safety,
    )?;

    let slice_contexts = record.slice_contexts;
    let all_slots = record.all_slots;
    let total_slots = all_slots.len();
    let pool_size = total_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);

    if pool_size < hdr_slots || total_slots < hdr_slots + body_needed_slots {
        return Err(StrHideError::PayloadTooLarge(format!(
            "HEVC carrier capacity exceeded: needed at least {} slots, but carrier only has {}",
            hdr_slots + body_needed_slots,
            total_slots
        )));
    }

    // A container that only ever holds video is a video carrier regardless of
    // how many pictures it has; an Annex-B stream or a HEIF still is judged by
    // the picture count.
    let is_video = matches!(
        kind,
        HevcCarrierKind::Mp4Container | HevcCarrierKind::MkvContainer
    ) || record.pictures > 1;
    if is_video && total_slots < hdr_slots + desired_body_slots {
        let current_tier = safety.level.as_str();
        let hint = match safety.level {
            SafetyLevel::Paranoid => {
                "carrier capacity insufficient for paranoid tier (0.1 budget); try '--safety high' (0.2) or '--safety balanced' (0.4)"
            }
            SafetyLevel::High => {
                "carrier capacity insufficient for default high tier (0.2 budget); try '--safety balanced' (0.4)"
            }
            SafetyLevel::Balanced => {
                "carrier capacity insufficient for balanced tier (0.4 budget); payload is too large for this carrier"
            }
        };
        return Err(StrHideError::General(format!(
            "HEVC capacity insufficient for tier '{current_tier}': needed {needed} slots ({factor:.1}x sparsity), carrier only has {available} slots. Hint: {hint}",
            needed = hdr_slots + desired_body_slots,
            available = total_slots,
        )));
    }

    // 2. L1/L2 locator, session keys and keyed slot plans
    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    let master = derive_locator_master(cred, domain, fmt.cipher, &cover_digest)?;
    let locator = derive_l2_locator_keys(&master, fmt.cipher, fmt.magic_label, domain)?;

    let fresh_binding =
        Freshness::seeded_binding(carrier, payload.as_bytes(), HEVC_FORMAT_ID, &extension);
    let nonce_bytes = freshness.nonce(0, &fresh_binding);
    let session = derive_l3_session_keys(
        fmt.cipher,
        suite,
        &master,
        &hevc_session_salt(&nonce_bytes),
        domain,
    )?;

    let header_positions = superblock_positions(pool_size, &locator.locate_seed, ext_len);
    let (body_band0, body_band1) = get_body_slot_indices(
        total_slots,
        pool_size,
        &header_positions,
        &record.slice_slot_ranges,
    );
    let body_bands = vec![
        0..body_band0.len(),
        body_band0.len()..(body_band0.len() + body_band1.len()),
    ];
    let mut all_body_indices = body_band0;
    all_body_indices.extend(body_band1);
    let body_positions_rel = band_positions(&body_bands, body_needed_slots, &session.perm_seed);
    let body_positions: Vec<usize> = body_positions_rel
        .into_iter()
        .map(|rel| all_body_indices[rel])
        .collect();

    // 3. Prepare Superblock, extension area and AEAD ciphertext
    let window_slices = u16::try_from(slice_contexts.len()).map_err(|_| {
        StrHideError::UnsupportedFormat(format!(
            "HEVC carrier has {} slices, exceeding the superblock window slice limit (65535)",
            slice_contexts.len()
        ))
    })?;

    let flags = (if ext_len > 0 { FLAG_EXT_PRESENT } else { 0 })
        | (if has_critical_tlv(extensions) {
            FLAG_EXT_CRITICAL
        } else {
            0
        });
    let body_len = u32::try_from(body_msg_len).map_err(|_| {
        StrHideError::General("HEVC payload exceeds the 32-bit body length field".into())
    })?;
    let sb = HevcSuperblockV4 {
        magic: locator.magic4,
        version: CONTENT_ENVELOPE_VERSION,
        flags,
        stc_u: fmt.stc_u,
        window_slices,
        ext_len: ext_len as u8,
        suite_id,
        body_len,
        nonce: nonce_bytes,
    };
    let sb_bytes = sb.encode();
    let aad = build_v4_aad(HEVC_FORMAT_ID, &sb_bytes, &extension);
    let ciphertext = encrypt_v4_with_aad(suite, &session.enc_key, &nonce_bytes, &aad, &plaintext)?;

    let sb_trellis =
        StcTrellis::from_seed_grouped(locator.header_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)?;
    let ext_trellis =
        StcTrellis::from_seed_grouped(locator.ext_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)?;
    let body_trellis = StcTrellis::from_seed_grouped(session.stc_seed, fmt.stc_h, fmt.stc_u)?;
    let base_positions = &header_positions[..HEVC_SUPERBLOCK_MIN_SLOTS];
    let ext_positions = &header_positions[HEVC_SUPERBLOCK_MIN_SLOTS..];

    let mut forbidden: HashSet<usize> = HashSet::new();
    let mut bad_substreams: HashSet<(usize, usize)> = HashSet::new();

    for round in 0..MAX_EMBED_ROUNDS {
        control.check()?;

        // 3a. Solve Superblock STC
        let mut sb_cover_bits = Vec::with_capacity(base_positions.len());
        let mut sb_costs = Vec::with_capacity(base_positions.len());
        let mut sb_moves = Vec::with_capacity(base_positions.len());
        for &pos in base_positions {
            let slot = &all_slots[pos];
            sb_cover_bits.push(slot.original_bit);
            sb_costs.push(if forbidden.contains(&pos) {
                slot.cost as f64 + FORBIDDEN_SLOT_SURCHARGE
            } else {
                slot.cost as f64
            });
            sb_moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }
        let mut sb_deltas = vec![0i8; base_positions.len()];
        if let Err(e) = sb_trellis.embed_with_deltas(
            &sb_cover_bits,
            &sb_moves,
            &sb_costs,
            &sb_costs,
            &sb_bytes,
            &mut sb_deltas,
        ) {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC Superblock STC exhausted usable slots after {round} round(s) ({} slot(s) excluded): {e}",
                    forbidden.len()
                ),
            });
        }

        // 3a-bis. Solve the extension TLV area STC (keyed by the L2 ext seed)
        let mut ext_cover_bits = Vec::with_capacity(ext_positions.len());
        let mut ext_costs = Vec::with_capacity(ext_positions.len());
        let mut ext_moves = Vec::with_capacity(ext_positions.len());
        for &pos in ext_positions {
            let slot = &all_slots[pos];
            ext_cover_bits.push(slot.original_bit);
            ext_costs.push(if forbidden.contains(&pos) {
                slot.cost as f64 + FORBIDDEN_SLOT_SURCHARGE
            } else {
                slot.cost as f64
            });
            ext_moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }
        let mut ext_deltas = vec![0i8; ext_positions.len()];
        if ext_len > 0
            && let Err(e) = ext_trellis.embed_with_deltas(
                &ext_cover_bits,
                &ext_moves,
                &ext_costs,
                &ext_costs,
                &extension,
                &mut ext_deltas,
            )
        {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC extension area STC exhausted usable slots after {round} round(s) ({} slot(s) excluded): {e}",
                    forbidden.len()
                ),
            });
        }

        // 3b. Solve Body STC using cost closure (zero-allocation for body_costs)
        let mut body_cover_bits = Vec::with_capacity(body_positions.len());
        let mut body_moves = Vec::with_capacity(body_positions.len());
        for &pos in &body_positions {
            let slot = &all_slots[pos];
            body_cover_bits.push(slot.original_bit);
            body_moves.push(if slot.original_bit == 0 {
                Move::PlusOnly
            } else {
                Move::MinusOnly
            });
        }
        let mut body_deltas = vec![0i8; body_positions.len()];
        if let Err(e) = body_trellis.embed_with_cost_fn(
            &body_cover_bits,
            &body_moves,
            |j| {
                let pos = body_positions[j];
                let cost = if forbidden.contains(&pos) {
                    all_slots[pos].cost as f64 + FORBIDDEN_SLOT_SURCHARGE
                } else {
                    all_slots[pos].cost as f64
                };
                (cost, cost)
            },
            &ciphertext,
            &mut body_deltas,
        ) {
            if round == 0 {
                return Err(e);
            }
            return Err(StrHideError::TrellisInfeasible {
                cause: crate::errors::TrellisCause::ExhaustedSlots,
                detail: format!(
                    "HEVC Body STC exhausted usable slots after {round} round(s) ({} slot(s) excluded): {e}",
                    forbidden.len()
                ),
            });
        }

        let mut flips_per_slice: BTreeMap<usize, Vec<(usize, usize)>> = BTreeMap::new();
        for (i, &delta) in sb_deltas.iter().enumerate() {
            if delta != 0 {
                let global_slot_idx = base_positions[i];
                let slot = &all_slots[global_slot_idx];
                flips_per_slice
                    .entry(slot.slice_idx as usize)
                    .or_default()
                    .push((slot.op_idx as usize, global_slot_idx));
            }
        }
        for (i, &delta) in ext_deltas.iter().enumerate() {
            if delta != 0 {
                let global_slot_idx = ext_positions[i];
                let slot = &all_slots[global_slot_idx];
                flips_per_slice
                    .entry(slot.slice_idx as usize)
                    .or_default()
                    .push((slot.op_idx as usize, global_slot_idx));
            }
        }
        for (i, &delta) in body_deltas.iter().enumerate() {
            if delta != 0 {
                let global_slot_idx = body_positions[i];
                let slot = &all_slots[global_slot_idx];
                flips_per_slice
                    .entry(slot.slice_idx as usize)
                    .or_default()
                    .push((slot.op_idx as usize, global_slot_idx));
            }
        }
        for entries in flips_per_slice.values_mut() {
            entries.sort_unstable_by_key(|(op_idx, _)| *op_idx);
        }

        // 3c. Re-encode every touched slice in parallel using rayon (including journal fidelity checks)
        let mut conflicts: Vec<EpbConflict> = Vec::new();
        let mut reencoded_slices = Vec::new();

        let slice_items: Vec<(usize, &Vec<(usize, usize)>)> = flips_per_slice
            .iter()
            .map(|(&idx, entries)| (idx, entries))
            .collect();

        control.stage_sized(Stage::Encode, slice_items.len() as u64);

        let outcomes: Result<Vec<SliceReencodeOutcome>, StrHideError> = slice_items
            .into_par_iter()
            .map(|(slice_idx, flipped_entries)| {
                control.check()?;
                let ctx = slice_contexts.get(slice_idx).ok_or_else(|| {
                    StrHideError::General(format!(
                        "HEVC slice index {slice_idx} has no recorded context"
                    ))
                })?;
                Ok(reencode_slice(slice_idx, ctx, flipped_entries))
            })
            .collect();
        let outcomes = outcomes?;

        for outcome in outcomes {
            match outcome {
                SliceReencodeOutcome::Success { span, re_nal } => {
                    reencoded_slices.push((span, re_nal));
                }
                SliceReencodeOutcome::Conflict(c) => {
                    conflicts.extend(c);
                }
                SliceReencodeOutcome::BadSubstream(slice_idx, sub_idx) => {
                    bad_substreams.insert((slice_idx, sub_idx));
                }
                SliceReencodeOutcome::LengthError(msg) => {
                    return Err(StrHideError::General(msg));
                }
            }
        }

        let mut had_bad_substream = false;
        for &pos in header_positions.iter().chain(body_positions.iter()) {
            let slot = &all_slots[pos];
            if bad_substreams.contains(&(slot.slice_idx as usize, slot.substream_idx as usize))
                && forbidden.insert(pos)
            {
                had_bad_substream = true;
            }
        }
        if had_bad_substream {
            continue;
        }

        if conflicts.is_empty() && reencoded_slices.len() == flips_per_slice.len() {
            let modified_slots = sb_deltas.iter().filter(|&&d| d != 0).count()
                + ext_deltas.iter().filter(|&&d| d != 0).count()
                + body_deltas.iter().filter(|&&d| d != 0).count();
            let stats = crate::stego::EmbedStats {
                modified_slots,
                total_candidate_slots: total_slots,
            };
            return Ok((reencoded_slices, capacity_info, stats));
        }

        // 3c. Exclude the slots whose flipped bits sit next to a disturbed
        //     window. A bypass bin owns one codeword bit but its carry can
        //     rewrite the neighbouring bytes, so widen the radius every round.
        let radius = 8usize << round.min(3);
        let mut progress = 0usize;
        for (window, trace) in &conflicts {
            let lo = window.saturating_sub(radius);
            let hi = window + radius;
            for &(global, byte_lo, byte_hi) in trace {
                if global < total_slots
                    && byte_hi >= lo
                    && byte_lo <= hi
                    && forbidden.insert(global)
                {
                    progress += 1;
                }
            }
        }

        if progress == 0 {
            // The carry travelled further than any traced flip: exclude the
            // closest flip that precedes the window so the next round cannot
            // stall on the same conflict.
            for (window, trace) in &conflicts {
                if let Some(&(global, _, _)) = trace
                    .iter()
                    .filter(|(_, _, byte_hi)| *byte_hi <= *window)
                    .max_by_key(|(_, _, byte_hi)| *byte_hi)
                    && global < total_slots
                    && forbidden.insert(global)
                {
                    progress += 1;
                }
            }
        }

        if progress == 0 {
            // `conflicts` can be empty here when a BadSubstream hit a substream
            // whose slots were all excluded in an earlier round: the slice
            // failed to re-encode, yet there is no EPB trace to point at.
            // Report that explicitly instead of indexing `conflicts[0]`.
            if conflicts.is_empty() {
                return Err(StrHideError::General(format!(
                    "HEVC stego cannot resolve a substream whose slots were already excluded \
                     (round {round}, {} slot(s) forbidden)",
                    forbidden.len()
                )));
            }
            return Err(StrHideError::General(format!(
                "HEVC stego cannot localize the emulation-prevention conflict at RBSP byte {}",
                conflicts[0].0
            )));
        }
    }

    Err(StrHideError::General(format!(
        "HEVC stego cannot settle on an EPB-safe flip set within {MAX_EMBED_ROUNDS} rounds"
    )))
}

pub fn embed_hevc_payload(
    carrier: &[u8],
    payload: &Payload<'_>,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
) -> Result<Vec<u8>, StrHideError> {
    embed_hevc_with_info(
        carrier,
        payload,
        secret,
        domain,
        fmt,
        freshness,
        SafetyPolicy::new(),
        &Control::none(),
    )
    .map(|(bytes, _, _)| bytes)
}

/// Embed a payload into an HEVC/HEIC carrier using content-adaptive sign-bit steganography.
///
/// Wrapper around [`embed_hevc_with_info`] discarding the structured capacity metadata.
pub fn embed_hevc(
    carrier: &[u8],
    payload: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    freshness: Freshness,
) -> Result<Vec<u8>, StrHideError> {
    embed_hevc_payload(
        carrier,
        &Payload::bytes(payload),
        secret,
        domain,
        fmt,
        freshness,
    )
}

/// Re-encode one CABAC substream from its recorded journal.
///
/// `flipped_ops` marks the journal entries whose bypass bin was inverted. The
/// second return value lists, for every inverted bin, the global slot index and
/// the `[first, last)` bit range it can occupy in the output stream, which lets
/// the caller map a broken `00 00 xx` window back to a slot.
fn encode_substream(
    slice: &SliceContext,
    sub: &SubstreamRecord,
    flipped_ops: &[(usize, usize)],
) -> Result<(Vec<u8>, Vec<SlotBitTrace>), StrHideError> {
    let mut enc = CabacEncoder::new();
    let mut writer = BitWriter::new();
    let mut ctx_array = [ContextModel::init(154, 26); ENCODER_CONTEXTS];
    for (model, &state) in ctx_array.iter_mut().zip(sub.init_contexts.iter()) {
        *model = ContextModel {
            p_state_idx: state >> 1,
            val_mps: state & 1,
        };
    }

    let ops = &slice.ops[sub.op_start..sub.op_end];
    let mut trace = Vec::new();

    let mut flip_cursor = 0usize;
    while flip_cursor < flipped_ops.len() && flipped_ops[flip_cursor].0 < sub.op_start {
        flip_cursor += 1;
    }

    for (offset, op) in ops.iter().enumerate() {
        let op_idx = sub.op_start + offset;
        let mut flipped_global = None;
        if flip_cursor < flipped_ops.len() && flipped_ops[flip_cursor].0 == op_idx {
            flipped_global = Some(flipped_ops[flip_cursor].1);
            flip_cursor += 1;
        }
        let flipped = flipped_global.is_some();
        if op.is_decision() {
            let idx = op.ctx_idx();
            // A context index outside the model array means the journal and
            // this build disagree about the syntax. Skipping the bin would
            // silently desynchronise the replay, so it is a hard error: the
            // caller marks the substream unsupported.
            let ctx = ctx_array.get_mut(idx).ok_or_else(|| {
                StrHideError::CorruptedData(format!(
                    "CABAC context index {idx} is out of range (ENCODER_CONTEXTS = {ENCODER_CONTEXTS})"
                ))
            })?;
            enc.encode_decision(&mut writer, ctx, op.bit());
        } else if op.is_bypass() {
            let out_bit = if flipped { op.bit() ^ 1 } else { op.bit() };
            let bit_lo = writer.bit_len();
            enc.encode_bypass(&mut writer, out_bit);
            let bit_hi = writer.bit_len();
            if op.is_stego()
                && let Some(global) = flipped_global
            {
                trace.push((global, bit_lo, bit_hi));
            }
        } else {
            enc.encode_terminate(&mut writer, op.bit());
        }
    }

    // H.265 §9.3.2.6 / §7.3.8.2 substream termination:
    // - The final substream of a slice ends with `end_of_slice_segment_flag = 1`
    //   (`BinOp::Terminate { bit: 1 }` already recorded at the end of `ops`).
    // - Mid-slice WPP/tile substreams end their CTU row with
    //   `end_of_slice_segment_flag = 0` (`BinOp::Terminate { bit: 0 }`), followed
    //   in the bitstream by `end_of_subset_one_bit = 1` and byte alignment.
    //   The decoder jumps straight to the next entry point after
    //   `Terminate { bit: 0 }` and so never records that bit; emitting
    //   `encode_terminate(1)` here reconstructs the exact standard substream
    //   tail, which is what makes mid-row substreams usable at all.
    //
    // Verified 2026-10-25 by replaying every substream of the local corpus: all
    // match byte-exactly (512×512 WPP 16/16, real HEICs 768/768 each).
    if !ops
        .last()
        .is_some_and(|op| op.is_terminate() && op.bit() == 1)
    {
        enc.encode_terminate(&mut writer, 1);
    }
    writer.align_zero();
    Ok((writer.finish(), trace))
}

enum SliceReencodeOutcome {
    Success {
        span: std::ops::Range<usize>,
        re_nal: Vec<u8>,
    },
    Conflict(Vec<EpbConflict>),
    BadSubstream(usize, usize),
    LengthError(String),
}

fn reencode_slice(
    slice_idx: usize,
    slice_rec: &SliceContext,
    flipped_entries: &[(usize, usize)],
) -> SliceReencodeOutcome {
    let mut substream_ids: Vec<usize> = flipped_entries
        .iter()
        .filter_map(|&(op_idx, _)| {
            slice_rec
                .substreams
                .iter()
                .position(|s| op_idx >= s.op_start && op_idx < s.op_end)
        })
        .collect();
    substream_ids.sort_unstable();
    substream_ids.dedup();

    let mut modified_rbsp = slice_rec.orig_rbsp.clone();
    let mut trace: Vec<SlotBitTrace> = Vec::new();

    for sub_idx in &substream_ids {
        let sub = &slice_rec.substreams[*sub_idx];
        let cover = &slice_rec.orig_rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end];
        match encode_substream(slice_rec, sub, &[]) {
            Ok((replay, _)) if replay_matches_cover(&replay, cover) => {}
            _ => return SliceReencodeOutcome::BadSubstream(slice_idx, *sub_idx),
        }

        let orig_sub_len = sub.rbsp_byte_end.saturating_sub(sub.rbsp_byte_start);
        let (reencoded, sub_trace) = match encode_substream(slice_rec, sub, flipped_entries) {
            Ok(pair) => pair,
            Err(_) => return SliceReencodeOutcome::BadSubstream(slice_idx, *sub_idx),
        };

        // A replay that is 1-4 bytes shorter is padded to the original span.
        // This is not dead tolerance: real HEIC carriers (e.g. the
        // IMG_5887.HEIC baseline) legitimately produce such replays, and
        // rejecting them made the content embed fail. Keep the padding until
        // `encode_substream` can be made length-exact; the EPB conflict scan and
        // the final NAL length check below still gate the result.
        if reencoded.len() == orig_sub_len {
            modified_rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end].copy_from_slice(&reencoded);
        } else if reencoded.len() < orig_sub_len && orig_sub_len - reencoded.len() <= 4 {
            modified_rbsp[sub.rbsp_byte_start..sub.rbsp_byte_start + reencoded.len()]
                .copy_from_slice(&reencoded);
            for b in &mut modified_rbsp[sub.rbsp_byte_start + reencoded.len()..sub.rbsp_byte_end] {
                *b = 0;
            }
        } else {
            return SliceReencodeOutcome::BadSubstream(slice_idx, *sub_idx);
        }

        for (global, bit_lo, bit_hi) in sub_trace {
            trace.push((
                global,
                sub.rbsp_byte_start + bit_lo / 8,
                sub.rbsp_byte_start + bit_hi.saturating_sub(1) / 8,
            ));
        }
    }

    let mut conflicts = Vec::new();
    for p in 2..modified_rbsp.len() {
        let now_starts_epb =
            modified_rbsp[p - 2] == 0 && modified_rbsp[p - 1] == 0 && modified_rbsp[p] <= 3;
        let cover_starts_epb = slice_rec.orig_rbsp[p - 2] == 0
            && slice_rec.orig_rbsp[p - 1] == 0
            && slice_rec.orig_rbsp[p] <= 3;
        if now_starts_epb != cover_starts_epb {
            conflicts.push((p, trace));
            return SliceReencodeOutcome::Conflict(conflicts);
        }
    }

    let re_nal = rbsp_to_nal(
        slice_rec.nal_type,
        slice_rec.layer_id,
        slice_rec.temporal_id,
        &modified_rbsp,
    );
    if re_nal.len() == slice_rec.carrier_span.len() {
        SliceReencodeOutcome::Success {
            span: slice_rec.carrier_span.clone(),
            re_nal,
        }
    } else {
        SliceReencodeOutcome::LengthError(format!(
            "HEVC slice {slice_idx}: re-encoded NAL is {} bytes but the cover span is {} bytes",
            re_nal.len(),
            slice_rec.carrier_span.len()
        ))
    }
}

/// Is the journal replay byte-identical to the cover substream?
///
/// A shortfall of up to four trailing zero bytes is accepted: those are the HEVC
/// `cabac_zero_word`s that the journal does not model and the re-encoder
/// restores as padding. Anything else means the recorder and the stream
/// disagree about the syntax in this substream.
fn replay_matches_cover(replay: &[u8], cover: &[u8]) -> bool {
    if replay == cover {
        return true;
    }
    cover.len() > replay.len()
        && cover.len() - replay.len() <= 4
        && cover.starts_with(replay)
        && cover[replay.len()..].iter().all(|b| *b == 0)
}

/// Keyed stride permutation of each drift band, consumed band by band.
///
/// Element `i` maps to slot `band.start + (j * stride) mod len` where `j` is the
/// element's index inside that band. `stride` is derived per band from the
/// payload key (SplitMix64, see `keyed_band_params`); the fixed Weyl step of
/// earlier builds was removed. Consecutive elements therefore land in
/// different slices, different pictures and different corners of the frame.
/// Consuming slots in recording order
/// instead concentrates the whole payload on the first item -- for a burst
/// `.heic` (dozens of independent pictures in one file) that flattens the
/// primary image while the other 40-odd pictures stay pristine.
///
/// Two properties matter:
///
/// * `count` only decides how many elements are produced; the mapping of element
///   `i` never depends on it, which is what lets the extractor read the header
///   prefix and then the full message with the same mapping.
/// * Bands are never interleaved. A payload that fits in band 0 (pictures
///   nothing predicts from) never reaches band 1, so the drift-free rung is
///   exhausted before any reference picture is touched.
fn band_positions(
    bands: &[std::ops::Range<usize>],
    count: usize,
    perm_seed: &[u8; 32],
) -> Vec<usize> {
    let mut out = Vec::with_capacity(count);
    for band in bands {
        if out.len() >= count {
            break;
        }
        let len = band.len();
        if len == 0 {
            continue;
        }
        let (start, stride) = keyed_band_params(len, perm_seed, band.start);
        for i in 0..len {
            if out.len() >= count {
                break;
            }
            // `i * stride` overflows `usize` on 32-bit targets once a burst
            // HEIC exposes a few billion slots; the modulus only needs the
            // product's low bits, so the multiply runs in `u64`.
            out.push(
                band.start + ((start as u64 + i as u64 * stride as u64) % len as u64) as usize,
            );
        }
    }
    out
}

fn gcd_usize(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// Extract hidden payload from an HEVC/HEIC carrier.
pub fn extract_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    extract_hevc_v4(
        carrier,
        legacy_credential(secret),
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware extraction with explicit policy limits.
pub fn extract_hevc_v4(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    check_l1_floor(&cred, limits)?;
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;

    // 1. First stage: scan up to HEVC_SUPERBLOCK_POOL_SLOTS to read the header.
    let sb_record = record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    )?;
    extract_hevc_from_sb_record_v4(carrier, kind, sb_record, cred, domain, fmt, limits, control)
}

#[allow(clippy::too_many_arguments)]
fn extract_hevc_from_sb_record(
    carrier: &[u8],
    kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    extract_hevc_from_sb_record_v4(
        carrier,
        kind,
        sb_record,
        legacy_credential(secret),
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// The header half of an extraction: everything read and validated before any
/// body slot is touched.
struct HevcHeaderRead {
    sb: HevcSuperblockV4,
    sb_bytes: [u8; HEVC_SUPERBLOCK_BYTES],
    header_positions: Vec<usize>,
    extension: Vec<u8>,
    extension_tags: Vec<u8>,
    session: crate::stego::format::SessionKeys,
}

/// Locate, decode and validate the V4 header (base + extension).
///
/// Order matters and is the same for `extract`, `inspect` and `verify`:
/// CRC/version/magic → structural bounds → extension TLV → `validate_header`
/// (suite/body_len/header slots) → L3 session keys. Every failure is folded to
/// `NoHiddenData` so a wrong password and a tampered header are indistinguishable.
fn read_hevc_header_v4(
    carrier: &[u8],
    record: &CarrierRecord,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
) -> Result<Option<HevcHeaderRead>, StrHideError> {
    let total_slots = record.total_slots();
    let pool_size = total_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);
    if pool_size < HEVC_SUPERBLOCK_MIN_SLOTS {
        return Ok(None);
    }

    let cover_digest = derive_carrier_digest(carrier, &record.digest_inputs, fmt);
    let master = derive_locator_master(cred, domain, fmt.cipher, &cover_digest)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let locator = derive_l2_locator_keys(&master, fmt.cipher, fmt.magic_label, domain)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;

    let base_positions = superblock_positions(pool_size, &locator.locate_seed, 0);
    let sb_bits: Vec<u8> = base_positions
        .iter()
        .map(|&p| record.raw_slot_bit(p))
        .collect();
    let sb_trellis =
        StcTrellis::from_seed_grouped(locator.header_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)
            .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let sb_raw = sb_trellis.extract(&sb_bits, HEVC_SUPERBLOCK_BYTES * 8);
    if sb_raw.len() < HEVC_SUPERBLOCK_BYTES {
        return Ok(None);
    }
    let mut sb_bytes = [0u8; HEVC_SUPERBLOCK_BYTES];
    sb_bytes.copy_from_slice(&sb_raw[..HEVC_SUPERBLOCK_BYTES]);

    let Ok(sb) = HevcSuperblockV4::decode(&sb_bytes, locator.magic4) else {
        return Ok(None);
    };

    let header_slots = hevc_header_slots(sb.ext_len as usize);
    if header_slots > pool_size || header_slots > total_slots {
        return Ok(None);
    }
    if limits
        .validate_header(sb.suite_id, sb.body_len, header_slots, total_slots)
        .is_err()
    {
        return Ok(None);
    }

    let ext_bytes = sb.ext_len as usize;
    let header_positions = superblock_positions(pool_size, &locator.locate_seed, ext_bytes);
    let ext_slots = hevc_extension_slots(ext_bytes);
    let mut extension = Vec::new();
    let mut extension_tags = Vec::new();
    if ext_slots > 0 {
        let ext_positions = &header_positions[HEVC_SUPERBLOCK_MIN_SLOTS..];
        let ext_bits: Vec<u8> = ext_positions
            .iter()
            .map(|&p| record.raw_slot_bit(p))
            .collect();
        let ext_trellis =
            StcTrellis::from_seed_grouped(locator.ext_stc_seed, HEVC_EXT_STC_H, HEVC_EXT_STC_U)
                .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
        // The trellis message is the extension *bytes*, not the slot count.
        extension = ext_trellis.extract(&ext_bits, ext_bytes * 8);
        if extension.len() < ext_bytes {
            return Ok(None);
        }
        let tlvs = parse_extension(&extension)
            .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;
        extension_tags = tlvs.iter().map(|(tag, _)| *tag).collect();
    }
    // The flag and the TLVs must agree before any caller trusts the header:
    // `inspect`/`verify` never reach the post-decrypt check below, so a header
    // that merely sets the bit used to look like a critical carrier (review
    // B-05).
    validate_ext_critical_flag(sb.flags, &extension)
        .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;

    let suite = CipherSuiteId::from_u16(sb.suite_id)
        .ok_or_else(|| StrHideError::NoHiddenData("No valid payload found".into()))?;
    let session = derive_l3_session_keys(
        fmt.cipher,
        suite,
        &master,
        &hevc_session_salt(&sb.nonce),
        domain,
    )
    .map_err(|_| StrHideError::NoHiddenData("No valid payload found".into()))?;

    Ok(Some(HevcHeaderRead {
        sb,
        sb_bytes,
        header_positions,
        extension,
        extension_tags,
        session,
    }))
}

#[allow(clippy::too_many_arguments)]
fn extract_hevc_from_sb_record_v4(
    carrier: &[u8],
    _kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    control.check()?;
    check_l1_floor(&cred, limits)?;
    let no_data = || StrHideError::NoHiddenData("No valid payload found".into());

    let header =
        read_hevc_header_v4(carrier, &sb_record, cred, domain, fmt, limits)?.ok_or_else(no_data)?;
    extract_hevc_with_header(carrier, _kind, sb_record, &header, fmt, limits, control)
}

/// Body extraction over an already-read, policy-checked V4 header.
///
/// `verify` reads the header for its level-2 verdict and then needs the same
/// header for level 3; re-deriving it would pay the 200k-iteration L1 twice for
/// one request (plan M-14).
#[allow(clippy::too_many_arguments)]
fn extract_hevc_with_header(
    carrier: &[u8],
    kind: HevcCarrierKind,
    sb_record: CarrierRecord,
    header: &HevcHeaderRead,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let no_data = || StrHideError::NoHiddenData("No valid payload found".into());

    // 2. Second stage: read the Body, but only after the header passed policy.
    let w0 = header.sb.window_slices as usize;
    let body_record = if sb_record.recorded_slices >= w0 {
        sb_record
    } else {
        record_carrier_state(
            carrier,
            kind,
            Capture::Bits,
            StopCondition::TargetSlices(w0),
            control,
        )?
    };

    let total_window_slots = body_record.total_slots();
    let pool_size = total_window_slots.min(HEVC_SUPERBLOCK_POOL_SLOTS);
    if pool_size < header.header_positions.len() {
        return Err(no_data());
    }
    let (body_band0, body_band1) = get_body_slot_indices(
        total_window_slots,
        pool_size,
        &header.header_positions,
        &body_record.slice_slot_ranges,
    );

    let body_trellis =
        StcTrellis::from_seed_grouped(header.session.stc_seed, fmt.stc_h, header.sb.stc_u)?;
    let body_msg_len = header.sb.body_len as usize;
    let body_needed_slots = body_trellis.slots_for(body_msg_len * 8);

    let available_body_slots = body_band0.len() + body_band1.len();
    if available_body_slots < body_needed_slots {
        return Err(no_data());
    }

    let body_bands = vec![
        0..body_band0.len(),
        body_band0.len()..(body_band0.len() + body_band1.len()),
    ];
    let mut all_body_indices = body_band0;
    all_body_indices.extend(body_band1);
    let body_positions_rel =
        band_positions(&body_bands, body_needed_slots, &header.session.perm_seed);
    let body_bits: Vec<u8> = body_positions_rel
        .into_iter()
        .map(|rel| body_record.raw_slot_bit(all_body_indices[rel]))
        .collect();

    let ciphertext = body_trellis.extract(&body_bits, body_msg_len * 8);
    if ciphertext.len() < body_msg_len {
        return Err(no_data());
    }
    let ciphertext = &ciphertext[..body_msg_len];

    let aad = build_v4_aad(HEVC_FORMAT_ID, &header.sb_bytes, &header.extension);
    let suite = CipherSuiteId::from_u16(header.sb.suite_id).ok_or_else(no_data)?;
    let payload = unpack_v4_envelope_parts(
        suite,
        &header.session.enc_key,
        &header.sb.nonce,
        &aad,
        ciphertext,
        limits,
    )?;

    // Critical extension TLVs are only meaningful after AEAD proved the header
    // is authentic; an unknown critical tag means this build cannot honour the
    // carrier's contract.
    let flag_critical = header.sb.flags & FLAG_EXT_CRITICAL != 0;
    let has_critical = tags_have_critical(&header.extension_tags);
    if flag_critical != has_critical || has_critical {
        return Err(no_data());
    }

    Ok(payload)
}

#[allow(dead_code)]
fn extract_hevc_record(
    carrier: &[u8],
    record: &CarrierRecord,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<Payload<'static>, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    extract_hevc_from_sb_record(
        carrier,
        kind,
        CarrierRecord {
            slice_contexts: record.slice_contexts.clone(),
            all_slots: record.all_slots.clone(),
            band_bits: record.band_bits.clone(),
            bands: record.bands.clone(),
            pictures: record.pictures,
            band_pictures: record.band_pictures,
            digest_inputs: match &record.digest_inputs {
                DigestInputs::ParameterSets { parameter_sets } => DigestInputs::ParameterSets {
                    parameter_sets: parameter_sets.clone(),
                },
                DigestInputs::AnnexB { spans } => DigestInputs::AnnexB {
                    spans: spans.clone(),
                },
            },
            recorded_slices: record.recorded_slices,
            raw_bits: record.raw_bits.clone(),
            slice_slot_ranges: record.slice_slot_ranges.clone(),
            capacity_band_counts: record.capacity_band_counts,
        },
        secret,
        domain,
        fmt,
        control,
    )
}

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
        return Ok(empty_info);
    }
    let header = match read_hevc_header_v4(carrier, record, cred, domain, fmt, limits) {
        Ok(Some(header)) => header,
        Ok(None) | Err(_) => return Ok(empty_info),
    };

    Ok(hevc_header_info(kind, &header, media_info).unwrap_or(empty_info))
}

/// Header report shared by `inspect` and `verify`.
fn hevc_header_info(
    kind: HevcCarrierKind,
    header: &HevcHeaderRead,
    media_info: Option<MediaInfo>,
) -> Option<StegoHeaderInfo> {
    let _suite = CipherSuiteId::from_u16(header.sb.suite_id)?;
    // The plaintext length lives inside the AEAD body: what remains after the
    // tag and the compact header includes the optional filename micro-header
    // and any compression, so it is not the payload length. Report `None`
    // until the body is decrypted, like the PNG/JPEG engines (review B-04).
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
pub fn inspect_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    inspect_hevc_v4(
        carrier,
        legacy_credential(secret),
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware inspection with explicit policy limits.
pub fn inspect_hevc_v4(
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
        Err(_) => return Ok(empty_info),
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
fn sample_prefix_has_inter(prefix: &[u8], length_size: usize) -> bool {
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
pub fn inspect_hevc_mp4_file(
    carrier_path: &std::path::Path,
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoHeaderInfo, StrHideError> {
    inspect_hevc_mp4_file_v4(
        carrier_path,
        legacy_credential(secret),
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware streaming MP4 inspection with explicit policy limits.
pub fn inspect_hevc_mp4_file_v4(
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
        Err(_) => return Ok(StegoHeaderInfo::empty("MP4/HEVC")),
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

/// Three-level diagnostic verification for HEVC carriers.
pub fn verify_hevc(
    carrier: &[u8],
    secret: Option<&str>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    verify_hevc_v4(
        carrier,
        legacy_credential(secret),
        domain,
        fmt,
        &ExtractParams::default(),
        control,
    )
}

/// Credential-aware three-level verification with explicit policy limits.
pub fn verify_hevc_v4(
    carrier: &[u8],
    cred: Credential<'_>,
    domain: Option<&str>,
    fmt: &HevcFormatProfile,
    limits: &ExtractParams,
    control: &Control<'_>,
) -> Result<StegoVerifyResult, StrHideError> {
    control.check()?;
    let mut levels = Vec::new();
    let format_name = sniff_hevc_carrier(carrier).map_or("HEVC", |k| k.label());

    let kind = match sniff_hevc_carrier(carrier) {
        Some(k) => k,
        None => {
            levels.push(VerifyLevel::fail(
                1,
                "HEVC container format",
                "Unrecognized HEVC carrier",
            ));
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
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
    };

    let record = match record_carrier_state(
        carrier,
        kind,
        Capture::Bits,
        StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
        control,
    ) {
        Ok(rec) => {
            levels.push(VerifyLevel::pass(
                1,
                format!(
                    "HEVC bitstream and CABAC slots valid ({} slots)",
                    rec.total_slots()
                ),
            ));
            rec
        }
        Err(e) => {
            levels.push(VerifyLevel::fail(1, "HEVC bitstream parse", e.to_string()));
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
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
    };
    control.check()?;

    // The V4 L1 cost is fixed; a policy below it must fail with a policy
    // verdict, not "wrong password" (plan §4.2), and it must not pay PBKDF2.
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < CONTENT_L1_PBKDF2_ITERATIONS
    {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            format!(
                "PBKDF2 iteration limit {} is below the V4 L1 cost {}",
                limits.max_pbkdf2_iterations, CONTENT_L1_PBKDF2_ITERATIONS
            ),
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "Skipped due to level 2 policy failure",
        ));
        return Ok(StegoVerifyResult::new(format_name, levels));
    }

    // One header read serves both level 2 and level 3: re-deriving it in the
    // extract step paid the 200k-iteration L1 twice for one request (M-14).
    let media_info = {
        let (width, height) = extract_hevc_dimensions(carrier).unwrap_or((0, 0));
        if width > 0 && height > 0 {
            Some(MediaInfo::new(width, height))
        } else {
            None
        }
    };
    let header = match read_hevc_header_v4(carrier, &record, cred, domain, fmt, limits) {
        Ok(Some(header)) => header,
        Ok(None) | Err(_) => {
            levels.push(VerifyLevel::fail(
                2,
                "Stego header",
                "No valid HEVC stego signature found (or wrong password)",
            ));
            levels.push(VerifyLevel::fail(
                3,
                "Payload decryption",
                "No stego header to extract payload from",
            ));
            return Ok(StegoVerifyResult::new(format_name, levels));
        }
    };
    let Some(header_info) = hevc_header_info(kind, &header, media_info) else {
        levels.push(VerifyLevel::fail(
            2,
            "Stego header",
            "No valid HEVC stego signature found (or wrong password)",
        ));
        levels.push(VerifyLevel::fail(
            3,
            "Payload decryption",
            "No stego header to extract payload from",
        ));
        return Ok(StegoVerifyResult::new(format_name, levels));
    };
    levels.push(VerifyLevel::pass(
        2,
        format!(
            "Stego header valid (payload: {} B, total: {} B)",
            header_info.payload_len.unwrap_or(0),
            header_info.envelope_len.unwrap_or(0),
        ),
    ));
    control.check()?;

    match extract_hevc_with_header(carrier, kind, record, &header, fmt, limits, control) {
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

    Ok(StegoVerifyResult::new(format_name, levels))
}

/// Helper struct for slice recording and span tracking.
#[derive(Clone)]
struct SliceContext {
    carrier_span: std::ops::Range<usize>,
    nal_type: u8,
    layer_id: u8,
    temporal_id: u8,
    #[allow(dead_code)]
    band: u8,
    orig_rbsp: Vec<u8>,
    ops: Vec<BinOp>,
    substreams: Vec<SubstreamRecord>,
}

/// How much of every recorded slot `record_carrier_state` keeps.
///
/// Every pass used to build the full 32-byte [`StegoSlot`] pool even when it
/// only needed a count. A 24-minute 1080p carrier has 5.7e8 slots, i.e. 18 GB
/// (34 GB once `Vec` doubles to the next power of two) for data a capacity probe
/// never reads. The capture level is what keeps a probe at a few counters and an
/// extract at one bit per slot.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Capture {
    /// Per-band slot counts only: capacity probe, verify.
    Count,
    /// Counts plus the sign bit of every slot in pool order: extract, inspect.
    Bits,
    /// Full slot records, replay journal and RBSP: embed.
    Full,
}

/// One pass over the carrier: the recorded slice journals and slot pool,
/// plus the container parse the digest derivation reuses — deriving the
/// cover digest must not walk the container a second time (audit 2026-10-24
/// 2.5).
struct CarrierRecord {
    slice_contexts: Vec<SliceContext>,
    /// Slot pool in stream recording order.
    /// Populated by [`Capture::Full`] only.
    all_slots: Vec<StegoSlot>,
    /// Sign bit of every slot, packed LSB-first, one vector per band in
    /// recording order.
    band_bits: [Vec<u8>; 2],
    /// Pool ranges of each band, in consumption order.
    bands: Vec<std::ops::Range<usize>>,
    /// Pictures in the carrier (all VCL, including excluded IRAPs).
    pictures: usize,
    /// Pictures that may carry slots, per band.
    band_pictures: [usize; 2],
    digest_inputs: DigestInputs,
    /// Total slices recorded in this window pass.
    recorded_slices: usize,
    /// Sign bit of every recorded slot in stream order.
    raw_bits: Vec<u8>,
    /// (slot_count, band) for each recorded slice.
    slice_slot_ranges: Vec<(usize, u8)>,
    /// Whole-carrier slot counts per band when the recording pass continued
    /// counting after the write window stopped (`record_carrier_state_with_capacity`).
    /// `None` means `bands` only covers the write window.
    capacity_band_counts: Option<[usize; 2]>,
}

impl CarrierRecord {
    /// Size of the slot pool. Valid for every capture level.
    fn total_slots(&self) -> usize {
        self.bands.iter().map(|range| range.len()).sum()
    }

    /// Sign bit at pool position `index`, where the pool is band 0 followed by
    /// band 1. Valid for [`Capture::Bits`].
    #[cfg(test)]
    fn slot_bit(&self, index: usize) -> u8 {
        let band = usize::from(index >= self.bands[0].len());
        let range = &self.bands[band];
        debug_assert!(range.contains(&index));
        bit_at(&self.band_bits[band], index.saturating_sub(range.start))
    }

    /// Sign bit at stream position `index`. Valid for [`Capture::Bits`].
    fn raw_slot_bit(&self, index: usize) -> u8 {
        bit_at(&self.raw_bits, index)
    }
}

/// Read bit `index` out of an LSB-first packed vector.
#[inline]
fn bit_at(bits: &[u8], index: usize) -> u8 {
    bits.get(index / 8)
        .map_or(0, |byte| (byte >> (index % 8)) & 1)
}

/// Append-only LSB-first bit vector. One sign bit per slot instead of 32 bytes.
#[derive(Default)]
struct BitPacker {
    bytes: Vec<u8>,
    len: usize,
}

impl BitPacker {
    #[inline]
    fn push(&mut self, bit: u8) {
        if self.len.is_multiple_of(8) {
            self.bytes.push(0);
        }
        if bit & 1 != 0 {
            let last = self.bytes.len() - 1;
            self.bytes[last] |= 1 << (self.len % 8);
        }
        self.len += 1;
    }

    fn truncate(&mut self, new_len: usize) {
        if new_len >= self.len {
            return;
        }
        self.len = new_len;
        let needed_bytes = self.len.div_ceil(8);
        self.bytes.truncate(needed_bytes);
        if let Some(last) = self.bytes.last_mut() {
            let rem = self.len % 8;
            if rem != 0 {
                *last &= (1 << rem) - 1;
            }
        }
    }

    fn extend(&mut self, other: &BitPacker) {
        if other.len == 0 {
            return;
        }
        let shift = self.len % 8;
        if shift == 0 {
            self.bytes.extend_from_slice(&other.bytes);
            self.len += other.len;
            return;
        }
        let inv_shift = 8 - shift;
        for &b in &other.bytes {
            let last = self.bytes.len() - 1;
            self.bytes[last] |= b << shift;
            self.bytes.push(b >> inv_shift);
        }
        self.len += other.len;
        let needed_bytes = self.len.div_ceil(8);
        self.bytes.truncate(needed_bytes);
        if let Some(last) = self.bytes.last_mut() {
            let rem = self.len % 8;
            if rem != 0 {
                *last &= (1 << rem) - 1;
            }
        }
    }
}

/// Where the slots of the current slice go, according to [`Capture`].
struct SlotSink {
    capture: Capture,
    /// Slots that entered the pool, per band.
    counts: [usize; 2],
    band_bits: [BitPacker; 2],
    raw_bits: BitPacker,
    raw_slots: Vec<StegoSlot>,
    slice_slot_ranges: Vec<(usize, u8)>,
}

impl SlotSink {
    fn new(capture: Capture) -> Self {
        SlotSink {
            capture,
            counts: [0; 2],
            band_bits: [BitPacker::default(), BitPacker::default()],
            raw_bits: BitPacker::default(),
            raw_slots: Vec::new(),
            slice_slot_ranges: Vec::new(),
        }
    }

    /// Record one pool slot.
    fn push(&mut self, slot: StegoSlot, band: usize) {
        self.counts[band] += 1;
        match self.capture {
            Capture::Count => {}
            Capture::Bits => {
                self.band_bits[band].push(slot.original_bit);
                self.raw_bits.push(slot.original_bit);
            }
            Capture::Full => {
                self.raw_slots.push(slot);
            }
        }
    }
}

/// Pool geometry the capacity report needs: how big the ladder is, how it is
/// split, and how many pictures each rung holds.
pub(crate) struct PoolProfile {
    total_slots: usize,
    band_slots: [usize; 2],
    band_pictures: [usize; 2],
    pictures: usize,
    is_estimated: bool,
}

impl PoolProfile {
    fn from_record(record: &CarrierRecord) -> Self {
        if let Some(band_slots) = record.capacity_band_counts {
            return PoolProfile {
                total_slots: band_slots[0] + band_slots[1],
                band_slots,
                band_pictures: record.band_pictures,
                pictures: record.pictures,
                is_estimated: false,
            };
        }
        let mut band_slots = [0usize; 2];
        // `bands` is [band 0, band 1] in that order. Index by position, not by
        // `range.start`: an empty band 0 makes both ranges start at 0, and
        // testing the start silently credited band 1's slots to band 0 -- which
        // let an all-reference video spend the drift-free budget it does not
        // have.
        for (index, range) in record.bands.iter().enumerate().take(2) {
            band_slots[index] = range.len();
        }
        PoolProfile {
            total_slots: record.total_slots(),
            band_slots,
            band_pictures: record.band_pictures,
            pictures: record.pictures,
            is_estimated: false,
        }
    }
}

/// The already-parsed container pieces `derive_carrier_digest` needs.
enum DigestInputs {
    /// HEIF/HEIC and MP4/MOV: owned copies of the `hvcC` VPS/SPS/PPS NAL bytes.
    ///
    /// Both containers keep the parameter sets in a `hvcC` record that the
    /// embedder never touches, so one digest recipe covers both.
    ParameterSets { parameter_sets: Vec<Vec<u8>> },
    /// Annex-B: the NAL span table.
    AnnexB {
        spans: Vec<crate::stego::hevc::bitstream::HevcNalSpan>,
    },
}

/// One VCL NAL unit that may be recorded, in decode order.
#[derive(Clone)]
struct CandidateSlice {
    /// File byte range of the NAL (header included, length prefix or start
    /// code excluded) -- the exact range the re-encoder writes back.
    span: std::ops::Range<usize>,
    nal_type: u8,
    layer_id: u8,
    temporal_id: u8,
}

struct GopSliceRecord {
    recorded_slices: usize,
    sink: SlotSink,
    slice_contexts: Vec<SliceContext>,
    decode_error: Option<String>,
}

impl GopSliceRecord {
    fn new(capture: Capture) -> Self {
        GopSliceRecord {
            recorded_slices: 0,
            sink: SlotSink::new(capture),
            slice_contexts: Vec::new(),
            decode_error: None,
        }
    }

    fn truncate_to_slices(&mut self, kept_slices: usize) {
        if kept_slices >= self.recorded_slices {
            return;
        }
        let new_counts_0: usize = self.sink.slice_slot_ranges[..kept_slices]
            .iter()
            .filter(|(_, b)| *b == 0)
            .map(|(c, _)| *c)
            .sum();
        let new_counts_1: usize = self.sink.slice_slot_ranges[..kept_slices]
            .iter()
            .filter(|(_, b)| *b == 1)
            .map(|(c, _)| *c)
            .sum();
        let total_kept_slots = new_counts_0 + new_counts_1;

        self.sink.counts = [new_counts_0, new_counts_1];
        self.sink.slice_slot_ranges.truncate(kept_slices);
        match self.sink.capture {
            Capture::Count => {}
            Capture::Bits => {
                self.sink.band_bits[0].truncate(new_counts_0);
                self.sink.band_bits[1].truncate(new_counts_1);
                self.sink.raw_bits.truncate(total_kept_slots);
            }
            Capture::Full => {
                self.sink.raw_slots.truncate(total_kept_slots);
                self.slice_contexts.truncate(kept_slices);
            }
        }
        self.recorded_slices = kept_slices;
    }
}

fn find_gop_ranges(carrier: &[u8], candidates: &[CandidateSlice]) -> Vec<std::ops::Range<usize>> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let mut gop_starts = Vec::new();
    for (idx, cand) in candidates.iter().enumerate() {
        if idx == 0 || (is_irap(cand.nal_type) && starts_picture(&carrier[cand.span.clone()])) {
            gop_starts.push(idx);
        }
    }
    let mut ranges = Vec::with_capacity(gop_starts.len());
    for i in 0..gop_starts.len() {
        let start = gop_starts[i];
        let end = if i + 1 < gop_starts.len() {
            gop_starts[i + 1]
        } else {
            candidates.len()
        };
        ranges.push(start..end);
    }
    ranges
}

fn estimate_gops_for_slices(
    remaining_gops: &[std::ops::Range<usize>],
    candidates: &[CandidateSlice],
    has_inter: bool,
    needed_slices: usize,
) -> usize {
    let mut sum = 0usize;
    for (i, range) in remaining_gops.iter().enumerate() {
        for cand in &candidates[range.clone()] {
            if picture_band(cand.nal_type, has_inter).is_some() {
                sum += 1;
            }
        }
        if sum >= needed_slices {
            return i + 1;
        }
    }
    remaining_gops.len().max(1)
}

/// Decode one GOP, stopping after `slot_budget` recorded slots when given.
///
/// The budget is the batch's remaining target: a GOP that reaches it on its own
/// has already supplied everything the window needs, and the merge truncates to
/// the exact slice anyway. Stopping here instead of decoding the GOP out turns
/// the embed's transient footprint from "every slice of the batch" into "the
/// slices that survive truncation" — the difference between decoding 1200
/// frames and 1 for a 4 KiB payload.
fn decode_gop_slice_range(
    carrier: &[u8],
    candidates: &[CandidateSlice],
    parameter_sets: &[&[u8]],
    has_inter: bool,
    mode: RecordMode,
    capture: Capture,
    slot_budget: Option<usize>,
) -> Result<GopSliceRecord, String> {
    let mut decoder = Decoder::new();
    decoder.skip_loop_filters = true;
    decoder.ablate = Ablate {
        mc: true,
        intra: true,
        residual: true,
    };
    for ps in parameter_sets {
        if let Err(e) = decoder.push_nal(ps, None) {
            return Err(format!("parameter set: {e}"));
        }
    }

    let mut record = GopSliceRecord::new(capture);
    let mut decode_error: Option<String> = None;
    let mut local_slice_idx = 0usize;

    for cand in candidates {
        let slice_bytes = &carrier[cand.span.clone()];
        if slice_bytes.len() < 2 {
            continue;
        }
        let Some(band) = picture_band(cand.nal_type, has_inter) else {
            if let Err(e) = decoder.push_nal(slice_bytes, None) {
                decode_error.get_or_insert_with(|| e.to_string());
            }
            drain_frames(&mut decoder);
            continue;
        };

        let mut recorder =
            CabacRecorder::with_slice_capacity(local_slice_idx, band, mode, slice_bytes.len());
        let decoded = decoder.decode_nal_with_observer(slice_bytes, &mut recorder);
        drain_frames(&mut decoder);

        match decoded {
            Err(e) => {
                decode_error.get_or_insert_with(|| e.to_string());
            }
            Ok(_) if recorder.substreams.is_empty() => {}
            Ok(_) => {
                let is_multi_sub = recorder.substreams.len() > 1;
                let rbsp = if is_multi_sub || capture == Capture::Full {
                    nal_rbsp(slice_bytes)
                } else {
                    Vec::new()
                };
                // A slice that decoded only part-way has its slots discarded
                // inside `absorb_recorder`; it must not advance the slice
                // counter either, or later slots point at the wrong context.
                if absorb_recorder(&mut recorder, &rbsp, &mut record.sink) {
                    record.recorded_slices += 1;
                    if capture == Capture::Full {
                        record.slice_contexts.push(SliceContext {
                            carrier_span: cand.span.clone(),
                            nal_type: cand.nal_type,
                            layer_id: cand.layer_id,
                            temporal_id: cand.temporal_id,
                            band,
                            orig_rbsp: rbsp,
                            ops: recorder.ops,
                            substreams: recorder.substreams,
                        });
                    }
                    local_slice_idx += 1;
                }
                if let Some(budget) = slot_budget
                    && record.sink.counts[0] + record.sink.counts[1] >= budget
                {
                    break;
                }
            }
        }
    }

    record.decode_error = decode_error;
    Ok(record)
}

fn merge_gop_record(
    global_sink: &mut SlotSink,
    global_slice_contexts: &mut Vec<SliceContext>,
    global_recorded_slices: &mut usize,
    mut gop: GopSliceRecord,
) {
    global_sink.counts[0] += gop.sink.counts[0];
    global_sink.counts[1] += gop.sink.counts[1];
    global_sink
        .slice_slot_ranges
        .extend_from_slice(&gop.sink.slice_slot_ranges);

    match global_sink.capture {
        Capture::Count => {}
        Capture::Bits => {
            global_sink.band_bits[0].extend(&gop.sink.band_bits[0]);
            global_sink.band_bits[1].extend(&gop.sink.band_bits[1]);
            global_sink.raw_bits.extend(&gop.sink.raw_bits);
        }
        Capture::Full => {
            let base_slice_idx = *global_recorded_slices as u32;
            for slot in &mut gop.sink.raw_slots {
                slot.slice_idx += base_slice_idx;
            }
            global_sink.raw_slots.extend(gop.sink.raw_slots);
            global_slice_contexts.extend(gop.slice_contexts);
        }
    }
    *global_recorded_slices += gop.recorded_slices;
}

/// Parameter sets that are active at a GOP's first slice.
///
/// Container carriers (`hvcC`) declare every set up front (`ends = None`). An
/// Annex-B stream may redefine SPS/PPS mid-file, so a GOP may only see the sets
/// that physically precede it. Feeding the whole file's sets to every GOP made
/// the last definition of `sps/pps id 0` overwrite the earlier ones, decoding
/// early GOPs with the wrong geometry.
fn active_parameter_sets<'a>(
    sets: &'a [Vec<u8>],
    ends: Option<&[usize]>,
    gop_start_byte: usize,
) -> Vec<&'a [u8]> {
    match ends {
        None => sets.iter().map(Vec::as_slice).collect(),
        Some(ends) => sets
            .iter()
            .zip(ends)
            .filter(|(_, end)| **end <= gop_start_byte)
            .map(|(ps, _)| ps.as_slice())
            .collect(),
    }
}

/// Carrier bytes an embed keeps recorded at once, in groups of pictures.
///
/// `record_carrier_state` decodes a batch of this many GOPs and only then
/// merges it, checks the stopping condition and truncates the window. Every
/// slot, CABAC bin and RBSP in that batch is live at the same time, so this
/// constant — not the carrier size — sets the embed's memory peak.
pub const EMBED_WINDOW_GOPS: usize = 16;

/// Container facts `record_carrier_state` needs before it can decode.
///
/// Parsed once so the peak estimator and the recorder see exactly the same
/// slice spans and GOP boundaries; a second, cheaper parser would be free to
/// disagree with the one that decides where memory goes.
struct CarrierLayout {
    candidates: Vec<CandidateSlice>,
    parameter_sets: Vec<Vec<u8>>,
    ps_end_offsets: Option<Vec<usize>>,
    digest_inputs: DigestInputs,
}

fn parse_carrier_layout(
    carrier: &[u8],
    kind: HevcCarrierKind,
) -> Result<CarrierLayout, StrHideError> {
    let (candidates, parameter_sets, ps_end_offsets, digest_inputs) = match kind {
        HevcCarrierKind::HeifContainer => {
            let target = parse_heif_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("HEIF parse error: {e}")))?;
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                parameter_sets.clone(),
                None,
                DigestInputs::ParameterSets { parameter_sets },
            )
        }
        HevcCarrierKind::Mp4Container => {
            let target = parse_mp4_targets(carrier).map_err(|e| {
                StrHideError::UnsupportedFormat(format!("MP4/MOV parse error: {e}"))
            })?;
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                parameter_sets.clone(),
                None,
                DigestInputs::ParameterSets { parameter_sets },
            )
        }
        HevcCarrierKind::MkvContainer => {
            let target = parse_mkv_targets(carrier)
                .map_err(|e| StrHideError::UnsupportedFormat(format!("MKV parse error: {e}")))?;
            let parameter_sets = owned_parameter_sets(&target.parameter_sets);
            let mut candidates = Vec::with_capacity(target.slice_spans.len());
            for span in &target.slice_spans {
                if let Some(cand) = candidate_slice(carrier, span.start..span.end()) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                parameter_sets.clone(),
                None,
                DigestInputs::ParameterSets { parameter_sets },
            )
        }
        HevcCarrierKind::AnnexBStream => {
            let spans = parse_annex_b_spans(carrier);
            let mut parameter_sets = Vec::new();
            let mut ps_end_offsets = Vec::new();
            for span in &spans {
                if span.is_param_set() {
                    let end = span.end_offset().min(carrier.len());
                    parameter_sets.push(carrier[span.header_offset..end].to_vec());
                    ps_end_offsets.push(end);
                }
            }
            let mut candidates = Vec::new();
            for span in &spans {
                if !span.is_vcl() {
                    continue;
                }
                let range = span.header_offset..span.end_offset().min(carrier.len());
                if let Some(cand) = candidate_slice(carrier, range) {
                    candidates.push(cand);
                }
            }
            (
                candidates,
                parameter_sets,
                Some(ps_end_offsets),
                DigestInputs::AnnexB { spans },
            )
        }
    };
    Ok(CarrierLayout {
        candidates,
        parameter_sets,
        ps_end_offsets,
        digest_inputs,
    })
}

/// One batch's ceiling: the carrier bytes and group count of the first
/// [`EMBED_WINDOW_GOPS`] GOPs, or of the whole carrier when it has fewer.
///
/// `None` when the carrier is not HEVC or has no decodable slice.
fn embed_window(carrier: &[u8]) -> Option<(u64, usize)> {
    let kind = sniff_hevc_carrier(carrier)?;
    let layout = parse_carrier_layout(carrier, kind).ok()?;
    if layout.candidates.is_empty() {
        return None;
    }
    let gops = find_gop_ranges(carrier, &layout.candidates);
    let taken = gops.len().min(EMBED_WINDOW_GOPS);
    let first = gops.first()?;
    let last = gops.get(taken.checked_sub(1)?)?;
    let start = layout.candidates.get(first.start)?.span.start;
    let end = layout.candidates.get(last.end.checked_sub(1)?)?.span.end;
    Some((end.saturating_sub(start).min(carrier.len()) as u64, taken))
}

/// Carrier bytes the first batch of an embed records, measured over VCL spans.
pub fn embed_window_bytes(carrier: &[u8]) -> Option<u64> {
    embed_window(carrier).map(|(bytes, _)| bytes)
}

/// Predicted peak of an in-place embed, split into the part that scales with
/// the recorded window and the part that does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbedPeakEstimate {
    /// Carrier bytes the recorder holds at once (the recorded window).
    pub window_bytes: u64,
    /// Groups of pictures that window covers.
    pub window_gops: usize,
    /// Predicted peak private bytes.
    pub peak_bytes: u64,
}

/// Measured private-byte peak per carrier byte of the recorded window.
///
/// Fitted at 66 on Windows (24-minute 1080p film, 40 s 720p 21 Mbps clip);
/// rounded up because the window is measured over VCL spans, which are
/// slightly smaller than the file the fit was taken against.
const EMBED_WINDOW_BYTES_PER_CARRIER_BYTE: u64 = 70;

/// Fixed decoder/pool overhead of an in-place embed.
const EMBED_FIXED_BYTES: u64 = 64 * 1024 * 1024;

/// Peak private bytes for a recorded window of `window` carrier bytes.
#[inline]
fn embed_peak_for_window(window: u64, carrier_len: u64) -> u64 {
    window
        .saturating_mul(EMBED_WINDOW_BYTES_PER_CARRIER_BYTE)
        .saturating_add(carrier_len)
        .saturating_add(EMBED_FIXED_BYTES)
}

/// Peak estimate for embedding `payload_len` bytes into `carrier`.
///
/// The embed stops at the slice that meets the payload's slot target and keeps
/// only that window; the batch it was decoded in doubles from one GOP up to
/// [`EMBED_WINDOW_GOPS`], so at most one more window's worth is live beside it.
/// A `file_size × constant` estimate over-rejects long videos by ~12×, and a
/// whole-batch estimate over-rejects small payloads by 50×: a 4 KiB payload on
/// a 104 MB clip peaks at 129 MiB, not 6,759 MiB.
///
/// Returns `None` for carriers this engine does not decode.
pub fn estimate_embed_peak_bytes(
    carrier: &[u8],
    payload_len: usize,
    safety: SafetyPolicy,
    fmt: &HevcFormatProfile,
) -> Option<EmbedPeakEstimate> {
    let (batch_bytes, window_gops) = embed_window(carrier)?;
    // Header + payload + AEAD tag, with the flag/name area rounded up.
    let body_msg_len = payload_len.saturating_add(256);
    let body_slots = StcTrellis::slots_for_params(body_msg_len * 8, fmt.stc_h, fmt.stc_u);
    let factor = (1.0 / safety.level.video_budget().non_ref_fraction).max(1.0);
    let target_bytes = ((body_slots as f64 * factor).ceil() as u64).min(carrier.len() as u64);
    // One batch's worth on top of the window: the ramp decodes at most as much
    // again as it had already recorded before it can stop.
    let overshoot = target_bytes.min(batch_bytes);
    let window = target_bytes.saturating_add(overshoot);
    // Matroska and HEIF are committed as a whole rewritten file, so they hold a
    // second copy of the carrier beside the original. MP4 and Annex-B stream
    // their patches and never do. Once the window stopped dominating, this copy
    // became the peak: a 429.5 MB MKV peaks at 831 MiB, its 405.6 MB MP4 twin
    // at 443 MiB.
    let rewrite_copy = match sniff_hevc_carrier(carrier) {
        Some(HevcCarrierKind::MkvContainer | HevcCarrierKind::HeifContainer) => {
            carrier.len() as u64
        }
        _ => 0,
    };
    Some(EmbedPeakEstimate {
        window_bytes: window,
        window_gops,
        peak_bytes: embed_peak_for_window(window, carrier.len() as u64)
            .saturating_add(rewrite_copy),
    })
}

fn record_carrier_state(
    carrier: &[u8],
    kind: HevcCarrierKind,
    capture: Capture,
    stop: StopCondition,
    control: &Control<'_>,
) -> Result<CarrierRecord, StrHideError> {
    record_carrier_state_inner(carrier, kind, capture, stop, control, false)
}

/// Like [`record_carrier_state`], but when a `TargetSlots` window stops early
/// the remaining GOPs are decoded once more in slot-only mode and counted, so
/// the whole-carrier capacity needs no second pass. The capacity is exact:
/// slot counts do not depend on the capture level.
fn record_carrier_state_with_capacity(
    carrier: &[u8],
    kind: HevcCarrierKind,
    capture: Capture,
    stop: StopCondition,
    control: &Control<'_>,
) -> Result<CarrierRecord, StrHideError> {
    record_carrier_state_inner(carrier, kind, capture, stop, control, true)
}

fn record_carrier_state_inner(
    carrier: &[u8],
    kind: HevcCarrierKind,
    capture: Capture,
    stop: StopCondition,
    control: &Control<'_>,
    count_after_stop: bool,
) -> Result<CarrierRecord, StrHideError> {
    let count_remaining = count_after_stop && matches!(stop, StopCondition::TargetSlots(_));
    let mode = if capture == Capture::Full {
        RecordMode::Embed
    } else {
        RecordMode::Slots
    };

    let CarrierLayout {
        candidates,
        parameter_sets,
        ps_end_offsets,
        digest_inputs,
    } = parse_carrier_layout(carrier, kind)?;

    let has_inter = candidates.iter().any(|c| !is_irap(c.nal_type));

    let (pictures, band_pictures) = if capture == Capture::Bits {
        (1, [1, 0])
    } else {
        count_pictures(carrier, kind, &candidates, has_inter)
    };

    let gop_ranges = find_gop_ranges(carrier, &candidates);
    let total_slices = candidates.len();
    control.stage_sized(Stage::Decode, total_slices as u64);

    let mut global_sink = SlotSink::new(capture);
    let mut global_slice_contexts = Vec::new();
    let mut global_recorded_slices = 0usize;
    let mut decode_error: Option<String> = None;
    // Whole-carrier counts, filled from every GOP the window pass completes and
    // then from the slot-only continuation after the window stops.
    let mut capacity_counts = count_remaining.then_some([0usize; 2]);
    let mut counting_remaining = false;
    let mut reported_gops = 0usize;

    let mut gop_idx = 0;
    // A payload that fits in one GOP must not pay for sixteen: start at one and
    // double until the window batch is reached. `capacity --exact` (All) keeps
    // its fixed 32 and never ramps.
    let mut batch_cap = 1usize;
    while gop_idx < gop_ranges.len() {
        control.check()?;
        if counting_remaining {
            // The write window is complete; decode the rest slot-only. The
            // first GOP here is the one the window truncated (or completed on
            // its last slice), so decoding it again keeps the count exact.
            let end_idx = (gop_idx + 32).min(gop_ranges.len());
            let batch_ranges = &gop_ranges[gop_idx..end_idx];
            let batch_results: Vec<Result<GopSliceRecord, String>> = batch_ranges
                .par_iter()
                .map(|range| {
                    let gop_start_byte = candidates
                        .get(range.start)
                        .map_or(0, |cand| cand.span.start);
                    let active_sets = active_parameter_sets(
                        &parameter_sets,
                        ps_end_offsets.as_deref(),
                        gop_start_byte,
                    );
                    decode_gop_slice_range(
                        carrier,
                        &candidates[range.clone()],
                        &active_sets,
                        has_inter,
                        RecordMode::Slots,
                        Capture::Count,
                        None,
                    )
                })
                .collect();
            for gop_res in batch_results {
                if let Ok(gop) = gop_res
                    && let Some(counts) = capacity_counts.as_mut()
                {
                    counts[0] += gop.sink.counts[0];
                    counts[1] += gop.sink.counts[1];
                }
            }
            if end_idx > reported_gops {
                reported_gops = end_idx;
                control.report(Event::progress(
                    Stage::Decode,
                    gop_ranges[..end_idx].iter().map(|r| r.len()).sum::<usize>() as u64,
                    Some(total_slices as u64),
                ));
            }
            gop_idx = end_idx;
            continue;
        }
        let batch_size = match stop {
            StopCondition::All => 32,
            StopCondition::MinSlots(min) => {
                if min <= 2048 {
                    1
                } else {
                    16
                }
            }
            StopCondition::TargetSlices(target_slices) => {
                let needed = target_slices.saturating_sub(global_recorded_slices);
                let est_gops = estimate_gops_for_slices(
                    &gop_ranges[gop_idx..],
                    &candidates,
                    has_inter,
                    needed,
                );
                est_gops.clamp(1, 48)
            }
            StopCondition::TargetSlots(_) => batch_cap,
        };

        let end_idx = (gop_idx + batch_size).min(gop_ranges.len());
        let batch_ranges = &gop_ranges[gop_idx..end_idx];

        // Slots still missing before the window can stop. Every GOP in the
        // batch may record up to this; a GOP that reaches it stops decoding,
        // and the merge truncates to the exact slice either way.
        let slot_budget = match stop {
            StopCondition::TargetSlots(target) => Some(
                target
                    .saturating_sub(global_sink.counts[0] + global_sink.counts[1])
                    .max(1),
            ),
            // The header read (`MinSlots`) needs only the pool prefix; without a
            // budget every GOP in the wave decodes all of its slices, even though
            // the first slice already crosses the threshold. The budget makes the
            // GOP stop at exactly the slice where the outer merge would truncate,
            // so the recorded pool is unchanged.
            StopCondition::MinSlots(min) => Some(
                min.saturating_sub(global_sink.counts[0] + global_sink.counts[1])
                    .max(1),
            ),
            _ => None,
        };

        let batch_results: Vec<Result<GopSliceRecord, String>> = batch_ranges
            .par_iter()
            .map(|range| {
                let gop_start_byte = candidates
                    .get(range.start)
                    .map_or(0, |cand| cand.span.start);
                let active_sets = active_parameter_sets(
                    &parameter_sets,
                    ps_end_offsets.as_deref(),
                    gop_start_byte,
                );
                decode_gop_slice_range(
                    carrier,
                    &candidates[range.clone()],
                    &active_sets,
                    has_inter,
                    mode,
                    capture,
                    slot_budget,
                )
            })
            .collect();

        let mut finished = false;
        let mut resume_counting_at = None;
        for (batch_i, gop_res) in batch_results.into_iter().enumerate() {
            let mut gop = match gop_res {
                Ok(g) => g,
                Err(e) => {
                    decode_error.get_or_insert(e);
                    continue;
                }
            };
            if let Some(err) = gop.decode_error.take() {
                decode_error.get_or_insert(err);
            }
            let gop_counts = gop.sink.counts;

            let mut current_slots = global_sink.counts[0] + global_sink.counts[1];
            let mut current_slices = global_recorded_slices;
            let mut slices_to_take = gop.recorded_slices;
            let mut stop_now = false;

            for (idx, &(slot_cnt, _band)) in gop.sink.slice_slot_ranges.iter().enumerate() {
                current_slots += slot_cnt;
                current_slices += 1;
                let should_stop = match stop {
                    StopCondition::All => false,
                    StopCondition::MinSlots(min) => current_slots >= min,
                    StopCondition::TargetSlices(target_slices) => current_slices >= target_slices,
                    StopCondition::TargetSlots(target) => current_slots >= target,
                };
                if should_stop {
                    slices_to_take = idx + 1;
                    stop_now = true;
                    break;
                }
            }

            if slices_to_take < gop.recorded_slices {
                gop.truncate_to_slices(slices_to_take);
            }

            // A GOP that does not stop the window was decoded completely (the
            // slot budget only truncates the GOP that crosses the target), so
            // its counts belong to the whole-carrier capacity. The stopping GOP
            // is re-decoded in the counting phase instead of being counted
            // twice.
            if !stop_now && let Some(counts) = capacity_counts.as_mut() {
                counts[0] += gop_counts[0];
                counts[1] += gop_counts[1];
            }

            merge_gop_record(
                &mut global_sink,
                &mut global_slice_contexts,
                &mut global_recorded_slices,
                gop,
            );

            if stop_now {
                if capacity_counts.is_some() {
                    resume_counting_at = Some(gop_idx + batch_i);
                }
                finished = true;
                break;
            }
        }

        if end_idx > reported_gops {
            reported_gops = end_idx;
            control.report(Event::progress(
                Stage::Decode,
                gop_ranges[..end_idx].iter().map(|r| r.len()).sum::<usize>() as u64,
                Some(total_slices as u64),
            ));
        }

        if finished {
            if let Some(start) = resume_counting_at {
                counting_remaining = true;
                gop_idx = start;
                continue;
            }
            break;
        }
        if matches!(stop, StopCondition::TargetSlots(_)) {
            batch_cap = (batch_cap * 2).min(EMBED_WINDOW_GOPS);
        }
        gop_idx = end_idx;
    }

    if global_recorded_slices == 0
        && let Some(reason) = decode_error
    {
        return Err(StrHideError::UnsupportedFormat(format!(
            "HEVC carrier could not be decoded: {reason}"
        )));
    }

    let SlotSink {
        counts,
        band_bits,
        raw_bits,
        raw_slots,
        slice_slot_ranges,
        ..
    } = global_sink;
    let band0_len = counts[0];
    let total_slots = counts[0] + counts[1];

    let [band0_bits, band1_bits] = band_bits;
    let bands = vec![0..band0_len, band0_len..total_slots];

    Ok(CarrierRecord {
        slice_contexts: global_slice_contexts,
        all_slots: raw_slots,
        band_bits: [band0_bits.bytes, band1_bits.bytes],
        bands,
        pictures,
        band_pictures,
        digest_inputs,
        recorded_slices: global_recorded_slices,
        raw_bits: raw_bits.bytes,
        slice_slot_ranges,
        capacity_band_counts: capacity_counts,
    })
}

fn owned_parameter_sets(parameter_sets: &[&[u8]]) -> Vec<Vec<u8>> {
    parameter_sets.iter().map(|ps| ps.to_vec()).collect()
}

/// Wrap one candidate span, reading its NAL header fields (H.265 7.3.1.2).
///
/// Returns `None` for a span too short to hold a header, for a set
/// `forbidden_zero_bit`, or for `temporal_id_plus1 == 0` (invalid per spec and
/// the same rule the Annex-B parser applies).
fn candidate_slice(carrier: &[u8], span: std::ops::Range<usize>) -> Option<CandidateSlice> {
    let nal = carrier.get(span.clone())?;
    if nal.len() < 2 {
        return None;
    }
    let b0 = nal[0];
    let b1 = nal[1];
    if (b0 & 0x80) != 0 || (b1 & 0x07) == 0 {
        return None;
    }
    let (nal_type, layer_id, temporal_id) = nal_header_fields(nal);
    Some(CandidateSlice {
        span,
        nal_type,
        layer_id,
        temporal_id,
    })
}

/// Non-reference VCL NAL types (H.265 Table 7-1, even values in 0..=8).
///
/// A picture of one of these types is not added to the decoded picture buffer,
/// so no later picture predicts from it: flipping its coefficients cannot drift
/// into the rest of the video.
fn is_non_reference_vcl(nal_type: u8) -> bool {
    matches!(
        nal_type,
        NAL_TRAIL_N | NAL_TSA_N | NAL_STSA_N | NAL_RADL_N | NAL_RASL_N
    )
}

/// IRAP (intra random access point) VCL types: BLA/IDR/CRA, H.265 Table 7-1.
///
/// These are the prediction roots of a GOP. A flip in one of them is seen by
/// every picture that follows until the next IRAP, which is why they are the
/// one class the ladder never spends: measured at equal payload, including them
/// costs 15-20 dB (`docs/hevc_video_capacity_quality_audit_20261026.md` §2).
fn is_irap(nal_type: u8) -> bool {
    (16..=23).contains(&nal_type)
}

/// Drift-free band: pictures nothing predicts from.
const BAND_NON_REFERENCE: u8 = 0;
/// Reference band: pictures later pictures predict from until the next IRAP.
const BAND_REFERENCE: u8 = 1;

/// Place a VCL picture on the drift ladder, or `None` when it may not carry
/// slots at all.
///
/// * **No inter picture anywhere** (still image, all-intra stream): nothing is
///   predicted from anything, so every picture is drift-free.
/// * **Otherwise**: non-reference pictures are drift-free (band 0), reference
///   non-IRAP pictures are band 1, and IRAPs are excluded.
///
/// The answer depends only on the sequence of `nal_unit_type` values, which
/// embedding never changes (sign flips live inside the CABAC payload), so both
/// ends derive the same ladder and the wire header carries no flag.
fn picture_band(nal_type: u8, has_inter: bool) -> Option<u8> {
    if nal_type == NAL_RASL_N || nal_type == NAL_RASL_R {
        return None;
    }
    if !has_inter || is_non_reference_vcl(nal_type) {
        return Some(BAND_NON_REFERENCE);
    }
    if is_irap(nal_type) {
        return None;
    }
    Some(BAND_REFERENCE)
}

/// Count the pictures of a carrier and how many of them sit on each rung.
///
/// A HEIF carrier is a single image: its grid tiles are separate items, each a
/// standalone picture, but they are all the same image, so counting them would
/// inflate every per-picture budget by the tile count. For streams the answer
/// comes from `first_slice_segment_in_pic_flag`, which the container parsers do
/// not expose (a multi-slice picture is one sample, several NAL units).
fn count_pictures(
    carrier: &[u8],
    kind: HevcCarrierKind,
    candidates: &[CandidateSlice],
    has_inter: bool,
) -> (usize, [usize; 2]) {
    let mut band_pictures = [0usize; 2];
    if kind == HevcCarrierKind::HeifContainer {
        if let Some(first) = candidates.first()
            && let Some(band) = picture_band(first.nal_type, has_inter)
        {
            band_pictures[band as usize] = 1;
        }
        return (1, band_pictures);
    }

    let mut pictures = 0usize;
    for cand in candidates {
        if !starts_picture(&carrier[cand.span.clone()]) {
            continue;
        }
        pictures += 1;
        if let Some(band) = picture_band(cand.nal_type, has_inter) {
            band_pictures[band as usize] += 1;
        }
    }
    (pictures.max(1), band_pictures)
}

/// Does this VCL NAL start a new picture?
///
/// `first_slice_segment_in_pic_flag` is the first syntax element of every slice
/// segment header (H.265 §7.3.6.1), i.e. the MSB of the first RBSP byte. A
/// picture made of several slices must be counted once: the per-picture budgets
/// are expressed per picture, not per slice.
fn starts_picture(nal: &[u8]) -> bool {
    nal.get(2).is_some_and(|&first| (first & 0x80) != 0)
}

/// Drop every decoded picture the decoder has queued.
///
/// The decoder hands finished pictures out through a queue and only
/// `next_frame` releases them; each entry pins its sample planes through an
/// `Arc<Picture>` the DPB shares, so the buffers come back only when the last
/// handle goes. This engine never looks at pixels — it wants the bin stream —
/// so leaving the queue alone would hold one picture per frame of the carrier
/// (12 MB each at 4K; a five-clip corpus peaked at 2.0 GB without this).
fn drain_frames(decoder: &mut Decoder) {
    while decoder.next_frame().is_ok() {}
}

/// Move a slice's recorded slots into the carrier-wide slot pool.
///
/// Returns the recorder-local → global slot mapping the re-encoder uses to walk
/// from a recorded bypass bin back to the trellis element it carries.
///
/// Multi-substream slices (WPP / tiles) address their substreams through
/// `entry_point_offset`s expressed in **NAL** bytes, so a substream that already
/// carries a `00 00 xx<=3` window stays out of the pool: flipping near it could
/// shift every following substream even when the total NAL length is preserved.
fn absorb_recorder(recorder: &mut CabacRecorder, rbsp: &[u8], sink: &mut SlotSink) -> bool {
    if recorder.next_pending_slot() != recorder.slots.len() {
        // Slice decoding was truncated mid-slice before every sign got its
        // level back-fill. Discard all incomplete slots from this slice so
        // desynced slots never enter the pool. The check runs in every record
        // mode: embed used to drop the slice while extract (slot-only mode)
        // kept its slots, which shifted every later global slot index.
        recorder.slots.clear();
        recorder.reset_pending();
        return false;
    }

    let is_multi_sub = recorder.substreams.len() > 1;
    let mut excluded = std::collections::HashSet::new();
    if is_multi_sub {
        for sub in &recorder.substreams {
            if sub.rbsp_byte_start <= sub.rbsp_byte_end && sub.rbsp_byte_end <= rbsp.len() {
                let sub_data = &rbsp[sub.rbsp_byte_start..sub.rbsp_byte_end];
                if sub_data
                    .windows(3)
                    .any(|w| w[0] == 0 && w[1] == 0 && w[2] <= 3)
                {
                    excluded.insert(sub.substream_idx);
                }
            }
        }
    }

    let band = recorder.current_band as usize;
    let start_count = sink.counts[0] + sink.counts[1];

    if sink.capture == Capture::Count && (!is_multi_sub || excluded.is_empty()) {
        let count = recorder.slots.len();
        sink.counts[band] += count;
        sink.slice_slot_ranges.push((count, recorder.current_band));
        recorder.slots.clear();
        recorder.reset_pending();
        return true;
    }

    for slot in recorder.slots.drain(..) {
        if is_multi_sub && excluded.contains(&(slot.substream_idx as usize)) {
            continue;
        }
        sink.push(slot, band);
    }
    let added = (sink.counts[0] + sink.counts[1]) - start_count;
    sink.slice_slot_ranges.push((added, recorder.current_band));
    recorder.reset_pending();
    true
}

fn scan_hevc_slot_count(carrier: &[u8]) -> Result<usize, StrHideError> {
    let kind = sniff_hevc_carrier(carrier).ok_or_else(|| {
        StrHideError::UnsupportedFormat(
            "Unrecognized HEVC carrier (not HEIF/HEIC, Annex-B, or MP4)".into(),
        )
    })?;
    let record = record_carrier_state(
        carrier,
        kind,
        Capture::Count,
        StopCondition::All,
        &Control::none(),
    )?;
    Ok(record.total_slots())
}

/// Derive the cover digest from the container parse `record_carrier_state`
/// already produced — the container is walked exactly once per operation
/// (audit 2026-10-24 2.5).
fn derive_carrier_digest(
    carrier: &[u8],
    inputs: &DigestInputs,
    fmt: &HevcFormatProfile,
) -> [u8; 32] {
    // V4 pre_salt domain separation: only immutable metadata may enter, and
    // the label keeps HEVC salts distinct from JPEG/PNG ones even if the same
    // cover bytes are reused.
    let mut salt = Vec::with_capacity(fmt.cover_salt.len() + 8);
    salt.extend_from_slice(fmt.cover_salt);
    salt.extend_from_slice(b"hevc-v4");
    match inputs {
        DigestInputs::ParameterSets { parameter_sets } => {
            // Hash the parameter set *contents*. They are immutable during
            // embedding, which is what makes the digest — and therefore the
            // L1/L2/L3 keys and every keyed slot plan — identical on both ends.
            //
            // (Feeding them through `compute_hevc_cover_digest` would need
            // byte offsets into `carrier`; the parsed sets are copies, and
            // an offset of 0 quietly hashed the file header instead.)
            let mut hasher = Sha256::new();
            hasher.update(&salt);
            hasher.update((parameter_sets.len() as u64).to_be_bytes());
            for ps in parameter_sets {
                hasher.update((ps.len() as u64).to_be_bytes());
                hasher.update(ps);
            }
            hasher.finalize().into()
        }
        DigestInputs::AnnexB { spans } => compute_hevc_cover_digest(carrier, spans, &salt),
    }
}

#[cfg(test)]
mod capture_tests {
    use super::*;
    use crate::stego::format::DEFAULT_HEVC_FORMAT;

    fn record(bands: Vec<std::ops::Range<usize>>, band_bits: [Vec<u8>; 2]) -> CarrierRecord {
        let total = bands.iter().map(|r| r.len()).sum();
        CarrierRecord {
            slice_contexts: Vec::new(),
            all_slots: Vec::new(),
            band_bits,
            bands,
            pictures: 1,
            band_pictures: [1, 0],
            digest_inputs: DigestInputs::ParameterSets {
                parameter_sets: Vec::new(),
            },
            recorded_slices: 1,
            raw_bits: Vec::new(),
            slice_slot_ranges: vec![(total, 0)],
            capacity_band_counts: None,
        }
    }

    fn pack(bits: &[u8]) -> Vec<u8> {
        let mut packer = BitPacker::default();
        for &bit in bits {
            packer.push(bit);
        }
        packer.bytes
    }

    /// `Capture::Bits` must answer exactly what `all_slots[p].original_bit`
    /// answered, including across byte boundaries and across the drift-ladder
    /// partition.
    #[test]
    fn slot_bit_matches_the_pool_order() {
        // band 0: 10 slots (not a byte multiple), band 1: 3 slots.
        let band0 = [1u8, 0, 1, 1, 0, 0, 0, 1, 1, 0];
        let band1 = [0u8, 1, 1];
        let rec = record(vec![0..10, 10..13], [pack(&band0), pack(&band1)]);
        assert_eq!(rec.total_slots(), 13);
        let expected: Vec<u8> = band0.iter().chain(band1.iter()).copied().collect();
        for (index, &want) in expected.iter().enumerate() {
            assert_eq!(rec.slot_bit(index), want, "pool position {index}");
        }
    }

    /// An empty band 0 shifts band 1 to pool position 0; the mapping must not
    /// fall back to band 0's (empty) buffer.
    #[test]
    fn slot_bit_handles_an_empty_leading_band() {
        let rec = record(vec![0..0, 0..4], [Vec::new(), pack(&[1, 0, 0, 1])]);
        assert_eq!(rec.total_slots(), 4);
        assert_eq!(
            (0..4).map(|i| rec.slot_bit(i)).collect::<Vec<_>>(),
            vec![1, 0, 0, 1]
        );
    }

    /// LSB-first packing, including the last partial byte.
    #[test]
    fn bit_packer_packs_lsb_first() {
        assert_eq!(pack(&[1]), vec![0b0000_0001]);
        assert_eq!(pack(&[0, 0, 0, 0, 0, 0, 0, 1]), vec![0b1000_0000]);
        assert_eq!(pack(&[1; 9]), vec![0xFF, 0b0000_0001]);
        assert_eq!(pack(&[]), Vec::<u8>::new());
    }

    #[test]
    fn superblock_v4_encode_decode_roundtrip() {
        let sb = HevcSuperblockV4 {
            magic: [0x53, 0x54, 0x52, 0x48],
            version: CONTENT_ENVELOPE_VERSION,
            flags: FLAG_EXT_PRESENT,
            stc_u: 2,
            window_slices: 12,
            ext_len: 8,
            suite_id: 1,
            body_len: 1040,
            nonce: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };
        let encoded = sb.encode();
        assert_eq!(encoded.len(), HEVC_SUPERBLOCK_BYTES);
        let decoded = HevcSuperblockV4::decode(&encoded, sb.magic).expect("decode superblock");
        assert_eq!(decoded, sb);
    }

    #[test]
    fn superblock_v4_rejects_truncated_or_tampered_headers() {
        let sb = HevcSuperblockV4 {
            magic: [0x53, 0x54, 0x52, 0x48],
            version: CONTENT_ENVELOPE_VERSION,
            flags: 0,
            stc_u: 2,
            window_slices: 1,
            ext_len: 0,
            suite_id: 1,
            body_len: 64,
            nonce: [0u8; 12],
        };
        let encoded = sb.encode();
        // Wrong magic is "someone else's carrier", never a version error.
        assert!(HevcSuperblockV4::decode(&encoded, [0, 0, 0, 0]).is_err());
        // CRC mismatch is rejected before any field drives an allocation.
        let mut flipped = encoded;
        flipped[0] ^= 0x80;
        assert!(HevcSuperblockV4::decode(&flipped, sb.magic).is_err());
        // body_len bounds: 0, below BODY_OVERHEAD, and above HEADER_LEN_MAX.
        let mut zero = encoded;
        zero[12..16].copy_from_slice(&0u32.to_be_bytes());
        let zero_crc = crc32_span(&zero);
        zero[28..32].copy_from_slice(&zero_crc.to_be_bytes());
        assert!(HevcSuperblockV4::decode(&zero, sb.magic).is_err());
        let mut below = encoded;
        below[12..16].copy_from_slice(&(BODY_OVERHEAD as u32 - 1).to_be_bytes());
        let below_crc = crc32_span(&below);
        below[28..32].copy_from_slice(&below_crc.to_be_bytes());
        assert!(HevcSuperblockV4::decode(&below, sb.magic).is_err());
        // A forged huge body_len inside the byte range must be rejected by the
        // slot budget in extract; decode itself cannot know the carrier size.
        let mut huge = encoded;
        huge[12..16].copy_from_slice(&0x00FF_FFFFu32.to_be_bytes());
        let huge_crc = crc32_span(&huge);
        huge[28..32].copy_from_slice(&huge_crc.to_be_bytes());
        assert!(HevcSuperblockV4::decode(&huge, sb.magic).is_ok());
        // Above HEADER_LEN_MAX the length field itself is invalid.
        let mut over = encoded;
        over[12..16].copy_from_slice(&0x0400_0000u32.to_be_bytes());
        let over_crc = crc32_span(&over);
        over[28..32].copy_from_slice(&over_crc.to_be_bytes());
        assert!(HevcSuperblockV4::decode(&over, sb.magic).is_err());
        // Unknown suite is "no data", not an oracle.
        let mut suite = encoded;
        suite[10..12].copy_from_slice(&999u16.to_be_bytes());
        let suite_crc = crc32_span(&suite);
        suite[28..32].copy_from_slice(&suite_crc.to_be_bytes());
        assert!(HevcSuperblockV4::decode(&suite, sb.magic).is_err());
        // Truncation: `decode` takes a fixed 32-byte array, so a short buffer
        // cannot reach it; the extractor's `sb_raw.len()` guard is the
        // equivalent check and is covered by the caller contract.
        assert!(encoded.len() == HEVC_SUPERBLOCK_BYTES);
    }

    fn crc32_span(bytes: &[u8; HEVC_SUPERBLOCK_BYTES]) -> u32 {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&bytes[..HEVC_V4_CRC_SPAN]);
        hasher.finalize()
    }

    /// Probe and embed must agree byte for byte: the payload the probe
    /// advertises is exactly the largest body the writer can place, including
    /// the extension area's slot cost.
    #[test]
    fn capacity_formula_is_the_written_body_budget() {
        let fmt = &DEFAULT_HEVC_FORMAT;
        for total_slots in [2048usize, 4096, 10000] {
            for ext_len in [0usize, 8, 16] {
                let cap =
                    hevc_max_raw_payload(total_slots, ext_len, fmt).expect("capacity formula");
                let fits = cap + BODY_OVERHEAD;
                let slots = StcTrellis::slots_for_params(fits * 8, fmt.stc_h, fmt.stc_u);
                assert!(hevc_header_slots(ext_len) + slots <= total_slots);
                if cap > 0 {
                    let over = cap + 1 + BODY_OVERHEAD;
                    let over_slots = StcTrellis::slots_for_params(over * 8, fmt.stc_h, fmt.stc_u);
                    assert!(hevc_header_slots(ext_len) + over_slots > total_slots);
                }
            }
        }
        // An extension area strictly reduces the payload budget.
        let plain = hevc_max_raw_payload(4096, 0, fmt).expect("plain");
        let ext = hevc_max_raw_payload(4096, 8, fmt).expect("ext");
        assert!(ext < plain);
    }

    /// The extension area is part of the AAD; a carrier whose extension bytes
    /// changed must fail authentication.
    #[test]
    fn extension_area_is_bound_into_the_aad() {
        let header = [0x5Au8; HEVC_SUPERBLOCK_BYTES];
        let without = build_v4_aad(HEVC_FORMAT_ID, &header, &[]);
        let with = build_v4_aad(HEVC_FORMAT_ID, &header, &[0x01, 0x02, 0xAA, 0xBB]);
        assert_ne!(without, with);
        let changed = build_v4_aad(HEVC_FORMAT_ID, &header, &[0x01, 0x02, 0xAA, 0xBC]);
        assert_ne!(with, changed);
    }

    #[test]
    fn unknown_tlv_criticality_is_classified() {
        assert!(!tags_have_critical(&[0x01, 0x02]));
        assert!(tags_have_critical(&[0x81]));
        assert!(tags_have_critical(&[0x01, 0x83]));
    }

    /// A forged header field with a *recomputed* CRC passes `decode` (the CRC
    /// only protects against accidental damage), so authentication has to
    /// reject it: the AAD is built over the exact 32 header bytes.
    #[test]
    fn header_tamper_with_recomputed_crc_is_rejected_by_aead() {
        let sb = HevcSuperblockV4 {
            magic: [0x53, 0x54, 0x52, 0x48],
            version: CONTENT_ENVELOPE_VERSION,
            flags: 0,
            stc_u: 2,
            window_slices: 1,
            ext_len: 0,
            suite_id: 1,
            body_len: 32,
            nonce: [9; 12],
        };
        let key = [0x11u8; 32];
        let original = sb.encode();
        let plaintext = build_plaintext(&Payload::bytes(b"hevc aead header")).expect("plaintext");
        let ciphertext = encrypt_v4_with_aad(
            CipherSuiteId::Aes256Gcm,
            &key,
            &sb.nonce,
            &build_v4_aad(HEVC_FORMAT_ID, &original, &[]),
            &plaintext,
        )
        .expect("encrypt");

        let ok = unpack_v4_envelope_parts(
            CipherSuiteId::Aes256Gcm,
            &key,
            &sb.nonce,
            &build_v4_aad(HEVC_FORMAT_ID, &original, &[]),
            &ciphertext,
            &ExtractParams::default(),
        )
        .expect("authentic header decrypts");
        assert_eq!(ok.as_bytes(), b"hevc aead header");

        let mut forged = sb;
        forged.window_slices = 999;
        let forged_bytes = forged.encode();
        // The CRC is recomputed, so the structural parser accepts it.
        assert!(HevcSuperblockV4::decode(&forged_bytes, sb.magic).is_ok());
        let res = unpack_v4_envelope_parts(
            CipherSuiteId::Aes256Gcm,
            &key,
            &sb.nonce,
            &build_v4_aad(HEVC_FORMAT_ID, &forged_bytes, &[]),
            &ciphertext,
            &ExtractParams::default(),
        );
        assert!(matches!(res, Err(StrHideError::NoHiddenData(_))));
    }

    #[test]
    fn superblock_positions_are_distinct_and_prefix_stable() {
        let seed = [7u8; 32];
        let base = superblock_positions(2048, &seed, 0);
        assert_eq!(base.len(), HEVC_SUPERBLOCK_MIN_SLOTS);
        let set: HashSet<usize> = base.iter().copied().collect();
        assert_eq!(set.len(), HEVC_SUPERBLOCK_MIN_SLOTS);
        for &p in &base {
            assert!(p < 2048);
        }

        let with_ext = superblock_positions(2048, &seed, 8);
        assert_eq!(
            with_ext.len(),
            HEVC_SUPERBLOCK_MIN_SLOTS + hevc_extension_slots(8)
        );
        assert_eq!(with_ext[..base.len()], base[..]);

        // Different credentials must not reproduce the header permutation.
        let other = superblock_positions(2048, &[9u8; 32], 0);
        assert_ne!(other, base);
    }

    #[test]
    fn bitpacker_extend_and_truncate_correctness() {
        for len1 in 0..35 {
            for len2 in 0..35 {
                let bits1: Vec<u8> = (0..len1).map(|i| ((i * 7 + 3) % 2) as u8).collect();
                let bits2: Vec<u8> = (0..len2).map(|i| ((i * 11 + 5) % 2) as u8).collect();

                let mut p1 = BitPacker::default();
                for &b in &bits1 {
                    p1.push(b);
                }

                let mut p2 = BitPacker::default();
                for &b in &bits2 {
                    p2.push(b);
                }

                p1.extend(&p2);

                assert_eq!(p1.len, len1 + len2);
                let combined: Vec<u8> = bits1.iter().chain(bits2.iter()).copied().collect();
                for (i, &expected) in combined.iter().enumerate() {
                    assert_eq!(
                        bit_at(&p1.bytes, i),
                        expected,
                        "Mismatch at index {i} for len1={len1}, len2={len2}"
                    );
                }

                // Test truncate
                for trunc_len in [0, len1 / 2, len1, len1 + len2 / 2, len1 + len2] {
                    let mut p_trunc = BitPacker::default();
                    for &b in &combined {
                        p_trunc.push(b);
                    }
                    p_trunc.truncate(trunc_len);
                    assert_eq!(p_trunc.len, trunc_len);
                    for (i, &expected) in combined.iter().enumerate().take(trunc_len) {
                        assert_eq!(
                            bit_at(&p_trunc.bytes, i),
                            expected,
                            "Truncate mismatch at {i} for trunc_len={trunc_len}"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod dialect_tests {
    use super::*;
    use crate::stego::format::DEFAULT_HEVC_FORMAT;
    use crate::stego::hevc::sniff::{NAL_IDR_W_RADL, NAL_TRAIL_R};

    /// The literals below are pinned to `docs/api/WIRE_SPEC.md` §13.11.2. The
    /// spec is the only reproduction recipe a private build has; if an
    /// implementation constant changes without the doc (or vice versa),
    /// third-party rebuilds silently produce mutually unreadable carriers.
    #[test]
    fn default_format_literals_match_the_wire_spec() {
        let fmt = &DEFAULT_HEVC_FORMAT;
        assert_eq!(fmt.magic_label, b"strhide-hevc-magic-v4");
        assert_eq!(fmt.cover_salt, b"strhide-hevc-cover-v1");
        assert_eq!(fmt.stc_h, 7);
        assert_eq!(fmt.stc_u, 2);
        assert_eq!(fmt.cipher.default_suite, CipherSuiteId::Aes256Gcm);
    }

    /// The V4 magic comes out of the L2 locator keys, so it changes with the
    /// credential and with the domain; it is not a searchable constant.
    #[test]
    fn magic_is_derived_from_the_credential_and_domain() {
        let fmt = &DEFAULT_HEVC_FORMAT;
        let salt = [0x11u8; 32];
        let magic_for = |pw: &str, domain: Option<&str>| {
            let master = derive_locator_master(Credential::Password(pw), domain, fmt.cipher, &salt)
                .expect("master");
            derive_l2_locator_keys(&master, fmt.cipher, fmt.magic_label, domain)
                .expect("locator")
                .magic4
        };
        let m1 = magic_for("secret-one", None);
        let m2 = magic_for("secret-two", None);
        assert_ne!(m1, m2, "different credentials must yield different magics");
        assert_eq!(m1, magic_for("secret-one", None), "stable for same inputs");
        assert_ne!(m1, magic_for("secret-one", Some("org.acme")));
    }

    /// The no-secret fallback is the shared public constant, not a
    /// HEVC-private string: one public default key per crate, resolved through
    /// the same chain as PNG/JPEG.
    #[test]
    fn no_secret_falls_back_to_the_public_constant() {
        assert!(matches!(
            legacy_credential(None),
            Credential::Password(pw) if pw == PUBLIC_DEFAULT_SECRET
        ));
        assert!(matches!(
            legacy_credential(Some("")),
            Credential::Password(pw) if pw == PUBLIC_DEFAULT_SECRET
        ));
        assert!(matches!(
            legacy_credential(Some("pw")),
            Credential::Password(pw) if pw != PUBLIC_DEFAULT_SECRET
        ));
    }

    /// Domain isolation subkeys the credential: same secret, different domain,
    /// unrelated locator master.
    #[test]
    fn domain_changes_the_derived_keys() {
        let digest = [7u8; 32];
        let fmt = &DEFAULT_HEVC_FORMAT;
        let k_none = derive_locator_master(Credential::Password("pw"), None, fmt.cipher, &digest)
            .expect("master");
        let k_domain = derive_locator_master(
            Credential::Password("pw"),
            Some("org.acme"),
            fmt.cipher,
            &digest,
        )
        .expect("master");
        assert_ne!(k_none, k_domain);
    }

    /// The ladder is stateless and depends only on the NAL type sequence: a
    /// non-reference picture sits on the drift-free rung, a reference non-IRAP
    /// picture on the second rung, an IRAP is excluded. An all-intra stream
    /// (still image, all-IDR video) has nothing predicted from anything, so
    /// every picture is drift-free.
    #[test]
    fn ladder_is_stateless_and_has_two_rungs() {
        // Inter stream: non-reference -> band 0, reference -> band 1.
        assert_eq!(picture_band(NAL_TRAIL_N, true), Some(BAND_NON_REFERENCE));
        assert_eq!(picture_band(NAL_TSA_N, true), Some(BAND_NON_REFERENCE));
        assert_eq!(picture_band(NAL_RASL_N, true), None);
        assert_eq!(picture_band(NAL_RASL_R, true), None);
        assert_eq!(picture_band(NAL_TRAIL_R, true), Some(BAND_REFERENCE));
        // IRAP is the prediction root of a whole GOP: never carries slots when
        // the stream has inter pictures.
        assert_eq!(picture_band(NAL_IDR_W_RADL, true), None);
        assert_eq!(picture_band(21, true), None);

        // All-intra: nothing predicts from anything, so everything is band 0 --
        // that is the still-image case and the all-IDR video case.
        assert_eq!(picture_band(NAL_TRAIL_R, false), Some(BAND_NON_REFERENCE));
        assert_eq!(
            picture_band(NAL_IDR_W_RADL, false),
            Some(BAND_NON_REFERENCE)
        );
        assert_eq!(picture_band(NAL_TRAIL_N, false), Some(BAND_NON_REFERENCE));
    }

    /// Band order is the drift ladder: element 0..len(band0) all land in band 0,
    /// so a 40-byte header and a small payload never touch a reference picture.
    #[test]
    fn band_positions_exhaust_the_drift_free_rung_first() {
        let seed = [3u8; 32];
        let bands = vec![0..10usize, 10..40];
        let positions = band_positions(&bands, 10, &seed);
        assert_eq!(positions.len(), 10);
        assert!(positions.iter().all(|p| *p < 10));
        // Every slot of the band is used exactly once (a permutation).
        let mut seen = positions.clone();
        seen.sort_unstable();
        assert_eq!(seen, (0..10).collect::<Vec<_>>());

        // Spilling into band 1 happens only after band 0 is exhausted.
        let wide = band_positions(&bands, 25, &seed);
        assert!(wide[..10].iter().all(|p| *p < 10));
        assert!(wide[10..].iter().all(|p| (10..40).contains(p)));
    }

    /// The body slot order must depend on the session `perm_seed`; a fixed
    /// Weyl order would let an analyst reproduce it from the public build.
    #[test]
    fn band_positions_are_keyed_by_perm_seed() {
        let bands = vec![0..16usize, 16..40];
        let a = band_positions(&bands, 20, &[1u8; 32]);
        let b = band_positions(&bands, 20, &[2u8; 32]);
        assert_ne!(a, b, "different session seeds must reorder the slots");
        // Both remain valid per-band permutations.
        for (positions, band) in [(&a, &bands[0]), (&b, &bands[0])] {
            let mut prefix = positions[..16].to_vec();
            prefix.sort_unstable();
            assert_eq!(prefix, (0..16).collect::<Vec<_>>());
            assert!(positions[16..].iter().all(|p| (16..40).contains(p)));
            let _ = band;
        }
    }

    /// Element `i` must map to the same slot no matter how many elements are
    /// requested -- the extractor reads the header with a short prefix and then
    /// the whole message with a longer one.
    #[test]
    fn band_positions_are_prefix_stable() {
        let seed = [5u8; 32];
        let bands = vec![0..7usize, 7..23, 23..24];
        let full = band_positions(&bands, 24, &seed);
        for count in [1usize, 5, 7, 12, 23] {
            assert_eq!(band_positions(&bands, count, &seed), full[..count].to_vec());
        }
        // Empty bands (no slots recorded) must not shift the mapping.
        let with_empty = vec![0..0usize, 0..7, 7..7, 7..23];
        assert_eq!(band_positions(&with_empty, 12, &seed), full[..12].to_vec());
    }

    #[test]
    fn non_reference_types_are_the_even_vcl_range() {
        for t in 0u8..=9 {
            assert_eq!(is_non_reference_vcl(t), t % 2 == 0, "nal_type {t}");
        }
        // 16..=21 (BLA/IDR/CRA) are all reference pictures.
        for t in 16u8..=21 {
            assert!(!is_non_reference_vcl(t), "nal_type {t} is an IRAP");
        }
    }
}

/// Regression tests for the safety-policy gate (bug B1: the HEVC path used to
/// receive only the tier's level, so `--enforce-safety` never blocked).
#[cfg(test)]
mod safety_policy_tests {
    use super::enforce_safety;
    use crate::errors::StrHideError;
    use crate::stego::{SafetyEnforcement, SafetyLevel, SafetyPolicy};

    fn policy(enforcement: SafetyEnforcement) -> SafetyPolicy {
        SafetyPolicy {
            level: SafetyLevel::High,
            enforcement,
        }
    }

    #[test]
    fn advisory_policy_never_blocks_an_over_tier_payload() {
        let p = policy(SafetyEnforcement::Advisory);
        assert!(enforce_safety(10_000, 4_788, 16_618, p).is_ok());
    }

    #[test]
    fn enforced_policy_blocks_an_over_tier_payload() {
        let p = policy(SafetyEnforcement::Enforced);
        let err = enforce_safety(9_216, 4_788, 16_618, p).expect_err("must be refused");
        assert!(
            matches!(err, StrHideError::SafetyThreshold { .. }),
            "expected SafetyThreshold, got {err:?}"
        );
        let text = err.to_string();
        assert!(text.contains("4788") && text.contains("9216"), "{text}");
    }

    #[test]
    fn enforced_policy_allows_a_payload_at_the_recommended_boundary() {
        let p = policy(SafetyEnforcement::Enforced);
        assert!(enforce_safety(4_788, 4_788, 16_618, p).is_ok());
        assert!(enforce_safety(0, 4_788, 16_618, p).is_ok());
    }
}

#[cfg(test)]
mod annex_b_parameter_set_tests {
    use super::{active_parameter_sets, sample_prefix_has_inter};

    #[test]
    fn a_gop_only_sees_parameter_sets_that_precede_it() {
        let sets = vec![vec![0x40, 0x01], vec![0x42, 0x01], vec![0x44, 0x01]];
        // Container carriers apply every set up front.
        let all = active_parameter_sets(&sets, None, 0);
        assert_eq!(all.len(), 3);

        // Annex-B: the set ending at byte 10 is not visible to a GOP at byte 5,
        // while both earlier sets are.
        let ends = [10usize, 20, 90];
        assert_eq!(active_parameter_sets(&sets, Some(&ends), 5).len(), 0);
        assert_eq!(active_parameter_sets(&sets, Some(&ends), 10).len(), 1);
        assert_eq!(active_parameter_sets(&sets, Some(&ends), 90).len(), 3);
        // A mid-stream redefinition does not leak backwards.
        assert_eq!(active_parameter_sets(&sets, Some(&ends), 45).len(), 2);
    }

    #[test]
    fn sample_prefix_classifies_slice_nal_types() {
        let mut sample = Vec::new();
        // length_size = 2, IRAP slice (type 19) then a trailing P slice (type 1).
        sample.extend_from_slice(&4u16.to_be_bytes());
        sample.extend_from_slice(&[19 << 1, 1, 0, 0]);
        sample.extend_from_slice(&4u16.to_be_bytes());
        sample.extend_from_slice(&[1 << 1, 1, 0, 0]);
        assert!(sample_prefix_has_inter(&sample, 2));

        // Only an IRAP slice is not an inter frame.
        let mut irap_only = Vec::new();
        irap_only.extend_from_slice(&4u16.to_be_bytes());
        irap_only.extend_from_slice(&[19 << 1, 1, 0, 0]);
        assert!(!sample_prefix_has_inter(&irap_only, 2));

        // A truncated final NAL simply ends the walk.
        let mut truncated = Vec::new();
        truncated.extend_from_slice(&4u16.to_be_bytes());
        truncated.extend_from_slice(&[19 << 1, 1]);
        assert!(!sample_prefix_has_inter(&truncated, 2));

        // Empty/garbage prefixes never panic.
        assert!(!sample_prefix_has_inter(&[], 4));
        assert!(!sample_prefix_has_inter(&[0u8; 4], 0));
        let mut huge = 0xFFFF_FFFFu32.to_be_bytes().to_vec();
        huge.push(0);
        assert!(!sample_prefix_has_inter(&huge, 4));
    }
}

/// F-01 regression: the writer's decode window must never fall below the
/// reader's fixed `HEVC_SUPERBLOCK_POOL_SLOTS` header pool.
#[cfg(test)]
mod window_tests {
    use super::*;

    #[test]
    fn writer_window_never_drops_below_the_reader_pool() {
        let hdr = hevc_header_slots(0);
        // Even with no body at all the window must cover the reader's pool.
        assert_eq!(hevc_window_target_slots(hdr, 0), HEVC_SUPERBLOCK_POOL_SLOTS);
        // A body larger than the pool keeps its own demand.
        assert_eq!(hevc_window_target_slots(hdr, 4096), hdr + 4096 + 128);
    }

    /// A multi-picture carrier where one picture is smaller than the reader
    /// pool: without the floor, `TargetSlots(652)` stops after the first
    /// picture (~650 slots) and places the header over a 650-slot permutation,
    /// while extraction scans 2048 slots and reads nothing.
    #[test]
    fn write_and_read_record_the_same_pool_for_a_multipicture_carrier() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/assets/tiny40.hevc");
        let frame = std::fs::read(&path).expect("read tiny40.hevc");
        let mut carrier = Vec::new();
        for _ in 0..64 {
            carrier.extend_from_slice(&frame);
        }
        let kind = sniff_hevc_carrier(&carrier).expect("annex-b carrier");
        let target = hevc_window_target_slots(hevc_header_slots(0), 0);
        let write = record_carrier_state(
            &carrier,
            kind,
            Capture::Full,
            StopCondition::TargetSlots(target),
            &Control::none(),
        )
        .expect("write record");
        let read = record_carrier_state(
            &carrier,
            kind,
            Capture::Bits,
            StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
            &Control::none(),
        )
        .expect("read record");
        assert_eq!(
            write.total_slots().min(HEVC_SUPERBLOCK_POOL_SLOTS),
            read.total_slots().min(HEVC_SUPERBLOCK_POOL_SLOTS),
            "writer and reader must derive the header permutation from the same pool"
        );
    }

    /// The header read stops scanning at the first slice that crosses the pool
    /// threshold. `slot_budget` lets a GOP stop decoding there instead of
    /// decoding every slice of its wave; the resulting pool must be byte-for-byte
    /// the same one a `TargetSlots` window records.
    #[test]
    fn header_read_and_target_window_record_the_same_pool() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/assets/tiny40.hevc");
        let frame = std::fs::read(&path).expect("read tiny40.hevc");
        let mut carrier = Vec::new();
        for _ in 0..64 {
            carrier.extend_from_slice(&frame);
        }
        let kind = sniff_hevc_carrier(&carrier).expect("annex-b carrier");
        let read = record_carrier_state(
            &carrier,
            kind,
            Capture::Bits,
            StopCondition::MinSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
            &Control::none(),
        )
        .expect("header record");
        let window = record_carrier_state(
            &carrier,
            kind,
            Capture::Bits,
            StopCondition::TargetSlots(HEVC_SUPERBLOCK_POOL_SLOTS),
            &Control::none(),
        )
        .expect("window record");
        assert_eq!(read.total_slots(), window.total_slots());
        assert_eq!(read.slice_slot_ranges, window.slice_slot_ranges);
        assert_eq!(read.raw_bits, window.raw_bits);
        assert!(
            read.total_slots() >= HEVC_SUPERBLOCK_POOL_SLOTS,
            "fixture must cross the header pool so the stop path is exercised"
        );
        let last = read
            .slice_slot_ranges
            .last()
            .expect("non-empty recording")
            .0;
        let before_last = read.total_slots() - last;
        assert!(
            before_last < HEVC_SUPERBLOCK_POOL_SLOTS,
            "the read must stop at the crossing slice: {before_last} slots before the last one"
        );
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct ScanStats {
    pub slices_scanned: usize,
    pub total_slots: usize,
    pub band0_slots: usize,
    pub band1_slots: usize,
    pub elapsed_micros: u64,
}

#[doc(hidden)]
pub fn bench_scan_slices(
    carrier: &[u8],
    slice_count: usize,
    full_capture: bool,
) -> Result<ScanStats, StrHideError> {
    let kind = sniff_hevc_carrier(carrier)
        .ok_or_else(|| StrHideError::UnsupportedFormat("Not HEVC carrier".into()))?;
    let capture = if full_capture {
        Capture::Full
    } else {
        Capture::Bits
    };
    let t0 = std::time::Instant::now();
    let record = record_carrier_state(
        carrier,
        kind,
        capture,
        StopCondition::TargetSlices(slice_count),
        &Control::none(),
    )?;
    let elapsed = t0.elapsed().as_micros() as u64;
    let band0 = record.bands.first().map_or(0, |r| r.len());
    let band1 = record.bands.get(1).map_or(0, |r| r.len());
    Ok(ScanStats {
        slices_scanned: record.slice_slot_ranges.len(),
        total_slots: band0 + band1,
        band0_slots: band0,
        band1_slots: band1,
        elapsed_micros: elapsed,
    })
}

#[cfg(test)]
mod v4_superblock_tests {
    use super::*;

    // Frozen in docs/stego_content_envelope_v4_golden_vectors_20261103.md.
    const GOLDEN: &str = concat!(
        "1234567840010200010400010000012c",
        "202122232425262728292a2b65db3bcb",
    );
    const MAGIC: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2, "hex length");
        let mut out = [0u8; N];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    #[test]
    fn golden_superblock_round_trips_byte_for_byte() {
        let raw = hex::<32>(GOLDEN);
        let header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
        assert_eq!(
            header.version,
            crate::stego::header::CONTENT_ENVELOPE_VERSION
        );
        assert_eq!(header.stc_u, 2);
        assert_eq!(header.window_slices, 1);
        assert_eq!(header.ext_len, 4);
        assert_eq!(header.suite_id, 1);
        assert_eq!(header.body_len, 300);
        assert!(header.ext_present());
        assert!(!header.ext_critical());
        assert_eq!(header.encode(), raw);
    }

    #[test]
    fn magic_and_field_ranges_are_enforced() {
        let raw = hex::<32>(GOLDEN);
        let err =
            HevcSuperblockV4::decode(&raw, [0x12, 0x34, 0x56, 0x79]).expect_err("wrong magic");
        assert!(matches!(err, StrHideError::CorruptedData(_)));

        let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
        header.version = 0x30;
        let err = HevcSuperblockV4::decode(&header.encode(), MAGIC).expect_err("v3 must fail");
        assert!(matches!(err, StrHideError::UnsupportedVersion(_)));

        let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
        header.flags = 0x04;
        assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

        let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
        header.ext_len = 0;
        assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

        let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
        header.ext_len = 65;
        assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

        let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
        header.stc_u = 0;
        assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

        let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
        header.stc_u = 65;
        assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

        let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
        header.window_slices = 0;
        assert!(HevcSuperblockV4::decode(&header.encode(), MAGIC).is_err());

        let mut header = HevcSuperblockV4::decode(&raw, MAGIC).unwrap();
        header.suite_id = 3;
        let err = HevcSuperblockV4::decode(&header.encode(), MAGIC).expect_err("unknown suite");
        assert!(matches!(err, StrHideError::UnsupportedVersion(_)));

        let mut raw = hex::<32>(GOLDEN);
        raw[16] ^= 0x01;
        let err = HevcSuperblockV4::decode(&raw, MAGIC).expect_err("flip must fail CRC");
        assert!(matches!(err, StrHideError::CorruptedData(_)));
    }

    #[test]
    fn extension_slots_match_the_plan() {
        assert_eq!(hevc_extension_slots(0), 0);
        assert_eq!(hevc_extension_slots(1), 28);
        assert_eq!(hevc_extension_slots(64), 1036);
        assert_eq!(524 + hevc_extension_slots(64), 1560);
        assert!(524 + hevc_extension_slots(HEVC_MAX_EXT_BYTES) <= HEVC_HEADER_SLOTS_MAX);
    }

    /// Patch validation is the release-build guard for a mismatched internal
    /// patch list: it rejects the three shapes that used to panic inside
    /// `apply_hevc_patches` (reversed span, end past the carrier, replacement
    /// length differing from the span). Runs in every profile, unlike the
    /// debug assertion in the apply loop.
    #[test]
    fn patch_validation_rejects_malformed_spans() {
        let carrier_len = 16;
        assert!(validate_hevc_patches(carrier_len, &[(2..6, vec![9; 4])]).is_ok());
        assert!(validate_hevc_patches(carrier_len, &[]).is_ok());

        for (span, re_nal) in [
            (0..8, vec![9; 4]),   // replacement too short
            (0..4, vec![9; 5]),   // replacement too long
            (8..20, vec![9; 12]), // end beyond the carrier
            // Built as a struct literal: `6..2` is rejected by clippy's
            // `reversed_empty_ranges` before the test can observe it.
            (std::ops::Range { start: 6, end: 2 }, vec![9; 4]),
        ] {
            let err = validate_hevc_patches(carrier_len, &[(span, re_nal)])
                .expect_err("malformed patch must be rejected");
            assert!(
                matches!(err, StrHideError::General(ref msg) if msg.contains("does not fit")),
                "unexpected error: {err}"
            );
        }
    }

    /// The debug assertion fires before the copy, so a direct caller gets a
    /// message naming the span instead of `range end index out of range`.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "does not fit")]
    fn patch_apply_asserts_before_copying_in_debug() {
        let mut carrier = vec![0u8; 8];
        apply_hevc_patches(&mut carrier, &[(0..4, vec![1; 3])]);
    }
}

#[cfg(test)]
mod mkv_crc_tests {
    use super::*;
    use crate::stego::format::DEFAULT_HEVC_FORMAT;
    use crate::stego::hevc::mkv_boxes::parse_mkv_targets;

    /// Count checksums `parse_mkv_targets` accepts as consistent. A patched
    /// cluster whose CRC was left stale is no longer recognised, so the count
    /// drops when a caller skips the refresh.
    fn valid_crc_count(bytes: &[u8]) -> usize {
        parse_mkv_targets(bytes)
            .expect("parse Matroska")
            .crcs
            .iter()
            .filter(|crc| crc.endian.is_some())
            .count()
    }

    /// A caller that writes MKV through the library entry point, not
    /// `MkvEngine`, must still get a file whose Matroska CRC-32 elements match.
    /// The refresh lives in `embed_hevc_with_info_v4` so both paths share it.
    #[test]
    fn library_embed_refreshes_mkv_crcs() {
        let path = "../temp/videosamples/TEST2__hevc_mkv_1080.mkv";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let carrier = std::fs::read(path).expect("read MKV sample");
        assert!(
            !parse_mkv_targets(&carrier)
                .expect("parse Matroska")
                .crcs
                .is_empty(),
            "sample must carry CRC-32 elements"
        );
        let before = valid_crc_count(&carrier);
        assert!(
            before > 0,
            "sample must have a consistent CRC-32 to compare"
        );

        let (out, _, _) = embed_hevc_with_info(
            &carrier,
            &Payload::bytes(b"mkv-crc"),
            Some("mkv-crc-pw"),
            None,
            &DEFAULT_HEVC_FORMAT,
            Freshness::Random,
            SafetyPolicy::new(),
            &Control::none(),
        )
        .expect("library embed");

        assert_eq!(out.len(), carrier.len(), "patch embed keeps the length");
        assert_eq!(valid_crc_count(&out), before, "CRC-32 refreshed");
    }
}
