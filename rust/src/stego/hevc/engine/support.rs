//! Shared HEVC helpers: NAL primitives, credential gates, TLV and window math.

use sha2::{Digest, Sha256};

use crate::core::crypto::{CONTENT_L1_PBKDF2_ITERATIONS, Credential};
use crate::errors::StrHideError;
use crate::stego::coding::StcTrellis;
use crate::stego::envelope::BODY_OVERHEAD;
use crate::stego::format::HevcFormatProfile;
use crate::stego::header::{TLV_CRITICAL, Tlv, encode_extension_for_write};
use crate::stego::hevc::superblock::{
    HEVC_MAX_EXT_BYTES, HEVC_SUPERBLOCK_POOL_SLOTS, hevc_header_slots,
};
use crate::stego::params::ExtractParams;

/// The three header fields the writer needs back, read straight off the 2-byte
/// NAL header (§7.3.1.2). The decoder hands us the same stream but not the
/// envelope, and the span table only covers Annex-B carriers.
pub(super) fn nal_header_fields(nal: &[u8]) -> (u8, u8, u8) {
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
pub(super) fn nal_rbsp(nal: &[u8]) -> Vec<u8> {
    if nal.len() < 2 {
        return Vec::new();
    }
    rusty_h265::nal::unescape(&nal[2..]).data
}

/// Fixed seed for the capacity probe's trellis. Only `slots_for` is used
/// (which depends on `h`/`u`, not the seed), so any value works.
pub(super) const CAPACITY_PROBE_SEED: u64 = 0x5465_676f;

/// Maximum number of STC re-solves while settling the flip set. Each round
/// either drops the slots that disturbed an emulation-prevention (EPB) window,
/// drops a substream whose journal does not replay the cover, or gives up, so
/// the loop always makes progress. Healthy carriers settle in one round.
pub(super) const MAX_EMBED_ROUNDS: usize = 24;

/// Extra cost added to a slot excluded by an earlier round. It must lift the
/// slot strictly above its own legal cost: a legal high-displacement slot
/// already costs `HIGH_DISPLACEMENT_PENALTY + l2_cost`, so reusing the bare
/// penalty here made excluded slots *cheaper* and the trellis preferred them.
pub(super) const FORBIDDEN_SLOT_SURCHARGE: f64 = 1e9;

/// Format id bound into the V4 AAD (JPEG = 4, HEVC = 5).
pub(crate) const HEVC_FORMAT_ID: u8 = 5;

/// Credential mapping for the pre-V4 `Option<&str>` entry points.
///
/// An absent secret is a **hard error**, not a fallback to
/// [`crate::stego::envelope::PUBLIC_DEFAULT_SECRET`]. These entry points receive a format profile but
/// no [`crate::stego::params::StegoProfile`], so they cannot honour a private
/// `default_secret`; silently keying the carrier with the public constant would
/// produce a file every other strhide build can read, which defeats the point
/// of a private dialect. Callers must pass the secret explicitly (the facade
/// resolves it from the dialect before reaching these wrappers).
pub(super) fn legacy_credential(secret: Option<&str>) -> Result<Credential<'_>, StrHideError> {
    match secret.filter(|s| !s.is_empty()) {
        Some(s) => Ok(Credential::Password(s)),
        None => Err(StrHideError::General(
            "HEVC entry points need an explicit password or file key: an absent secret would be \
             keyed with the public default, making the carrier readable by any strhide build"
                .into(),
        )),
    }
}

/// Refuse a password-mode L1 below the fixed V4 work factor before the KDF runs.
///
/// A caller that lowers `max_pbkdf2_iterations` is asking the extractor to run
/// a cheaper (weaker) L1 than the writer used; every such carrier is simply
/// unreadable, so the answer is `NoHiddenData` without paying any KDF cost.
pub(super) fn check_l1_floor(
    cred: &Credential<'_>,
    limits: &ExtractParams,
) -> Result<(), StrHideError> {
    if matches!(cred, Credential::Password(_))
        && limits.max_pbkdf2_iterations < CONTENT_L1_PBKDF2_ITERATIONS
    {
        return Err(StrHideError::NoHiddenData(
            "No valid payload found (L1 work factor below the V4 floor)".into(),
        ));
    }
    Ok(())
}

/// Early-exit stopping condition for streaming NAL decode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StopCondition {
    /// Full scan (for probe_hevc_capacity).
    All,
    /// Stop as soon as at least `min_slots` are accumulated (for Superblock probing).
    MinSlots(usize),
    /// Stop after `target` recorded slices (for window extraction).
    TargetSlices(usize),
    /// Stop as soon as at least `target` slots are accumulated (for window embedding).
    TargetSlots(usize),
}

/// Partition non-Superblock slots within the window into Band 0 and Band 1 stream indices.
pub(super) fn get_body_slot_indices(
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
pub(super) type SlotBitTrace = (usize, usize, usize);

/// A disturbed emulation-prevention window: the RBSP byte that starts the
/// `00 00 xx<=3` triple, plus the trace of every flipped slot in that slice.
pub(super) type EpbConflict = (usize, Vec<SlotBitTrace>);

/// Slots the writer must decode before it can place the header and body.
///
/// The floor is `HEVC_SUPERBLOCK_POOL_SLOTS`, the same upper bound the reader
/// records in its first pass. Both sides derive the keyed header permutation
/// from `recorded_slots.min(POOL_SLOTS)`, so a smaller write window would move
/// the header to different slot positions and make the carrier unreadable.
pub(super) fn hevc_window_target_slots(hdr_slots: usize, desired_body_slots: usize) -> usize {
    (hdr_slots + desired_body_slots + 128).max(HEVC_SUPERBLOCK_POOL_SLOTS)
}

/// Serialize the extension area and enforce the HEVC upper bound.
pub(super) fn extension_len(extensions: &[Tlv]) -> Result<usize, StrHideError> {
    let len = encode_extension_for_write(extensions)?.len();
    if len > HEVC_MAX_EXT_BYTES {
        return Err(StrHideError::UnsupportedFormat(format!(
            "HEVC extension area is {len} bytes, maximum is {HEVC_MAX_EXT_BYTES}"
        )));
    }
    Ok(len)
}

/// L3 session salt: domain-separated SHA-256 of the header nonce.
pub(super) fn hevc_session_salt(label: &[u8], nonce: &[u8; 12]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(nonce);
    hasher.finalize().into()
}

pub(super) fn has_critical_tlv(extensions: &[Tlv]) -> bool {
    extensions.iter().any(Tlv::is_critical)
}

/// Critical-bit check over raw tag bytes read back from the extension area.
pub(super) fn tags_have_critical(tags: &[u8]) -> bool {
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
pub(super) fn hevc_max_raw_payload(
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
