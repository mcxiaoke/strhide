//! HEVC V4 superblock: wire format, extension-area sizing and keyed slot layout.
//!
//! The superblock is the only structure the extractor can find without knowing
//! anything about the payload, so its byte layout and the keyed permutation
//! that scatters it over the first candidate slots are kept together here. The
//! embedder and extractor both derive the same positions from the same
//! constants; nothing in this module depends on the decode pipeline.

use crate::errors::StrHideError;

/// Fixed 32-byte HEVC superblock.
pub(crate) const HEVC_SUPERBLOCK_BYTES: usize = 32;
/// Number of initial carrier slots that form the Superblock candidate pool.
pub const HEVC_SUPERBLOCK_POOL_SLOTS: usize = 2048;
/// Base header slots of the 32-byte Superblock under STC h=7, u=2.
pub(crate) const HEVC_SUPERBLOCK_MIN_SLOTS: usize = 524;

/// Upper bound of the HEVC V4 extension area.
pub(crate) const HEVC_MAX_EXT_BYTES: usize = 64;

/// Largest header slot pool the HEVC locator may use.
#[allow(dead_code)]
pub(crate) const HEVC_HEADER_SLOTS_MAX: usize = 2048;

/// STC height of the HEVC extension area.
pub(crate) const HEVC_EXT_STC_H: u8 = 7;

/// STC group size of the HEVC extension area.
pub(crate) const HEVC_EXT_STC_U: u8 = 2;

/// Slots used by `ext_len` extension bytes under STC `h=7, u=2`.
pub(crate) fn hevc_extension_slots(ext_len: usize) -> usize {
    if ext_len == 0 {
        0
    } else {
        HEVC_EXT_STC_U as usize * (8 * ext_len + HEVC_EXT_STC_H as usize - 1)
    }
}

/// CRC scope of the 32-byte HEVC V4 superblock.
pub(crate) const HEVC_V4_CRC_SPAN: usize = 28;

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

/// Keyed slot permutation of the header area.
///
/// The first `HEVC_SUPERBLOCK_MIN_SLOTS` slots carry the base header; the
/// following `hevc_extension_slots(ext_len)` slots carry the extension TLV
/// area. Both are the *prefix* of one permutation driven by the L2
/// `locate_seed`, so the extractor reads the base first and can extend to the
/// continuation slots only after learning `ext_len` from it.
pub(crate) fn superblock_positions(
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
pub(crate) fn keyed_band_params(
    len: usize,
    perm_seed: &[u8; 32],
    band_start: usize,
) -> (usize, usize) {
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

/// Header slots of a carrier with `ext_len` extension bytes.
pub(crate) fn hevc_header_slots(ext_len: usize) -> usize {
    HEVC_SUPERBLOCK_MIN_SLOTS + hevc_extension_slots(ext_len)
}

pub(crate) fn gcd_usize(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}
