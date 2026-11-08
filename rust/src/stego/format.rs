//! Format identities for the content-domain steganography formats.
//!
//! The wire formats live here, all of them *compile-time* facts rather than
//! runtime options:
//!
//! [`JpegFormatProfile`] (and its HEVC / spatial / audio siblings) is the
//! identity of a wire format: the domain-separation labels that feed every KDF,
//! the superblock / extension geometry, the slot grid rule, and the default
//! cipher suite. Changing any of it produces a *different format*: two binaries
//! built with different profiles cannot read each other's carriers, and the
//! failure is indistinguishable from a wrong password.
//!
//! [`CipherSuiteId`] is the runtime suite id stored in the superblock; it
//! selects the AEAD algorithm and is validated against the compiled-in
//! whitelist.
//!
//! # Why the profile is a value and not a pile of constants
//!
//! The realistic use of a steganography tool is "compile a private build": edit
//! every constant an upstream detector could model as a fingerprint, and use it
//! yourself. If those constants are `const` items scattered across modules, that
//! means forking the crate. As a public value, a private build is a single
//! `JpegFormatProfile` literal plus `cargo build`.
//!
//! # Frozen once published
//!
//! `DEFAULT_JPEG_FORMAT` is the wire format. Its fields are documented one by one
//! below; after the first release they may only be changed by bumping
//! `format_major` (a new format), because every historical carrier was written
//! with the old derivation.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::{CONTENT_L1_PBKDF2_ITERATIONS, CipherSuiteId, Credential, normalize_nfc};
use crate::errors::StrHideError;
use crate::stego::envelope::derive_domain_subkey_with_label;

/// Which coefficients of a block belong to the slot grid.
///
/// The default covers every AC position (`k = 1..=63`). A private build may
/// narrow it to a mid-frequency band; what it must **never** do is include
/// `k = 0`, because the DC coefficients are the salt of the header-location KDF
/// and must stay untouched by embedding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridRule {
    /// Lowest AC index in the grid (>= 1).
    pub k_min: u8,
    /// Highest AC index in the grid (<= 63).
    pub k_max: u8,
}

impl GridRule {
    /// All AC positions of a block.
    pub const ALL_AC: GridRule = GridRule {
        k_min: 1,
        k_max: 63,
    };

    /// Positions per block carried by this rule.
    pub const fn slots_per_block(&self) -> usize {
        (self.k_max - self.k_min + 1) as usize
    }
}

/// HKDF label of the FLAC body-phase draw (`strhide-v4-flac-body-phase`).
pub(crate) const OFFICIAL_FLAC_BODY_PHASE_LABEL: &[u8] = b"strhide-v4-flac-body-phase";

/// Domain separator of the HEVC L3 session salt (`strhide-hevc-session-v4`).
pub(crate) const OFFICIAL_HEVC_SESSION_LABEL: &[u8] = b"strhide-hevc-session-v4";

/// Identity of the HEVC Scheme C wire format.
///
/// The JPEG and PNG engines derive everything from labelled HKDF inputs and a
/// geometric slot grid; Scheme C does the same, but until now its labels lived
/// as module constants, so a private build could not own them without forking.
/// Changing any field here produces a different format: two builds with
/// different profiles cannot read each other's carriers, and the failure is
/// indistinguishable from a wrong password.
///
/// # Field effects (for private builds)
///
/// | field | change it and… |
/// | :--- | :--- |
/// | `cipher` | the V4 label table, default suite and L1/L2/L3 derivations change |
/// | `magic_label` | the L2-derivation label changes, so the derived magic and locator keys move |
/// | `cover_salt` | the cover digest changes, so every key and the trellis seed move |
/// | `stc_h` / `stc_u` | different trellis geometry; both sides must agree (the header does not carry them) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HevcFormatProfile {
    /// V4 label table and default suite.
    pub cipher: &'static WireCipherProfile,
    /// HKDF-style label the locator keys (and the derived 4-byte magic) are
    /// derived from. V4 no longer mixes the secret into a separate magic hash.
    pub magic_label: &'static [u8],
    /// Prefix mixed into the cover digest (`SHA-256(cover_salt ‖ "hevc-v4" ‖ parameter sets)`).
    pub cover_salt: &'static [u8],
    /// Domain separator of the L3 session salt
    /// (`SHA-256(label ‖ nonce)`), derived after the superblock is readable.
    pub session_salt_label: &'static [u8],
    /// STC constraint height.
    pub stc_h: u8,
    /// STC group size (elements per syndrome row).
    pub stc_u: u8,
}

/// Official Scheme C wire format (V4 content envelope).
pub const DEFAULT_HEVC_FORMAT: HevcFormatProfile = HevcFormatProfile {
    cipher: &OFFICIAL_HEVC_CIPHER,
    magic_label: b"strhide-hevc-magic-v4",
    cover_salt: b"strhide-hevc-cover-v1",
    session_salt_label: OFFICIAL_HEVC_SESSION_LABEL,
    stc_h: 7,
    stc_u: 2,
};

/// Serialised JPEG superblock size in bytes (352 bits).
#[doc(hidden)]
pub const JPEG_SUPERBLOCK_BYTES: usize = 44;

/// Bit slots of the default JPEG superblock (`2 * (44 * 8 + 8 - 1)`).
#[doc(hidden)]
pub const JPEG_SUPERBLOCK_SLOTS: usize = 718;

/// Identity of one JPEG wire format.
///
/// # Field effects (for private builds)
///
/// | field | change it and… |
/// | :--- | :--- |
/// | `cover_digest_tag` | the L1 `pre_salt` changes, so no header can be found: unreadable |
/// | `cipher` | the V4 label table and the default suite change: unreadable |
/// | `sb_bytes` | must stay 44, the serialised superblock length |
/// | `sb_h` / `sb_u` | different superblock slot count; must stay self-consistent |
/// | `ext_h` / `ext_u` | different extension-area slot count |
/// | `grid_rule` | different slot set |
///
/// A mismatch on any of the derivation labels behaves exactly like a wrong
/// password (`NoHiddenData`), which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JpegFormatProfile {
    /// KDF-salt tag of the cover digest (V4 `pre_salt` domain separation).
    pub cover_digest_tag: &'static [u8],
    /// V4 label table and default suite.
    pub cipher: &'static WireCipherProfile,
    /// Superblock size in bytes (44).
    pub sb_bytes: u8,
    /// Superblock STC constraint height (8).
    pub sb_h: u8,
    /// Superblock STC group size (2).
    pub sb_u: u8,
    /// Extension-area STC constraint height (8).
    pub ext_h: u8,
    /// Extension-area STC group size (4).
    pub ext_u: u8,
    /// Which AC positions form the slot grid.
    pub grid_rule: GridRule,
}

impl JpegFormatProfile {
    /// Bits carried by the superblock (`sb_bytes * 8`).
    pub const fn superblock_bits(&self) -> usize {
        self.sb_bytes as usize * 8
    }

    /// Slots the superblock occupies: `u * (bits + h - 1)`, exact by design.
    pub const fn superblock_slots(&self) -> usize {
        self.sb_u as usize * (self.superblock_bits() + self.sb_h as usize - 1)
    }

    /// Slots the extension area occupies for `ext_bytes` of TLV data.
    pub const fn extension_slots(&self, ext_bytes: usize) -> usize {
        self.ext_u as usize * (8 * ext_bytes + self.ext_h as usize - 1)
    }

    /// Total header slots (superblock + extension area).
    pub const fn header_slots(&self, ext_bytes: usize) -> usize {
        self.superblock_slots() + self.extension_slots(ext_bytes)
    }

    /// The suite a fresh carrier is written with when the caller is silent.
    pub fn default_suite(&self) -> CipherSuiteId {
        self.cipher.default_suite
    }

    /// First structural problem with this profile, if any.
    fn problem(&self) -> Option<String> {
        if self.sb_bytes < 1 {
            return Some("sb_bytes must be >= 1".into());
        }
        if !(4..=10).contains(&self.sb_h) {
            return Some(format!("sb_h must be in 4..=10, got {}", self.sb_h));
        }
        if !(1..=64).contains(&self.sb_u) {
            return Some(format!("sb_u must be in 1..=64, got {}", self.sb_u));
        }
        if !(4..=10).contains(&self.ext_h) {
            return Some(format!("ext_h must be in 4..=10, got {}", self.ext_h));
        }
        if !(1..=64).contains(&self.ext_u) {
            return Some(format!("ext_u must be in 1..=64, got {}", self.ext_u));
        }
        // `n = u * (bits + h - 1)` must carry exactly `bits` message bits, i.e.
        // `n / u - (h - 1) == bits`, which holds by construction. The check that
        // *can* fail is the one below: the superblock is serialised to a fixed
        // [`SUPERBLOCK_BYTES`] buffer, so a profile that claims a different
        // `sb_bytes` embeds the wrong number of bits -- fewer silently truncates
        // the header and makes every carrier unreadable, more reads past the
        // buffer.
        if self.sb_bytes as usize != JPEG_SUPERBLOCK_BYTES {
            return Some(format!(
                "sb_bytes must be {}, the serialised superblock length, got {}",
                JPEG_SUPERBLOCK_BYTES, self.sb_bytes
            ));
        }
        if self.grid_rule.k_min < 1 {
            return Some(format!(
                "grid_rule.k_min must be >= 1 (DC must never enter the grid), got {}",
                self.grid_rule.k_min
            ));
        }
        if self.grid_rule.k_max > 63 || self.grid_rule.k_min > self.grid_rule.k_max {
            return Some(format!(
                "grid_rule [{}, {}] is out of range or inverted",
                self.grid_rule.k_min, self.grid_rule.k_max
            ));
        }
        if self.cover_digest_tag.is_empty() {
            return Some("cover_digest_tag must not be empty".into());
        }
        None
    }

    /// Validate the profile, rejecting a geometry that cannot decode itself.
    ///
    /// Called at every public entry point; it is a handful of integer
    /// comparisons, so there is no reason to make it optional.
    pub fn validate(&self) -> Result<(), StrHideError> {
        match self.problem() {
            Some(problem) => Err(StrHideError::General(format!(
                "Invalid JpegFormatProfile: {problem}"
            ))),
            None => Ok(()),
        }
    }
}

/// The v1 wire format: 44-byte superblock (718 slots), 4-way extension area,
/// full AC grid, PBKDF2 suites 1 and 2.
pub const DEFAULT_JPEG_FORMAT: JpegFormatProfile = JpegFormatProfile {
    cover_digest_tag: b"strhide-cover-v1",
    cipher: &OFFICIAL_JPEG_CIPHER,
    sb_bytes: 44,
    sb_h: 8,
    sb_u: 2,
    ext_h: 8,
    ext_u: 4,
    grid_rule: GridRule::ALL_AC,
};

/// Identity and KDF derivation labels for spatial (PNG) steganography.
///
/// V4 keeps the same shape as [`AudioFormatProfile`]: the public `hpos_salt`
/// feeds the carrier-derived `pre_salt`, and the private [`WireCipherProfile`]
/// supplies every non-secret KDF label. Changing either produces a different
/// wire format -- a carrier written with one build is unreadable with another,
/// and the failure is indistinguishable from a wrong password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PngFormatProfile {
    /// HKDF salt mixed into the carrier's `pre_salt`.
    pub hpos_salt: &'static [u8],
    /// V4 label table and default suite.
    pub cipher: &'static WireCipherProfile,
}

pub const OFFICIAL_PNG_FORMAT: PngFormatProfile = PngFormatProfile {
    hpos_salt: b"strhide-stego-hpos-salt-v2",
    cipher: &OFFICIAL_PNG_CIPHER,
};

/// Identity of audio (WAV / FLAC) steganography.
///
/// V4 splits identity into two pieces: the public `hpos_salt` feeds the
/// carrier-derived `pre_salt`, and the private [`WireCipherProfile`] supplies
/// every non-secret KDF label. A private profile still changes both, so a
/// carrier written with one build is unreadable with another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioFormatProfile {
    /// HKDF salt mixed into the carrier's `pre_salt`.
    pub hpos_salt: &'static [u8],
    /// V4 label table and default suite.
    pub cipher: &'static WireCipherProfile,
    /// Domain separator of the FLAC body-phase draw
    /// (`SHA-256(label ‖ base ‖ salt ‖ nonce)`).
    ///
    /// Consumed by the FLAC engine only; the WAV engine has no per-attempt body
    /// phase and ignores it. Both ends of a FLAC carrier must agree, so a
    /// private value isolates the body slot subset without touching any other
    /// derivation.
    pub flac_body_phase_label: &'static [u8],
}

/// Official WAV profile.
pub const OFFICIAL_WAV_FORMAT: AudioFormatProfile = AudioFormatProfile {
    hpos_salt: b"strhide-audio-hpos-salt-v1",
    cipher: &OFFICIAL_AUDIO_CIPHER,
    flac_body_phase_label: OFFICIAL_FLAC_BODY_PHASE_LABEL,
};

/// Official FLAC profile.
///
/// A separate `hpos_salt` from WAV keeps the header permutation independent
/// between the two carriers even when a caller reuses one password across a
/// library of mixed formats.
pub const OFFICIAL_FLAC_FORMAT: AudioFormatProfile = AudioFormatProfile {
    hpos_salt: b"strhide-flac-hpos-salt-v1",
    cipher: &OFFICIAL_AUDIO_CIPHER,
    flac_body_phase_label: OFFICIAL_FLAC_BODY_PHASE_LABEL,
};

/// HKDF label of the L2 header-trellis seed (`strhide-v4-hdr-stc`).
pub(crate) const OFFICIAL_HDR_STC_LABEL: &[u8] = b"strhide-v4-hdr-stc";

/// HKDF label of the L2 extension-area trellis seed (`strhide-v4-ext-stc`).
pub(crate) const OFFICIAL_EXT_STC_LABEL: &[u8] = b"strhide-v4-ext-stc";

/// Domain prefix of the V4 AEAD associated data
/// (`strhide-content-envelope-v4\0`).
pub(crate) const OFFICIAL_AAD_PREFIX: &[u8] = b"strhide-content-envelope-v4\0";

/// Non-secret cipher identity of a V4 wire format.
///
/// The V4 envelope derives everything from one symbol table: the L1 party label
/// is the only per-format secret input, and the remaining labels separate
/// header location, payload key, permutation and trellis. `default_suite` is an
/// opinion, not a policy: the carrier's `suite_id` always wins when reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireCipherProfile {
    /// HKDF label of the L1 domain-subkey (also the `credential_kind` outcome's
    /// domain separation input).
    pub domain_label: &'static [u8],
    /// HKDF label of the header-location seed (`locate_seed`).
    pub hpos_label: &'static [u8],
    /// HKDF label of the AEAD key (`enc_key`).
    pub enc_label: &'static [u8],
    /// HKDF label of the body permutation seed.
    pub perm_label: &'static [u8],
    /// HKDF label of the trellis seed.
    pub stc_label: &'static [u8],
    /// HKDF label of the base-header trellis seed (L2, derived before the
    /// header is readable).
    ///
    /// Consumed by the carriers whose header is trellis-coded — JPEG's
    /// superblock and HEVC's superblock. The PNG and audio engines read their
    /// base header by direct LSB (`read_slot_bytes`) and never build this
    /// trellis, so for those two the label is inert: changing it isolates
    /// nothing. It still has to be part of the table so every format names its
    /// own seeds.
    pub hdr_stc_label: &'static [u8],
    /// HKDF label of the extension-area trellis seed (L2). Same consumer set as
    /// [`hdr_stc_label`](Self::hdr_stc_label).
    pub ext_stc_label: &'static [u8],
    /// Domain prefix of the V4 AEAD associated data. Both ends must agree:
    /// it is hashed into every header/body authentication tag, so a mismatch
    /// fails the tag exactly like a wrong password.
    pub aad_prefix: &'static [u8],
    /// Suite id written when the caller does not override it.
    pub default_suite: CipherSuiteId,
}

/// V4 official cipher for PNG carriers.
#[doc(hidden)]
pub const OFFICIAL_PNG_CIPHER: WireCipherProfile = WireCipherProfile {
    domain_label: b"strhide-stego-domain-v1",
    hpos_label: b"strhide-stego-hpos-v2",
    enc_label: b"enc",
    perm_label: b"perm",
    stc_label: b"strhide-stc-trellis-v1",
    hdr_stc_label: OFFICIAL_HDR_STC_LABEL,
    ext_stc_label: OFFICIAL_EXT_STC_LABEL,
    aad_prefix: OFFICIAL_AAD_PREFIX,
    default_suite: CipherSuiteId::Aes256Gcm,
};

/// V4 official cipher for WAV / FLAC carriers.
#[doc(hidden)]
pub const OFFICIAL_AUDIO_CIPHER: WireCipherProfile = WireCipherProfile {
    domain_label: b"strhide-stego-domain-v1",
    hpos_label: b"audio-hpos",
    enc_label: b"audio-enc-v1",
    perm_label: b"audio-perm-v1",
    stc_label: b"audio-stc-trellis-v1",
    hdr_stc_label: OFFICIAL_HDR_STC_LABEL,
    ext_stc_label: OFFICIAL_EXT_STC_LABEL,
    aad_prefix: OFFICIAL_AAD_PREFIX,
    default_suite: CipherSuiteId::Aes256Gcm,
};

/// V4 official cipher for JPEG carriers.
#[doc(hidden)]
pub const OFFICIAL_JPEG_CIPHER: WireCipherProfile = WireCipherProfile {
    domain_label: b"strhide-stego-domain-v1",
    hpos_label: b"hpos",
    enc_label: b"enc",
    perm_label: b"perm",
    stc_label: b"stc-trellis",
    hdr_stc_label: OFFICIAL_HDR_STC_LABEL,
    ext_stc_label: OFFICIAL_EXT_STC_LABEL,
    aad_prefix: OFFICIAL_AAD_PREFIX,
    default_suite: CipherSuiteId::Aes256Gcm,
};

/// V4 official cipher for HEVC carriers (MOV/MP4/HEIC/Annex B).
#[doc(hidden)]
pub const OFFICIAL_HEVC_CIPHER: WireCipherProfile = WireCipherProfile {
    domain_label: b"strhide-stego-domain-v1",
    hpos_label: b"strhide-hevc-hpos-v4",
    enc_label: b"strhide-hevc-enc-v4",
    perm_label: b"strhide-hevc-perm-v4",
    stc_label: b"strhide-hevc-stc-v4",
    hdr_stc_label: OFFICIAL_HDR_STC_LABEL,
    ext_stc_label: OFFICIAL_EXT_STC_LABEL,
    aad_prefix: OFFICIAL_AAD_PREFIX,
    default_suite: CipherSuiteId::Aes256Gcm,
};

/// Keys derived before the header is located (L2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct HeaderLocatorKeys {
    /// Slot permutation seed for the header block.
    pub locate_seed: [u8; 32],
    /// Trellis seed of the base header block.
    pub header_stc_seed: u64,
    /// Trellis seed of the extension area.
    pub ext_stc_seed: u64,
    /// Derived 4-byte HEVC magic (unused by the other formats).
    pub magic4: [u8; 4],
}

/// Per-carrier payload keys (L3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionKeys {
    /// AEAD key.
    pub enc_key: [u8; 32],
    /// Body slot permutation seed.
    pub perm_seed: [u8; 32],
    /// Body trellis seed.
    pub stc_seed: u64,
}

fn hkdf_expand(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info, out)
        .expect("HKDF expand fits the SHA-256 output budget");
}

fn hkdf_expand_u64(ikm: &[u8], info: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    hkdf_expand(None, ikm, info, &mut out);
    u64::from_be_bytes(out)
}

thread_local! {
    /// Number of [`derive_locator_master`] calls on the current thread.
    ///
    /// One L1 derivation is the expensive half of every operation (200k PBKDF2
    /// for a password), so "one derivation per request" is a testable contract
    /// rather than a comment: `verify` used to re-run it for its payload level.
    /// Thread-local on purpose -- the test harness runs cases concurrently in
    /// one process, and a global counter would be noise.
    static LOCATOR_DERIVATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Read the L1 derivation counter of the current thread.
#[doc(hidden)]
pub fn locator_derivation_count() -> usize {
    LOCATOR_DERIVATIONS.with(std::cell::Cell::get)
}

/// Reset the L1 derivation counter of the current thread.
#[doc(hidden)]
pub fn reset_locator_derivation_count() {
    LOCATOR_DERIVATIONS.with(|count| count.set(0));
}

/// L1: derive the locator master from a password or a 32-byte file key.
///
/// A password costs exactly [`CONTENT_L1_PBKDF2_ITERATIONS`] PBKDF2 iterations;
/// a file key is already high-entropy and only runs one HKDF expansion. The
/// header location is derived from the result, so a password guess cannot be
/// tested without paying the full L1 cost.
pub fn derive_locator_master(
    cred: Credential<'_>,
    domain: Option<&str>,
    cipher: &WireCipherProfile,
    pre_salt: &[u8; 32],
) -> Result<[u8; 32], StrHideError> {
    LOCATOR_DERIVATIONS.with(|count| count.set(count.get() + 1));
    match cred {
        Credential::Password(password) => {
            let normalized = normalize_nfc(password);
            let subkey =
                derive_domain_subkey_with_label(normalized.as_bytes(), domain, cipher.domain_label);
            let effective_ikm: &[u8] = match &subkey {
                Some(subkey) => subkey,
                None => normalized.as_bytes(),
            };
            let mut master = [0u8; 32];
            pbkdf2::pbkdf2_hmac::<Sha256>(
                effective_ikm,
                pre_salt,
                CONTENT_L1_PBKDF2_ITERATIONS,
                &mut master,
            );
            Ok(master)
        }
        Credential::FileKey(key) => {
            let info = info_with_domain(cipher.domain_label, domain);
            let mut master = [0u8; 32];
            hkdf_expand(Some(pre_salt.as_slice()), key, &info, &mut master);
            Ok(master)
        }
    }
}

/// L2: derive the header-locator keys without any random salt.
pub fn derive_l2_locator_keys(
    master: &[u8; 32],
    cipher: &WireCipherProfile,
    magic_label: &[u8],
    domain: Option<&str>,
) -> Result<HeaderLocatorKeys, StrHideError> {
    let locate_info = info_with_domain(cipher.hpos_label, domain);
    let magic_info = info_with_domain(magic_label, domain);
    let mut locate_seed = [0u8; 32];
    let mut magic4 = [0u8; 4];
    hkdf_expand(None, master, &locate_info, &mut locate_seed);
    hkdf_expand(None, master, &magic_info, &mut magic4);
    Ok(HeaderLocatorKeys {
        locate_seed,
        header_stc_seed: hkdf_expand_u64(master, cipher.hdr_stc_label),
        ext_stc_seed: hkdf_expand_u64(master, cipher.ext_stc_label),
        magic4,
    })
}

fn suite_info(label: &[u8], domain: Option<&str>, suite: CipherSuiteId) -> Vec<u8> {
    let mut info = info_with_domain(label, domain);
    info.extend_from_slice(&suite.as_u16().to_be_bytes());
    info
}

/// L3: derive the per-carrier payload keys from the header salt or nonce.
pub(crate) fn derive_l3_session_keys(
    cipher: &WireCipherProfile,
    suite: CipherSuiteId,
    master: &[u8; 32],
    session_salt: &[u8],
    domain: Option<&str>,
) -> Result<SessionKeys, StrHideError> {
    let enc_info = suite_info(cipher.enc_label, domain, suite);
    let perm_info = suite_info(cipher.perm_label, domain, suite);
    let stc_info = suite_info(cipher.stc_label, domain, suite);
    let mut enc_key = [0u8; 32];
    let mut perm_seed = [0u8; 32];
    let mut stc_seed = [0u8; 8];
    hkdf_expand(Some(session_salt), master, &enc_info, &mut enc_key);
    hkdf_expand(Some(session_salt), master, &perm_info, &mut perm_seed);
    hkdf_expand(Some(session_salt), master, &stc_info, &mut stc_seed);
    Ok(SessionKeys {
        enc_key,
        perm_seed,
        stc_seed: u64::from_be_bytes(stc_seed),
    })
}

/// Domain-separated HKDF info string: `label || u64be(len) || domain`.
///
/// The length prefix keeps `("ab", "c")` and `("a", "bc")` from colliding.
pub(crate) fn info_with_domain(label: &[u8], domain: Option<&str>) -> Vec<u8> {
    match domain.filter(|d| !d.is_empty()) {
        Some(domain) => {
            let normalized = normalize_nfc(domain);
            let mut info = Vec::with_capacity(label.len() + 8 + normalized.len());
            info.extend_from_slice(label);
            info.extend_from_slice(&(normalized.len() as u64).to_be_bytes());
            info.extend_from_slice(normalized.as_bytes());
            info
        }
        None => label.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_self_consistent() {
        DEFAULT_JPEG_FORMAT.validate().expect("default profile");
        assert_eq!(DEFAULT_JPEG_FORMAT.superblock_bits(), 352);
        assert_eq!(DEFAULT_JPEG_FORMAT.superblock_slots(), 718);
        assert_eq!(DEFAULT_JPEG_FORMAT.extension_slots(0), 4 * 7);
        // `n = u * (bits + h - 1)` must carry exactly `bits` bits.
        let bits = DEFAULT_JPEG_FORMAT.superblock_bits();
        let n = DEFAULT_JPEG_FORMAT.superblock_slots();
        assert_eq!(
            n / DEFAULT_JPEG_FORMAT.sb_u as usize - (DEFAULT_JPEG_FORMAT.sb_h as usize - 1),
            bits
        );
        assert_eq!(DEFAULT_JPEG_FORMAT.header_slots(3), 718 + 4 * (24 + 7));
    }

    #[test]
    fn invalid_profiles_are_rejected() {
        let mut p = DEFAULT_JPEG_FORMAT;
        p.grid_rule = GridRule {
            k_min: 0,
            k_max: 63,
        };
        assert!(p.validate().is_err(), "DC in the grid must be refused");

        let mut p = DEFAULT_JPEG_FORMAT;
        p.cover_digest_tag = b"";
        assert!(p.validate().is_err(), "empty digest tag must be refused");

        let mut p = DEFAULT_JPEG_FORMAT;
        p.sb_h = 3;
        assert!(p.validate().is_err());

        // The serialised superblock is a fixed 44-byte buffer: any other
        // `sb_bytes` embeds the wrong bit count (short = truncated header that
        // no reader can decode, long = reads past the buffer).
        let mut p = DEFAULT_JPEG_FORMAT;
        p.sb_bytes = 43;
        let err = p.validate().expect_err("short superblock must be refused");
        assert!(format!("{err}").contains("sb_bytes"), "{err}");
        let mut p = DEFAULT_JPEG_FORMAT;
        p.sb_bytes = 45;
        assert!(p.validate().is_err(), "long superblock must be refused");

        let mut p = DEFAULT_JPEG_FORMAT;
        p.grid_rule = GridRule {
            k_min: 20,
            k_max: 10,
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn domain_separated_labels_do_not_collide() {
        let a = info_with_domain(b"hpos", Some("ab"));
        let b = info_with_domain(b"hpos", Some("bc"));
        assert_ne!(a, b);
        assert_eq!(info_with_domain(b"hpos", None), b"hpos".to_vec());
        assert_eq!(info_with_domain(b"hpos", Some("")), b"hpos".to_vec());
        // NFC-normalized: precomposed and decomposed spellings agree.
        assert_eq!(
            info_with_domain(b"enc", Some("caf\u{00e9}")),
            info_with_domain(b"enc", Some("cafe\u{0301}"))
        );
    }
}

#[cfg(test)]
mod v4_kdf_tests {
    use super::*;
    use sha2::Digest;

    // Frozen golden test vectors (see docs/api/WIRE_SPEC_CONTENT.md).
    const PASSWORD: &str = "correct horse battery staple";
    const DOMAIN: &str = "domain-a";
    const PRE_SALT: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const SALT16: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const NONCE12: [u8; 12] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    ];

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2, "hex length");
        let mut out = [0u8; N];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap();
        }
        out
    }

    fn file_key() -> [u8; 32] {
        [0x11; 32]
    }

    #[test]
    fn l1_password_and_file_key_match_frozen_vectors() {
        let master = derive_locator_master(
            Credential::Password(PASSWORD),
            None,
            &OFFICIAL_PNG_CIPHER,
            &PRE_SALT,
        )
        .unwrap();
        assert_eq!(
            master,
            hex::<32>("5c74266ed4bf466efdc5e45163cda9427ef19efc78a7e16ebff3399ce7100195")
        );

        let master = derive_locator_master(
            Credential::Password(PASSWORD),
            Some(DOMAIN),
            &OFFICIAL_PNG_CIPHER,
            &PRE_SALT,
        )
        .unwrap();
        assert_eq!(
            master,
            hex::<32>("62446079c4653df74842c5ae42d381853084d6d9d9ee022f2b11a4c2b406614c")
        );

        let key = file_key();
        let master = derive_locator_master(
            Credential::FileKey(&key),
            None,
            &OFFICIAL_PNG_CIPHER,
            &PRE_SALT,
        )
        .unwrap();
        assert_eq!(
            master,
            hex::<32>("659fae03605b2874adac6d8d06a9be0d818a9bf206d4392111f7b6c24d27e614")
        );
    }

    #[test]
    fn l2_png_matches_frozen_vectors() {
        let master = derive_locator_master(
            Credential::Password(PASSWORD),
            None,
            &OFFICIAL_PNG_CIPHER,
            &PRE_SALT,
        )
        .unwrap();
        let keys =
            derive_l2_locator_keys(&master, &OFFICIAL_PNG_CIPHER, b"strhide-v4-hdr-magic", None)
                .unwrap();
        assert_eq!(
            keys.locate_seed,
            hex::<32>("43a7f549fa24f4215b93e94db68a7e081766533451884574560b01139f798273")
        );
        assert_eq!(keys.header_stc_seed, 11887539032958310912);
        assert_eq!(keys.ext_stc_seed, 14052583312398415470);
        assert_eq!(keys.magic4, hex::<4>("6f361b87"));
    }

    #[test]
    fn l2_domain_separation_matches_frozen_vectors() {
        let master = derive_locator_master(
            Credential::Password(PASSWORD),
            Some(DOMAIN),
            &OFFICIAL_PNG_CIPHER,
            &PRE_SALT,
        )
        .unwrap();
        let keys = derive_l2_locator_keys(
            &master,
            &OFFICIAL_PNG_CIPHER,
            b"strhide-v4-hdr-magic",
            Some(DOMAIN),
        )
        .unwrap();
        assert_eq!(
            keys.locate_seed,
            hex::<32>("b10faf49f4cb177fc5b913249889d52345fb6a0143e52434b71201328bb00803")
        );
        assert_eq!(keys.header_stc_seed, 17242176147011615236);
        assert_eq!(keys.ext_stc_seed, 5631860850739589937);
        assert_eq!(keys.magic4, hex::<4>("9f9c9968"));
    }

    #[test]
    fn l2_hevc_matches_frozen_vectors() {
        let master = derive_locator_master(
            Credential::Password(PASSWORD),
            None,
            &OFFICIAL_HEVC_CIPHER,
            &PRE_SALT,
        )
        .unwrap();
        let keys = derive_l2_locator_keys(
            &master,
            &OFFICIAL_HEVC_CIPHER,
            b"strhide-v4-hdr-magic",
            None,
        )
        .unwrap();
        assert_eq!(
            keys.locate_seed,
            hex::<32>("67ece4982f1805d48497a032b08f8cabb793513f592b7e1a603bb7589074978f")
        );
        assert_eq!(keys.header_stc_seed, 11887539032958310912);
        assert_eq!(keys.ext_stc_seed, 14052583312398415470);
        assert_eq!(keys.magic4, hex::<4>("6f361b87"));
    }

    #[test]
    fn l3_png_suite_selection_and_values_match_frozen_vectors() {
        let master = derive_locator_master(
            Credential::Password(PASSWORD),
            None,
            &OFFICIAL_PNG_CIPHER,
            &PRE_SALT,
        )
        .unwrap();

        let aes = derive_l3_session_keys(
            &OFFICIAL_PNG_CIPHER,
            CipherSuiteId::Aes256Gcm,
            &master,
            &SALT16,
            None,
        )
        .unwrap();
        assert_eq!(
            aes.enc_key,
            hex::<32>("944a517a1c450540bb22bc033bf78231661e151db9006c55dec7f0194fb11da8")
        );
        assert_eq!(
            aes.perm_seed,
            hex::<32>("620cd14dbd302ca5e63b2f984b07e90a69b9a26752c96cea460a90514b424ae0")
        );
        assert_eq!(aes.stc_seed, 13240335620252696060);

        let chacha = derive_l3_session_keys(
            &OFFICIAL_PNG_CIPHER,
            CipherSuiteId::ChaCha20Poly1305,
            &master,
            &SALT16,
            None,
        )
        .unwrap();
        assert_eq!(
            chacha.enc_key,
            hex::<32>("4f9c8db066b8d33ba5f6cdbe75c90bc693d2a093c6c0c9710dc6a705be4f6996")
        );
        assert_eq!(
            chacha.perm_seed,
            hex::<32>("b660a92fb3be3b6bb3f4bd4d9dc291ab46f393cf06c9a3e52be208648624b6a6")
        );
        assert_eq!(chacha.stc_seed, 7702655012707632498);
    }

    #[test]
    fn l3_hevc_uses_sha256_of_label_and_nonce() {
        let master = derive_locator_master(
            Credential::Password(PASSWORD),
            None,
            &OFFICIAL_HEVC_CIPHER,
            &PRE_SALT,
        )
        .unwrap();
        let mut input = b"strhide-hevc-session-v4".to_vec();
        input.extend_from_slice(&NONCE12);
        let session_salt = sha2::Sha256::digest(&input);
        assert_eq!(
            session_salt.as_slice(),
            hex::<32>("84b2263f7aa00ac331e6e64c26372559ed919e2a5020aff25535238242516e38")
                .as_slice()
        );
        let keys = derive_l3_session_keys(
            &OFFICIAL_HEVC_CIPHER,
            CipherSuiteId::Aes256Gcm,
            &master,
            &session_salt,
            None,
        )
        .unwrap();
        assert_eq!(
            keys.enc_key,
            hex::<32>("b3e72b4ec894dd16129e14edfa8293d6455692110336c9f4d87d2b0b1aa71230")
        );
        assert_eq!(
            keys.perm_seed,
            hex::<32>("08922a6bca4b5de63a74e4cd03eccb89464f71ed1fc76e0baeeaea2ceaa0c426")
        );
        assert_eq!(keys.stc_seed, 18245078319218299937);
    }

    #[test]
    fn cipher_profiles_actually_separate_formats() {
        let master = derive_locator_master(
            Credential::Password(PASSWORD),
            None,
            &OFFICIAL_PNG_CIPHER,
            &PRE_SALT,
        )
        .unwrap();
        let png = derive_l2_locator_keys(&master, &OFFICIAL_PNG_CIPHER, b"magic", None).unwrap();
        let hevc = derive_l2_locator_keys(&master, &OFFICIAL_HEVC_CIPHER, b"magic", None).unwrap();
        assert_ne!(png.locate_seed, hevc.locate_seed);
        assert_eq!(png.magic4, hevc.magic4, "magic label is not per-format");
        let audio =
            derive_l2_locator_keys(&master, &OFFICIAL_AUDIO_CIPHER, b"magic", None).unwrap();
        let jpeg = derive_l2_locator_keys(&master, &OFFICIAL_JPEG_CIPHER, b"magic", None).unwrap();
        assert_ne!(audio.locate_seed, jpeg.locate_seed);
    }
}
