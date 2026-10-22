//! Format identity and cipher-suite table for the image steganography formats.
//!
//! Two things live here, both of them *compile-time* facts rather than runtime
//! options:
//!
//! 1. [`FormatProfile`] — the identity of a wire format: the domain-separation
//!    labels that feed every KDF, the superblock / extension geometry, the slot
//!    grid rule, and the suite whitelist. Changing any of it produces a
//!    *different format*: two binaries built with different profiles cannot read
//!    each other's carriers, and the failure is indistinguishable from a wrong
//!    password.
//! 2. [`CipherSuite`] — "one id, one full set of crypto parameters". The suite
//!    id in the superblock indexes this table, so iterating PBKDF2, memory cost
//!    or the AEAD algorithm only ever adds a table entry; it never reshapes the
//!    header.
//!
//! # Why the profile is a value and not a pile of constants
//!
//! The realistic use of a steganography tool is "compile a private build": edit
//! every constant an upstream detector could model as a fingerprint, and use it
//! yourself. If those constants are `const` items scattered across modules, that
//! means forking the crate. As a public value, a private build is a single
//! `FormatProfile` literal plus `cargo build`.
//!
//! # Frozen once published
//!
//! `DEFAULT_FORMAT` is the wire format. Its fields are documented one by one
//! below; after the first release they may only be changed by bumping
//! `format_major` (a new format), because every historical carrier was written
//! with the old derivation.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::crypto::normalize_nfc;
use crate::errors::StrHideError;

/// Iteration ceiling the decoder is willing to execute for one PBKDF2 suite.
///
/// Decoding a hostile carrier is a DoS vector: a forged `suite_id` must not be
/// able to make the extractor run an hour of KDF. Anything above this is
/// refused *before* the KDF runs.
pub const MAX_PBKDF2_ITERATIONS: u32 = 2_000_000;

/// Key-derivation function of a cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    /// PBKDF2-HMAC-SHA256 over the NFC-normalized password, 32-byte output.
    Pbkdf2HmacSha256 {
        /// Iteration count; the whole anti-brute-force cost of the suite.
        iterations: u32,
    },
}

/// Authenticated-encryption algorithm of a cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    /// AES-256-GCM with a 16-byte tag (12-byte nonce, as the superblock allots).
    Aes256Gcm,
}

impl Aead {
    /// Authentication tag length in bytes.
    pub fn tag_len(self) -> usize {
        match self {
            Aead::Aes256Gcm => 16,
        }
    }
}

/// One row of the cipher-suite table.
///
/// The table is a **code constant**: once published, an id's parameters never
/// change. Raising the iteration count, switching the AEAD or adding a KDF
/// family is a new id, never an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherSuite {
    /// Wire id, 1..=0x00FF. `0` means "unset" and is always rejected.
    pub id: u16,
    /// Human-readable name for diagnostics.
    pub name: &'static str,
    /// Password-based KDF, also the per-guess cost an attacker pays.
    pub kdf: Kdf,
    /// Payload AEAD.
    pub aead: Aead,
}

impl CipherSuite {
    /// Bytes of salt the superblock reserves for this suite (fixed 16).
    pub fn salt_len(&self) -> usize {
        16
    }

    /// Bytes of nonce the superblock reserves for this suite (fixed 12).
    pub fn nonce_len(&self) -> usize {
        12
    }

    /// Authentication tag length in bytes.
    pub fn tag_len(&self) -> usize {
        self.aead.tag_len()
    }

    /// Work factor of one password guess: PBKDF2 iterations.
    pub fn cost(&self) -> u32 {
        match self.kdf {
            Kdf::Pbkdf2HmacSha256 { iterations } => iterations,
        }
    }
}

/// v1 default suite: PBKDF2-HMAC-SHA256, 200k iterations, AES-256-GCM.
pub const SUITE_PBKDF2_200K: CipherSuite = CipherSuite {
    id: 1,
    name: "pbkdf2-sha256-200k",
    kdf: Kdf::Pbkdf2HmacSha256 {
        iterations: 200_000,
    },
    aead: Aead::Aes256Gcm,
};

/// Optional slower suite: same construction, 600k iterations.
pub const SUITE_PBKDF2_600K: CipherSuite = CipherSuite {
    id: 2,
    name: "pbkdf2-sha256-600k",
    kdf: Kdf::Pbkdf2HmacSha256 {
        iterations: 600_000,
    },
    aead: Aead::Aes256Gcm,
};

/// Reserved id for `argon2id-m64t2p2`; deliberately **not** implemented in v1.
///
/// A 64 MiB blind guess per suite attempt is exactly what the trial enumeration
/// must avoid, so the id is reserved (a decoder says "unsupported suite") until
/// the cost of enumeration is re-evaluated.
pub const RESERVED_SUITE_ARGON2ID: u16 = 3;

/// Suites this build implements, in trial order (ascending id).
pub const SUITES: &[CipherSuite] = &[SUITE_PBKDF2_200K, SUITE_PBKDF2_600K];

/// Default suite written by the embedder.
pub const DEFAULT_SUITE_ID: u16 = SUITE_PBKDF2_200K.id;

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

/// Identity of one wire format.
///
/// # Field effects (for private builds)
///
/// | field | change it and… |
/// | :--- | :--- |
/// | `format_major` / `format_minor` | the decoder accepts/rejects differently; the bytes stay readable |
/// | `cover_digest_tag` | the header-location KDF salt changes, so no header can be found: unreadable |
/// | `hpos_label` | header slots move: unreadable |
/// | `stc_label` / `enc_label` / `perm_label` | body trellis / key / slot order change: unreadable |
/// | `sb_bytes` / `sb_h` / `sb_u` | different superblock slot count; must stay self-consistent |
/// | `ext_h` / `ext_u` | different extension-area slot count |
/// | `grid_rule` | different slot set |
/// | `suites` | which ids may be written and read |
///
/// A mismatch on any of the derivation labels behaves exactly like a wrong
/// password (`NoHiddenData`), which is the point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatProfile {
    /// Major version; a different value is a different format.
    pub format_major: u8,
    /// Minor version; only optional extensions bump it.
    pub format_minor: u8,
    /// KDF-salt tag of the cover digest.
    pub cover_digest_tag: &'static [u8],
    /// HKDF info label for the header permutation seed.
    pub hpos_label: &'static [u8],
    /// HKDF info label for the STC trellis seed.
    pub stc_label: &'static [u8],
    /// HKDF info label for the AEAD key.
    pub enc_label: &'static [u8],
    /// HKDF info label for the body permutation seed.
    pub perm_label: &'static [u8],
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
    /// Suites this binary accepts, ascending by id.
    pub suites: &'static [CipherSuite],
}

impl FormatProfile {
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

    /// Suite with the given wire id, if this build implements it.
    pub fn suite(&self, id: u16) -> Option<&'static CipherSuite> {
        self.suites.iter().find(|s| s.id == id)
    }

    /// The suite a fresh carrier is written with.
    pub fn default_suite(&self) -> &'static CipherSuite {
        self.suite(DEFAULT_SUITE_ID)
            .or_else(|| self.suites.first())
            .expect("a FormatProfile must list at least one cipher suite")
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
        // `n / u - (h - 1) == bits`, which holds by construction; the check that
        // can actually fail is a group wider than the trellis window needs.
        if self.sb_u as usize * (self.sb_h as usize - 1) > self.superblock_slots() {
            return Some("superblock geometry is not self-consistent".into());
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
        for (name, label) in [
            ("cover_digest_tag", self.cover_digest_tag),
            ("hpos_label", self.hpos_label),
            ("stc_label", self.stc_label),
            ("enc_label", self.enc_label),
            ("perm_label", self.perm_label),
        ] {
            if label.is_empty() {
                return Some(format!("{name} must not be empty"));
            }
        }
        let labels = [
            self.cover_digest_tag,
            self.hpos_label,
            self.stc_label,
            self.enc_label,
            self.perm_label,
        ];
        for (i, a) in labels.iter().enumerate() {
            for b in labels.iter().skip(i + 1) {
                if a == b {
                    return Some("derivation labels must be pairwise distinct".into());
                }
            }
        }
        if self.suites.is_empty() {
            return Some("suites must not be empty".into());
        }
        let mut last = 0u16;
        for suite in self.suites {
            if suite.id == 0 {
                return Some("suite id 0 is reserved for 'unset'".into());
            }
            if suite.id <= last {
                return Some("suite ids must be unique and ascending".into());
            }
            if suite.id > 0x00FF {
                return Some(format!(
                    "suite id {:#06x} is in the experimental range and cannot be a default",
                    suite.id
                ));
            }
            last = suite.id;
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
                "Invalid FormatProfile: {problem}"
            ))),
            None => Ok(()),
        }
    }
}

/// The v1 wire format: 44-byte superblock (718 slots), 4-way extension area,
/// full AC grid, PBKDF2 suites 1 and 2.
pub const DEFAULT_FORMAT: FormatProfile = FormatProfile {
    format_major: 1,
    format_minor: 0,
    cover_digest_tag: b"strhide-cover-v1",
    hpos_label: b"hpos",
    stc_label: b"stc-trellis",
    enc_label: b"enc",
    perm_label: b"perm",
    sb_bytes: 44,
    sb_h: 8,
    sb_u: 2,
    ext_h: 8,
    ext_u: 4,
    grid_rule: GridRule::ALL_AC,
    suites: SUITES,
};

/// Identity and KDF derivation labels for spatial (PNG) steganography.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpatialFormatProfile {
    /// Stand-in secret used when neither a user password nor a private secret is provided.
    pub fallback_secret: &'static str,
    /// HKDF info label for domain subkey derivation.
    pub domain_label: &'static [u8],
    /// HKDF salt for header position permutation seed derivation.
    pub hpos_salt: &'static [u8],
    /// HKDF info label for header position permutation seed derivation.
    pub hpos_label: &'static [u8],
    /// HKDF info label for STC trellis seed derivation.
    pub stc_label: &'static [u8],
    /// Format settings for cipher suite and payload keys.
    pub body: &'static FormatProfile,
}

pub const OFFICIAL_SPATIAL: SpatialFormatProfile = SpatialFormatProfile {
    fallback_secret: "strhide-default-content-stego-key-2026",
    domain_label: b"strhide-stego-domain-v1",
    hpos_salt: b"strhide-stego-hpos-salt-v2",
    hpos_label: b"strhide-stego-hpos-v2",
    stc_label: b"strhide-stc-trellis-v1",
    body: &DEFAULT_FORMAT,
};

/// Domain-separated HKDF info string: `label || u64be(len) || domain`.
///
/// The length prefix keeps `("ab", "c")` and `("a", "bc")` from colliding.
pub fn info_with_domain(label: &[u8], domain: Option<&str>) -> Vec<u8> {
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

/// `master = SuiteKDF(password, salt_material)`.
///
/// This is the *only* place the (expensive) password KDF runs, and therefore
/// the floor on what one password guess costs an attacker: the header location
/// is derived from the result, so a guess cannot be tested without paying it.
pub fn derive_master(
    suite: &CipherSuite,
    password: &str,
    salt_material: &[u8],
) -> Result<[u8; 32], StrHideError> {
    let normalized = normalize_nfc(password);
    let mut master = [0u8; 32];
    match suite.kdf {
        Kdf::Pbkdf2HmacSha256 { iterations } => {
            if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
                return Err(StrHideError::UnsupportedVersion(format!(
                    "cipher suite {} asks for {iterations} PBKDF2 iterations, outside the supported 1..={MAX_PBKDF2_ITERATIONS}",
                    suite.id
                )));
            }
            pbkdf2::pbkdf2_hmac::<Sha256>(
                normalized.as_bytes(),
                salt_material,
                iterations,
                &mut master,
            );
        }
    }
    Ok(master)
}

/// Header permutation seed: decides which of the grid slots carry the superblock.
///
/// `master` already costs one KDF, so an offline guess cannot locate the header
/// without paying the suite's full price -- this is what closes the "fast
/// password oracle" hole a plain structural check would open.
pub fn header_perm_seed(fmt: &FormatProfile, master: &[u8; 32], domain: Option<&str>) -> [u8; 32] {
    let info = info_with_domain(fmt.hpos_label, domain);
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    hk.expand(&info, &mut out)
        .expect("HKDF expand header permutation seed");
    out
}

/// `(enc_key, perm_seed)` for the payload, layered on the superblock salt.
///
/// The salt is public (it sits in the superblock), but it is no longer the KDF
/// salt: it only splits the master into per-carrier subkeys, so a precomputed
/// table cannot be reused across carriers.
pub fn body_keys(
    fmt: &FormatProfile,
    master: &[u8; 32],
    salt: &[u8],
    domain: Option<&str>,
) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let enc_info = info_with_domain(fmt.enc_label, domain);
    let perm_info = info_with_domain(fmt.perm_label, domain);
    let mut enc_key = [0u8; 32];
    let mut perm_seed = [0u8; 32];
    hk.expand(&enc_info, &mut enc_key)
        .expect("HKDF expand payload key");
    hk.expand(&perm_info, &mut perm_seed)
        .expect("HKDF expand permutation seed");
    (enc_key, perm_seed)
}

/// STC trellis seed, derived from the body permutation seed and the salt.
pub fn stc_seed(fmt: &FormatProfile, perm_seed: &[u8; 32], salt: &[u8]) -> u64 {
    let hk = Hkdf::<Sha256>::new(Some(salt), perm_seed);
    let mut out = [0u8; 8];
    hk.expand(fmt.stc_label, &mut out)
        .expect("HKDF expand STC trellis seed");
    u64::from_be_bytes(out)
}

/// Seed of the superblock / header trellis.
///
/// Domain-separated from the body trellis by the header salt material
/// (`"hpos"`-derived seed), so header and body never share a matrix.
pub fn header_stc_seed(fmt: &FormatProfile, header_seed: &[u8; 32], domain: Option<&str>) -> u64 {
    let mut label = Vec::with_capacity(fmt.stc_label.len() + 4);
    label.extend_from_slice(fmt.stc_label);
    label.extend_from_slice(b"-hdr");
    seed_u64(header_seed, &info_with_domain(&label, domain))
}

/// Seed of the extension-area trellis (separate from the superblock's).
pub fn extension_stc_seed(
    fmt: &FormatProfile,
    header_seed: &[u8; 32],
    domain: Option<&str>,
) -> u64 {
    let mut label = Vec::with_capacity(fmt.stc_label.len() + 4);
    label.extend_from_slice(fmt.stc_label);
    label.extend_from_slice(b"-ext");
    seed_u64(header_seed, &info_with_domain(&label, domain))
}

fn seed_u64(ikm: &[u8; 32], info: &[u8]) -> u64 {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 8];
    hk.expand(info, &mut out).expect("HKDF expand trellis seed");
    u64::from_be_bytes(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_is_self_consistent() {
        DEFAULT_FORMAT.validate().expect("default profile");
        assert_eq!(DEFAULT_FORMAT.superblock_bits(), 352);
        assert_eq!(DEFAULT_FORMAT.superblock_slots(), 718);
        assert_eq!(DEFAULT_FORMAT.extension_slots(0), 4 * 7);
        // `n = u * (bits + h - 1)` must carry exactly `bits` bits.
        let bits = DEFAULT_FORMAT.superblock_bits();
        let n = DEFAULT_FORMAT.superblock_slots();
        assert_eq!(
            n / DEFAULT_FORMAT.sb_u as usize - (DEFAULT_FORMAT.sb_h as usize - 1),
            bits
        );
        assert_eq!(DEFAULT_FORMAT.header_slots(3), 718 + 4 * (24 + 7));
    }

    #[test]
    fn suite_table_is_unique_and_ascending() {
        let mut last = 0u16;
        for suite in SUITES {
            assert!(suite.id > last, "suite ids must ascend");
            assert_ne!(suite.id, 0);
            assert!(suite.cost() >= 200_000);
            last = suite.id;
        }
        assert_eq!(DEFAULT_FORMAT.default_suite().id, DEFAULT_SUITE_ID);
        assert_eq!(DEFAULT_SUITE_ID, 1);
        assert!(DEFAULT_FORMAT.suite(0).is_none());
        assert!(DEFAULT_FORMAT.suite(RESERVED_SUITE_ARGON2ID).is_none());
        assert!(DEFAULT_FORMAT.suite(9999).is_none());
    }

    #[test]
    fn invalid_profiles_are_rejected() {
        let mut p = DEFAULT_FORMAT;
        p.grid_rule = GridRule {
            k_min: 0,
            k_max: 63,
        };
        assert!(p.validate().is_err(), "DC in the grid must be refused");

        let mut p = DEFAULT_FORMAT;
        p.hpos_label = b"enc";
        assert!(p.validate().is_err(), "duplicate labels must be refused");

        let mut p = DEFAULT_FORMAT;
        p.sb_h = 3;
        assert!(p.validate().is_err());

        let mut p = DEFAULT_FORMAT;
        p.suites = &[];
        assert!(p.validate().is_err());

        let mut p = DEFAULT_FORMAT;
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

    #[test]
    fn key_layering_is_separated_and_stable() {
        let master = derive_master(&SUITE_PBKDF2_200K, "password", b"cover-digest").unwrap();
        let hdr_a = header_perm_seed(&DEFAULT_FORMAT, &master, None);
        let hdr_b = header_perm_seed(&DEFAULT_FORMAT, &master, Some("domain-a"));
        assert_ne!(hdr_a, hdr_b, "domain must separate the header seed");

        let salt = [7u8; 16];
        let (enc_a, perm_a) = body_keys(&DEFAULT_FORMAT, &master, &salt, None);
        let (enc_b, perm_b) = body_keys(&DEFAULT_FORMAT, &master, &salt, Some("domain-a"));
        assert_ne!(enc_a, enc_b);
        assert_ne!(perm_a, perm_b);
        assert_ne!(enc_a, perm_a, "key and permutation seed must differ");

        // Stable across calls: this is the whole "same cover + password = same
        // slot sequence" contract.
        assert_eq!(
            body_keys(&DEFAULT_FORMAT, &master, &salt, None),
            (enc_a, perm_a)
        );
        assert_eq!(
            stc_seed(&DEFAULT_FORMAT, &perm_a, &salt),
            stc_seed(&DEFAULT_FORMAT, &perm_a, &salt)
        );
        assert_ne!(
            stc_seed(&DEFAULT_FORMAT, &perm_a, &salt),
            header_stc_seed(&DEFAULT_FORMAT, &hdr_a, None),
            "header and body trellis seeds must be domain-separated"
        );

        // A different password or cover digest must move everything.
        let other = derive_master(&SUITE_PBKDF2_200K, "password2", b"cover-digest").unwrap();
        assert_ne!(header_perm_seed(&DEFAULT_FORMAT, &other, None), hdr_a);
    }

    #[test]
    fn suite_cost_matches_the_table() {
        assert_eq!(SUITE_PBKDF2_200K.cost(), 200_000);
        assert_eq!(SUITE_PBKDF2_600K.cost(), 600_000);
        assert_eq!(SUITE_PBKDF2_200K.salt_len(), 16);
        assert_eq!(SUITE_PBKDF2_200K.nonce_len(), 12);
        assert_eq!(SUITE_PBKDF2_200K.tag_len(), 16);
    }
}
