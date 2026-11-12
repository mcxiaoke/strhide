#![cfg(feature = "structure-pe")]

//! Windows PE code-bit channel steganography (strategy `pe_codebits`).
//!
//! Hides a strhide UBE envelope inside the *encodings* of existing x86/x64
//! instructions in a PE `.text` section, exploiting the ModR/M semantic-pair
//! redundancy: `mov eax, ebx` encodes identically-semantically as `89 D8` or
//! `8B C3`, so each register-to-register ALU instruction carries one bit. The
//! carrier file size is unchanged and every rewritten instruction is
//! semantically identical to the original.
//!
//! Layer split:
//! - [`profile`], [`embed`], [`extract_ube`], [`apply_diff`] are format
//!   agnostic: they operate on a code byte range plus a bitness, so future
//!   ELF/Mach-O support only needs a new section locator.
//! - `parse_pe_code_layout` and `find_slack_run` are the PE-specific
//!   locator (`.text` discovery, bitness, zero-value slack scan).
//!
//! The UBE bytes are an opaque payload to this module; they are never parsed
//! here. Restoration is driven by a diff bitmap stored in verified-zero PE
//! padding ("slack"), which makes the scheme self-terminating: the diff region
//! is restored by zeroing, because it was all-zero before writing.

use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction, OpKind, Register};

pub use super::pe_layout::*;

/// The channel magic in standard mode. In stealth mode the magic is the
/// password-derived value that the engine bakes into the UBE trailer, and the
/// channel simply reuses it: [`embed`] takes the magic from the last four
/// bytes of the UBE blob (its trailer magic), so a stealth channel is
/// invisible to `locate(None)` and findable only with the right password.
/// This is a deliberate deviation from design doc §5.2's `STHC` placeholder:
/// deriving the magic from the UBE trailer keeps the adapter free of any
/// stealth/password knowledge while preserving deniability.
pub const CHANNEL_MAGIC: [u8; 4] = crate::structure::envelope::STANDARD_TRAILER_MAGIC;

/// Channel container version (see design doc §5).
pub const CHANNEL_VERSION: u8 = 1;

/// Channel header length: magic(4) + version(1) + flags(1) + ube_len(4) + slack_off(4).
pub const CHANNEL_HEADER_LEN: usize = 14;

const CHANNEL_HEADER_BITS: usize = CHANNEL_HEADER_LEN * 8;

/// Channel positions needed before the header can be unpacked: the 14 header
/// bytes plus the first 8 UBE bytes, which hold the envelope header magic that
/// keys the channel-header mask.
const CHANNEL_PREFIX_BITS: usize = CHANNEL_HEADER_BITS + 64;

/// Structural lower bound for a channel payload: a bare envelope is a 112-byte
/// header plus a 24-byte trailer, so anything smaller means a corrupt header
/// rather than a real envelope. Capacity reporting must use the writer-side
/// minimum instead ([`crate::structure::envelope::min_ube_len`]), not this.
pub const MIN_UBE_LEN: u32 = crate::structure::envelope::HEADER_SIZE as u32
    + crate::structure::envelope::TRAILER_SIZE as u32;

/// Upper bound for a channel payload read from an untrusted header.
///
/// A `codebits` channel needs eight reversible instruction slots per payload
/// byte, so even a very large `.text` section cannot legitimately carry
/// hundreds of megabytes. Without a ceiling, `total_bits`/`diff_len` can
/// overflow on 32-bit targets and a forged header can ask the reader for an
/// implausible allocation before the capacity check runs.
pub const MAX_CODEBITS_UBE_LEN: u32 = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Opcode tables (identical to steg86's SUPPORTED_OPCODES / SEMANTIC_PAIRS)
// ---------------------------------------------------------------------------

/// Returns `(dual opcode, bit)` for a semantic-pair opcode.
///
/// `bit == false` is the `r/m, r` ("store") form (tuple member 0),
/// `bit == true` is the `r, r/m` ("load") form (tuple member 1).
fn dual_and_bit(code: Code) -> Option<(Code, bool)> {
    use Code::*;
    Some(match code {
        // ADD
        Add_rm8_r8 => (Add_r8_rm8, false),
        Add_r8_rm8 => (Add_rm8_r8, true),
        Add_rm16_r16 => (Add_r16_rm16, false),
        Add_r16_rm16 => (Add_rm16_r16, true),
        Add_rm32_r32 => (Add_r32_rm32, false),
        Add_r32_rm32 => (Add_rm32_r32, true),
        Add_rm64_r64 => (Add_r64_rm64, false),
        Add_r64_rm64 => (Add_rm64_r64, true),
        // ADC
        Adc_rm8_r8 => (Adc_r8_rm8, false),
        Adc_r8_rm8 => (Adc_rm8_r8, true),
        Adc_rm16_r16 => (Adc_r16_rm16, false),
        Adc_r16_rm16 => (Adc_rm16_r16, true),
        Adc_rm32_r32 => (Adc_r32_rm32, false),
        Adc_r32_rm32 => (Adc_rm32_r32, true),
        Adc_rm64_r64 => (Adc_r64_rm64, false),
        Adc_r64_rm64 => (Adc_rm64_r64, true),
        // AND
        And_rm8_r8 => (And_r8_rm8, false),
        And_r8_rm8 => (And_rm8_r8, true),
        And_rm16_r16 => (And_r16_rm16, false),
        And_r16_rm16 => (And_rm16_r16, true),
        And_rm32_r32 => (And_r32_rm32, false),
        And_r32_rm32 => (And_rm32_r32, true),
        And_rm64_r64 => (And_r64_rm64, false),
        And_r64_rm64 => (And_rm64_r64, true),
        // OR
        Or_rm8_r8 => (Or_r8_rm8, false),
        Or_r8_rm8 => (Or_rm8_r8, true),
        Or_rm16_r16 => (Or_r16_rm16, false),
        Or_r16_rm16 => (Or_rm16_r16, true),
        Or_rm32_r32 => (Or_r32_rm32, false),
        Or_r32_rm32 => (Or_rm32_r32, true),
        Or_rm64_r64 => (Or_r64_rm64, false),
        Or_r64_rm64 => (Or_rm64_r64, true),
        // XOR
        Xor_rm8_r8 => (Xor_r8_rm8, false),
        Xor_r8_rm8 => (Xor_rm8_r8, true),
        Xor_rm16_r16 => (Xor_r16_rm16, false),
        Xor_r16_rm16 => (Xor_rm16_r16, true),
        Xor_rm32_r32 => (Xor_r32_rm32, false),
        Xor_r32_rm32 => (Xor_rm32_r32, true),
        Xor_rm64_r64 => (Xor_r64_rm64, false),
        Xor_r64_rm64 => (Xor_rm64_r64, true),
        // SUB
        Sub_rm8_r8 => (Sub_r8_rm8, false),
        Sub_r8_rm8 => (Sub_rm8_r8, true),
        Sub_rm16_r16 => (Sub_r16_rm16, false),
        Sub_r16_rm16 => (Sub_rm16_r16, true),
        Sub_rm32_r32 => (Sub_r32_rm32, false),
        Sub_r32_rm32 => (Sub_rm32_r32, true),
        Sub_rm64_r64 => (Sub_r64_rm64, false),
        Sub_r64_rm64 => (Sub_rm64_r64, true),
        // SBB
        Sbb_rm8_r8 => (Sbb_r8_rm8, false),
        Sbb_r8_rm8 => (Sbb_rm8_r8, true),
        Sbb_rm16_r16 => (Sbb_r16_rm16, false),
        Sbb_r16_rm16 => (Sbb_rm16_r16, true),
        Sbb_rm32_r32 => (Sbb_r32_rm32, false),
        Sbb_r32_rm32 => (Sbb_rm32_r32, true),
        Sbb_rm64_r64 => (Sbb_r64_rm64, false),
        Sbb_r64_rm64 => (Sbb_rm64_r64, true),
        // MOV
        Mov_rm8_r8 => (Mov_r8_rm8, false),
        Mov_r8_rm8 => (Mov_rm8_r8, true),
        Mov_rm16_r16 => (Mov_r16_rm16, false),
        Mov_r16_rm16 => (Mov_rm16_r16, true),
        Mov_rm32_r32 => (Mov_r32_rm32, false),
        Mov_r32_rm32 => (Mov_rm32_r32, true),
        Mov_rm64_r64 => (Mov_r64_rm64, false),
        Mov_r64_rm64 => (Mov_rm64_r64, true),
        // CMP
        Cmp_rm8_r8 => (Cmp_r8_rm8, false),
        Cmp_r8_rm8 => (Cmp_rm8_r8, true),
        Cmp_rm16_r16 => (Cmp_r16_rm16, false),
        Cmp_r16_rm16 => (Cmp_rm16_r16, true),
        Cmp_rm32_r32 => (Cmp_r32_rm32, false),
        Cmp_r32_rm32 => (Cmp_rm32_r32, true),
        Cmp_rm64_r64 => (Cmp_r64_rm64, false),
        Cmp_r64_rm64 => (Cmp_rm64_r64, true),
        _ => return None,
    })
}

/// Commutative opcodes (TEST): swapping the two register operands leaves the
/// semantics unchanged, so operand order carries one bit.
fn is_commutative(code: Code) -> bool {
    matches!(
        code,
        Code::Test_rm8_r8 | Code::Test_rm16_r16 | Code::Test_rm32_r32 | Code::Test_rm64_r64
    )
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

/// One instrumentable instruction position inside a code range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodePosition {
    /// Offset within the scanned code range.
    pub offset: usize,
    /// Current opcode (one of the supported semantic-pair / TEST forms).
    pub code: Code,
    /// First operand register.
    pub r0: Register,
    /// Second operand register.
    pub r1: Register,
    /// Whether this is a commutative (TEST) position.
    pub commutative: bool,
    /// Bit value of the *current* form (semantic pair: opcode membership;
    /// TEST: `r0 < r1` by `Register` ordinal).
    pub bit: bool,
    /// Instruction length in bytes.
    pub len: usize,
}

/// Linearly scans a code range and returns every position that can carry one
/// channel bit, in scan order (design doc §4.2, filters F0-F5).
///
/// The position list is a pure function of `(text, bitness)`: because every
/// rewrite is an equal-length in-place substitution, re-profiling an embedded
/// range yields the identical list (design doc §4.3).
pub fn profile(text: &[u8], bitness: u32) -> Vec<CodePosition> {
    profile_upto(text, bitness, None)
}

/// [`profile`] that stops after `max_positions` candidates.
///
/// A channel header lives in the first 112 positions, so reading it does not
/// need a full-`.text` disassembly. The returned list is always a prefix of
/// [`profile`]'s output; callers that need a capacity figure keep `None`.
pub fn profile_upto(text: &[u8], bitness: u32, max_positions: Option<usize>) -> Vec<CodePosition> {
    let mut out = Vec::new();
    let mut decoder = Decoder::new(bitness, text, DecoderOptions::NONE);
    let mut encoder = Encoder::new(bitness);

    for insn in &mut decoder {
        if max_positions.is_some_and(|max| out.len() >= max) {
            break;
        }
        let code = insn.code();
        // F0: skip data embedded in .text (jump tables, constants, ...).
        if code == Code::INVALID {
            continue;
        }

        let commutative = is_commutative(code);
        // F1: opcode must be a supported semantic-pair or commutative form.
        let dual = if commutative {
            None
        } else {
            match dual_and_bit(code) {
                Some((dual, _)) => Some(dual),
                None => continue,
            }
        };

        // F2: both operands must be bare registers (mod = 11).
        if insn.op0_kind() != OpKind::Register || insn.op1_kind() != OpKind::Register {
            continue;
        }
        let (r0, r1) = (insn.op0_register(), insn.op1_register());

        let bit = if commutative {
            // F3: equal registers carry no information.
            if r0 == r1 {
                continue;
            }
            (r0 as usize) < (r1 as usize)
        } else {
            dual_and_bit(code).map(|(_, b)| b).unwrap_or(false)
        };

        let len = insn.len();
        let offset = insn.ip() as usize;
        let orig = match text.get(offset..offset + len) {
            Some(s) => s,
            None => continue,
        };

        // F4: re-encoding the decoded instruction must reproduce the original
        // bytes exactly. Rejects non-minimal encodings (redundant prefixes),
        // for which a later canonical re-encode could not restore bit-exactly.
        //
        // NOTE: iced's `Encoder::encode` *appends* to its internal buffer and
        // only `take_buffer()` drains it, so every encode below is paired with
        // an immediate drain. Leaving bytes behind would corrupt the next
        // position's F4 comparison.
        let same_res = encoder.encode(&insn, offset as u64);
        let same = encoder.take_buffer();
        if same_res.is_err() || same != orig {
            continue;
        }

        // F5: the opposite form must encode to exactly the same length.
        let other = if commutative {
            match Instruction::with2(code, r1, r0) {
                Ok(i) => i,
                Err(_) => continue,
            }
        } else {
            match Instruction::with2(dual.unwrap(), r0, r1) {
                Ok(i) => i,
                Err(_) => continue,
            }
        };
        let other_res = encoder.encode(&other, offset as u64);
        let _ = encoder.take_buffer();
        match other_res {
            Ok(other_len) if other_len == len => {}
            _ => continue,
        }

        out.push(CodePosition {
            offset,
            code,
            r0,
            r1,
            commutative,
            bit,
            len,
        });
    }
    out
}

/// Number of channel bits and slack bytes required for a UBE of `ube_len`
/// bytes (design doc §10.1).
pub fn channel_requirement(ube_len: usize) -> (usize, usize) {
    let bits = (CHANNEL_HEADER_LEN + ube_len) * 8;
    let slack = CHANNEL_HEADER_LEN + ube_len;
    (bits, slack)
}

// ---------------------------------------------------------------------------
// Bit <-> byte helpers (MSB-first, design doc §5.3)
// ---------------------------------------------------------------------------

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for k in (0..8).rev() {
            bits.push((b >> k) & 1 == 1);
        }
    }
    bits
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bits.len().div_ceil(8));
    for chunk in bits.chunks(8) {
        let mut v = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            if b {
                v |= 1 << (7 - i);
            }
        }
        out.push(v);
    }
    out
}

fn set_bit(buf: &mut [u8], idx: usize) {
    buf[idx / 8] |= 1 << (7 - (idx % 8));
}

fn get_bit(buf: &[u8], idx: usize) -> bool {
    (buf[idx / 8] >> (7 - (idx % 8))) & 1 == 1
}

// ---------------------------------------------------------------------------
// Channel container
// ---------------------------------------------------------------------------

/// Parsed channel header (design doc §5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelHeader {
    pub magic: [u8; 4],
    pub version: u8,
    pub flags: u8,
    /// Length of the embedded UBE payload in bytes.
    pub ube_len: u32,
    /// Absolute file offset of the restore diff inside the PE slack region.
    pub slack_off: u32,
}

impl ChannelHeader {
    /// Serializes the channel header in unmasked format. Only [`Self::pack_masked`]
    /// writes this to a carrier; this helper exists so the masking can be built
    /// and tested field by field.
    pub fn pack_unmasked(&self) -> [u8; CHANNEL_HEADER_LEN] {
        let mut buf = [0u8; CHANNEL_HEADER_LEN];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.version;
        buf[5] = self.flags;
        buf[6..10].copy_from_slice(&self.ube_len.to_le_bytes());
        buf[10..14].copy_from_slice(&self.slack_off.to_le_bytes());
        buf
    }

    /// Serializes the channel header with deterministic keystream masking on
    /// bytes [4..14] (version, flags, ube_len, slack_off) derived from the
    /// **8-byte envelope header magic**.
    ///
    /// `buf[0..4]` only carries the 4-byte trailer magic; the mask IKM is the
    /// different 8-byte header magic stored in the UBE (channel positions
    /// `112..176`). In stealth mode that value is password-derived, so an
    /// observer holding only `buf[0..4]` cannot unmask the lengths. In standard
    /// mode the IKM is the public `STANDARD_HEADER_MAGIC`: this is format
    /// obfuscation, explicitly **not** secrecy. Payload secrecy is always the
    /// AEAD layer.
    pub fn pack_masked(&self, envelope_header_magic: &[u8; 8]) -> [u8; CHANNEL_HEADER_LEN] {
        let mut buf = self.pack_unmasked();
        let mask = crate::crypto::derive_channel_header_mask(envelope_header_magic);
        for i in 0..10 {
            buf[4 + i] ^= mask[i];
        }
        buf
    }

    /// Default pack method uses masked encoding.
    pub fn pack(&self, envelope_header_magic: &[u8; 8]) -> [u8; CHANNEL_HEADER_LEN] {
        self.pack_masked(envelope_header_magic)
    }

    /// Unpacks a 14-byte slice. The version/flags/lengths fields are always
    /// masked with the keystream derived from `envelope_header_magic`; there is
    /// no unmasked (pre-v1) layout any more.
    pub fn unpack(bytes: &[u8], envelope_header_magic: &[u8; 8]) -> Result<Self, CodebitsError> {
        Self::unpack_masked(bytes, envelope_header_magic)
    }

    pub fn unpack_masked(
        bytes: &[u8],
        envelope_header_magic: &[u8; 8],
    ) -> Result<Self, CodebitsError> {
        if bytes.len() < CHANNEL_HEADER_LEN {
            return Err(CodebitsError::Corrupted("short channel header".into()));
        }
        let magic: [u8; 4] = bytes[0..4].try_into().unwrap();
        let mask = crate::crypto::derive_channel_header_mask(envelope_header_magic);
        let mut unmasked = [0u8; 10];
        for i in 0..10 {
            unmasked[i] = bytes[4 + i] ^ mask[i];
        }
        // `validate_header` owns the version check; returning the de-masked view
        // unconditionally keeps the error path identical for masked garbage.
        Ok(Self {
            magic,
            version: unmasked[0],
            flags: unmasked[1],
            ube_len: u32::from_le_bytes(unmasked[2..6].try_into().unwrap()),
            slack_off: u32::from_le_bytes(unmasked[6..10].try_into().unwrap()),
        })
    }

    /// Number of channel bits (header + UBE) this header describes.
    fn total_bits(&self) -> usize {
        (self.ube_len as usize)
            .saturating_add(CHANNEL_HEADER_LEN)
            .saturating_mul(8)
    }

    /// Length of the restore diff: one bit per channel position.
    fn diff_len(&self) -> usize {
        (self.ube_len as usize).saturating_add(CHANNEL_HEADER_LEN)
    }
}

/// Unpacks the raw 14-byte channel header from the first channel positions,
/// without any validation. Callers must apply the magic check *before* the
/// version/capacity checks: on a carrier with no channel the first 112 bits
/// are arbitrary host instruction bits, and a repetitive code pattern can
/// otherwise produce a plausible-looking but bogus header.
///
/// The mask is keyed by the envelope header magic in the immediately following
/// 8 UBE bytes (`prof[112..176]`, see [`CHANNEL_PREFIX_BITS`]), so a profile
/// that does not reach that far cannot contain a channel.
fn header_from_positions(prof: &[CodePosition]) -> Result<ChannelHeader, CodebitsError> {
    if prof.len() < CHANNEL_PREFIX_BITS {
        return Err(CodebitsError::ChannelNotFound);
    }
    let header_bits: Vec<bool> = prof
        .iter()
        .take(CHANNEL_HEADER_BITS)
        .map(|p| p.bit)
        .collect();
    let envelope_magic_bits: Vec<bool> = prof[CHANNEL_HEADER_BITS..CHANNEL_PREFIX_BITS]
        .iter()
        .map(|p| p.bit)
        .collect();
    let envelope_magic: [u8; 8] = bits_to_bytes(&envelope_magic_bits)
        .try_into()
        .expect("64 bits assemble into 8 bytes");
    ChannelHeader::unpack(&bits_to_bytes(&header_bits), &envelope_magic)
}

/// Version + payload-floor sanity for a header whose capacity is not yet known.
fn validate_header_prefix(header: &ChannelHeader) -> Result<(), CodebitsError> {
    if header.version != CHANNEL_VERSION {
        return Err(CodebitsError::Corrupted(format!(
            "unsupported channel version {} (expected {CHANNEL_VERSION})",
            header.version
        )));
    }
    if header.ube_len < MIN_UBE_LEN {
        return Err(CodebitsError::Corrupted(
            "channel header payload length is below the minimum".into(),
        ));
    }
    if header.ube_len > MAX_CODEBITS_UBE_LEN {
        return Err(CodebitsError::Corrupted(
            "channel header payload length exceeds the supported maximum".into(),
        ));
    }
    Ok(())
}

/// Version + capacity sanity for an already magic-verified header.
fn validate_header(header: &ChannelHeader, positions: usize) -> Result<(), CodebitsError> {
    validate_header_prefix(header)?;
    if positions < header.total_bits() {
        return Err(CodebitsError::Corrupted(
            "channel header payload length inconsistent with .text capacity".into(),
        ));
    }
    Ok(())
}

/// Decodes the channel header from an already-computed full profile: version,
/// payload floor and `.text` capacity must all be consistent.
pub fn parse_channel_header_from_profile(
    prof: &[CodePosition],
) -> Result<ChannelHeader, CodebitsError> {
    let header = header_from_positions(prof)?;
    validate_header(&header, prof.len())?;
    Ok(header)
}

/// Reads the channel header from a code range, scanning only the first
/// `CHANNEL_HEADER_BITS` candidate positions.
///
/// Callers that need capacity validation use
/// [`parse_channel_header_from_profile`] with a full profile; this entry point
/// is for "does a header already exist?" and post-`locate` field reads.
pub fn parse_channel_header(text: &[u8], bitness: u32) -> Result<ChannelHeader, CodebitsError> {
    let prof = profile_upto(text, bitness, Some(CHANNEL_PREFIX_BITS));
    let header = header_from_positions(&prof)?;
    validate_header_prefix(&header)?;
    Ok(header)
}

/// Reads and validates the channel header, requiring the magic to equal
/// `expected_magic` (or [`CHANNEL_MAGIC`] when `None`). This is the `locate`
/// entry point: a magic mismatch is a clean "no channel here", never an error.
///
/// Only the 112 header positions are disassembled; `ube_len` is validated
/// against the minimum here, and `extract_ube` re-checks it against the real
/// `.text` capacity when it reads the payload.
pub fn read_channel_header(
    text: &[u8],
    bitness: u32,
    expected_magic: Option<[u8; 4]>,
) -> Result<ChannelHeader, CodebitsError> {
    let prof = profile_upto(text, bitness, Some(CHANNEL_PREFIX_BITS));
    let header = header_from_positions(&prof)?;
    let want = expected_magic.unwrap_or(CHANNEL_MAGIC);
    if header.magic != want {
        return Err(CodebitsError::ChannelNotFound);
    }
    validate_header_prefix(&header)?;
    Ok(header)
}

/// Reads the full channel (header + UBE payload) from an instrumented code
/// range. The returned `Vec<u8>` is the opaque UBE byte stream. Does not
/// filter by magic — callers must have located the channel first.
pub fn extract_ube(text: &[u8], bitness: u32) -> Result<(ChannelHeader, Vec<u8>), CodebitsError> {
    let prefix = profile_upto(text, bitness, Some(CHANNEL_PREFIX_BITS));
    let header = header_from_positions(&prefix)?;
    validate_header_prefix(&header)?;
    let total_bits = header.total_bits();
    // Second pass bounded by the payload the header declares: a full scan is
    // only paid when the channel really spans the whole section.
    let prof = profile_upto(text, bitness, Some(total_bits));
    if prof.len() < total_bits {
        return Err(CodebitsError::Corrupted(
            "channel header payload length inconsistent with .text capacity".into(),
        ));
    }
    let bits: Vec<bool> = prof.iter().take(total_bits).map(|p| p.bit).collect();
    let channel = bits_to_bytes(&bits);
    Ok((header, channel[CHANNEL_HEADER_LEN..].to_vec()))
}

/// Embeds `ube` into `text` as a code-bit channel and returns the restore diff
/// bitmap (`CHANNEL_HEADER_LEN + ube.len()` bytes, one bit per channel
/// position). The caller stores the diff at `slack_off` in the PE file
/// (design doc §7.2).
pub fn embed(
    text: &mut [u8],
    bitness: u32,
    ube: &[u8],
    slack_off: u32,
) -> Result<Vec<u8>, CodebitsError> {
    let prof = profile(text, bitness);
    let (need_bits, need_slack) = channel_requirement(ube.len());
    if prof.len() < need_bits {
        return Err(CodebitsError::Capacity {
            need_bits,
            have_bits: prof.len(),
        });
    }
    debug_assert_eq!(need_slack, CHANNEL_HEADER_LEN + ube.len());

    let mut channel = Vec::with_capacity(CHANNEL_HEADER_LEN + ube.len());
    // The channel magic mirrors the UBE trailer magic (standard `STH!`, or the
    // password-derived stealth magic): the engine has already finalized the
    // trailer by the time it hands the UBE to `inject`, so the last four bytes
    // of the blob are exactly the magic `locate` will expect.
    let magic = *ube.last_chunk::<4>().ok_or_else(|| {
        CodebitsError::Corrupted("UBE is too short for a 4-byte trailer magic".into())
    })?;
    // The mask key is the 8-byte envelope header magic at the very start of the
    // UBE, which the reader can recover from the channel prefix without a password.
    // It is deliberately *not* `magic`.
    let envelope_header_magic: [u8; 8] = ube
        .get(0..8)
        .ok_or_else(|| CodebitsError::Corrupted("UBE is too short for its header magic".into()))?
        .try_into()
        .expect("8-byte slice");
    let header = ChannelHeader {
        magic,
        version: CHANNEL_VERSION,
        flags: 0,
        ube_len: ube.len() as u32,
        slack_off,
    };
    channel.extend_from_slice(&header.pack(&envelope_header_magic));
    channel.extend_from_slice(ube);

    let bits = bytes_to_bits(&channel);
    let mut diff = vec![0u8; need_slack];
    let mut encoder = Encoder::new(bitness);

    for (i, (&want, pos)) in bits.iter().zip(prof.iter()).enumerate() {
        if pos.bit == want {
            continue;
        }
        // Flip the instruction to its opposite form (same length by F5).
        let other = if pos.commutative {
            Instruction::with2(pos.code, pos.r1, pos.r0)
        } else {
            let dual = dual_and_bit(pos.code)
                .map(|(d, _)| d)
                .ok_or_else(|| CodebitsError::Iced("position lost its semantic dual".into()))?;
            Instruction::with2(dual, pos.r0, pos.r1)
        }
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;

        let end = pos.offset + pos.len;
        encoder
            .encode(&other, pos.offset as u64)
            .map_err(|e| CodebitsError::Iced(e.to_string()))?;
        let encoded = encoder.take_buffer();
        if encoded.len() != pos.len {
            return Err(CodebitsError::Iced(format!(
                "flip at offset {} changed length ({} -> {})",
                pos.offset,
                pos.len,
                encoded.len()
            )));
        }
        text[pos.offset..end].copy_from_slice(&encoded);
        set_bit(&mut diff, i);
    }

    Ok(diff)
}

/// Applies a restore diff to an instrumented code range, flipping every
/// marked position back to its original form (design doc §7.4). The diff
/// region in the file itself is zeroed by the caller.
pub fn apply_diff(
    text: &mut [u8],
    bitness: u32,
    diff: &[u8],
) -> Result<ChannelHeader, CodebitsError> {
    // The header rides inside the diff-covered region; read it from the text
    // itself so that a stale/short diff is caught by the length check below.
    let prefix = profile_upto(text, bitness, Some(CHANNEL_PREFIX_BITS));
    let header = header_from_positions(&prefix)?;
    validate_header_prefix(&header)?;

    let total_bits = header.total_bits();
    if diff.len() != header.diff_len() {
        return Err(CodebitsError::Corrupted(format!(
            "diff length {} != expected {}",
            diff.len(),
            header.diff_len()
        )));
    }

    let prof = profile_upto(text, bitness, Some(total_bits));
    if prof.len() < total_bits {
        return Err(CodebitsError::Corrupted(
            ".text capacity shrank below channel size".into(),
        ));
    }

    let mut encoder = Encoder::new(bitness);
    for (i, pos) in prof.iter().take(total_bits).enumerate() {
        if !get_bit(diff, i) {
            continue;
        }
        let other = if pos.commutative {
            Instruction::with2(pos.code, pos.r1, pos.r0)
        } else {
            let dual = dual_and_bit(pos.code)
                .map(|(d, _)| d)
                .ok_or_else(|| CodebitsError::Iced("position lost its semantic dual".into()))?;
            Instruction::with2(dual, pos.r0, pos.r1)
        }
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;

        encoder
            .encode(&other, pos.offset as u64)
            .map_err(|e| CodebitsError::Iced(e.to_string()))?;
        let encoded = encoder.take_buffer();
        if encoded.len() != pos.len {
            return Err(CodebitsError::Iced(format!(
                "restore at offset {} changed length ({} -> {})",
                pos.offset,
                pos.len,
                encoded.len()
            )));
        }
        text[pos.offset..pos.offset + pos.len].copy_from_slice(&encoded);
    }

    Ok(header)
}

// PE locator and slack logic lives in `super::pe_layout` and is re-exported above.

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
