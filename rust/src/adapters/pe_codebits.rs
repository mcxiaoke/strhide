//! Windows PE code-bit channel steganography (strategy `pe_codebits`).
//!
//! Hides a strhide UBE envelope inside the *encodings* of existing x86/x64
//! instructions in a PE `.text` section, exploiting the ModR/M semantic-pair
//! redundancy: `mov eax, ebx` encodes identically-semantically as `89 D8` or
//! `8B C3`, so each register-to-register ALU instruction carries one bit. The
//! carrier file size is unchanged and every rewritten instruction is
//! semantically identical to the original.
//!
//! Design document: `docs/pe_codebits_plugin_design.md` (v1.0).
//!
//! Layer split:
//! - [`profile`], [`embed`], [`extract_ube`], [`apply_diff`] are format
//!   agnostic: they operate on a code byte range plus a bitness, so future
//!   ELF/Mach-O support only needs a new section locator.
//! - [`parse_pe_code_layout`] and [`find_slack_run`] are the PE-specific
//!   locator (`.text` discovery, bitness, zero-value slack scan).
//!
//! The UBE bytes are an opaque payload to this module; they are never parsed
//! here. Restoration is driven by a diff bitmap stored in verified-zero PE
//! padding ("slack"), which makes the scheme self-terminating: the diff region
//! is restored by zeroing, because it was all-zero before writing.

use std::io::{Read, Seek, SeekFrom, Write};

use iced_x86::{Code, Decoder, DecoderOptions, Encoder, Instruction, OpKind, Register};

use crate::errors::StrHideError;

/// Channel magic, standard mode. Stealth mode uses the password-derived
/// 4-byte magic that the engine passes to `locate` as `expected_trailer_magic`.
pub const CHANNEL_MAGIC: [u8; 4] = *b"STHC";

/// Channel container version (see design doc §5).
pub const CHANNEL_VERSION: u8 = 1;

/// Channel header length: magic(4) + version(1) + flags(1) + ube_len(4) + slack_off(4).
pub const CHANNEL_HEADER_LEN: usize = 14;

const CHANNEL_HEADER_BITS: usize = CHANNEL_HEADER_LEN * 8;

/// Smallest possible UBE (header 112 + trailer 24, no hint/meta/payload).
/// Used as a sanity bound when reading an untrusted channel header.
const MIN_UBE_LEN: u32 = 136;

/// Errors raised by the code-bit channel. Mapped onto [`StrHideError`] at the
/// adapter boundary; `ChannelNotFound` is *not* an error for `locate` (it
/// simply means "no channel here").
#[derive(Debug)]
pub enum CodebitsError {
    /// Not a PE file (missing MZ / PE signature).
    NotPe,
    /// PE without a usable `.text` section.
    NoText,
    /// PE `Machine` value is neither x86 nor x86-64.
    UnsupportedMachine(u16),
    /// `.text` does not have enough instrumentable positions.
    Capacity { need_bits: usize, have_bits: usize },
    /// No contiguous zero-value slack run large enough for the diff.
    NoSlack { need_bytes: usize },
    /// Channel header magic/version mismatch (locate: no channel present).
    ChannelNotFound,
    /// Channel header parsed but the payload region is inconsistent.
    Corrupted(String),
    /// iced-x86 encode/decode failure.
    Iced(String),
}

impl std::fmt::Display for CodebitsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPe => write!(f, "not a PE executable (missing MZ/PE signature)"),
            Self::NoText => write!(f, "PE has no usable .text section"),
            Self::UnsupportedMachine(m) => {
                write!(f, "unsupported PE machine type 0x{m:04X} (x86/x64 only)")
            }
            Self::Capacity {
                need_bits,
                have_bits,
            } => write!(
                f,
                "insufficient .text steganographic capacity: need {need_bits} bits, have {have_bits}"
            ),
            Self::NoSlack { need_bytes } => write!(
                f,
                "no contiguous zero-value PE slack run of {need_bytes} bytes for the restore diff"
            ),
            Self::ChannelNotFound => write!(f, "no code-bit channel found"),
            Self::Corrupted(msg) => write!(f, "corrupted code-bit channel: {msg}"),
            Self::Iced(msg) => write!(f, "instruction codec error: {msg}"),
        }
    }
}

impl From<CodebitsError> for StrHideError {
    fn from(e: CodebitsError) -> Self {
        match e {
            // A missing channel is a clean "nothing here" for the engine's
            // locate path; report it as no-hidden-data rather than corruption.
            CodebitsError::ChannelNotFound => {
                StrHideError::NoHiddenData("no code-bit channel found".into())
            }
            // Capacity/slack exhaustion is a strategy-selection failure, same
            // class as the other adapters' capacity errors.
            CodebitsError::Capacity { .. } | CodebitsError::NoSlack { .. } => {
                StrHideError::UnsupportedFormat(e.to_string())
            }
            other => StrHideError::CorruptedData(other.to_string()),
        }
    }
}

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
    let mut out = Vec::new();
    let mut decoder = Decoder::new(bitness, text, DecoderOptions::NONE);
    let mut encoder = Encoder::new(bitness);

    for insn in &mut decoder {
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
    fn pack(&self) -> [u8; CHANNEL_HEADER_LEN] {
        let mut buf = [0u8; CHANNEL_HEADER_LEN];
        buf[0..4].copy_from_slice(&self.magic);
        buf[4] = self.version;
        buf[5] = self.flags;
        buf[6..10].copy_from_slice(&self.ube_len.to_le_bytes());
        buf[10..14].copy_from_slice(&self.slack_off.to_le_bytes());
        buf
    }

    fn unpack(bytes: &[u8]) -> Result<Self, CodebitsError> {
        if bytes.len() < CHANNEL_HEADER_LEN {
            return Err(CodebitsError::Corrupted("short channel header".into()));
        }
        Ok(Self {
            magic: bytes[0..4].try_into().unwrap(),
            version: bytes[4],
            flags: bytes[5],
            ube_len: u32::from_le_bytes(bytes[6..10].try_into().unwrap()),
            slack_off: u32::from_le_bytes(bytes[10..14].try_into().unwrap()),
        })
    }

    /// Number of channel bits (header + UBE) this header describes.
    fn total_bits(&self) -> usize {
        (CHANNEL_HEADER_LEN + self.ube_len as usize) * 8
    }

    /// Length of the restore diff: one bit per channel position.
    fn diff_len(&self) -> usize {
        CHANNEL_HEADER_LEN + self.ube_len as usize
    }
}

/// Reads and validates the channel header from an instrumented code range.
/// `expected_magic` selects the standard (`STHC`) or stealth-derived magic.
pub fn read_channel_header(
    text: &[u8],
    bitness: u32,
    expected_magic: Option<[u8; 4]>,
) -> Result<ChannelHeader, CodebitsError> {
    let prof = profile(text, bitness);
    if prof.len() < CHANNEL_HEADER_BITS {
        return Err(CodebitsError::ChannelNotFound);
    }
    let header_bits: Vec<bool> = prof
        .iter()
        .take(CHANNEL_HEADER_BITS)
        .map(|p| p.bit)
        .collect();
    let header = ChannelHeader::unpack(&bits_to_bytes(&header_bits))?;

    let want = expected_magic.unwrap_or(CHANNEL_MAGIC);
    if header.magic != want {
        return Err(CodebitsError::ChannelNotFound);
    }
    if header.version != CHANNEL_VERSION {
        return Err(CodebitsError::Corrupted(format!(
            "unsupported channel version {} (expected {CHANNEL_VERSION})",
            header.version
        )));
    }
    if header.ube_len < MIN_UBE_LEN || prof.len() < header.total_bits() {
        return Err(CodebitsError::Corrupted(
            "channel header payload length inconsistent with .text capacity".into(),
        ));
    }
    Ok(header)
}

/// Reads the full channel (header + UBE payload) from an instrumented code
/// range. The returned `Vec<u8>` is the opaque UBE byte stream.
pub fn extract_ube(
    text: &[u8],
    bitness: u32,
    expected_magic: Option<[u8; 4]>,
) -> Result<(ChannelHeader, Vec<u8>), CodebitsError> {
    let header = read_channel_header(text, bitness, expected_magic)?;
    let prof = profile(text, bitness);
    let bits: Vec<bool> = prof
        .iter()
        .take(header.total_bits())
        .map(|p| p.bit)
        .collect();
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
    let header = ChannelHeader {
        magic: CHANNEL_MAGIC,
        version: CHANNEL_VERSION,
        flags: 0,
        ube_len: ube.len() as u32,
        slack_off,
    };
    channel.extend_from_slice(&header.pack());
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
    let header = {
        let prof = profile(text, bitness);
        if prof.len() < CHANNEL_HEADER_BITS {
            return Err(CodebitsError::Corrupted(
                "no channel header in .text".into(),
            ));
        }
        let header_bits: Vec<bool> = prof
            .iter()
            .take(CHANNEL_HEADER_BITS)
            .map(|p| p.bit)
            .collect();
        ChannelHeader::unpack(&bits_to_bytes(&header_bits))?
    };

    let total_bits = header.total_bits();
    if diff.len() != header.diff_len() {
        return Err(CodebitsError::Corrupted(format!(
            "diff length {} != expected {}",
            diff.len(),
            header.diff_len()
        )));
    }

    let prof = profile(text, bitness);
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

// ---------------------------------------------------------------------------
// PE locator
// ---------------------------------------------------------------------------

/// `.text` location, bitness and candidate slack ranges of a PE file.
#[derive(Debug, Clone)]
pub struct PeCodeLayout {
    /// 16/32/64.
    pub bitness: u32,
    /// File offset of the `.text` section raw data.
    pub text_offset: u64,
    /// Bytes to scan: `min(virtual_size, size_of_raw_data)`, clamped to EOF.
    pub text_scan_len: u64,
    /// Total file size.
    pub host_size: u64,
    /// Candidate zero-value padding ranges `(start, end)`, file order.
    pub slack_ranges: Vec<(u64, u64)>,
}

/// Reads a PE's code layout from an in-memory image.
pub fn pe_code_layout(data: &[u8]) -> Result<PeCodeLayout, CodebitsError> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err(CodebitsError::NotPe);
    }
    let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if e_lfanew < 0x40 || e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(CodebitsError::NotPe);
    }
    let coff = e_lfanew + 4;
    let machine = u16::from_le_bytes(data[coff..coff + 2].try_into().unwrap());
    let num_sections = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().unwrap()) as usize;
    let size_of_opt = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().unwrap()) as usize;

    let bitness = match machine {
        0x14C => 32,
        0x8664 => 64,
        other => return Err(CodebitsError::UnsupportedMachine(other)),
    };

    let opt = coff + 20;
    if opt + 2 > data.len() {
        return Err(CodebitsError::NotPe);
    }
    let opt_magic = u16::from_le_bytes(data[opt..opt + 2].try_into().unwrap());
    if !matches!(opt_magic, 0x10B | 0x20B) {
        return Err(CodebitsError::NotPe);
    }

    let sec_table = opt + size_of_opt;
    let mut sections: Vec<(String, u32, u32, u32)> = Vec::new(); // (name, vsize, rawsize, rawptr)
    for i in 0..num_sections {
        let off = sec_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let name = String::from_utf8_lossy(&data[off..off + 8])
            .trim_end_matches('\0')
            .to_string();
        let vsize = u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap());
        let rawsize = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap());
        let rawptr = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap());
        sections.push((name, vsize, rawsize, rawptr));
    }

    let text = sections
        .iter()
        .find(|(name, ..)| name == ".text")
        .ok_or(CodebitsError::NoText)?;
    let text_offset = text.3 as u64;
    let scan_len = (text.1.min(text.2) as u64).min(data.len() as u64 - text_offset);

    // Slack candidates: header padding between the section table and the
    // first section's raw data, plus each section's tail padding beyond
    // min(vsize, rawsize). The file-tail overlay region is deliberately
    // excluded (design doc §6.3).
    let host_size = data.len() as u64;
    let mut slack_ranges = Vec::new();
    let sec_table_end = (sec_table + sections.len() * 40) as u64;
    let first_raw = sections
        .iter()
        .map(|(.., rawptr)| *rawptr as u64)
        .filter(|p| *p > 0)
        .min();
    if let Some(first_raw) = first_raw
        && first_raw > sec_table_end
    {
        slack_ranges.push((sec_table_end, first_raw.min(host_size)));
    }
    for (_, vsize, rawsize, rawptr) in &sections {
        let a = *rawptr as u64 + (*vsize).min(*rawsize) as u64;
        let b = (*rawptr as u64 + *rawsize as u64).min(host_size);
        if b > a {
            slack_ranges.push((a, b));
        }
    }

    Ok(PeCodeLayout {
        bitness,
        text_offset,
        text_scan_len: scan_len,
        host_size,
        slack_ranges,
    })
}

/// Scans the slack candidate ranges of an in-memory image for the best
/// contiguous all-zero run of at least `needed` bytes: shortest sufficient run,
/// ties broken by lowest file offset (design doc §6.3). Returns its offset.
pub fn find_slack_run(data: &[u8], ranges: &[(u64, u64)], needed: usize) -> Option<u64> {
    let mut best: Option<(usize, u64)> = None; // (len, offset)
    for &(start, end) in ranges {
        let start = start as usize;
        let end = (end as usize).min(data.len());
        if start >= end {
            continue;
        }
        let mut i = start;
        while i < end {
            if data[i] != 0 {
                i += 1;
                continue;
            }
            let run_start = i;
            while i < end && data[i] == 0 {
                i += 1;
            }
            let len = i - run_start;
            if len >= needed && best.is_none_or(|(bl, _)| len < bl) {
                best = Some((len, run_start as u64));
            }
        }
    }
    best.map(|(_, off)| off)
}

/// Reads a `Read + Seek` stream's PE code layout without loading the whole
/// file: only the headers are parsed here; `.text` and slack are read by the
/// caller through [`read_text_range`] / [`read_slack_candidates`].
pub fn parse_pe_code_layout_streaming<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<PeCodeLayout, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    let host_size = reader
        .seek(SeekFrom::End(0))
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    if host_size < 0x40 {
        reader.seek(SeekFrom::Start(start_pos)).ok();
        return Err(CodebitsError::NotPe);
    }
    // Headers are at most a few KB; read them once.
    let header_window = (host_size.min(0x10000)) as usize;
    reader.seek(SeekFrom::Start(0)).ok();
    let mut head = vec![0u8; header_window];
    reader
        .read_exact(&mut head)
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;

    let layout = pe_code_layout(&head).inspect_err(|_| {
        reader.seek(SeekFrom::Start(start_pos)).ok();
    })?;
    // Recompute fields that depend on the true host size.
    let text_scan_len = layout
        .text_scan_len
        .min(host_size.saturating_sub(layout.text_offset));
    let slack_ranges = layout
        .slack_ranges
        .into_iter()
        .map(|(a, b)| (a, b.min(host_size)))
        .filter(|(a, b)| b > a)
        .collect();
    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(PeCodeLayout {
        bitness: layout.bitness,
        text_offset: layout.text_offset,
        text_scan_len,
        host_size,
        slack_ranges,
    })
}

/// Reads the `.text` scan window of `layout` from `reader`.
pub fn read_text_range<R: Read + Seek + ?Sized>(
    reader: &mut R,
    layout: &PeCodeLayout,
) -> Result<Vec<u8>, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    reader
        .seek(SeekFrom::Start(layout.text_offset))
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    let mut buf = vec![0u8; layout.text_scan_len as usize];
    reader
        .read_exact(&mut buf)
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(buf)
}

/// Streams the slack candidate ranges, tracking the best all-zero run of at
/// least `needed` bytes (shortest sufficient run, ties -> lowest offset).
pub fn find_slack_run_streaming<R: Read + Seek + ?Sized>(
    reader: &mut R,
    ranges: &[(u64, u64)],
    needed: usize,
) -> Result<Option<u64>, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    let mut best: Option<(usize, u64)> = None;
    let mut buf = vec![0u8; 64 * 1024];

    for &(start, end) in ranges {
        if end <= start {
            continue;
        }
        reader
            .seek(SeekFrom::Start(start))
            .map_err(|e| CodebitsError::Iced(e.to_string()))?;
        let mut remaining = end - start;
        let mut run_start: Option<u64> = None;
        let mut run_len = 0usize;
        let mut pos = start;
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = reader
                .read(&mut buf[..want])
                .map_err(|e| CodebitsError::Iced(e.to_string()))?;
            if n == 0 {
                break;
            }
            for &b in &buf[..n] {
                if b == 0 {
                    if run_start.is_none() {
                        run_start = Some(pos);
                    }
                    run_len += 1;
                } else {
                    if let Some(rs) = run_start.take()
                        && run_len >= needed
                        && best.is_none_or(|(bl, _)| run_len < bl)
                    {
                        best = Some((run_len, rs));
                    }
                    run_len = 0;
                }
                pos += 1;
            }
            remaining -= n as u64;
        }
        if let Some(rs) = run_start.take()
            && run_len >= needed
            && best.is_none_or(|(bl, _)| run_len < bl)
        {
            best = Some((run_len, rs));
        }
    }

    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(best.map(|(_, off)| off))
}

/// Reads `len` bytes at `offset` from a `Read + Seek` stream.
pub fn read_at<R: Read + Seek + ?Sized>(
    reader: &mut R,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, CodebitsError> {
    let start_pos = reader
        .stream_position()
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    reader.seek(SeekFrom::Start(start_pos)).ok();
    Ok(buf)
}

/// Verifies that `[offset, offset + len)` is entirely zero, then returns a
/// zero-filled buffer of `len` bytes for the diff (design doc §6.3).
pub fn verify_zero_slack<R: Read + Seek + ?Sized>(
    reader: &mut R,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, CodebitsError> {
    let existing = read_at(reader, offset, len)?;
    if existing.iter().any(|&b| b != 0) {
        return Err(CodebitsError::NoSlack { need_bytes: len });
    }
    Ok(vec![0u8; len])
}

/// Writes `bytes` at `offset` into a `Write + Seek` stream.
pub fn write_at<W: Write + Seek + ?Sized>(
    writer: &mut W,
    offset: u64,
    bytes: &[u8],
) -> Result<(), CodebitsError> {
    writer
        .seek(SeekFrom::Start(offset))
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    writer
        .write_all(bytes)
        .map_err(|e| CodebitsError::Iced(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic 64-bit code: a repeating mix of `mov eax, ebx` (89 D8),
    /// `mov ebx, eax` (8B C3-equivalent is 89 D9? no: 8B D9 = mov ebx, ecx),
    /// TEST forms and a memory-operand instruction that must be filtered out.
    fn synthetic_text() -> Vec<u8> {
        let mut v = Vec::new();
        // mov eax, ebx        ; 89 D8  (pair, bit 0)
        v.extend_from_slice(&[0x89, 0xD8]);
        // mov ecx, edx        ; 89 CA  (pair, bit 0)
        v.extend_from_slice(&[0x89, 0xCA]);
        // mov edx, ecx        ; 8B D1  (pair, bit 1)
        v.extend_from_slice(&[0x8B, 0xD1]);
        // mov [eax], ebx      ; 89 18  (memory operand -> filtered by F2)
        v.extend_from_slice(&[0x89, 0x18]);
        // test eax, ebx       ; 85 C3  (commutative, r0<r1 -> bit 0)
        v.extend_from_slice(&[0x85, 0xC3]);
        // test ebx, eax       ; 85 D8  (commutative, r0>r1 -> bit 1)
        v.extend_from_slice(&[0x85, 0xD8]);
        // test eax, eax       ; 85 C0  (equal regs -> filtered by F3)
        v.extend_from_slice(&[0x85, 0xC0]);
        // add eax, ebx        ; 01 D8  (pair, bit 0)
        v.extend_from_slice(&[0x01, 0xD8]);
        // cmp ebx, eax        ; 3B C3  (pair, bit 1)
        v.extend_from_slice(&[0x3B, 0xC3]);
        // embedded data (must be skipped as INVALID or unsupported)
        v.extend_from_slice(&[0x90, 0x90, 0x48, 0x89, 0x00]);
        v
    }

    #[test]
    fn profile_filters_and_bits() {
        let text = synthetic_text();
        let prof = profile(&text, 64);
        // 89D8, 89CA, 8BD1, 85C3, 85D8, 01D8, 3BC3 = 7 positions.
        // 8918 (memory) and 85C0 (equal regs) are filtered out.
        assert_eq!(prof.len(), 7, "positions: {prof:?}");
        assert_eq!(prof[0].offset, 0);
        assert!(!prof[0].bit, "89 D8 is the store form (bit 0)");
        assert_eq!(prof[1].offset, 2);
        assert!(prof[2].bit, "8B D1 is the load form (bit 1)");
        assert_eq!(prof[3].offset, 8, "85 C3 after the memory-operand insn");
        assert!(!prof[3].bit);
        assert!(prof[4].bit, "85 D8 has r0 > r1 (bit 1)");
        assert!(!prof[5].bit, "01 D8 add store form");
        assert!(prof[6].bit, "3B C3 cmp load form");
        for p in &prof {
            assert!(p.len == 2);
        }
    }

    #[test]
    fn profile_is_stable_after_embed() {
        // Repeat the synthetic pattern until there is enough capacity.
        let mut full = Vec::new();
        while full.len() < 8192 {
            full.extend_from_slice(&synthetic_text());
        }
        full.truncate(8192);
        let ube = vec![0xA5u8; 200];
        let (need_bits, need_slack) = channel_requirement(ube.len());
        let before = profile(&full, 64);
        assert!(before.len() >= need_bits);

        let diff = embed(&mut full, 64, &ube, 0x1000).expect("embed");
        assert_eq!(diff.len(), need_slack);

        let after = profile(&full, 64);
        assert_eq!(
            after.iter().map(|p| p.offset).collect::<Vec<_>>(),
            before.iter().map(|p| p.offset).collect::<Vec<_>>(),
            "position list must be identical after embed"
        );
    }

    #[test]
    fn embed_extract_roundtrip() {
        let mut full = Vec::new();
        while full.len() < 8192 {
            full.extend_from_slice(&synthetic_text());
        }
        full.truncate(8192);
        let ube: Vec<u8> = (0..200u32).map(|i| (i * 31 + 7) as u8).collect();
        let original = full.clone();

        let diff = embed(&mut full, 64, &ube, 0x2222).expect("embed");

        let (header, got) = extract_ube(&full, 64, None).expect("extract");
        assert_eq!(header.magic, CHANNEL_MAGIC);
        assert_eq!(header.version, CHANNEL_VERSION);
        assert_eq!(header.ube_len, ube.len() as u32);
        assert_eq!(header.slack_off, 0x2222);
        assert_eq!(got, ube, "extracted UBE must round-trip byte-exactly");

        // Stealth magic: a wrong expected magic must read as "not found".
        let err = read_channel_header(&full, 64, Some(*b"XXXX"));
        assert!(matches!(err, Err(CodebitsError::ChannelNotFound)));
        let _ = read_channel_header(&full, 64, Some(CHANNEL_MAGIC)).expect("standard magic");

        // Restore: apply the diff, then the text must equal the original.
        apply_diff(&mut full, 64, &diff).expect("apply_diff");
        assert_eq!(full, original, "strip must restore .text byte-exactly");
    }

    #[test]
    fn embed_capacity_error() {
        let text = synthetic_text();
        let mut text = text;
        let ube = vec![0u8; 1000];
        let err = embed(&mut text, 64, &ube, 0).unwrap_err();
        assert!(
            matches!(err, CodebitsError::Capacity { .. }),
            "expected capacity error, got {err:?}"
        );
    }

    #[test]
    fn bit_helpers_msb_first() {
        assert_eq!(
            bytes_to_bits(&[0b1000_0000, 0b0000_0001]),
            vec![
                true, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, true
            ]
        );
        assert_eq!(bits_to_bytes(&[true, false, true]), vec![0b1010_0000]);
        let mut buf = vec![0u8; 2];
        set_bit(&mut buf, 0);
        set_bit(&mut buf, 9);
        assert!(get_bit(&buf, 0));
        assert!(get_bit(&buf, 9));
        assert!(!get_bit(&buf, 1));
    }

    #[test]
    fn pe_layout_and_slack_on_synthetic_image() {
        let img = synthetic_pe();
        let layout = pe_code_layout(&img).expect("layout");
        assert_eq!(layout.bitness, 64);
        assert_eq!(layout.text_offset, 0x400);
        assert!(layout.text_scan_len > 0);
        // Header padding [sec_table_end, 0x400) plus .text tail padding must
        // both be present and all-zero.
        assert!(layout.slack_ranges.len() >= 2);
        for (a, b) in &layout.slack_ranges {
            assert!(img[*a as usize..*b as usize].iter().all(|&x| x == 0));
        }
        let run = find_slack_run(&img, &layout.slack_ranges, 300).expect("slack run");
        assert!(
            img[run as usize..run as usize + 300]
                .iter()
                .all(|&x| x == 0)
        );
        // Streaming variant must agree with the in-memory variant.
        let mut cursor = std::io::Cursor::new(img.clone());
        let slayout = parse_pe_code_layout_streaming(&mut cursor).expect("stream layout");
        assert_eq!(slayout.text_offset, layout.text_offset);
        assert_eq!(slayout.text_scan_len, layout.text_scan_len);
        let srun = find_slack_run_streaming(&mut cursor, &slayout.slack_ranges, 300)
            .expect("stream slack")
            .expect("run");
        assert_eq!(srun, run);
    }

    /// Builds a minimal but structurally valid PE32+ image with a `.text`
    /// section full of instrumentable instructions and zero padding.
    pub fn synthetic_pe() -> Vec<u8> {
        let mut img = vec![0u8; 0x400];
        // DOS header
        img[0..2].copy_from_slice(b"MZ");
        img[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature at 0x80
        img[0x80..0x84].copy_from_slice(b"PE\0\0");
        // COFF: machine=amd64, 1 section, opt header size 240, characteristics
        img[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        img[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        // TimeDateStamp / PointerToSymbolTable / NumberOfSymbols stay zero.
        img[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader
        img[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes()); // executable
        // Optional header PE32+ (magic 0x20B), 240 bytes; security dir at +144 stays zero
        let opt = 0x98;
        img[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        // Section table at 0x94 + 240 = 0x184
        let sec = opt + 240;
        let name = b".text\0\0\0";
        img[sec..sec + 8].copy_from_slice(name);
        let vsize: u32 = 0x300;
        let rawsize: u32 = 0x400;
        let rawptr: u32 = 0x400;
        img[sec + 8..sec + 12].copy_from_slice(&vsize.to_le_bytes());
        img[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        img[sec + 16..sec + 20].copy_from_slice(&rawsize.to_le_bytes());
        img[sec + 20..sec + 24].copy_from_slice(&rawptr.to_le_bytes());
        img[sec + 36..sec + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // code|exec|read

        // .text body: repeat a mixed pattern of instrumentable instructions.
        let body = synthetic_text();
        let mut text = Vec::new();
        while text.len() < vsize as usize {
            text.extend_from_slice(&body);
        }
        text.truncate(vsize as usize);
        img.extend_from_slice(&text);
        // Tail padding up to rawsize (0x100 bytes of zeros) then EOF.
        img.resize(rawptr as usize + rawsize as usize, 0);
        img
    }
}
