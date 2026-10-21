//! Windows Portable Executable (PE) adapter for strhide.

use crate::adapters::pe_codebits;
use crate::adapters::pe_slack;
use crate::adapters::{
    HostAdapter, SeekRead, SeekWrite, StrategyCapacity, SubStream, format_bytes,
};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

pub const PE_DOS_MAGIC: [u8; 2] = *b"MZ";
pub const PE_NT_MAGIC: [u8; 4] = *b"PE\x00\x00";

pub struct PeInfo {
    pub arch: &'static str,
    pub num_sections: usize,
    pub pe_image_end: u64,
    pub host_size: u64,
    pub has_authenticode: bool,
}

pub fn parse_pe_headers<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<PeInfo, StrHideError> {
    let host_size = reader.seek(SeekFrom::End(0))?;
    if host_size < 0x40 {
        return Err(StrHideError::UnsupportedFormat(
            "File too small to be a PE executable".into(),
        ));
    }

    reader.seek(SeekFrom::Start(0))?;
    let mut mz = [0u8; 2];
    reader.read_exact(&mut mz)?;
    if mz != PE_DOS_MAGIC {
        return Err(StrHideError::UnsupportedFormat(
            "Not a valid DOS/PE executable (missing 'MZ')".into(),
        ));
    }

    reader.seek(SeekFrom::Start(0x3C))?;
    let mut lfanew_bytes = [0u8; 4];
    reader.read_exact(&mut lfanew_bytes)?;
    let e_lfanew = u32::from_le_bytes(lfanew_bytes) as u64;

    if e_lfanew < 0x40 || e_lfanew + 24 > host_size {
        return Err(StrHideError::UnsupportedFormat(format!(
            "Invalid e_lfanew offset (0x{e_lfanew:X})"
        )));
    }

    reader.seek(SeekFrom::Start(e_lfanew))?;
    let mut pe_sig = [0u8; 4];
    reader.read_exact(&mut pe_sig)?;
    if pe_sig != PE_NT_MAGIC {
        return Err(StrHideError::UnsupportedFormat(
            "Not a valid PE executable (missing 'PE\\0\\0')".into(),
        ));
    }

    let mut coff_header = [0u8; 20];
    reader.read_exact(&mut coff_header)?;

    let num_sections = u16::from_le_bytes(coff_header[2..4].try_into().unwrap()) as usize;
    let size_of_opt_header = u16::from_le_bytes(coff_header[16..18].try_into().unwrap()) as u64;

    let mut arch = "Unknown";
    let mut has_authenticode = false;

    if size_of_opt_header >= 2 {
        let opt_pos = reader.stream_position()?;
        let mut opt_magic_bytes = [0u8; 2];
        reader.read_exact(&mut opt_magic_bytes)?;
        let opt_magic = u16::from_le_bytes(opt_magic_bytes);

        let sec_dir_offset = if opt_magic == 0x10B {
            arch = "PE32";
            Some(128u64)
        } else if opt_magic == 0x20B {
            arch = "PE32+";
            Some(144u64)
        } else {
            None
        };

        if let Some(offset) = sec_dir_offset
            && size_of_opt_header >= offset + 8
        {
            reader.seek(SeekFrom::Start(opt_pos + offset))?;
            let mut sec_bytes = [0u8; 8];
            if reader.read_exact(&mut sec_bytes).is_ok() {
                let sec_va = u32::from_le_bytes(sec_bytes[0..4].try_into().unwrap());
                let sec_sz = u32::from_le_bytes(sec_bytes[4..8].try_into().unwrap());
                if sec_va != 0 && sec_sz != 0 {
                    has_authenticode = true;
                }
            }
        }
    }

    // Read sections to determine pe_image_end
    let sec_table_offset = e_lfanew + 24 + size_of_opt_header;
    reader.seek(SeekFrom::Start(sec_table_offset))?;
    let mut pe_image_end = sec_table_offset;

    for _ in 0..num_sections {
        let mut sec_header = [0u8; 40];
        if reader.read_exact(&mut sec_header).is_err() {
            break;
        }
        let raw_size = u32::from_le_bytes(sec_header[16..20].try_into().unwrap()) as u64;
        let raw_ptr = u32::from_le_bytes(sec_header[20..24].try_into().unwrap()) as u64;
        let sec_end = raw_ptr + raw_size;
        if sec_end > pe_image_end {
            pe_image_end = sec_end;
        }
    }

    Ok(PeInfo {
        arch,
        num_sections,
        pe_image_end,
        host_size,
        has_authenticode,
    })
}

pub struct PeAdapter;

impl HostAdapter for PeAdapter {
    fn format_name(&self) -> &'static str {
        "PE"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        let ok = parse_pe_headers(reader).is_ok();
        let _ = reader.seek(SeekFrom::Start(start_pos));
        ok
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["pe_codebits", "pe_slack", "pe_overlay", "eof"]
    }

    fn is_scattered_strategy(&self, strategy: &str) -> bool {
        strategy == "pe_codebits"
    }

    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
        // Priority: instruction channel -> section padding -> overlay.
        //
        // Both zero-growth strategies are tried first because `pe_overlay`
        // grows the file and leaves the single most obvious PE stego trace
        // (data past the last section).
        //
        // `pe_codebits` needs (a) an x86/x64 `.text` with enough instrumentable
        // positions and (b) a contiguous zero-value slack run for the restore
        // diff. `pe_slack` needs only a zero run, and a *smaller* one: the
        // envelope is written in place, while the code-bit channel must park
        // its `14 + ube` restore diff in padding. So any carrier that fits
        // `pe_codebits` also fits `pe_slack` — the reverse is not true.
        if let Ok(layout) = pe_codebits::parse_pe_code_layout_streaming(reader)
            && let Ok(text) = pe_codebits::read_text_range(reader, &layout)
        {
            let (need_bits, need_slack) = pe_codebits::channel_requirement(ube_size as usize);
            if pe_codebits::profile(&text, layout.bitness).len() >= need_bits
                && let Ok(Some(_)) =
                    pe_codebits::find_slack_run_streaming(reader, &layout.slack_ranges, need_slack)
            {
                return "pe_codebits";
            }
        }
        if let Ok(layout) = pe_codebits::parse_slack_layout_streaming(reader)
            && let Ok(Some(_)) = pe_slack::find_slack_run(
                reader,
                &layout.slack_ranges,
                usize::try_from(ube_size).unwrap_or(usize::MAX),
            )
        {
            return "pe_slack";
        }
        "pe_overlay"
    }

    fn strategy_capacities(&self, reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        // Static answer first; `Some(reader)` replaces it with a measurement of
        // THIS carrier's `.text` and zero-value slack.
        let mut codebits = StrategyCapacity {
            strategy: "pe_codebits".into(),
            capacity_bytes: None,
            available: true,
            limit: "carrier-dependent (.text density + zero slack)".into(),
            note: Some(
                "x86/x64 instruction-encoding channel; file size unchanged; run `inspect <carrier>` for the exact limit"
                    .into(),
            ),
        };
        let mut pad = StrategyCapacity {
            strategy: "pe_slack".into(),
            capacity_bytes: None,
            available: true,
            limit: "carrier-dependent (section padding)".into(),
            note: Some(
                "envelope written into PE alignment padding; file size unchanged; run `inspect <carrier>` for the exact limit"
                    .into(),
            ),
        };
        let mut signed = false;

        if let Some(r) = reader {
            let start = r.stream_position().ok();
            if let Ok(info) = parse_pe_headers(r) {
                signed = info.has_authenticode;
            }
            match pe_codebits::parse_pe_code_layout_streaming(r) {
                Ok(layout) => match pe_codebits::read_text_range(r, &layout) {
                    Ok(text) => {
                        let bits = pe_codebits::profile(&text, layout.bitness).len();
                        let slack = pe_codebits::max_zero_run_streaming(r, &layout.slack_ranges)
                            .unwrap_or(0);
                        // bits:   (14 + ube) * 8 <= usable positions
                        // slack:  14 + ube <= longest contiguous zero run
                        let cap_bits = (bits / 8).saturating_sub(pe_codebits::CHANNEL_HEADER_LEN);
                        let cap_slack = slack.saturating_sub(pe_codebits::CHANNEL_HEADER_LEN);
                        let cap = cap_bits.min(cap_slack);
                        codebits.capacity_bytes = Some(cap as u64);
                        // Report against the *real* smallest envelope the writer
                        // emits, not the 136-byte structural bound: otherwise
                        // `inspect` advertises a capacity that every `write`
                        // rejects.
                        let plain_ok = cap >= crate::envelope::MIN_UBE_PLAIN as usize;
                        let encrypted_ok = cap >= crate::envelope::MIN_UBE_ENCRYPTED as usize;
                        codebits.available = plain_ok;
                        codebits.limit =
                            format!("<= {} B (file size unchanged)", format_bytes(cap as u64));
                        codebits.note = Some(if encrypted_ok {
                            format!(
                                "instruction-encoding channel; fits an encrypted envelope (smallest {} B); longest zero-value slack run is {} B, which caps the restore diff",
                                format_bytes(crate::envelope::MIN_UBE_ENCRYPTED as u64),
                                format_bytes(slack as u64)
                            )
                        } else if plain_ok {
                            format!(
                                "instruction-encoding channel; fits an unencrypted envelope only (encrypted needs >= {} B); longest zero-value slack run is {} B, which caps the restore diff",
                                format_bytes(crate::envelope::MIN_UBE_ENCRYPTED as u64),
                                format_bytes(slack as u64)
                            )
                        } else {
                            format!(
                                "not usable on this .text: at most {} B (unencrypted needs >= {} B, encrypted >= {} B)",
                                format_bytes(cap as u64),
                                format_bytes(crate::envelope::MIN_UBE_PLAIN as u64),
                                format_bytes(crate::envelope::MIN_UBE_ENCRYPTED as u64)
                            )
                        });
                    }
                    Err(_) => {
                        codebits.available = false;
                        codebits.note = Some(".text could not be read".into());
                    }
                },
                Err(e) => {
                    codebits.available = false;
                    codebits.limit = "unavailable".into();
                    codebits.note = Some(match e {
                        pe_codebits::CodebitsError::UnsupportedMachine(_) => {
                            "carrier PE is not x86/x64; code-bit channel unsupported".into()
                        }
                        pe_codebits::CodebitsError::NoText => {
                            "carrier PE has no usable .text section".into()
                        }
                        pe_codebits::CodebitsError::NotPe => "not a PE executable".into(),
                        _ => "PE code layout could not be parsed".into(),
                    });
                }
            }
            // Padding capacity is measured independently of `.text`: it works
            // on any architecture, and the limit is the longest single zero run
            // (the envelope is contiguous and self-contained).
            match pe_codebits::parse_slack_layout_streaming(r) {
                Ok(layout) => {
                    let run =
                        pe_codebits::max_zero_run_streaming(r, &layout.slack_ranges).unwrap_or(0);
                    pad.capacity_bytes = Some(run as u64);
                    let plain_ok = run >= crate::envelope::MIN_UBE_PLAIN as usize;
                    pad.available = plain_ok;
                    pad.limit = format!("<= {} B (file size unchanged)", format_bytes(run as u64));
                    pad.note = Some(if plain_ok {
                        format!(
                            "envelope written into PE alignment padding (largest zero run {} B over {} padding range(s)); file size unchanged, nothing appended",
                            format_bytes(run as u64),
                            layout.slack_ranges.len()
                        )
                    } else {
                        format!(
                            "not usable on this carrier: largest zero run is {} B (smallest envelope is {} B)",
                            format_bytes(run as u64),
                            format_bytes(crate::envelope::MIN_UBE_PLAIN as u64)
                        )
                    });
                }
                Err(_) => {
                    pad.available = false;
                    pad.limit = "unavailable".into();
                    pad.note = Some("PE section table could not be parsed".into());
                }
            }
            if let Some(p) = start {
                let _ = r.seek(SeekFrom::Start(p));
            }
        }

        let mut caps = vec![
            codebits,
            pad,
            StrategyCapacity {
                strategy: "pe_overlay".into(),
                capacity_bytes: None,
                available: true,
                limit: "unlimited (file grows)".into(),
                note: Some("appended beyond the PE image boundary".into()),
            },
            StrategyCapacity {
                strategy: "eof".into(),
                capacity_bytes: None,
                available: true,
                limit: "unlimited (file grows)".into(),
                note: Some("appended at file EOF".into()),
            },
        ];

        if signed {
            // run_all_rejection_checks refuses Authenticode-signed PEs for every
            // strategy; surface that here instead of reporting a usable carrier.
            for c in &mut caps {
                c.available = false;
                c.note = Some(
                    "carrier is Authenticode-signed: strhide refuses to modify it (the signature would be invalidated)"
                        .into(),
                );
            }
        }
        caps
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<(u64, u64, u32, u32), StrHideError> {
        if !matches!(strategy, "pe_codebits" | "pe_slack" | "pe_overlay" | "eof") {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by PE adapter"
            )));
        }

        let pe_info = parse_pe_headers(host_in)?;

        if pe_info.has_authenticode {
            return Err(StrHideError::UnsupportedFormat(
                "Cannot inject into Windows PE: Executable contains an Authenticode digital signature. Modifying it will invalidate the digital signature.".into(),
            ));
        }

        if pe_info.host_size < pe_info.pe_image_end {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Corrupted PE executable: file size ({} bytes) is smaller than PE section headers dictate ({} bytes).",
                pe_info.host_size, pe_info.pe_image_end
            )));
        }

        if strategy == "pe_codebits" {
            return inject_codebits(host_in, ube_in, out);
        }

        if strategy == "pe_slack" {
            // The envelope overwrites zero-value padding in place; the host is
            // otherwise reproduced byte-for-byte, so `inject_size` describes an
            // overwrite rather than an insertion.
            return pe_slack::inject(host_in, ube_in, out);
        }

        host_in.seek(SeekFrom::Start(0))?;
        let mut buf = [0u8; 64 * 1024];
        let mut host_len = 0u64;

        loop {
            let n = host_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            host_len += n as u64;
        }

        let inject_offset = host_len;
        let ube_size = ube_in.seek(SeekFrom::End(0))?;
        ube_in.seek(SeekFrom::Start(0))?;

        loop {
            let n = ube_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        Ok((inject_offset, ube_size, 0, 0))
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        // Code-bit channel first (design doc §8.1): a channel carrier has no
        // trailer at EOF and a trailer carrier has no channel, so the two
        // checks are mutually exclusive and the order only affects cost.
        if let Some(loc) = locate_codebits(stego_in, expected_trailer_magic)? {
            return Ok(Some(loc));
        }

        // A trailing envelope comes before a padding envelope so that stacked
        // envelopes unwrap outermost-first: whatever was appended sits after
        // everything else and can be removed without touching the padding.
        let trailer = EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)?;

        if let Some(trailer) = &trailer
            && let Ok(pe_info) = parse_pe_headers(stego_in)
            && trailer.ube_offset >= pe_info.pe_image_end
        {
            return Ok(Some((
                trailer.ube_offset,
                trailer.ube_total_size,
                "pe_overlay".into(),
            )));
        }

        // Envelope inside the section alignment padding (file size unchanged).
        // Checked before the generic EOF fallback: an envelope placed in the
        // *last* section's padding also ends at EOF, and must still be reported
        // as `pe_slack`.
        if let Some((ube_offset, ube_total_size)) =
            pe_slack::locate(stego_in, expected_trailer_magic)?
        {
            return Ok(Some((ube_offset, ube_total_size, "pe_slack".into())));
        }

        if let Some(trailer) = &trailer {
            let file_size = stego_in.seek(SeekFrom::End(0))?;
            if trailer.ube_offset.checked_add(trailer.ube_total_size) == Some(file_size) {
                return Ok(Some((
                    trailer.ube_offset,
                    trailer.ube_total_size,
                    "eof".into(),
                )));
            }
        }

        Ok(None)
    }

    fn open_ube_reader<'a>(
        &self,
        carrier: &'a mut dyn SeekRead,
        ube_offset: u64,
        ube_total_size: u64,
        strategy: &str,
    ) -> Result<Box<dyn SeekRead + 'a>, StrHideError> {
        if strategy == "pe_codebits" {
            let layout = pe_codebits::parse_pe_code_layout_streaming(carrier)?;
            let text = pe_codebits::read_text_range(carrier, &layout)?;
            let (_header, ube) = pe_codebits::extract_ube(&text, layout.bitness)?;
            if ube.len() as u64 != ube_total_size {
                return Err(StrHideError::CorruptedData(format!(
                    "code-bit channel payload is {} bytes but {} were located",
                    ube.len(),
                    ube_total_size
                )));
            }
            return Ok(Box::new(Cursor::new(ube)));
        }
        Ok(Box::new(SubStream::new(
            carrier,
            ube_offset,
            ube_total_size,
        )?))
    }

    fn strip(
        &self,
        stego_in: &mut dyn SeekRead,
        out: &mut dyn SeekWrite,
        header: &crate::envelope::EnvelopeHeader,
    ) -> Result<(), StrHideError> {
        if crate::router::id_to_strategy(header.strategy_id) == "pe_codebits" {
            return strip_codebits(stego_in, out);
        }
        if crate::router::id_to_strategy(header.strategy_id) == "pe_slack" {
            // The envelope overwrote padding in place: restore = zero-fill that
            // exact region, which reproduces the original bytes because the
            // writer verified the region was all-zero before overwriting it.
            return pe_slack::strip(stego_in, out, header);
        }
        // pe_overlay / eof: the envelope was appended at the end of the host,
        // so restoring means keeping the first `inject_offset` bytes. This
        // mirrors the trait's universal default; it is replicated here only
        // because the codebits dispatch needs a strategy hook that the header
        // provides (PE never emits a non-zero patch_offset).
        stego_in.seek(SeekFrom::Start(0))?;
        let mut remaining = header.inject_offset;
        let mut buf = [0u8; 64 * 1024];
        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            let n = stego_in.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        Ok(())
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        match parse_pe_headers(stego_in) {
            Ok(info) => Ok((
                true,
                format!(
                    "Valid Windows PE executable ({}, {} sections, code boundary at {} bytes)",
                    info.arch, info.num_sections, info.pe_image_end
                ),
            )),
            Err(e) => Ok((false, format!("Corrupted PE executable: {e}"))),
        }
    }

    fn suspicious_structures(&self, stego_in: &mut dyn SeekRead) -> Vec<String> {
        // Data appended beyond the PE image boundary is an overlay; anything
        // past the minimum envelope size is a probable hidden envelope.
        const MIN_ENVELOPE: u64 = 112 + 24;
        let mut found = Vec::new();
        if let Ok(info) = parse_pe_headers(stego_in)
            && info.host_size > info.pe_image_end + MIN_ENVELOPE
        {
            found.push(format!(
                    "overlay of {} bytes beyond PE image boundary (minimum envelope size is {MIN_ENVELOPE})",
                    info.host_size - info.pe_image_end
                ));
        }
        // Hard evidence first: a strhide header magic inside padding can only be
        // a `pe_slack` envelope (standard and legacy magic are both checked).
        // Without a magic the evidence is statistical: ciphertext fills most of
        // the 0..=255 alphabet, while ordinary non-zero padding is repetitive
        // (one corpus executable has a 224-byte block with only 7 distinct
        // values), so require both a plausible size and byte diversity.
        if let Ok(scan) = pe_slack::scan_slack(stego_in) {
            if let Some(offset) = scan.header_offset {
                found.push(format!(
                    "strhide envelope header at offset {offset} inside PE section padding ({} padding range(s) scanned)",
                    scan.ranges
                ));
            } else if scan.nonzero >= crate::envelope::MIN_UBE_PLAIN as u64
                && scan.distinct >= pe_slack::MIN_CIPHERTEXT_DISTINCT
            {
                found.push(format!(
                    "{} non-zero bytes ({} distinct byte values) in PE section padding ({} padding range(s) scanned); this looks like ciphertext, i.e. a stealth envelope whose password is unknown",
                    scan.nonzero, scan.distinct, scan.ranges
                ));
            }
        }
        found
    }

    fn strategy_note(&self, strategy: &str, _fallback: bool) -> Option<String> {
        if strategy == "pe_codebits" {
            Some("Embedded into x86/x64 instruction encodings (ModR/M semantic pairs) in .text; carrier file size unchanged (restore diff stored in zero-value PE padding).".into())
        } else if strategy == "pe_slack" {
            Some("Embedded into Windows PE section alignment padding (file size unchanged; no overlaying data past the last section, executable code untouched).".into())
        } else if strategy == "pe_overlay" {
            Some("Embedded into Windows PE image overlay (executable code and PE sections remain 100% intact).".into())
        } else if strategy == "eof" {
            Some("Appended after PE executable EOF (EOF overlay).".into())
        } else {
            None
        }
    }
}

/// Copies `[0, EOF)` from `reader` to `writer`, substituting each patch region
/// `(start, end)` with the corresponding replacement bytes. Regions are sorted
/// internally and must be non-overlapping (the `.text` scan window and the
/// slack diff region are disjoint by construction).
fn copy_with_patches<R: Read + Seek + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    patches: &[(u64, u64, &[u8])],
) -> Result<(), StrHideError> {
    let mut sorted: Vec<(u64, u64, &[u8])> = patches.to_vec();
    sorted.sort_by_key(|(start, ..)| *start);

    reader.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut cursor = 0u64;
    for (start, end, replacement) in sorted {
        if start > cursor {
            let mut remaining = start - cursor;
            while remaining > 0 {
                let want = remaining.min(buf.len() as u64) as usize;
                let n = reader.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(StrHideError::Io(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "host file ended before the expected patch offset",
                    )));
                }
                writer.write_all(&buf[..n])?;
                remaining -= n as u64;
            }
        }
        writer.write_all(replacement)?;
        cursor = end;
        reader.seek(SeekFrom::Start(cursor))?;
    }
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
    }
    Ok(())
}

/// `pe_codebits` injection (design doc §7.2 / §8.1): embed the UBE into the
/// `.text` instruction encodings and store the restore diff in zero-value
/// slack. The output has exactly the host's size; `inject_offset` and friends
/// are all zero because the envelope has no contiguous file location.
fn inject_codebits(
    host_in: &mut dyn SeekRead,
    ube_in: &mut dyn SeekRead,
    out: &mut dyn Write,
) -> Result<(u64, u64, u32, u32), StrHideError> {
    let layout = pe_codebits::parse_pe_code_layout_streaming(host_in)?;
    let mut text = pe_codebits::read_text_range(host_in, &layout)?;

    let mut ube = Vec::new();
    ube_in.read_to_end(&mut ube)?;
    if ube.is_empty() {
        return Err(StrHideError::CorruptedData(
            "empty UBE payload for pe_codebits".into(),
        ));
    }

    let (_need_bits, need_slack) = pe_codebits::channel_requirement(ube.len());

    // Defensive check: carrier must not already contain a pe_codebits channel.
    // A second codebits injection would overwrite the first channel's header in .text,
    // permanently orphaning the first restore diff in slack (P1-1).
    if let Ok(existing) = pe_codebits::parse_channel_header(&text, layout.bitness) {
        let diff_len = pe_codebits::CHANNEL_HEADER_LEN + existing.ube_len as usize;
        let in_slack = layout.slack_ranges.iter().any(|&(s, e)| {
            (existing.slack_off as u64) >= s && (existing.slack_off as u64 + diff_len as u64) <= e
        });
        if in_slack
            && let Ok(sample) =
                pe_codebits::read_at(host_in, existing.slack_off as u64, diff_len.min(64))
            && sample.iter().any(|&b| b != 0)
        {
            return Err(StrHideError::General(
                "Carrier already contains hidden data (pe_codebits channel). Use remove first or specify another file.".into(),
            ));
        }
    }

    let slack_off = pe_codebits::find_slack_run_streaming(host_in, &layout.slack_ranges, need_slack)?
        .ok_or_else(|| {
            StrHideError::UnsupportedFormat(format!(
                "PE .text cannot host a pe_codebits channel: no contiguous zero-value slack run of {need_slack} bytes for the restore diff (try pe_overlay)"
            ))
        })?;
    // Defensive re-check: the chosen run must be entirely zero before we
    // overwrite it (design doc §6.3); zeroing it on strip then restores the
    // original bytes bit-for-bit.
    let _zeroed = pe_codebits::verify_zero_slack(host_in, slack_off, need_slack)?;

    let diff = pe_codebits::embed(&mut text, layout.bitness, &ube, slack_off as u32)?;

    copy_with_patches(
        host_in,
        out,
        &[
            (
                layout.text_offset,
                layout.text_offset + layout.text_scan_len,
                text.as_slice(),
            ),
            (slack_off, slack_off + need_slack as u64, diff.as_slice()),
        ],
    )?;
    Ok((0, 0, 0, 0))
}

/// `pe_codebits` location: read the channel header from `.text` and validate
/// the magic (standard `CHANNEL_MAGIC`, legacy `STH!` / `STHC`, or the
/// password-derived stealth magic passed in as `expected_trailer_magic`).
/// A magic mismatch is "no channel here".
fn locate_codebits(
    stego_in: &mut dyn SeekRead,
    expected_trailer_magic: Option<&[u8; 4]>,
) -> Result<Option<(u64, u64, String)>, StrHideError> {
    let layout = match pe_codebits::parse_pe_code_layout_streaming(stego_in) {
        Ok(l) => l,
        Err(
            pe_codebits::CodebitsError::NotPe
            | pe_codebits::CodebitsError::NoText
            | pe_codebits::CodebitsError::UnsupportedMachine(_),
        ) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let text = pe_codebits::read_text_range(stego_in, &layout)?;
    match pe_codebits::read_channel_header(&text, layout.bitness, expected_trailer_magic.copied()) {
        Ok(header) => Ok(Some((0, header.ube_len as u64, "pe_codebits".to_string()))),
        Err(pe_codebits::CodebitsError::ChannelNotFound) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// `pe_codebits` restoration (design doc §7.4): flip the marked `.text`
/// positions back to their original forms and zero the slack diff region.
fn strip_codebits(
    stego_in: &mut dyn SeekRead,
    out: &mut dyn SeekWrite,
) -> Result<(), StrHideError> {
    let layout = pe_codebits::parse_pe_code_layout_streaming(stego_in)?;
    let mut text = pe_codebits::read_text_range(stego_in, &layout)?;
    let channel = pe_codebits::parse_channel_header(&text, layout.bitness)?;
    let diff_len = pe_codebits::CHANNEL_HEADER_LEN + channel.ube_len as usize;
    let diff = pe_codebits::read_at(stego_in, channel.slack_off as u64, diff_len)?;

    pe_codebits::apply_diff(&mut text, layout.bitness, &diff)?;

    // The diff region was verified all-zero at write time, so writing zeros
    // restores the original host bytes exactly.
    let zeros = vec![0u8; diff_len];
    copy_with_patches(
        stego_in,
        out,
        &[
            (
                layout.text_offset,
                layout.text_offset + layout.text_scan_len,
                text.as_slice(),
            ),
            (
                channel.slack_off as u64,
                channel.slack_off as u64 + diff_len as u64,
                zeros.as_slice(),
            ),
        ],
    )?;
    Ok(())
}
