//! ZIP format adapter for strhide using pre-CD injection and EOCD CD Offset adjustment.

use crate::adapters::{
    HostAdapter, SeekRead, SeekWrite, StrategyCapacity, eof::EofAdapter, format_bytes,
};
use crate::envelope::{EnvelopeHeader, EnvelopeTrailer};
use crate::errors::StrHideError;
use std::io::{Read, Seek, SeekFrom, Write};

pub const ZIP_LOCAL_MAGIC: [u8; 4] = *b"PK\x03\x04";
pub const ZIP_EOCD_MAGIC: [u8; 4] = *b"PK\x05\x06";
pub const ZIP_SPAN_MAGIC: [u8; 4] = *b"PK\x07\x08";

pub fn find_eocd_offset<R: Read + Seek + ?Sized>(
    reader: &mut R,
) -> Result<(u64, u64, u64), StrHideError> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let scan_len = std::cmp::min(file_size, 65536 + 22);
    reader.seek(SeekFrom::End(-(scan_len as i64)))?;
    let mut tail = vec![0u8; scan_len as usize];
    reader.read_exact(&mut tail)?;

    // Walk EOCD magic candidates from the end backwards. A naive rposition()
    // can be fooled by comment bytes that happen to contain "PK\x05\x06",
    // which would misplace the injection point and corrupt the archive.
    // Two passes: first require the record to end exactly at EOF (the shape of
    // a clean archive); if none qualifies, accept a record that merely fits
    // inside the file (the shape left by an EOF-strategy envelope appended
    // past the EOCD). Both passes additionally require the declared central
    // directory to lie before the record.
    for require_exact_eof in [true, false] {
        let mut search_end = tail.len();
        while search_end >= 4 {
            let idx = match tail[..search_end]
                .windows(4)
                .rposition(|w| w == ZIP_EOCD_MAGIC)
            {
                Some(i) => i,
                None => break,
            };
            let eocd_pos = (file_size - scan_len) + idx as u64;

            if idx + 22 <= tail.len() {
                let comment_len =
                    u16::from_le_bytes(tail[idx + 20..idx + 22].try_into().unwrap()) as u64;
                let record_end = eocd_pos + 22 + comment_len;
                let fits = if require_exact_eof {
                    record_end == file_size
                } else {
                    record_end <= file_size
                };
                if fits {
                    let cd_size =
                        u32::from_le_bytes(tail[idx + 12..idx + 16].try_into().unwrap()) as u64;
                    let cd_offset =
                        u32::from_le_bytes(tail[idx + 16..idx + 20].try_into().unwrap()) as u64;
                    if cd_offset + cd_size <= eocd_pos || (cd_offset == 0 && cd_size == 0) {
                        return Ok((eocd_pos, cd_offset, cd_size));
                    }
                }
            }
            search_end = idx;
        }
    }

    Err(StrHideError::CorruptedData(
        "Valid ZIP EOCD (End of Central Directory) record not found".into(),
    ))
}

pub struct ZipAdapter;

impl HostAdapter for ZipAdapter {
    fn format_name(&self) -> &'static str {
        "ZIP"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut prefix = [0u8; 4];
        let ok = if reader.read_exact(&mut prefix).is_ok() {
            prefix == ZIP_LOCAL_MAGIC || prefix == ZIP_EOCD_MAGIC || prefix == ZIP_SPAN_MAGIC
        } else {
            false
        };
        let _ = reader.seek(SeekFrom::Start(start_pos));
        ok
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["pre_cd_inject", "eof"]
    }

    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, ube_size: u64) -> &'static str {
        match find_eocd_offset(reader) {
            Ok((eocd_pos, cd_offset, _)) => {
                // The EOCD cd_offset field AND the patch position
                // (eocd_pos + 16, shifted by ube_size) must both stay inside
                // the 32-bit range, otherwise removal would restore a
                // truncated offset.
                let patch_limit = std::cmp::max(cd_offset, eocd_pos + 16);
                if patch_limit + ube_size >= 0xFFFFFFFF {
                    "eof"
                } else {
                    "pre_cd_inject"
                }
            }
            Err(_) => "eof",
        }
    }

    fn strategy_capacities(&self, reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        // EOCD position determines the 32-bit headroom, so the limit is only
        // known once the carrier is known.
        let mut pre_cd = StrategyCapacity {
            strategy: "pre_cd_inject".into(),
            capacity_bytes: None,
            available: true,
            limit: "carrier-dependent (4 GiB - EOCD offset)".into(),
            note: Some(
                "before Central Directory; file grows; run `inspect -c <carrier>` for the exact limit"
                    .into(),
            ),
        };
        if let Some(r) = reader {
            let start = r.stream_position().ok();
            match find_eocd_offset(r) {
                Ok((eocd_pos, cd_offset, _)) => {
                    let patch_limit = std::cmp::max(cd_offset, eocd_pos + 16);
                    // Mirrors choose_auto_strategy: patch_limit + ube must stay
                    // strictly below 0xFFFFFFFF.
                    let cap = 0xFFFF_FFFEu64.saturating_sub(patch_limit);
                    pre_cd.capacity_bytes = Some(cap);
                    pre_cd.limit = format!(
                        "<= {} B (4 GiB - EOCD offset {})",
                        format_bytes(cap),
                        format_bytes(patch_limit)
                    );
                    pre_cd.note = Some("before Central Directory; file grows".into());
                }
                Err(_) => {
                    pre_cd.available = false;
                    pre_cd.note =
                        Some("Central Directory / EOCD not found; auto falls back to eof".into());
                }
            }
            if let Some(p) = start {
                let _ = r.seek(SeekFrom::Start(p));
            }
        }
        vec![
            pre_cd,
            StrategyCapacity {
                strategy: "eof".into(),
                capacity_bytes: None,
                available: true,
                limit: "unlimited (file grows)".into(),
                note: Some("appended after EOCD".into()),
            },
        ]
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<(u64, u64, u32, u32), StrHideError> {
        if strategy == "eof" {
            return EofAdapter.inject(host_in, ube_in, out, strategy);
        }

        if strategy != "pre_cd_inject" {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by ZIP adapter"
            )));
        }

        let (eocd_pos, cd_offset, _) = find_eocd_offset(host_in)?;

        let ube_size = ube_in.seek(SeekFrom::End(0))?;
        ube_in.seek(SeekFrom::Start(0))?;

        // Both the adjusted cd_offset and the patch position
        // (eocd_pos + 16 + ube_size) must fit in uint32.
        let patch_limit = std::cmp::max(cd_offset, eocd_pos + 16);
        if patch_limit + ube_size >= 0xFFFFFFFF {
            return Err(StrHideError::UnsupportedFormat(
                "Central directory or EOCD patch offset overflow (>4GB) for standard ZIP. Please specify --strategy eof.".into(),
            ));
        }

        // 1. Write everything before Central Directory
        host_in.seek(SeekFrom::Start(0))?;
        let mut remaining = cd_offset;
        let mut buf = [0u8; 64 * 1024];

        while remaining > 0 {
            let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
            let n = host_in.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            remaining -= n as u64;
        }

        let inject_offset = cd_offset;

        // 2. Write UBE data stream (propagate read errors instead of treating them as EOF)
        loop {
            let n = ube_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        let inject_size = ube_size;

        // 3. Write Central Directory and EOCD up to cd_offset field (offset 16 of EOCD)
        let cd_and_eocd_prefix_len = (eocd_pos + 16) - cd_offset;
        let mut rem_cd = cd_and_eocd_prefix_len;
        while rem_cd > 0 {
            let to_read = std::cmp::min(rem_cd, buf.len() as u64) as usize;
            let n = host_in.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            rem_cd -= n as u64;
        }

        // 4. Write updated Central Directory offset
        let new_cd_offset = (cd_offset + ube_size) as u32;
        let patch_offset = (eocd_pos + 16 + ube_size) as u32;
        let orig_patch_val = cd_offset as u32;
        out.write_all(&new_cd_offset.to_le_bytes())?;

        // Skip 4 bytes of original cd_offset in host
        host_in.seek(SeekFrom::Current(4))?;

        // 5. Write remaining part of EOCD (comment length and comment data)
        loop {
            let n = host_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        Ok((inject_offset, inject_size, patch_offset, orig_patch_val))
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        // 1. Try finding UBE before Central Directory
        if let Ok((_, cd_offset, _)) = find_eocd_offset(stego_in)
            && cd_offset >= 112 + 24
        {
            stego_in.seek(SeekFrom::Start(cd_offset - 24))?;
            let mut trailer_bytes = [0u8; 24];
            if stego_in.read_exact(&mut trailer_bytes).is_ok()
                && let Ok(trailer) = EnvelopeTrailer::unpack(&trailer_bytes, expected_trailer_magic)
                && trailer.ube_offset + trailer.ube_total_size == cd_offset
            {
                return Ok(Some((
                    trailer.ube_offset,
                    trailer.ube_total_size,
                    "pre_cd_inject".into(),
                )));
            }
        }

        // 2. Fallback to EOF
        if let Some(t) = EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
            let file_size = stego_in.seek(SeekFrom::End(0))?;
            if t.ube_offset + t.ube_total_size == file_size {
                return Ok(Some((t.ube_offset, t.ube_total_size, "eof".into())));
            }
        }

        Ok(None)
    }

    fn strip(
        &self,
        stego_in: &mut dyn SeekRead,
        out: &mut dyn SeekWrite,
        header: &EnvelopeHeader,
    ) -> Result<(), StrHideError> {
        if header.strategy_id == 1 {
            return EofAdapter.strip(stego_in, out, header);
        }

        // Cut out [inject_offset : inject_offset + inject_size]
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

        // Copy Central Directory and EOCD up to patch_offset.
        //
        // Every offset below comes from the envelope header, which is not
        // covered by the AEAD (see `EnvelopeHeader::get_aad`): a corrupted or
        // tampered header must fail as `CorruptedData`, never panic in a debug
        // build or wrap around into a bogus seek in release.
        let inject_end = header
            .inject_offset
            .checked_add(header.inject_size)
            .ok_or_else(|| {
                StrHideError::CorruptedData(format!(
                    "Injected region [{}, {}] overflows u64 offsets",
                    header.inject_offset, header.inject_size
                ))
            })?;
        stego_in.seek(SeekFrom::Start(inject_end))?;
        let mut bytes_before_patch = (header.patch_offset as u64)
            .checked_sub(inject_end)
            .ok_or_else(|| {
                StrHideError::CorruptedData(format!(
                    "patch_offset {} precedes the end of the injected region ({inject_end})",
                    header.patch_offset
                ))
            })?;
        while bytes_before_patch > 0 {
            let to_read = std::cmp::min(bytes_before_patch, buf.len() as u64) as usize;
            let n = stego_in.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
            bytes_before_patch -= n as u64;
        }

        // Write original patch value (original cd_offset)
        out.write_all(&header.orig_patch_val.to_le_bytes())?;

        // Skip the modified patch field in stego_in (4 bytes)
        let patch_field_end = header.patch_offset.checked_add(4).ok_or_else(|| {
            StrHideError::CorruptedData(format!(
                "patch_offset {} leaves no room for the patch field",
                header.patch_offset
            ))
        })?;
        stego_in.seek(SeekFrom::Start(patch_field_end as u64))?;

        // Copy remaining EOCD bytes (comment len + comment)
        loop {
            let n = stego_in.read(&mut buf)?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        Ok(())
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        match find_eocd_offset(stego_in) {
            Ok((eocd_pos, cd_offset, cd_size)) => Ok((
                true,
                format!(
                    "Valid ZIP archive (EOCD at {eocd_pos}, Central Directory at {cd_offset}, size {cd_size})"
                ),
            )),
            Err(e) => Ok((false, format!("Corrupted ZIP archive: {e}"))),
        }
    }
}
