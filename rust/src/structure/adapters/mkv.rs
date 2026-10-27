use std::io::{SeekFrom, Write};

use crate::errors::StrHideError;
use crate::structure::adapters::ebml::{
    EBML_HEADER_ID, EBML_VOID_ID, MATROSKA_SEGMENT_ID, encode_vint, read_element_id, read_vint_size,
};
use crate::structure::adapters::{HostAdapter, SeekRead, StrategyCapacity};
use crate::structure::envelope::EnvelopeTrailer;

pub struct MkvAdapter;

impl HostAdapter for MkvAdapter {
    fn format_name(&self) -> &'static str {
        "MKV"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }

        let mut id_buf = [0u8; 4];
        let detected = if reader.read_exact(&mut id_buf).is_ok()
            && u32::from_be_bytes(id_buf) == EBML_HEADER_ID
        {
            read_vint_size(reader).is_ok()
        } else {
            false
        };

        let _ = reader.seek(SeekFrom::Start(start_pos));
        detected
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["ebml_void", "eof"]
    }

    fn choose_auto_strategy(&self, _reader: &mut dyn SeekRead, _ube_size: u64) -> &'static str {
        "ebml_void"
    }

    fn strategy_capacities(&self, _reader: Option<&mut dyn SeekRead>) -> Vec<StrategyCapacity> {
        vec![
            StrategyCapacity {
                strategy: "ebml_void".into(),
                capacity_bytes: None,
                available: true,
                limit: "unlimited (file grows)".into(),
                note: Some("Embedded into compliant EBML Void element (0 trailing bytes)".into()),
            },
            StrategyCapacity {
                strategy: "eof".into(),
                capacity_bytes: None,
                available: true,
                limit: "unlimited (file grows)".into(),
                note: Some("Appended after Matroska EOF (EOF overlay)".into()),
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
        if strategy != "ebml_void" && strategy != "eof" {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by MKV adapter"
            )));
        }

        host_in.seek(SeekFrom::Start(0))?;
        let host_len = crate::structure::adapters::io::copy_stream(host_in, out)?;

        let inject_offset = host_len;
        let ube_size = ube_in.seek(SeekFrom::End(0))?;
        ube_in.seek(SeekFrom::Start(0))?;

        let inject_size = if strategy == "ebml_void" {
            let vint = encode_vint(ube_size).ok_or_else(|| {
                StrHideError::General("Envelope size exceeds the EBML VINT range".into())
            })?;
            out.write_all(&[EBML_VOID_ID])?;
            out.write_all(&vint)?;
            1 + vint.len() as u64 + ube_size
        } else {
            ube_size
        };

        crate::structure::adapters::io::copy_exact(ube_in, out, ube_size)?;

        Ok((inject_offset, inject_size, 0, 0))
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        let file_size = stego_in.seek(SeekFrom::End(0))?;
        let trailer = match EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
            Some(t) => t,
            None => return Ok(None),
        };

        // 1. Check ebml_void element
        if let Some(vint) = encode_vint(trailer.ube_total_size) {
            let prefix_len = 1 + vint.len() as u64;
            if trailer.ube_offset >= prefix_len {
                stego_in.seek(SeekFrom::Start(trailer.ube_offset - prefix_len))?;
                let mut prefix = vec![0u8; prefix_len as usize];
                if stego_in.read_exact(&mut prefix).is_ok()
                    && prefix[0] == EBML_VOID_ID
                    && prefix[1..] == *vint
                {
                    return Ok(Some((
                        trailer.ube_offset,
                        trailer.ube_total_size,
                        "ebml_void".into(),
                    )));
                }
            }
        }

        // 2. Fallback to EOF
        if trailer.ube_offset.checked_add(trailer.ube_total_size) == Some(file_size) {
            return Ok(Some((
                trailer.ube_offset,
                trailer.ube_total_size,
                "eof".into(),
            )));
        }

        Ok(None)
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        let file_size = stego_in.seek(SeekFrom::End(0))?;
        if file_size < 12 {
            return Ok((false, "MKV file too small for EBML container".into()));
        }
        stego_in.seek(SeekFrom::Start(0))?;

        let mut offset = 0u64;
        let mut has_ebml_hdr = false;
        let mut has_segment = false;
        let mut elem_count = 0u64;

        while offset < file_size {
            // Check trailing EOF envelope
            let tail_envelope = EnvelopeTrailer::read_from_tail(stego_in, None)
                .ok()
                .flatten()
                .filter(|t| {
                    t.ube_offset == offset
                        && offset.checked_add(t.ube_total_size) == Some(file_size)
                });
            if let Some(trailer) = tail_envelope.filter(|_| has_ebml_hdr && has_segment) {
                return Ok((
                    true,
                    format!(
                        "Valid Matroska EBML container ({elem_count} top-level elements, {} bytes appended after container boundary)",
                        trailer.ube_total_size
                    ),
                ));
            }

            stego_in.seek(SeekFrom::Start(offset))?;
            let (id, id_len) = match read_element_id(stego_in) {
                Ok(res) => res,
                Err(e) => {
                    return Ok((false, format!("Failed to read element ID at {offset}: {e}")));
                }
            };

            if id == EBML_HEADER_ID {
                has_ebml_hdr = true;
            } else if id == MATROSKA_SEGMENT_ID {
                has_segment = true;
            }

            let (size_opt, size_len) = match read_vint_size(stego_in) {
                Ok(res) => res,
                Err(e) => {
                    return Ok((
                        false,
                        format!("Failed to read element size at {offset}: {e}"),
                    ));
                }
            };

            elem_count += 1;
            let header_len = (id_len + size_len) as u64;

            match size_opt {
                Some(data_size) => {
                    let elem_size = match header_len.checked_add(data_size) {
                        Some(s) => s,
                        None => {
                            return Ok((false, "Element size calculation overflow".into()));
                        }
                    };
                    let elem_offset = offset;
                    offset = match offset.checked_add(elem_size) {
                        Some(o) => o,
                        None => {
                            return Ok((false, "Element offset calculation overflow".into()));
                        }
                    };
                    if offset > file_size {
                        return Ok((
                            false,
                            format!("Element 0x{id:08X} at offset {elem_offset} extends past EOF"),
                        ));
                    }
                }
                None => {
                    // Unknown size (usually Segment): extends to EOF
                    offset = file_size;
                }
            }
        }

        if !has_ebml_hdr {
            return Ok((false, "MKV missing EBML Header".into()));
        }
        if !has_segment {
            return Ok((false, "MKV missing Matroska Segment".into()));
        }

        Ok((
            true,
            format!("Valid Matroska EBML container ({elem_count} top-level elements)"),
        ))
    }

    fn suspicious_structures(&self, stego_in: &mut dyn SeekRead) -> Vec<String> {
        let mut found = Vec::new();
        let file_size = match stego_in.seek(SeekFrom::End(0)) {
            Ok(s) => s,
            Err(_) => return found,
        };
        if file_size < 24 {
            return found;
        }

        if stego_in.seek(SeekFrom::End(-24)).is_err() {
            return found;
        }
        let mut tail = [0u8; 24];
        if stego_in.read_exact(&mut tail).is_err() {
            return found;
        }
        let ube_offset = u64::from_le_bytes(tail[0..8].try_into().unwrap());
        let ube_total_size = u64::from_le_bytes(tail[8..16].try_into().unwrap());
        if ube_offset.checked_add(ube_total_size) != Some(file_size) {
            return found;
        }

        if let Some(vint) = encode_vint(ube_total_size) {
            let prefix_len = 1 + vint.len() as u64;
            if ube_offset >= prefix_len
                && stego_in
                    .seek(SeekFrom::Start(ube_offset - prefix_len))
                    .is_ok()
            {
                let mut prefix = vec![0u8; prefix_len as usize];
                if stego_in.read_exact(&mut prefix).is_ok()
                    && prefix[0] == EBML_VOID_ID
                    && prefix[1..] == *vint
                {
                    found.push(format!(
                        "trailing EBML Void element at offset {} carries {ube_total_size} bytes",
                        ube_offset - prefix_len
                    ));
                }
            }
        }
        found
    }

    fn envelope_offset_delta(
        &self,
        _carrier: &mut dyn SeekRead,
        strategy: &str,
        ube_size: u64,
    ) -> Result<u64, StrHideError> {
        if strategy == "ebml_void" {
            let vint = encode_vint(ube_size).ok_or_else(|| {
                StrHideError::General("Envelope size exceeds the EBML VINT range".into())
            })?;
            Ok(1 + vint.len() as u64)
        } else {
            Ok(0)
        }
    }

    fn strategy_note(&self, strategy: &str, _fallback: bool) -> Option<String> {
        if strategy == "ebml_void" {
            Some("Embedded into compliant EBML Void element (0 trailing bytes).".into())
        } else if strategy == "eof" {
            Some("Appended after Matroska EOF (EOF overlay).".into())
        } else {
            None
        }
    }
}
