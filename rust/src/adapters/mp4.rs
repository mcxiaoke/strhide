use std::io::{SeekFrom, Write};
use crate::adapters::{HostAdapter, SeekRead};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;

pub const MP4_UUID_NEUTRAL: [u8; 16] = [
    0xd4, 0x1a, 0x8e, 0x9c, 0x4f, 0x21, 0x4e, 0x87, 0x9a, 0x33, 0x5b, 0x6d, 0x12, 0x84, 0xef, 0x70,
];
pub const LEGACY_UUID_NAMESPACE: [u8; 16] = [
    0x89, b'S', b'T', b'R', b'H', b'I', b'D', b'E', 0, 0, 0, 0, 0, 0, 0, 1,
];

pub struct Mp4Adapter;

impl Mp4Adapter {
    pub fn calc_prefix_len(ube_size: u64) -> u64 {
        if 24 + ube_size < 0xFFFFFFFF {
            24
        } else {
            32
        }
    }
}

impl HostAdapter for Mp4Adapter {
    fn format_name(&self) -> &'static str {
        "MP4"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut prefix = [0u8; 8];
        let ok = if reader.read_exact(&mut prefix).is_ok() {
            let tag = &prefix[4..8];
            tag == b"ftyp" || tag == b"moov" || tag == b"mdat" || tag == b"wide" || tag == b"skip"
        } else {
            false
        };
        let _ = reader.seek(SeekFrom::Start(start_pos));
        ok
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["box_uuid", "eof"]
    }

    fn choose_auto_strategy(&self, _reader: &mut dyn SeekRead, _ube_size: u64) -> &'static str {
        "box_uuid"
    }

    fn inject(
        &self,
        host_in: &mut dyn SeekRead,
        ube_in: &mut dyn SeekRead,
        out: &mut dyn Write,
        strategy: &str,
    ) -> Result<(u64, u64, u32, u32), StrHideError> {
        if strategy != "box_uuid" && strategy != "eof" {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by MP4 adapter"
            )));
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

        let inject_size = if strategy == "box_uuid" {
            if 24 + ube_size < 0xFFFFFFFF {
                // Standard 32-bit Box header (24 bytes)
                let total_box_size = (24 + ube_size) as u32;
                out.write_all(&total_box_size.to_be_bytes())?;
                out.write_all(b"uuid")?;
                out.write_all(&MP4_UUID_NEUTRAL)?;
                24 + ube_size
            } else {
                // 64-bit Large Box header (32 bytes)
                let total_box_size = 32 + ube_size;
                out.write_all(&(1u32).to_be_bytes())?;
                out.write_all(b"uuid")?;
                out.write_all(&total_box_size.to_be_bytes())?;
                out.write_all(&MP4_UUID_NEUTRAL)?;
                32 + ube_size
            }
        } else {
            ube_size
        };

        // Write UBE stream
        while let Ok(n) = ube_in.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        Ok((inject_offset, inject_size, 0, 0))
    }

    fn locate(
        &self,
        stego_in: &mut dyn SeekRead,
        expected_trailer_magic: Option<&[u8; 4]>,
    ) -> Result<Option<(u64, u64, String)>, StrHideError> {
        let trailer = match EnvelopeTrailer::read_from_tail(stego_in, expected_trailer_magic)? {
            Some(t) => t,
            None => return Ok(None),
        };

        // 1. Check standard 32-bit uuid box (24-byte header before trailer.ube_offset)
        if trailer.ube_offset >= 24 {
            stego_in.seek(SeekFrom::Start(trailer.ube_offset - 24))?;
            let mut hdr24 = [0u8; 24];
            if stego_in.read_exact(&mut hdr24).is_ok() {
                let box_type = &hdr24[4..8];
                let box_uuid = &hdr24[8..24];
                let box_size = u32::from_be_bytes(hdr24[0..4].try_into().unwrap()) as u64;

                if box_type == b"uuid"
                    && (box_uuid == MP4_UUID_NEUTRAL || box_uuid == LEGACY_UUID_NAMESPACE)
                    && box_size == 24 + trailer.ube_total_size
                {
                    return Ok(Some((
                        trailer.ube_offset,
                        trailer.ube_total_size,
                        "box_uuid".into(),
                    )));
                }
            }
        }

        // 2. Check 64-bit uuid box (32-byte header before trailer.ube_offset)
        if trailer.ube_offset >= 32 {
            stego_in.seek(SeekFrom::Start(trailer.ube_offset - 32))?;
            let mut hdr32 = [0u8; 32];
            if stego_in.read_exact(&mut hdr32).is_ok() {
                let box_size = u32::from_be_bytes(hdr32[0..4].try_into().unwrap());
                let box_type = &hdr32[4..8];
                let large_size = u64::from_be_bytes(hdr32[8..16].try_into().unwrap());
                let box_uuid = &hdr32[16..32];

                if box_size == 1
                    && box_type == b"uuid"
                    && (box_uuid == MP4_UUID_NEUTRAL || box_uuid == LEGACY_UUID_NAMESPACE)
                    && large_size == 32 + trailer.ube_total_size
                {
                    return Ok(Some((
                        trailer.ube_offset,
                        trailer.ube_total_size,
                        "box_uuid".into(),
                    )));
                }
            }
        }

        // 3. Fallback to EOF
        let file_size = stego_in.seek(SeekFrom::End(0))?;
        if trailer.ube_offset + trailer.ube_total_size == file_size {
            return Ok(Some((trailer.ube_offset, trailer.ube_total_size, "eof".into())));
        }

        Ok(None)
    }

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        stego_in.seek(SeekFrom::Start(0))?;
        let mut prefix = [0u8; 8];
        if stego_in.read_exact(&mut prefix).is_err() {
            return Ok((false, "File too small to be an MP4/MOV container".into()));
        }
        let tag = &prefix[4..8];
        if tag != b"ftyp" && tag != b"moov" && tag != b"mdat" && tag != b"wide" && tag != b"skip" {
            return Ok((
                false,
                format!("Invalid ISO BMFF initial box type: {:?}", String::from_utf8_lossy(tag)),
            ));
        }

        Ok((
            true,
            format!(
                "Valid ISO BMFF container (first box '{}')",
                String::from_utf8_lossy(tag)
            ),
        ))
    }
}
