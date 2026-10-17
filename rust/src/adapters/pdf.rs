//! PDF format adapter for strhide with compliant Incremental Update object stream hiding.

use std::io::{Read, Seek, SeekFrom, Write};
use crate::adapters::{HostAdapter, SeekRead, eof::EofAdapter};
use crate::envelope::EnvelopeTrailer;
use crate::errors::StrHideError;

pub const PDF_MAGIC: [u8; 5] = *b"%PDF-";

pub struct PdfTrailerInfo {
    pub eof_offset: u64,
    pub prev_startxref: u64,
    pub new_obj_num: u64,
    pub root_ref: Option<String>,
    pub info_ref: Option<String>,
}

pub fn parse_pdf_trailer_info<R: Read + Seek + ?Sized>(reader: &mut R) -> Result<PdfTrailerInfo, StrHideError> {
    let file_size = reader.seek(SeekFrom::End(0))?;
    let scan_len = std::cmp::min(file_size, 64 * 1024);
    reader.seek(SeekFrom::End(-(scan_len as i64)))?;
    let mut tail = vec![0u8; scan_len as usize];
    reader.read_exact(&mut tail)?;

    let eof_idx = tail
        .windows(5)
        .rposition(|w| w == b"%%EOF")
        .ok_or_else(|| StrHideError::CorruptedData("Valid PDF %%EOF marker not found within tail window".into()))?;

    let abs_eof_pos = (file_size - scan_len) + eof_idx as u64 + 5;
    reader.seek(SeekFrom::Start(abs_eof_pos))?;
    let mut trailing = [0u8; 16];
    let n = reader.read(&mut trailing)?;
    let mut idx_nl = 0;
    while idx_nl < n && (trailing[idx_nl] == b'\r' || trailing[idx_nl] == b'\n') {
        idx_nl += 1;
    }
    let eof_offset = abs_eof_pos + idx_nl as u64;

    let text_before_eof = String::from_utf8_lossy(&tail[..eof_idx]);
    let sx_idx = text_before_eof
        .rfind("startxref")
        .ok_or_else(|| StrHideError::CorruptedData("PDF startxref marker not found before %%EOF".into()))?;

    let sx_part = text_before_eof[sx_idx + "startxref".len()..].trim();
    let prev_startxref: u64 = sx_part
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| StrHideError::CorruptedData("Could not parse startxref offset integer".into()))?;

    let mut size_val: u64 = 9999;
    let mut root_ref = None;
    let mut info_ref = None;

    if let Some(trailer_idx) = text_before_eof.rfind("trailer") {
        let trailer_str = &text_before_eof[trailer_idx..sx_idx];
        if let Some(pos) = trailer_str.find("/Size") {
            let after = trailer_str[pos + 5..].trim_start();
            if let Some(num_str) = after.split_whitespace().next() {
                if let Ok(v) = num_str.parse::<u64>() {
                    size_val = v;
                }
            }
        }
        if let Some(pos) = trailer_str.find("/Root") {
            let after = trailer_str[pos + 5..].trim_start();
            let parts: Vec<&str> = after.split_whitespace().take(3).collect();
            if parts.len() == 3 && parts[2] == "R" {
                root_ref = Some(format!("{} {} R", parts[0], parts[1]));
            }
        }
        if let Some(pos) = trailer_str.find("/Info") {
            let after = trailer_str[pos + 5..].trim_start();
            let parts: Vec<&str> = after.split_whitespace().take(3).collect();
            if parts.len() == 3 && parts[2] == "R" {
                info_ref = Some(format!("{} {} R", parts[0], parts[1]));
            }
        }
    }

    Ok(PdfTrailerInfo {
        eof_offset,
        prev_startxref,
        new_obj_num: size_val,
        root_ref,
        info_ref,
    })
}

pub struct PdfAdapter;

impl PdfAdapter {
    pub fn calc_prefix_len<R: Read + Seek + ?Sized>(reader: &mut R, ube_size: u64) -> Result<u64, StrHideError> {
        let info = parse_pdf_trailer_info(reader)?;
        let obj_header = format!(
            "\n{} 0 obj\n<< /Type /Metadata /Length {} >>\nstream\n",
            info.new_obj_num, ube_size
        );
        Ok(obj_header.len() as u64)
    }
}

impl HostAdapter for PdfAdapter {
    fn format_name(&self) -> &'static str {
        "PDF"
    }

    fn detect(&self, reader: &mut dyn SeekRead) -> bool {
        let start_pos = match reader.stream_position() {
            Ok(pos) => pos,
            Err(_) => return false,
        };
        if reader.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }
        let mut prefix = [0u8; 5];
        let ok = reader.read_exact(&mut prefix).is_ok() && prefix == PDF_MAGIC;
        let _ = reader.seek(SeekFrom::Start(start_pos));
        ok
    }

    fn supported_strategies(&self) -> Vec<&'static str> {
        vec!["incremental", "eof"]
    }

    fn choose_auto_strategy(&self, reader: &mut dyn SeekRead, _ube_size: u64) -> &'static str {
        if parse_pdf_trailer_info(reader).is_ok() {
            "incremental"
        } else {
            "eof"
        }
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

        if strategy != "incremental" {
            return Err(StrHideError::UnsupportedFormat(format!(
                "Strategy '{strategy}' not supported by PDF adapter"
            )));
        }

        let info = parse_pdf_trailer_info(host_in).map_err(|e| {
            StrHideError::UnsupportedFormat(format!(
                "PDF cannot be incrementally updated ({e}). Please specify --strategy eof."
            ))
        })?;

        let ube_size = ube_in.seek(SeekFrom::End(0))?;
        ube_in.seek(SeekFrom::Start(0))?;

        // 1. Write host up to eof_offset
        host_in.seek(SeekFrom::Start(0))?;
        let mut remaining = info.eof_offset;
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

        let inject_offset = info.eof_offset;

        // 2. Construct object header
        let obj_header = format!(
            "\n{} 0 obj\n<< /Type /Metadata /Length {} >>\nstream\n",
            info.new_obj_num, ube_size
        );
        let actual_obj_offset = inject_offset + 1; // skips leading \n
        out.write_all(obj_header.as_bytes())?;

        // 3. Write UBE data stream
        while let Ok(n) = ube_in.read(&mut buf) {
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n])?;
        }

        // 4. End object stream
        out.write_all(b"\nendstream\nendobj\n")?;

        // 5. Write incremental xref
        let xref_offset = inject_offset
            + obj_header.len() as u64
            + ube_size
            + b"\nendstream\nendobj\n".len() as u64;

        let xref_str = format!("xref\n{} 1\n{:010} 00000 n \n", info.new_obj_num, actual_obj_offset);
        out.write_all(xref_str.as_bytes())?;

        // 6. Write incremental trailer
        let mut trailer_str = format!("trailer\n<<\n/Size {}\n", info.new_obj_num + 1);
        if let Some(root) = &info.root_ref {
            trailer_str.push_str(&format!("/Root {root}\n"));
        }
        if let Some(info_r) = &info.info_ref {
            trailer_str.push_str(&format!("/Info {info_r}\n"));
        }
        trailer_str.push_str(&format!(
            "/Prev {}\n>>\nstartxref\n{}\n%%EOF\n",
            info.prev_startxref, xref_offset
        ));
        out.write_all(trailer_str.as_bytes())?;

        let inject_size = obj_header.len() as u64
            + ube_size
            + b"\nendstream\nendobj\n".len() as u64
            + xref_str.len() as u64
            + trailer_str.len() as u64;

        // 7. Preserve any bytes the original host carried after its final
        // %%EOF (non-standard "dirty tail"). Dropping them would silently
        // damage the carrier and break the 100% bit-exact restore guarantee,
        // so they are copied verbatim after the new %%EOF.
        host_in.seek(SeekFrom::Start(info.eof_offset))?;
        loop {
            let n = host_in.read(&mut buf)?;
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
        stego_in.seek(SeekFrom::Start(0))?;
        let mut magic = [0u8; 5];
        if stego_in.read_exact(&mut magic).is_err() || magic != PDF_MAGIC {
            return Ok(None);
        }

        // 1. Check incremental update object stream first
        let total_size = stego_in.seek(SeekFrom::End(0))?;
        let scan_len = std::cmp::min(total_size, 128 * 1024);
        stego_in.seek(SeekFrom::End(-(scan_len as i64)))?;
        let mut tail = vec![0u8; scan_len as usize];
        stego_in.read_exact(&mut tail)?;

        if let Some(eof_idx) = tail.windows(5).rposition(|w| w == b"%%EOF") {
            if let Some(endstream_idx) = tail[..eof_idx].windows(9).rposition(|w| w == b"endstream") {
                let stream_content_tail = &tail[..endstream_idx];
                let mut stream_end_in_tail = stream_content_tail.len();
                while stream_end_in_tail > 0
                    && (stream_content_tail[stream_end_in_tail - 1] == b'\r'
                        || stream_content_tail[stream_end_in_tail - 1] == b'\n')
                {
                    stream_end_in_tail -= 1;
                }

                if stream_end_in_tail >= 24 {
                    let trailer_bytes = &stream_content_tail[stream_end_in_tail - 24..stream_end_in_tail];
                    if let Ok(trailer) = EnvelopeTrailer::unpack(trailer_bytes, expected_trailer_magic) {
                        let abs_stream_end = (total_size - scan_len) + stream_end_in_tail as u64;
                        if trailer.ube_offset + trailer.ube_total_size == abs_stream_end {
                            if trailer.ube_offset >= 8 {
                                stego_in.seek(SeekFrom::Start(trailer.ube_offset - 8))?;
                                let mut prefix = [0u8; 8];
                                if stego_in.read_exact(&mut prefix).is_ok()
                                    && (prefix.ends_with(b"stream\r\n")
                                        || prefix.ends_with(b"stream\n")
                                        || prefix.ends_with(b"stream"))
                                {
                                    return Ok(Some((
                                        trailer.ube_offset,
                                        trailer.ube_total_size,
                                        "incremental".into(),
                                    )));
                                }
                            }
                        }
                    }
                }
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

    fn verify_structure(
        &self,
        stego_in: &mut dyn SeekRead,
    ) -> Result<(bool, String), StrHideError> {
        match parse_pdf_trailer_info(stego_in) {
            Ok(info) => Ok((
                true,
                format!(
                    "Valid PDF document (%%EOF at {}, prev_startxref at {})",
                    info.eof_offset, info.prev_startxref
                ),
            )),
            Err(e) => Ok((false, format!("Corrupted PDF structure: {e}"))),
        }
    }
}
