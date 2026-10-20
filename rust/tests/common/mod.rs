//! Common test helpers, fixtures, and scratch directory management for strhide integration tests.

#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::path::PathBuf;

pub fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_strhide")
}

pub fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "strhide_test_{}_{}_{}",
        std::process::id(),
        name,
        rand::random::<u32>()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Minimal valid 1x1 PNG (IHDR + IDAT + IEND, CRCs valid).
pub fn make_png() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let ihdr_data: [u8; 13] = [1, 0, 0, 0, 1, 0, 0, 0, 8, 2, 0, 0, 0];
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(ihdr_data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"IHDR");
    chunk.extend_from_slice(&ihdr_data);
    let crc = crc32fast::hash(&chunk[4..]);
    chunk.extend_from_slice(&crc.to_be_bytes());
    out.extend_from_slice(&chunk);

    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(b"\x00\xff\x00\x00").unwrap();
    let idat_data = enc.finish().unwrap();
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(idat_data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"IDAT");
    chunk.extend_from_slice(&idat_data);
    let crc = crc32fast::hash(&chunk[4..]);
    chunk.extend_from_slice(&crc.to_be_bytes());
    out.extend_from_slice(&chunk);

    out.extend_from_slice(b"\x00\x00\x00\x00IEND\xaeB`\x82");
    out
}

/// Minimal JPEG: SOI, JFIF APP0, DQT, SOF0, SOS, entropy data, EOI.
pub fn make_jpeg() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\xff\xd8");
    let app0 = b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0";
    out.extend_from_slice(b"\xff\xe0");
    out.extend_from_slice(&(2u16 + app0.len() as u16).to_be_bytes());
    out.extend_from_slice(app0);
    out.extend_from_slice(b"\xff\xdb\x00\x43\x00");
    out.extend_from_slice(&[16u8; 64]);
    out.extend_from_slice(b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00");
    out.extend_from_slice(b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00");
    out.extend_from_slice(&[0x12u8; 32]);
    out.extend_from_slice(b"\xff\xd9");
    out
}

/// Minimal ISO BMFF: `ftyp` followed by a `mdat` box.
pub fn make_mp4() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&24u32.to_be_bytes());
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(b"isom");
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(b"isomiso2");
    v.extend_from_slice(&(8u32 + 64).to_be_bytes());
    v.extend_from_slice(b"mdat");
    v.extend_from_slice(&[0xAAu8; 64]);
    v
}

/// Minimal HEIF: ftyp box with 'heic' major brand followed by a 'free' box.
pub fn make_heif() -> Vec<u8> {
    let mut out = Vec::new();
    let ftyp = b"heic\0\0\0\0mif1heic";
    out.extend_from_slice(&(8u32 + ftyp.len() as u32).to_be_bytes());
    out.extend_from_slice(b"ftyp");
    out.extend_from_slice(ftyp);
    out.extend_from_slice(&8u32.to_be_bytes());
    out.extend_from_slice(b"free");
    out
}

/// Minimal valid WebP: RIFF header with 'WEBP' and a minimal 'VP8 ' chunk.
pub fn make_webp() -> Vec<u8> {
    let mut out = Vec::new();
    let vp8_data = b"\x00\x00\x00\x9d\x01\x2a\x01\x00\x01\x00";
    let file_size = 12 + 8 + vp8_data.len();
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((file_size - 8) as u32).to_le_bytes());
    out.extend_from_slice(b"WEBP");
    out.extend_from_slice(b"VP8 ");
    out.extend_from_slice(&(vp8_data.len() as u32).to_le_bytes());
    out.extend_from_slice(vp8_data);
    out
}

/// Minimal valid WAV: RIFF header with 'WAVE', 'fmt ' chunk, and 'data' chunk.
pub fn make_wav() -> Vec<u8> {
    let mut out = Vec::new();
    let mut fmt_chunk = Vec::new();
    fmt_chunk.extend_from_slice(&1u16.to_le_bytes()); // PCM
    fmt_chunk.extend_from_slice(&1u16.to_le_bytes()); // 1 channel
    fmt_chunk.extend_from_slice(&8000u32.to_le_bytes()); // 8000 Hz
    fmt_chunk.extend_from_slice(&16000u32.to_le_bytes()); // 16000 bytes/sec
    fmt_chunk.extend_from_slice(&2u16.to_le_bytes()); // block align 2
    fmt_chunk.extend_from_slice(&16u16.to_le_bytes()); // 16 bits per sample

    let data_chunk = vec![0u8; 16];
    let file_size = 12 + (8 + fmt_chunk.len()) + (8 + data_chunk.len());

    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&((file_size - 8) as u32).to_le_bytes());
    out.extend_from_slice(b"WAVE");
    out.extend_from_slice(b"fmt ");
    out.extend_from_slice(&(fmt_chunk.len() as u32).to_le_bytes());
    out.extend_from_slice(&fmt_chunk);
    out.extend_from_slice(b"data");
    out.extend_from_slice(&(data_chunk.len() as u32).to_le_bytes());
    out.extend_from_slice(&data_chunk);
    out
}

/// Minimal valid Matroska (MKV): EBML header + Segment element.
pub fn make_mkv() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x1A\x45\xDF\xA3\x8F\x42\x86\x81\x01\x42\x82\x88matroska");
    out.extend_from_slice(b"\x18\x53\x80\x67\x80");
    out
}

/// Minimal stored-entry ZIP.
pub fn make_zip() -> Vec<u8> {
    make_zip_with_entries(&[("hello.txt", b"hello in zip payload")])
}

/// Build a minimal ZIP containing the specified entries (stored, uncompressed).
pub fn make_zip_with_entries(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();

    for (name, data) in entries {
        let crc = crc32fast::hash(data);
        let local_off = out.len() as u32;

        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        cd.extend_from_slice(b"PK\x01\x02");
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes());
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&local_off.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }

    let cd_off = out.len() as u32;
    let cd_size = cd.len() as u32;
    out.extend_from_slice(&cd);

    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

pub fn make_zip_with_fake_eocd_comment() -> Vec<u8> {
    let mut zip = make_zip();
    let fake_comment = b"Some comment ending with fake PK\x05\x06\x00\x00\x00\x00\x01\x00\x01\x00\x20\x00\x00\x00\x10\x00\x00\x00\x00\x00";
    let comment_len = fake_comment.len() as u16;
    let len = zip.len();
    zip[len - 2..len].copy_from_slice(&comment_len.to_le_bytes());
    zip.extend_from_slice(fake_comment);
    zip
}

/// Minimal PDF 1.4 with a classic xref table and a `/Root` trailer entry.
pub fn make_pdf() -> Vec<u8> {
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
      xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
      trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
        .to_vec()
}

pub fn make_pdf_with_dirty_tail() -> Vec<u8> {
    let mut pdf = make_pdf();
    pdf.extend_from_slice(b"GARBAGE_APPENDED_TO_END");
    pdf
}

pub fn make_pdf_without_root() -> Vec<u8> {
    b"%PDF-1.4\n1 0 obj\n<< /Type /Info >>\nendobj\n\
      xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
      trailer\n<< /Size 2 >>\nstartxref\n9\n%%EOF\n"
        .to_vec()
}

pub const TEXT_PATTERN: &[u8] = &[
    0x89, 0xD8, 0x89, 0xCA, 0x8B, 0xD1, 0x89, 0x18, 0x85, 0xC3, 0x85, 0xD8, 0x85, 0xC0, 0x01, 0xD8,
    0x3B, 0xC3, 0x90, 0x90, 0x48, 0x89, 0x00,
];

/// Minimal PE64 with a `.text` of instrumentable instructions.
pub fn make_pe(text_len: usize) -> Vec<u8> {
    make_pe_custom(0x8664, 0x20B, text_len, false)
}

pub fn make_pe_custom(machine: u16, opt_magic: u16, text_len: usize, tight: bool) -> Vec<u8> {
    let opt_size: u16 = if opt_magic == 0x20B { 240 } else { 224 };
    let e_lfanew: u32 = 0x80;
    let sec_table = e_lfanew as usize + 24 + opt_size as usize;
    let sec_table_end = sec_table + 40;
    let raw_ptr: u32 = if tight { sec_table_end as u32 } else { 0x400 };
    let raw_size = if tight {
        text_len as u32
    } else {
        (text_len as u32).div_ceil(0x200) * 0x200
    };

    let mut img = vec![0u8; raw_ptr as usize];
    img[0..2].copy_from_slice(b"MZ");
    img[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
    img[0x80..0x84].copy_from_slice(b"PE\0\0");
    img[0x84..0x86].copy_from_slice(&machine.to_le_bytes());
    img[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    img[0x94..0x96].copy_from_slice(&opt_size.to_le_bytes());
    img[0x96..0x98].copy_from_slice(&0x0022u16.to_le_bytes());
    let opt = 0x98;
    img[opt..opt + 2].copy_from_slice(&opt_magic.to_le_bytes());

    let sec = sec_table;
    img[sec..sec + 8].copy_from_slice(b".text\0\0\0");
    img[sec + 8..sec + 12].copy_from_slice(&(text_len as u32).to_le_bytes());
    img[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    img[sec + 16..sec + 20].copy_from_slice(&raw_size.to_le_bytes());
    img[sec + 20..sec + 24].copy_from_slice(&raw_ptr.to_le_bytes());
    img[sec + 36..sec + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    let mut text = Vec::with_capacity(text_len);
    while text.len() < text_len {
        text.extend_from_slice(TEXT_PATTERN);
    }
    text.truncate(text_len);
    img.extend_from_slice(&text);
    img.resize(raw_ptr as usize + raw_size as usize, 0);
    img
}
