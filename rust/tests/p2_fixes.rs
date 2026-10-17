//! Regression tests for P2 engineering-quality fixes (2026-10-17).
//!
//! Batch 1:
//! - #10: adapter inject must propagate I/O errors instead of silently
//!   treating a failed read as EOF (which produced truncated envelopes).
//! - #23: MP4/PNG `verify_structure` must walk the full container (box tree /
//!   all chunks with CRC verification), not just the first box or the tail
//!   IEND. Mirrors the Python adapter behavior.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use strhide::adapters::jpeg::JpegAdapter;
use strhide::adapters::mp4::Mp4Adapter;
use strhide::adapters::pdf::PdfAdapter;
use strhide::adapters::pe::PeAdapter;
use strhide::adapters::png::PngAdapter;
use strhide::adapters::zip::ZipAdapter;
use strhide::adapters::HostAdapter;
use strhide::engine::{verify_carrier, write_carrier, PayloadSource};

// --------------------------------------------------------------------------- helpers

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_p2_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn make_png() -> Vec<u8> {
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
    out.extend_from_slice(b"\x00\x00\x00\x00IEND\xaeB`\x82");
    out
}

fn make_jpeg() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"\xff\xd8");
    let app0_data = b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00";
    v.extend_from_slice(b"\xff\xe0");
    v.extend_from_slice(&(2u16 + app0_data.len() as u16).to_be_bytes());
    v.extend_from_slice(app0_data);
    v.extend_from_slice(b"\xff\xda");
    v.extend_from_slice(&3u16.to_be_bytes());
    v.extend_from_slice(&[1u8]);
    v.extend_from_slice(&[0u8; 16]);
    v.extend_from_slice(b"\xff\xd9");
    v
}

fn make_zip() -> Vec<u8> {
    let name = b"hello.txt";
    let data: Vec<u8> = b"hello world".repeat(20);
    let crc = crc32fast::hash(&data);
    let mut out = Vec::new();
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
    out.extend_from_slice(name);
    out.extend_from_slice(&data);

    let cd_offset = out.len() as u32;
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(&20u16.to_le_bytes());
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
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name);
    let cd_size = out.len() as u32 - cd_offset;

    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// Minimal ISO BMFF file: one ftyp box plus a trailing free box.
fn make_mp4() -> Vec<u8> {
    let mut v = Vec::new();
    let ftyp_body = b"isom\x00\x00\x02\x00isom";
    v.extend_from_slice(&(8u32 + ftyp_body.len() as u32).to_be_bytes());
    v.extend_from_slice(b"ftyp");
    v.extend_from_slice(ftyp_body);
    v.extend_from_slice(&8u32.to_be_bytes());
    v.extend_from_slice(b"free");
    v
}

/// Minimal PE32 image: MZ stub, PE signature, COFF + 2-byte optional header,
/// one section whose raw data ends at 0x300, padded to 0x400.
fn make_pe() -> Vec<u8> {
    let mut v = vec![0u8; 0x40];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    v.extend_from_slice(b"PE\x00\x00");
    v.extend_from_slice(&0x014Cu16.to_le_bytes()); // machine: i386
    v.extend_from_slice(&1u16.to_le_bytes()); // number of sections
    v.extend_from_slice(&0u32.to_le_bytes()); // timestamp
    v.extend_from_slice(&0u32.to_le_bytes()); // symbol table ptr
    v.extend_from_slice(&0u32.to_le_bytes()); // symbol count
    v.extend_from_slice(&2u16.to_le_bytes()); // optional header size
    v.extend_from_slice(&0x0102u16.to_le_bytes()); // characteristics
    v.extend_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    let mut sec = [0u8; 40];
    sec[0..5].copy_from_slice(b".text");
    sec[8..12].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
    sec[12..16].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual address
    sec[16..20].copy_from_slice(&0x100u32.to_le_bytes()); // size of raw data
    sec[20..24].copy_from_slice(&0x200u32.to_le_bytes()); // pointer to raw data
    v.extend_from_slice(&sec);
    v.resize(0x400, 0);
    v
}

fn make_pdf() -> Vec<u8> {
    b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n\
      xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \n\
      trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n9\n%%EOF\n"
        .to_vec()
}

/// A `Read + Seek` source that yields `fail_after` bytes and then fails with
/// an I/O error. The pre-fix `while let Ok(n) = read(..)` loops treated this
/// failure as EOF and silently produced a truncated envelope.
struct FailingReader {
    data: Vec<u8>,
    pos: u64,
    fail_after: u64,
}

impl FailingReader {
    fn new(data: Vec<u8>, fail_after: u64) -> Self {
        Self { data, pos: 0, fail_after }
    }
}

impl Read for FailingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.fail_after {
            return Err(io::Error::other("injected read failure"));
        }
        let avail = (self.data.len() as u64 - self.pos).min(self.fail_after - self.pos);
        if avail == 0 {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(avail) as usize;
        buf[..n].copy_from_slice(&self.data[self.pos as usize..self.pos as usize + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for FailingReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let new_pos = match from {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::Current(d) => self.pos as i64 + d,
            SeekFrom::End(d) => self.data.len() as i64 + d,
        };
        if new_pos < 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "negative seek"));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

/// Every format adapter's inject must surface the UBE read error instead of
/// stopping at the bytes read so far.
fn assert_inject_propagates_ube_read_error(
    name: &str,
    host: Vec<u8>,
    inject: impl Fn(
        &mut dyn strhide::adapters::SeekRead,
        &mut dyn strhide::adapters::SeekRead,
        &mut dyn Write,
    ) -> Result<(), strhide::errors::StrHideError>,
) {
    let dir = scratch(name);
    let host_path = dir.join("host.bin");
    fs::write(&host_path, &host).unwrap();
    let ube: Vec<u8> = vec![0x5Au8; 4096];

    let mut host_in = fs::File::open(&host_path).unwrap();
    let mut ube_in = FailingReader::new(ube, 1024);
    let mut out = Vec::new();
    let err = inject(&mut host_in, &mut ube_in, &mut out).unwrap_err();
    assert!(
        err.to_string().contains("injected read failure"),
        "{name}: error was silently swallowed: {err}"
    );
}

// --------------------------------------------------------------------------- #10: I/O error propagation

#[test]
fn inject_propagates_ube_read_errors_png() {
    assert_inject_propagates_ube_read_error("io_png", make_png(), |h, u, o| {
        PngAdapter.inject(h, u, o, "chunk").map(|_| ())
    });
}

#[test]
fn inject_propagates_ube_read_errors_jpeg() {
    assert_inject_propagates_ube_read_error("io_jpeg", make_jpeg(), |h, u, o| {
        JpegAdapter.inject(h, u, o, "app_segment").map(|_| ())
    });
}

#[test]
fn inject_propagates_ube_read_errors_zip() {
    assert_inject_propagates_ube_read_error("io_zip", make_zip(), |h, u, o| {
        ZipAdapter.inject(h, u, o, "pre_cd_inject").map(|_| ())
    });
}

#[test]
fn inject_propagates_ube_read_errors_mp4() {
    assert_inject_propagates_ube_read_error("io_mp4", make_mp4(), |h, u, o| {
        Mp4Adapter.inject(h, u, o, "box_uuid").map(|_| ())
    });
}

#[test]
fn inject_propagates_ube_read_errors_pe() {
    assert_inject_propagates_ube_read_error("io_pe", make_pe(), |h, u, o| {
        PeAdapter.inject(h, u, o, "pe_overlay").map(|_| ())
    });
}

#[test]
fn inject_propagates_ube_read_errors_pdf() {
    assert_inject_propagates_ube_read_error("io_pdf", make_pdf(), |h, u, o| {
        PdfAdapter.inject(h, u, o, "incremental").map(|_| ())
    });
}

// --------------------------------------------------------------------------- #23: PNG verify depth

#[test]
fn png_verify_detects_corrupted_chunk_crc() {
    let dir = scratch("png_crc");
    let carrier = dir.join("c.png");
    let mut png = make_png();
    // Flip a byte inside the IHDR chunk data (data starts at offset 16).
    png[16] ^= 0xFF;
    fs::write(&carrier, &png).unwrap();

    let res = verify_carrier(&carrier, None).unwrap();
    assert!(!res.level1_host.ok, "corrupted CRC passed Level 1");
    assert!(
        res.level1_host.detail.contains("CRC32 mismatch"),
        "unexpected detail: {}",
        res.level1_host.detail
    );
}

#[test]
fn png_verify_detects_missing_iend() {
    let dir = scratch("png_iend");
    let carrier = dir.join("c.png");
    // Magic + IHDR chunk, no IEND.
    let mut png = make_png();
    png.truncate(png.len() - 12);
    fs::write(&carrier, &png).unwrap();

    let res = verify_carrier(&carrier, None).unwrap();
    assert!(!res.level1_host.ok, "PNG without IEND passed Level 1");
}

#[test]
fn png_verify_accepts_valid_carrier_with_envelope() {
    let dir = scratch("png_ok");
    let carrier = dir.join("c.png");
    let out = dir.join("o.png");
    fs::write(&carrier, make_png()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("batch1 png"),
        Some(&out),
        None,
        None,
        "auto",
        false,
        true,
        false,
    )
    .unwrap();

    let res = verify_carrier(&out, None).unwrap();
    assert!(res.level1_host.ok, "{}", res.level1_host.detail);
    assert!(
        res.level1_host.detail.contains("private chunk 'prIv'"),
        "unexpected detail: {}",
        res.level1_host.detail
    );
}

// --------------------------------------------------------------------------- #23: MP4 verify depth

#[test]
fn mp4_verify_detects_invalid_box_size() {
    let dir = scratch("mp4_size");
    let carrier = dir.join("c.mp4");
    // ftyp box declaring size 2 (< the 8-byte header).
    let mut mp4 = Vec::new();
    mp4.extend_from_slice(&2u32.to_be_bytes());
    mp4.extend_from_slice(b"ftyp");
    mp4.extend_from_slice(&[0u8; 16]);
    fs::write(&carrier, &mp4).unwrap();

    let res = verify_carrier(&carrier, None).unwrap();
    assert!(!res.level1_host.ok, "invalid box size passed Level 1");
    assert!(
        res.level1_host.detail.contains("Invalid box size"),
        "unexpected detail: {}",
        res.level1_host.detail
    );
}

#[test]
fn mp4_verify_detects_box_past_eof() {
    let dir = scratch("mp4_eof");
    let carrier = dir.join("c.mp4");
    let mut mp4 = make_mp4();
    // Inflate the ftyp box size far beyond the file length.
    mp4[0..4].copy_from_slice(&0x10000u32.to_be_bytes());
    fs::write(&carrier, &mp4).unwrap();

    let res = verify_carrier(&carrier, None).unwrap();
    assert!(!res.level1_host.ok, "box past EOF passed Level 1");
    assert!(
        res.level1_host.detail.contains("past end of file"),
        "unexpected detail: {}",
        res.level1_host.detail
    );
}

#[test]
fn mp4_verify_detects_missing_ftyp() {
    let dir = scratch("mp4_ftyp");
    let carrier = dir.join("c.mp4");
    // First box is moov (still detected as ISO BMFF, but not a valid file).
    let mut mp4 = Vec::new();
    mp4.extend_from_slice(&8u32.to_be_bytes());
    mp4.extend_from_slice(b"moov");
    mp4.extend_from_slice(&8u32.to_be_bytes());
    mp4.extend_from_slice(b"free");
    fs::write(&carrier, &mp4).unwrap();

    let res = verify_carrier(&carrier, None).unwrap();
    assert!(!res.level1_host.ok, "MP4 without ftyp passed Level 1");
    assert!(
        res.level1_host.detail.contains("missing ftyp"),
        "unexpected detail: {}",
        res.level1_host.detail
    );
}

#[test]
fn mp4_verify_accepts_valid_carrier_with_envelope() {
    let dir = scratch("mp4_ok");
    let carrier = dir.join("c.mp4");
    let out = dir.join("o.mp4");
    fs::write(&carrier, make_mp4()).unwrap();
    write_carrier(
        &carrier,
        PayloadSource::Text("batch1 mp4"),
        Some(&out),
        None,
        None,
        "auto",
        false,
        true,
        false,
    )
    .unwrap();

    let res = verify_carrier(&out, None).unwrap();
    assert!(res.level1_host.ok, "{}", res.level1_host.detail);
    assert!(
        res.level1_host.detail.contains("top-level boxes"),
        "unexpected detail: {}",
        res.level1_host.detail
    );
}
