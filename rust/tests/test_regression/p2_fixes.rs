// Regression tests for P2 engineering-quality fixes (2026-10-17).
//
// Batch 1:
// - #10: adapter inject must propagate I/O errors instead of silently
//   treating a failed read as EOF (which produced truncated envelopes).
// - #23: MP4/PNG `verify_structure` must walk the full container (box tree /
//   all chunks with CRC verification), not just the first box or the tail
//   IEND. Mirrors the Python adapter behavior.

use crate::common::*;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};

use strhide::adapters::HostAdapter;
use strhide::adapters::jpeg::JpegAdapter;
use strhide::adapters::mp4::Mp4Adapter;
use strhide::adapters::pdf::PdfAdapter;
use strhide::adapters::pe::PeAdapter;
use strhide::adapters::png::PngAdapter;
use strhide::adapters::zip::ZipAdapter;
use strhide::engine::{PayloadSource, WriteOptions, verify_carrier, write_carrier};

// --------------------------------------------------------------------------- helpers

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
        Self {
            data,
            pos: 0,
            fail_after,
        }
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
    assert_inject_propagates_ube_read_error("io_pe", make_pe(64), |h, u, o| {
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
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
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
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
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

#[test]
fn test_verify_payload_stream_limit_rejection() {
    let payload = b"hello streaming verification world";
    let key = [0x42u8; 32];
    let nonce = [0x11u8; 12];
    let aad = [0xaau8; 80];

    let mut cipher = Vec::new();
    let cipher_len = strhide::crypto::encrypt_stream_to_chunks(
        &mut std::io::Cursor::new(payload),
        &mut cipher,
        &key,
        &nonce,
        &aad,
        4096,
    )
    .unwrap();

    let sha = strhide::crypto::compute_sha256(payload);
    let sha_str = sha.iter().map(|b| format!("{b:02x}")).collect::<String>();

    // Normal verification under ample limit succeeds
    let verified_len = strhide::crypto::verify_payload_stream(
        &mut std::io::Cursor::new(&cipher),
        &key,
        &nonce,
        &aad,
        cipher_len,
        false,
        payload.len() as u64,
        &sha_str,
        1024,
    )
    .expect("verify succeeds within limit");
    assert_eq!(verified_len, payload.len() as u64);

    // Limit exceeded: declared raw size > limit rejects immediately
    let err = strhide::crypto::verify_payload_stream(
        &mut std::io::Cursor::new(&cipher),
        &key,
        &nonce,
        &aad,
        cipher_len,
        false,
        payload.len() as u64,
        &sha_str,
        payload.len() as u64 - 1,
    )
    .unwrap_err();
    assert!(err.to_string().contains("exceeds verification limit"));
}

#[test]
fn test_commit_carrier_bytes_atomic_and_backup() {
    let dir = scratch("commit_carrier");
    let carrier = dir.join("carrier.png");
    let target = dir.join("carrier.png"); // in-place
    fs::write(&carrier, make_png()).unwrap();

    let stego_bytes = b"new stego content";
    let bak1 = strhide::engine::commit_carrier_bytes(&carrier, &target, stego_bytes, true, true)
        .unwrap()
        .expect("in-place backup created");

    assert!(bak1.exists());
    assert_eq!(fs::read(&bak1).unwrap(), make_png());
    assert_eq!(fs::read(&target).unwrap(), stego_bytes);

    // Second commit: backup must not overwrite existing bak1
    let bak2 =
        strhide::engine::commit_carrier_bytes(&carrier, &target, b"another round", true, true)
            .unwrap()
            .expect("second backup created");

    assert!(bak2.exists());
    assert_ne!(bak1, bak2);
    assert_eq!(fs::read(&bak1).unwrap(), make_png());
    assert_eq!(fs::read(&bak2).unwrap(), stego_bytes);
}
