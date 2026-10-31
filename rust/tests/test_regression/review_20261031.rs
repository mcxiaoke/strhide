// Regression tests for the third-round review (docs/CODE-REVIEW-R3-20261031.md).
//
// The cases here are the findings that survived re-verification against the
// source: a slice panic reachable from an 86-byte archive, and a cancel marker
// that made `write_all` spin instead of returning.

use std::io::{Cursor, ErrorKind, Write};
use std::sync::mpsc;
use std::time::Duration;

use strhide::core::control::{CancelToken, Control, ProgressWriter, Stage};
use strhide::structure::rejection::check_jar_signature;

/// `PK\x03\x04` + 60 filler bytes + an EOCD whose `cd_size` is smaller than the
/// 4-byte central-directory magic.
///
/// `check_jar_signature` only filtered `cd_size == 0` and then sliced
/// `cd_buf[0..4]`, so a 1-to-3-byte central directory panicked. Release builds
/// use `panic = "abort"`, so the whole process died before anything was written
/// (review R3 P0-1).
fn jar_with_tiny_central_directory(cd_size: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&[0u8; 60]);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes()); // disk number
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with CD
    out.extend_from_slice(&0u16.to_le_bytes()); // entries on this disk
    out.extend_from_slice(&0u16.to_le_bytes()); // entries total
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // cd_offset
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    out
}

#[test]
fn jar_signature_check_survives_short_central_directory() {
    for cd_size in 0..=4u32 {
        let data = jar_with_tiny_central_directory(cd_size);
        assert_eq!(data.len(), 86, "fixture shape must match the review");
        let mut cur = Cursor::new(data);
        let found = check_jar_signature(&mut cur, Some("tiny.zip"))
            .expect("a short central directory is not an I/O error");
        assert!(
            found.is_none(),
            "cd_size={cd_size} must not invent a signature"
        );
        assert_eq!(
            cur.position(),
            0,
            "the check must restore the reader position"
        );
    }
}

/// A cancelled `ProgressWriter` must fail fast.
///
/// It used to answer `ErrorKind::Interrupted`, which `Write::write_all` retries
/// with a bare `continue`: the write stage spun at 100% CPU forever and
/// `map_io_cancel` never saw an error (review R3 P1-5). The write runs on a
/// worker thread so a regression fails the test instead of hanging the suite.
#[test]
fn cancelled_writer_fails_instead_of_spinning() {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let token = CancelToken::new();
        token.cancel();
        let mut sink: Vec<u8> = Vec::new();
        let result = {
            let control = Control::with_cancel(&token);
            let mut writer = ProgressWriter::new(&mut sink, control, Stage::Write, 16);
            writer.write_all(&[0xAB; 16]).map_err(|e| e.kind())
        };
        let _ = tx.send(result);
        assert!(sink.is_empty(), "a cancelled write must not reach the sink");
    });

    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(Ok(())) => panic!("write_all on a cancelled writer must fail"),
        Ok(Err(kind)) => assert_ne!(
            kind,
            ErrorKind::Interrupted,
            "Interrupted is retried by write_all and produces a spin"
        ),
        Err(_) => panic!("write_all did not return: the cancel marker spins"),
    }
}

/// Deleting the last 12 bytes of a PNG and appending a payload used to produce
/// a completely clean scan: the chunk walk never reached IEND, the whole-file
/// branch said nothing, the entropy detector exempts PNG, and the metric still
/// claimed "0 bytes / clean termination at IEND" (review R3 P1-2).
#[cfg(feature = "analysis")]
#[test]
fn scan_flags_a_png_without_iend() {
    let mut data = crate::common::make_png();
    assert!(data.ends_with(b"IEND\xaeB`\x82"));
    data.truncate(data.len() - 12);
    data.extend_from_slice(b"\xff\xff\xff\x7fappended-payload");

    let report = strhide::analysis::scan_bytes(&data, "noiend.png");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.detector == "png:trailing-data"),
        "a PNG whose terminator is gone must produce a finding"
    );
    assert_ne!(report.verdict, "clean", "verdict: {}", report.verdict);

    let metric = report
        .detectors
        .iter()
        .find(|d| d.name == "png:trailing-data")
        .expect("trailing-data metric must be reported");
    assert_eq!(metric.status, "ALERT");
    assert!(
        !metric.detail.contains("clean termination"),
        "detail still claims a clean IEND: {}",
        metric.detail
    );
}

/// A carrier without IEND cannot be re-encoded byte-for-byte, so the content
/// domain refuses it instead of silently dropping everything it could not read
/// as a chunk (review R3 P2-11).
#[cfg(feature = "cli")]
#[test]
fn content_domain_refuses_a_png_without_iend() {
    let dir = crate::common::scratch("r3_noiend_capacity");
    let carrier = dir.join("noiend.png");
    let mut data = crate::common::make_png();
    data.truncate(data.len() - 12);
    std::fs::write(&carrier, &data).unwrap();

    let out = crate::common::base_cmd()
        .args(["capacity", carrier.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success(), "a PNG without IEND must be refused");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("IEND"),
        "the error must name the missing chunk, stderr: {stderr}"
    );
}

/// A 204-byte MP4 whose trailer claims a 1 TiB envelope and whose header claims
/// a ~4 GiB metadata block.
///
/// `isobmff_locate` compared the envelope only with its own box size, so this
/// was accepted as "hidden data present" and `read` allocated the metadata
/// buffer before the short stream was noticed. The other adapters already
/// bounded the envelope against the real file length (review R3 P2-17/P2-18).
#[cfg(feature = "cli")]
fn mp4_with_forged_trailer() -> Vec<u8> {
    const MAGIC: [u8; 4] = [0x78, 0xe6, 0x66, 0xd2];
    const UUID: [u8; 16] = [
        0xd4, 0x1a, 0x8e, 0x9c, 0x4f, 0x21, 0x4e, 0x87, 0x9a, 0x33, 0x5b, 0x6d, 0x12, 0x84, 0xef,
        0x70,
    ];
    let total: u64 = 1 << 40;

    let mut host = Vec::new();
    host.extend_from_slice(&24u32.to_be_bytes());
    host.extend_from_slice(b"ftypmp42");
    host.extend_from_slice(&0u32.to_be_bytes());
    host.extend_from_slice(b"mp42");
    host.extend_from_slice(&[0u8; 16]);

    let envelope_offset = (host.len() + 32) as u64;
    let mut box_header = Vec::new();
    box_header.extend_from_slice(&1u32.to_be_bytes()); // 64-bit size follows
    box_header.extend_from_slice(b"uuid");
    box_header.extend_from_slice(&(32 + total).to_be_bytes());
    box_header.extend_from_slice(&UUID);

    let mut header = [0u8; 112];
    header[0..8].copy_from_slice(b"STRHIDE\0");
    header[8] = 0x02; // CURRENT_VERSION
    header[10] = 3; // strategy: box_uuid
    header[40..48].copy_from_slice(&40u64.to_le_bytes());
    header[80..88].copy_from_slice(&envelope_offset.to_le_bytes());
    header[88..96].copy_from_slice(&total.to_le_bytes());
    header[104..108].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes()); // meta_len

    let mut trailer = Vec::new();
    trailer.extend_from_slice(&envelope_offset.to_le_bytes());
    trailer.extend_from_slice(&total.to_le_bytes());
    let crc = crc32fast::hash(&trailer);
    trailer.extend_from_slice(&crc.to_le_bytes());
    trailer.extend_from_slice(&MAGIC);

    [host, box_header, header.to_vec(), trailer].concat()
}

#[cfg(feature = "cli")]
#[test]
fn isobmff_rejects_an_envelope_larger_than_the_file() {
    let dir = crate::common::scratch("r3_isobmff_bounds");
    let carrier = dir.join("forged.mp4");
    std::fs::write(&carrier, mp4_with_forged_trailer()).unwrap();

    let out = crate::common::base_cmd()
        .args(["inspect", carrier.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("Has Hidden Data: true"),
        "a forged 1 TiB trailer must not be adopted as an envelope:\n{stdout}"
    );
    assert!(
        stdout.contains("Has Hidden Data: false"),
        "inspect should report no hidden data:\n{stdout}"
    );
}

/// Same blind spot as the PNG `IEND` case above, in the JPEG marker walk: a
/// whole-file view that never reaches `EOI` reported nothing at all, the
/// entropy detector exempts JPEG, and the metric still claimed "0 bytes /
/// clean termination at EOI". Deleting the trailing `FF D9` and appending a
/// payload therefore scanned clean (review R4 P1-7).
#[cfg(feature = "analysis")]
#[test]
fn scan_flags_a_jpeg_without_eoi() {
    let mut data = crate::common::make_jpeg();
    assert!(data.ends_with(b"\xff\xd9"));
    data.truncate(data.len() - 2);
    data.extend_from_slice(b"\xff\xff\xff\x7fappended-payload");

    let report = strhide::analysis::scan_bytes(&data, "noeoi.jpg");
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.detector == "jpeg:trailing-data"),
        "a JPEG whose terminator is gone must produce a finding: {:?}",
        report.findings
    );
    assert_ne!(report.verdict, "clean", "verdict: {}", report.verdict);

    let metric = report
        .detectors
        .iter()
        .find(|d| d.name == "jpeg:trailing-data")
        .expect("trailing-data metric must be reported");
    assert_eq!(metric.status, "ALERT");
    assert!(
        !metric.detail.contains("clean termination"),
        "detail still claims a clean EOI: {}",
        metric.detail
    );

    // A clean JPEG must stay clean: no finding, PASS, "0 bytes".
    let clean = strhide::analysis::scan_bytes(&crate::common::make_jpeg(), "clean.jpg");
    assert!(
        !clean
            .findings
            .iter()
            .any(|f| f.detector == "jpeg:trailing-data"),
        "a well-formed JPEG must not be flagged: {:?}",
        clean.findings
    );
    let metric = clean
        .detectors
        .iter()
        .find(|d| d.name == "jpeg:trailing-data")
        .expect("metric present");
    assert_eq!(metric.status, "PASS");
    assert_eq!(metric.metric, "0 bytes");
}
