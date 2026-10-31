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
