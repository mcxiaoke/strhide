//! CLI diagnostic-output tests.
//!
//! The engines report recoverable degradations through the `log` crate, but
//! nothing installed a logger in the CLI builds, so every one of those records
//! was compiled into a no-op. These tests pin the wiring: without `-v` the
//! stderr channel stays quiet, with `-v` engine records appear, and `-q`
//! silences both.

use crate::common::*;
use std::fs;
use std::io::Write;
use std::process::Command;

/// A textured RGB PNG of the requested size.
///
/// Two properties matter here: `common::make_png` is 1×1 and cannot hold an
/// envelope, and a flat white image has zero usable slots (the cost model
/// rejects perfectly uniform pixels), so the bytes are pseudo-random but
/// deterministic.
fn png_rgb(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");

    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    push_chunk(&mut out, b"IHDR", &ihdr);

    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut raw = Vec::with_capacity((1 + width as usize * 3) * height as usize);
    for _ in 0..height {
        raw.extend_from_slice(&[0u8]); // scanline filter: none
        for _ in 0..width {
            let v = next();
            raw.extend_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
        }
    }
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(&raw).unwrap();
    push_chunk(&mut out, b"IDAT", &enc.finish().unwrap());

    push_chunk(&mut out, b"IEND", &[]);
    out
}

fn push_chunk(out: &mut Vec<u8>, kind: &[u8; 4], body: &[u8]) {
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(body);
    let crc = crc32fast::hash(&out[start..]);
    out.extend_from_slice(&crc.to_be_bytes());
}

fn embed_args(carrier: &std::path::Path, out: &std::path::Path) -> Vec<std::ffi::OsString> {
    vec![
        "embed".into(),
        carrier.into(),
        "-t".into(),
        "hello".into(),
        "-o".into(),
        out.into(),
    ]
}

#[test]
fn verbose_flag_is_documented_in_help() {
    let out = Command::new(bin())
        .args(["--help"])
        .output()
        .expect("run sth --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--verbose"), "stdout: {stdout}");
}

#[test]
fn engine_records_reach_stderr_only_with_verbose() {
    let dir = scratch("cli_logging");
    let carrier = dir.join("carrier.png");
    fs::write(&carrier, png_rgb(128, 128)).unwrap();

    let quiet_out = dir.join("quiet.png");
    let quiet = Command::new(bin())
        .env("STRHIDE_LANG", "en")
        .args(embed_args(&carrier, &quiet_out))
        .output()
        .expect("run embed");
    assert!(quiet.status.success(), "embed failed: {quiet:?}");
    let quiet_stderr = String::from_utf8_lossy(&quiet.stderr);
    assert!(
        !quiet_stderr.contains("[INFO]"),
        "default run must not print engine info records: {quiet_stderr}"
    );

    let verbose_out = dir.join("verbose.png");
    let verbose = Command::new(bin())
        .env("STRHIDE_LANG", "en")
        .arg("-v")
        .args(embed_args(&carrier, &verbose_out))
        .output()
        .expect("run embed -v");
    assert!(verbose.status.success(), "embed -v failed: {verbose:?}");
    let verbose_stderr = String::from_utf8_lossy(&verbose.stderr);
    assert!(
        verbose_stderr.contains("[INFO] [stego::png]"),
        "-v must surface engine records: {verbose_stderr}"
    );
    // Diagnostics go to stderr; stdout keeps the normal report.
    let verbose_stdout = String::from_utf8_lossy(&verbose.stdout);
    assert!(
        !verbose_stdout.contains("[INFO]"),
        "stdout must stay free of log records: {verbose_stdout}"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn quiet_wins_over_verbose() {
    let dir = scratch("cli_logging_quiet");
    let carrier = dir.join("carrier.png");
    fs::write(&carrier, png_rgb(128, 128)).unwrap();
    let out_path = dir.join("out.png");

    let out = Command::new(bin())
        .env("STRHIDE_LANG", "en")
        .args(["-q", "-v"])
        .args(embed_args(&carrier, &out_path))
        .output()
        .expect("run embed -q -v");
    assert!(out.status.success(), "embed failed: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.is_empty(), "-q must silence diagnostics: {stderr}");

    let _ = fs::remove_dir_all(&dir);
}
