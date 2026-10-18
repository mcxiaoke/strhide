//! Multi-carrier (`-c a.png b.png ...`) behavior for `write` and `remove`.
//!
//! Covered here: the same payload reaching every carrier, `--stdin` being read
//! exactly once, `-d` payload filename retention per carrier, the `-o` batch
//! directory rule, preflight refusal that leaves every carrier untouched, the
//! per-run `[SUMMARY]` line, and byte-exact batch restore.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

// --------------------------------------------------------------------------- helpers

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_batch_{}_{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_strhide")
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

/// Seed `dir` with identical minimal PNG carriers.
fn seed(dir: &Path, names: &[&str]) {
    for name in names {
        fs::write(dir.join(name), make_png()).unwrap();
    }
}

/// Run the binary inside `dir`, isolated from the caller's config file and
/// payload environment variables.
fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("USERPROFILE", dir)
        .env("HOME", dir)
        .env("STRHIDE_PASSWORD", "")
        .env_remove("STRHIDE_TEXT")
        .output()
        .expect("failed to run strhide binary")
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn payload(dir: &Path, carrier: &str) -> String {
    let out = run(dir, &["read", "-c", carrier, "--stdout"]);
    assert_eq!(code(&out), 0, "read {carrier} failed: {}", stderr(&out));
    stdout(&out)
}

// --------------------------------------------------------------------------- write

#[test]
fn batch_write_embeds_the_same_payload_into_every_carrier() {
    let dir = scratch("same_payload");
    seed(&dir, &["a.png", "b.png", "c.png"]);

    let out = run(
        &dir,
        &[
            "write",
            "-c",
            "a.png",
            "b.png",
            "c.png",
            "-t",
            "shared secret",
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("[SUMMARY] 3/3 carriers succeeded."),
        "stdout: {}",
        stdout(&out)
    );

    for name in ["a.png", "b.png", "c.png"] {
        assert_eq!(payload(&dir, name), "shared secret", "{name} payload");
        assert!(
            fs::metadata(dir.join(name)).unwrap().len() > make_png().len() as u64,
            "{name} was not modified"
        );
    }
}

#[test]
fn batch_write_reads_stdin_once_for_all_carriers() {
    let dir = scratch("stdin");
    seed(&dir, &["a.png", "b.png"]);

    // A second stdin read would yield an empty payload; the old single-carrier
    // code path would have embedded "" into the second carrier.
    let mut child = Command::new(bin())
        .args(["write", "-c", "a.png", "b.png", "--stdin"])
        .current_dir(&dir)
        .env("USERPROFILE", &dir)
        .env("HOME", &dir)
        .env("STRHIDE_PASSWORD", "")
        .env_remove("STRHIDE_TEXT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn strhide");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"piped payload")
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    for name in ["a.png", "b.png"] {
        assert_eq!(payload(&dir, name), "piped payload", "{name} payload");
    }
}

#[test]
fn batch_write_keeps_the_data_filename_for_every_carrier() {
    let dir = scratch("filename");
    seed(&dir, &["a.png", "b.png"]);
    fs::write(dir.join("vault.dat"), b"file payload").unwrap();

    let out = run(&dir, &["write", "-c", "a.png", "b.png", "-d", "vault.dat"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    fs::create_dir_all(dir.join("got")).unwrap();
    for name in ["a.png", "b.png"] {
        let out = run(&dir, &["read", "-c", name, "-o", "got"]);
        assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
        assert_eq!(
            fs::read_to_string(dir.join("got").join("vault.dat")).unwrap(),
            "file payload",
            "{name} lost the original payload filename"
        );
        fs::remove_file(dir.join("got").join("vault.dat")).unwrap();
    }
}

#[test]
fn single_carrier_output_still_has_no_summary_line() {
    let dir = scratch("no_summary");
    seed(&dir, &["a.png"]);

    let out = run(&dir, &["write", "-c", "a.png", "-t", "one"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        !stdout(&out).contains("[SUMMARY]"),
        "stdout: {}",
        stdout(&out)
    );
}

// --------------------------------------------------------------------------- batch guards

#[test]
fn batch_write_requires_an_existing_output_directory() {
    let dir = scratch("out_file");
    seed(&dir, &["a.png", "b.png"]);
    fs::write(dir.join("target.bin"), b"x").unwrap();

    let out = run(
        &dir,
        &[
            "write",
            "-c",
            "a.png",
            "b.png",
            "-t",
            "x",
            "-o",
            "target.bin",
        ],
    );
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("must be an existing directory"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn batch_write_into_a_directory_leaves_the_carriers_untouched() {
    let dir = scratch("out_dir");
    seed(&dir, &["a.png", "b.png"]);
    fs::create_dir_all(dir.join("out")).unwrap();

    let out = run(
        &dir,
        &["write", "-c", "a.png", "b.png", "-t", "x", "-o", "out"],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    for name in ["a.png", "b.png"] {
        assert_eq!(
            fs::read(dir.join(name)).unwrap(),
            make_png(),
            "{name} should not be modified when -o is used"
        );
        assert!(dir.join("out").join(name).exists(), "missing out/{name}");
    }
    assert_eq!(payload(&dir, "out/a.png"), "x");
    assert_eq!(payload(&dir, "out/b.png"), "x");
}

#[test]
fn batch_write_rejects_interactive_strategy_selection() {
    let dir = scratch("ask");
    seed(&dir, &["a.png", "b.png"]);

    let out = run(
        &dir,
        &[
            "write",
            "-c",
            "a.png",
            "b.png",
            "-t",
            "x",
            "--strategy",
            "ask",
        ],
    );
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("multiple carriers"),
        "stderr: {}",
        stderr(&out)
    );
    // Refused before anything was written.
    for name in ["a.png", "b.png"] {
        assert_eq!(fs::read(dir.join(name)).unwrap(), make_png());
    }
}

#[test]
fn batch_preflight_blocks_an_unsupported_carrier_before_writing() {
    let dir = scratch("preflight");
    seed(&dir, &["a.png"]);
    fs::write(dir.join("notes.txt"), b"not a carrier").unwrap();

    let out = run(&dir, &["write", "-c", "a.png", "notes.txt", "-t", "x"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("not a supported carrier format"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(
        fs::read(dir.join("a.png")).unwrap(),
        make_png(),
        "a.png must be untouched when preflight fails"
    );
}

#[test]
fn duplicate_carrier_is_rejected() {
    let dir = scratch("duplicate");
    seed(&dir, &["a.png"]);

    let out = run(&dir, &["write", "-c", "a.png", "a.png", "-t", "x"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("listed more than once"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(fs::read(dir.join("a.png")).unwrap(), make_png());
}

// --------------------------------------------------------------------------- remove

#[test]
fn batch_remove_restores_every_carrier_byte_exactly() {
    let dir = scratch("remove");
    seed(&dir, &["a.png", "b.png", "c.png"]);

    let out = run(
        &dir,
        &["write", "-c", "a.png", "b.png", "c.png", "-t", "round trip"],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let out = run(&dir, &["remove", "-c", "a.png", "b.png", "c.png"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("[SUMMARY] 3/3 carriers succeeded."),
        "stdout: {}",
        stdout(&out)
    );
    for name in ["a.png", "b.png", "c.png"] {
        assert_eq!(
            fs::read(dir.join(name)).unwrap(),
            make_png(),
            "{name} was not restored byte-exactly"
        );
    }
}

#[test]
fn batch_remove_reports_how_far_it_got_before_failing() {
    let dir = scratch("remove_partial");
    seed(&dir, &["a.png", "clean.png", "c.png"]);

    let out = run(&dir, &["write", "-c", "a.png", "c.png", "-t", "x"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    // clean.png never held an envelope, so the batch stops there.
    let out = run(&dir, &["remove", "-c", "a.png", "clean.png", "c.png"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("[FAIL] clean.png"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("[SUMMARY] 1/3 carriers succeeded; 1 not attempted."),
        "stdout: {}",
        stdout(&out)
    );
    // a.png was restored; c.png was never touched and still holds its payload.
    assert_eq!(fs::read(dir.join("a.png")).unwrap(), make_png());
    assert_eq!(payload(&dir, "c.png"), "x");
}
