//! Multi-carrier (`-c a.png b.png ...`) behavior for `write` and `remove`.
//!
//! Covered here: the same payload reaching every carrier, `--stdin` being read
//! exactly once, `-d` payload filename retention per carrier, the `-o` batch
//! directory rule, preflight refusal that leaves every carrier untouched, the
//! per-run `[SUMMARY]` line, and byte-exact batch restore.

use crate::common::*;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};

// --------------------------------------------------------------------------- helpers

/// Seed `dir` with identical minimal PNG carriers.
fn seed(dir: &Path, names: &[&str]) {
    for name in names {
        fs::write(dir.join(name), make_png()).unwrap();
    }
}

/// Run the binary inside `dir`, isolated from the caller's config file and
/// payload environment variables.
fn run(dir: &Path, args: &[&str]) -> Output {
    base_cmd()
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
    let out = run(dir, &["read", carrier, "--stdout"]);
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
            "a.png",
            "b.png",
            "c.png",
            "-t",
            "shared secret",
            "--in-place",
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
    let mut child = base_cmd()
        .args(["write", "a.png", "b.png", "--stdin", "--in-place"])
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

    let out = run(
        &dir,
        &["write", "a.png", "b.png", "-d", "vault.dat", "--in-place"],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    fs::create_dir_all(dir.join("got")).unwrap();
    for name in ["a.png", "b.png"] {
        let out = run(&dir, &["read", name, "-o", "got"]);
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

    let out = run(&dir, &["write", "a.png", "-t", "one"]);
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
        &["write", "a.png", "b.png", "-t", "x", "-o", "target.bin"],
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

    let out = run(&dir, &["write", "a.png", "b.png", "-t", "x", "-o", "out"]);
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
        &["write", "a.png", "b.png", "-t", "x", "--strategy", "ask"],
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

    let out = run(&dir, &["write", "a.png", "notes.txt", "-t", "x"]);
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

    let out = run(&dir, &["write", "a.png", "a.png", "-t", "x"]);
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
        &[
            "write",
            "a.png",
            "b.png",
            "c.png",
            "-t",
            "round trip",
            "--in-place",
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let out = run(&dir, &["restore", "a.png", "b.png", "c.png", "--in-place"]);
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

    let out = run(&dir, &["write", "a.png", "c.png", "-t", "x", "--in-place"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    // clean.png never held an envelope, so the batch stops there.
    let out = run(
        &dir,
        &["restore", "a.png", "clean.png", "c.png", "--in-place"],
    );
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

// ------------------------------------------------------------ read / extract

#[test]
fn batch_read_writes_one_named_payload_per_carrier() {
    // Stage 4 gave `read` the same `CARRIER...` + `-o <DIR>` shape the other
    // eight commands already had. Two text payloads record no filename, so the
    // outputs must be named after their carriers instead of colliding on
    // `extracted.bin`.
    let dir = scratch("read_batch");
    seed(&dir, &["a.png", "b.png"]);
    let out = run(
        &dir,
        &["write", "a.png", "b.png", "-t", "shared", "--in-place"],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let out_dir = dir.join("out");
    fs::create_dir(&out_dir).unwrap();
    let out = run(
        &dir,
        &["read", "a.png", "b.png", "-o", "out", "--lang", "en"],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("[SUMMARY] 2/2 carriers succeeded."),
        "stdout: {}",
        stdout(&out)
    );

    assert_eq!(fs::read_to_string(out_dir.join("a.txt")).unwrap(), "shared");
    assert_eq!(fs::read_to_string(out_dir.join("b.txt")).unwrap(), "shared");
    assert!(
        !out_dir.join("extracted.bin").exists(),
        "unnamed payloads must not all be called extracted.bin"
    );
}

#[test]
fn batch_read_requires_an_output_directory_for_several_carriers() {
    let dir = scratch("read_batch_no_out");
    seed(&dir, &["a.png", "b.png"]);
    let out = run(&dir, &["write", "a.png", "b.png", "-t", "x", "--in-place"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let out = run(&dir, &["read", "a.png", "b.png", "--lang", "en"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("needs `-o <DIR>`"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn batch_read_rejects_stdout_for_several_carriers() {
    let dir = scratch("read_batch_stdout");
    seed(&dir, &["a.png", "b.png"]);
    let out = run(&dir, &["write", "a.png", "b.png", "-t", "x", "--in-place"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let out = run(
        &dir,
        &["read", "a.png", "b.png", "--stdout", "--lang", "en"],
    );
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("--stdout"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn batch_read_refuses_to_overwrite_without_the_flag() {
    let dir = scratch("read_batch_overwrite");
    seed(&dir, &["a.png", "b.png"]);
    let out = run(&dir, &["write", "a.png", "b.png", "-t", "x", "--in-place"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let out_dir = dir.join("out");
    fs::create_dir(&out_dir).unwrap();
    fs::write(out_dir.join("a.txt"), "stale").unwrap();

    let out = run(
        &dir,
        &["read", "a.png", "b.png", "-o", "out", "--lang", "en"],
    );
    assert_eq!(code(&out), 1);
    assert_eq!(
        fs::read_to_string(out_dir.join("a.txt")).unwrap(),
        "stale",
        "a refused read must not truncate the existing file"
    );

    let out = run(
        &dir,
        &[
            "read",
            "a.png",
            "b.png",
            "-o",
            "out",
            "--overwrite",
            "--lang",
            "en",
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert_eq!(fs::read_to_string(out_dir.join("a.txt")).unwrap(), "x");
}
