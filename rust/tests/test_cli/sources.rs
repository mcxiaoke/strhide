//! CLI payload/password source coverage (gap report 2026-10-19, gaps #1 #2 #5).
//!
//! Previously untested source paths, all exercised through the real binary:
//!
//! - payload sources `--text-base64`, `STRHIDE_TEXT`
//!   (`cli.rs` payload resolution chain), including invalid-base64 /
//!   non-UTF-8 errors and the `-t` vs `STRHIDE_TEXT` precedence;
//! - password sources `--password-file` (CLI) and `config.password_file`
//!   (`resolve_password` precedence), including trailing-newline trimming;
//! - previously untested config keys `unescape`, `backup`, `hint`,
//!   `password_file` plus the `<home>/.strhide/config.toml` discovery path
//!   and the "exists but unreadable" hard-error branch.

use crate::common::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

/// Config factors: STRHIDE_PASSWORD cleared, STRHIDE_TEXT removed, config
/// candidates (cwd strhide.toml + home config.toml) hidden unless a test
/// re-exports them explicitly.
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

/// Override the config home (tests `~/.strhide/config.toml` discovery).
fn run_with_home(dir: &Path, home: &Path, args: &[&str]) -> Output {
    base_cmd()
        .args(args)
        .current_dir(dir)
        .env("USERPROFILE", home)
        .env("HOME", home)
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

fn assert_ok(out: &Output, args: &[&str]) {
    assert_eq!(
        code(out),
        0,
        "args {:?} failed\nstderr: {}",
        args,
        stderr(out)
    );
}

fn read_stdout(dir: &Path, carrier: &str) -> String {
    let out = run(dir, &["read", carrier, "--stdout"]);
    assert_ok(&out, &["read", carrier, "--stdout"]);
    stdout(&out)
}

// --------------------------------------------------------------------------- payload sources

#[test]
fn cli_text_base64_valid_roundtrip() {
    let dir = scratch("b64_ok");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    // base64("用户可见的真实内容") — valid UTF-8 after decoding.
    let b64 = "55So5oi35Y+v6KeB55qE55yf5a6e5YaF5a65";

    let out = run(
        &dir,
        &["write", "c.png", "--text-base64", b64, "--in-place"],
    );
    assert_ok(&out, &["write", "--text-base64"]);

    assert_eq!(read_stdout(&dir, "c.png"), "用户可见的真实内容");
}

#[test]
fn cli_text_base64_invalid_encoding_is_rejected() {
    let dir = scratch("b64_bad");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let out = run(&dir, &["write", "c.png", "--text-base64", "not_base64!!"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Invalid base64 string"),
        "stderr: {}",
        stderr(&out)
    );
    // The carrier must be untouched after the failure.
    assert_eq!(fs::read(dir.join("c.png")).unwrap(), make_png());
}

#[test]
fn cli_text_base64_non_utf8_is_rejected() {
    let dir = scratch("b64_utf8");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    // Valid base64 of raw bytes [0xFF 0xFE 0xFF] — not valid UTF-8.
    let b64 = "//7/";

    let out = run(&dir, &["write", "c.png", "--text-base64", b64]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("not valid UTF-8"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(fs::read(dir.join("c.png")).unwrap(), make_png());
}

#[test]
fn env_text_is_used_as_payload_source() {
    let dir = scratch("env_text");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let secret = "来自 STRHIDE_TEXT 环境变量的载荷";

    let out = base_cmd()
        .args(["write", "c.png", "--in-place"])
        .current_dir(&dir)
        .env("USERPROFILE", &dir)
        .env("HOME", &dir)
        .env("STRHIDE_PASSWORD", "")
        .env("STRHIDE_TEXT", secret)
        .output()
        .unwrap();
    assert_ok(&out, &["write via STRHIDE_TEXT"]);

    assert_eq!(read_stdout(&dir, "c.png"), secret);
}

#[test]
fn cli_text_wins_over_env_text() {
    let dir = scratch("env_priority");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let out = base_cmd()
        .args(["write", "c.png", "-t", "来自 -t", "--in-place"])
        .current_dir(&dir)
        .env("USERPROFILE", &dir)
        .env("HOME", &dir)
        .env("STRHIDE_PASSWORD", "")
        .env("STRHIDE_TEXT", "来自 STRHIDE_TEXT")
        .output()
        .unwrap();
    assert_ok(&out, &["write"]);

    assert_eq!(read_stdout(&dir, "c.png"), "来自 -t");
}

#[test]
fn empty_env_text_still_rejected() {
    let dir = scratch("env_empty");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let out = base_cmd()
        .args(["write", "c.png"])
        .current_dir(&dir)
        .env("USERPROFILE", &dir)
        .env("HOME", &dir)
        .env("STRHIDE_PASSWORD", "")
        .env("STRHIDE_TEXT", "")
        .output()
        .unwrap();
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Must provide either"),
        "stderr: {}",
        stderr(&out)
    );
}

// --------------------------------------------------------------------------- password sources

#[test]
fn password_file_write_and_read_roundtrip() {
    let dir = scratch("pwfile");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    // Trailing newline/CR must be trimmed by resolve_password.
    fs::write(dir.join("pwd.txt"), b"pw-file-secret\n").unwrap();

    let write = run(
        &dir,
        &[
            "write",
            "c.png",
            "-t",
            "encrypted via password file",
            "--password-file",
            "pwd.txt",
            "--in-place",
        ],
    );
    assert_ok(&write, &["write", "--password-file"]);

    // The trailing newline was NOT part of the password: -p with the bare text
    // must read it, and so must the same --password-file.
    let read1 = run(&dir, &["read", "c.png", "--stdout", "-p", "pw-file-secret"]);
    assert_ok(&read1, &["read -p"]);
    assert_eq!(stdout(&read1), "encrypted via password file");

    let read2 = run(
        &dir,
        &["read", "c.png", "--stdout", "--password-file", "pwd.txt"],
    );
    assert_ok(&read2, &["read --password-file"]);
    assert_eq!(stdout(&read2), "encrypted via password file");

    // Without any password source this is an encrypted envelope.
    let read3 = run(&dir, &["read", "c.png", "--stdout"]);
    assert_eq!(code(&read3), 1);
    assert!(
        stderr(&read3).contains("assword"),
        "expected password error, stderr: {}",
        stderr(&read3)
    );
}

#[test]
fn password_file_missing_is_a_hard_error() {
    let dir = scratch("pwfile_missing");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let out = run(
        &dir,
        &["write", "c.png", "-t", "x", "--password-file", "nope.txt"],
    );
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Failed to read password file"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("nope.txt"),
        "error must name the file, stderr: {}",
        stderr(&out)
    );
}

#[test]
fn config_password_file_key_is_warned_and_not_used() {
    let dir = scratch("cfg_pwfile");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("pwd.txt"), "cfg-wd\n").unwrap();
    fs::write(
        dir.join("custom.toml"),
        "encrypt = true\npassword_file = \"pwd.txt\"\n",
    )
    .unwrap();

    let write = run(
        &dir,
        &[
            "--config",
            "custom.toml",
            "write",
            "c.png",
            "-t",
            "secret",
            "--in-place",
        ],
    );
    assert_eq!(code(&write), 1);
    assert!(stderr(&write).contains("Unknown key 'password_file'"));
    assert!(stderr(&write).contains("Password required but no interactive terminal"));
}

// --------------------------------------------------------------------------- mutual exclusion

/// Payload sources (`-d`, `-t`, `--text-base64`, `--stdin`) are
/// mutually exclusive at parse time (exit code 2): the old silent priority
/// chain hid whichever source lost the fixed lookup order.
#[test]
fn payload_sources_reject_conflicting_input() {
    let dir = scratch("mutex_payload");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    for args in [
        vec!["write", "c.png", "-t", "x", "-d", "s.txt"],
        vec!["write", "c.png", "-d", "s.txt", "--stdin"],
        vec!["write", "c.png", "--text-base64", "aGk=", "-t", "x"],
    ] {
        let out = run(&dir, &args);
        assert_eq!(
            code(&out),
            2,
            "conflicting payload sources must be parse errors, args: {:?}\nstderr: {}",
            args,
            stderr(&out)
        );
        assert!(
            stderr(&out).contains("cannot be used with"),
            "error must name the conflict, args {:?}, stderr: {}",
            args,
            stderr(&out)
        );
        // The carrier must be untouched after a rejected invocation.
        assert_eq!(fs::read(dir.join("c.png")).unwrap(), make_png());
    }
}

/// `-p` and `--password-file` are mutually exclusive at parse time.
#[test]
fn password_sources_reject_conflicting_input() {
    let dir = scratch("mutex_password");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    for args in [
        vec![
            "write",
            "c.png",
            "-t",
            "x",
            "-p",
            "a",
            "--password-file",
            "b",
        ],
        vec!["read", "c.png", "-p", "a", "--password-file", "b"],
        vec!["restore", "c.png", "-p", "a", "--password-file", "b"],
        vec!["inspect", "c.png", "-p", "a", "--password-file", "b"],
        vec!["verify", "c.png", "-p", "a", "--password-file", "b"],
    ] {
        let out = run(&dir, &args);
        assert_eq!(
            code(&out),
            2,
            "conflicting password sources must be parse errors, args: {:?}\nstderr: {}",
            args,
            stderr(&out)
        );
        assert!(
            stderr(&out).contains("cannot be used with"),
            "error must name the conflict, args {:?}, stderr: {}",
            args,
            stderr(&out)
        );
    }
}

/// `read` output routing (`-o` vs `--stdout`) is mutually exclusive at parse
/// time; previously `-o` silently won over `--stdout`.
#[test]
fn read_output_routing_rejects_conflicting_input() {
    let dir = scratch("mutex_out");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let out = run(&dir, &["read", "c.png", "-o", "out.bin", "--stdout"]);
    assert_eq!(code(&out), 2);
    assert!(
        stderr(&out).contains("cannot be used with"),
        "error must name the conflict, stderr: {}",
        stderr(&out)
    );
    // No file may have been created by the rejected invocation.
    assert!(!dir.join("out.bin").exists());
}

/// The STRHIDE_TEXT fallback must survive the payload-source mutex group:
/// with no CLI payload source at all, the env var is still the last resort.
#[test]
fn env_text_fallback_after_mutex_introduced() {
    let dir = scratch("mutex_env_fallback");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let secret = "mutex 互斥组不影响 STRHIDE_TEXT 兜底";

    let out = base_cmd()
        .args(["write", "c.png", "--in-place"])
        .current_dir(&dir)
        .env("USERPROFILE", &dir)
        .env("HOME", &dir)
        .env("STRHIDE_PASSWORD", "")
        .env("STRHIDE_TEXT", secret)
        .output()
        .unwrap();
    assert_ok(&out, &["write via STRHIDE_TEXT"]);
    assert_eq!(read_stdout(&dir, "c.png"), secret);
}

/// A missing payload source still fails at runtime with the same message as
/// before (the mutex group is not required, so `handle_write` keeps reporting
/// "Must provide either ..." when neither CLI args nor STRHIDE_TEXT supplied).
#[test]
fn missing_payload_source_message_unchanged() {
    let dir = scratch("mutex_none");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let out = run(&dir, &["write", "c.png"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Must provide either"),
        "stderr: {}",
        stderr(&out)
    );
}

// --------------------------------------------------------------------------- global -q/--quiet

/// `write -q` prints nothing on stdout/stderr yet still performs the write
/// (verified by a plain `read --stdout` afterwards).
#[test]
fn write_quiet_is_silent_and_still_writes() {
    let dir = scratch("quiet_write");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let secret = "静默写入的载荷 quiet write";

    let out = run(&dir, &["write", "c.png", "-t", secret, "-q", "--in-place"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).is_empty(),
        "quiet write must stay silent on stdout, got: {}",
        stdout(&out)
    );
    assert!(
        stderr(&out).is_empty(),
        "quiet write must stay silent on stderr, got: {}",
        stderr(&out)
    );
    // A .bak was created (default) without being announced.
    assert!(dir.join("c.png.bak").exists());

    assert_eq!(read_stdout(&dir, "c.png"), secret);
}

/// `read -q` must NOT swallow payload data: what reaches stdout is the
/// payload itself, without any [OK] status line around it.
#[test]
fn read_quiet_stdout_prints_payload_only() {
    let dir = scratch("quiet_read");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let write = run(
        &dir,
        &[
            "write",
            "c.png",
            "-t",
            "data only",
            "--no-backup",
            "--in-place",
        ],
    );
    assert_ok(&write, &["write"]);

    let out = run(&dir, &["read", "c.png", "--stdout", "-q"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "data only");
}

/// `read -o <file> -q` still writes the file and stays silent.
#[test]
fn read_quiet_to_file_suppresses_status_only() {
    let dir = scratch("quiet_read_file");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let write = run(
        &dir,
        &[
            "write",
            "c.png",
            "-t",
            "into a file",
            "--no-backup",
            "--in-place",
        ],
    );
    assert_ok(&write, &["write"]);

    let out = run(&dir, &["read", "c.png", "-o", "payload.out", "-q"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).is_empty(), "stdout: {}", stdout(&out));
    assert_eq!(
        fs::read_to_string(dir.join("payload.out")).unwrap(),
        "into a file"
    );
}

/// `restore -q` restores silently; the carrier is verified restored.
#[test]
fn restore_quiet_is_silent_and_restores() {
    let dir = scratch("quiet_restore");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let write = run(
        &dir,
        &["write", "c.png", "-t", "x", "--no-backup", "--in-place"],
    );
    assert_ok(&write, &["write"]);

    let out = run(&dir, &["restore", "c.png", "-q", "--in-place"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).is_empty() && stderr(&out).is_empty(),
        "quiet restore must print nothing, stdout: {} stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    // Fully restored original host.
    assert_eq!(fs::read(dir.join("c.png")).unwrap(), make_png());
}

/// `inspect -q` suppresses the human report (the --json form remains the
/// machine-readable equivalent); a non-quiet run still prints it.
#[test]
fn inspect_quiet_suppresses_human_report() {
    let dir = scratch("quiet_inspect");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let loud = run(&dir, &["inspect", "c.png"]);
    assert_ok(&loud, &["inspect"]);
    assert!(
        stdout(&loud).contains("Carrier:"),
        "stdout: {}",
        stdout(&loud)
    );

    let out = run(&dir, &["inspect", "c.png", "-q"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).is_empty(), "stdout: {}", stdout(&out));
    assert!(stderr(&out).is_empty(), "stderr: {}", stderr(&out));
}

/// `verify -q` suppresses the three-level report; the exit code remains the
/// documented gate (valid envelope -> 0).
#[test]
fn verify_quiet_suppresses_report_keeps_exit_code() {
    let dir = scratch("quiet_verify");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let write = run(
        &dir,
        &["write", "c.png", "-t", "x", "--no-backup", "--in-place"],
    );
    assert_ok(&write, &["write"]);

    let loud = run(&dir, &["verify", "c.png"]);
    assert_ok(&loud, &["verify"]);
    assert!(
        stdout(&loud).contains("Level 1"),
        "stdout: {}",
        stdout(&loud)
    );

    let out = run(&dir, &["verify", "c.png", "-q"]);
    assert_eq!(code(&out), 0);
    assert!(stdout(&out).is_empty(), "stdout: {}", stdout(&out));
    assert!(stderr(&out).is_empty(), "stderr: {}", stderr(&out));
}

// --------------------------------------------------------------------------- config keys & home discovery

/// Small helper: write a config file, then run a write+read cycle in an
/// isolated home/cwd so the config is the only password/hint/unescape source.
fn seeded_dir(name: &str, config: &str) -> PathBuf {
    let dir = scratch(name);
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("custom.toml"), config).unwrap();
    dir
}

#[test]
fn config_hint_key_applies_on_write() {
    // Only the hint comes from the config; the password is supplied on the
    // command line so that a later password-less read has no source at all and
    // must surface the hint in its error.
    let dir = seeded_dir("cfg_hint", "hint = \"配置里的提示 3班1975\"\n");
    let write = run(
        &dir,
        &[
            "--config",
            "custom.toml",
            "write",
            "c.png",
            "-t",
            "secret",
            "-p",
            "hint-pw",
            "--in-place",
        ],
    );
    assert_ok(&write, &["write hint config"]);
    assert!(
        stdout(&write).contains("Password Hint: '配置里的提示 3班1975'"),
        "hint must be reported from the config, stdout: {}",
        stdout(&write)
    );

    // Reading without any password source surfaces the hint. With `--stdout`
    // the payload owns stdout, so the hint must go to stderr instead: a banner
    // or hint on stdout would prepend itself to the piped payload (review R3
    // P1-8).
    let read = run(&dir, &["read", "c.png", "--stdout"]);
    assert_eq!(code(&read), 1);
    assert!(
        stderr(&read).contains("[INFO] Password hint: 配置里的提示 3班1975"),
        "hint must be surfaced to stderr under --stdout, stderr: {}",
        stderr(&read)
    );
    assert!(
        !stdout(&read).contains("Password hint"),
        "stdout must stay payload-only under --stdout, stdout: {}",
        stdout(&read)
    );
    assert!(
        stderr(&read).contains("Password required but no interactive terminal"),
        "stderr: {}",
        stderr(&read)
    );
}

#[test]
fn config_unescape_key_applies() {
    let dir = seeded_dir("cfg_unescape", "unescape = true\n");
    // \u escapes decode to UTF-8 content before embedding.
    let write = run(
        &dir,
        &[
            "--config",
            "custom.toml",
            "write",
            "c.png",
            "-t",
            r"\u4e2d\u6587ABC",
            "--in-place",
        ],
    );
    assert_ok(&write, &["write unescape config"]);
    assert_eq!(read_stdout(&dir, "c.png"), "中文ABC");
}

#[test]
fn config_backup_false_keeps_no_bak_file() {
    let dir = seeded_dir("cfg_backup", "backup = false\n");
    let write = run(
        &dir,
        &[
            "--config",
            "custom.toml",
            "write",
            "c.png",
            "-t",
            "x",
            "--in-place",
        ],
    );
    assert_ok(&write, &["write backup=false"]);
    assert!(
        !dir.join("c.png.bak").exists(),
        "config backup=false must suppress the .bak file"
    );
}

#[test]
fn config_backup_false_is_overridden_by_no_cli_flag() {
    let dir = seeded_dir("cfg_backup_pre", "backup = true\n");
    let write = run(
        &dir,
        &[
            "--config",
            "custom.toml",
            "write",
            "c.png",
            "-t",
            "x",
            "--no-backup",
            "--in-place",
        ],
    );
    assert_ok(&write, &["write --no-backup"]);
    assert!(!dir.join("c.png.bak").exists());
}

#[test]
fn config_backup_true_creates_bak_file() {
    let dir = seeded_dir("cfg_backup_on", "backup = true\n");
    let write = run(
        &dir,
        &[
            "--config",
            "custom.toml",
            "write",
            "c.png",
            "-t",
            "x",
            "--in-place",
        ],
    );
    assert_ok(&write, &["write backup=true"]);
    assert!(
        dir.join("c.png.bak").exists(),
        "config backup=true must keep the .bak backup"
    );
}

#[test]
fn config_valid_keys_print_no_unknown_key_warning() {
    let dir = seeded_dir(
        "cfg_all_keys",
        "strategy = \"auto\"\nstealth = false\nencrypt = false\nhint = \"h\"\npreserve_time = true\nbackup = false\nunescape = false\n",
    );
    let out = run(&dir, &["--config", "custom.toml", "list"]);
    assert_ok(&out, &["list"]);
    assert!(
        !stderr(&out).contains("[WARNING] Unknown key"),
        "recognized keys must not warn, stderr: {}",
        stderr(&out)
    );
}

#[test]
fn home_config_toml_is_discovered() {
    let dir = scratch("home_cwd");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let home = scratch("home_root");
    fs::create_dir_all(home.join(".strhide")).unwrap();
    fs::write(
        home.join(".strhide").join("config.toml"),
        "backup = false\nhint = \"home-hint\"\n",
    )
    .unwrap();

    let write = run_with_home(
        &dir,
        &home,
        &[
            "write",
            "c.png",
            "-t",
            "home secret",
            "-p",
            "pwd",
            "--in-place",
        ],
    );
    assert_ok(&write, &["write home config"]);
    assert!(
        !dir.join("c.png.bak").exists(),
        "home config backup=false must be applied"
    );
    assert!(stdout(&write).contains("Password Hint: 'home-hint'"));
}

#[test]
fn cwd_strhide_toml_is_ignored_and_home_config_applies() {
    let dir = scratch("both_cwd");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    // In CWD, put backup = true
    fs::write(dir.join("strhide.toml"), "backup = true\n").unwrap();
    let home = scratch("both_home");
    fs::create_dir_all(home.join(".strhide")).unwrap();
    fs::write(
        home.join(".strhide").join("config.toml"),
        "backup = false\n",
    )
    .unwrap();

    let write = run_with_home(
        &dir,
        &home,
        &["write", "c.png", "-t", "secret", "--in-place"],
    );
    assert_ok(&write, &["write cwd vs home"]);
    // CWD is ignored, so home config backup=false applies!
    assert!(
        !dir.join("c.png.bak").exists(),
        "CWD config must be ignored; home config must apply"
    );
}

#[test]
fn config_file_that_cannot_be_read_is_a_hard_error() {
    let dir = scratch("cfg_dir");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    // Make explicit config a directory: read_to_string fails with an error that
    // is not NotFound, so it must surface as a hard error.
    fs::create_dir(dir.join("bad_cfg")).unwrap();
    let out = run(&dir, &["--config", "bad_cfg", "list"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Failed to read config file"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_empty_password_flag_rejected() {
    let dir = scratch("empty_pwd_flag");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let out = run(&dir, &["write", "c.png", "-t", "hello", "-p", ""]);
    assert_ne!(code(&out), 0);
    assert!(
        stderr(&out).contains("Password cannot be empty"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_multiline_password_file_reads_first_line() {
    let dir = scratch("multiline_pwd_file");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(
        dir.join("pw.txt"),
        "first_secret_pass\nsecond_garbage_line\n",
    )
    .unwrap();

    let out = run(
        &dir,
        &[
            "write",
            "c.png",
            "-t",
            "hidden_text",
            "--password-file",
            "pw.txt",
        ],
    );
    assert_ok(&out, &["write with multiline pw file"]);

    // Must decode with the first line as password
    let read_ok = run(
        &dir,
        &["read", "c-out.png", "--stdout", "-p", "first_secret_pass"],
    );
    assert_eq!(stdout(&read_ok), "hidden_text");
}
