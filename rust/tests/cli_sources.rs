//! CLI payload/password source coverage (gap report 2026-10-19, gaps #1 #2 #5).
//!
//! Previously untested source paths, all exercised through the real binary:
//!
//! - payload sources `--text-file`, `--text-base64`, `STRHIDE_TEXT`
//!   (`cli.rs` payload resolution chain), including invalid-base64 /
//!   non-UTF-8 errors and the `-t` vs `STRHIDE_TEXT` precedence;
//! - password sources `--password-file` (CLI) and `config.password_file`
//!   (`resolve_password` precedence), including trailing-newline trimming;
//! - previously untested config keys `unescape`, `backup`, `hint`,
//!   `password_file` plus the `<home>/.strhide/config.toml` discovery path
//!   and the "exists but unreadable" hard-error branch.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_src_{}_{}", std::process::id(), name));
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

/// Config factors: STRHIDE_PASSWORD cleared, STRHIDE_TEXT removed, config
/// candidates (cwd strhide.toml + home config.toml) hidden unless a test
/// re-exports them explicitly.
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

/// Override the config home (tests `~/.strhide/config.toml` discovery).
fn run_with_home(dir: &Path, home: &Path, args: &[&str]) -> Output {
    Command::new(bin())
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
    let out = run(dir, &["read", "-c", carrier, "--stdout"]);
    assert_ok(&out, &["read", carrier, "--stdout"]);
    stdout(&out)
}

// --------------------------------------------------------------------------- payload sources

#[test]
fn cli_text_file_source_roundtrip() {
    let dir = scratch("text_file");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let secret = "秘密文件载荷 secret.txt line 2 with Emoji 🚀";
    fs::write(dir.join("secret.txt"), secret).unwrap();

    let out = run(&dir, &["write", "-c", "c.png", "--text-file", "secret.txt"]);
    assert_ok(&out, &["write", "--text-file"]);

    assert_eq!(read_stdout(&dir, "c.png"), secret);
}

#[test]
fn cli_text_base64_valid_roundtrip() {
    let dir = scratch("b64_ok");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    // base64("用户可见的真实内容") — valid UTF-8 after decoding.
    let b64 = "55So5oi35Y+v6KeB55qE55yf5a6e5YaF5a65";

    let out = run(&dir, &["write", "-c", "c.png", "--text-base64", b64]);
    assert_ok(&out, &["write", "--text-base64"]);

    assert_eq!(read_stdout(&dir, "c.png"), "用户可见的真实内容");
}

#[test]
fn cli_text_base64_invalid_encoding_is_rejected() {
    let dir = scratch("b64_bad");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let out = run(
        &dir,
        &["write", "-c", "c.png", "--text-base64", "not_base64!!"],
    );
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

    let out = run(&dir, &["write", "-c", "c.png", "--text-base64", b64]);
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

    let out = Command::new(bin())
        .args(["write", "-c", "c.png"])
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

    let out = Command::new(bin())
        .args(["write", "-c", "c.png", "-t", "来自 -t"])
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

    let out = Command::new(bin())
        .args(["write", "-c", "c.png"])
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
            "-c",
            "c.png",
            "-t",
            "encrypted via password file",
            "--password-file",
            "pwd.txt",
        ],
    );
    assert_ok(&write, &["write", "--password-file"]);

    // The trailing newline was NOT part of the password: -p with the bare text
    // must read it, and so must the same --password-file.
    let read1 = run(
        &dir,
        &["read", "-c", "c.png", "--stdout", "-p", "pw-file-secret"],
    );
    assert_ok(&read1, &["read -p"]);
    assert_eq!(stdout(&read1), "encrypted via password file");

    let read2 = run(
        &dir,
        &[
            "read",
            "-c",
            "c.png",
            "--stdout",
            "--password-file",
            "pwd.txt",
        ],
    );
    assert_ok(&read2, &["read --password-file"]);
    assert_eq!(stdout(&read2), "encrypted via password file");

    // Without any password source this is an encrypted envelope.
    let read3 = run(&dir, &["read", "-c", "c.png", "--stdout"]);
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
        &[
            "write",
            "-c",
            "c.png",
            "-t",
            "x",
            "--password-file",
            "nope.txt",
        ],
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
fn config_password_file_key_is_used() {
    let dir = scratch("cfg_pwfile");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("pwd.txt"), "cfg-wd\n").unwrap();
    fs::write(dir.join("strhide.toml"), "password_file = \"pwd.txt\"\n").unwrap();

    let write = run(&dir, &["write", "-c", "c.png", "-t", "secret"]);
    assert_ok(&write, &["write config_password_file"]);

    // No CLI password anywhere: the config's password_file supplies it on read.
    let read = run(&dir, &["read", "-c", "c.png", "--stdout"]);
    assert_ok(&read, &["read config_password_file"]);
    assert_eq!(stdout(&read), "secret");

    // A wrong CLI password overrides the config file and fails.
    let wrong = run(
        &dir,
        &["read", "-c", "c.png", "--stdout", "-p", "different"],
    );
    assert_eq!(code(&wrong), 1);
}

#[test]
fn cli_password_beats_config_password_file() {
    let dir = scratch("cfg_pwfile_pre");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("pwd.txt"), "cfg-wd\n").unwrap();
    fs::write(dir.join("strhide.toml"), "password_file = \"pwd.txt\"\n").unwrap();

    // -e with an explicit CLI password: the CLI argument must win over the
    // config password_file (precedence: -p > --password-file > env > config).
    let out = run(
        &dir,
        &["write", "-c", "c.png", "-t", "s", "-e", "-p", "cli-pass"],
    );
    assert_ok(&out, &["write"]);

    let read = run(&dir, &["read", "-c", "c.png", "--stdout", "-p", "cli-pass"]);
    assert_ok(&read, &["read cli-pass"]);
    assert_eq!(stdout(&read), "s");

    // The config file password does not apply.
    let wrong = run(&dir, &["read", "-c", "c.png", "--stdout", "-p", "cfg-wd"]);
    assert_eq!(code(&wrong), 1);
}

// --------------------------------------------------------------------------- config keys & home discovery

/// Small helper: write a config file, then run a write+read cycle in an
/// isolated home/cwd so the config is the only password/hint/unescape source.
fn seeded_dir(name: &str, config: &str) -> PathBuf {
    let dir = scratch(name);
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("strhide.toml"), config).unwrap();
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
        &["write", "-c", "c.png", "-t", "secret", "-p", "hint-pw"],
    );
    assert_ok(&write, &["write hint config"]);
    assert!(
        stdout(&write).contains("Password Hint: '配置里的提示 3班1975'"),
        "hint must be reported from the config, stdout: {}",
        stdout(&write)
    );

    // Reading without any password source surfaces the hint on stdout (the CLI
    // prints "[INFO] Password hint: ..." before failing on the missing TTY).
    let read = run(&dir, &["read", "-c", "c.png", "--stdout"]);
    assert_eq!(code(&read), 1);
    assert!(
        stdout(&read).contains("[INFO] Password hint: 配置里的提示 3班1975"),
        "hint must be surfaced to stdout, stdout: {}",
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
    let write = run(&dir, &["write", "-c", "c.png", "-t", r"\u4e2d\u6587ABC"]);
    assert_ok(&write, &["write unescape config"]);
    assert_eq!(read_stdout(&dir, "c.png"), "中文ABC");
}

#[test]
fn config_backup_false_keeps_no_bak_file() {
    let dir = seeded_dir("cfg_backup", "backup = false\n");
    let write = run(&dir, &["write", "-c", "c.png", "-t", "x"]);
    assert_ok(&write, &["write backup=false"]);
    assert!(
        !dir.join("c.png.bak").exists(),
        "config backup=false must suppress the .bak file"
    );
}

#[test]
fn config_backup_false_is_overridden_by_no_cli_flag() {
    let dir = seeded_dir("cfg_backup_pre", "backup = true\n");
    let write = run(&dir, &["write", "-c", "c.png", "-t", "x", "--no-backup"]);
    assert_ok(&write, &["write --no-backup"]);
    assert!(!dir.join("c.png.bak").exists());
}

#[test]
fn config_backup_true_creates_bak_file() {
    let dir = seeded_dir("cfg_backup_on", "backup = true\n");
    let write = run(&dir, &["write", "-c", "c.png", "-t", "x"]);
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
        "strategy = \"auto\"\nstealth = false\nencrypt = false\npassword = \"p\"\nhint = \"h\"\npreserve_time = true\nbackup = false\nunescape = false\npassword_file = \"pwd.txt\"\n",
    );
    fs::write(dir.join("pwd.txt"), "p\n").unwrap();
    let out = run(&dir, &["list"]);
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
        "encrypt = true\npassword = \"home-pass\"\n",
    )
    .unwrap();

    // cwd holds no strhide.toml, so the home config must supply the password.
    let write = run_with_home(&dir, &home, &["write", "-c", "c.png", "-t", "home secret"]);
    assert_ok(&write, &["write home config"]);

    let read = run_with_home(&dir, &home, &["read", "-c", "c.png", "--stdout"]);
    assert_ok(&read, &["read home config"]);
    assert_eq!(stdout(&read), "home secret");

    // A different (empty) home cannot decrypt it.
    let other_home = scratch("home_other");
    let fail = run_with_home(&dir, &other_home, &["read", "-c", "c.png", "--stdout"]);
    assert_eq!(code(&fail), 1);
}

#[test]
fn cwd_strhide_toml_wins_over_home_config() {
    let dir = scratch("both_cwd");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(
        dir.join("strhide.toml"),
        "encrypt = true\npassword = \"cwd-pass\"\n",
    )
    .unwrap();
    let home = scratch("both_home");
    fs::create_dir_all(home.join(".strhide")).unwrap();
    fs::write(
        home.join(".strhide").join("config.toml"),
        "encrypt = true\npassword = \"home-pass\"\n",
    )
    .unwrap();

    let write = run_with_home(&dir, &home, &["write", "-c", "c.png", "-t", "secret"]);
    assert_ok(&write, &["write cwd vs home"]);

    // The cwd config's password is the one that must be applied: reading with
    // it succeeds, reading with the shadowed home password fails.
    let ok = run_with_home(&dir, &home, &["read", "-c", "c.png", "--stdout"]);
    assert_ok(&ok, &["read cwd config"]);

    let shadowed = run_with_home(
        &dir,
        &home,
        &["read", "-c", "c.png", "--stdout", "-p", "home-pass"],
    );
    assert_eq!(
        code(&shadowed),
        1,
        "home config must be shadowed by ./strhide.toml, stderr: {}",
        stderr(&shadowed)
    );
}

#[test]
fn config_file_that_cannot_be_read_is_a_hard_error() {
    let dir = scratch("cfg_dir");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    // Make ./strhide.toml a directory: read_to_string fails with an error that
    // is not NotFound, so it must surface as a hard error.
    fs::create_dir(dir.join("strhide.toml")).unwrap();
    let out = run(&dir, &["list"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Failed to read config file"),
        "stderr: {}",
        stderr(&out)
    );
}
