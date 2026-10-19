//! verify / warning / CLI-output coverage (gap report 2026-10-19, gaps #3 #4 #6 #7).
//!
//! Previously untested paths:
//!
//! - `verify_carrier` early-return branch: no envelope at all (Level 2
//!   "No envelope found", Level 3 "Skipped (no envelope)") and the
//!   Level 3 "Password required for cryptographic verification" skip for an
//!   encrypted envelope verified without its password;
//! - the >50% size-inflation warning and its merge with the structural
//!   "carrier already looks like a hidden envelope" warning;
//! - `inspect --json` / `verify --json` stdout (schema + the `[auto
//!   preference]` capacity marker is only in the human output, so it is
//!   checked there);
//! - `--strategy ask` interactive selection for a single carrier, including
//!   out-of-range and non-numeric answers falling back to the first strategy.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
    write_carrier,
};
use strhide::errors::StrHideError;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("strhide_ver_{}_{}", std::process::id(), name));
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

fn run_with_stdin(dir: &Path, args: &[&str], stdin_data: &[u8]) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("USERPROFILE", dir)
        .env("HOME", dir)
        .env("STRHIDE_PASSWORD", "")
        .env_remove("STRHIDE_TEXT")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn strhide");
    child.stdin.take().unwrap().write_all(stdin_data).unwrap();
    child.wait_with_output().unwrap()
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

// --------------------------------------------------------------------------- verify branches

#[test]
fn verify_on_clean_carrier_reports_no_envelope() {
    let dir = scratch("verify_none");
    let carrier = dir.join("clean.png");
    fs::write(&carrier, make_png()).unwrap();

    let v = verify_carrier(&carrier, None).expect("verify clean carrier");

    assert!(v.level1_host.ok, "L1 must pass: {}", v.level1_host.detail);
    assert!(
        !v.level2_envelope.ok,
        "L2 must fail when there is no envelope"
    );
    assert_eq!(v.level2_envelope.detail, "No envelope found");
    assert!(!v.level3_crypto.ok);
    assert_eq!(v.level3_crypto.detail, "Skipped (no envelope)");
}

#[test]
fn verify_on_clean_carrier_cli_exits_one() {
    let dir = scratch("verify_none_cli");
    fs::write(dir.join("clean.png"), make_png()).unwrap();

    let out = run(&dir, &["verify", "-c", "clean.png"]);
    assert_eq!(
        code(&out),
        1,
        "stdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("No envelope found"),
        "stdout: {}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("Skipped (no envelope)"),
        "stdout: {}",
        stdout(&out)
    );
}

#[test]
fn verify_encrypted_envelope_without_password_skips_level3() {
    let dir = scratch("verify_l3_skip");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let out = dir.join("o.png");
    write_carrier(
        &carrier,
        PayloadSource::Text("secret"),
        &WriteOptions {
            output_path: Some(&out),
            password: Some("pw-l3"),
            backup: false,
            ..Default::default()
        },
    )
    .expect("write");

    // Without the password the standard magic still locates the envelope, so
    // Level 2 passes while Level 3 must report the skipped crypto check.
    let v = verify_carrier(&out, None).expect("verify without password");
    assert!(v.level1_host.ok, "L1: {}", v.level1_host.detail);
    assert!(v.level2_envelope.ok, "L2: {}", v.level2_envelope.detail);
    assert!(!v.level3_crypto.ok, "L3 must not pass without a password");
    assert_eq!(
        v.level3_crypto.detail,
        "Password required for cryptographic verification"
    );

    // With the password Level 3 passes.
    let with_pwd = verify_carrier(&out, Some("pw-l3")).expect("verify with password");
    assert!(
        with_pwd.level3_crypto.ok,
        "L3: {}",
        with_pwd.level3_crypto.detail
    );
}

#[test]
fn verify_level3_failure_is_reported_but_exit_code_stays_zero() {
    // The CLI contract (p2_cli #15): Level 1/2 failures exit 1, a Level 3
    // crypto failure is only reported. Wrong password => L3 fails, L1/L2 pass.
    let dir = scratch("verify_l3_exit");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let write = run(&dir, &["write", "-c", "c.png", "-t", "s", "-p", "right-pw"]);
    assert_eq!(code(&write), 0, "stderr: {}", stderr(&write));

    let out = run(&dir, &["verify", "-c", "c.png", "-p", "wrong-pw"]);
    assert_eq!(
        code(&out),
        0,
        "Level 3 failure must not change the exit code, stdout: {}",
        stdout(&out)
    );
    assert!(stdout(&out).contains("[FAIL]"), "stdout: {}", stdout(&out));
}

// --------------------------------------------------------------------------- size-inflation warning

#[test]
fn size_inflation_warning_is_raised_above_fifty_percent() {
    let dir = scratch("inflate");
    // A deliberately tiny carrier with a payload whose envelope dwarfs it.
    let tiny = include_bytes!("assets/minimal.png").to_vec();
    let carrier = dir.join("tiny.png");
    fs::write(&carrier, &tiny).unwrap();
    let out = dir.join("tiny.steg.png");

    let payload: String = "X".repeat(64);
    let res = write_carrier(
        &carrier,
        PayloadSource::Text(&payload),
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
    )
    .expect("write");

    let carrier_size = tiny.len() as u64;
    assert!(
        res.ube_size * 2 > carrier_size,
        "test premise: envelope {} must exceed 50% of carrier {}",
        res.ube_size,
        carrier_size
    );
    let warning = res
        .warning
        .as_deref()
        .expect("a payload this large relative to the carrier must warn");
    assert!(
        warning.contains("exceeds 50.0% of carrier file size"),
        "warning: {warning}"
    );
    assert!(
        warning.contains(&format!("{} bytes", carrier_size)),
        "warning must quote the carrier size: {warning}"
    );
    assert!(warning.contains("stealthiness"), "warning text: {warning}");
}

#[test]
fn small_payload_in_large_carrier_does_not_warn() {
    let dir = scratch("no_inflate");
    // The real sample PNG is far larger than a tiny text envelope.
    let carrier = dir.join("big.png");
    fs::write(&carrier, include_bytes!("assets/minimal.png")).unwrap();
    // Pad the carrier with a large ancillary chunk so the ratio stays low.
    // The chunk name must NOT be `prIv`: that is strhide's own chunk type, so
    // a `prIv` chunk is by design reported as an envelope-shaped structure.
    let mut padded = fs::read(&carrier).unwrap();
    let iend = padded.len() - 12;
    let big_data = vec![0u8; 200_000];
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(big_data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"vpAg");
    chunk.extend_from_slice(&big_data);
    let crc = crc32fast::hash(&chunk[4..]);
    chunk.extend_from_slice(&crc.to_be_bytes());
    padded.splice(iend..iend, chunk);
    fs::write(&carrier, &padded).unwrap();

    let out = dir.join("big.steg.png");
    let res = write_carrier(
        &carrier,
        PayloadSource::Text("small"),
        &WriteOptions {
            output_path: Some(&out),
            backup: false,
            ..Default::default()
        },
    )
    .expect("write");
    assert_eq!(
        res.warning, None,
        "tiny payload in a 200 KB carrier must not warn"
    );
}

#[test]
fn inflation_and_structural_warnings_are_merged() {
    let dir = scratch("merged_warn");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();

    // First write: stealth envelope with a password we will not reuse, so the
    // second write cannot find it by magic and must fall back to the
    // structural scan.
    let stego = dir.join("w.png");
    write_carrier(
        &carrier,
        PayloadSource::Text("first"),
        &WriteOptions {
            output_path: Some(&stego),
            password: Some("unknown-pw-1"),
            stealth: true,
            backup: false,
            ..Default::default()
        },
    )
    .expect("first write");

    // Second write without the password: structural warning + (payload large
    // enough relative to this small carrier) inflation warning.
    let big: String = "Y".repeat(96);
    let res = write_carrier(
        &stego,
        PayloadSource::Text(&big),
        &WriteOptions {
            output_path: Some(&dir.join("w2.png")),
            backup: false,
            ..Default::default()
        },
    )
    .expect("second write");

    let warning = res
        .warning
        .as_deref()
        .expect("expected a structural warning at minimum");
    assert!(
        warning.contains("only a hidden envelope would produce"),
        "structural part missing: {warning}"
    );
    assert!(
        warning.contains("exceeds 50.0% of carrier file size"),
        "inflation part missing: {warning}"
    );
}

// --------------------------------------------------------------------------- CLI --json output

#[test]
fn cli_inspect_json_is_valid_and_complete() {
    let dir = scratch("inspect_json");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let write = run(
        &dir,
        &["write", "-c", "c.png", "-t", "json secret", "-p", "json-pw"],
    );
    assert_eq!(code(&write), 0, "stderr: {}", stderr(&write));

    let out = run(&dir, &["inspect", "-c", "c.png", "-p", "json-pw", "--json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let json: serde_json::Value = serde_json::from_str(&stdout(&out))
        .unwrap_or_else(|e| panic!("inspect --json must emit valid JSON: {e}\n{}", stdout(&out)));
    assert_eq!(json["format"], "PNG");
    assert_eq!(json["has_hidden_data"], true);
    assert_eq!(json["strategy"], "chunk");
    assert_eq!(json["is_encrypted"], true);
    assert_eq!(json["is_stealth"], false);
    assert!(json["ube_offset"].is_u64(), "ube_offset must be a number");
    assert!(json["ube_total_size"].is_u64());
    assert!(json["orig_host_size"].is_u64());
    assert_eq!(
        json["orig_host_sha256"].as_str().map(|s| s.len()),
        Some(64),
        "sha256 must be hex"
    );
    // Metadata is only decrypted when the password is supplied.
    assert_eq!(json["metadata"]["raw_size"], 11);
    // The capacity table is part of the JSON contract too.
    let strategies = json["strategies"].as_array().expect("strategies array");
    assert_eq!(strategies.len(), 2);
    assert_eq!(strategies[0]["strategy"], "chunk");
    assert_eq!(strategies[1]["strategy"], "eof");
    assert_eq!(strategies[0]["available"], true);
    assert!(
        strategies[0]["limit"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn cli_inspect_human_output_marks_auto_preference() {
    let dir = scratch("inspect_auto_mark");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let out = run(&dir, &["inspect", "-c", "c.png"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("Has Hidden Data: false"), "{text}");
    assert!(
        text.contains("chunk [auto preference]"),
        "first available strategy must be marked: {text}"
    );
}

#[test]
fn cli_inspect_json_on_clean_carrier_reports_no_hidden_data() {
    let dir = scratch("inspect_json_clean");
    fs::write(dir.join("clean.png"), make_png()).unwrap();
    let out = run(&dir, &["inspect", "-c", "clean.png", "--json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json["has_hidden_data"], false);
    assert!(json["strategy"].is_null());
    assert!(json["metadata"].is_null());
    assert!(
        json["strategies"].as_array().is_some_and(|a| !a.is_empty()),
        "capacities are reported even without an envelope"
    );
}

#[test]
fn cli_verify_json_is_valid_and_complete() {
    let dir = scratch("verify_json");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let write = run(
        &dir,
        &["write", "-c", "c.png", "-t", "json secret", "-p", "json-pw"],
    );
    assert_eq!(code(&write), 0, "stderr: {}", stderr(&write));

    let out = run(&dir, &["verify", "-c", "c.png", "-p", "json-pw", "--json"]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));

    let json: serde_json::Value = serde_json::from_str(&stdout(&out))
        .unwrap_or_else(|e| panic!("verify --json must emit valid JSON: {e}\n{}", stdout(&out)));
    assert_eq!(json["format"], "PNG");
    assert_eq!(json["level1_host"]["ok"], true);
    assert_eq!(json["level2_envelope"]["ok"], true);
    assert_eq!(json["level3_crypto"]["ok"], true);
    assert!(
        json["level1_host"]["detail"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
    assert!(
        json["level3_crypto"]["detail"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    );
}

#[test]
fn cli_verify_json_on_encrypted_envelope_without_password() {
    let dir = scratch("verify_json_l3");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let write = run(&dir, &["write", "-c", "c.png", "-t", "s", "-p", "json-pw"]);
    assert_eq!(code(&write), 0, "stderr: {}", stderr(&write));

    let out = run(&dir, &["verify", "-c", "c.png", "--json"]);
    assert_eq!(code(&out), 0, "stdout: {}", stdout(&out));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON");
    assert_eq!(json["level2_envelope"]["ok"], true);
    assert_eq!(json["level3_crypto"]["ok"], false);
    assert_eq!(
        json["level3_crypto"]["detail"],
        "Password required for cryptographic verification"
    );
}

// --------------------------------------------------------------------------- --strategy ask

#[test]
fn strategy_ask_selects_the_chosen_entry() {
    let dir = scratch("ask_pick");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let orig = fs::read(dir.join("c.png")).unwrap();

    // PNG offers [1] chunk, [2] eof -> pick 2.
    let out = run_with_stdin(
        &dir,
        &[
            "write",
            "-c",
            "c.png",
            "-t",
            "asked payload",
            "--strategy",
            "ask",
        ],
        b"2\n",
    );
    assert_eq!(
        code(&out),
        0,
        "stdout: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("Available strategies for"),
        "the option list must be printed: {}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("[1] chunk") && stdout(&out).contains("[2] eof"),
        "stdout: {}",
        stdout(&out)
    );
    assert!(
        stdout(&out).contains("using strategy 'eof'"),
        "selection 2 must resolve to eof: {}",
        stdout(&out)
    );

    // eof appends after IEND, so the carrier grew and the payload is readable.
    let stego = fs::read(dir.join("c.png")).unwrap();
    assert!(stego.len() > orig.len(), "eof must grow the file");
    assert!(
        stego.starts_with(&orig),
        "eof must keep the host bytes intact"
    );
    let read = read_carrier(&dir.join("c.png"), None, None).expect("read");
    assert_eq!(read.data, b"asked payload");
}

#[test]
fn strategy_ask_out_of_range_and_non_numeric_fall_back_to_first() {
    for (label, answer) in [
        ("out-of-range", b"99\n".as_slice()),
        ("non-numeric", b"abc\n".as_slice()),
    ] {
        let dir = scratch(&format!("ask_{label}"));
        fs::write(dir.join("c.png"), make_png()).unwrap();

        let out = run_with_stdin(
            &dir,
            &[
                "write",
                "-c",
                "c.png",
                "-t",
                "fallback",
                "--strategy",
                "ask",
            ],
            answer,
        );
        assert_eq!(code(&out), 0, "{label}: stderr: {}", stderr(&out));
        assert!(
            stdout(&out).contains("using strategy 'chunk'"),
            "{label} must fall back to the first strategy (chunk): {}",
            stdout(&out)
        );
        // chunk embeds before IEND: the file must NOT end with the envelope.
        let read = read_carrier(&dir.join("c.png"), None, None).expect("read");
        assert_eq!(read.data, b"fallback");
        let restored = dir.join("restored.png");
        remove_carrier(&dir.join("c.png"), Some(&restored), None, false).expect("remove");
        assert_eq!(fs::read(&restored).unwrap(), make_png());
    }
}

#[test]
fn strategy_ask_empty_answer_defaults_to_first() {
    let dir = scratch("ask_empty");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let out = run_with_stdin(
        &dir,
        &["write", "-c", "c.png", "-t", "x", "--strategy", "ask"],
        b"\n",
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("using strategy 'chunk'"),
        "stdout: {}",
        stdout(&out)
    );
}

// --------------------------------------------------------------------------- misc engine branch

#[test]
fn read_encrypted_without_password_returns_password_variant_with_hint() {
    let dir = scratch("read_hint");
    let carrier = dir.join("c.png");
    fs::write(&carrier, make_png()).unwrap();
    let out = dir.join("o.png");
    write_carrier(
        &carrier,
        PayloadSource::Text("secret"),
        &WriteOptions {
            output_path: Some(&out),
            password: Some("pw"),
            password_hint: Some("3班1975"),
            backup: false,
            ..Default::default()
        },
    )
    .expect("write");

    let err = read_carrier(&out, None, None).unwrap_err();
    assert!(
        matches!(err, StrHideError::Password(_)),
        "expected Password variant, got {err:?}"
    );
    assert!(err.to_string().contains("3班1975"), "{err}");

    // inspect without the password still shows the hint (metadata encrypted).
    let insp = inspect_carrier(&out, None).expect("inspect");
    assert!(insp.has_hidden_data);
    assert_eq!(insp.password_hint.as_deref(), Some("3班1975"));
}
