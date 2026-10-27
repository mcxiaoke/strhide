//! Tests for CLI parameter unification:
//! - Default output `<stem>-out.<ext>` (original untouched, output populated)
//! - `--overwrite` protection (refuses overwrite unless specified)
//! - `--in-place` explicit flag
//! - `inspect` and `verify` multi-file (`Vec<PathBuf>`) and directory (`-r`) support
//! - `extract --stdout` and `--overwrite`
//! - `list --json` machine-readable output
//! - `embed` multi-carrier batch support
//! - Global `-c, --config` short option

use crate::common::*;
use std::fs;
use std::path::Path;
use std::process::Output;

fn seed(dir: &Path, names: &[&str]) {
    for name in names {
        fs::write(dir.join(name), make_png()).unwrap();
    }
}

fn make_stego_png() -> Vec<u8> {
    let w = 128;
    let h = 128;
    let mut pixels = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            let r = ((x * 17) ^ (y * 31) ^ ((x + y) * 7)) as u8;
            let g = ((x * 23 + y * 19) % 256) as u8;
            let b = ((x * 13) ^ (y * 29)) as u8;
            pixels.push(r);
            pixels.push(g);
            pixels.push(b);
        }
    }
    let img = strhide::stego::png::RawImage {
        width: w,
        height: h,
        channels: 3,
        pixels,
        chunks: Vec::new(),
        idat_sizes: Vec::new(),
        row_filters: Vec::new(),
        idat_info: None,
        tail: Vec::new(),
    };
    strhide::stego::png::encode_png(&img).expect("encode png")
}

fn seed_stego(dir: &Path, names: &[&str]) {
    let png = make_stego_png();
    for name in names {
        fs::write(dir.join(name), &png).unwrap();
    }
}

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

#[test]
fn write_default_output_naming_and_integrity() {
    let dir = scratch("unify_write_default");
    seed(&dir, &["sample.png"]);
    let original_bytes = fs::read(dir.join("sample.png")).unwrap();

    let out = run(
        &dir,
        &["write", "sample.png", "-t", "hello world", "--no-backup"],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    // Original file must remain 100% untouched
    let current_bytes = fs::read(dir.join("sample.png")).unwrap();
    assert_eq!(
        original_bytes, current_bytes,
        "original sample.png was modified!"
    );

    // Default output file 'sample-out.png' must exist and have the hidden payload
    let out_file = dir.join("sample-out.png");
    assert!(out_file.exists(), "sample-out.png was not created");

    let read_out = run(&dir, &["read", "sample-out.png", "--stdout"]);
    assert_eq!(code(&read_out), 0, "stderr: {}", stderr(&read_out));
    assert_eq!(stdout(&read_out), "hello world");
}

#[test]
fn write_refuses_to_overwrite_existing_file_without_flag() {
    let dir = scratch("unify_write_overwrite");
    seed(&dir, &["sample.png"]);
    // Pre-create sample-out.png
    fs::write(dir.join("sample-out.png"), b"already exists").unwrap();

    let out = run(&dir, &["write", "sample.png", "-t", "secret"]);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Refusing to overwrite existing file 'sample-out.png'"),
        "stderr: {}",
        stderr(&out)
    );
    // Pre-existing file content unchanged
    assert_eq!(
        fs::read(dir.join("sample-out.png")).unwrap(),
        b"already exists"
    );

    // With --overwrite it succeeds
    let out_force = run(
        &dir,
        &["write", "sample.png", "-t", "secret", "--overwrite"],
    );
    assert_eq!(code(&out_force), 0, "stderr: {}", stderr(&out_force));
    let read_out = run(&dir, &["read", "sample-out.png", "--stdout"]);
    assert_eq!(stdout(&read_out), "secret");
}

#[test]
fn write_with_explicit_inplace_modifies_carrier() {
    let dir = scratch("unify_write_inplace");
    seed(&dir, &["sample.png"]);

    let out = run(
        &dir,
        &[
            "write",
            "sample.png",
            "-t",
            "in place text",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    assert!(
        !dir.join("sample-out.png").exists(),
        "sample-out.png should not exist"
    );

    let read_out = run(&dir, &["read", "sample.png", "--stdout"]);
    assert_eq!(code(&read_out), 0, "stderr: {}", stderr(&read_out));
    assert_eq!(stdout(&read_out), "in place text");
}

#[test]
fn restore_default_output_and_explicit_inplace() {
    let dir = scratch("unify_restore_default");
    seed(&dir, &["carrier.png"]);
    let original = fs::read(dir.join("carrier.png")).unwrap();

    // Write hidden data in-place
    let write = run(
        &dir,
        &[
            "write",
            "carrier.png",
            "-t",
            "payload",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(code(&write), 0, "stderr: {}", stderr(&write));

    // Restore without --in-place defaults to carrier-out.png
    let restore = run(&dir, &["restore", "carrier.png"]);
    assert_eq!(code(&restore), 0, "stderr: {}", stderr(&restore));

    let restored_file = dir.join("carrier-out.png");
    assert!(restored_file.exists(), "carrier-out.png was not created");
    assert_eq!(fs::read(&restored_file).unwrap(), original);

    // If carrier-out.png already exists, restore without --overwrite should fail
    let restore_fail = run(&dir, &["restore", "carrier.png"]);
    assert_eq!(code(&restore_fail), 1);
    assert!(
        stderr(&restore_fail).contains("Refusing to overwrite existing file"),
        "stderr: {}",
        stderr(&restore_fail)
    );

    // Restore with --overwrite succeeds
    let restore_force = run(&dir, &["restore", "carrier.png", "--overwrite"]);
    assert_eq!(code(&restore_force), 0);

    // Restore with --in-place modifies carrier.png in-place
    let restore_inplace = run(
        &dir,
        &["restore", "carrier.png", "--in-place", "--no-backup"],
    );
    assert_eq!(
        code(&restore_inplace),
        0,
        "stderr: {}",
        stderr(&restore_inplace)
    );
    assert_eq!(fs::read(dir.join("carrier.png")).unwrap(), original);
}

#[test]
fn inspect_multi_carrier_json_and_recursive() {
    let dir = scratch("unify_inspect_multi");
    seed(&dir, &["clean.png", "hidden.png"]);
    let sub = dir.join("sub");
    fs::create_dir_all(&sub).unwrap();
    seed(&sub, &["nested.png"]);

    // Write payload to hidden.png and nested.png
    run(
        &dir,
        &[
            "write",
            "hidden.png",
            "-t",
            "secret1",
            "--in-place",
            "--no-backup",
        ],
    );
    run(
        &sub,
        &[
            "write",
            "nested.png",
            "-t",
            "secret2",
            "--in-place",
            "--no-backup",
        ],
    );

    // Test multiple files -> JSON array
    let out = run(&dir, &["inspect", "clean.png", "hidden.png", "--json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON array");
    let arr = json.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["carrier"], "clean.png");
    assert_eq!(arr[0]["has_hidden_data"], false);
    assert_eq!(arr[1]["carrier"], "hidden.png");
    assert_eq!(arr[1]["has_hidden_data"], true);

    // Test recursive directory scan -> discovers both top-level and sub/
    let out_rec = run(&dir, &["inspect", ".", "-r", "--json"]);
    assert_eq!(code(&out_rec), 0, "stderr: {}", stderr(&out_rec));
    let json_rec: serde_json::Value =
        serde_json::from_str(&stdout(&out_rec)).expect("valid JSON array");
    let arr_rec = json_rec.as_array().expect("array");
    assert!(
        arr_rec.len() >= 3,
        "expected at least 3 carriers found recursively, got {}",
        arr_rec.len()
    );

    // Test single file -> keeps backwards-compatible single JSON object
    let out_single = run(&dir, &["inspect", "hidden.png", "--json"]);
    assert_eq!(code(&out_single), 0);
    let single_json: serde_json::Value =
        serde_json::from_str(&stdout(&out_single)).expect("single JSON object");
    assert!(single_json.is_object(), "single inspect must be an object");
    assert_eq!(single_json["carrier"], "hidden.png");
    assert_eq!(single_json["has_hidden_data"], true);
}

#[test]
fn verify_multi_carrier_json_and_recursive() {
    let dir = scratch("unify_verify_multi");
    seed(&dir, &["v1.png", "v2.png"]);
    let sub = dir.join("nested_v");
    fs::create_dir_all(&sub).unwrap();
    seed(&sub, &["v3.png"]);

    run(
        &dir,
        &[
            "write",
            "v1.png",
            "-t",
            "v1-data",
            "--in-place",
            "--no-backup",
        ],
    );
    run(
        &dir,
        &[
            "write",
            "v2.png",
            "-t",
            "v2-data",
            "--in-place",
            "--no-backup",
        ],
    );
    run(
        &sub,
        &[
            "write",
            "v3.png",
            "-t",
            "v3-data",
            "--in-place",
            "--no-backup",
        ],
    );

    // Multi-file verify --json -> JSON array (all valid carriers pass Level 2 -> exit code 0)
    let out = run(&dir, &["verify", "v1.png", "v2.png", "--json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let json: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("valid JSON array");
    let arr = json.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["carrier"], "v1.png");
    assert_eq!(arr[0]["level2_envelope"]["ok"], true);
    assert_eq!(arr[1]["carrier"], "v2.png");
    assert_eq!(arr[1]["level2_envelope"]["ok"], true);

    // If one carrier is clean (no envelope), verify exits 1 but still emits full JSON array
    fs::write(dir.join("clean.png"), make_png()).unwrap();
    let out_clean = run(&dir, &["verify", "v1.png", "clean.png", "--json"]);
    assert_eq!(code(&out_clean), 1, "clean file must fail verify check");
    let json_clean: serde_json::Value =
        serde_json::from_str(&stdout(&out_clean)).expect("valid JSON array");
    let arr_clean = json_clean.as_array().expect("array");
    assert_eq!(arr_clean.len(), 2);
    assert_eq!(arr_clean[0]["level2_envelope"]["ok"], true);
    assert_eq!(arr_clean[1]["level2_envelope"]["ok"], false);

    // Recursive directory verify
    let out_rec = run(&dir, &["verify", ".", "-r", "--json"]);
    let json_rec: serde_json::Value =
        serde_json::from_str(&stdout(&out_rec)).expect("valid JSON array");
    let arr_rec = json_rec.as_array().expect("array");
    assert!(arr_rec.len() >= 4);
}

#[test]
fn extract_stdout_and_overwrite() {
    let dir = scratch("unify_extract");
    seed_stego(&dir, &["carrier.png"]);
    let secret = "extracted secret content 12345";
    fs::write(dir.join("data.txt"), secret).unwrap();

    let embed = run(
        &dir,
        &[
            "embed",
            "carrier.png",
            "-d",
            "data.txt",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(code(&embed), 0, "stderr: {}", stderr(&embed));

    // extract --stdout
    let out_stdout = run(&dir, &["extract", "carrier.png", "--stdout"]);
    assert_eq!(code(&out_stdout), 0, "stderr: {}", stderr(&out_stdout));
    assert_eq!(stdout(&out_stdout), secret);

    // extract to file
    let out_file = run(&dir, &["extract", "carrier.png", "-o", "dump.txt"]);
    assert_eq!(code(&out_file), 0, "stderr: {}", stderr(&out_file));
    assert_eq!(fs::read_to_string(dir.join("dump.txt")).unwrap(), secret);

    // extract to existing file without --overwrite should fail
    let out_fail = run(&dir, &["extract", "carrier.png", "-o", "dump.txt"]);
    assert_eq!(code(&out_fail), 1);
    assert!(
        stderr(&out_fail).contains("Refusing to overwrite existing file 'dump.txt'"),
        "stderr: {}",
        stderr(&out_fail)
    );

    // extract to existing file with --overwrite should succeed
    let out_force = run(
        &dir,
        &["extract", "carrier.png", "-o", "dump.txt", "--overwrite"],
    );
    assert_eq!(code(&out_force), 0, "stderr: {}", stderr(&out_force));
}

#[test]
fn list_json_output() {
    let dir = scratch("unify_list_json");
    let out = run(&dir, &["list", "--json"]);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let json: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("valid JSON list output");
    let arr = json["formats"].as_array().expect("array of format entries");
    assert!(!arr.is_empty(), "format array must not be empty");

    let has_png = arr.iter().any(|f| f["format"] == "PNG");
    assert!(has_png, "PNG format must be in list --json output");
}

#[test]
fn embed_multi_carrier_and_default_naming() {
    let dir = scratch("unify_embed_multi");
    seed_stego(&dir, &["c1.png", "c2.png"]);
    let orig1 = fs::read(dir.join("c1.png")).unwrap();
    let orig2 = fs::read(dir.join("c2.png")).unwrap();
    fs::write(dir.join("file.bin"), b"binary payload").unwrap();

    let out = run(
        &dir,
        &["embed", "c1.png", "c2.png", "-d", "file.bin", "--no-backup"],
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    // Original files untouched
    assert_eq!(fs::read(dir.join("c1.png")).unwrap(), orig1);
    assert_eq!(fs::read(dir.join("c2.png")).unwrap(), orig2);

    // c1-out.png and c2-out.png created and extractable
    let ext1 = run(&dir, &["extract", "c1-out.png", "--stdout"]);
    assert_eq!(code(&ext1), 0, "stderr: {}", stderr(&ext1));
    assert_eq!(stdout(&ext1), "binary payload");

    let ext2 = run(&dir, &["extract", "c2-out.png", "--stdout"]);
    assert_eq!(code(&ext2), 0, "stderr: {}", stderr(&ext2));
    assert_eq!(stdout(&ext2), "binary payload");
}

#[test]
fn global_config_short_option() {
    let dir = scratch("unify_short_cfg");
    seed(&dir, &["carrier.png"]);
    fs::write(
        dir.join("custom.toml"),
        "hint = \"custom_short_cfg_hint\"\n",
    )
    .unwrap();

    let write = run(
        &dir,
        &[
            "write",
            "carrier.png",
            "-t",
            "secret",
            "-p",
            "mypass",
            "-c",
            "custom.toml",
            "--in-place",
        ],
    );
    assert_eq!(code(&write), 0, "stderr: {}", stderr(&write));

    let insp = run(&dir, &["inspect", "carrier.png", "--json"]);
    assert_eq!(code(&insp), 0);
    let json: serde_json::Value = serde_json::from_str(&stdout(&insp)).expect("valid json");
    assert_eq!(json["password_hint"], "custom_short_cfg_hint");
}

/// The stego credential flags were removed from the CLI surface: a private
/// no-password dialect is compile-time `Profile` territory, and the password
/// is the only credential the extract side must remember. The flags must be
/// rejected on every verb that used to accept them, and a no-password embed
/// must round-trip with no credentials at all.
#[test]
fn stego_credential_flags_are_rejected_and_no_password_roundtrips() {
    let dir = scratch("unify_stego_credential_flags_removed");
    seed_stego(&dir, &["carrier.png"]);
    let payload = "public constant payload 2026";
    fs::write(dir.join("data.txt"), payload).unwrap();

    for (verb, mut args) in [
        ("embed", vec!["embed", "carrier.png", "-d", "data.txt"]),
        ("extract", vec!["extract", "carrier.png", "--stdout"]),
        ("capacity", vec!["capacity", "carrier.png"]),
    ] {
        for flag in ["--stego-secret", "--stego-domain"] {
            args.push(flag);
            args.push("whatever");
            let out = run(&dir, &args);
            assert_eq!(
                code(&out),
                2,
                "{verb} must reject {flag}: stderr: {}",
                stderr(&out)
            );
        }
    }

    // No-password embed uses the public built-in constant...
    let embed = run(
        &dir,
        &[
            "embed",
            "carrier.png",
            "-d",
            "data.txt",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(code(&embed), 0, "stderr: {}", stderr(&embed));

    // ...so extraction needs no credential whatsoever.
    let ok = run(&dir, &["extract", "carrier.png", "--stdout"]);
    assert_eq!(code(&ok), 0, "stderr: {}", stderr(&ok));
    assert_eq!(stdout(&ok), payload);
}

/// `stego_secret` / `stego_domain` config keys and `STRHIDE_STEGO_SECRET` /
/// `STRHIDE_STEGO_DOMAIN` environment variables are no longer part of the CLI
/// surface: leftover config keys warn as unknown and are ignored, the env vars
/// are inert, and a no-password embed stays readable regardless of both.
#[test]
fn removed_stego_credential_sources_are_inert() {
    let dir = scratch("unify_stego_credential_sources_inert");
    seed_stego(&dir, &["carrier.png"]);
    let payload = "inert sources payload 2026";
    fs::write(dir.join("data.txt"), payload).unwrap();
    fs::write(
        dir.join("strhide.toml"),
        "stego_secret = \"leftover-secret\"\nstego_domain = \"leftover-domain\"\n",
    )
    .unwrap();

    // Embed ignores the leftover keys (unknown-key warning) and uses the
    // public constant.
    let embed = run(
        &dir,
        &[
            "embed",
            "carrier.png",
            "-d",
            "data.txt",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(code(&embed), 0, "stderr: {}", stderr(&embed));
    assert!(
        stderr(&embed).contains("stego_secret") && stderr(&embed).contains("stego_domain"),
        "leftover keys must be named in the unknown-key warning: {}",
        stderr(&embed)
    );

    // Extraction ignores the env vars too: the same public constant applies,
    // so the payload reads back with no credential at all.
    let out = base_cmd()
        .args(["extract", "carrier.png", "--stdout"])
        .current_dir(&dir)
        .env("USERPROFILE", &dir)
        .env("HOME", &dir)
        .env("STRHIDE_PASSWORD", "")
        .env("STRHIDE_STEGO_SECRET", "some-other-secret")
        .env("STRHIDE_STEGO_DOMAIN", "some-other-domain")
        .output()
        .expect("failed to run strhide binary");
    assert_eq!(
        code(&out),
        0,
        "env vars must be inert: stderr: {}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), payload);
}

/// Test CLI --safety and --enforce-safety flags on probe and embed.
#[test]
fn embed_safety_tiers_probe_and_enforcement() {
    let dir = scratch("unify_stego_safety");
    seed_stego(&dir, &["carrier.png"]);

    // 1. Capacity probe outputs selected safety tier and bpp
    let probe = run(
        &dir,
        &["embed", "carrier.png", "--capacity", "--safety", "paranoid"],
    );
    assert_eq!(code(&probe), 0, "stderr: {}", stderr(&probe));
    let out = stdout(&probe);
    assert!(
        out.contains("paranoid") && out.contains("0.06"),
        "probe output should reflect paranoid tier: {out}"
    );

    // 2. Large payload under paranoid with --enforce-safety is rejected
    let payload = vec![0x41u8; 800]; // exceeds paranoid capacity for small 128x128 carrier
    fs::write(dir.join("data.txt"), &payload).unwrap();

    let reject = run(
        &dir,
        &[
            "embed",
            "carrier.png",
            "-d",
            "data.txt",
            "--safety",
            "paranoid",
            "--enforce-safety",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(
        code(&reject),
        1,
        "Enforced safety must reject oversized payload"
    );
    assert!(
        stderr(&reject).contains("safety threshold"),
        "stderr: {}",
        stderr(&reject)
    );

    // 3. Same payload without --enforce-safety (Advisory) succeeds with warning
    let advise = run(
        &dir,
        &[
            "embed",
            "carrier.png",
            "-d",
            "data.txt",
            "--safety",
            "paranoid",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(
        code(&advise),
        0,
        "Advisory safety must succeed, stderr: {}",
        stderr(&advise)
    );
    assert!(
        stderr(&advise).contains("exceeds recommended safety threshold"),
        "stderr should warn: {}",
        stderr(&advise)
    );

    // 4. Extraction succeeds
    let ext = run(&dir, &["extract", "carrier.png", "-o", "extracted.bin"]);
    assert_eq!(code(&ext), 0, "stderr: {}", stderr(&ext));
    let extracted = fs::read(dir.join("extracted.bin")).unwrap();
    assert_eq!(extracted, payload);
}

/// `--seed` must make a content-domain embed byte-reproducible.
///
/// Without it the salt/nonce come from fresh randomness, so the same carrier
/// and payload never produce the same file twice — which is why the refactor
/// baseline harness (`scripts/baseline_hash.py`) drives every embed with a
/// fixed seed and compares the stego bytes, not just their size.
#[test]
fn embed_seed_is_reproducible_and_seed_dependent() {
    let dir = scratch("unify_embed_seed");
    seed_stego(&dir, &["a.png"]);

    const SEED: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const OTHER_SEED: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

    let embed = |out: &str, extra: &[&str]| {
        let mut args = vec![
            "embed",
            "a.png",
            "-t",
            "seed repro",
            "-o",
            out,
            "--no-backup",
            "--overwrite",
        ];
        args.extend_from_slice(extra);
        run(&dir, &args)
    };

    let first = embed("one.png", &["--seed", SEED]);
    assert_eq!(code(&first), 0, "stderr: {}", stderr(&first));
    let again = embed("two.png", &["--seed", SEED]);
    assert_eq!(code(&again), 0, "stderr: {}", stderr(&again));
    assert_eq!(
        fs::read(dir.join("one.png")).unwrap(),
        fs::read(dir.join("two.png")).unwrap(),
        "the same seed must produce a byte-identical carrier"
    );

    let other = embed("three.png", &["--seed", OTHER_SEED]);
    assert_eq!(code(&other), 0, "stderr: {}", stderr(&other));
    assert_ne!(
        fs::read(dir.join("one.png")).unwrap(),
        fs::read(dir.join("three.png")).unwrap(),
        "a different seed must produce a different carrier"
    );

    // A seeded carrier is still an ordinary carrier: extraction must work.
    let extract = run(&dir, &["extract", "one.png", "--stdout"]);
    assert_eq!(code(&extract), 0, "stderr: {}", stderr(&extract));
    assert_eq!(stdout(&extract).trim(), "seed repro");

    // A malformed seed is rejected instead of being silently padded/hashed.
    let bad = embed("four.png", &["--seed", "abc"]);
    assert_eq!(code(&bad), 1);
    assert!(
        stderr(&bad).contains("64 hex digits"),
        "stderr: {}",
        stderr(&bad)
    );
}

#[test]
fn dual_domain_inspect_and_verify() {
    let dir = scratch("dual_domain_inspect_verify");
    seed_stego(&dir, &["stego.png"]);

    let embed = run(
        &dir,
        &[
            "embed",
            "stego.png",
            "-t",
            "hello stego content",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(code(&embed), 0, "stderr: {}", stderr(&embed));

    // 1. Inspect human output
    let insp = run(&dir, &["inspect", "stego.png"]);
    assert_eq!(code(&insp), 0, "stderr: {}", stderr(&insp));
    let text = stdout(&insp);
    assert!(text.contains("Content Steganography Domain:"), "{text}");
    assert!(text.contains("Has Hidden Data: true"), "{text}");
    assert!(text.contains("Format: PNG"), "{text}");

    // 2. Inspect JSON output
    let insp_json = run(&dir, &["inspect", "stego.png", "--json"]);
    assert_eq!(code(&insp_json), 0, "stderr: {}", stderr(&insp_json));
    let val: serde_json::Value = serde_json::from_str(&stdout(&insp_json)).expect("parse json");
    assert_eq!(val["format"], "PNG");
    assert_eq!(val["content_stego"]["has_hidden_data"], true);
    assert!(val["content_stego"]["algorithm"].is_string());

    // 3. Verify human output (should pass for content stego!)
    let ver = run(&dir, &["verify", "stego.png"]);
    assert_eq!(
        code(&ver),
        0,
        "stdout: {}\nstderr: {}",
        stdout(&ver),
        stderr(&ver)
    );
    let ver_text = stdout(&ver);
    assert!(
        ver_text.contains("Content Steganography Domain Verification"),
        "{ver_text}"
    );
    assert!(ver_text.contains("Level 1"), "{ver_text}");
    assert!(ver_text.contains("Level 2"), "{ver_text}");
    assert!(ver_text.contains("Level 3"), "{ver_text}");

    // 4. Verify JSON output
    let ver_json = run(&dir, &["verify", "stego.png", "--json"]);
    assert_eq!(code(&ver_json), 0, "stderr: {}", stderr(&ver_json));
    let ver_val: serde_json::Value =
        serde_json::from_str(&stdout(&ver_json)).expect("parse verify json");
    assert!(ver_val["content_stego"].is_object());
}

#[test]
fn cross_domain_auto_fallback() {
    let dir = scratch("cross_domain_fallback");
    seed_stego(&dir, &["stego.png", "carrier.png"]);

    // 1. Prepare stego carrier
    let embed = run(
        &dir,
        &[
            "embed",
            "stego.png",
            "-t",
            "cross domain stego payload",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(code(&embed), 0, "stderr: {}", stderr(&embed));

    // Try `read` without --auto: fails with helpful hint
    let read_fail = run(&dir, &["read", "stego.png"]);
    assert_eq!(code(&read_fail), 1);
    let fail_err = stderr(&read_fail);
    assert!(
        fail_err.contains("detected content-adaptive steganography") && fail_err.contains("--auto"),
        "stderr: {fail_err}"
    );

    // Try `read --auto`: succeeds and outputs payload!
    let read_auto = run(&dir, &["read", "stego.png", "--auto", "--stdout"]);
    assert_eq!(code(&read_auto), 0, "stderr: {}", stderr(&read_auto));
    assert_eq!(stdout(&read_auto).trim(), "cross domain stego payload");

    // 2. Prepare structure hidden carrier
    let write = run(
        &dir,
        &[
            "write",
            "carrier.png",
            "-t",
            "cross domain struct payload",
            "--in-place",
            "--no-backup",
        ],
    );
    assert_eq!(code(&write), 0, "stderr: {}", stderr(&write));

    // Try `extract` without --auto: fails with helpful hint
    let extract_fail = run(&dir, &["extract", "carrier.png"]);
    assert_eq!(code(&extract_fail), 1);
    let ext_err = stderr(&extract_fail);
    assert!(
        ext_err.contains("detected structure-domain hidden data") && ext_err.contains("--auto"),
        "stderr: {ext_err}"
    );

    // Try `extract --auto`: succeeds and outputs payload!
    let extract_auto = run(&dir, &["extract", "carrier.png", "--auto", "--stdout"]);
    assert_eq!(code(&extract_auto), 0, "stderr: {}", stderr(&extract_auto));
    assert_eq!(stdout(&extract_auto).trim(), "cross domain struct payload");
}
