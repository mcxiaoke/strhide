//! Config file support tests (--config / strhide.toml discovery and
//! precedence: CLI args > STRHIDE_PASSWORD env > config file > built-ins).

use crate::common::*;
use std::fs;
use std::path::PathBuf;
use std::process::Output;

/// Run the binary inside `dir` with STRHIDE_PASSWORD cleared unless
/// `env_password` says otherwise.
fn run(dir: &PathBuf, args: &[&str], env_password: Option<&str>) -> Output {
    let mut cmd = base_cmd();
    cmd.args(args)
        .current_dir(dir)
        .env("STRHIDE_PASSWORD", env_password.unwrap_or(""));
    cmd.output().expect("failed to run strhide binary")
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// --------------------------------------------------------------------------- lookup and errors

#[test]
fn explicit_missing_config_is_a_hard_error() {
    let dir = scratch("missing");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let out = run(&dir, &["--config", "nope.toml", "list"], None);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Failed to read config file"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn invalid_toml_is_a_hard_error() {
    let dir = scratch("invalid");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("bad.toml"), "strategy = [broken\n").unwrap();
    let out = run(&dir, &["--config", "bad.toml", "list"], None);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Invalid TOML"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cwd_config_is_ignored() {
    let dir = scratch("cwd_ignored");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    // In CWD, write invalid TOML and bogus strategy:
    fs::write(dir.join("strhide.toml"), "strategy = \"bogus\"\n").unwrap();
    // Running without --config in CWD must ignore ./strhide.toml:
    let out = run(&dir, &["list"], None);
    assert_eq!(code(&out), 0);
    assert!(!stderr(&out).contains("bogus"));
}

#[test]
fn unknown_nested_key_in_stego_section_warns() {
    // `[stego]` has its own key set and was not checked at all, so a typo like
    // `algoritm` silently left the default in force (review R2 P1-8).
    let dir = scratch("unknown_nested");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(
        dir.join("custom.toml"),
        "[stego]
algoritm = \"hill\"
",
    )
    .unwrap();
    let out = run(&dir, &["--config", "custom.toml", "list"], None);
    assert_eq!(code(&out), 0, "a warning must not fail the command");
    let err = stderr(&out);
    assert!(
        err.contains("[stego].algoritm"),
        "the warning must name the nested key, stderr: {err}"
    );
    // The correctly spelled key stays silent.
    fs::write(
        dir.join("ok.toml"),
        "[stego]
algorithm = \"hill\"
",
    )
    .unwrap();
    let out = run(&dir, &["--config", "ok.toml", "list"], None);
    assert_eq!(code(&out), 0);
    assert!(
        !stderr(&out).contains("Unknown key"),
        "a valid [stego] key must not warn: {}",
        stderr(&out)
    );
}

#[test]
fn unknown_key_warns_but_does_not_fail() {
    let dir = scratch("unknown");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("custom.toml"), "pasword = \"x\"\n").unwrap();
    let out = run(&dir, &["--config", "custom.toml", "list"], None);
    assert_eq!(code(&out), 0);
    assert!(
        stderr(&out).contains("Unknown key 'pasword'"),
        "stderr: {}",
        stderr(&out)
    );
}

// --------------------------------------------------------------------------- defaults and precedence

#[test]
fn config_password_keys_are_warned_and_not_used() {
    let dir = scratch("cfg_pwd_warn");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(
        dir.join("custom.toml"),
        "encrypt = true\npassword = \"cfg-pass-1\"\npassword_file = \"test.key\"\n",
    )
    .unwrap();

    let out = run(
        &dir,
        &[
            "--config",
            "custom.toml",
            "write",
            "c.png",
            "-t",
            "hello",
            "--in-place",
        ],
        None,
    );
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("Unknown key 'password'"));
    assert!(stderr(&out).contains("Unknown key 'password_file'"));
    assert!(stderr(&out).contains("Password required but no interactive terminal"));
}

#[test]
fn explicit_config_path_applies() {
    let dir = scratch("explicit");
    let cfg_dir = scratch("explicit_cfg");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(
        cfg_dir.join("custom.toml"),
        "hint = \"custom-cfg-hint\"\nbackup = false\n",
    )
    .unwrap();

    let cfg_arg = cfg_dir.join("custom.toml").to_str().unwrap().to_string();
    let out = run(
        &dir,
        &[
            "--config",
            &cfg_arg,
            "write",
            "c.png",
            "-t",
            "hello",
            "--in-place",
            "-p",
            "test-pass",
        ],
        None,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    // backup = false was applied:
    assert!(!dir.join("c.png.bak").exists());

    let out = run(
        &dir,
        &[
            "--config",
            &cfg_arg,
            "read",
            "c.png",
            "-o",
            "out.bin",
            "-p",
            "test-pass",
        ],
        None,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert_eq!(fs::read_to_string(dir.join("out.bin")).unwrap(), "hello");
}

#[test]
fn strategy_from_config_is_used_by_write() {
    let dir = scratch("strategy");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("custom.toml"), "strategy = \"bogus-strategy\"\n").unwrap();
    let out = run(
        &dir,
        &["--config", "custom.toml", "write", "c.png", "-t", "hello"],
        None,
    );
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("bogus-strategy"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn sample_config_file_parses_without_warnings_or_errors() {
    let sample_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("strhide.sample.toml");
    assert!(
        sample_path.exists(),
        "strhide.sample.toml must exist at repo root: {}",
        sample_path.display()
    );
    let dir = scratch("sample_cfg");
    let out = run(
        &dir,
        &["--config", sample_path.to_str().unwrap(), "list"],
        None,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        !stderr(&out).contains("[WARNING]"),
        "strhide.sample.toml must not trigger warnings, stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_version_flag_contains_git_hash_and_build_time() {
    let dir = scratch("version_test");
    let out = run(&dir, &["--version"], None);
    assert_eq!(code(&out), 0);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains("sth") || s.contains("strhide"),
        "version output: {s}"
    );
    assert!(s.contains("commit:"), "must contain commit hash: {s}");
    assert!(s.contains("built:"), "must contain built time: {s}");
}

#[test]
fn cli_normal_run_prints_banner_and_quiet_suppresses_it() {
    let dir = scratch("banner_test");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    // 1. Normal run (e.g. list or inspect) prints banner
    let out_list = run(&dir, &["list"], None);
    assert_eq!(code(&out_list), 0);
    let s_list = String::from_utf8_lossy(&out_list.stdout);
    assert!(
        (s_list.starts_with("sth ") || s_list.starts_with("strhide "))
            && s_list.contains("commit:")
            && s_list.contains("built:"),
        "list output must start with banner: {s_list}"
    );

    let out_inspect = run(&dir, &["inspect", "c.png"], None);
    assert_eq!(code(&out_inspect), 0);
    let s_inspect = String::from_utf8_lossy(&out_inspect.stdout);
    assert!(
        (s_inspect.starts_with("sth ") || s_inspect.starts_with("strhide "))
            && s_inspect.contains("commit:"),
        "inspect output must start with banner: {s_inspect}"
    );

    // 2. Quiet run (-q) must completely suppress banner and status output
    let out_quiet = run(&dir, &["inspect", "c.png", "-q"], None);
    assert_eq!(code(&out_quiet), 0);
    assert!(
        out_quiet.stdout.is_empty(),
        "quiet inspect must not print anything on stdout: {}",
        String::from_utf8_lossy(&out_quiet.stdout)
    );
    assert!(
        out_quiet.stderr.is_empty(),
        "quiet inspect must not print anything on stderr: {}",
        String::from_utf8_lossy(&out_quiet.stderr)
    );
}

#[test]
fn cli_json_run_embeds_banner_as_field_and_emits_valid_json() {
    let dir = scratch("banner_json_test");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    // Inspect --json
    let out_inspect = run(&dir, &["inspect", "c.png", "--json"], None);
    assert_eq!(code(&out_inspect), 0);
    let raw_inspect = String::from_utf8_lossy(&out_inspect.stdout);
    let v_inspect: serde_json::Value = serde_json::from_str(&raw_inspect)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON: {e}\n{raw_inspect}"));
    let banner_inspect = v_inspect["banner"]
        .as_str()
        .expect("inspect json must contain banner string");
    assert!(
        (banner_inspect.starts_with("sth ") || banner_inspect.starts_with("strhide "))
            && banner_inspect.contains("commit:")
            && banner_inspect.contains("built:"),
        "banner format: {banner_inspect}"
    );

    // Verify --json
    let out_verify = run(&dir, &["verify", "c.png", "--json"], None);
    let raw_verify = String::from_utf8_lossy(&out_verify.stdout);
    let v_verify: serde_json::Value = serde_json::from_str(&raw_verify)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON: {e}\n{raw_verify}"));
    let banner_verify = v_verify["banner"]
        .as_str()
        .expect("verify json must contain banner string");
    assert_eq!(banner_verify, banner_inspect);

    // Scan --json
    let out_scan = run(&dir, &["scan", "c.png", "--json"], None);
    assert_eq!(code(&out_scan), 0);
    let raw_scan = String::from_utf8_lossy(&out_scan.stdout);
    let v_scan: serde_json::Value = serde_json::from_str(&raw_scan)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON: {e}\n{raw_scan}"));
    assert!(v_scan.is_array());
    let banner_scan = v_scan[0]["banner"]
        .as_str()
        .expect("scan json item must contain banner string");
    assert_eq!(banner_scan, banner_inspect);
}

#[test]
fn loaded_config_path_printed_on_stdout_in_normal_mode() {
    let dir = scratch("cfg_print_normal");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let cfg_path = dir.join("my_config.toml");
    fs::write(&cfg_path, "backup = false\n").unwrap();

    let out = run(
        &dir,
        &["--config", cfg_path.to_str().unwrap(), "list"],
        None,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout_str.contains("Loaded config:"),
        "stdout must contain 'Loaded config:', got: {stdout_str}"
    );
    // Must contain absolute path (check filename and parent)
    assert!(
        stdout_str.contains("my_config.toml"),
        "stdout must mention config filename: {stdout_str}"
    );
}

#[test]
fn loaded_config_path_not_printed_in_json_mode() {
    let dir = scratch("cfg_print_json");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let cfg_path = dir.join("json_config.toml");
    fs::write(&cfg_path, "backup = false\n").unwrap();

    let out = run(
        &dir,
        &[
            "--config",
            cfg_path.to_str().unwrap(),
            "inspect",
            "c.png",
            "--json",
        ],
        None,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    // In JSON mode, loaded config path must NOT be printed to stderr or stdout
    let stderr_str = stderr(&out);
    assert!(
        !stderr_str.contains("Loaded config:"),
        "stderr must not contain 'Loaded config:' in json mode, got: {stderr_str}"
    );

    // Stdout MUST NOT contain 'Loaded config:' and MUST be valid JSON:
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout_str.contains("Loaded config:"),
        "stdout must not contain plain text in json mode: {stdout_str}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout_str)
        .unwrap_or_else(|e| panic!("stdout must be valid JSON: {e}\n{stdout_str}"));
    assert!(v.is_object());
}

#[test]
fn loaded_config_path_suppressed_when_quiet() {
    let dir = scratch("cfg_print_quiet");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    let cfg_path = dir.join("quiet_config.toml");
    fs::write(&cfg_path, "backup = false\n").unwrap();

    let out = run(
        &dir,
        &[
            "--config",
            cfg_path.to_str().unwrap(),
            "inspect",
            "c.png",
            "-q",
        ],
        None,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("Loaded config:"),
        "quiet mode must suppress stdout config line"
    );
    assert!(
        !stderr(&out).contains("Loaded config:"),
        "quiet mode must suppress stderr config line"
    );
}

#[test]
fn loaded_config_path_not_printed_when_no_config_exists() {
    let dir = scratch("cfg_none");
    fs::write(dir.join("c.png"), make_png()).unwrap();

    let out = run(&dir, &["list"], None);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("Loaded config:"),
        "stdout must not mention Loaded config when no config loaded"
    );
    assert!(
        !stderr(&out).contains("Loaded config:"),
        "stderr must not mention Loaded config when no config loaded"
    );
}
