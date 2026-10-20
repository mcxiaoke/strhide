//! Config file support tests (--config / strhide.toml discovery and
//! precedence: CLI args > STRHIDE_PASSWORD env > config file > built-ins).

use crate::common::*;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

/// Run the binary inside `dir` with STRHIDE_PASSWORD cleared unless
/// `env_password` says otherwise.
fn run(dir: &PathBuf, args: &[&str], env_password: Option<&str>) -> Output {
    let mut cmd = Command::new(bin());
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
    fs::write(dir.join("strhide.toml"), "strategy = [broken\n").unwrap();
    let out = run(&dir, &["list"], None);
    assert_eq!(code(&out), 1);
    assert!(
        stderr(&out).contains("Invalid TOML"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn unknown_key_warns_but_does_not_fail() {
    let dir = scratch("unknown");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("strhide.toml"), "pasword = \"x\"\n").unwrap();
    let out = run(&dir, &["list"], None);
    assert_eq!(code(&out), 0);
    assert!(
        stderr(&out).contains("Unknown key 'pasword'"),
        "stderr: {}",
        stderr(&out)
    );
}

// --------------------------------------------------------------------------- defaults and precedence

#[test]
fn config_password_and_encrypt_apply_on_write_and_read() {
    let dir = scratch("write_read");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(
        dir.join("strhide.toml"),
        "encrypt = true\npassword = \"cfg-pass-1\"\n",
    )
    .unwrap();

    // Write with no CLI password/encrypt flags: both come from the config.
    let out = run(&dir, &["write", "c.png", "-t", "hello"], None);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    // Read without any password: the config supplies it.
    let out = run(&dir, &["read", "c.png", "-o", "out1.bin"], None);
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert_eq!(fs::read_to_string(dir.join("out1.bin")).unwrap(), "hello");

    // An explicit CLI password equal to the config one still works.
    let out = run(
        &dir,
        &["read", "c.png", "-p", "cfg-pass-1", "-o", "out2.bin"],
        None,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    // A wrong CLI password fails even though the config holds the right one.
    let out = run(
        &dir,
        &["read", "c.png", "-p", "wrong", "-o", "out3.bin"],
        None,
    );
    assert_eq!(code(&out), 1);
    assert!(stderr(&out).contains("assword"), "stderr: {}", stderr(&out));
}

#[test]
fn env_password_overrides_config_password() {
    let dir = scratch("env");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(
        dir.join("strhide.toml"),
        "encrypt = true\npassword = \"cfg-pass-1\"\n",
    )
    .unwrap();

    // Write with the env password (wins over the config password).
    let out = run(&dir, &["write", "c.png", "-t", "hello"], Some("env-pass-2"));
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    // Reading with only the config password fails (it is the wrong password).
    let out = run(&dir, &["read", "c.png", "-o", "o1.bin"], None);
    assert_eq!(code(&out), 1);

    // Reading with the env password succeeds.
    let out = run(&dir, &["read", "c.png", "-o", "o2.bin"], Some("env-pass-2"));
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert_eq!(fs::read_to_string(dir.join("o2.bin")).unwrap(), "hello");
}

#[test]
fn explicit_config_path_applies() {
    let dir = scratch("explicit");
    let cfg_dir = scratch("explicit_cfg");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(
        cfg_dir.join("custom.toml"),
        "encrypt = true\npassword = \"cfg-pass-3\"\n",
    )
    .unwrap();

    let cfg_arg = cfg_dir.join("custom.toml").to_str().unwrap().to_string();
    let out = run(
        &dir,
        &["--config", &cfg_arg, "write", "c.png", "-t", "hello"],
        None,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));

    let out = run(
        &dir,
        &["--config", &cfg_arg, "read", "c.png", "-o", "out.bin"],
        None,
    );
    assert_eq!(code(&out), 0, "stderr: {}", stderr(&out));
    assert_eq!(fs::read_to_string(dir.join("out.bin")).unwrap(), "hello");
}

#[test]
fn strategy_from_config_is_used_by_write() {
    let dir = scratch("strategy");
    fs::write(dir.join("c.png"), make_png()).unwrap();
    fs::write(dir.join("strhide.toml"), "strategy = \"bogus-strategy\"\n").unwrap();
    let out = run(&dir, &["write", "c.png", "-t", "hello"], None);
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
