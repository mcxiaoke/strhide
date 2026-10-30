//! Integration tests for the domain-specific CLI entry points
//! (`sthc`, `sths`, `sthv`).
//!
//! They are thin binaries over the same lib crate: each must expose only its
//! own command group, reject other groups, keep the shared global options, and
//! behave identically to the full `strhide <verb>` for the verbs it does have.

use crate::common::*;
use std::path::PathBuf;
use std::process::{Command, Output};

/// Resolve a domain binary next to the full `strhide` binary (all bins land in
/// the same target directory), avoiding assumptions about `CARGO_BIN_EXE_*`
/// naming for targets containing hyphens.
fn domain_bin(name: &str) -> PathBuf {
    // Referencing CARGO_BIN_EXE_* makes Cargo build that bin for integration
    // tests; option_env! keeps this a soft dependency in case a Cargo version
    // normalizes hyphenated target names differently.
    let direct = match name {
        "sthc" => option_env!("CARGO_BIN_EXE_sthc"),
        "sths" => option_env!("CARGO_BIN_EXE_sths"),
        "sthv" => option_env!("CARGO_BIN_EXE_sthv"),
        _ => None,
    };
    if let Some(p) = direct {
        return PathBuf::from(p);
    }

    // Fallback: every bin of the package lands in the same target directory.
    let exe = std::path::Path::new(bin());
    let file_name = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    exe.with_file_name(file_name)
}

fn run_domain(name: &str, args: &[&str]) -> Output {
    Command::new(domain_bin(name))
        .args(args)
        .env("STRHIDE_LANG", "en")
        .output()
        .unwrap_or_else(|e| panic!("run {name}: {e}"))
}

#[test]
fn domain_help_lists_only_its_own_commands() {
    let cases: &[(&str, &[&str], &[&str])] = &[
        (
            "sthc",
            &["write", "read", "restore"],
            &["embed", "inspect", "list"],
        ),
        (
            "sths",
            &["embed", "extract", "capacity"],
            &["write", "read", "scan"],
        ),
        (
            "sthv",
            &["inspect", "verify", "scan", "list"],
            &["write", "embed", "restore"],
        ),
    ];

    for &(bin, present, absent) in cases {
        let out = run_domain(bin, &["--help"]);
        assert!(out.status.success(), "{bin}: {:?}", out.status);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&format!("Usage: {bin} [OPTIONS] <COMMAND>")),
            "{bin}: wrong usage line\n{stdout}"
        );
        for cmd in present {
            assert!(
                stdout.contains(*cmd),
                "{bin}: missing own command {cmd}\n{stdout}"
            );
        }
        for cmd in absent {
            // Match a whole command row ("  write ") so substrings such as
            // "read" inside "restore" cannot produce a false positive.
            let row = format!("  {cmd} ");
            assert!(
                !stdout.contains(row.as_str()),
                "{bin}: unexpectedly exposes {cmd}\n{stdout}"
            );
        }
    }
}

#[test]
fn domain_rejects_cross_domain_subcommand() {
    let cases: &[(&str, &str)] = &[("sthc", "embed"), ("sths", "write"), ("sthv", "restore")];

    for &(bin, cmd) in cases {
        let out = run_domain(bin, &[cmd]);
        assert!(!out.status.success(), "{bin} accepted {cmd}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("unrecognized subcommand"),
            "{bin} {cmd}: unexpected error\n{stderr}"
        );
    }
}

#[test]
fn domain_version_uses_its_own_name() {
    for bin in ["sthc", "sths", "sthv"] {
        let out = run_domain(bin, &["--version"]);
        assert!(out.status.success(), "{bin}: {:?}", out.status);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.starts_with(&format!("{bin} ")),
            "{bin}: banner does not use its own name\n{stdout}"
        );
        assert!(stdout.contains("commit:"), "{bin}: {stdout}");
    }
}

#[test]
fn domain_help_honours_lang_and_global_options() {
    // i18n must localize the domain root too (about + shared global options).
    let out = run_domain("sths", &["--lang", "zh", "--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("格式保持、无损数据隐藏与智能隐写工具"),
        "domain root about not localized\n{stdout}"
    );
    assert!(
        stdout.contains("配置文件路径"),
        "shared global option help not localized\n{stdout}"
    );

    // -q/--quiet is a shared global option and must be accepted everywhere.
    let quiet = run_domain("sthc", &["-q", "list"]);
    // `list` is not part of the struct domain, but -q itself must parse; the
    // failure (if any) must be about the subcommand, not about -q.
    let stderr = String::from_utf8_lossy(&quiet.stderr);
    assert!(
        !stderr.contains("unexpected argument '-q'"),
        "shared -q rejected\n{stderr}"
    );
}

#[test]
fn domain_and_full_entry_share_behaviour() {
    // `list --json` is read-only and deterministic: both entry points route
    // through the same handler and must produce byte-identical output.
    let full = base_cmd()
        .args(["list", "--json"])
        .output()
        .expect("run strhide");
    let domain = run_domain("sthv", &["list", "--json"]);
    assert_eq!(full.status.code(), domain.status.code());
    assert_eq!(
        full.stdout, domain.stdout,
        "domain and full entry must render the same JSON"
    );
}
