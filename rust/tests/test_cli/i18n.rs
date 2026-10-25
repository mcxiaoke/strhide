//! Integration tests for internationalization (i18n) and bilingual support.

use crate::common::*;
use clap::CommandFactory;
use std::fs;
use std::process::Command;
use strhide::cli::Cli;
use strhide::cli_i18n;
use strhide::i18n::Lang;

#[test]
fn cli_root_help_renders_chinese() {
    let out = Command::new(bin())
        .args(["--lang", "zh", "--help"])
        .output()
        .expect("run strhide");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("格式保持、无损数据隐藏与智能隐写工具"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("向载体文件中隐藏机密数据"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("配置文件路径"), "stdout: {stdout}");
}

#[test]
fn cli_no_args_renders_localized_help_with_missing_subcommand_code() {
    let out = Command::new(bin())
        .env("STRHIDE_LANG", "zh")
        .output()
        .expect("run strhide");
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("格式保持、无损数据隐藏与智能隐写工具"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_subcommand_after_help_renders_chinese() {
    let out = Command::new(bin())
        .args(["--lang", "zh", "write", "--help"])
        .output()
        .expect("run strhide");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("数据来源选项互斥"), "stdout: {stdout}");
    assert!(
        stdout.contains("写入新文件 photo-out.png"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("用于隐藏数据的载体文件"),
        "stdout: {stdout}"
    );
}

#[test]
fn env_var_lang_selection_and_flag_precedence() {
    // 1. Env STRHIDE_LANG=zh takes effect
    let out_zh = Command::new(bin())
        .arg("--help")
        .env("STRHIDE_LANG", "zh")
        .output()
        .expect("run strhide");
    let stdout_zh = String::from_utf8_lossy(&out_zh.stdout);
    assert!(
        stdout_zh.contains("格式保持、无损数据隐藏与智能隐写工具"),
        "env zh failed: {stdout_zh}"
    );

    // 2. CLI flag `--lang en` overrides STRHIDE_LANG=zh
    let out_en = Command::new(bin())
        .args(["--lang", "en", "--help"])
        .env("STRHIDE_LANG", "zh")
        .output()
        .expect("run strhide");
    let stdout_en = String::from_utf8_lossy(&out_en.stdout);
    assert!(
        stdout_en.contains("Format-preserving lossless data hiding and steganography tool"),
        "flag en override failed: {stdout_en}"
    );
}

#[test]
fn chinese_error_category_prefix_on_failure() {
    let dir = scratch("i18n_err");
    let bad_file = dir.join("not_a_carrier.txt");
    fs::write(&bad_file, b"random plain text that is not a valid carrier").unwrap();

    let out = Command::new(bin())
        .args(["--lang", "zh", "read", bad_file.to_str().unwrap()])
        .output()
        .expect("run strhide");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("[ERROR] 不支持的文件格式:"),
        "stderr should contain translated error category: {stderr}"
    );
}

#[test]
fn json_output_remains_machine_readable_in_chinese_mode() {
    let dir = scratch("i18n_json");
    let png = dir.join("clean.png");
    fs::write(&png, make_png()).unwrap();

    let out = Command::new(bin())
        .args(["--lang", "zh", "scan", png.to_str().unwrap(), "--json"])
        .output()
        .expect("run strhide");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let val: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(val.is_array());
    assert_eq!(val[0]["verdict"], "clean");
}

#[test]
fn invalid_lang_flag_is_rejected_by_clap() {
    let out = Command::new(bin())
        .args(["--lang", "unsupported_lang", "--help"])
        .output()
        .expect("run strhide");
    assert!(!out.status.success());
}

#[test]
fn test_command_tree_localization_completeness() {
    let mut cmd = Cli::command();
    cmd = cli_i18n::localize(cmd, Lang::Zh);

    // Verify root
    assert!(cmd.get_about().is_some());

    // Verify all subcommands have localized about and arguments
    for sub in cmd.get_subcommands() {
        assert!(
            sub.get_about().is_some(),
            "Subcommand '{}' missing about text",
            sub.get_name()
        );
        for arg in sub.get_arguments() {
            assert!(
                arg.get_help().is_some(),
                "Subcommand '{}' arg '{}' missing help text",
                sub.get_name(),
                arg.get_id()
            );
        }
    }
}

fn walk_help_guard(cmd: &clap::Command, path: &str, failures: &mut Vec<String>) {
    let name = if path.is_empty() {
        cmd.get_name().to_string()
    } else {
        format!("{path} {}", cmd.get_name())
    };

    if cmd
        .get_about()
        .map(|t| t.to_string().is_empty())
        .unwrap_or(true)
    {
        failures.push(format!("{name}: empty about"));
    }
    for arg in cmd.get_arguments() {
        if arg.is_hide_set() {
            continue;
        }
        let help = arg.get_help().or_else(|| arg.get_long_help());
        match help {
            None => failures.push(format!("{name}: argument --{} has no help", arg.get_id())),
            Some(h) if h.to_string().is_empty() => failures.push(format!(
                "{name}: argument --{} has empty help",
                arg.get_id()
            )),
            _ => {}
        }
    }
    for sub in cmd.get_subcommands() {
        walk_help_guard(sub, &name, failures);
    }
}

#[test]
fn every_localized_argument_has_non_empty_help() {
    for lang in [Lang::En, Lang::Zh] {
        let cmd = cli_i18n::localize(Cli::command(), lang);
        let mut failures = Vec::new();
        walk_help_guard(&cmd, "", &mut failures);
        assert!(
            failures.is_empty(),
            "localized({lang:?}) help gaps: {failures:#?}"
        );
    }
}
