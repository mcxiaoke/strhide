use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use tauri::async_runtime::block_on;
use tauri::ipc::Channel;

use strhide_gui_lib::commands::PayloadInputDto;
use strhide_gui_lib::commands::diag::inspect_carrier_impl;
use strhide_gui_lib::commands::stego::{
    StegoEmbedRequest, embed_stego_file_impl, smart_extract_impl,
};
use strhide_gui_lib::commands::structure::{
    StructureWriteRequest, read_structure_file_impl, restore_structure_file_impl,
    write_structure_file_impl,
};
use strhide_gui_lib::state::GuiState;

fn find_cli_bin() -> PathBuf {
    if let Ok(p) = std::env::var("STRHIDE_CLI_PATH") {
        let path = PathBuf::from(p);
        if path.exists() {
            return path;
        }
    }
    let candidates = [
        "rust/target/debug/strhide.exe",
        "rust/target/release/strhide.exe",
        "target/debug/strhide.exe",
        "target/release/strhide.exe",
        "../../rust/target/debug/strhide.exe",
        "../../rust/target/release/strhide.exe",
        "../../target/debug/strhide.exe",
        "../../target/release/strhide.exe",
        "rust/target/debug/strhide",
        "rust/target/release/strhide",
        "target/debug/strhide",
        "target/release/strhide",
        "../../rust/target/debug/strhide",
        "../../rust/target/release/strhide",
        "../../target/debug/strhide",
        "../../target/release/strhide",
    ];
    for c in &candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return fs::canonicalize(&p).unwrap_or(p);
        }
    }
    panic!("strhide CLI binary not found. Please compile the CLI first.");
}

fn find_carrier(name: &str) -> PathBuf {
    let candidates = [
        format!("rust/tests/fixtures/{name}"),
        format!("rust/tests/assets/{name}"),
        format!("../../rust/tests/fixtures/{name}"),
        format!("../../rust/tests/assets/{name}"),
        format!("temp/jpgtest/{name}"),
        format!("../../temp/jpgtest/{name}"),
    ];
    for c in &candidates {
        let p = PathBuf::from(c);
        if p.exists() {
            return fs::canonicalize(&p).unwrap_or(p);
        }
    }
    panic!("Carrier asset '{name}' not found");
}

fn temp_dir(prefix: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("strhide_cross_{prefix}_{now}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn noop_channel<T: Send + 'static>() -> Channel<T> {
    Channel::new(|_| Ok(()))
}

// =========================================================================
// 1. 内容隐写交叉验证（Content Domain Cross-Validation）
// =========================================================================

#[test]
fn test_cross_content_gui_embed_cli_extract_chinese() {
    block_on(async {
        let cli = find_cli_bin();
        let carrier_src = find_carrier("art002e004437~large.jpg");
        let state = GuiState::default();
        let dir = temp_dir("gui_embed_cn");

        let carrier = dir.join("carrier.jpg");
        let stego = dir.join("carrier_stego.jpg");
        fs::copy(&carrier_src, &carrier).unwrap();

        let chinese_payload = "根据目前公开信息，这项“禁止复刻特定现有游戏”的限制仅明确针对 Opus 5.5 模型中的 Claude Code。Anthropic 表示，他们在 Opus 5.5 的 Claude Code 提示词中加入了“两句引导内容”，让模型避免重现他人特定游戏。报道并未说明 Anthropic 已将同样规则推广到其他 Claude 模型或所有 Claude Code 版本。";
        let chinese_password = "根据目前公开信息";

        // 1. GUI 模拟调用 embed_stego_file_impl
        let req = StegoEmbedRequest {
            carrier: carrier.clone(),
            payload: PayloadInputDto::Text {
                content: chinese_payload.to_string(),
            },
            output_path: Some(stego.clone()),
            password: Some(chinese_password.to_string()),
            domain: None, // 严格验证必须为 None（对应前端修复后的 undefined）
            safety_level: strhide::stego::SafetyLevel::High,
            enforce_safety: false,
            algorithm: None,
            backup: false,
            overwrite: true,
        };

        let embed_res =
            embed_stego_file_impl(&state, "task-embed-cn".into(), req, noop_channel()).await;
        assert!(embed_res.is_ok(), "GUI embed failed: {:?}", embed_res.err());

        // 2. CLI 命令行调用 extract 提取该文件
        let output = Command::new(&cli)
            .arg("extract")
            .arg(&stego)
            .arg("-p")
            .arg(chinese_password)
            .arg("--stdout")
            .output()
            .expect("failed to run CLI extract");

        assert!(
            output.status.success(),
            "CLI extract failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let extracted_text = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            extracted_text.trim(),
            chinese_payload.trim(),
            "Extracted text must match original Chinese payload byte-for-byte"
        );

        // 3. CLI 命令行调用 inspect 验证双域扫描识别 content stego
        let inspect_out = Command::new(&cli)
            .arg("inspect")
            .arg(&stego)
            .output()
            .expect("failed to run CLI inspect");
        let stdout = String::from_utf8_lossy(&inspect_out.stdout);
        assert!(
            stdout.contains("Content-Adaptive Steganography")
                || stdout.contains("UERD")
                || stdout.contains("JPEG"),
            "CLI inspect should recognize content stego: {stdout}"
        );

        let _ = fs::remove_dir_all(&dir);
    });
}

#[test]
fn test_cross_content_cli_embed_gui_extract() {
    block_on(async {
        let cli = find_cli_bin();
        let carrier_src = find_carrier("carrier.jpg");
        let state = GuiState::default();
        let dir = temp_dir("cli_embed_gui_extract");

        let carrier = dir.join("carrier.jpg");
        let stego = dir.join("carrier_stego.jpg");
        fs::copy(&carrier_src, &carrier).unwrap();

        let secret_text = "Cross validation payload from CLI to GUI!";
        let secret_pwd = "pwd123456_test";

        // 1. CLI 命令行写入
        let cli_res = Command::new(&cli)
            .arg("embed")
            .arg(&carrier)
            .arg("-t")
            .arg(secret_text)
            .arg("-p")
            .arg(secret_pwd)
            .arg("-o")
            .arg(&stego)
            .output()
            .expect("failed to run CLI embed");
        assert!(
            cli_res.status.success(),
            "CLI embed failed: {}",
            String::from_utf8_lossy(&cli_res.stderr)
        );

        // 2. GUI smart_extract 提取
        let extract_res = smart_extract_impl(
            &state,
            "task-smart-extract".into(),
            stego.clone(),
            None, // 内存预览
            Some(secret_pwd.to_string()),
            None,
            Some(strhide::facade::Domain::Content),
            false,
            noop_channel(),
        )
        .await;

        assert!(
            extract_res.is_ok(),
            "GUI smart_extract failed: {:?}",
            extract_res.err()
        );
        let outcome = extract_res.unwrap();
        assert_eq!(outcome.source, strhide::facade::Domain::Content);
        assert_eq!(outcome.summary.text_preview.as_deref(), Some(secret_text));

        // 3. GUI inspect_carrier 验证
        let inspect_res =
            inspect_carrier_impl(&state, stego.clone(), Some(secret_pwd.to_string()), None).await;
        assert!(
            inspect_res.is_ok(),
            "GUI inspect failed: {:?}",
            inspect_res.err()
        );
        let dual = inspect_res.unwrap();
        assert!(dual.content.is_some(), "content stego should be present");
        assert!(dual.content.unwrap().has_hidden_data);

        let _ = fs::remove_dir_all(&dir);
    });
}

// =========================================================================
// 2. 结构隐写交叉验证（Structure Domain Cross-Validation）
// =========================================================================

#[test]
fn test_cross_structure_gui_write_cli_read_and_restore() {
    block_on(async {
        let cli = find_cli_bin();
        let carrier_src = find_carrier("carrier.png");
        let state = GuiState::default();
        let dir = temp_dir("gui_write_struct");

        let carrier = dir.join("carrier.png");
        let hidden = dir.join("carrier_hidden.png");
        fs::copy(&carrier_src, &carrier).unwrap();
        let orig_bytes = fs::read(&carrier).unwrap();

        let payload_content = "Structure hidden message via GUI backend";
        let password = "struct_secret_password";
        let hint = "remember me";

        // 1. GUI 写入结构域
        let req = StructureWriteRequest {
            carrier: carrier.clone(),
            payload: PayloadInputDto::Text {
                content: payload_content.to_string(),
            },
            output_path: Some(hidden.clone()),
            password: Some(password.to_string()),
            password_hint: Some(hint.to_string()),
            strategy: None,
            stealth: false,
            preserve_time: true,
            backup: false,
            overwrite: true,
        };

        let write_res =
            write_structure_file_impl(&state, "task-write-struct".into(), req, noop_channel())
                .await;
        assert!(
            write_res.is_ok(),
            "GUI write_structure failed: {:?}",
            write_res.err()
        );

        // 2. CLI 命令行调用 read 读取载荷
        let read_out = Command::new(&cli)
            .arg("read")
            .arg(&hidden)
            .arg("-p")
            .arg(password)
            .arg("--stdout")
            .output()
            .expect("failed to run CLI read");

        assert!(
            read_out.status.success(),
            "CLI read failed: {}",
            String::from_utf8_lossy(&read_out.stderr)
        );
        let read_text = String::from_utf8_lossy(&read_out.stdout);
        assert_eq!(read_text.trim(), payload_content.trim());

        // 3. CLI 命令行调用 restore 还原原始文件
        let restore_out = Command::new(&cli)
            .arg("restore")
            .arg(&hidden)
            .arg("-p")
            .arg(password)
            .arg("--in-place")
            .arg("--no-backup")
            .output()
            .expect("failed to run CLI restore");

        assert!(
            restore_out.status.success(),
            "CLI restore failed: {}",
            String::from_utf8_lossy(&restore_out.stderr)
        );
        let restored_bytes = fs::read(&hidden).unwrap();
        assert_eq!(
            restored_bytes, orig_bytes,
            "Carrier restored by CLI must be bit-for-bit identical to original"
        );

        let _ = fs::remove_dir_all(&dir);
    });
}

#[test]
fn test_cross_structure_cli_write_gui_read_and_restore() {
    block_on(async {
        let cli = find_cli_bin();
        let carrier_src = find_carrier("carrier.png");
        let state = GuiState::default();
        let dir = temp_dir("cli_write_gui_read");

        let carrier = dir.join("carrier.png");
        let hidden = dir.join("carrier_hidden.png");
        fs::copy(&carrier_src, &carrier).unwrap();
        let orig_bytes = fs::read(&carrier).unwrap();

        let payload_content = "Payload written by CLI tool";
        let password = "cli_write_pwd_999";

        // 1. CLI 命令行写入结构域
        let cli_res = Command::new(&cli)
            .arg("write")
            .arg(&carrier)
            .arg("-t")
            .arg(payload_content)
            .arg("-p")
            .arg(password)
            .arg("-o")
            .arg(&hidden)
            .output()
            .expect("failed to run CLI write");
        assert!(
            cli_res.status.success(),
            "CLI write failed: {}",
            String::from_utf8_lossy(&cli_res.stderr)
        );

        // 2. GUI 调用 read_structure_file_impl 读取
        let read_res = read_structure_file_impl(
            &state,
            "task-read-struct".into(),
            hidden.clone(),
            None, // 内存预览
            Some(password.to_string()),
            false,
            noop_channel(),
        )
        .await;

        assert!(
            read_res.is_ok(),
            "GUI read_structure failed: {:?}",
            read_res.err()
        );
        let summary = read_res.unwrap();
        assert_eq!(summary.text_preview.as_deref(), Some(payload_content));

        // 3. GUI 调用 restore_structure_file_impl 还原原文件
        let restored_path = dir.join("restored.png");
        let restore_res = restore_structure_file_impl(
            &state,
            "task-restore-struct".into(),
            hidden.clone(),
            Some(restored_path.clone()),
            Some(password.to_string()),
            false,
            true,
            noop_channel(),
        )
        .await;

        assert!(
            restore_res.is_ok(),
            "GUI restore_structure failed: {:?}",
            restore_res.err()
        );
        let restored_bytes = fs::read(&restored_path).unwrap();
        assert_eq!(
            restored_bytes, orig_bytes,
            "Carrier restored by GUI must be bit-for-bit identical to original"
        );

        let _ = fs::remove_dir_all(&dir);
    });
}

#[test]
fn test_cross_structure_stealth_mode_roundtrip() {
    block_on(async {
        let cli = find_cli_bin();
        let carrier_src = find_carrier("carrier.png");
        let state = GuiState::default();
        let dir = temp_dir("stealth_roundtrip");

        let carrier = dir.join("carrier.png");
        let hidden = dir.join("carrier_stealth.png");
        fs::copy(&carrier_src, &carrier).unwrap();
        let orig_bytes = fs::read(&carrier).unwrap();

        let payload_content = "Confidential stealth payload";
        let password = "super_stealth_secret";

        // 1. GUI 开启无痕隐蔽模式（stealth: true）写入
        let req = StructureWriteRequest {
            carrier: carrier.clone(),
            payload: PayloadInputDto::Text {
                content: payload_content.to_string(),
            },
            output_path: Some(hidden.clone()),
            password: Some(password.to_string()),
            password_hint: None,
            strategy: None,
            stealth: true,
            preserve_time: true,
            backup: false,
            overwrite: true,
        };

        let write_res =
            write_structure_file_impl(&state, "task-stealth".into(), req, noop_channel()).await;
        assert!(
            write_res.is_ok(),
            "GUI write stealth failed: {:?}",
            write_res.err()
        );

        // 2. CLI 命令行调用 read 读取隐蔽模式
        let read_out = Command::new(&cli)
            .arg("read")
            .arg(&hidden)
            .arg("-p")
            .arg(password)
            .arg("--stdout")
            .output()
            .expect("failed to run CLI read");

        assert!(
            read_out.status.success(),
            "CLI read stealth failed: {}",
            String::from_utf8_lossy(&read_out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&read_out.stdout).trim(),
            payload_content
        );

        // 3. CLI 命令行调用 restore 还原
        let restore_out = Command::new(&cli)
            .arg("restore")
            .arg(&hidden)
            .arg("-p")
            .arg(password)
            .arg("--in-place")
            .arg("--no-backup")
            .output()
            .expect("failed to run CLI restore");
        assert!(restore_out.status.success());
        assert_eq!(fs::read(&hidden).unwrap(), orig_bytes);

        let _ = fs::remove_dir_all(&dir);
    });
}
