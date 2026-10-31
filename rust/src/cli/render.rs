// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Rendering: every place the CLI turns a result or an error into text.
//!
//! The only module that prints result lines, so a change to a result struct
//! lands in one file. `--json` output serializes the library structs directly.

use crate::core::i18n::{self, Msg};
use crate::errors::StrHideError;
use crate::structure::{RemoveResult, WriteResult};
use crate::t;

use super::args::BANNER;

pub fn print_error(e: &StrHideError) {
    // One renderer, shared with every other front end: `detail_i18n` returns the
    // structured parts and `render` applies the current language, so the CLI no
    // longer owns a private copy of the "[ERROR] prefix: detail" layout.
    eprintln!("{}", e.detail_i18n().render(i18n::lang()));
}

pub(crate) fn print_inspect_result(res: &crate::structure::InspectResult) {
    println!("{}", t!(Msg::InspectCarrier, val = res.carrier.display()));
    println!("{}", t!(Msg::InspectFormat, val = res.format.as_str()));
    println!("{}", t!(Msg::InspectHasHidden, val = res.has_hidden_data));
    if res.has_hidden_data {
        if let Some(s) = &res.strategy {
            println!("{}", t!(Msg::InspectStrategy, val = s.name()));
        }
        if let Some(off) = res.ube_offset {
            println!("{}", t!(Msg::InspectUbeOffset, val = off));
        }
        if let Some(sz) = res.ube_total_size {
            println!("{}", t!(Msg::InspectUbeTotalSize, val = sz));
        }
        if let Some(enc) = res.is_encrypted {
            println!("{}", t!(Msg::InspectEncrypted, val = enc));
        }
        if let Some(stl) = res.is_stealth {
            println!("{}", t!(Msg::InspectStealth, val = stl));
        }
        if let Some(h) = &res.password_hint {
            println!("{}", t!(Msg::InspectPasswordHint, val = h));
        }
        if let Some(sz) = res.orig_host_size {
            println!("{}", t!(Msg::InspectOrigSize, val = sz));
        }
        if let Some(sha) = &res.orig_host_sha256 {
            println!("{}", t!(Msg::InspectOrigSha256, val = sha));
        }
        if let Some(meta) = &res.metadata {
            println!("{}", t!(Msg::InspectMetadata, val = meta));
        }
    }

    let auto_idx = res.strategies.iter().position(|c| c.available);
    println!("{}", t!(Msg::InspectCapacitiesHeader));
    for (idx, c) in res.strategies.iter().enumerate() {
        let auto = if Some(idx) == auto_idx {
            t!(Msg::InspectAutoPreference)
        } else {
            String::new()
        };
        let state = if c.available {
            String::new()
        } else {
            t!(Msg::InspectUnavailable)
        };
        let detail = c.note.as_deref().unwrap_or("");
        if detail.is_empty() {
            println!("  - {}{}{}: {}", c.strategy, auto, state, c.limit);
        } else {
            println!(
                "  - {}{}{}: {} - {}",
                c.strategy, auto, state, c.limit, detail
            );
        }
    }
}

pub(crate) fn print_json<T: serde::Serialize>(val: &T) -> Result<(), StrHideError> {
    let mut v = serde_json::to_value(val)?;
    match &mut v {
        serde_json::Value::Object(map) => {
            map.insert(
                "banner".to_string(),
                serde_json::Value::String(BANNER.to_string()),
            );
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                if let serde_json::Value::Object(map) = item {
                    map.insert(
                        "banner".to_string(),
                        serde_json::Value::String(BANNER.to_string()),
                    );
                }
            }
        }
        _ => {}
    }
    println!("{}", serde_json::to_string_pretty(&v)?);
    Ok(())
}

pub(crate) fn print_verify_result(res: &crate::structure::VerifyResult) {
    fn status(level: &crate::structure::LevelStatus) -> &'static str {
        if level.skipped {
            "SKIP"
        } else if level.ok {
            "OK"
        } else {
            "FAIL"
        }
    }
    println!("{}", t!(Msg::InspectCarrier, val = res.carrier.display()));
    println!("{}", t!(Msg::InspectFormat, val = res.format.as_str()));
    println!(
        "{}",
        t!(
            Msg::VerifyL1,
            status = status(&res.level1_host),
            detail = res.level1_host.detail
        )
    );
    println!(
        "{}",
        t!(
            Msg::VerifyL2,
            status = status(&res.level2_envelope),
            detail = res.level2_envelope.detail
        )
    );
    println!(
        "{}",
        t!(
            Msg::VerifyL3,
            status = status(&res.level3_crypto),
            detail = res.level3_crypto.detail
        )
    );
}

#[derive(serde::Serialize)]
pub(crate) struct DualVerifyResult {
    #[serde(flatten)]
    pub(crate) structure: crate::structure::VerifyResult,
    #[cfg(feature = "content")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) content_stego: Option<crate::stego::StegoVerifyResult>,
    /// Present when the content-domain verifier failed to run. Serialized so
    /// `--json` consumers see a failure instead of a missing field (review R3
    /// P1-1).
    #[cfg(feature = "content")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) content_error: Option<crate::core::errors::ErrorDetail>,
}

#[cfg(feature = "content")]
pub(crate) fn print_content_verify_result(res: &crate::stego::StegoVerifyResult) {
    println!(
        "Content Steganography Domain Verification ({}):",
        res.format
    );
    for lvl in &res.levels {
        let status = if lvl.ok { "OK" } else { "FAIL" };
        let msg = lvl.message.as_deref().unwrap_or("");
        if msg.is_empty() {
            println!("  Level {} [{}]: {}", lvl.level, lvl.name, status);
        } else {
            println!("  Level {} [{}]: {} - {}", lvl.level, lvl.name, status, msg);
        }
    }
}

pub(crate) fn print_write_result(res: &WriteResult, quiet: bool, elapsed: std::time::Duration) {
    if quiet {
        return;
    }
    let elapsed_str = super::helpers::format_duration(elapsed);
    println!(
        "{}",
        t!(
            Msg::WriteOk,
            carrier = res.carrier.display(),
            strategy = res.strategy.name(),
            elapsed = elapsed_str
        )
    );
    let backup_str = if let Some(bak) = &res.backup_file {
        t!(Msg::WriteBackupNote, path = bak.display())
    } else {
        String::new()
    };
    println!(
        "{}",
        t!(
            Msg::WritePayloadUbe,
            raw = super::helpers::format_size(res.raw_size),
            ube = super::helpers::format_size(res.ube_size),
            backup = backup_str
        )
    );
    if let Some(note) = &res.strategy_note {
        println!("{}", t!(Msg::WriteStrategyNote, note = note));
    }
    if let Some(hint) = &res.password_hint {
        println!("{}", t!(Msg::WritePasswordHint, hint = hint));
    }
    for warn in &res.warnings {
        eprintln!("{}", t!(Msg::WriteWarningNote, warn = warn.message()));
    }
}

pub(crate) fn print_remove_result(res: &RemoveResult, quiet: bool, elapsed: std::time::Duration) {
    if quiet {
        return;
    }
    let elapsed_str = super::helpers::format_duration(elapsed);
    println!(
        "{}",
        t!(
            Msg::RestoreOk,
            carrier = res.carrier.display(),
            bytes = super::helpers::format_size(res.restored_size),
            elapsed = elapsed_str
        )
    );
    let backup_str = if let Some(bak) = &res.backup_file {
        t!(Msg::RestoreBackupNote, path = bak.display())
    } else {
        String::new()
    };
    println!(
        "{}",
        t!(
            Msg::RestoreDetail,
            sha = res.restored_sha256,
            backup = backup_str
        )
    );
}
