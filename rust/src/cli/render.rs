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

pub(crate) fn print_error(e: &StrHideError) {
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
            // The hint is attacker-controlled and outside the AAD.
            let safe = crate::core::fs::escape_control_chars(h);
            println!("{}", t!(Msg::InspectPasswordHint, val = safe.as_ref()));
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

/// What [`write_payload_stdout`] should emit for a payload.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StdoutPlan<'a> {
    /// Bytes go out verbatim. Only for an explicit `--stdout` on a pipe, where
    /// `> out.bin` must stay byte-exact.
    Raw(&'a [u8]),
    /// Payload is text and the destination is a screen: control characters are
    /// escaped before they reach the terminal.
    Escaped(std::borrow::Cow<'a, str>),
    /// Payload is binary and the destination is a screen. The bytes are *not*
    /// written: a non-UTF-8 stream would sail straight past the escape above
    /// (the terminal does not care about UTF-8 when it sees `ESC`), so a
    /// crafted carrier could still drive `CSI`/`OSC 52` through it.
    BinaryNotice(usize),
}

/// Decide what to write for `data`.
///
/// Split out from the writer so the decision is testable without capturing a
/// real terminal.
pub(crate) fn plan_payload_stdout(data: &[u8], escape: bool) -> StdoutPlan<'_> {
    match std::str::from_utf8(data) {
        Ok(text) if escape => StdoutPlan::Escaped(crate::core::fs::escape_terminal_text(text)),
        Err(_) if escape => StdoutPlan::BinaryNotice(data.len()),
        _ => StdoutPlan::Raw(data),
    }
}

/// Write an extracted payload to stdout.
///
/// The bytes come from whoever built the carrier, so printing them verbatim
/// lets a crafted file drive the terminal (`CSI` cursor games, `OSC 52`
/// clipboard writes). Two modes, because the two callers have opposite needs:
///
/// * `escape_on_pipe = true` for the implicit "just show me the payload"
///   branches, which always end up on a screen.
/// * `escape_on_pipe = false` for an explicit `--stdout`, where piping must stay
///   byte-exact (`extract --stdout > out.bin`); only a real terminal gets the
///   escaped text.
///
/// A binary payload aimed at a screen produces a one-line notice on **stderr**
/// instead of bytes, so a redirect never receives a partial payload and a
/// terminal never receives unescaped control sequences.
pub(crate) fn write_payload_stdout(data: &[u8], escape_on_pipe: bool) -> std::io::Result<()> {
    use std::io::Write as _;

    let stdout = std::io::stdout();
    let escape = escape_on_pipe || std::io::IsTerminal::is_terminal(&stdout);
    match plan_payload_stdout(data, escape) {
        StdoutPlan::Raw(bytes) => {
            let mut out = stdout.lock();
            out.write_all(bytes)?;
            out.flush()
        }
        StdoutPlan::Escaped(text) => {
            let mut out = stdout.lock();
            out.write_all(text.as_bytes())?;
            out.flush()
        }
        StdoutPlan::BinaryNotice(len) => {
            eprintln!("{}", t!(Msg::PayloadStdoutBinary, bytes = len));
            Ok(())
        }
    }
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
    /// `--json` consumers see the error detail explicitly.
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
        let safe = crate::core::fs::escape_control_chars(hint);
        println!("{}", t!(Msg::WritePasswordHint, hint = safe.as_ref()));
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

#[cfg(test)]
mod tests {
    use super::{StdoutPlan, plan_payload_stdout};

    #[test]
    fn text_on_a_screen_is_escaped() {
        let plan = plan_payload_stdout(b"a\x1b[2Jb", true);
        match plan {
            StdoutPlan::Escaped(text) => {
                // The escaper writes a literal `\u{1b}` in place of the byte.
                assert_eq!(text, r"a\u{1b}[2Jb");
            }
            other => panic!("expected escaped text, got {other:?}"),
        }
    }

    #[test]
    fn text_on_a_pipe_is_byte_exact() {
        assert_eq!(
            plan_payload_stdout(b"plain\n", false),
            StdoutPlan::Raw(b"plain\n")
        );
    }

    #[test]
    fn binary_on_a_screen_is_never_written_raw() {
        // Even if terminal escape sequences hide inside non-UTF-8 bytes,
        // terminal output must not fall through to an unescaped raw write.
        let mut data = b"\x1b[2J".to_vec();
        data.push(0xff);
        match plan_payload_stdout(&data, true) {
            StdoutPlan::BinaryNotice(len) => assert_eq!(len, data.len()),
            other => panic!("expected a binary notice, got {other:?}"),
        }
    }

    #[test]
    fn binary_on_an_explicit_stdout_pipe_stays_raw() {
        // `extract --stdout > out.bin` must keep every byte.
        let data = [0xff_u8, 0x00, 0x1b];
        assert_eq!(plan_payload_stdout(&data, false), StdoutPlan::Raw(&data));
    }
}
