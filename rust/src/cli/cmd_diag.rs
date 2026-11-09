// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Diagnostic verbs: `inspect`, `verify`, `scan`, `list`.

use std::path::{Path, PathBuf};

use crate::core::config::FileConfig;
use crate::core::i18n::Msg;
use crate::errors::StrHideError;
use crate::facade::StrHide;
use crate::structure::registry::ADAPTERS;
use crate::t;

use super::args::*;
use super::banner;
use super::helpers::*;
use super::render::*;

/// Print the content-domain half of an `inspect` result.
///
/// Shared by single-carrier and batch paths, printing content-domain failures
/// when present to ensure failed content probes are explicitly reported.
fn print_content_domain(dual: &crate::facade::DualInspect) {
    if let Some(ref cs) = dual.content
        && cs.has_hidden_data
    {
        println!();
        println!("Content Steganography Domain:");
        println!("  Format: {}", cs.format);
        println!("  Has Hidden Data: true");
        if let Some(algo) = &cs.algorithm {
            println!("  Algorithm: {}", algo);
        }
        if let Some(codec) = &cs.codec {
            println!("  Codec: {}", codec);
        }
        if let Some(len) = cs.envelope_len {
            println!("  Envelope Size: {} bytes", len);
        }
        if let Some(len) = cs.payload_len {
            println!("  Payload Size: {} bytes", len);
        }
        if let Some(media) = &cs.media_info {
            println!("  Dimensions: {}", media);
        }
        return;
    }
    for line in content_domain_diagnostics(dual.content.as_ref(), dual.content_error.as_ref()) {
        println!("  ? {line}");
    }
}

/// Diagnostic lines for a content half that produced no verdict.
///
/// Split out from printing so the "a note the engine produced is actually
/// shown" contract can be tested without capturing stdout. The engines write a
/// `note` when a probe could not reach a verdict (JPEG preflight failure,
/// malformed extension area, unreadable header); text mode used to drop it, so
/// "verified empty" and "could not read the file" printed the same thing.
fn content_domain_diagnostics(
    content: Option<&crate::stego::StegoHeaderInfo>,
    content_error: Option<&crate::errors::ErrorDetail>,
) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(err) = content_error {
        lines.push(format!(
            "content inspection failed: {}",
            err.render(crate::core::i18n::lang())
        ));
    }
    if let Some(note) = content.and_then(|cs| cs.note.as_deref()) {
        lines.push(format!("content inspection note: {note}"));
    }
    lines
}

pub(crate) fn handle_inspect(
    args: InspectArgs,
    _cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<i32, StrHideError> {
    let password = args.passwords.resolve(false, false)?;
    let key = resolve_key_file(args.key_file.as_deref())?;

    let is_batch = args.carrier.len() > 1 || args.carrier.iter().any(|p| p.is_dir());
    let ExpandedInputs { files, missing } =
        expand_input_paths(&args.carrier, args.recursive, quiet)?;
    if files.is_empty() && missing.is_empty() {
        return Err(StrHideError::General(
            "No files to inspect (empty input or empty directory)".into(),
        ));
    }

    if !is_batch && files.len() == 1 {
        let carrier = &files[0];
        let dual = engine.inspect_any(
            carrier,
            &crate::facade::DualOptions {
                password: password.as_deref(),
                key: key.as_ref(),
                domain: engine.dialect().stego.stego_domain(),
                control: crate::core::control::Control::none(),
            },
        )?;
        if args.json {
            print_json(&dual)?;
        } else if !quiet {
            print_inspect_result(&dual.structure);
            print_content_domain(&dual);
        }
        return Ok(0);
    }

    let t_start = std::time::Instant::now();
    let mut reports = Vec::with_capacity(files.len());
    let mut json_items: Vec<serde_json::Value> = Vec::with_capacity(files.len() + missing.len());
    // A path the caller named but that does not exist is a failure, not a
    // no-op: otherwise `inspect good.png stale.png` reports success.
    let mut failures = missing.len();
    push_missing_items(&mut json_items, &missing);
    let mut any_failed = !missing.is_empty();
    for carrier in &files {
        match engine.inspect_any(
            carrier,
            &crate::facade::DualOptions {
                password: password.as_deref(),
                key: key.as_ref(),
                domain: engine.dialect().stego.stego_domain(),
                control: crate::core::control::Control::none(),
            },
        ) {
            Ok(dual) => {
                if !args.json && !quiet {
                    println!(
                        "=== [{}/{}] {} ===",
                        reports.len() + 1,
                        files.len(),
                        carrier.display()
                    );
                    print_inspect_result(&dual.structure);
                    print_content_domain(&dual);
                    println!();
                }
                if args.json {
                    json_items.push(serde_json::to_value(&dual).map_err(|e| {
                        StrHideError::General(format!("inspect serialization failed: {e}"))
                    })?);
                }
                reports.push(dual);
            }
            Err(e) => {
                failures += 1;
                any_failed = true;
                if args.json {
                    json_items.push(serde_json::json!({
                        "path": carrier.display().to_string(),
                        "error": e.to_string(),
                    }));
                }
                if !quiet {
                    eprintln!(
                        "{}",
                        t!(Msg::WarnInspectFailed, path = carrier.display(), err = e)
                    );
                }
            }
        }
    }

    if args.json {
        print_json(&json_items)?;
    } else if !quiet {
        let hidden = reports
            .iter()
            .filter(|r| {
                r.structure.has_hidden_data || {
                    #[cfg(feature = "content")]
                    {
                        r.content
                            .as_ref()
                            .map(|c| c.has_hidden_data)
                            .unwrap_or(false)
                    }
                    #[cfg(not(feature = "content"))]
                    {
                        false
                    }
                }
            })
            .count();
        let elapsed_str = format_duration(t_start.elapsed());
        println!(
            "{}",
            t!(
                Msg::InspectSummary,
                total = reports.len() + failures,
                hidden = hidden,
                failed = failures,
                elapsed = elapsed_str
            )
        );
    }

    // Same contract as `verify`: an unreadable or missing input fails the
    // batch. The per-file warnings above already say which ones.
    Ok(if any_failed { 1 } else { 0 })
}

/// Whether the structure domain actually ran for this carrier.
///
/// A content-only carrier (PNG/JPEG) comes back with every structure level
/// `skipped`: that is "not applicable", not "failed", and must not be reported
/// as a failure of its own. An all-skipped result used to be indistinguishable
/// from a real verdict once the two domains were collapsed into one exit code.
fn structure_domain_ran(res: &crate::structure::VerifyResult) -> bool {
    !(res.level1_host.skipped && res.level2_envelope.skipped && res.level3_crypto.skipped)
}

/// Whether the content verifier actually found an envelope.
///
/// Every content engine emits the same three levels (container, header/
/// superblock, payload). Level 2 failing means "nothing hidden here" — or a
/// wrong password — which is not a verification failure; level 2 passing
/// with level 3 failing is, distinguishing structure-only carriers from broken content envelopes.
#[cfg(feature = "content")]
fn content_envelope_present(res: &crate::stego::StegoVerifyResult) -> bool {
    res.levels.iter().any(|l| l.level == 2 && l.ok)
}

/// The `verify` exit verdict for one carrier.
///
/// Factored out so verification rules are consolidated and unit-testable.
fn dual_verify_failed(
    struct_ok: bool,
    content_ok: bool,
    content_present: bool,
    content_errored: bool,
) -> bool {
    !(struct_ok || content_ok) || (content_present && !content_ok) || content_errored
}

pub(crate) fn handle_verify(
    args: VerifyArgs,
    _cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<i32, StrHideError> {
    let password = args.passwords.resolve(false, false)?;
    let key = resolve_key_file(args.key_file.as_deref())?;

    let is_batch = args.carrier.len() > 1 || args.carrier.iter().any(|p| p.is_dir());
    let ExpandedInputs { files, missing } =
        expand_input_paths(&args.carrier, args.recursive, quiet)?;
    if files.is_empty() && missing.is_empty() {
        return Err(StrHideError::General(
            "No files to verify (empty input or empty directory)".into(),
        ));
    }

    if !is_batch && files.len() == 1 {
        let carrier = &files[0];
        let dual = engine.verify_any(
            carrier,
            &crate::facade::DualOptions {
                password: password.as_deref(),
                key: key.as_ref(),
                domain: engine.dialect().stego.stego_domain(),
                control: crate::core::control::Control::none(),
            },
        )?;

        let struct_ok = crate::structure::verify_passed(&dual.structure);
        let struct_ran = structure_domain_ran(&dual.structure);
        #[cfg(feature = "content")]
        let (content_ok, content_present, content_errored) = match &dual.content {
            Some(c) => (c.is_all_ok(), content_envelope_present(c), false),
            None => (false, false, dual.content_error.is_some()),
        };
        #[cfg(not(feature = "content"))]
        #[allow(unused_variables)]
        let (content_ok, content_present, content_errored) = (false, false, false);

        // A content envelope that was found but does not verify fails the file
        // even when the structure domain is intact; a verifier that could not
        // run does too. "Nothing hidden in the content domain" does not fail.
        let failed = dual_verify_failed(struct_ok, content_ok, content_present, content_errored);

        #[cfg(feature = "content")]
        let show_content = dual
            .content
            .as_ref()
            .is_some_and(|c| content_envelope_present(c) || c.is_all_ok());

        if args.json {
            let res = DualVerifyResult {
                structure: dual.structure,
                #[cfg(feature = "content")]
                content_stego: dual
                    .content
                    .filter(|c| content_envelope_present(c) || c.is_all_ok()),
                #[cfg(feature = "content")]
                content_error: dual.content_error,
            };
            print_json(&res)?;
        } else if !quiet {
            if struct_ran {
                print_verify_result(&dual.structure);
            }
            #[cfg(feature = "content")]
            if show_content {
                if struct_ran {
                    println!();
                }
                if let Some(cs) = &dual.content {
                    print_content_verify_result(cs);
                }
            }
            #[cfg(feature = "content")]
            if let Some(err) = &dual.content_error {
                println!(
                    "Content Steganography Domain Verification: FAIL - {}",
                    err.detail
                );
            }
        }
        return Ok(if failed { 1 } else { 0 });
    }

    let t_start = std::time::Instant::now();
    let mut reports = Vec::with_capacity(files.len());
    let mut json_items: Vec<serde_json::Value> = Vec::with_capacity(files.len() + missing.len());
    // Missing inputs are failures here too: `verify a.png stale.png` used to
    // exit 0 because only in-loop errors were counted.
    let mut failures = missing.len();
    let mut any_failed = !missing.is_empty();
    push_missing_items(&mut json_items, &missing);
    let mut passed = 0usize;
    for carrier in &files {
        match engine.verify_any(
            carrier,
            &crate::facade::DualOptions {
                password: password.as_deref(),
                key: key.as_ref(),
                domain: engine.dialect().stego.stego_domain(),
                control: crate::core::control::Control::none(),
            },
        ) {
            Ok(dual) => {
                let struct_ok = crate::structure::verify_passed(&dual.structure);
                let struct_ran = structure_domain_ran(&dual.structure);
                #[cfg(feature = "content")]
                let (content_ok, content_present, content_errored) = match &dual.content {
                    Some(c) => (c.is_all_ok(), content_envelope_present(c), false),
                    None => (false, false, dual.content_error.is_some()),
                };
                #[cfg(not(feature = "content"))]
                #[allow(unused_variables)]
                let (content_ok, content_present, content_errored) = (false, false, false);

                // Same verdict rule as the single-carrier path.
                let failed =
                    dual_verify_failed(struct_ok, content_ok, content_present, content_errored);
                if failed {
                    any_failed = true;
                } else {
                    passed += 1;
                }
                #[cfg(feature = "content")]
                let show_content = dual
                    .content
                    .as_ref()
                    .is_some_and(|c| content_envelope_present(c) || c.is_all_ok());
                if !args.json && !quiet {
                    println!(
                        "=== [{}/{}] {} ===",
                        reports.len() + 1,
                        files.len(),
                        carrier.display()
                    );
                    if struct_ran {
                        print_verify_result(&dual.structure);
                    }
                    #[cfg(feature = "content")]
                    if show_content {
                        if struct_ran {
                            println!();
                        }
                        if let Some(cs) = &dual.content {
                            print_content_verify_result(cs);
                        }
                    }
                    #[cfg(feature = "content")]
                    if let Some(err) = &dual.content_error {
                        println!(
                            "Content Steganography Domain Verification: FAIL - {}",
                            err.detail
                        );
                    }
                    println!();
                }
                reports.push(DualVerifyResult {
                    structure: dual.structure,
                    #[cfg(feature = "content")]
                    content_stego: dual
                        .content
                        .filter(|c| content_envelope_present(c) || c.is_all_ok()),
                    #[cfg(feature = "content")]
                    content_error: dual.content_error,
                });
                if args.json {
                    json_items.push(serde_json::to_value(&reports[reports.len() - 1]).map_err(
                        |e| StrHideError::General(format!("verify serialization failed: {e}")),
                    )?);
                }
            }
            Err(e) => {
                failures += 1;
                any_failed = true;
                if args.json {
                    json_items.push(serde_json::json!({
                        "path": carrier.display().to_string(),
                        "error": e.to_string(),
                    }));
                }
                if !quiet {
                    eprintln!(
                        "{}",
                        t!(Msg::WarnVerifyFailed, path = carrier.display(), err = e)
                    );
                }
            }
        }
    }

    if args.json {
        print_json(&json_items)?;
    } else if !quiet {
        let failed_cnt = reports.len() - passed;
        let elapsed_str = format_duration(t_start.elapsed());
        println!(
            "{}",
            t!(
                Msg::VerifySummary,
                total = reports.len() + failures,
                passed = passed,
                failed = failed_cnt,
                unreadable = failures,
                elapsed = elapsed_str
            )
        );
    }

    Ok(if any_failed { 1 } else { 0 })
}

pub(crate) fn handle_scan(args: ScanArgs, quiet: bool) -> Result<i32, StrHideError> {
    use crate::analysis::scan_file;

    // Expand inputs: directories become file lists.
    let ExpandedInputs { files, missing } = expand_input_paths(&args.input, args.recursive, quiet)?;

    if files.is_empty() && missing.is_empty() {
        return Err(StrHideError::General(
            "No files to scan (empty input or empty directory)".into(),
        ));
    }

    let t_start = std::time::Instant::now();
    let mut reports = Vec::with_capacity(files.len());
    let mut json_items: Vec<serde_json::Value> = Vec::with_capacity(files.len() + missing.len());
    // Counted and reported, but (unlike `inspect`/`verify`) they do not move
    // the exit code: `scan`'s exit status is the verdict gate, and unreadable
    // files were already documented as report-only.
    let mut failures = missing.len();
    push_missing_items(&mut json_items, &missing);
    for f in &files {
        match scan_file(f) {
            Ok(r) => {
                if args.json {
                    json_items.push(serde_json::to_value(&r).map_err(|e| {
                        StrHideError::General(format!("scan serialization failed: {e}"))
                    })?);
                }
                reports.push(r);
            }
            Err(e) => {
                failures += 1;
                if args.json {
                    json_items.push(serde_json::json!({
                        "path": f.display().to_string(),
                        "error": e.to_string(),
                    }));
                }
                if !quiet {
                    eprintln!("{}", t!(Msg::WarnScanFailed, path = f.display(), err = e));
                }
            }
        }
    }

    if args.json {
        print_json(&json_items)?;
    } else if quiet {
        // The exit code below is the entire quiet output: 1 when any report
        // reached "likely-hidden", 0 otherwise.
    } else {
        for r in &reports {
            let format_label = r.format.as_deref().unwrap_or("unknown");
            println!(
                "[{}] {} ({} - {} bytes) - risk {}/100",
                r.verdict.to_uppercase(),
                r.carrier,
                format_label,
                r.file_size,
                r.risk_score,
            );
            if !r.detectors.is_empty() {
                for d in &r.detectors {
                    let tag = match d.status.as_str() {
                        "ALERT" => "!",
                        "INFO" => "-",
                        _ => "✓",
                    };
                    let thresh_info = match &d.threshold {
                        Some(t) => format!(" (threshold: {t})"),
                        None => String::new(),
                    };
                    println!(
                        "    {tag} [{:<20}] {:<16}{thresh_info} | {}",
                        d.name, d.metric, d.detail
                    );
                }
            } else {
                for finding in &r.findings {
                    let tag = match finding.severity {
                        crate::analysis::Severity::Info => "-",
                        crate::analysis::Severity::Suspicious => "!",
                        crate::analysis::Severity::Likely => "!!",
                    };
                    println!("    {tag} [{}] {}", finding.detector, finding.detail);
                }
            }
            for note in &r.notes {
                // Notes explain how to interpret the verdict; caveats such as
                // "clean result is not proof" apply even when findings are empty.
                println!("    ? {note}");
            }
        }
        let findings_cnt = reports.iter().filter(|r| !r.findings.is_empty()).count();
        let elapsed_str = format_duration(t_start.elapsed());
        println!(
            "{}",
            t!(
                Msg::ScanSummary,
                total = reports.len() + failures,
                findings = findings_cnt,
                failed = failures,
                elapsed = elapsed_str
            )
        );
    }

    // Gate-style exit code, independent of quiet: `--fail-on` names the lowest
    // verdict that fails the scan (default "likely", the historical behaviour),
    // optionally widened to "suspicious" or "low" for stricter CI gates. Per-file
    // scan failures stay at 0 — they are reported in the JSON/human output.
    fn verdict_rank(verdict: &str) -> u8 {
        match verdict {
            "likely-hidden" => 3,
            "suspicious" => 2,
            "low" => 1,
            _ => 0,
        }
    }
    let fail_rank = match args.fail_on.as_str() {
        "low" => 1,
        "suspicious" => 2,
        _ => 3,
    };
    let worst = reports
        .iter()
        .map(|r| verdict_rank(&r.verdict))
        .max()
        .unwrap_or(0);
    Ok(if worst >= fail_rank { 1 } else { 0 })
}

/// Walk a directory non-recursively.
///
/// Individual entries that cannot be read (permissions, a broken symlink, a
/// device that vanished mid-walk) are skipped with a warning instead of
/// aborting the whole batch: one unreadable file must not cost the user every
/// other report. Same policy as [`expand_input_paths`] for missing paths.
fn walkdir_flat(dir: &Path, quiet: bool) -> Result<Vec<PathBuf>, StrHideError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if !quiet {
                    eprintln!("[WARN] Cannot read an entry in {}: {e}", dir.display());
                }
                continue;
            }
        };
        match entry.file_type() {
            Ok(ft) if ft.is_file() => out.push(entry.path()),
            Ok(_) => {}
            Err(e) => {
                if !quiet {
                    eprintln!("[WARN] Cannot stat {}: {e}", entry.path().display());
                }
            }
        }
    }
    Ok(out)
}

fn walkdir_recursive(dir: &Path, quiet: bool) -> Result<Vec<PathBuf>, StrHideError> {
    let mut out = Vec::new();
    push_files_recursive(dir, &mut out, quiet)?;
    Ok(out)
}

fn push_files_recursive(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    quiet: bool,
) -> Result<(), StrHideError> {
    // `entry.file_type()` does not follow symlinks, so a link to a directory is
    // reported as a file here and is never recursed into: no visited set is
    // needed to rule out cycles.
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if !quiet {
                    eprintln!("[WARN] Cannot read an entry in {}: {e}", dir.display());
                }
                continue;
            }
        };
        let path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => push_files_recursive(&path, out, quiet)?,
            Ok(_) => out.push(path),
            Err(e) => {
                if !quiet {
                    eprintln!("[WARN] Cannot stat {}: {e}", path.display());
                }
            }
        }
    }
    Ok(())
}

/// Result of expanding the positional arguments into concrete inputs.
struct ExpandedInputs {
    /// Paths that exist and will be processed.
    files: Vec<PathBuf>,
    /// Paths the caller named that do not exist (or are a dangling symlink).
    ///
    /// They used to be dropped with a stderr warning only, so a batch that
    /// silently lost an input still looked fully successful: `--json` carried
    /// no trace of the path and the exit code stayed 0. Scripts that pass a
    /// stale path must be able to see that.
    missing: Vec<PathBuf>,
}

/// Append one `{"path", "error"}` item per missing input, matching the shape
/// used for in-loop failures.
fn push_missing_items(json_items: &mut Vec<serde_json::Value>, missing: &[PathBuf]) {
    for path in missing {
        json_items.push(serde_json::json!({
            "path": path.display().to_string(),
            "error": "file does not exist",
        }));
    }
}

fn expand_input_paths(
    inputs: &[PathBuf],
    recursive: bool,
    quiet: bool,
) -> Result<ExpandedInputs, StrHideError> {
    let mut files = Vec::new();
    let mut missing = Vec::new();
    for entry in inputs {
        if entry.is_dir() {
            files.extend(if recursive {
                walkdir_recursive(entry, quiet)?
            } else {
                walkdir_flat(entry, quiet)?
            });
        } else if entry.is_file() {
            files.push(entry.clone());
        } else {
            if !quiet {
                eprintln!("{}", t!(Msg::WarnSkippedMissing, path = entry.display()));
            }
            missing.push(entry.clone());
        }
    }
    Ok(ExpandedInputs { files, missing })
}

pub(crate) fn handle_list(args: ListArgs) -> Result<(), StrHideError> {
    if args.json {
        #[derive(serde::Serialize)]
        struct ListStrategyItem {
            strategy: String,
            limit: String,
        }
        #[derive(serde::Serialize)]
        struct ListFormatItem {
            format: String,
            strategies: Vec<ListStrategyItem>,
        }
        #[derive(serde::Serialize)]
        struct ListAlgorithmItem {
            algorithm: String,
            domain: String,
            description: String,
        }
        #[derive(serde::Serialize)]
        struct ListReport {
            banner: String,
            formats: Vec<ListFormatItem>,
            stego_algorithms: Vec<ListAlgorithmItem>,
        }

        let mut formats = Vec::new();
        for adapter in ADAPTERS {
            let format = adapter.format_name().to_string();
            let mut strategies = Vec::new();
            for cap in adapter.strategy_capacities(None) {
                strategies.push(ListStrategyItem {
                    strategy: cap.strategy.to_string(),
                    limit: cap.limit.to_string(),
                });
            }
            formats.push(ListFormatItem { format, strategies });
        }

        let mut stego_algorithms = Vec::new();
        for (id, domain, desc) in crate::stego::CostModelRegistry::list_algorithms() {
            stego_algorithms.push(ListAlgorithmItem {
                algorithm: id.to_string(),
                domain: domain.to_string(),
                description: desc.to_string(),
            });
        }

        let report = ListReport {
            banner: banner(),
            formats,
            stego_algorithms,
        };

        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Static reference table: constants come from the adapters themselves (via
    // `strategy_capacities(None)`), so the table cannot drift from the code.
    // Carrier-specific limits are answered by `inspect <carrier>`.
    println!("{:<8} {:<15} Limit", "Format", "Strategy");
    println!("{:-<8} {:-<15} {:-<48}", "", "", "");
    for adapter in ADAPTERS {
        let format = adapter.format_name();
        for cap in adapter.strategy_capacities(None) {
            println!("{format:<8} {:<15} {}", cap.strategy, cap.limit);
        }
    }
    println!();
    println!("{}", t!(Msg::ListCarrierDependentNotice));

    println!("{}", t!(Msg::ListStegoAlgorithmsHeader));
    println!("{:<8} {:<15} Description", "Algorithm", "Target Domain");
    println!("{:-<8} {:-<15} {:-<48}", "", "", "");
    for (id, domain, desc) in crate::stego::CostModelRegistry::list_algorithms() {
        println!("{id:<8} {domain:<15} {desc}");
    }
    println!();

    Ok(())
}

#[cfg(test)]
mod verdict_tests {
    use super::{content_domain_diagnostics, dual_verify_failed};

    /// A probe that could not reach a verdict leaves a `note` behind; text mode
    /// must show it, otherwise "nothing hidden" and "could not read the file"
    /// look identical to the user.
    #[test]
    fn content_note_is_reported() {
        let mut info = crate::stego::StegoHeaderInfo::empty("JPEG");
        info.note = Some("Preflight failed: truncated scan".into());
        let lines = content_domain_diagnostics(Some(&info), None);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("Preflight failed: truncated scan"),
            "{lines:?}"
        );
    }

    /// No note, no line: a clean probe stays quiet.
    #[test]
    fn silent_probe_prints_nothing() {
        let info = crate::stego::StegoHeaderInfo::empty("JPEG");
        assert!(content_domain_diagnostics(Some(&info), None).is_empty());
        assert!(content_domain_diagnostics(None, None).is_empty());
    }

    /// A content verifier that could not run is reported before the note, so a
    /// hard failure and a soft "inconclusive" stay distinguishable.
    #[test]
    fn content_error_is_reported_first() {
        let err = crate::errors::ErrorDetail {
            kind: crate::errors::ErrorKind::General,
            category: None,
            category_label: None,
            detail: "decoder unavailable".into(),
            hint: None,
        };
        let mut info = crate::stego::StegoHeaderInfo::empty("JPEG");
        info.note = Some("header unreadable".into());
        let lines = content_domain_diagnostics(Some(&info), Some(&err));
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].contains("decoder unavailable"), "{lines:?}");
        assert!(lines[1].contains("header unreadable"), "{lines:?}");
    }

    /// A structure-only carrier also runs the content verifier, which answers
    /// "no header here". That is not a failure.
    #[test]
    fn absent_content_envelope_is_not_a_failure() {
        assert!(!dual_verify_failed(true, false, false, false));
    }

    /// Structure envelope intact, but content envelope found and failing its
    /// payload check must fail overall verification.
    #[test]
    fn broken_content_envelope_fails_despite_structure_passing() {
        assert!(dual_verify_failed(true, false, true, false));
    }

    /// A content verifier that could not run at all fails too.
    #[test]
    fn content_verifier_error_fails() {
        assert!(dual_verify_failed(true, false, false, true));
    }

    /// Neither domain produced a passing verdict: a clean carrier still exits 1.
    #[test]
    fn nothing_verified_fails() {
        assert!(dual_verify_failed(false, false, false, false));
    }

    /// Content-only carriers pass when their envelope verifies.
    #[test]
    fn verified_content_envelope_passes() {
        assert!(!dual_verify_failed(false, true, true, false));
    }
}
