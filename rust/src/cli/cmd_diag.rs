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
use super::helpers::*;
use super::render::*;

pub(crate) fn handle_inspect(
    args: InspectArgs,
    _cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        false,
        false,
    )?;

    let is_batch = args.carrier.len() > 1 || args.carrier.iter().any(|p| p.is_dir());
    let files = expand_input_paths(&args.carrier, args.recursive, quiet)?;
    if files.is_empty() {
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
                domain: None,
                control: crate::core::control::Control::none(),
            },
        )?;
        if args.json {
            print_json(&dual)?;
        } else if !quiet {
            print_inspect_result(&dual.structure);
            #[cfg(feature = "content")]
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
            }
        }
        return Ok(());
    }

    let t_start = std::time::Instant::now();
    let mut reports = Vec::with_capacity(files.len());
    let mut failures = 0usize;
    for carrier in &files {
        match engine.inspect_any(
            carrier,
            &crate::facade::DualOptions {
                password: password.as_deref(),
                domain: None,
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
                    #[cfg(feature = "content")]
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
                    }
                    println!();
                }
                reports.push(dual);
            }
            Err(e) => {
                failures += 1;
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
        print_json(&reports)?;
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
                total = reports.len(),
                hidden = hidden,
                failed = failures,
                elapsed = elapsed_str
            )
        );
    }

    Ok(())
}

pub(crate) fn handle_verify(
    args: VerifyArgs,
    _cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<i32, StrHideError> {
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        false,
        false,
    )?;

    let is_batch = args.carrier.len() > 1 || args.carrier.iter().any(|p| p.is_dir());
    let files = expand_input_paths(&args.carrier, args.recursive, quiet)?;
    if files.is_empty() {
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
                domain: None,
                control: crate::core::control::Control::none(),
            },
        )?;

        let struct_ok = crate::structure::verify_passed(&dual.structure);
        #[cfg(feature = "content")]
        let content_ok = dual
            .content
            .as_ref()
            .map(|c| c.is_all_ok())
            .unwrap_or(false);
        #[cfg(not(feature = "content"))]
        let content_ok = false;

        if args.json {
            let res = DualVerifyResult {
                structure: dual.structure,
                #[cfg(feature = "content")]
                content_stego: dual.content.filter(|c| c.is_all_ok()),
            };
            print_json(&res)?;
        } else if !quiet {
            if struct_ok || !content_ok {
                print_verify_result(&dual.structure);
            }
            #[cfg(feature = "content")]
            if let Some(ref cs) = dual.content
                && cs.is_all_ok()
            {
                if struct_ok {
                    println!();
                }
                print_content_verify_result(cs);
            }
        }
        return Ok(if struct_ok || content_ok { 0 } else { 1 });
    }

    let t_start = std::time::Instant::now();
    let mut reports = Vec::with_capacity(files.len());
    let mut failures = 0usize;
    let mut any_failed = false;
    for carrier in &files {
        match engine.verify_any(
            carrier,
            &crate::facade::DualOptions {
                password: password.as_deref(),
                domain: None,
                control: crate::core::control::Control::none(),
            },
        ) {
            Ok(dual) => {
                let struct_ok = crate::structure::verify_passed(&dual.structure);
                #[cfg(feature = "content")]
                let content_ok = dual
                    .content
                    .as_ref()
                    .map(|c| c.is_all_ok())
                    .unwrap_or(false);
                #[cfg(not(feature = "content"))]
                let content_ok = false;

                if !struct_ok && !content_ok {
                    any_failed = true;
                }
                if !args.json && !quiet {
                    println!(
                        "=== [{}/{}] {} ===",
                        reports.len() + 1,
                        files.len(),
                        carrier.display()
                    );
                    if struct_ok || !content_ok {
                        print_verify_result(&dual.structure);
                    }
                    #[cfg(feature = "content")]
                    if let Some(ref cs) = dual.content
                        && cs.is_all_ok()
                    {
                        if struct_ok {
                            println!();
                        }
                        print_content_verify_result(cs);
                    }
                    println!();
                }
                reports.push(DualVerifyResult {
                    structure: dual.structure,
                    #[cfg(feature = "content")]
                    content_stego: dual.content.filter(|c| c.is_all_ok()),
                });
            }
            Err(e) => {
                failures += 1;
                any_failed = true;
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
        print_json(&reports)?;
    } else if !quiet {
        let passed = reports
            .iter()
            .filter(|r| {
                crate::structure::verify_passed(&r.structure) || {
                    #[cfg(feature = "content")]
                    {
                        r.content_stego
                            .as_ref()
                            .map(|c| c.is_all_ok())
                            .unwrap_or(false)
                    }
                    #[cfg(not(feature = "content"))]
                    {
                        false
                    }
                }
            })
            .count();
        let failed_cnt = reports.len() - passed;
        let elapsed_str = format_duration(t_start.elapsed());
        println!(
            "{}",
            t!(
                Msg::VerifySummary,
                total = reports.len(),
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
    let files = expand_input_paths(&args.input, args.recursive, quiet)?;

    if files.is_empty() {
        return Err(StrHideError::General(
            "No files to scan (empty input or empty directory)".into(),
        ));
    }

    let t_start = std::time::Instant::now();
    let mut reports = Vec::with_capacity(files.len());
    let mut failures = 0usize;
    for f in &files {
        match scan_file(f) {
            Ok(r) => reports.push(r),
            Err(e) => {
                failures += 1;
                if !quiet {
                    eprintln!("{}", t!(Msg::WarnScanFailed, path = f.display(), err = e));
                }
            }
        }
    }

    if args.json {
        print_json(&reports)?;
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
                // Notes explain how to read the verdict, so the "a clean
                // result is not proof" caveat matters *most* when there are no
                // findings. Filtering on `findings.is_empty()` dropped exactly
                // those (review R2 P1-10).
                println!("    ? {note}");
            }
        }
        let findings_cnt = reports.iter().filter(|r| !r.findings.is_empty()).count();
        let elapsed_str = format_duration(t_start.elapsed());
        println!(
            "{}",
            t!(
                Msg::ScanSummary,
                total = reports.len(),
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

fn expand_input_paths(
    inputs: &[PathBuf],
    recursive: bool,
    quiet: bool,
) -> Result<Vec<PathBuf>, StrHideError> {
    let mut files = Vec::new();
    for entry in inputs {
        if entry.is_dir() {
            files.extend(if recursive {
                walkdir_recursive(entry, quiet)?
            } else {
                walkdir_flat(entry, quiet)?
            });
        } else if entry.is_file() {
            files.push(entry.clone());
        } else if !quiet {
            eprintln!("{}", t!(Msg::WarnSkippedMissing, path = entry.display()));
        }
    }
    Ok(files)
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
            banner: BANNER.to_string(),
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
        println!("{id:<8} {:<15} {desc}", domain);
    }
    println!();

    Ok(())
}
