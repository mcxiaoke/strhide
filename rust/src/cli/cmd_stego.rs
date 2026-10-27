// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Content-domain verbs: `embed`, `extract`, `capacity`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::core::config::FileConfig;
use crate::core::i18n::Msg;
use crate::core::payload::Payload;
use crate::core::pipeline::{
    batch_output_dir, check_overwrite, for_each_carrier, resolve_carrier_target,
};
use crate::errors::StrHideError;
use crate::facade::StrHide;
use crate::stego::SafetyEnforcement;
use crate::t;

use super::args::*;
use super::cmd_structure::handle_read;
use super::helpers::*;

/// Read-only capacity probe shared by `strhide capacity` and `embed --capacity`.
///
/// The probe uses the same credentials the embed would: they key the spatial
/// header permutation, which changes which pixels are available to the payload.
fn run_capacity_probe(
    carriers: Vec<PathBuf>,
    tuning: &StegoTuningArgs,
    cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
    json: bool,
) -> Result<(), StrHideError> {
    let password = resolve_password(
        tuning.passwords.password.as_deref(),
        tuning.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;
    for carrier in &carriers {
        let carrier_bytes = std::fs::read(carrier)?;
        let (_, options) = stego_options(
            tuning,
            password.as_deref(),
            carrier_format(&carrier_bytes),
            cfg,
        )?;
        let cap = crate::stego::probe_carrier_capacity_with_dialect(
            &carrier_bytes,
            &options,
            &engine.dialect().stego,
        )?;
        if json {
            println!(
                "{}",
                serde_json::to_string(&cap).map_err(|e| {
                    StrHideError::General(format!("capacity serialization failed: {e}"))
                })?
            );
            continue;
        }
        if quiet {
            continue;
        }
        println!("{}", t!(Msg::StegoProbeHeader, path = carrier.display()));
        println!("{}", t!(Msg::StegoProbeFormat, val = cap.format));
        println!("{}", t!(Msg::StegoProbeAlgorithm, val = cap.algorithm));
        if let Some(ref m) = cap.media_info {
            println!("{}", t!(Msg::StegoProbeMediaInfo, val = m));
        }
        println!(
            "{}",
            t!(Msg::StegoProbeTotalElements, val = cap.total_elements)
        );
        let approx = if cap.is_estimated { "~" } else { "" };
        println!(
            "{}",
            t!(
                Msg::StegoProbePayloadSlots,
                val = format_args!("{approx}{}", cap.available_slots)
            )
        );
        let kib = cap.max_raw_payload_bytes as f64 / 1024.0;
        let max_raw_msg = if cap.max_raw_is_grouped {
            Msg::StegoProbeMaxRawGrouped
        } else {
            Msg::StegoProbeMaxRaw
        };
        println!(
            "{}",
            t!(
                max_raw_msg,
                bytes = format_args!("{approx}{}", cap.max_raw_payload_bytes),
                kib = format_args!("{approx}{kib:.1}")
            )
        );
        let safe_kib = cap.recommended_max_bytes as f64 / 1024.0;
        println!(
            "{}",
            t!(
                Msg::StegoProbeRecommended,
                bytes = format_args!("{approx}{}", cap.recommended_max_bytes),
                kib = format_args!("{approx}{safe_kib:.1}"),
                level = cap.safety_level,
                bpp = format_args!("{:.2}", cap.safety_bpp_limit)
            )
        );
        println!(
            "{}",
            t!(Msg::StegoProbeEstChanges, rate = cap.estimated_change_rate)
        );
        if cap.is_estimated {
            println!("{}", t!(Msg::StegoProbeEstimatedNote));
        }
    }
    Ok(())
}

/// Read-only capacity probe: `strhide capacity [CARRIERS]...`.
pub(crate) fn handle_capacity(
    args: CapacityArgs,
    cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<(), StrHideError> {
    run_capacity_probe(args.carrier, &args.tuning, cfg, quiet, engine, args.json)
}

pub(crate) fn handle_embed(
    args: EmbedArgs,
    cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<(), StrHideError> {
    // The user password is the only runtime credential: a private no-password
    // dialect (secret, domain, wire-format identity) is compile-time Profile
    // territory and is bound on the engine, not populated from runtime data.
    if args.capacity {
        return run_capacity_probe(
            args.carrier.clone(),
            &args.tuning,
            cfg,
            quiet,
            engine,
            false,
        );
    }

    // 1. Resolve password
    let encrypt = args.encrypt || cfg.encrypt.unwrap_or(false);
    let password = resolve_password(
        args.tuning.passwords.password.as_deref(),
        args.tuning.passwords.password_file.as_deref(),
        cfg,
        encrypt,
        true,
    )?;
    // The content half of the dialect is bound on the engine; both halves are
    // `Copy`, so taking a local copy keeps the call sites below simple.
    let dialect = engine.dialect().stego;

    // 2. Resolve payload (shared with `write`).
    let payload = match resolve_payload(
        &args.payload,
        args.tuning.unescape,
        cfg,
        PayloadFlavor::Bytes,
    )? {
        ResolvedPayload::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf)?;
            Payload::owned(buf)
        }
        ResolvedPayload::File(f) => {
            let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let data = std::fs::read(&f)?;
            Payload::owned_file(name, data)
        }
        ResolvedPayload::TextFile(p) => {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let data = std::fs::read(&p)?;
            Payload::owned_file(name, data)
        }
        ResolvedPayload::Text(t) => {
            Payload::owned(t.into_bytes()).with_kind(crate::core::payload::PayloadKind::Text)
        }
        ResolvedPayload::Bytes(b) => Payload::owned(b),
    };

    if payload.is_empty() {
        return Err(StrHideError::General("Payload cannot be empty".into()));
    }
    let payload_len = payload.len();

    let multi = args.carrier.len() > 1;
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "embedding into")?;
    for carrier in &args.carrier {
        if !carrier.exists() {
            return Err(StrHideError::General(format!(
                "Carrier file '{}' not found",
                carrier.display()
            )));
        }
        // A dry run writes nothing, so the overwrite pre-check does not apply.
        if args.dry_run {
            continue;
        }
        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = target {
            check_overwrite(t, args.overwrite)?;
        }
    }

    for_each_carrier(&args.carrier, quiet, |carrier| {
        let t_start = std::time::Instant::now();
        let carrier_bytes = std::fs::read(carrier)?;

        let (mut options, probe_options) = stego_options(
            &args.tuning,
            password.as_deref(),
            carrier_format(&carrier_bytes),
            cfg,
        )?;
        options.no_filename = args.no_filename;

        let output = crate::stego::embed_carrier_with_dialect_info(
            &carrier_bytes,
            &payload,
            &options,
            &dialect,
        )?;
        let stego_bytes = output.bytes;
        let cap_info = output.capacity;

        if !quiet && options.safety.enforcement == SafetyEnforcement::Advisory {
            let cap_fallback;
            let cap = match cap_info.as_ref() {
                Some(c) => Some(c),
                None => {
                    cap_fallback = crate::stego::probe_carrier_capacity_with_dialect(
                        &carrier_bytes,
                        &probe_options,
                        &dialect,
                    )
                    .ok();
                    cap_fallback.as_ref()
                }
            };
            if let Some(cap) = cap
                && payload_len > cap.recommended_max_bytes
            {
                let bpp = (payload_len * 8) as f64 / cap.total_elements as f64;
                eprintln!(
                    "[WARN] Payload ({} bytes, bpp {:.4}) exceeds recommended safety threshold ({} bytes, tier: '{}', bpp <= {:.2}). Detection risk is elevated.",
                    payload_len,
                    bpp,
                    cap.recommended_max_bytes,
                    options.safety.level.as_str(),
                    options.safety.level.bpp_limit()
                );
            }
        }

        if args.dry_run {
            // Full rehearsal, no disk write: everything up to and including the
            // embed ran (capacity, safety gate, credential resolution), only the
            // commit is skipped.
            if !quiet {
                println!(
                    "[DRY-RUN] {} -> {} bytes stego (carrier {} bytes, +{} bytes, +{:.2}%). No file written.",
                    carrier.display(),
                    stego_bytes.len(),
                    carrier_bytes.len(),
                    stego_bytes.len().saturating_sub(carrier_bytes.len()),
                    if !carrier_bytes.is_empty() {
                        (stego_bytes.len() as f64 - carrier_bytes.len() as f64)
                            / carrier_bytes.len() as f64
                            * 100.0
                    } else {
                        0.0
                    }
                );
                if let Some(ref cap) = cap_info {
                    let used_pct = if cap.recommended_max_bytes > 0 {
                        (payload_len as f64 / cap.recommended_max_bytes as f64) * 100.0
                    } else {
                        0.0
                    };
                    println!(
                        "{}",
                        t!(
                            Msg::EmbedCapacityReport,
                            safe = cap.recommended_max_bytes,
                            used = format_args!("{used_pct:.1}"),
                            max = cap.max_raw_payload_bytes,
                            slots = cap.available_slots
                        )
                    );
                }
            }
            return Ok(());
        }

        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref dest) = target {
            check_overwrite(dest, args.overwrite)?;
        }
        let dest = target.unwrap_or_else(|| carrier.to_path_buf());

        let backup = !args.no_backup && cfg.backup.unwrap_or(true);
        let backup_created =
            crate::structure::commit_carrier_bytes(carrier, &dest, &stego_bytes, backup, true)?;

        if let Some(ref bak) = backup_created
            && !quiet
        {
            println!("{}", t!(Msg::InfoBackupCreated, path = bak.display()));
        }

        if !quiet {
            let elapsed = t_start.elapsed();
            let elapsed_str = if elapsed.as_secs_f64() < 1.0 {
                format!("{:.0}ms", elapsed.as_secs_f64() * 1000.0)
            } else {
                format!("{:.2}s", elapsed.as_secs_f64())
            };
            let is_inplace = crate::structure::same_file(carrier, &dest);
            if is_inplace {
                println!(
                    "{}",
                    t!(
                        Msg::EmbedOkInPlace,
                        bytes = payload_len,
                        carrier = carrier.display(),
                        elapsed = elapsed_str
                    )
                );
            } else {
                println!(
                    "{}",
                    t!(
                        Msg::EmbedOkDest,
                        bytes = payload_len,
                        carrier = carrier.display(),
                        dest = dest.display(),
                        elapsed = elapsed_str
                    )
                );
            }
            if let Some(ref cap) = cap_info {
                let used_pct = if cap.recommended_max_bytes > 0 {
                    (payload_len as f64 / cap.recommended_max_bytes as f64) * 100.0
                } else {
                    0.0
                };
                println!(
                    "{}",
                    t!(
                        Msg::EmbedCapacityReport,
                        safe = cap.recommended_max_bytes,
                        used = format_args!("{used_pct:.1}"),
                        max = cap.max_raw_payload_bytes,
                        slots = cap.available_slots
                    )
                );
            }
        }
        Ok(())
    })
}

pub(crate) fn handle_extract(
    args: ExtractArgs,
    cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<(), StrHideError> {
    let multi = args.carrier.len() > 1;
    if multi && args.stdout {
        return Err(StrHideError::General(
            "`--stdout` prints a single payload and cannot be combined with multiple carriers. Use `-o <DIR>` instead."
                .into(),
        ));
    }
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "extracting from")?;
    if multi && args.output.is_none() {
        return Err(StrHideError::General(
            "Extracting from several carriers needs `-o <DIR>`: the payload filenames can collide."
                .into(),
        ));
    }

    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    for_each_carrier(&args.carrier, quiet, |carrier| {
        extract_one(
            carrier,
            &args,
            output_dir,
            password.as_deref(),
            cfg,
            quiet,
            engine,
        )
    })
}

/// Extract one content-domain payload (the body of the `extract` batch).
///
/// Only the *path* decisions changed with batch support: the payload is still
/// self-describing (format, algorithm, every cost-map hyperparameter), so the
/// only credential is the password.
fn extract_one(
    carrier: &Path,
    args: &ExtractArgs,
    output_dir: Option<&Path>,
    password: Option<&str>,
    cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<(), StrHideError> {
    let carrier_bytes = std::fs::read(carrier)?;

    // A private no-password dialect is compile-time `Dialect` territory on the
    // engine, not a command-line flag.
    let dialect = engine.dialect().stego;
    let options = crate::stego::ExtractOptions {
        password,
        ..Default::default()
    };

    let payload = match crate::stego::extract_carrier_payload(&carrier_bytes, &options, &dialect) {
        Ok(p) => p,
        Err(e) => {
            #[cfg(feature = "structure")]
            if matches!(
                e,
                StrHideError::NoHiddenData(_) | StrHideError::UnsupportedFormat(_)
            ) && let Ok(inspect_res) = crate::structure::inspect_carrier_with(
                carrier,
                password,
                &engine.dialect().structure,
            ) && inspect_res.has_hidden_data
            {
                if args.auto {
                    if !quiet {
                        eprintln!(
                            "No content stego found; auto-redirecting to structure-domain read..."
                        );
                    }
                    let read_args = ReadArgs {
                        carrier: vec![carrier.to_path_buf()],
                        output: args.output.clone(),
                        passwords: args.passwords.clone(),
                        stdout: args.stdout,
                        overwrite: args.overwrite,
                        auto: false,
                    };
                    return handle_read(read_args, cfg, quiet, engine);
                } else {
                    return Err(StrHideError::NoHiddenData(format!(
                        "No content-adaptive steganography found, but detected structure-domain hidden data ({}, strategy: {}). Use `strhide read` or add `--auto` to read.",
                        inspect_res.format.as_str(),
                        inspect_res.strategy.map(|s| s.name()).unwrap_or("auto")
                    )));
                }
            }
            return Err(e);
        }
    };

    // `-o <DIR>` wins over `-o <FILE>`: for a batch it is the only sensible
    // shape, and for a single carrier it means "keep the recorded name". An
    // unnamed payload is named after its carrier so a batch cannot collide.
    let explicit = match output_dir {
        Some(dir) => {
            let recorded = payload.name().unwrap_or_default();
            let is_file = !matches!(payload.kind(), crate::core::payload::PayloadKind::Text);
            Some(dir.join(crate::core::fs::batch_payload_name(
                carrier, recorded, is_file,
            )))
        }
        None => args.output.clone(),
    };

    if let Some(ref out_path) = explicit {
        let dest = if out_path.is_dir() {
            let name = payload.name().unwrap_or("extracted.bin");
            out_path.join(name)
        } else {
            out_path.clone()
        };
        check_overwrite(&dest, args.overwrite)?;
        std::fs::write(&dest, payload.as_bytes())?;
        if !quiet {
            println!(
                "{}",
                t!(Msg::ExtractOk, bytes = payload.len(), path = dest.display())
            );
        }
    } else if args.stdout {
        std::io::stdout().write_all(payload.as_bytes())?;
    } else if let Some(name) = payload.name() {
        let dest = PathBuf::from(name);
        check_overwrite(&dest, args.overwrite)?;
        std::fs::write(&dest, payload.as_bytes())?;
        if !quiet {
            println!(
                "{}",
                t!(Msg::ExtractOk, bytes = payload.len(), path = dest.display())
            );
        }
    } else if let Ok(text) = std::str::from_utf8(payload.as_bytes()) {
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
    } else {
        let dest = PathBuf::from("extracted.bin");
        check_overwrite(&dest, args.overwrite)?;
        std::fs::write(&dest, payload.as_bytes())?;
        if !quiet {
            println!("{}", t!(Msg::ExtractBinaryDetected, bytes = payload.len()));
        }
    }

    Ok(())
}
