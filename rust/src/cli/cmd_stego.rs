// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Content-domain verbs: `embed`, `extract`, `capacity`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::core::config::FileConfig;
use crate::core::i18n::Msg;
use crate::core::payload::Payload;
use crate::core::pipeline::{
    BatchPreflight, batch_output_dir, check_overwrite, for_each_carrier, preflight_batch,
    resolve_carrier_target,
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
        false,
        false,
    )?;
    for carrier in &carriers {
        let t_start = std::time::Instant::now();
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

        let elapsed_str = format_duration(t_start.elapsed());
        println!(
            "{}",
            t!(
                Msg::StegoProbeHeader,
                path = carrier.display(),
                elapsed = elapsed_str
            )
        );

        // Line 1: Media info
        let is_zh = matches!(crate::core::i18n::lang(), crate::core::i18n::Lang::Zh);
        let elem_unit = if is_zh { "元素" } else { "elements" };
        let media_desc = if let Some(ref m) = cap.media_info {
            format!(
                "{}, {}, {} {}",
                cap.format,
                m,
                format_count(cap.total_elements as u64),
                elem_unit
            )
        } else {
            format!(
                "{}, {} {}",
                cap.format,
                format_count(cap.total_elements as u64),
                elem_unit
            )
        };
        println!("{}", t!(Msg::StegoProbeLineMedia, media = media_desc));

        // Line 2: Algorithm & Tuning & Rate
        let tier_label = if is_zh { "档位" } else { "tier" };
        let algo_desc = match &options.tuning {
            #[cfg(feature = "content-png")]
            crate::stego::StegoTuning::Png { params, .. } => {
                format!(
                    "{} (stc_h: {}, {}: {}, bpp <= {:.2})",
                    cap.algorithm, params.stc_h, tier_label, cap.safety_level, cap.safety_bpp_limit
                )
            }
            #[cfg(feature = "content-jpeg")]
            crate::stego::StegoTuning::Jpeg { params, .. } => {
                format!(
                    "{} (stc_h: {}, {}: {}, bpp <= {:.2})",
                    cap.algorithm, params.stc_h, tier_label, cap.safety_level, cap.safety_bpp_limit
                )
            }
            _ => {
                format!(
                    "{} ({}: {}, bpp <= {:.2})",
                    cap.algorithm, tier_label, cap.safety_level, cap.safety_bpp_limit
                )
            }
        };
        println!(
            "{}",
            t!(
                Msg::StegoProbeLineAlgo,
                algo = algo_desc,
                rate = cap.estimated_change_rate
            )
        );

        // Line 3: Capacity & Slots
        let approx = if cap.is_estimated { "~" } else { "" };
        let safe_str = format!("{approx}{}", format_size(cap.recommended_max_bytes as u64));
        let max_str = format!("{approx}{}", format_size(cap.max_raw_payload_bytes as u64));
        let slots_str = format!("{approx}{}", format_count(cap.available_slots as u64));
        let mut note = String::new();
        if cap.is_estimated {
            note.push_str(&t!(Msg::StegoProbeNoteExactHint));
        }
        if cap.max_raw_is_grouped {
            note.push_str(&t!(Msg::StegoProbeNoteGrouped));
        }
        println!(
            "{}",
            t!(
                Msg::StegoProbeLineCap,
                safe = safe_str,
                max = max_str,
                slots = slots_str,
                note = note
            )
        );
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
    if multi {
        preflight_batch(BatchPreflight {
            carriers: &args.carrier,
            in_place: args.in_place,
            output: args.output.as_deref(),
            output_dir,
            // A dry run writes nothing, so the overwrite pre-check does not apply.
            overwrite: args.dry_run || args.overwrite,
            validate: Some(&validate_stego_carrier_format),
        })?;
    } else {
        let carrier = &args.carrier[0];
        if !carrier.exists() {
            return Err(StrHideError::General(format!(
                "Carrier file '{}' not found",
                carrier.display()
            )));
        }
        if carrier.is_dir() {
            return Err(StrHideError::General(format!(
                "'{}' is a directory, not a carrier file",
                carrier.display()
            )));
        }
        validate_stego_carrier_format(carrier)?;
        if !args.dry_run {
            let target =
                resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
            if let Some(ref t) = target {
                check_overwrite(t, args.overwrite)?;
            }
        }
    }

    for_each_carrier(&args.carrier, quiet, |carrier| {
        let t_start = std::time::Instant::now();
        let format = crate::formats::sniff_file(carrier)?;

        let (mut options, probe_options) =
            stego_options(&args.tuning, password.as_deref(), format, cfg)?;
        options.no_filename = args.no_filename;

        if args.dry_run {
            let carrier_bytes = std::fs::read(carrier)?;
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

            let algo_str = format_stego_algorithm(
                &options.tuning,
                &options.safety,
                carrier_format(&carrier_bytes),
                cap_info.as_ref().map(|c| c.algorithm.as_str()),
            );

            // Full rehearsal, no disk write: everything up to and including the
            // embed ran (capacity, safety gate, credential resolution), only the
            // commit is skipped.
            if !quiet {
                let elapsed_str = format_duration(t_start.elapsed());
                let diff = stego_bytes.len().saturating_sub(carrier_bytes.len());
                let pct = if !carrier_bytes.is_empty() {
                    (stego_bytes.len() as f64 - carrier_bytes.len() as f64)
                        / carrier_bytes.len() as f64
                        * 100.0
                } else {
                    0.0
                };
                let diff_str = format!("+{}", format_size(diff as u64));
                println!(
                    "{}",
                    t!(
                        Msg::EmbedDryRun,
                        carrier = carrier.display(),
                        algo = algo_str,
                        elapsed = elapsed_str,
                        stego = format_size(stego_bytes.len() as u64),
                        orig = format_size(carrier_bytes.len() as u64),
                        diff = diff_str,
                        pct = pct
                    )
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
                            safe = format_size(cap.recommended_max_bytes as u64),
                            used = format_args!("{used_pct:.1}"),
                            max = format_size(cap.max_raw_payload_bytes as u64),
                            slots = format_count(cap.available_slots as u64)
                        )
                    );
                }
            }
            return Ok(());
        }

        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        let backup = !args.no_backup && cfg.backup.unwrap_or(true);
        let file_target = crate::commit::FileTarget {
            output_path: target.as_deref(),
            backup,
            preserve_time: true,
            overwrite: args.overwrite,
        };

        let res = crate::stego::io::embed_carrier_file(
            carrier,
            &payload,
            &options,
            &dialect,
            &file_target,
        )?;

        if !quiet {
            for w in &res.warnings {
                match w {
                    crate::stego::StegoWarning::SafetyThresholdExceeded {
                        payload_bytes,
                        recommended_max_bytes,
                        safety_level,
                        actual_bpp,
                        limit_bpp,
                    } => {
                        eprintln!(
                            "[WARN] Payload ({} bytes, bpp {:.4}) exceeds recommended safety threshold ({} bytes, tier: '{}', bpp <= {:.2}). Detection risk is elevated.",
                            payload_bytes,
                            actual_bpp,
                            recommended_max_bytes,
                            safety_level,
                            limit_bpp
                        );
                    }
                }
            }

            if let Some(ref bak) = res.backup_file {
                println!("{}", t!(Msg::InfoBackupCreated, path = bak.display()));
            }

            let elapsed_str = format_duration(t_start.elapsed());
            let is_inplace = crate::structure::same_file(carrier, &res.written_to);
            let algo_str = format_stego_algorithm(
                &options.tuning,
                &options.safety,
                Some(res.format),
                res.capacity.as_ref().map(|c| c.algorithm.as_str()),
            );

            if is_inplace {
                println!(
                    "{}",
                    t!(
                        Msg::EmbedOkInPlace,
                        bytes = format_size(payload_len as u64),
                        carrier = carrier.display(),
                        algo = algo_str,
                        elapsed = elapsed_str
                    )
                );
            } else {
                println!(
                    "{}",
                    t!(
                        Msg::EmbedOkDest,
                        bytes = format_size(payload_len as u64),
                        carrier = carrier.display(),
                        dest = res.written_to.display(),
                        algo = algo_str,
                        elapsed = elapsed_str
                    )
                );
            }
            if let Some(ref cap) = res.capacity {
                let used_pct = if cap.recommended_max_bytes > 0 {
                    (payload_len as f64 / cap.recommended_max_bytes as f64) * 100.0
                } else {
                    0.0
                };
                println!(
                    "{}",
                    t!(
                        Msg::EmbedCapacityReport,
                        safe = format_size(cap.recommended_max_bytes as u64),
                        used = format_args!("{used_pct:.1}"),
                        max = format_size(cap.max_raw_payload_bytes as u64),
                        slots = format_count(cap.available_slots as u64)
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
    let t_start = std::time::Instant::now();
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
            let name =
                crate::core::fs::sanitize_filename(payload.name().unwrap_or("extracted.bin"));
            out_path.join(name)
        } else {
            out_path.clone()
        };
        check_overwrite(&dest, args.overwrite)?;
        crate::core::commit::write_bytes_atomic(&dest, payload.as_bytes())?;
        if !quiet {
            let elapsed_str = format_duration(t_start.elapsed());
            println!(
                "{}",
                t!(
                    Msg::ExtractOk,
                    bytes = format_size(payload.len() as u64),
                    path = dest.display(),
                    elapsed = elapsed_str
                )
            );
        }
    } else if args.stdout {
        std::io::stdout().write_all(payload.as_bytes())?;
    } else if let Some(raw_name) = payload.name() {
        let clean_name = crate::core::fs::sanitize_filename(raw_name);
        let dest = PathBuf::from(clean_name);
        check_overwrite(&dest, args.overwrite)?;
        crate::core::commit::write_bytes_atomic(&dest, payload.as_bytes())?;
        if !quiet {
            let elapsed_str = format_duration(t_start.elapsed());
            println!(
                "{}",
                t!(
                    Msg::ExtractOk,
                    bytes = format_size(payload.len() as u64),
                    path = dest.display(),
                    elapsed = elapsed_str
                )
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
        crate::core::commit::write_bytes_atomic(&dest, payload.as_bytes())?;
        if !quiet {
            let elapsed_str = format_duration(t_start.elapsed());
            println!(
                "{}",
                t!(
                    Msg::ExtractBinaryDetected,
                    bytes = format_size(payload.len() as u64),
                    elapsed = elapsed_str
                )
            );
        }
    }

    Ok(())
}
