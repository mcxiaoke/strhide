// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Content-domain verbs: `embed`, `extract`, `capacity`.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::core::config::FileConfig;
use crate::core::control::Control;
use crate::core::i18n::Msg;
use crate::core::payload::Payload;
use crate::core::pipeline::{
    BatchPreflight, batch_output_dir, check_overwrite, preflight_batch, resolve_carrier_target,
    validate_carriers_exist,
};
use crate::errors::StrHideError;
use crate::facade::{DualOptions, StrHide};
use crate::stego::SafetyEnforcement;
use crate::t;

use super::args::*;
use super::cmd_structure::handle_read;
use super::helpers::*;
use super::render::print_json;

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
    if !json {
        validate_carriers_exist(&carriers)?;
    }
    log::info!("Starting capacity probe: {} carrier(s)", carriers.len());

    let password = tuning.passwords.resolve(false, false)?;
    let key = resolve_key_file(tuning.key_file.as_deref())?;
    let is_batch = carriers.len() > 1;
    let mut failures = 0usize;
    let mut last_error: Option<StrHideError> = None;
    let mut json_items: Vec<serde_json::Value> = Vec::new();

    for carrier in &carriers {
        let t_start = std::time::Instant::now();
        let carrier_bytes = match crate::stego::io::read_carrier_file(carrier) {
            Ok(bytes) => bytes,
            Err(err) => {
                if json {
                    json_items.push(serde_json::json!({
                        "path": carrier.display().to_string(),
                        "error": err.to_string(),
                    }));
                } else if is_batch && !quiet {
                    eprintln!(
                        "{}",
                        t!(Msg::WarnCapacityFailed, path = carrier.display(), err = err)
                    );
                }
                failures += 1;
                last_error = Some(err);
                continue;
            }
        };
        let (_, options) = match stego_options(
            tuning,
            password.as_deref(),
            key.as_ref(),
            carrier_format(&carrier_bytes),
            cfg,
        ) {
            Ok(opts) => opts,
            Err(e) => {
                if json {
                    json_items.push(serde_json::json!({
                        "path": carrier.display().to_string(),
                        "error": e.to_string(),
                    }));
                } else if is_batch && !quiet {
                    eprintln!(
                        "{}",
                        t!(Msg::WarnCapacityFailed, path = carrier.display(), err = e)
                    );
                }
                failures += 1;
                last_error = Some(e);
                continue;
            }
        };
        let cap = match crate::stego::probe_carrier_capacity_with_dialect(
            &carrier_bytes,
            &options,
            &engine.dialect().stego,
        ) {
            Ok(c) => c,
            Err(e) => {
                if json {
                    json_items.push(serde_json::json!({
                        "path": carrier.display().to_string(),
                        "error": e.to_string(),
                    }));
                } else if is_batch && !quiet {
                    eprintln!(
                        "{}",
                        t!(Msg::WarnCapacityFailed, path = carrier.display(), err = e)
                    );
                }
                failures += 1;
                last_error = Some(e);
                continue;
            }
        };
        if json {
            json_items.push(serde_json::to_value(&cap).map_err(|e| {
                StrHideError::General(format!("capacity serialization failed: {e}"))
            })?);
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
    if json {
        // Single carrier keeps the historical top-level object shape; a batch
        // must be one JSON document, not one concatenated object per line.
        if json_items.len() == 1 {
            print_json(&json_items[0])?;
        } else {
            print_json(&json_items)?;
        }
    }
    if failures > 0 {
        if is_batch {
            return Err(StrHideError::General(format!(
                "{failures} of {} files failed to probe capacity",
                carriers.len()
            )));
        } else if let Some(e) = last_error {
            return Err(StrHideError::General(format!(
                "{}: {e}",
                carriers[0].display()
            )));
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
    validate_carriers_exist(&args.carrier)?;
    log::info!("Starting embed: {} carrier(s)", args.carrier.len());

    // 1. Resolve password
    let encrypt = args.prompt_password || cfg.encrypt.unwrap_or(false);
    let password = args.tuning.passwords.resolve(encrypt, true)?;
    let key = resolve_key_file(args.tuning.key_file.as_deref())?;
    // The content half of the dialect is bound on the engine; both halves are
    // `Copy`, so taking a local copy keeps the call sites below simple.
    let dialect = engine.dialect().stego;

    // 2. Resolve payload (shared with `write`).
    let payload = match resolve_payload(&args.payload, args.unescape, cfg)? {
        ResolvedPayload::Stdin => {
            // A pipe can be arbitrarily large; reading it unbounded lets a
            // mistyped redirect exhaust memory before the carrier's own capacity
            // check ever runs. 1 GiB matches the extraction-side payload ceiling.
            const MAX_STDIN_PAYLOAD: u64 = 1 << 30;
            let mut buf = Vec::new();
            let read = std::io::stdin()
                .take(MAX_STDIN_PAYLOAD + 1)
                .read_to_end(&mut buf)?;
            if read as u64 > MAX_STDIN_PAYLOAD {
                return Err(StrHideError::General(
                    "Payload from --stdin exceeds the 1 GiB limit".into(),
                ));
            }
            Payload::owned(buf)
        }
        ResolvedPayload::File(f) => {
            let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let data = std::fs::read(&f)?;
            Payload::owned_file(name, data)
        }
        ResolvedPayload::Text(t) => {
            Payload::owned(t.into_bytes()).with_kind(crate::core::payload::PayloadKind::Text)
        }
    };

    if payload.is_empty() {
        return Err(StrHideError::General("Payload cannot be empty".into()));
    }
    let payload_len = payload.len();

    let multi = args.carrier.len() > 1;
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "embedding into")?;
    // Cross-domain occupancy is an orchestration decision: the structure and
    // content engines cannot inspect each other. Do it in preflight so a
    // multi-carrier batch fails before the first carrier is modified.
    let dual_opts = DualOptions {
        password: password.as_deref(),
        key: key.as_ref(),
        // Use the engine's bound content domain, not the official one: a
        // caller-supplied private dialect must be able to detect its own
        // payload in the cross-domain occupancy preflight.
        domain: engine.dialect().stego.stego_domain(),
        control: Control::none(),
    };
    let carrier_ready = |carrier: &Path| -> Result<(), StrHideError> {
        validate_stego_carrier_format(carrier)?;
        if !args.overwrite {
            engine.ensure_domains_free(carrier, &dual_opts)?;
        }
        Ok(())
    };
    if multi {
        preflight_batch(BatchPreflight {
            carriers: &args.carrier,
            in_place: args.in_place,
            output: args.output.as_deref(),
            output_dir,
            // A dry run writes nothing, so the overwrite pre-check does not apply.
            overwrite: args.dry_run || args.overwrite,
            validate: Some(&carrier_ready),
        })?;
    } else {
        validate_carriers_exist(&args.carrier)?;
        let carrier = &args.carrier[0];
        carrier_ready(carrier)?;
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
            stego_options(&args.tuning, password.as_deref(), key.as_ref(), format, cfg)?;
        options.no_filename = args.no_filename;

        if args.dry_run {
            // Dry-run still runs the whole in-memory embed, so it must pass the
            // same budget gate as a real write; sharing the reader keeps the
            // two paths from drifting apart.
            let (carrier_bytes, _) =
                crate::stego::io::read_carrier_for_embed(carrier, &payload, &options, &dialect)?;
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
                        // This probe only feeds the advisory warning below.
                        // Dropping its failure silently meant the user lost the
                        // "payload exceeds the safe tier" warning without being
                        // told why.
                        match crate::stego::probe_carrier_capacity_with_dialect(
                            &carrier_bytes,
                            &probe_options,
                            &dialect,
                        ) {
                            Ok(c) => {
                                cap_fallback = c;
                                Some(&cap_fallback)
                            }
                            Err(e) => {
                                if !quiet {
                                    eprintln!(
                                        "[WARN] safety-threshold check skipped: capacity probe failed: {e}"
                                    );
                                }
                                None
                            }
                        }
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
                        cap.safety_bpp_limit
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
        let preserve_time = args.preserve_time && cfg.preserve_time.unwrap_or(true);
        let file_target = crate::commit::FileTarget {
            output_path: target.as_deref(),
            backup,
            preserve_time,
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
                            "[WARN] Payload ({} bytes, bpp {:.4}) exceeds recommended safety threshold ({} bytes, tier: '{}', bpp <= {:.4}). Detection risk is elevated.",
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
    shared_batch: Option<&mut BatchOutputs<'_>>,
) -> Result<(), StrHideError> {
    validate_carriers_exist(&args.carrier)?;
    log::info!("Starting extract: {} carrier(s)", args.carrier.len());

    let multi = args.carrier.len() > 1;
    if multi && args.stdout {
        return Err(StrHideError::General(
            "`--stdout` prints a single payload and cannot be combined with multiple carriers. Use `-o <DIR>` instead."
                .into(),
        ));
    }
    if multi && args.output.is_none() {
        return Err(StrHideError::General(
            "Extracting from several carriers needs `-o <DIR>`: the payload filenames can collide."
                .into(),
        ));
    }

    let password = args.passwords.resolve(args.prompt_password, false)?;
    let key = resolve_key_file(args.key_file.as_deref())?;

    // Two carriers may record the same payload filename; keep this batch's
    // outputs distinct instead of overwriting or aborting halfway through.
    // `read --auto` hands over the outer batch so a redirected content payload
    // cannot collide with a name the structure side already reserved.
    let run = |batch: &mut BatchOutputs<'_>| {
        for_each_carrier(&args.carrier, quiet, |carrier| {
            extract_one(
                carrier,
                &args,
                batch,
                password.as_deref(),
                key.as_ref(),
                cfg,
                quiet,
                engine,
            )
        })
    };
    match shared_batch {
        Some(batch) => run(batch),
        None => {
            let output_dir = batch_output_dir(args.output.as_deref(), multi, "extracting from")?;
            run(&mut BatchOutputs::new(output_dir))
        }
    }
}

/// Extract one content-domain payload (the body of the `extract` batch).
///
/// Only the *path* decisions changed with batch support: the payload is still
/// self-describing, so the only credentials are the password or the file key.
#[allow(clippy::too_many_arguments)]
fn extract_one(
    carrier: &Path,
    args: &ExtractArgs,
    batch: &mut BatchOutputs<'_>,
    password: Option<&str>,
    key: Option<&[u8; 32]>,
    cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<(), StrHideError> {
    let t_start = std::time::Instant::now();
    let carrier_bytes = crate::stego::io::read_carrier_file(carrier)?;

    // A private no-password dialect is compile-time `Dialect` territory on the
    // engine, not a command-line flag.
    let dialect = engine.dialect().stego;
    let mut options = crate::stego::ExtractOptions {
        password,
        key,
        ..Default::default()
    };
    if let Some(max_payload) = args.max_payload {
        options.limits.max_payload_bytes = max_payload;
    }

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
                    let mut read_args = ReadArgs {
                        carrier: vec![carrier.to_path_buf()],
                        output: args.output.clone(),
                        passwords: args.passwords.clone(),
                        prompt_password: false,
                        stdout: args.stdout,
                        overwrite: args.overwrite,
                        auto: false,
                    };
                    if read_args.passwords.password.is_none() {
                        read_args.passwords.password = password.map(str::to_string);
                    }
                    return handle_read(read_args, cfg, quiet, engine, Some(batch));
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
    let explicit = match batch.dir {
        Some(dir) => {
            let recorded = payload.name().unwrap_or_default();
            let is_file = !matches!(payload.kind(), crate::core::payload::PayloadKind::Text);
            let name = crate::core::fs::batch_payload_name(carrier, recorded, is_file);
            Some(crate::core::fs::unique_batch_path(dir, &name, &batch.used))
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
        crate::core::commit::reject_carrier_output(&dest, &args.carrier)?;
        check_overwrite(&dest, args.overwrite)?;
        crate::core::commit::write_bytes_atomic(&dest, payload.as_bytes())?;
        batch.used.insert(dest.clone());
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
        crate::cli::render::write_payload_stdout(payload.as_bytes(), false)?;
    } else if let Some(raw_name) = payload.name() {
        let clean_name = crate::core::fs::sanitize_filename(raw_name);
        let dest = PathBuf::from(clean_name);
        crate::core::commit::reject_carrier_output(&dest, &args.carrier)?;
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
        // Implicit display path: untrusted text, so the terminal gets the
        // escaped form while ordinary line breaks stay readable.
        let safe = crate::core::fs::escape_terminal_text(text);
        print!("{safe}");
        if !text.ends_with('\n') {
            println!();
        }
    } else {
        let dest = PathBuf::from("extracted.bin");
        crate::core::commit::reject_carrier_output(&dest, &args.carrier)?;
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
