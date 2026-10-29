// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Structure-domain verbs: `write`, `read`, `restore`.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::core::config::FileConfig;
use crate::core::control::Control;
use crate::core::i18n::Msg;
use crate::core::pipeline::{
    BatchPreflight, batch_output_dir, check_overwrite, for_each_carrier, preflight_batch,
    resolve_carrier_target,
};
use crate::errors::StrHideError;
use crate::facade::StrHide;
use crate::structure::registry::find_adapter_or_reject;
use crate::structure::{
    PayloadSource, ReadOptions, RestoreOptions, WriteOptions, read_carrier_with_dialect,
    remove_carrier_with_dialect, write_carrier_with,
};
use crate::t;

use super::args::*;
use super::cmd_stego::handle_extract;
use super::helpers::*;
use super::render::{print_remove_result, print_write_result};

pub(crate) fn handle_write(
    args: WriteArgs,
    cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<(), StrHideError> {
    // Config values act as defaults; explicit CLI flags win. --stealth implies
    // encryption (its magics are password-derived); prompt for a password when
    // neither -p nor a password source was supplied.
    let stealth = args.stealth || cfg.stealth.unwrap_or(false);
    let encrypt = args.encrypt || cfg.encrypt.unwrap_or(false);
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        encrypt || stealth,
        true,
    )?;

    let multi = args.carrier.len() > 1;
    // A single file path cannot name every output, so with several carriers
    // -o must be an existing directory.
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "writing to")?;

    let mut strategy = args
        .strategy
        .clone()
        .or_else(|| cfg.strategy.clone())
        .unwrap_or_else(|| "auto".to_string());
    if strategy == "ask" {
        if multi {
            // The prompt answers for one carrier; asking once per file is
            // almost never what a batch user means, so refuse up front rather
            // than interleaving prompts with writes.
            return Err(StrHideError::General(
                "Interactive strategy selection (--strategy ask) cannot be combined with multiple carriers. Use --strategy auto or name a strategy explicitly.".into(),
            ));
        }
        let carrier = &args.carrier[0];
        let mut cf = File::open(carrier)?;
        let adapter = find_adapter_or_reject(&mut cf, &carrier.display().to_string())?;
        let strats = adapter.supported_strategies();
        println!(
            "{}",
            t!(Msg::PromptAvailableStrategies, path = carrier.display())
        );
        for (idx, s) in strats.iter().enumerate() {
            println!("  [{}] {s}", idx + 1);
        }
        print!("{}", t!(Msg::PromptSelectStrategy, max = strats.len()));
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let choice = input.trim();
        if let Ok(c) = choice.parse::<usize>() {
            if c >= 1 && c <= strats.len() {
                strategy = strats[c - 1].to_string();
            } else {
                strategy = strats[0].to_string();
            }
        } else {
            strategy = strats[0].to_string();
        }
    }

    // Resolve payload source (shared with `embed`).
    let text_buf: String;
    let payload_path: PathBuf;
    let payload_source: PayloadSource =
        match resolve_payload(&args.payload, args.unescape, cfg, PayloadFlavor::Text)? {
            ResolvedPayload::Stdin => PayloadSource::Stdin,
            ResolvedPayload::File(f) => {
                payload_path = f;
                PayloadSource::File(&payload_path)
            }
            ResolvedPayload::TextFile(p) => {
                text_buf = std::fs::read_to_string(p)?;
                PayloadSource::Text(&text_buf)
            }
            ResolvedPayload::Text(t) => {
                text_buf = t;
                PayloadSource::Text(&text_buf)
            }
            ResolvedPayload::Bytes(b) => {
                text_buf = String::from_utf8(b).map_err(|e| {
                    StrHideError::General(format!("Base64 content is not valid UTF-8: {e}"))
                })?;
                PayloadSource::Text(&text_buf)
            }
        };

    // Buffer the payload once. Sources are resolved here rather than per
    // carrier because --stdin can only be read once, and because this keeps the
    // stored filename / is_file flags byte-identical to single-carrier writes.
    let (payload, payload_name, payload_is_file) = payload_source.into_buffered()?;

    // Fail before the first carrier is modified when a batch is obviously bad
    // (missing/unrecognized files, duplicate targets, unpermitted overwrites).
    if multi {
        preflight_batch(BatchPreflight {
            carriers: &args.carrier,
            in_place: args.in_place,
            output: args.output.as_deref(),
            output_dir,
            overwrite: args.overwrite,
            validate: Some(&validate_carrier_format),
        })?;
    } else {
        let carrier = &args.carrier[0];
        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = target {
            check_overwrite(t, args.overwrite)?;
        }
    }

    // A password hint is incompatible with --stealth: stealth mode requires the
    // password to locate the envelope, so nothing can be left in the clear.
    // A hint that only comes from the config file is a default the user did not
    // ask for on this run — drop it instead of failing the write with an error
    // that blames `--stealth`. An explicit `-H` is still passed through so the
    // engine can report the conflict.
    let hint = if stealth && args.hint.is_none() {
        None
    } else {
        args.hint.clone().or_else(|| cfg.hint.clone())
    };
    let preserve_time = args.preserve_time && cfg.preserve_time.unwrap_or(true);
    let backup = !args.no_backup && cfg.backup.unwrap_or(true);

    for_each_carrier(&args.carrier, quiet, |carrier| {
        let t_start = std::time::Instant::now();
        let output =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = output {
            check_overwrite(t, args.overwrite)?;
        }
        let res = write_carrier_with(
            carrier,
            PayloadSource::Buffered {
                data: &payload,
                filename: &payload_name,
                is_file: payload_is_file,
            },
            &WriteOptions {
                output_path: output.as_deref(),
                password: password.as_deref(),
                password_hint: hint.as_deref(),
                strategy: &strategy,
                stealth,
                preserve_time,
                backup,
                overwrite: args.overwrite,
                control: Control::none(),
            },
            engine.local_params(),
            &engine.dialect().structure,
        )?;
        print_write_result(&res, quiet, t_start.elapsed());
        Ok(())
    })
}

pub(crate) fn handle_read(
    args: ReadArgs,
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
    // `-o` names one output; with several carriers it must be a directory.
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "reading")?;
    if multi && args.output.is_none() {
        return Err(StrHideError::General(
            "Reading several carriers needs `-o <DIR>`: the payload filenames recorded in the carriers can collide."
                .into(),
        ));
    }

    let mut password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    for_each_carrier(&args.carrier, quiet, |carrier| {
        read_one(
            carrier,
            &args,
            output_dir,
            &mut password,
            cfg,
            quiet,
            engine,
        )
    })
}

/// Extract one carrier's payload (the body of the `read` batch).
///
/// Split out of [`handle_read`] so the single- and multi-carrier paths share
/// every decision — password retry, cross-domain hint, output naming — instead
/// of the batch loop re-implementing a drift-prone subset.
fn read_one(
    carrier: &Path,
    args: &ReadArgs,
    output_dir: Option<&Path>,
    password: &mut Option<String>,
    cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<(), StrHideError> {
    let t_start = std::time::Instant::now();
    // In batch mode (`-o <DIR>`) the payload is read in memory and named here:
    // the engine can only name outputs after the recorded filename, which is
    // absent for text payloads, and two unnamed payloads would collide on
    // `extracted.bin`.
    let output_path = match output_dir {
        Some(_) => None,
        None => args.output.as_deref(),
    };
    let res = match read_carrier_with_dialect(
        carrier,
        &ReadOptions {
            output_path,
            password: password.as_deref(),
            overwrite: args.overwrite,
            control: Control::none(),
        },
        &engine.dialect().structure,
    ) {
        Ok(r) => r,
        // Discriminate by error variant, not by message text. A password error
        // with no password supplied means the envelope is encrypted: show the
        // hint (a structured field on the error), then prompt (interactive
        // terminals only) and retry once.
        Err(e @ StrHideError::PasswordWithHint { .. }) if password.is_none() => {
            if !quiet && let Some(hint) = e.hint() {
                println!("{}", t!(Msg::InfoPasswordHint, hint = hint));
            }
            if !(std::io::IsTerminal::is_terminal(&std::io::stdin())
                && std::io::IsTerminal::is_terminal(&std::io::stdout()))
            {
                return Err(StrHideError::Password(
                    "Password required but no interactive terminal is available. Use -p/--password, --password-file, or STRHIDE_PASSWORD.".into(),
                ));
            }
            *password = Some(prompt_password(false)?);
            read_carrier_with_dialect(
                carrier,
                &ReadOptions {
                    output_path,
                    password: password.as_deref(),
                    overwrite: args.overwrite,
                    control: Control::none(),
                },
                &engine.dialect().structure,
            )?
        }
        Err(e @ StrHideError::NoHiddenData(_)) => {
            #[cfg(feature = "content")]
            {
                let inspect_opts = crate::stego::InspectOptions::new()
                    .with_password(password.as_deref().unwrap_or_default());
                if let Ok(stego_info) = engine.stego().inspect_file(carrier, &inspect_opts)
                    && stego_info.has_hidden_data
                {
                    if args.auto {
                        if !quiet {
                            eprintln!(
                                "No structure hidden data found; auto-redirecting to content steganography extraction..."
                            );
                        }
                        let extract_args = ExtractArgs {
                            carrier: vec![carrier.to_path_buf()],
                            output: args.output.clone(),
                            stdout: args.stdout,
                            overwrite: args.overwrite,
                            passwords: args.passwords.clone(),
                            auto: false,
                        };
                        return handle_extract(extract_args, cfg, quiet, engine);
                    } else {
                        return Err(StrHideError::NoHiddenData(format!(
                            "No structure-domain envelope found, but detected content-adaptive steganography ({}, {}). Use `strhide extract` or add `--auto` to extract.",
                            stego_info.format,
                            stego_info.algorithm.as_deref().unwrap_or("stego")
                        )));
                    }
                }
            }
            return Err(e);
        }
        Err(e) => return Err(e),
    };

    // A password was supplied but the envelope is not encrypted: the built-in
    // public key masked it, so the password had no effect. Say so instead of
    // letting the user believe `-p` protected this payload.
    if password.is_some() && !res.is_encrypted && !quiet {
        eprintln!("{}", t!(Msg::WarnEnvelopeNotEncrypted));
    }

    if let Some(dir) = output_dir {
        let name = crate::core::fs::batch_payload_name(carrier, &res.filename, res.is_file);
        let dest = dir.join(name);
        check_overwrite(&dest, args.overwrite)?;
        std::fs::write(&dest, &res.data)?;
        if !quiet {
            let elapsed_str = format_duration(t_start.elapsed());
            println!(
                "{}",
                t!(
                    Msg::ReadOkExtracted,
                    path = dest.display(),
                    bytes = format_size(res.raw_size),
                    elapsed = elapsed_str
                )
            );
        }
    } else if let Some(wf) = res.written_file {
        if !quiet {
            let elapsed_str = format_duration(t_start.elapsed());
            println!(
                "{}",
                t!(
                    Msg::ReadOkExtracted,
                    path = wf.display(),
                    bytes = format_size(res.raw_size),
                    elapsed = elapsed_str
                )
            );
        }
    } else if args.stdout || !res.is_file {
        if let Ok(text) = std::str::from_utf8(&res.data) {
            print!("{text}");
        } else {
            std::io::stdout().write_all(&res.data)?;
        }
    } else {
        // Default filename in current dir; the metadata filename is untrusted
        // input, so sanitize it to a bare name (no traversal, no absolute path).
        let fn_to_use = if res.filename.is_empty() {
            "extracted.bin".to_string()
        } else {
            crate::structure::sanitize_filename(&res.filename)
        };
        // Same overwrite protection as the explicit-output path: never truncate
        // a file the user did not name.
        if Path::new(&fn_to_use).exists() && !args.overwrite {
            return Err(StrHideError::Rejection(format!(
                "Refusing to overwrite existing file '{fn_to_use}'. Choose another -o path or pass --overwrite."
            )));
        }
        let mut f = File::create(&fn_to_use).map_err(|e| {
            let reason = match e.kind() {
                std::io::ErrorKind::PermissionDenied => "permission denied",
                _ => "the file could not be created",
            };
            StrHideError::General(format!("Cannot create '{fn_to_use}': {reason} [{e}]"))
        })?;
        f.write_all(&res.data)?;
        if !quiet {
            let elapsed_str = format_duration(t_start.elapsed());
            println!(
                "{}",
                t!(
                    Msg::ReadOkExtracted,
                    path = fn_to_use,
                    bytes = format_size(res.raw_size),
                    elapsed = elapsed_str
                )
            );
        }
    }

    Ok(())
}

pub(crate) fn handle_restore(
    args: RestoreArgs,
    cfg: &FileConfig,
    quiet: bool,
    engine: &StrHide,
) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let multi = args.carrier.len() > 1;
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "removing hidden data from")?;
    if multi {
        preflight_batch(BatchPreflight {
            carriers: &args.carrier,
            in_place: args.in_place,
            output: args.output.as_deref(),
            output_dir,
            overwrite: args.overwrite,
            validate: Some(&validate_carrier_format),
        })?;
    } else {
        let carrier = &args.carrier[0];
        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = target {
            check_overwrite(t, args.overwrite)?;
        }
    }
    // Mirror `write`: `remove` also honours the configured backup default
    // (`config.rs` documents `backup` as covering both commands).
    let backup = !args.no_backup && cfg.backup.unwrap_or(true);

    for_each_carrier(&args.carrier, quiet, |carrier| {
        let t_start = std::time::Instant::now();
        let output =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = output {
            check_overwrite(t, args.overwrite)?;
        }
        // The user has already answered the overwrite question above, so the
        // library-level refusal is bypassed deliberately.
        let res = remove_carrier_with_dialect(
            carrier,
            &RestoreOptions {
                output_path: output.as_deref(),
                password: password.as_deref(),
                backup,
                overwrite: args.overwrite,
                control: Control::none(),
            },
            &engine.dialect().structure,
        )?;
        print_remove_result(&res, quiet, t_start.elapsed());
        Ok(())
    })
}
