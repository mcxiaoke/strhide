//! File-level convenience API for content-adaptive steganography.
//!
//! The bytes-level entry points in [`crate::stego`] do the embedding; this
//! module adds the file plumbing a host application would otherwise repeat:
//! read the carrier, embed in memory, commit atomically (temp file + rename),
//! optionally keep a `.bak` backup and clone the original timestamps.
//!
//! It is available with the `stego` feature alone — no structure-domain
//! `engine` required — so a pure stego consumer (e.g. a dedicated image tool)
//! does not have to reimplement ~150 lines of crash-safe file handling.

use std::path::Path;

#[cfg(feature = "content-hevc")]
use crate::commit::commit_carrier_patches;
use crate::commit::{FileTarget, commit_carrier_bytes, same_file};
use crate::core::payload::Payload;
use crate::core::pipeline::check_overwrite;
use crate::errors::StrHideError;
use crate::stego::embed_carrier_with_dialect_info;
use crate::stego::options::{EmbedOptions, ExtractOptions, StegoEmbedResult, StegoWarning};
use crate::stego::params::{SafetyEnforcement, StegoProfile};

/// Embed `payload` into the carrier file at `carrier_path` and commit the result.
///
/// The carrier is read, the embedding happens in memory, and the result is
/// committed through [`crate::commit::commit_carrier_bytes`] (same-directory
/// temp file + atomic rename, permissions and timestamps preserved) — the same
/// path the structure domain and the CLI use.
///
/// When `target_path` is `None` the carrier is replaced in place; otherwise the
/// result is written to `target_path` and the original carrier is left alone.
/// An in-place write keeps a `<carrier>.bak` copy when `backup` is set.
///
/// Embed `payload` into the carrier file at `carrier_path` and commit the result atomically.
pub fn embed_carrier_file(
    carrier_path: &Path,
    payload: &Payload<'_>,
    options: &EmbedOptions<'_>,
    dialect: &StegoProfile,
    target: &FileTarget<'_>,
) -> Result<StegoEmbedResult, StrHideError> {
    let carrier_meta = std::fs::metadata(carrier_path)?;
    let carrier_before_bytes = carrier_meta.len();
    let dest = target.output_path.unwrap_or(carrier_path);
    // `-o <same path as the carrier>` is an in-place write, not an overwrite of
    // a *different* file: refusing it because the destination exists would make
    // the explicit and implicit spellings of the same request behave
    // differently (review B-07). Other destinations keep the overwrite gate.
    if target.output_path.is_some() && !same_file(carrier_path, dest) {
        check_overwrite(dest, target.overwrite)?;
    }
    // Held until the commit finishes: a concurrent writer to the same target
    // must fail instead of silently replacing this payload.
    let _target_lock = crate::commit::TargetLock::acquire(dest)?;

    let (carrier_bytes, format) = read_carrier_for_embed(carrier_path, payload, options, dialect)?;
    let format = format.ok_or_else(|| {
        StrHideError::UnsupportedFormat(format!(
            "Failed to identify carrier format for '{}'",
            carrier_path.display()
        ))
    })?;

    #[cfg(feature = "content-hevc")]
    if matches!(
        format,
        crate::formats::FileFormat::Mp4 | crate::formats::FileFormat::HevcAnnexB
    ) {
        options.tuning.applicable_to(format)?;
        let domain = options.domain(dialect);
        options.control.check()?;
        let anon_payload;
        let eff_payload = if options.no_filename && payload.name().is_some() {
            anon_payload = Payload::bytes(payload.as_bytes());
            &anon_payload
        } else {
            payload
        };
        let direct = || {
            crate::stego::hevc::embed_hevc_patches_v4(
                &carrier_bytes,
                eff_payload,
                crate::stego::options::resolve_credential(options.password, options.key, dialect)?,
                domain,
                options
                    .suite_id
                    .unwrap_or_else(|| dialect.hevc_format().cipher.default_suite.as_u16()),
                &options.extensions,
                dialect.hevc_format(),
                options.freshness,
                options.safety,
                &options.control,
            )
        };
        let patches_res = match &options.pool {
            Some(pool) => pool.install(direct),
            None => direct(),
        };
        match patches_res {
            Ok((patches, capacity, stats)) => {
                // The unified embed/probe entries reserve the worst-case
                // filename overhead in their capacity report. The patch path
                // must do the same or `sth embed x.mp4` and `sth capacity x.mp4`
                // disagree by MAX_FILENAME_OVERHEAD bytes.
                let capacity = crate::stego::filename_safe_capacity(capacity);
                drop(carrier_bytes);
                let backup_file = commit_carrier_patches(
                    carrier_path,
                    dest,
                    &patches,
                    target.backup,
                    target.preserve_time,
                )?;
                let carrier_after_bytes = std::fs::metadata(dest)?.len();

                let mut warnings = Vec::new();
                if options.safety.enforcement == SafetyEnforcement::Advisory
                    && payload.as_bytes().len() > capacity.recommended_max_bytes
                {
                    let bpp = (payload.as_bytes().len() * 8) as f64
                        / capacity.total_elements.max(1) as f64;
                    warnings.push(StegoWarning::SafetyThresholdExceeded {
                        payload_bytes: payload.as_bytes().len(),
                        recommended_max_bytes: capacity.recommended_max_bytes,
                        safety_level: options.safety.level.as_str().to_string(),
                        actual_bpp: bpp,
                        limit_bpp: capacity.safety_bpp_limit,
                    });
                }

                return Ok(StegoEmbedResult {
                    carrier: carrier_path.to_path_buf(),
                    written_to: dest.to_path_buf(),
                    format,
                    payload_bytes: payload.as_bytes().len(),
                    carrier_before_bytes,
                    carrier_after_bytes,
                    backup_file,
                    capacity: Some(capacity),
                    stats: Some(stats),
                    warnings,
                });
            }
            Err(e) => return Err(e),
        }
    }

    let output = embed_carrier_with_dialect_info(&carrier_bytes, payload, options, dialect)?;
    let cap = match output.capacity {
        Some(c) => Some(c),
        None => {
            let probe_opts = crate::stego::ProbeOptions {
                password: options.password,
                key: options.key,
                domain: options.domain,
                extensions: options.extensions.clone(),
                safety: options.safety,
                tuning: options.tuning.clone(),
                exact: false,
                control: options.control,
                pool: options.pool.clone(),
            };
            // A carrier whose format simply has no capacity concept is the
            // only reason to report "unknown": every other error here is a
            // real decode failure that `embed` also hit, and swallowing it as
            // `None` would present a broken carrier as valid.
            match crate::stego::probe_carrier_capacity_with_dialect(
                &carrier_bytes,
                &probe_opts,
                dialect,
            ) {
                Ok(c) => Some(c),
                Err(StrHideError::UnsupportedFormat(_)) => None,
                Err(e) => return Err(e),
            }
        }
    };
    drop(carrier_bytes);
    let backup_file = commit_carrier_bytes(
        carrier_path,
        dest,
        &output.bytes,
        target.backup,
        target.preserve_time,
    )?;
    let carrier_after_bytes = std::fs::metadata(dest)?.len();

    let mut warnings = Vec::new();
    if options.safety.enforcement == SafetyEnforcement::Advisory
        && let Some(ref cap_ref) = cap
        && payload.as_bytes().len() > cap_ref.recommended_max_bytes
    {
        let bpp = (payload.as_bytes().len() * 8) as f64 / cap_ref.total_elements.max(1) as f64;
        warnings.push(StegoWarning::SafetyThresholdExceeded {
            payload_bytes: payload.as_bytes().len(),
            recommended_max_bytes: cap_ref.recommended_max_bytes,
            safety_level: options.safety.level.as_str().to_string(),
            actual_bpp: bpp,
            limit_bpp: cap_ref.safety_bpp_limit,
        });
    }

    Ok(StegoEmbedResult {
        carrier: carrier_path.to_path_buf(),
        written_to: dest.to_path_buf(),
        format,
        payload_bytes: payload.as_bytes().len(),
        carrier_before_bytes,
        carrier_after_bytes,
        backup_file,
        capacity: cap,
        stats: output.stats,
        warnings,
    })
}

/// Extract the payload from the carrier file at `carrier_path`.
///
/// The counterpart of [`embed_carrier_file`]: read the file, extract in memory,
/// return the payload bytes. Writing the payload somewhere is the caller's
/// decision, which keeps this function free of overwrite policy.
pub fn extract_carrier_file(
    carrier_path: &Path,
    options: &ExtractOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Vec<u8>, StrHideError> {
    extract_carrier_file_payload(carrier_path, options, dialect).map(Payload::into_bytes)
}

/// [`extract_carrier_file`] returning the unified [`Payload`] with preserved metadata.
pub fn extract_carrier_file_payload(
    carrier_path: &Path,
    options: &ExtractOptions<'_>,
    dialect: &StegoProfile,
) -> Result<Payload<'static>, StrHideError> {
    let carrier_bytes = read_carrier_file(carrier_path)?;
    crate::stego::extract_carrier_payload(&carrier_bytes, options, dialect)
}

/// Inspect the carrier file at `carrier_path`.
pub fn inspect_carrier_file(
    carrier_path: &Path,
    options: &crate::stego::InspectOptions<'_>,
    dialect: &StegoProfile,
) -> Result<crate::stego::StegoHeaderInfo, StrHideError> {
    #[cfg(feature = "content-hevc")]
    {
        let mut file = std::fs::File::open(carrier_path)?;
        let format = crate::formats::sniff::sniff_stream(&mut file)?;
        drop(file);

        if format == Some(crate::formats::FileFormat::Mp4) {
            return crate::stego::hevc::inspect_hevc_mp4_file_v4(
                carrier_path,
                crate::stego::options::resolve_credential(options.password, options.key, dialect)?,
                options.domain(dialect),
                dialect.hevc_format(),
                &options.limits,
                &options.control,
            );
        }
    }

    let carrier_bytes = read_carrier_file(carrier_path)?;
    crate::stego::inspect_carrier_with_dialect(&carrier_bytes, options, dialect)
}

/// Probe the carrier file capacity at `carrier_path`.
pub fn probe_carrier_file(
    carrier_path: &Path,
    options: &crate::stego::ProbeOptions<'_>,
    dialect: &StegoProfile,
) -> Result<crate::stego::StegoCapacityInfo, StrHideError> {
    let carrier_bytes = read_carrier_file(carrier_path)?;
    crate::stego::probe_carrier_capacity_with_dialect(&carrier_bytes, options, dialect)
}

/// Verify the carrier file at `carrier_path`.
pub fn verify_carrier_file(
    carrier_path: &Path,
    options: &crate::stego::VerifyOptions<'_>,
    dialect: &StegoProfile,
) -> Result<crate::stego::StegoVerifyResult, StrHideError> {
    let carrier_bytes = read_carrier_file(carrier_path)?;
    crate::stego::verify_carrier_with_dialect(&carrier_bytes, options, dialect)
}

/// Fixed decoder/pool overhead added to every whole-file estimate.
const BUFFERED_FIXED_BYTES: u64 = 64 * 1024 * 1024;

/// Measured peak/input ratios (private bytes, Windows) for the audio carriers
/// the engine rewrites whole: WAV 2.06x on 11.5 MB, 2.02x on 96 MB, 2.01x on
/// 366 MB; FLAC 2.01x on 39.7 MB. The peak is exactly the carrier plus one
/// rewrite copy (`carrier.to_vec()`), so 5/2 keeps ~20% headroom instead of
/// the 2x margin a factor of 4 charged. Matroska is deliberately absent: its
/// peak is set by the HEVC recording window, not by the file size (see
/// `hevc::estimate_embed_peak_bytes`).
const WAV_PEAK: (u64, u64) = (5, 2);
const FLAC_PEAK: (u64, u64) = (5, 2);

/// Embeds keep 40% of free physical memory for the WebView, OS and other
/// jobs; this is the same 60% share the GUI admission uses.
fn buffered_embed_budget() -> u64 {
    crate::core::sysmem::available_physical_memory()
        .map(|available| available.saturating_mul(3) / 5)
        // Platforms without a memory query keep a conservative 4 GiB ceiling.
        .unwrap_or(4 * 1024 * 1024 * 1024)
}

/// Peak estimate for a carrier with no recording window to bound the work,
/// or `None` for formats that are not buffered whole.
fn whole_file_peak_bytes(format: crate::formats::FileFormat, file_size: u64) -> Option<u64> {
    let (num, den) = match format {
        crate::formats::FileFormat::Wav => WAV_PEAK,
        crate::formats::FileFormat::Flac => FLAC_PEAK,
        _ => return None,
    };
    Some(
        file_size
            .saturating_mul(num)
            .saturating_div(den)
            .saturating_add(BUFFERED_FIXED_BYTES),
    )
}

fn budget_rejection(message: String) -> StrHideError {
    StrHideError::Rejection(message)
}

/// Refuse a carrier that cannot be held in a single buffer at all.
///
/// This is the only gate that can run before the file is read, and it is never
/// a false positive: every whole-file path (embed, extract, inspect, probe,
/// verify) calls `fs::read` on the carrier, so a file larger than the budget
/// cannot be processed whatever the engine does with it afterwards.
fn check_carrier_fits_budget(file_size: u64, budget: u64) -> Result<(), StrHideError> {
    let needed = file_size.saturating_add(BUFFERED_FIXED_BYTES);
    if needed > budget {
        return Err(budget_rejection(format!(
            "Refusing to process: this carrier is {:.1} MiB and does not fit the {:.1} MiB budget \
             even before decoding. Reading it needs about {:.1} MiB of working memory \
             (file + decoder overhead); the budget is 60% of the physical memory available \
             right now, so this is a memory-pressure limit, not a problem with the carrier. \
             Free memory or retry when the machine is idle.",
            file_size as f64 / (1024.0 * 1024.0),
            budget as f64 / (1024.0 * 1024.0),
            needed as f64 / (1024.0 * 1024.0),
        )));
    }
    Ok(())
}

/// Read a whole carrier file after proving it fits one buffer.
///
/// [`read_carrier_for_embed`] applies the same first gate plus the engine's
/// window estimate; the read-only entry points below only need this one.
pub(crate) fn read_carrier_file(path: &Path) -> Result<Vec<u8>, StrHideError> {
    read_carrier_file_with_budget(path, buffered_embed_budget())
}

fn read_carrier_file_with_budget(path: &Path, budget: u64) -> Result<Vec<u8>, StrHideError> {
    let file_size = std::fs::metadata(path)?.len();
    check_carrier_fits_budget(file_size, budget)?;
    Ok(std::fs::read(path)?)
}

fn check_buffered_embed_budget_against(
    format: crate::formats::FileFormat,
    file_size: u64,
    budget: u64,
) -> Result<(), StrHideError> {
    let Some(peak) = whole_file_peak_bytes(format, file_size) else {
        return Ok(());
    };
    if peak > budget {
        return Err(budget_rejection(format!(
            "Refusing to embed: this {format:?} carrier is {:.1} MiB and needs an estimated {:.1} MiB \
             at peak, above the {:.1} MiB budget (60% of currently available physical memory). \
             Free memory or use a smaller carrier.",
            file_size as f64 / (1024.0 * 1024.0),
            peak as f64 / (1024.0 * 1024.0),
            budget as f64 / (1024.0 * 1024.0),
        )));
    }
    Ok(())
}

/// HEVC peak estimate against the budget, using the recording window.
///
/// The engine records whole GOP batches and holds every recorded slice journal
/// for re-encoding, so the peak follows the window (the first
/// [`hevc::EMBED_WINDOW_GOPS`] groups of pictures), not the file size. A
/// whole-file factor here rejected a 429.5 MB film at 26,279 MiB while the
/// embed actually peaked at 2,243 MiB.
#[cfg(feature = "content-hevc")]
fn check_hevc_embed_budget(
    format: crate::formats::FileFormat,
    carrier: &[u8],
    payload: &Payload<'_>,
    options: &EmbedOptions<'_>,
    dialect: &StegoProfile,
    budget: u64,
) -> Result<(), StrHideError> {
    use crate::formats::FileFormat;
    if !matches!(
        format,
        FileFormat::Mp4 | FileFormat::Mkv | FileFormat::HevcAnnexB | FileFormat::Heif
    ) {
        return Ok(());
    }
    let Some(estimate) = crate::stego::hevc::estimate_embed_peak_bytes(
        carrier,
        payload.as_bytes().len(),
        options.safety,
        dialect.hevc_format(),
    ) else {
        return Ok(());
    };
    if estimate.peak_bytes > budget {
        return Err(budget_rejection(format!(
            "Refusing to embed: this {format:?} carrier is {:.1} MiB; about {:.1} MiB of it stays \
             recorded while the payload is solved (batches of up to {} groups of pictures), at an \
             estimated peak of {:.1} MiB, above the {:.1} MiB budget (60% of currently available \
             physical memory). Free memory or use a smaller payload.",
            carrier.len() as f64 / (1024.0 * 1024.0),
            estimate.window_bytes as f64 / (1024.0 * 1024.0),
            estimate.window_gops,
            estimate.peak_bytes as f64 / (1024.0 * 1024.0),
            budget as f64 / (1024.0 * 1024.0),
        )));
    }
    Ok(())
}

/// Read `carrier_path` after proving the embed can afford to hold it.
///
/// Two gates, both before the expensive part: the carrier must fit one buffer,
/// and the engine's recorded window must fit the budget. Both fail with a
/// `Rejection` that names the numbers instead of letting the allocator abort.
/// `--dry-run` runs the same in-memory embed, so it goes through here too and
/// cannot drift from a real write.
pub(crate) fn read_carrier_for_embed(
    carrier_path: &Path,
    payload: &Payload<'_>,
    options: &EmbedOptions<'_>,
    dialect: &StegoProfile,
) -> Result<(Vec<u8>, Option<crate::formats::FileFormat>), StrHideError> {
    let file_size = std::fs::metadata(carrier_path)?.len();
    let budget = buffered_embed_budget();
    check_carrier_fits_budget(file_size, budget)?;

    // Audio has no GOP window, so its whole-file ratio is still the right
    // estimate and can be applied before the read allocates anything.
    if let Some(format) = crate::formats::sniff::sniff_file(carrier_path)? {
        check_buffered_embed_budget_against(format, file_size, budget)?;
    }

    let bytes = std::fs::read(carrier_path)?;
    let format = crate::formats::sniff::sniff_bytes(&bytes);

    #[cfg(feature = "content-hevc")]
    if let Some(format) = format {
        check_hevc_embed_budget(format, &bytes, payload, options, dialect, budget)?;
    }
    #[cfg(not(feature = "content-hevc"))]
    let _ = (payload, options, dialect);

    Ok((bytes, format))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stego::{EmbedOptions, ExtractOptions};

    #[test]
    fn whole_file_peak_covers_audio_but_not_matroska() {
        use crate::formats::FileFormat;
        assert_eq!(
            whole_file_peak_bytes(FileFormat::Wav, 10_000_000).unwrap(),
            25_000_000 + BUFFERED_FIXED_BYTES
        );
        assert_eq!(
            whole_file_peak_bytes(FileFormat::Flac, 5_000_000).unwrap(),
            12_500_000 + BUFFERED_FIXED_BYTES
        );
        // Matroska peaks with the HEVC recording window, not with the file;
        // a whole-file factor here was what rejected a 429.5 MB film by 12x.
        assert!(
            whole_file_peak_bytes(FileFormat::Mkv, 12_360_000).is_none(),
            "Matroska is judged by the GOP window, not by the file size"
        );
        assert!(
            whole_file_peak_bytes(FileFormat::Jpeg, 5_000_000).is_none(),
            "patch engines stream instead of buffering the whole carrier"
        );
    }

    #[test]
    fn over_budget_audio_carrier_is_rejected_with_the_reason() {
        use crate::formats::FileFormat;
        let budget = 1u64 << 30;
        let err =
            check_buffered_embed_budget_against(FileFormat::Wav, 450_000_000, budget).unwrap_err();
        match err {
            StrHideError::Rejection(message) => {
                assert!(
                    message.contains("429.2 MiB"),
                    "states the input size: {message}"
                );
                assert!(message.contains("budget"), "states the limit: {message}");
            }
            other => panic!("expected Rejection, got {other:?}"),
        }

        assert!(
            check_buffered_embed_budget_against(FileFormat::Wav, 400_000_000, budget).is_ok(),
            "measured peak is 2x, not 4x: a 400 MB WAV fits where the old factor refused it"
        );
        assert!(
            check_buffered_embed_budget_against(FileFormat::Flac, 40_000_000, budget).is_ok(),
            "a 40 MB FLAC sample is inside a 1 GiB budget"
        );
        assert!(
            check_buffered_embed_budget_against(FileFormat::Jpeg, 400_000_000, budget).is_ok(),
            "formats without a whole-file estimate are not rejected here"
        );
    }

    #[test]
    fn a_carrier_that_cannot_be_read_at_all_is_refused_before_the_read() {
        let budget = 1u64 << 30;
        let err = check_carrier_fits_budget(budget, budget).unwrap_err();
        match err {
            StrHideError::Rejection(message) => {
                assert!(
                    message.contains("before decoding"),
                    "explains that this is the unavoidable copy: {message}"
                );
            }
            other => panic!("expected Rejection, got {other:?}"),
        }
        assert!(
            check_carrier_fits_budget(budget / 2, budget).is_ok(),
            "a carrier that fits one buffer passes this gate"
        );
    }

    #[test]
    fn a_carrier_file_above_the_budget_is_refused_before_the_read() {
        let path = std::env::temp_dir().join(format!("strhide-budget-{}.bin", std::process::id()));
        std::fs::write(&path, b"carrier").expect("write scratch carrier");
        let err = read_carrier_file_with_budget(&path, BUFFERED_FIXED_BYTES - 1).unwrap_err();
        match err {
            StrHideError::Rejection(message) => {
                assert!(
                    message.contains("does not fit") && message.contains("MiB"),
                    "names the size and the limit: {message}"
                );
            }
            other => panic!("expected Rejection, got {other:?}"),
        }
        assert!(
            read_carrier_file_with_budget(&path, BUFFERED_FIXED_BYTES + 8).is_ok(),
            "a carrier that fits one buffer is read normally"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The window, not the file, decides the peak: a long video records the
    /// same first-batch bytes however long it is, so the estimate must not grow
    /// with the file. The 24-minute sample is in `temp/` and not committed, so
    /// this skips when it is absent.
    #[test]
    #[cfg(feature = "content-hevc")]
    fn embed_window_is_bounded_by_the_gop_batch_not_the_file() {
        let short = Path::new("../temp/mem_probe/a_480s.mp4");
        let long = Path::new("../temp/bighevc/anime-a.mp4");
        let (Ok(short_bytes), Ok(long_bytes)) = (std::fs::read(short), std::fs::read(long)) else {
            return;
        };
        assert!(long_bytes.len() > 3 * short_bytes.len());
        let short_window = crate::stego::hevc::embed_window_bytes(&short_bytes)
            .expect("the 480 s sample is an HEVC carrier");
        let long_window = crate::stego::hevc::embed_window_bytes(&long_bytes)
            .expect("the 24-minute sample is an HEVC carrier");
        assert!(
            long_window < (long_bytes.len() as u64) / 4,
            "the window must stay a small share of a long film: {long_window}"
        );
        assert!(
            long_window <= short_window + short_window / 2,
            "same content, same first batch: {long_window} vs {short_window}"
        );
    }

    /// The embed stops at the slice that meets the payload's target, so the
    /// estimate must follow the payload, not the batch it was decoded in. This
    /// pins the regression that made a 4 KiB payload cost 6,759 MiB.
    #[test]
    #[cfg(feature = "content-hevc")]
    fn embed_peak_follows_the_payload_not_the_batch() {
        use crate::stego::params::{SafetyPolicy, StegoProfile};
        let sample = Path::new("../temp/mem_probe/a_480s.mp4");
        let Ok(bytes) = std::fs::read(sample) else {
            return;
        };
        let profile = StegoProfile::default();
        let peak = |payload: usize| {
            crate::stego::hevc::estimate_embed_peak_bytes(
                &bytes,
                payload,
                SafetyPolicy::new(),
                profile.hevc_format(),
            )
            .expect("the 480 s sample is an HEVC carrier")
        };

        let small = peak(4096);
        assert!(
            small.window_bytes < (bytes.len() as u64) / 20,
            "a 4 KiB payload records a tiny window, not a batch: {}",
            small.window_bytes
        );
        // 80 carrier bytes per payload byte at the default tier (stc_u 2 x
        // sparsity 5), plus at most one batch's worth for the GOP that decoded
        // it -- never the 16-GOP batch the recorder used to hold.
        let big = peak(1 << 20);
        let needed = (1u64 << 20) * 80;
        assert!(
            big.window_bytes >= needed && big.window_bytes <= needed * 2,
            "1 MiB payload window {} vs needed {needed}",
            big.window_bytes
        );
        assert!(big.window_bytes <= bytes.len() as u64);
        assert!(small.peak_bytes < big.peak_bytes / 10);
    }

    #[test]
    fn non_hevc_carriers_have_no_window() {
        assert!(
            crate::stego::hevc::embed_window_bytes(b"not a video at all").is_none(),
            "a non-HEVC carrier cannot be estimated this way"
        );
    }

    #[test]
    fn unsupported_carrier_is_refused_without_touching_the_file() {
        let dir = std::env::temp_dir().join(format!("strhide-io-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let carrier = dir.join("carrier.bin");
        let original = b"this is not an image carrier";
        std::fs::write(&carrier, original).expect("write carrier");

        let target = FileTarget::default();
        let result = embed_carrier_file(
            &carrier,
            &Payload::bytes(b"payload"),
            &EmbedOptions::default(),
            &StegoProfile::default(),
            &target,
        );
        assert!(
            matches!(result, Err(StrHideError::UnsupportedFormat(_))),
            "a non-image carrier must be refused as UnsupportedFormat, got {result:?}"
        );

        let after = std::fs::read(&carrier).expect("read back");
        assert_eq!(
            after, original,
            "a refused embed must not modify or replace the carrier"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_reports_unsupported_format() {
        let dir = std::env::temp_dir().join(format!("strhide-io-test-x-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let carrier = dir.join("carrier.bin");
        std::fs::write(&carrier, b"still not an image").expect("write carrier");

        let result = extract_carrier_file(
            &carrier,
            &ExtractOptions::default(),
            &StegoProfile::default(),
        );
        assert!(matches!(result, Err(StrHideError::UnsupportedFormat(_))));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(feature = "content-hevc")]
    fn hevc_annexb_embed_carrier_file_roundtrip_patches() {
        let candidate = Path::new("../temp/testhevc/annexb/test-25fps.hevc");
        if !candidate.is_file() {
            return;
        }
        let dir = std::env::temp_dir().join(format!("strhide-io-hevc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let dest = dir.join("stego.hevc");

        let secret = "io-patch-test-pwd";
        let payload = Payload::bytes(b"hello patches from io");
        let opts = EmbedOptions {
            password: Some(secret),
            ..EmbedOptions::default()
        };
        let profile = StegoProfile::default();

        let target = FileTarget {
            output_path: Some(&dest),
            backup: false,
            preserve_time: true,
            overwrite: true,
        };
        let res = embed_carrier_file(candidate, &payload, &opts, &profile, &target)
            .expect("embed_carrier_file");
        assert!(res.backup_file.is_none());
        assert!(dest.is_file());

        let extract_opts = ExtractOptions {
            password: Some(secret),
            ..ExtractOptions::default()
        };
        let extracted =
            extract_carrier_file(&dest, &extract_opts, &profile).expect("extract_carrier_file");
        assert_eq!(extracted, b"hello patches from io");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
