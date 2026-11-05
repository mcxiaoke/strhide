use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use tauri::ipc::Channel;

use strhide::core::commit::{FileTarget, write_bytes_atomic};
use strhide::core::payload::{Payload, PayloadKind};
use strhide::core::pipeline::check_overwrite;
use strhide::errors::ErrorDetail;
use strhide::facade::{Domain, SmartExtractOptions};
use strhide::stego::io::extract_carrier_file_payload;
use strhide::stego::options::{
    EmbedOptions, ExtractOptions, HevcMode, JpegAlgorithm, ProbeOptions, SpatialAlgorithm,
    StegoEmbedResult, StegoTuning,
};
use strhide::stego::params::{JpegParams, PngParams};
use strhide::stego::{
    SafetyEnforcement, SafetyLevel, SafetyPolicy, StegoAlgorithmInfo, StegoCapacityInfo,
};
use strhide::structure::engine::ReadSummary;

use crate::commands::PayloadInputDto;
use crate::state::{GuiState, ProgressEvent, run_cancellable_task};

#[tauri::command]
pub fn get_stego_algorithms_cmd() -> Vec<StegoAlgorithmInfo> {
    strhide::stego::list_stego_algorithms()
}

fn resolve_tuning(algo: Option<&str>) -> StegoTuning {
    if let Some(name) = algo {
        let name = name.trim();
        if let Some(m) = SpatialAlgorithm::from_name(name) {
            return StegoTuning::Png {
                model: m,
                params: PngParams::default(),
            };
        }
        if let Some(m) = JpegAlgorithm::from_name(name) {
            return StegoTuning::Jpeg {
                model: m,
                params: JpegParams::default(),
            };
        }
        if let Some(mode) = HevcMode::from_name(name) {
            return StegoTuning::hevc(mode);
        }
    }
    StegoTuning::Auto
}

#[derive(Debug, Clone, Deserialize)]
pub struct StegoEmbedRequest {
    pub carrier: PathBuf,
    pub payload: PayloadInputDto,
    pub output_path: Option<PathBuf>,
    pub password: Option<String>,
    pub domain: Option<String>,
    pub safety_level: SafetyLevel,
    pub enforce_safety: bool,
    pub algorithm: Option<String>,
    pub backup: bool,
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SmartExtractSummaryDto {
    pub source: Domain,
    pub also_present: Option<Domain>,
    pub summary: ReadSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct StegoCapacityFullDto {
    #[serde(flatten)]
    pub info: StegoCapacityInfo,
    pub paranoid_max_bytes: usize,
    pub high_max_bytes: usize,
    pub balanced_max_bytes: usize,
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn probe_stego_capacity_cmd(
    state: State<'_, GuiState>,
    task_id: String,
    path: PathBuf,
    password: Option<String>,
    domain: Option<String>,
    safety_level: SafetyLevel,
    algorithm: Option<String>,
    exact: bool,
    on_progress: Channel<ProgressEvent>,
) -> Result<StegoCapacityFullDto, ErrorDetail> {
    run_cancellable_task(
        &state,
        task_id,
        on_progress,
        move |engine, pool, ctrl, _| {
            let tuning = resolve_tuning(algorithm.as_deref());
            let safety = SafetyPolicy {
                level: safety_level,
                enforcement: SafetyEnforcement::Advisory,
            };

            let probe_opts = ProbeOptions {
                password: password.as_deref(),
                key: None,
                domain: domain.as_deref(),
                extensions: Vec::new(),
                safety,
                tuning,
                exact,
                control: ctrl,
                pool: Some(Arc::clone(&pool)),
            };

            let info = engine.stego().probe_file(&path, &probe_opts)?;

            // The per-tier ceilings come from the engine that owns the budget
            // formula. Deriving them here used to compare `info.format`
            // against "hevc"/"mp4", strings no engine produces ("HEIF/HEVC",
            // "HEVC-AnnexB", "MP4/HEVC"), so every HEVC carrier was measured
            // with the image formula and the video tiers were never applied.
            let paranoid_max_bytes = info.tier_limit(SafetyLevel::Paranoid);
            let high_max_bytes = info.tier_limit(SafetyLevel::High);
            let balanced_max_bytes = info.tier_limit(SafetyLevel::Balanced);

            let res = StegoCapacityFullDto {
                info,
                paranoid_max_bytes,
                high_max_bytes,
                balanced_max_bytes,
            };

            crate::logger::record_custom_log(
                "info",
                "ipc::probe_capacity",
                &format!(
                    "Probed capacity for {}: high={} B, paranoid={} B, balanced={} B",
                    path.display(),
                    res.high_max_bytes,
                    res.paranoid_max_bytes,
                    res.balanced_max_bytes
                ),
                serde_json::to_value(&res).ok(),
            );

            Ok(res)
        },
    )
    .await
}

pub async fn embed_stego_file_impl(
    state: &GuiState,
    task_id: String,
    req: StegoEmbedRequest,
    on_progress: Channel<ProgressEvent>,
) -> Result<StegoEmbedResult, ErrorDetail> {
    // Admission before the worker starts: a batch of large JPEGs otherwise
    // asks for one full coefficient set each and the allocator decides, which
    // is an OOM abort rather than a message the user can act on.
    let _embed_slot =
        crate::state::reserve_embed_slot(&state.embed_reserved).map_err(|e| e.detail_i18n())?;
    run_cancellable_task(state, task_id, on_progress, move |engine, pool, ctrl, _| {
        // An omitted `-o` means "write in place": the carrier is the
        // destination, and `overwrite=false` must not reject the user's
        // in-place embed. Only an explicit different destination is checked.
        if let Some(dest) = overwrite_target(req.output_path.as_deref(), &req.carrier) {
            check_overwrite(dest, req.overwrite)?;
        }

        let payload = match req.payload {
            PayloadInputDto::Text { content } => {
                Payload::owned(content.into_bytes()).with_kind(PayloadKind::Text)
            }
            PayloadInputDto::File { path } => {
                let data = std::fs::read(&path)?;
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("payload.bin")
                    .to_string();
                Payload::owned_file(name, data)
            }
        };

        let target = FileTarget {
            output_path: req.output_path.as_deref(),
            backup: req.backup,
            preserve_time: true,
            overwrite: req.overwrite,
        };

        let enforcement = if req.enforce_safety {
            SafetyEnforcement::Enforced
        } else {
            SafetyEnforcement::Advisory
        };

        let embed_opts = EmbedOptions {
            password: req.password.as_deref(),
            domain: req.domain.as_deref(),
            safety: SafetyPolicy {
                level: req.safety_level,
                enforcement,
            },
            tuning: resolve_tuning(req.algorithm.as_deref()),
            control: ctrl,
            pool: Some(Arc::clone(&pool)),
            ..Default::default()
        };

        let res = engine
            .stego()
            .embed_file(&req.carrier, &payload, &embed_opts, &target)?;

        crate::logger::record_custom_log(
            "info",
            "ipc::embed_stego",
            &format!(
                "Embedded stego to {}: carrier_after_bytes={}, payload_bytes={}",
                res.written_to.display(),
                res.carrier_after_bytes,
                res.payload_bytes
            ),
            serde_json::to_value(&res).ok(),
        );

        Ok(res)
    })
    .await
}

#[tauri::command]
pub async fn embed_stego_file_cmd(
    state: State<'_, GuiState>,
    task_id: String,
    req: StegoEmbedRequest,
    on_progress: Channel<ProgressEvent>,
) -> Result<StegoEmbedResult, ErrorDetail> {
    embed_stego_file_impl(&state, task_id, req, on_progress).await
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn extract_stego_file_cmd(
    state: State<'_, GuiState>,
    task_id: String,
    path: PathBuf,
    output_path: Option<PathBuf>,
    password: Option<String>,
    domain: Option<String>,
    overwrite: bool,
    on_progress: Channel<ProgressEvent>,
) -> Result<ReadSummary, ErrorDetail> {
    run_cancellable_task(
        &state,
        task_id,
        on_progress,
        move |engine, pool, ctrl, _| {
            if let Some(ref dest) = output_path {
                check_overwrite(dest, overwrite)?;
            }

            let ex_opts = ExtractOptions {
                password: password.as_deref(),
                key: None,
                domain: domain.as_deref(),
                limits: strhide::stego::ExtractParams::default(),
                control: ctrl,
                pool: Some(Arc::clone(&pool)),
            };

            let payload = extract_carrier_file_payload(&path, &ex_opts, &engine.dialect().stego)?;

            let is_file = payload.kind == PayloadKind::File;
            let is_encrypted = password.is_some_and(|p| !p.is_empty())
                || engine.dialect().stego.secret().is_some();
            let filename = payload.name.clone().unwrap_or_else(|| {
                (if is_file {
                    "payload.bin"
                } else {
                    "payload.txt"
                })
                .to_string()
            });
            let raw_size = payload.data.len() as u64;

            if let Some(ref dest) = output_path {
                write_bytes_atomic(dest, &payload.data)?;
                Ok(ReadSummary {
                    carrier: path,
                    is_file,
                    is_encrypted,
                    filename,
                    raw_size,
                    written_file: Some(dest.clone()),
                    text_preview: None,
                })
            } else {
                let text_preview = if payload.data.len() <= 64 * 1024 {
                    std::str::from_utf8(&payload.data)
                        .ok()
                        .map(|s| s.to_string())
                } else {
                    None
                };
                Ok(ReadSummary {
                    carrier: path,
                    is_file,
                    is_encrypted,
                    filename,
                    raw_size,
                    written_file: None,
                    text_preview,
                })
            }
        },
    )
    .await
}

/// Bare file name to use for a payload whose recorded name is attacker input.
///
/// The envelope metadata (especially for unencrypted envelopes) is untrusted:
/// a name like `../../evil.sh` must never escape the directory the user picked.
/// `sanitize_filename` keeps only the last path component, rejects drive
/// prefixes, control characters and Windows device names, so joining it to the
/// destination cannot traverse outside it.
fn safe_output_filename(name: Option<&str>, is_file: bool) -> String {
    name.map(strhide::structure::engine::sanitize_filename)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            (if is_file {
                "payload.bin"
            } else {
                "payload.txt"
            })
            .to_string()
        })
}

/// The destination that needs an overwrite check.
///
/// No `-o` (or `-o` naming the carrier itself) is an in-place write and must
/// not be rejected by `overwrite=false`; only a different explicit destination
/// can clobber an unrelated file. `same_file` catches the same file addressed
/// through a different spelling (relative vs absolute, Windows letter case).
pub(crate) fn overwrite_target<'a>(
    output: Option<&'a std::path::Path>,
    carrier: &'a std::path::Path,
) -> Option<&'a std::path::Path> {
    output.filter(|dest| !strhide::core::commit::same_file(dest, carrier))
}

#[allow(clippy::too_many_arguments)]
pub async fn smart_extract_impl(
    state: &GuiState,
    task_id: String,
    path: PathBuf,
    output_path: Option<PathBuf>,
    password: Option<String>,
    domain: Option<String>,
    prefer: Option<Domain>,
    overwrite: bool,
    on_progress: Channel<ProgressEvent>,
) -> Result<SmartExtractSummaryDto, ErrorDetail> {
    let cache = Arc::clone(&state.extract_cache);
    run_cancellable_task(state, task_id, on_progress, move |engine, pool, ctrl, _| {
        if let Some(ref dest) = output_path {
            check_overwrite(dest, overwrite)?;
        }

        let mtime = std::fs::metadata(&path).ok().and_then(|m| m.modified().ok());
        let cached_hit = {
            let guard = cache.lock().ok();
            guard.and_then(|g| {
                g.as_ref().and_then(|c| {
                    if c.matches(&path, mtime, &password, &domain, prefer) {
                        Some(c.outcome.clone())
                    } else {
                        None
                    }
                })
            })
        };

        let outcome = if let Some(hit) = cached_hit {
            hit
        } else {
            let smart_opts = SmartExtractOptions {
                password: password.as_deref(),
                domain: domain.as_deref(),
                limits: strhide::stego::ExtractParams::default(),
                prefer,
                control: ctrl,
                pool: Some(Arc::clone(&pool)),
            };
            let fresh = engine.smart_extract(&path, &smart_opts)?;
            if let Ok(mut guard) = cache.lock() {
                *guard = Some(crate::state::CachedExtract {
                    path: path.clone(),
                    mtime,
                    password: password.clone(),
                    domain: domain.clone(),
                    prefer,
                    outcome: fresh.clone(),
                });
            }
            fresh
        };

        let payload = outcome.payload;
        let source = outcome.source;
        let also_present = outcome.also_present;

        let is_file = payload.kind == PayloadKind::File;
        let is_encrypted = outcome.is_encrypted;
        let filename = safe_output_filename(payload.name.as_deref(), is_file);
        let raw_size = payload.data.len() as u64;

        let is_text = !is_file && payload.data.len() <= 64 * 1024;
        let text_preview = if is_text {
            std::str::from_utf8(&payload.data).ok().map(|s| s.to_string())
        } else {
            None
        };

        let summary = if let Some(ref dest) = output_path {
            if text_preview.is_some() && dest.is_dir() {
                // If it's short UTF-8 text and the caller gave a directory, prefer returning text_preview
                // so the user can read it in the UI without cluttering the directory.
                ReadSummary {
                    carrier: path,
                    is_file,
                    is_encrypted,
                    filename,
                    raw_size,
                    written_file: None,
                    text_preview,
                }
            } else {
                let target_file = if dest.is_dir() {
                    let mut candidate = dest.join(&filename);
                    if candidate.exists() {
                        let path = std::path::Path::new(&filename);
                        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or(&filename);
                        let ext = path.extension().and_then(|s| s.to_str());
                        for i in 1..=9999 {
                            let name = match ext {
                                Some(e) => format!("{stem} ({i}).{e}"),
                                None => format!("{stem} ({i})"),
                            };
                            let next = dest.join(name);
                            if !next.exists() {
                                candidate = next;
                                break;
                            }
                        }
                    }
                    candidate
                } else {
                    dest.clone()
                };
                write_bytes_atomic(&target_file, &payload.data)?;
                ReadSummary {
                    carrier: path,
                    is_file,
                    is_encrypted,
                    filename,
                    raw_size,
                    written_file: Some(target_file),
                    text_preview: None,
                }
            }
        } else {
            ReadSummary {
                carrier: path,
                is_file,
                is_encrypted,
                filename,
                raw_size,
                written_file: None,
                text_preview,
            }
        };

        let res = SmartExtractSummaryDto {
            source,
            also_present,
            summary,
        };

        let log_data = serde_json::json!({
            "source": res.source,
            "also_present": res.also_present,
            "carrier": res.summary.carrier,
            "is_file": res.summary.is_file,
            "is_encrypted": res.summary.is_encrypted,
            "filename": res.summary.filename,
            "raw_size": res.summary.raw_size,
            "written_file": res.summary.written_file,
            "has_text_preview": res.summary.text_preview.is_some(),
        });

        crate::logger::record_custom_log(
            "info",
            "ipc::smart_extract",
            &format!(
                "Smart extract succeeded from {:?}: is_file={}, size={}",
                res.source,
                res.summary.is_file,
                res.summary.raw_size
            ),
            Some(log_data),
        );

        Ok(res)
    })
    .await
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn smart_extract_cmd(
    state: State<'_, GuiState>,
    task_id: String,
    path: PathBuf,
    output_path: Option<PathBuf>,
    password: Option<String>,
    domain: Option<String>,
    prefer: Option<Domain>,
    overwrite: bool,
    on_progress: Channel<ProgressEvent>,
) -> Result<SmartExtractSummaryDto, ErrorDetail> {
    smart_extract_impl(
        &state,
        task_id,
        path,
        output_path,
        password,
        domain,
        prefer,
        overwrite,
        on_progress,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{overwrite_target, safe_output_filename};
    use std::path::Path;

    /// P2-7: an in-place embed (no `-o`, or `-o` equal to the carrier) used to
    /// call `check_overwrite` on the carrier itself, so `overwrite=false`
    /// failed before writing. Only a different destination may be checked.
    #[test]
    fn in_place_embed_is_not_an_overwrite_target() {
        let carrier = Path::new("carrier.png");
        assert_eq!(overwrite_target(None, carrier), None);
        assert_eq!(overwrite_target(Some(carrier), carrier), None);
        assert_eq!(
            overwrite_target(Some(Path::new("other.png")), carrier),
            Some(Path::new("other.png"))
        );
    }

    #[test]
    fn smart_extract_recorded_filename_cannot_traverse() {
        for recorded in [
            "../../evil.sh",
            r"..\..\Windows\evil.dll",
            "sub/dir/evil.bin",
            "C:evil.txt",
            "..",
            ".",
            "CON.txt",
            "\u{1b}[31mevil.txt",
            "/absolute/evil.txt",
        ] {
            let name = safe_output_filename(Some(recorded), true);
            assert!(
                !name.contains('/') && !name.contains('\\') && !name.contains(':'),
                "recorded name {recorded:?} produced a path-like output {name:?}"
            );
            assert_ne!(name, "..", "recorded name {recorded:?} escaped to ..");
            assert!(
                !name.starts_with(".."),
                "recorded name {recorded:?} kept a parent prefix: {name:?}"
            );
        }
        assert_eq!(safe_output_filename(Some("../../evil.sh"), true), "evil.sh");
        assert_eq!(
            safe_output_filename(Some(r"..\..\Windows\evil.dll"), true),
            "evil.dll"
        );
        assert_eq!(safe_output_filename(Some("CON.txt"), true), "_CON.txt");
        assert_eq!(safe_output_filename(None, true), "payload.bin");
        assert_eq!(safe_output_filename(None, false), "payload.txt");
    }
}
