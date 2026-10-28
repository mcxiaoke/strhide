use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tauri::State;
use tauri::ipc::Channel;

use strhide::core::commit::FileTarget;
use strhide::core::payload::{Payload, PayloadKind};
use strhide::core::pipeline::check_overwrite;
use strhide::errors::ErrorDetail;
use strhide::facade::{Domain, SmartExtractOptions};
use strhide::formats::sniff::{FileFormat, sniff_file};
use strhide::stego::io::extract_carrier_file_payload;
use strhide::stego::options::{
    EmbedOptions, ExtractOptions, JpegAlgorithm, ProbeOptions, SpatialAlgorithm, StegoEmbedResult,
    StegoTuning,
};
use strhide::stego::params::{JpegParams, PngParams};
use strhide::stego::{SafetyEnforcement, SafetyLevel, SafetyPolicy, StegoCapacityInfo};
use strhide::structure::engine::ReadSummary;

use crate::commands::PayloadInputDto;
use crate::state::{GuiState, ProgressEvent, run_cancellable_task};

fn resolve_tuning(algo: Option<&str>) -> StegoTuning {
    if let Some(name) = algo {
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
) -> Result<StegoCapacityInfo, ErrorDetail> {
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
                domain: domain.as_deref(),
                safety,
                tuning,
                exact,
                control: ctrl,
                pool: Some(Arc::clone(&pool)),
            };

            engine.stego().probe_file(&path, &probe_opts)
        },
    )
    .await
}

#[tauri::command]
pub async fn embed_stego_file_cmd(
    state: State<'_, GuiState>,
    task_id: String,
    req: StegoEmbedRequest,
    on_progress: Channel<ProgressEvent>,
) -> Result<StegoEmbedResult, ErrorDetail> {
    run_cancellable_task(
        &state,
        task_id,
        on_progress,
        move |engine, pool, ctrl, _| {
            let dest = req.output_path.as_deref().unwrap_or(&req.carrier);
            check_overwrite(dest, req.overwrite)?;

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

            engine
                .stego()
                .embed_file(&req.carrier, &payload, &embed_opts, &target)
        },
    )
    .await
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
                domain: domain.as_deref(),
                limits: strhide::stego::ExtractParams::default(),
                control: ctrl,
                pool: Some(Arc::clone(&pool)),
            };

            let payload = extract_carrier_file_payload(&path, &ex_opts, &engine.dialect().stego)?;

            let is_file = payload.kind == PayloadKind::File;
            let is_encrypted = password.is_some();
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
                std::fs::write(dest, &payload.data)?;
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
    run_cancellable_task(
        &state,
        task_id,
        on_progress,
        move |engine, pool, ctrl, _| {
            if let Some(ref dest) = output_path {
                check_overwrite(dest, overwrite)?;
            }

            let fmt = sniff_file(&path).ok().flatten();
            let is_annexb = fmt == Some(FileFormat::HevcAnnexB);

            let (payload, source, also_present) = if is_annexb {
                let ex_opts = ExtractOptions {
                    password: password.as_deref(),
                    domain: domain.as_deref(),
                    limits: strhide::stego::ExtractParams::default(),
                    control: ctrl,
                    pool: Some(Arc::clone(&pool)),
                };
                let p = extract_carrier_file_payload(&path, &ex_opts, &engine.dialect().stego)?;
                (p, Domain::Content, None)
            } else {
                let smart_opts = SmartExtractOptions {
                    password: password.as_deref(),
                    domain: domain.as_deref(),
                    limits: strhide::stego::ExtractParams::default(),
                    prefer,
                    control: ctrl,
                };
                let outcome = engine.smart_extract(&path, &smart_opts)?;
                (outcome.payload, outcome.source, outcome.also_present)
            };

            let is_file = payload.kind == PayloadKind::File;
            let is_encrypted = password.is_some();
            let filename = payload.name.clone().unwrap_or_else(|| {
                (if is_file {
                    "payload.bin"
                } else {
                    "payload.txt"
                })
                .to_string()
            });
            let raw_size = payload.data.len() as u64;

            let summary = if let Some(ref dest) = output_path {
                std::fs::write(dest, &payload.data)?;
                ReadSummary {
                    carrier: path,
                    is_file,
                    is_encrypted,
                    filename,
                    raw_size,
                    written_file: Some(dest.clone()),
                    text_preview: None,
                }
            } else {
                let text_preview = if payload.data.len() <= 64 * 1024 {
                    std::str::from_utf8(&payload.data)
                        .ok()
                        .map(|s| s.to_string())
                } else {
                    None
                };
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

            Ok(SmartExtractSummaryDto {
                source,
                also_present,
                summary,
            })
        },
    )
    .await
}
