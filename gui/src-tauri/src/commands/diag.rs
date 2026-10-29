use std::path::PathBuf;
use tauri::State;

use strhide::analysis::ScanReport;
use strhide::core::control::Control;
use strhide::core::i18n::{self, RenderCtx};
use strhide::errors::ErrorDetail;
use strhide::facade::{DualInspect, DualOptions, DualVerify};
use strhide::formats::capability::{CAPABILITIES, Capability};
use strhide::formats::sniff::{FileFormat, sniff_file};
use strhide::structure::engine::{InspectResult, LevelStatus, VerifyResult};

use crate::state::GuiState;

#[tauri::command]
pub fn get_capabilities_cmd() -> Vec<Capability> {
    CAPABILITIES.to_vec()
}

#[tauri::command]
pub async fn inspect_carrier_cmd(
    state: State<'_, GuiState>,
    path: PathBuf,
    password: Option<String>,
    domain: Option<String>,
) -> Result<DualInspect, ErrorDetail> {
    let ctx = RenderCtx::new(i18n::lang());
    let engine = state.engine;

    tauri::async_runtime::spawn_blocking(move || {
        let fmt = sniff_file(&path).ok().flatten();
        let is_annexb = fmt == Some(FileFormat::HevcAnnexB);

        let mut dual = if is_annexb {
            let stego_opts = strhide::stego::InspectOptions {
                password: password.as_deref(),
                domain: domain.as_deref(),
                limits: strhide::stego::ExtractParams::default(),
                control: Control::none(),
            };
            let (content, content_error, media_info) =
                match engine.stego().inspect_file(&path, &stego_opts) {
                    Ok(info) => {
                        let mi = info.media_info;
                        (Some(info), None, mi)
                    }
                    Err(err) => (None, Some(err.detail_i18n_with_ctx(ctx)), None),
                };

            DualInspect {
                structure: InspectResult {
                    carrier: path.clone(),
                    format: FileFormat::HevcAnnexB,
                    has_hidden_data: false,
                    strategy: None,
                    ube_offset: None,
                    ube_total_size: None,
                    is_encrypted: None,
                    is_compressed: None,
                    is_stealth: None,
                    password_hint: None,
                    orig_host_size: None,
                    orig_host_sha256: None,
                    metadata: None,
                    suspicious_hints: Vec::new(),
                    strategies: Vec::new(),
                },
                content,
                content_error,
                media_info,
            }
        } else {
            let opts = DualOptions {
                password: password.as_deref(),
                domain: domain.as_deref(),
                control: Control::none(),
            };
            engine
                .inspect_any(&path, &opts)
                .map_err(|e| e.detail_i18n_with_ctx(ctx))?
        };

        // Localize strategy capacity limits
        for strat in &mut dual.structure.strategies {
            strat.limit = strat.render_limit(ctx);
        }

        Ok(dual)
    })
    .await
    .map_err(|join_err| {
        strhide::errors::StrHideError::General(format!("Worker thread join error: {join_err}"))
            .detail_i18n_with_ctx(ctx)
    })?
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FileMetadataDto {
    pub path: String,
    pub filename: String,
    pub size_bytes: u64,
    pub exists: bool,
    pub is_file: bool,
    pub is_dir: bool,
    pub modified_ms: Option<u64>,
}

#[tauri::command]
pub fn get_file_metadata_cmd(path: PathBuf) -> Result<FileMetadataDto, ErrorDetail> {
    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();

    match std::fs::metadata(&path) {
        Ok(meta) => {
            let modified_ms = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64);

            Ok(FileMetadataDto {
                path: path.to_string_lossy().into_owned(),
                filename,
                size_bytes: meta.len(),
                exists: true,
                is_file: meta.is_file(),
                is_dir: meta.is_dir(),
                modified_ms,
            })
        }
        Err(err) => {
            let ctx = RenderCtx::new(i18n::lang());
            Err(strhide::errors::StrHideError::Io(err).detail_i18n_with_ctx(ctx))
        }
    }
}

#[tauri::command]
pub async fn verify_carrier_cmd(
    state: State<'_, GuiState>,
    path: PathBuf,
    password: Option<String>,
    domain: Option<String>,
) -> Result<DualVerify, ErrorDetail> {
    let ctx = RenderCtx::new(i18n::lang());
    let engine = state.engine;

    tauri::async_runtime::spawn_blocking(move || {
        let fmt = sniff_file(&path).ok().flatten();
        let is_annexb = fmt == Some(FileFormat::HevcAnnexB);

        if is_annexb {
            let ver_opts = strhide::stego::VerifyOptions {
                password: password.as_deref(),
                domain: domain.as_deref(),
                limits: strhide::stego::ExtractParams::default(),
                control: Control::none(),
            };
            let content = engine.stego().verify_file(&path, &ver_opts).ok();
            Ok(DualVerify {
                structure: VerifyResult {
                    carrier: path,
                    format: FileFormat::HevcAnnexB,
                    level1_host: LevelStatus {
                        ok: true,
                        detail: "Annex-B bitstream syntax (no UBE container)".into(),
                        skipped: false,
                    },
                    level2_envelope: LevelStatus {
                        ok: false,
                        detail: "No structure envelope in Annex-B bitstream".into(),
                        skipped: true,
                    },
                    level3_crypto: LevelStatus {
                        ok: false,
                        detail: "Structure crypto skipped".into(),
                        skipped: true,
                    },
                },
                content,
            })
        } else {
            let opts = DualOptions {
                password: password.as_deref(),
                domain: domain.as_deref(),
                control: Control::none(),
            };
            engine
                .verify_any(&path, &opts)
                .map_err(|e| e.detail_i18n_with_ctx(ctx))
        }
    })
    .await
    .map_err(|join_err| {
        strhide::errors::StrHideError::General(format!("Worker thread join error: {join_err}"))
            .detail_i18n_with_ctx(ctx)
    })?
}

#[tauri::command]
pub async fn scan_carrier_cmd(
    state: State<'_, GuiState>,
    path: PathBuf,
) -> Result<ScanReport, ErrorDetail> {
    let ctx = RenderCtx::new(i18n::lang());
    let engine = state.engine;

    tauri::async_runtime::spawn_blocking(move || {
        engine
            .analysis()
            .scan_file(&path)
            .map_err(|e| e.detail_i18n_with_ctx(ctx))
    })
    .await
    .map_err(|join_err| {
        strhide::errors::StrHideError::General(format!("Worker thread join error: {join_err}"))
            .detail_i18n_with_ctx(ctx)
    })?
}
