use std::path::PathBuf;
use tauri::State;

use strhide::analysis::ScanReport;
use strhide::core::control::Control;
use strhide::core::i18n::{self, RenderCtx};
use strhide::errors::ErrorDetail;
use strhide::facade::{DualInspect, DualOptions, DualVerify};
use strhide::formats::capability::{CAPABILITIES, Capability};

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
        // `inspect_any` already exempts content-only carriers (Annex-B HEVC has
        // no structure adapter) and reports content-domain failures through
        // `content_error`. The hand-rolled Annex-B branch that used to live here
        // duplicated that logic and silently dropped the error.
        let opts = DualOptions {
            password: password.as_deref(),
            domain: domain.as_deref(),
            control: Control::none(),
        };
        let mut dual = engine
            .inspect_any(&path, &opts)
            .map_err(|e| e.detail_i18n_with_ctx(ctx))?;

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
        // Same content-only exemption as `inspect_carrier_cmd`: `verify_any`
        // returns `VerifyResult::not_applicable` for Annex-B HEVC and keeps the
        // content-domain failure in `content_error`.
        let opts = DualOptions {
            password: password.as_deref(),
            domain: domain.as_deref(),
            control: Control::none(),
        };
        engine
            .verify_any(&path, &opts)
            .map_err(|e| e.detail_i18n_with_ctx(ctx))
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
