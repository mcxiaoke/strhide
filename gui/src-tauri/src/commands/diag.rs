use std::path::PathBuf;
use std::sync::Arc;
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

pub async fn inspect_carrier_impl(
    state: &GuiState,
    path: PathBuf,
    password: Option<String>,
    domain: Option<String>,
) -> Result<DualInspect, ErrorDetail> {
    let start = std::time::Instant::now();
    let path_display = path.display().to_string();
    log::info!(
        target: "ipc::inspect",
        "Inspecting carrier: path={}, domain={:?}",
        path_display,
        domain
    );

    let ctx = RenderCtx::new(i18n::lang());
    let engine = state.engine;
    let pool = Arc::clone(&state.pool);

    let res: Result<DualInspect, ErrorDetail> = tauri::async_runtime::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.install(|| {
                // `inspect_any` already exempts content-only carriers (Annex-B HEVC has
                // no structure adapter) and reports content-domain failures through
                // `content_error`. The hand-rolled Annex-B branch that used to live here
                // duplicated that logic and silently dropped the error.
                let opts = DualOptions::new()
                    .with_password_option(password.as_deref())
                    .with_domain_option(domain.as_deref())
                    .with_control(Control::none());
                let mut dual = engine
                    .inspect_any(&path, &opts)
                    .map_err(|e| e.detail_i18n_with_ctx(ctx))?;

                // Localize strategy capacity limits
                for strat in &mut dual.structure.strategies {
                    strat.limit = strat.render_limit(ctx);
                }

                Ok(dual)
            })
        }))
        .unwrap_or_else(|payload| {
            Err(crate::state::panic_error(payload.as_ref(), "ipc::inspect")
                .detail_i18n_with_ctx(ctx))
        })
    })
    .await
    .map_err(|join_err| {
        strhide::errors::StrHideError::General(format!("Worker thread join error: {join_err}"))
            .detail_i18n_with_ctx(ctx)
    })?;

    match &res {
        Ok(dual) => {
            crate::logger::record_json(
                "info",
                "ipc::inspect",
                &format!(
                    "Inspected {} in {:?}: format={}, has_hidden_data={}",
                    path_display,
                    start.elapsed(),
                    dual.structure.format,
                    dual.structure.has_hidden_data
                ),
                dual,
            );
        }
        Err(err) => {
            log::warn!(
                target: "ipc::inspect",
                "Inspect {} failed in {:?}: {}",
                path_display,
                start.elapsed(),
                err.detail
            );
        }
    }

    res
}

#[tauri::command]
pub async fn inspect_carrier_cmd(
    state: State<'_, GuiState>,
    path: PathBuf,
    password: Option<String>,
    domain: Option<String>,
) -> Result<DualInspect, ErrorDetail> {
    inspect_carrier_impl(&state, path, password, domain).await
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
        // "The file is not there" is an answer this DTO can express, not an
        // error: the caller uses it to pick a non-colliding output name, and
        // reporting an error made it treat *every* failure (permission denied,
        // IPC hiccup) as "path is free".
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(FileMetadataDto {
            path: path.to_string_lossy().into_owned(),
            filename,
            size_bytes: 0,
            exists: false,
            is_file: false,
            is_dir: false,
            modified_ms: None,
        }),
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
    let pool = Arc::clone(&state.pool);

    tauri::async_runtime::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.install(|| {
                // Same content-only exemption as `inspect_carrier_cmd`: `verify_any`
                // returns `VerifyResult::not_applicable` for Annex-B HEVC and keeps the
                // content-domain failure in `content_error`.
                let opts = DualOptions::new()
                    .with_password_option(password.as_deref())
                    .with_domain_option(domain.as_deref())
                    .with_control(Control::none());
                engine
                    .verify_any(&path, &opts)
                    .map_err(|e| e.detail_i18n_with_ctx(ctx))
            })
        }))
        .unwrap_or_else(|payload| {
            Err(crate::state::panic_error(payload.as_ref(), "ipc::verify")
                .detail_i18n_with_ctx(ctx))
        })
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
    let start = std::time::Instant::now();
    let path_display = path.display().to_string();
    log::info!(target: "ipc::scan", "Scanning carrier: path={}", path_display);

    let ctx = RenderCtx::new(i18n::lang());
    let engine = state.engine;
    let pool = Arc::clone(&state.pool);

    let res: Result<ScanReport, ErrorDetail> = tauri::async_runtime::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pool.install(|| {
                engine
                    .analysis()
                    .scan_file(&path)
                    .map_err(|e| e.detail_i18n_with_ctx(ctx))
            })
        }))
        .unwrap_or_else(|payload| {
            Err(crate::state::panic_error(payload.as_ref(), "ipc::scan")
                .detail_i18n_with_ctx(ctx))
        })
    })
    .await
    .map_err(|join_err| {
        strhide::errors::StrHideError::General(format!("Worker thread join error: {join_err}"))
            .detail_i18n_with_ctx(ctx)
    })?;

    match &res {
        Ok(report) => {
            crate::logger::record_json(
                "info",
                "ipc::scan",
                &format!(
                    "Scanned {} in {:?}: risk_score={}, verdict={}, findings={}",
                    path_display,
                    start.elapsed(),
                    report.risk_score,
                    report.verdict,
                    report.findings.len()
                ),
                report,
            );
        }
        Err(err) => {
            log::warn!(
                target: "ipc::scan",
                "Scan {} failed in {:?}: {}",
                path_display,
                start.elapsed(),
                err.detail
            );
        }
    }

    res
}
