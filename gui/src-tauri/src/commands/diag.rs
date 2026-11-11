use std::path::PathBuf;
use tauri::State;

use strhide::analysis::ScanReport;
use strhide::core::i18n::{self, RenderCtx};
use strhide::errors::ErrorDetail;
use strhide::facade::{DualInspect, DualOptions, DualVerify};
use strhide::formats::capability::{CAPABILITIES, Capability};

use crate::state::{GuiState, run_blocking_task};

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
    inspect_carrier_with_task(state, path, password, domain, None).await
}

/// [`inspect_carrier_impl`] with a cancellation token bound to `task_id`.
pub async fn inspect_carrier_with_task(
    state: &GuiState,
    path: PathBuf,
    password: Option<String>,
    domain: Option<String>,
    task_id: Option<String>,
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
    let res = run_blocking_task(state, task_id, "ipc::inspect", move |engine, ctrl| {
        // `inspect_any` already exempts content-only carriers (Annex-B HEVC has
        // no structure adapter) and reports content-domain failures through
        // `content_error`. The hand-rolled Annex-B branch that used to live here
        // duplicated that logic and silently dropped the error.
        let opts = DualOptions::new()
            .with_password_option(password.as_deref())
            .with_domain_option(domain.as_deref())
            .with_control(ctrl);
        let mut dual = engine.inspect_any(&path, &opts)?;

        // Localize strategy capacity limits
        for strat in &mut dual.structure.strategies {
            strat.limit = strat.render_limit(ctx);
        }

        Ok(dual)
    })
    .await;

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
    task_id: Option<String>,
) -> Result<DualInspect, ErrorDetail> {
    inspect_carrier_with_task(&state, path, password, domain, task_id).await
}

/// Pick a non-colliding output path under `dir` for `filename`.
///
/// The numbering rule (`stem (n).ext`) lives in the library so the GUI views,
/// smart-extract's directory mode and the CLI batch cannot drift apart; one IPC
/// call also replaces the frontend's per-candidate `get_file_metadata_cmd`
/// round trip.
#[tauri::command]
pub fn unique_output_path_cmd(dir: PathBuf, filename: String) -> String {
    strhide::core::fs::unique_free_path(&dir, &filename)
        .to_string_lossy()
        .into_owned()
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
    task_id: Option<String>,
) -> Result<DualVerify, ErrorDetail> {
    run_blocking_task(&state, task_id, "ipc::verify", move |engine, ctrl| {
        // Same content-only exemption as `inspect_carrier_cmd`: `verify_any`
        // returns `VerifyResult::not_applicable` for Annex-B HEVC and keeps the
        // content-domain failure in `content_error`.
        let opts = DualOptions::new()
            .with_password_option(password.as_deref())
            .with_domain_option(domain.as_deref())
            .with_control(ctrl);
        engine.verify_any(&path, &opts)
    })
    .await
}

#[tauri::command]
pub async fn scan_carrier_cmd(
    state: State<'_, GuiState>,
    path: PathBuf,
    task_id: Option<String>,
) -> Result<ScanReport, ErrorDetail> {
    let start = std::time::Instant::now();
    let path_display = path.display().to_string();
    log::info!(target: "ipc::scan", "Scanning carrier: path={}", path_display);

    let res = run_blocking_task(&state, task_id, "ipc::scan", move |engine, ctrl| {
        // The analysis pass has no internal checkpoints, so cancellation is
        // observed before the (bounded, 64 MiB) read starts: enough to drop a
        // scan that was queued behind other pool work.
        ctrl.check()?;
        engine.analysis().scan_file(&path)
    })
    .await;

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
