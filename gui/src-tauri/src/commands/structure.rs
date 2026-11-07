use serde::Deserialize;
use std::path::PathBuf;
use tauri::State;
use tauri::ipc::Channel;

use strhide::core::pipeline::check_overwrite;
use strhide::errors::ErrorDetail;
use strhide::structure::engine::{PayloadSource, ReadSummary, RemoveResult, WriteResult};
use strhide::structure::options::{ReadOptions, RestoreOptions, WriteOptions};

use crate::commands::PayloadInputDto;
use crate::state::{GuiState, ProgressEvent, run_cancellable_task};

#[derive(Debug, Clone, Deserialize)]
pub struct StructureWriteRequest {
    pub carrier: PathBuf,
    pub payload: PayloadInputDto,
    pub output_path: Option<PathBuf>,
    pub password: Option<String>,
    pub password_hint: Option<String>,
    pub strategy: Option<String>,
    pub stealth: bool,
    pub preserve_time: bool,
    pub backup: bool,
    pub overwrite: bool,
}

pub async fn write_structure_file_impl(
    state: &GuiState,
    task_id: String,
    req: StructureWriteRequest,
    on_progress: Channel<ProgressEvent>,
) -> Result<WriteResult, ErrorDetail> {
    // Check destination file overwrite policy before entering the engine.
    // An omitted `output_path` means "write in place": the carrier is the
    // destination, and `overwrite=false` must not reject the user's in-place
    // write. Only a different explicit destination is checked.
    let overwrite = req.overwrite;

    run_cancellable_task(state, task_id, on_progress, move |engine, pool, ctrl, _| {
        if let Some(dest) = crate::commands::stego::overwrite_target(
            req.output_path.as_deref(),
            &req.carrier,
        ) {
            check_overwrite(dest, overwrite)?;
        }

        let (buf, filename, is_file);
        let source = match req.payload {
            PayloadInputDto::Text { ref content } => {
                let res = PayloadSource::Text(content).into_buffered()?;
                buf = res.0;
                filename = res.1;
                is_file = res.2;
                PayloadSource::Buffered {
                    data: &buf,
                    filename: &filename,
                    is_file,
                }
            }
            PayloadInputDto::File { ref path } => PayloadSource::File(path),
        };

        let strategy_str = req.strategy.as_deref().unwrap_or("auto");
        let write_opts = WriteOptions::default()
            .with_output_option(req.output_path.as_deref())
            .with_password_option(req.password.as_deref())
            .with_password_hint_option(req.password_hint.as_deref())
            .with_strategy(strategy_str)
            .with_stealth(req.stealth)
            .with_preserve_time(req.preserve_time)
            .with_backup(req.backup)
            // Same value the pre-flight `check_overwrite` above used, so
            // the engine's own guard agrees with the IPC-level check.
            .with_overwrite(overwrite)
            .with_control(ctrl);

        let res = pool.install(|| {
            engine
                .structure()
                .write_file(&req.carrier, source, &write_opts)
        })?;

        crate::logger::record_json(
            "info",
            "ipc::write_structure",
            &format!(
                "Wrote structure: strategy={}, ube_size={}, raw_size={}",
                res.strategy, res.ube_size, res.raw_size
            ),
            &res,
        );

        Ok(res)
    })
    .await
}

#[tauri::command]
pub async fn write_structure_file_cmd(
    state: State<'_, GuiState>,
    task_id: String,
    req: StructureWriteRequest,
    on_progress: Channel<ProgressEvent>,
) -> Result<WriteResult, ErrorDetail> {
    write_structure_file_impl(&state, task_id, req, on_progress).await
}

pub async fn read_structure_file_impl(
    state: &GuiState,
    task_id: String,
    path: PathBuf,
    output_path: Option<PathBuf>,
    password: Option<String>,
    overwrite: bool,
    on_progress: Channel<ProgressEvent>,
) -> Result<ReadSummary, ErrorDetail> {
    run_cancellable_task(state, task_id, on_progress, move |engine, pool, ctrl, _| {
        let opts = ReadOptions::default().with_output_option(output_path.as_deref()).with_password_option(password.as_deref()).with_overwrite(overwrite).with_control(ctrl);
        let res = pool.install(|| engine.structure().read_file(&path, &opts))?;
        let summary = res.summary();

        let log_data = serde_json::json!({
            "carrier": summary.carrier,
            "is_file": summary.is_file,
            "is_encrypted": summary.is_encrypted,
            "filename": summary.filename,
            "raw_size": summary.raw_size,
            "written_file": summary.written_file,
            "has_text_preview": summary.text_preview.is_some(),
        });

        crate::logger::record_custom_log(
            "info",
            "ipc::read_structure",
            &format!(
                "Read structure: is_file={}, raw_size={}, filename={}",
                summary.is_file, summary.raw_size, summary.filename
            ),
            Some(log_data),
        );

        Ok(summary)
    })
    .await
}

#[tauri::command]
pub async fn read_structure_file_cmd(
    state: State<'_, GuiState>,
    task_id: String,
    path: PathBuf,
    output_path: Option<PathBuf>,
    password: Option<String>,
    overwrite: bool,
    on_progress: Channel<ProgressEvent>,
) -> Result<ReadSummary, ErrorDetail> {
    read_structure_file_impl(
        &state,
        task_id,
        path,
        output_path,
        password,
        overwrite,
        on_progress,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn restore_structure_file_impl(
    state: &GuiState,
    task_id: String,
    path: PathBuf,
    output_path: Option<PathBuf>,
    password: Option<String>,
    backup: bool,
    overwrite: bool,
    on_progress: Channel<ProgressEvent>,
) -> Result<RemoveResult, ErrorDetail> {
    run_cancellable_task(state, task_id, on_progress, move |engine, pool, ctrl, _| {
        let opts = RestoreOptions::default().with_output_option(output_path.as_deref()).with_password_option(password.as_deref()).with_backup(backup).with_overwrite(overwrite).with_control(ctrl);
        pool.install(|| engine.structure().restore_file(&path, &opts))
    })
    .await
}

#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn restore_structure_file_cmd(
    state: State<'_, GuiState>,
    task_id: String,
    path: PathBuf,
    output_path: Option<PathBuf>,
    password: Option<String>,
    backup: bool,
    overwrite: bool,
    on_progress: Channel<ProgressEvent>,
) -> Result<RemoveResult, ErrorDetail> {
    restore_structure_file_impl(
        &state,
        task_id,
        path,
        output_path,
        password,
        backup,
        overwrite,
        on_progress,
    )
    .await
}
