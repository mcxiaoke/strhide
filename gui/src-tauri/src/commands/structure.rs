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
    // Check destination file overwrite policy before entering the engine
    let target = req.output_path.as_deref().unwrap_or(&req.carrier);
    let target_buf = target.to_path_buf();
    let overwrite = req.overwrite;

    run_cancellable_task(state, task_id, on_progress, move |engine, pool, ctrl, _| {
        // Enforce overwrite check on output path
        check_overwrite(&target_buf, overwrite)?;

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
        let write_opts = WriteOptions {
            output_path: req.output_path.as_deref(),
            password: req.password.as_deref(),
            password_hint: req.password_hint.as_deref(),
            strategy: strategy_str,
            stealth: req.stealth,
            preserve_time: req.preserve_time,
            backup: req.backup,
            // Same value the pre-flight `check_overwrite` above used, so
            // the engine's own guard agrees with the IPC-level check.
            overwrite,
            control: ctrl,
        };

        pool.install(|| {
            engine
                .structure()
                .write_file(&req.carrier, source, &write_opts)
        })
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
        let opts = ReadOptions {
            output_path: output_path.as_deref(),
            password: password.as_deref(),
            overwrite,
            control: ctrl,
        };
        let res = pool.install(|| engine.structure().read_file(&path, &opts))?;
        Ok(res.summary())
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
        let opts = RestoreOptions {
            output_path: output_path.as_deref(),
            password: password.as_deref(),
            backup,
            overwrite,
            control: ctrl,
        };
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
