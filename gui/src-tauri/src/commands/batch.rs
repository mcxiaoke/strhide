use serde::Deserialize;
use std::path::PathBuf;
use tauri::State;
use tauri::ipc::Channel;

use strhide::core::batch::{BatchOutcome, BatchPlan, run_batch};
use strhide::core::i18n::{self, Lang, RenderCtx};
use strhide::errors::ErrorDetail;
use strhide::facade::DualOptions;
use strhide::structure::options::RestoreOptions;

use crate::state::{GuiState, ProgressEvent, lock_unpoisoned, run_cancellable_task};

#[derive(Debug, Clone, Deserialize)]
pub struct BatchJobSpec {
    pub job_type: String, // "inspect" | "verify" | "scan" | "restore"
    pub password: Option<String>,
    pub domain: Option<String>,
    pub continue_on_error: bool,
    pub max_concurrency: usize,
}

#[tauri::command]
pub fn set_ui_language_cmd(lang: Lang) -> Lang {
    i18n::set_lang(lang);
    lang
}

#[tauri::command]
pub fn cancel_task_cmd(state: State<'_, GuiState>, task_id: String) -> bool {
    let tasks = lock_unpoisoned(&state.tasks);
    if let Some(token) = tasks.get(&task_id) {
        token.cancel();
        true
    } else {
        false
    }
}

#[tauri::command]
pub async fn run_batch_job_cmd(
    state: State<'_, GuiState>,
    task_id: String,
    items: Vec<PathBuf>,
    job: BatchJobSpec,
    on_progress: Channel<ProgressEvent>,
) -> Result<BatchOutcome<serde_json::Value>, ErrorDetail> {
    run_batch_job_impl(&state, task_id, items, job, on_progress).await
}

/// Testable core of [`run_batch_job_cmd`]: the Tauri command only unwraps
/// `State`, so cross-validation can drive the same path with a recording
/// channel.
pub async fn run_batch_job_impl(
    state: &GuiState,
    task_id: String,
    items: Vec<PathBuf>,
    job: BatchJobSpec,
    on_progress: Channel<ProgressEvent>,
) -> Result<BatchOutcome<serde_json::Value>, ErrorDetail> {
    run_cancellable_task(
        state,
        task_id,
        on_progress,
        move |engine, pool, batch_ctrl, token| {
            let plan = BatchPlan::new()
                .with_continue_on_error(job.continue_on_error)
                .with_max_concurrency(job.max_concurrency.max(1))
                .with_cancel(token)
                .with_ctx(RenderCtx::new(i18n::lang()));

            let job_type = job.job_type.clone();
            let password = job.password.clone();
            let domain = job.domain.clone();

            let outcome = pool.install(|| {
                run_batch(
                    &items,
                    &plan,
                    batch_ctrl.progress,
                    |_idx, path, ctrl| match job_type.as_str() {
                        "inspect" => {
                        let opts = DualOptions::new()
                            .with_password_option(password.as_deref())
                            .with_domain_option(domain.as_deref())
                            .with_control(*ctrl);
                            let res = engine.inspect_any(path, &opts)?;
                            serde_json::to_value(res)
                                .map_err(|e| strhide::errors::StrHideError::General(e.to_string()))
                        }
                        "verify" => {
                        let opts = DualOptions::new()
                            .with_password_option(password.as_deref())
                            .with_domain_option(domain.as_deref())
                            .with_control(*ctrl);
                            let res = engine.verify_any(path, &opts)?;
                            serde_json::to_value(res)
                                .map_err(|e| strhide::errors::StrHideError::General(e.to_string()))
                        }
                        "scan" => {
                            let res = engine.analysis().scan_file(path)?;
                            serde_json::to_value(res)
                                .map_err(|e| strhide::errors::StrHideError::General(e.to_string()))
                        }
                        "restore" => {
                            let opts = RestoreOptions::default().with_output_option(None).with_password_option(password.as_deref()).with_backup(true).with_overwrite(true).with_control(*ctrl);
                            let res = engine.structure().restore_file(path, &opts)?;
                            serde_json::to_value(res)
                                .map_err(|e| strhide::errors::StrHideError::General(e.to_string()))
                        }
                        other => Err(strhide::errors::StrHideError::General(format!(
                            "Unknown batch job type: {other}"
                        ))),
                    },
                )
            });

            Ok(outcome)
        },
    )
    .await
}
