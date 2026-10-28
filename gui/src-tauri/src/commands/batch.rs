use serde::Deserialize;
use std::path::PathBuf;
use tauri::State;
use tauri::ipc::Channel;

use strhide::core::batch::{BatchOutcome, BatchPlan, run_batch};
use strhide::core::i18n::{self, Lang, RenderCtx};
use strhide::errors::ErrorDetail;
use strhide::facade::DualOptions;
use strhide::structure::options::RestoreOptions;

use crate::state::{GuiState, ProgressEvent, run_cancellable_task};

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
    let tasks = state.tasks.lock().unwrap();
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
    run_cancellable_task(
        &state,
        task_id,
        on_progress,
        move |engine, pool, _ctrl, token| {
            let plan = BatchPlan {
                continue_on_error: job.continue_on_error,
                max_concurrency: job.max_concurrency.max(1),
                cancel: Some(token),
                ctx: Some(RenderCtx::new(i18n::lang())),
            };

            let job_type = job.job_type.clone();
            let password = job.password.clone();
            let domain = job.domain.clone();

            let outcome = pool.install(|| {
                run_batch(&items, &plan, |_idx, path, ctrl| match job_type.as_str() {
                    "inspect" => {
                        let opts = DualOptions {
                            password: password.as_deref(),
                            domain: domain.as_deref(),
                            control: *ctrl,
                        };
                        let res = engine.inspect_any(path, &opts)?;
                        serde_json::to_value(res)
                            .map_err(|e| strhide::errors::StrHideError::General(e.to_string()))
                    }
                    "verify" => {
                        let opts = DualOptions {
                            password: password.as_deref(),
                            domain: domain.as_deref(),
                            control: *ctrl,
                        };
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
                        let opts = RestoreOptions {
                            output_path: None,
                            password: password.as_deref(),
                            backup: true,
                            overwrite: true,
                            control: *ctrl,
                        };
                        let res = engine.structure().restore_file(path, &opts)?;
                        serde_json::to_value(res)
                            .map_err(|e| strhide::errors::StrHideError::General(e.to_string()))
                    }
                    other => Err(strhide::errors::StrHideError::General(format!(
                        "Unknown batch job type: {other}"
                    ))),
                })
            });

            Ok(outcome)
        },
    )
    .await
}
