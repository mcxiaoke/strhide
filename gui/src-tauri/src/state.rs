use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;
use tauri::ipc::Channel;

use strhide::core::control::{CancelToken, Control, Event, Progress};
use strhide::core::i18n::{self, RenderCtx};
use strhide::errors::{ErrorDetail, StrHideError};
use strhide::facade::StrHide;

pub struct GuiState {
    pub engine: StrHide,
    pub tasks: Mutex<HashMap<String, Arc<CancelToken>>>,
    pub pool: Arc<rayon::ThreadPool>,
}

impl Default for GuiState {
    fn default() -> Self {
        // Reserve 1~2 CPU cores for OS and UI/WebView rendering threads
        let total_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let worker_threads = total_cores.saturating_sub(1).max(1);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(worker_threads)
            .thread_name(|i| format!("strhide-worker-{i}"))
            .build()
            .expect("failed to build strhide rayon pool");

        Self {
            engine: StrHide::new(),
            tasks: Mutex::new(HashMap::new()),
            pool: Arc::new(pool),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressEvent {
    pub task_id: String,
    pub stage: &'static str,
    pub done: u64,
    pub total: Option<u64>,
    pub percent: Option<f32>,
}

/// Pure throttling decision function for deterministic unit testing.
pub fn should_emit_throttle(
    is_boundary: bool,
    stage_changed: bool,
    now_ms: u64,
    last_emit_ms: u64,
    min_interval_ms: u64,
) -> bool {
    if is_boundary || stage_changed {
        return true;
    }
    now_ms.saturating_sub(last_emit_ms) >= min_interval_ms
}

/// Tauri Channel progress forwarder with 60fps (16ms) throttling protection.
pub struct ThrottledChannelProgress {
    pub task_id: String,
    pub channel: Channel<ProgressEvent>,
    pub start_instant: Instant,
    pub last_emit_ms: AtomicU64,
    pub last_stage: Mutex<&'static str>,
}

impl ThrottledChannelProgress {
    pub fn new(task_id: String, channel: Channel<ProgressEvent>) -> Self {
        Self {
            task_id,
            channel,
            start_instant: Instant::now(),
            last_emit_ms: AtomicU64::new(0),
            last_stage: Mutex::new(""),
        }
    }
}

impl Progress for ThrottledChannelProgress {
    fn report(&self, ev: Event) {
        let stage_str = ev.stage.as_str();
        let is_boundary = ev.done == 0 || ev.total.is_some_and(|t| ev.done >= t);
        let now_ms = self.start_instant.elapsed().as_millis() as u64;

        let mut prev_stage = self.last_stage.lock().unwrap();
        let stage_changed = *prev_stage != stage_str;
        if stage_changed {
            *prev_stage = stage_str;
        }
        drop(prev_stage);

        let last = self.last_emit_ms.load(Ordering::Relaxed);
        if !should_emit_throttle(is_boundary, stage_changed, now_ms, last, 16) {
            return;
        }
        self.last_emit_ms.store(now_ms, Ordering::Relaxed);

        let percent = ev.total.and_then(|t| {
            if t > 0 {
                Some(((ev.done as f64 / t as f64) * 100.0).clamp(0.0, 100.0) as f32)
            } else {
                None
            }
        });

        let _ = self.channel.send(ProgressEvent {
            task_id: self.task_id.clone(),
            stage: stage_str,
            done: ev.done,
            total: ev.total,
            percent,
        });
    }
}

/// Unified cancellable background task executor:
/// registers/unregisters CancelToken, executes with catch_unwind protection,
/// and localizes StrHideError to ErrorDetail.
pub async fn run_cancellable_task<T, F>(
    state: &GuiState,
    task_id: String,
    on_progress: Channel<ProgressEvent>,
    worker: F,
) -> Result<T, ErrorDetail>
where
    T: Send + 'static,
    F: FnOnce(
            StrHide,
            Arc<rayon::ThreadPool>,
            Control<'_>,
            Arc<CancelToken>,
        ) -> Result<T, StrHideError>
        + Send
        + 'static,
{
    let engine = state.engine;
    let pool = Arc::clone(&state.pool);
    let token = Arc::new(CancelToken::new());
    state
        .tasks
        .lock()
        .unwrap()
        .insert(task_id.clone(), Arc::clone(&token));

    let task_id_clone = task_id.clone();
    let token_clone = Arc::clone(&token);

    let join_res = tauri::async_runtime::spawn_blocking(move || {
        let reporter = ThrottledChannelProgress::new(task_id_clone, on_progress);
        let unwind_res = catch_unwind(AssertUnwindSafe(|| {
            let ctrl = Control {
                progress: &reporter,
                cancel: Some(token_clone.as_ref()),
            };
            worker(engine, pool, ctrl, Arc::clone(&token_clone))
        }));

        match unwind_res {
            Ok(res) => res,
            Err(_) => Err(StrHideError::General(
                "Internal engine panic caught safely at GUI worker boundary".into(),
            )),
        }
    })
    .await;

    state.tasks.lock().unwrap().remove(&task_id);

    let ctx = RenderCtx::new(i18n::lang());
    match join_res {
        Ok(Ok(val)) => Ok(val),
        Ok(Err(err)) => Err(err.detail_i18n_with_ctx(ctx)),
        Err(join_err) => Err(StrHideError::General(format!(
            "Worker thread join error: {join_err}"
        ))
        .detail_i18n_with_ctx(ctx)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strhide::core::control::{Event, Stage};

    #[test]
    fn test_should_emit_throttle_pure_logic() {
        // Boundary events always emit
        assert!(should_emit_throttle(true, false, 5, 0, 16));
        // Stage change always emits
        assert!(should_emit_throttle(false, true, 5, 0, 16));
        // Sub-16ms intermediate events do not emit
        assert!(!should_emit_throttle(false, false, 10, 0, 16));
        assert!(!should_emit_throttle(false, false, 15, 0, 16));
        // >= 16ms intermediate events emit
        assert!(should_emit_throttle(false, false, 16, 0, 16));
        assert!(should_emit_throttle(false, false, 100, 50, 16));
    }

    #[test]
    fn test_cancel_token_registration_and_cancellation() {
        let state = GuiState::default();
        let token = Arc::new(CancelToken::new());
        state
            .tasks
            .lock()
            .unwrap()
            .insert("task-1".to_string(), Arc::clone(&token));

        assert!(!token.is_cancelled());

        // Cancel through tasks map
        {
            let tasks = state.tasks.lock().unwrap();
            if let Some(t) = tasks.get("task-1") {
                t.cancel();
            }
        }
        assert!(token.is_cancelled());

        // Remove task
        state.tasks.lock().unwrap().remove("task-1");
        assert!(state.tasks.lock().unwrap().get("task-1").is_none());
    }

    #[test]
    fn test_throttled_channel_progress_flow() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_clone = Arc::clone(&received);

        let channel = Channel::new(move |msg| {
            received_clone.lock().unwrap().push(msg);
            Ok(())
        });

        let progress = ThrottledChannelProgress::new("task-test".into(), channel);

        // 1. Initial event (boundary: done == 0)
        progress.report(Event {
            stage: Stage::Read,
            done: 0,
            total: Some(100),
        });

        // 2. Rapid intermediate events (< 16ms)
        for d in 1..10 {
            progress.report(Event {
                stage: Stage::Read,
                done: d,
                total: Some(100),
            });
        }

        // 3. Stage boundary event (stage changed to Decode)
        progress.report(Event {
            stage: Stage::Decode,
            done: 0,
            total: Some(200),
        });

        // 4. Completion event (done == total)
        progress.report(Event {
            stage: Stage::Decode,
            done: 200,
            total: Some(200),
        });

        let msgs = received.lock().unwrap();
        // Boundary events and stage change must be received
        assert!(
            msgs.len() >= 3,
            "Expected at least 3 events, got {}",
            msgs.len()
        );
    }
}
