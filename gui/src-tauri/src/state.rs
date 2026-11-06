use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;
use tauri::ipc::Channel;

use strhide::core::control::{CancelToken, Control, Event, Progress, Stage};
use strhide::core::i18n::{self, RenderCtx};
use strhide::errors::{ErrorDetail, StrHideError};
use strhide::facade::StrHide;

#[derive(Clone)]
pub struct CachedExtract {
    pub path: std::path::PathBuf,
    pub mtime: Option<std::time::SystemTime>,
    pub password: Option<String>,
    /// The extraction parameters are part of the key: a probe made for one
    /// domain or preference must not answer a different request on the same
    /// unchanged file.
    pub domain: Option<String>,
    pub prefer: Option<strhide::facade::Domain>,
    pub outcome: strhide::facade::ExtractOutcome,
}

impl CachedExtract {
    /// The cache is only reusable when every input that changes the result is
    /// identical. `domain` and `prefer` are part of that input: without them a
    /// result probed for one domain answers a different request on the same
    /// unchanged carrier.
    #[allow(clippy::too_many_arguments)]
    pub fn matches(
        &self,
        path: &std::path::Path,
        mtime: Option<std::time::SystemTime>,
        password: &Option<String>,
        domain: &Option<String>,
        prefer: Option<strhide::facade::Domain>,
    ) -> bool {
        self.path == path
            && self.mtime == mtime
            && &self.password == password
            && &self.domain == domain
            && self.prefer == prefer
    }
}

pub struct GuiState {
    pub engine: StrHide,
    pub tasks: Mutex<HashMap<String, Arc<CancelToken>>>,
    pub pool: Arc<rayon::ThreadPool>,
    pub extract_cache: Arc<Mutex<Option<CachedExtract>>>,
    /// Bytes reserved by in-flight embed tasks. Admission compares this with
    /// [`embed_concurrency_limit`] so a burst of large JPEGs cannot exhaust
    /// the machine before the allocator reports it.
    pub embed_reserved: AtomicUsize,
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
            extract_cache: Arc::new(Mutex::new(None)),
            embed_reserved: AtomicUsize::new(0),
        }
    }
}

/// Per-task reservation for the largest measured JPEG peak: 50 MP 4:4:4 with
/// a 4 KiB payload used 1,427 MiB private bytes; round up to 1.43 GiB so the
/// tier also covers ordinary metadata overhead.
pub const EMBED_PEAK_BYTES: usize = 1_535_000_000;

/// Embeds may use 60% of the free physical memory; the rest stays with the
/// WebView, the engine's rayon pool and the OS.
const EMBED_MEMORY_NUMERATOR: usize = 3;
const EMBED_MEMORY_DENOMINATOR: usize = 5;

/// Number of embed slots that fit `available_bytes` of free physical memory
/// at the [`EMBED_PEAK_BYTES`] tier. One slot is always allowed so a small
/// machine can still run a single small image; a platform that cannot report
/// memory is treated as single-slot.
pub fn embed_concurrency_limit(available_bytes: Option<u64>) -> usize {
    let Some(available) = available_bytes else {
        return 1;
    };
    let budget =
        (available as usize).saturating_mul(EMBED_MEMORY_NUMERATOR) / EMBED_MEMORY_DENOMINATOR;
    (budget / EMBED_PEAK_BYTES).max(1)
}

/// Reservation held for the lifetime of one embed command.
pub struct EmbedReservation<'a> {
    reserved: &'a AtomicUsize,
}

impl Drop for EmbedReservation<'_> {
    fn drop(&mut self) {
        self.reserved.fetch_sub(EMBED_PEAK_BYTES, Ordering::SeqCst);
    }
}

/// Reserve one embed slot against the machine's free memory, or reject the
/// command with a reason instead of starting a job that would OOM.
pub fn reserve_embed_slot(reserved: &AtomicUsize) -> Result<EmbedReservation<'_>, StrHideError> {
    reserve_embed_slot_with_limit(
        reserved,
        embed_concurrency_limit(strhide::core::sysmem::available_physical_memory()),
    )
}

fn reserve_embed_slot_with_limit(
    reserved: &AtomicUsize,
    limit: usize,
) -> Result<EmbedReservation<'_>, StrHideError> {
    loop {
        let current = reserved.load(Ordering::SeqCst);
        let active = current / EMBED_PEAK_BYTES;
        if active >= limit {
            return Err(StrHideError::Rejection(format!(
                "Not enough memory for another concurrent embed: {active} of {limit} slots are in use \
                 (each reserves {:.2} GiB, the budget is 60% of free physical memory). \
                 Wait for a running embed to finish.",
                EMBED_PEAK_BYTES as f64 / (1024.0 * 1024.0 * 1024.0)
            )));
        }
        if reserved
            .compare_exchange(
                current,
                current + EMBED_PEAK_BYTES,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            return Ok(EmbedReservation { reserved });
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
        // Per-item batch events are the progress bar's unit of truth; throttle
        // must not merge two finished items into one report.
        let is_boundary = matches!(ev.stage, Stage::Batch)
            || ev.done == 0
            || ev.total.is_some_and(|t| ev.done >= t);
        let now_ms = self.start_instant.elapsed().as_millis() as u64;

        let mut prev_stage = self.last_stage.lock().unwrap();
        let stage_changed = *prev_stage != stage_str;
        if stage_changed {
            *prev_stage = stage_str;
            log::debug!(
                target: "engine::progress",
                "Task [{}] entered stage: {}",
                self.task_id,
                stage_str
            );
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

/// Recover the message a panic carried.
///
/// `catch_unwind` hands back `Box<dyn Any + Send>`, and the previous
/// `Err(_) =>` arms discarded it: the log and the user were both left with
/// "Worker thread panicked", which is the one piece of information that
/// cannot be reconstructed after the fact.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    const MAX: usize = 512;
    let raw = if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_string()
    };
    if raw.chars().count() <= MAX {
        return raw;
    }
    let mut truncated: String = raw.chars().take(MAX).collect();
    truncated.push('…');
    truncated
}

/// Build the user-facing error for a panic caught at a worker boundary while
/// keeping the payload in the log.
pub fn panic_error(payload: &(dyn std::any::Any + Send), target: &str) -> StrHideError {
    let msg = panic_message(payload);
    log::error!(target: "engine::panic", "{target}: {msg}");
    StrHideError::General(format!("Internal engine panic: {msg}"))
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
    let start_time = Instant::now();
    log::info!(target: "engine::task", "Task [{}] started", task_id);

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
            Err(payload) => Err(panic_error(payload.as_ref(), "cancellable worker")),
        }
    })
    .await;

    state.tasks.lock().unwrap().remove(&task_id);

    match &join_res {
        Ok(Ok(_)) => {
            log::info!(
                target: "engine::task",
                "Task [{}] completed successfully in {:?}",
                task_id,
                start_time.elapsed()
            );
        }
        Ok(Err(err)) => {
            log::warn!(
                target: "engine::task",
                "Task [{}] failed in {:?}: {}",
                task_id,
                start_time.elapsed(),
                err
            );
        }
        Err(join_err) => {
            log::error!(
                target: "engine::task",
                "Task [{}] thread join error in {:?}: {}",
                task_id,
                start_time.elapsed(),
                join_err
            );
        }
    }

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

    /// P2-7: the extraction cache used to key only on path/mtime/password, so
    /// switching the requested domain or preference on an unchanged carrier
    /// returned the previous probe's result.
    #[test]
    fn extract_cache_key_includes_domain_and_prefer() {
        use strhide::core::payload::Payload;
        use strhide::facade::{Domain, ExtractOutcome};

        let path = std::path::PathBuf::from("carrier.png");
        let cached = CachedExtract {
            path: path.clone(),
            mtime: None,
            password: None,
            domain: Some("structure".to_string()),
            prefer: Some(Domain::Structure),
            outcome: ExtractOutcome {
                payload: Payload::bytes(b"x"),
                source: Domain::Structure,
                also_present: None,
                is_encrypted: false,
            },
        };
        assert!(cached.matches(
            &path,
            None,
            &None,
            &Some("structure".to_string()),
            Some(Domain::Structure)
        ));
        assert!(!cached.matches(
            &path,
            None,
            &None,
            &Some("content".to_string()),
            Some(Domain::Structure)
        ));
        assert!(!cached.matches(
            &path,
            None,
            &None,
            &Some("structure".to_string()),
            Some(Domain::Content)
        ));
    }

    /// The panic payload used to be discarded at every worker boundary, so a
    /// panic surfaced as "Worker thread panicked" with nothing to act on.
    #[test]
    fn panic_message_keeps_the_text_the_panic_carried() {
        let str_payload: Box<dyn std::any::Any + Send> = Box::new("index out of bounds");
        assert_eq!(panic_message(str_payload.as_ref()), "index out of bounds");

        let string_payload: Box<dyn std::any::Any + Send> =
            Box::new(String::from("assertion failed: coeffs.len() == expected"));
        assert_eq!(
            panic_message(string_payload.as_ref()),
            "assertion failed: coeffs.len() == expected"
        );

        let opaque: Box<dyn std::any::Any + Send> = Box::new(7u32);
        assert_eq!(panic_message(opaque.as_ref()), "non-string panic payload");
    }

    #[test]
    fn panic_message_truncates_oversized_payloads() {
        let long = "x".repeat(600);
        let payload: Box<dyn std::any::Any + Send> = Box::new(long);
        let msg = panic_message(payload.as_ref());
        assert_eq!(msg.chars().count(), 513);
        assert!(msg.ends_with('…'));
    }

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
    fn embed_concurrency_limit_uses_60_percent_of_free_memory() {
        assert_eq!(embed_concurrency_limit(None), 1);
        assert_eq!(embed_concurrency_limit(Some(1 << 30)), 1);
        assert_eq!(embed_concurrency_limit(Some(4 << 30)), 1);
        assert_eq!(embed_concurrency_limit(Some(8 << 30)), 3);
        assert_eq!(embed_concurrency_limit(Some(16 << 30)), 6);
    }

    #[test]
    fn concurrent_embeds_beyond_the_limit_are_rejected() {
        let reserved = AtomicUsize::new(0);
        let first = reserve_embed_slot_with_limit(&reserved, 2).expect("first slot");
        let second = reserve_embed_slot_with_limit(&reserved, 2).expect("second slot");
        assert!(
            matches!(
                reserve_embed_slot_with_limit(&reserved, 2),
                Err(StrHideError::Rejection(_))
            ),
            "a third concurrent embed must be rejected, not started"
        );
        drop(first);
        assert!(reserve_embed_slot_with_limit(&reserved, 2).is_ok());
        drop(second);
        assert_eq!(reserved.load(Ordering::SeqCst), 0);
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
