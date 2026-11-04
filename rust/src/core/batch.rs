//! Batch execution engine for processing multiple carriers with structured outcomes.
//!
//! Provides concurrency control, cancellation propagation, and per-item timing/error
//! capture without printing to stdout/stderr, suitable for GUI task queues and CLI batch ops.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::core::control::{CancelToken, Control, Event, Progress, Stage};
use crate::errors::{ErrorDetail, StrHideError};

/// Configuration and control policy for a batch run.
#[derive(Debug, Clone)]
pub struct BatchPlan {
    /// When true, records item errors and continues processing remaining items.
    /// When false, stops immediately on the first error.
    pub continue_on_error: bool,
    /// Maximum concurrent worker threads: 1 = sequential (recommended for large content stego),
    /// >1 = multi-threaded parallel execution. Defaults to 1.
    pub max_concurrency: usize,
    /// Optional cancellation token shared with a GUI controller or worker manager.
    pub cancel: Option<Arc<CancelToken>>,
    /// Optional render context for error detail rendering.
    pub ctx: Option<crate::core::i18n::RenderCtx>,
}

impl Default for BatchPlan {
    fn default() -> Self {
        Self {
            continue_on_error: true,
            max_concurrency: 1,
            cancel: None,
            ctx: None,
        }
    }
}

/// Execution outcome for a single carrier item in a batch run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemOutcome<R> {
    pub index: usize,
    pub item: PathBuf,
    pub result: Result<R, ErrorDetail>,
    pub elapsed_ms: u64,
}

/// Aggregated outcome of a completed or cancelled batch run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchOutcome<R> {
    pub items: Vec<ItemOutcome<R>>,
    pub succeeded: usize,
    pub failed: usize,
    pub cancelled: bool,
}

/// Execute `worker` against each item in `items` according to `plan`.
///
/// `progress` receives one [`Stage::Batch`] event per finished item (success
/// or failure), with `done` counting completed items and `total` the item
/// count. Per-item engines also report their own stage events through the
/// [`Control`] handed to `worker`.
///
/// Pure library operation with zero stdout/stderr output.
pub fn run_batch<T, R, F>(
    items: &[T],
    plan: &BatchPlan,
    progress: &dyn Progress,
    worker: F,
) -> BatchOutcome<R>
where
    T: AsRef<Path> + Sync,
    R: Send + 'static,
    F: Fn(usize, &Path, &Control<'_>) -> Result<R, StrHideError> + Sync + Send,
{
    if items.is_empty() {
        return BatchOutcome {
            items: Vec::new(),
            succeeded: 0,
            failed: 0,
            cancelled: false,
        };
    }

    let is_cancelled = || {
        plan.cancel
            .as_ref()
            .is_some_and(|token| token.is_cancelled())
    };

    let total = items.len();
    let max_concurrency = plan.max_concurrency.max(1).min(total);

    let stopped = AtomicBool::new(false);
    let cancelled_flag = AtomicBool::new(false);
    let completed = AtomicUsize::new(0);

    let outcomes = std::sync::Mutex::new(
        (0..total)
            .map(|_| None::<ItemOutcome<R>>)
            .collect::<Vec<_>>(),
    );

    if max_concurrency == 1 {
        for (idx, item) in items.iter().enumerate() {
            if is_cancelled() {
                cancelled_flag.store(true, Ordering::SeqCst);
                break;
            }
            if stopped.load(Ordering::SeqCst) {
                break;
            }

            let path = item.as_ref();
            let ctrl = Control {
                progress,
                cancel: plan.cancel.as_deref(),
            };

            let start = Instant::now();
            let res = worker(idx, path, &ctrl);
            let elapsed_ms = start.elapsed().as_millis() as u64;

            let is_err = res.is_err();
            let mapped = res.map_err(|e| match plan.ctx {
                Some(ctx) => e.detail_i18n_with_ctx(ctx),
                None => e.detail_i18n(),
            });
            let outcome = ItemOutcome {
                index: idx,
                item: path.to_path_buf(),
                result: mapped,
                elapsed_ms,
            };

            outcomes.lock().unwrap()[idx] = Some(outcome);
            let done = completed.fetch_add(1, Ordering::SeqCst) + 1;
            progress.report(Event::progress(
                Stage::Batch,
                done as u64,
                Some(total as u64),
            ));

            if is_err && !plan.continue_on_error {
                stopped.store(true, Ordering::SeqCst);
                break;
            }
        }
    } else {
        let next_idx = AtomicUsize::new(0);

        std::thread::scope(|s| {
            for _ in 0..max_concurrency {
                s.spawn(|| {
                    loop {
                        if is_cancelled() {
                            cancelled_flag.store(true, Ordering::SeqCst);
                            break;
                        }
                        if stopped.load(Ordering::SeqCst) {
                            break;
                        }

                        let idx = next_idx.fetch_add(1, Ordering::SeqCst);
                        if idx >= total {
                            break;
                        }

                        let path = items[idx].as_ref();
                        let ctrl = Control {
                            progress,
                            cancel: plan.cancel.as_deref(),
                        };

                        let start = Instant::now();
                        let res = worker(idx, path, &ctrl);
                        let elapsed_ms = start.elapsed().as_millis() as u64;

                        let is_err = res.is_err();
                        let mapped = res.map_err(|e| match plan.ctx {
                            Some(ctx) => e.detail_i18n_with_ctx(ctx),
                            None => e.detail_i18n(),
                        });
                        let outcome = ItemOutcome {
                            index: idx,
                            item: path.to_path_buf(),
                            result: mapped,
                            elapsed_ms,
                        };

                        outcomes.lock().unwrap()[idx] = Some(outcome);
                        let done = completed.fetch_add(1, Ordering::SeqCst) + 1;
                        progress.report(Event::progress(
                            Stage::Batch,
                            done as u64,
                            Some(total as u64),
                        ));

                        if is_err && !plan.continue_on_error {
                            stopped.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                });
            }
        });
    }

    let raw_outcomes = outcomes.into_inner().unwrap();
    let mut collected = Vec::with_capacity(total);
    let mut succeeded = 0usize;
    let mut failed = 0usize;

    for item in raw_outcomes.into_iter().flatten() {
        if item.result.is_ok() {
            succeeded += 1;
        } else {
            failed += 1;
        }
        collected.push(item);
    }

    let was_cancelled = cancelled_flag.load(Ordering::SeqCst) || is_cancelled();

    BatchOutcome {
        items: collected,
        succeeded,
        failed,
        cancelled: was_cancelled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::control::NoProgress;

    #[test]
    fn batch_continues_on_error_when_flagged() {
        let items: Vec<PathBuf> = (0..20)
            .map(|i| PathBuf::from(format!("item_{i}")))
            .collect();
        let plan = BatchPlan {
            continue_on_error: true,
            max_concurrency: 1,
            cancel: None,
            ctx: None,
        };

        let outcome = run_batch(&items, &plan, &NoProgress, |idx, _path, _ctrl| {
            if idx == 2 {
                Err(StrHideError::General("item 2 failed".into()))
            } else {
                Ok(idx * 10)
            }
        });

        assert_eq!(outcome.items.len(), 20);
        assert_eq!(outcome.succeeded, 19);
        assert_eq!(outcome.failed, 1);
        assert!(!outcome.cancelled);
        assert!(outcome.items[2].result.is_err());
        assert_eq!(outcome.items[3].result.as_ref().unwrap(), &30);
    }

    #[test]
    fn batch_stops_on_first_error_when_continue_false() {
        let items: Vec<PathBuf> = (0..20)
            .map(|i| PathBuf::from(format!("item_{i}")))
            .collect();
        let plan = BatchPlan {
            continue_on_error: false,
            max_concurrency: 1,
            cancel: None,
            ctx: None,
        };

        let outcome = run_batch(&items, &plan, &NoProgress, |idx, _path, _ctrl| {
            if idx == 2 {
                Err(StrHideError::General("item 2 failed".into()))
            } else {
                Ok(idx * 10)
            }
        });

        assert_eq!(outcome.items.len(), 3);
        assert_eq!(outcome.succeeded, 2);
        assert_eq!(outcome.failed, 1);
    }

    #[test]
    fn batch_parallel_processes_all_items() {
        let items: Vec<PathBuf> = (0..20)
            .map(|i| PathBuf::from(format!("item_{i}")))
            .collect();
        let plan = BatchPlan {
            continue_on_error: true,
            max_concurrency: 4,
            cancel: None,
            ctx: None,
        };

        let outcome = run_batch(&items, &plan, &NoProgress, |idx, _path, _ctrl| Ok(idx));
        assert_eq!(outcome.items.len(), 20);
        assert_eq!(outcome.succeeded, 20);
        assert_eq!(outcome.failed, 0);
    }

    #[derive(Default)]
    struct Recorder(std::sync::Mutex<Vec<Event>>);

    impl Progress for Recorder {
        fn report(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    /// A batch of two or more items must announce every finished item, failures
    /// included: the GUI progress bar is driven by this count, and a failed
    /// item that reported nothing would leave the bar short of 100%.
    #[test]
    fn batch_reports_one_event_per_item_including_failures() {
        let items: Vec<PathBuf> = (0..8).map(|i| PathBuf::from(format!("item_{i}"))).collect();
        let plan = BatchPlan {
            continue_on_error: true,
            max_concurrency: 1,
            cancel: None,
            ctx: None,
        };
        let recorder = Recorder::default();

        let outcome = run_batch(&items, &plan, &recorder, |idx, _path, _ctrl| {
            if idx % 3 == 0 {
                Err(StrHideError::General("failed".into()))
            } else {
                Ok(idx)
            }
        });

        assert_eq!(outcome.items.len(), 8);
        assert_eq!(outcome.failed, 3);
        let batch: Vec<Event> = recorder
            .0
            .lock()
            .unwrap()
            .iter()
            .copied()
            .filter(|event| event.stage == Stage::Batch)
            .collect();
        assert_eq!(batch.len(), 8, "one event per item, failures included");
        for (n, event) in batch.iter().enumerate() {
            assert_eq!(event.total, Some(8));
            assert_eq!(event.done, n as u64 + 1);
        }
    }
}
