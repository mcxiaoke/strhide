//! Progress reporting and cooperative cancellation.
//!
//! Both domains run long tasks: a 13.6 s 1080p60 HEVC carrier takes ~116 s and
//! peaks at ~12 GB, and a 50 MP JPEG costs a full DCT read plus a cost map.
//! Without a progress channel a GUI can only spin, and a user who assumes the
//! process hung kills it mid-write. This module is the single place that
//! answers "how far along is it" and "did the caller ask me to stop".
//!
//! # Design
//!
//! - **Carried in the options structs, not as method arguments**. Adding a
//!   control knob must not change six trait signatures
//!   (`EmbedOptions { control, .. }`, and the structure domain's
//!   `WriteOptions`).
//! - **Stage granularity**. An engine reports at stage boundaries
//!   (`Decode` -> `CostMap` -> `Solve` -> `Encode`); a byte-exact progress bar
//!   is not achievable while one CABAC round can take tens of seconds, and not
//!   needed either -- "the stage changed" is what tells a user it is alive.
//! - **Cancellation returns an error**. Engines must not call
//!   `std::process::exit`: that skips `Drop`, so the temp file a
//!   [`crate::commit`] guard created would survive as a half-written carrier.
//!   Returning [`StrHideError::Cancelled`] unwinds normally and lets the guard
//!   clean up.
//!
//! The default is [`Control::none`]: no callback, no token, no behaviour change
//! for every existing caller (including the CLI's `--quiet` path).

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::errors::StrHideError;

/// Which phase of a domain operation an [`Event`] describes.
///
/// The set is deliberately small and shared by both domains: a consumer
/// renders "Decoding carrier" / "Solving trellis" as a status line and does not
/// need to know whether the carrier is a PNG or a ZIP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Stage {
    /// Reading the carrier or payload from disk.
    Read,
    /// Parsing the carrier into its working representation (pixels, DCT
    /// coefficients, CABAC bins, container tree).
    Decode,
    /// Computing distortion costs and the candidate slot set.
    CostMap,
    /// Running the embedding solver (STC trellis / matrix coding / slot pick).
    Solve,
    /// Re-encoding the modified representation back into carrier bytes.
    Encode,
    /// Committing the result to disk.
    Write,
    /// A verification pass (restore check, AEAD tag re-check, structure scan).
    Verify,
}

impl Stage {
    /// Stable lowercase name, for log lines and GUI status text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Read => "read",
            Stage::Decode => "decode",
            Stage::CostMap => "cost_map",
            Stage::Solve => "solve",
            Stage::Encode => "encode",
            Stage::Write => "write",
            Stage::Verify => "verify",
        }
    }
}

/// One progress report.
///
/// `total` is `None` when the stage's size is not known in advance (a CABAC
/// re-encode cannot know its bin count before it starts walking the stream).
/// `done >= total` always means the stage finished, whether or not `total` was
/// known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Event {
    /// The stage this report belongs to.
    pub stage: Stage,
    /// Work units completed in this stage (blocks, coefficients, bytes).
    pub done: u64,
    /// Work units the stage is expected to perform, if known.
    pub total: Option<u64>,
}

impl Event {
    /// A stage-boundary report with no size information.
    pub const fn stage(stage: Stage) -> Self {
        Self {
            stage,
            done: 0,
            total: None,
        }
    }

    /// A stage-boundary report that also carries the stage's size.
    pub const fn sized(stage: Stage, total: u64) -> Self {
        Self {
            stage,
            done: 0,
            total: Some(total),
        }
    }

    /// A within-stage progress report.
    pub const fn progress(stage: Stage, done: u64, total: Option<u64>) -> Self {
        Self { stage, done, total }
    }
}

/// Sink for [`Event`]s.
///
/// `Send + Sync` because engines fan out over a rayon pool and may report from
/// worker threads; an implementation that touches a GUI toolkit has to marshal
/// to its own thread inside `report`.
pub trait Progress: Send + Sync {
    /// Called at stage boundaries and, in the slow stages, every N work units.
    fn report(&self, event: Event);
}

/// The no-op sink used when the caller did not ask for progress.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProgress;

impl Progress for NoProgress {
    fn report(&self, _event: Event) {}
}

/// A cloneable "please stop" flag.
///
/// Shared between the caller (usually a UI thread) and the running task: the
/// caller calls [`cancel`](Self::cancel), the engine polls
/// [`is_cancelled`](Self::is_cancelled) at its checkpoints. An
/// [`Arc`](std::sync::Arc) is not required in the options struct because the
/// token is passed by reference; wrap it in one when the cancelling thread
/// needs to outlive the borrow.
#[derive(Debug, Default)]
pub struct CancelToken(AtomicBool);

impl CancelToken {
    /// A fresh, uncancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask the running task to stop. Idempotent; safe from any thread.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation has been requested.
    ///
    /// `Relaxed` is enough: the flag orders nothing but itself, and a task that
    /// observes it stops without needing to see the canceller's other writes.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Progress sink plus optional cancellation token, borrowed for one call.
///
/// [`Control::none`] is the default and costs one null check per checkpoint.
#[derive(Clone, Copy)]
pub struct Control<'a> {
    /// Where progress events go. [`NoProgress`] when the caller did not ask.
    pub progress: &'a dyn Progress,
    /// The token to poll, when the caller wants to be able to stop the task.
    pub cancel: Option<&'a CancelToken>,
}

impl<'a> Control<'a> {
    /// No progress, no cancellation.
    pub const fn none() -> Self {
        Self {
            progress: &NoProgress,
            cancel: None,
        }
    }

    /// Report progress to `progress`, but do not allow cancellation.
    pub const fn with_progress(progress: &'a dyn Progress) -> Self {
        Self {
            progress,
            cancel: None,
        }
    }

    /// Allow cancellation through `cancel`, but report no progress.
    pub const fn with_cancel(cancel: &'a CancelToken) -> Self {
        Self {
            progress: &NoProgress,
            cancel: Some(cancel),
        }
    }

    /// Report this event to the sink.
    pub fn report(&self, event: Event) {
        self.progress.report(event);
    }

    /// Report a stage boundary.
    pub fn stage(&self, stage: Stage) {
        self.progress.report(Event::stage(stage));
    }

    /// Report a stage boundary that also announces the stage's size.
    pub fn stage_sized(&self, stage: Stage, total: u64) {
        self.progress.report(Event::sized(stage, total));
    }

    /// Whether the caller asked to stop.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_some_and(CancelToken::is_cancelled)
    }

    /// Checkpoint: `Err(StrHideError::Cancelled)` once the caller asked to stop.
    ///
    /// Engines call this after decoding, after the cost map, before encoding and
    /// every N blocks/coefficients; the error unwinds through the normal
    /// cleanup path so no partial output is committed.
    pub fn check(&self) -> Result<(), StrHideError> {
        if self.is_cancelled() {
            Err(StrHideError::Cancelled)
        } else {
            Ok(())
        }
    }
}

impl Default for Control<'_> {
    fn default() -> Self {
        Self::none()
    }
}

impl std::fmt::Debug for Control<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Control")
            .field("progress", &"<sink>")
            .field("cancel", &self.cancel.is_some())
            .finish()
    }
}

impl PartialEq for Control<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.progress, other.progress)
            && match (self.cancel, other.cancel) {
                (None, None) => true,
                (Some(a), Some(b)) => std::ptr::eq(a, b),
                _ => false,
            }
    }
}

impl Eq for Control<'_> {}

pub const PROGRESS_STEP_BYTES: u64 = 4 * 1024 * 1024; // Every 4 MiB trigger a progress report

pub struct ProgressWriter<'a, 'c, W: Write + ?Sized> {
    inner: &'a mut W,
    control: Control<'c>,
    stage: Stage,
    total: u64,
    done: u64,
    next_report: u64,
}

impl<'a, 'c, W: Write + ?Sized> ProgressWriter<'a, 'c, W> {
    pub fn new(inner: &'a mut W, control: Control<'c>, stage: Stage, total: u64) -> Self {
        control.stage_sized(stage, total);
        Self {
            inner,
            control,
            stage,
            total,
            done: 0,
            next_report: PROGRESS_STEP_BYTES.min(total),
        }
    }
}

impl<W: Write + ?Sized> Write for ProgressWriter<'_, '_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.control.is_cancelled() {
            // Not `ErrorKind::Interrupted`: `Write::write_all` (used by every
            // `copy_exact`/`copy_stream` in the adapters) retries that kind
            // unconditionally with a bare `continue`, so a cancelled writer
            // that keeps answering `Interrupted` spins forever at 100% CPU and
            // `map_io_cancel` never sees an error (review R3 P1-5).
            return Err(io::Error::other("strhide: cancelled"));
        }
        let n = self.inner.write(buf)?;
        self.done += n as u64;
        if self.done >= self.next_report || self.done == self.total {
            self.control
                .report(Event::progress(self.stage, self.done, Some(self.total)));
            self.next_report = self.done + PROGRESS_STEP_BYTES;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Write + Read + ?Sized> Read for ProgressWriter<'_, '_, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<W: Write + Seek + ?Sized> Seek for ProgressWriter<'_, '_, W> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Convert an interrupted I/O error into StrHideError::Cancelled if cancelled.
pub fn map_io_cancel(control: &Control<'_>, err: StrHideError) -> StrHideError {
    match err {
        // Any I/O failure while the token is cancelled is the cancellation
        // showing through, whatever `ErrorKind` the writer chose. Keying on
        // `Interrupted` alone silently dropped the mapping once the cancel
        // marker changed kind (review R3 P1-5).
        StrHideError::Io(_) if control.is_cancelled() => StrHideError::Cancelled,
        other => other,
    }
}

/// Owned carrier of progress reporter and cancel token for background worker threads (GUI / async tasks).
///
/// Preserves the lightweight `Copy` semantics of [`Control<'_>`] while providing an owned,
/// thread-safe container that can be safely moved across thread boundaries.
#[derive(Clone, Default)]
pub struct TaskControl {
    pub progress: Option<std::sync::Arc<dyn Progress>>,
    pub cancel: std::sync::Arc<CancelToken>,
}

impl TaskControl {
    pub fn new(progress: impl Progress + 'static) -> Self {
        Self {
            progress: Some(std::sync::Arc::new(progress)),
            cancel: std::sync::Arc::new(CancelToken::new()),
        }
    }

    pub fn with_cancel(cancel: std::sync::Arc<CancelToken>) -> Self {
        Self {
            progress: None,
            cancel,
        }
    }

    /// Borrow an ephemeral [`Control<'_>`] suitable for passing into options structs.
    pub fn borrow_control(&self) -> Control<'_> {
        Control {
            progress: match &self.progress {
                Some(p) => p.as_ref(),
                None => &NoProgress,
            },
            cancel: Some(&self.cancel),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<Event>>);

    impl Progress for Recorder {
        fn report(&self, event: Event) {
            self.0.lock().unwrap().push(event);
        }
    }

    #[test]
    fn default_control_is_inert() {
        let control = Control::none();
        assert!(!control.is_cancelled());
        assert!(control.check().is_ok());
        // Reporting through the default sink must not panic and must not be
        // observable anywhere -- it is the "caller does not care" path.
        control.stage(Stage::Encode);
    }

    #[test]
    fn events_reach_the_sink_in_order() {
        let recorder = Recorder::default();
        let control = Control::with_progress(&recorder);
        control.stage(Stage::Decode);
        control.stage_sized(Stage::CostMap, 4096);
        control.report(Event::progress(Stage::Solve, 512, Some(4096)));

        let events = recorder.0.lock().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], Event::stage(Stage::Decode));
        assert_eq!(events[1].total, Some(4096));
        assert_eq!(
            events[2],
            Event {
                stage: Stage::Solve,
                done: 512,
                total: Some(4096)
            }
        );
    }

    #[test]
    fn cancel_token_is_visible_through_control() {
        let token = CancelToken::new();
        let control = Control::with_cancel(&token);

        assert!(control.check().is_ok());
        token.cancel();
        assert!(control.is_cancelled());
        assert!(matches!(control.check(), Err(StrHideError::Cancelled)));
    }

    /// Cancellation must be shareable across threads: that is the whole point
    /// of the token, and `Relaxed` ordering must still propagate.
    #[test]
    fn cancel_propagates_across_threads() {
        struct Counting;

        impl Progress for Counting {
            fn report(&self, _event: Event) {}
        }

        let token = std::sync::Arc::new(CancelToken::new());
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let worker_token = std::sync::Arc::clone(&token);
        let handle = std::thread::spawn(move || {
            let control = Control {
                progress: &Counting,
                cancel: Some(&worker_token),
            };
            // Report once, then tell the main thread it may cancel: asserting
            // on a report count that depends on thread scheduling would be a
            // race, not a test.
            control.stage(Stage::Solve);
            started_tx.send(()).expect("signal");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while control.check().is_ok() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "worker never observed the cancellation"
                );
                std::hint::spin_loop();
            }
            // Polling must keep reporting the same verdict once set.
            assert!(control.is_cancelled());
        });

        started_rx.recv().expect("worker started");
        token.cancel();
        handle.join().expect("worker");
    }

    #[test]
    fn task_control_borrows_and_cancels() {
        let task_ctrl = TaskControl::new(Recorder::default());
        let ctrl = task_ctrl.borrow_control();
        assert!(!ctrl.is_cancelled());
        assert!(ctrl.check().is_ok());

        task_ctrl.cancel.cancel();
        assert!(ctrl.is_cancelled());
        assert!(matches!(ctrl.check(), Err(StrHideError::Cancelled)));
    }
}
