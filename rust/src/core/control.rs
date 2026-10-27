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
}
