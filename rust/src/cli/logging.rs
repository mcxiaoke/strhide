// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Console logging for the CLI binaries.
//!
//! The engines report recoverable degradations through the `log` crate, but
//! `main` never installed a logger: every `log::debug!` / `log::warn!` emitted
//! inside `rust/src` was compiled into a no-op in the CLI builds (the GUI has
//! its own ring-buffer logger, so only the desktop client ever saw them).
//!
//! This logger keeps the single-binary CLI self-contained — no new dependency —
//! and writes to stderr only, so `--json` and `--stdout` payloads stay
//! machine-readable at every verbosity.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use log::{LevelFilter, Metadata, Record};

/// Active filter, shared between [`install`] and [`StderrLogger::enabled`].
///
/// Stored as the `LevelFilter` discriminant so the logger itself can stay a
/// unit struct with a `static` instance.
static FILTER: AtomicUsize = AtomicUsize::new(LevelFilter::Warn as usize);

struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= filter()
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut err = std::io::stderr().lock();
        let _ = writeln!(
            err,
            "[{}] [{}] {}",
            record.level(),
            record.target(),
            record.args()
        );
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

static LOGGER: StderrLogger = StderrLogger;

fn filter() -> LevelFilter {
    match FILTER.load(Ordering::Relaxed) {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

/// Map `-q` / `-v` onto a filter.
///
/// `quiet` wins over `verbose`: `-q -v` stays silent, otherwise a script that
/// asked for silence would start leaking debug output into stderr.
pub(crate) fn level_for(quiet: bool, verbose: u8) -> LevelFilter {
    if quiet {
        return LevelFilter::Off;
    }
    match verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

/// Install the process-wide logger, once per CLI process.
///
/// Without `-v` the level stays at `WARN`, so "this fallback/cleanup step
/// failed" is visible on a normal run without drowning it in debug output.
///
/// Installation failure is reported instead of ignored: it only happens when a
/// host application already owns the global logger, and in that case every
/// diagnostic the engines emit is being dropped.
pub fn install(quiet: bool, verbose: u8) {
    let level = level_for(quiet, verbose);
    FILTER.store(level as usize, Ordering::Relaxed);
    if log::set_logger(&LOGGER).is_err() {
        eprintln!("[WARN] a global logger is already installed; CLI diagnostics stay disabled");
        return;
    }
    log::set_max_level(level);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quiet_overrides_verbose() {
        assert_eq!(level_for(true, 2), LevelFilter::Off);
        assert_eq!(level_for(false, 0), LevelFilter::Warn);
        assert_eq!(level_for(false, 1), LevelFilter::Debug);
        assert_eq!(level_for(false, 5), LevelFilter::Trace);
    }
}
