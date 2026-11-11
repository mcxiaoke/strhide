// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Shared utilities for strhide examples and stress test harnesses.

pub mod stress;

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use log::{Level, LevelFilter, Log, Metadata, Record};

/// Generate a UTC timestamp formatted as `YYYYMMDD_HHMMSS`.
pub fn current_datetime() -> String {
    let epoch_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let secs = epoch_secs % 60;
    let mins = (epoch_secs / 60) % 60;
    let hours = (epoch_secs / 3600) % 24;
    let days = epoch_secs / 86400;

    // Howard Hinnant algorithm for civil date from days since 1970-01-01
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}{m:02}{d:02}_{hours:02}{mins:02}{secs:02}")
}

struct DualLogger {
    file: Mutex<Option<File>>,
}

impl Log for DualLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let msg = record.args();
        if record.level() == Level::Error {
            eprintln!("{msg}");
        } else {
            println!("{msg}");
        }
        if let Ok(mut guard) = self.file.lock()
            && let Some(f) = guard.as_mut()
        {
            let _ = writeln!(f, "{msg}");
            let _ = f.flush();
        }
    }

    fn flush(&self) {
        if let Ok(mut guard) = self.file.lock()
            && let Some(f) = guard.as_mut()
        {
            let _ = f.flush();
        }
    }
}

/// Initialize the stress harness logger:
///
/// Logs are printed to console (without variable-length prefixes so tables remain aligned)
/// and simultaneously written to `<temp_dir>/strhide-logs/{name}_log_{datetime}.txt`.
pub fn init_stress_logger(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("strhide-logs");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("{name}_log_{}.txt", current_datetime()));
    let file = File::create(&path).ok();
    let logger = Box::leak(Box::new(DualLogger {
        file: Mutex::new(file),
    }));
    let _ = log::set_logger(logger);
    log::set_max_level(LevelFilter::Info);
    path
}
