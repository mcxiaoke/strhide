use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{LevelFilter, Metadata, Record};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

pub const MAX_LOG_ENTRIES: usize = 2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntryDto {
    pub id: u64,
    pub timestamp: u64,
    pub level: String, // "DEBUG" | "INFO" | "WARN" | "ERROR" | "TRACE"
    pub target: String,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

struct LoggerState {
    buffer: Mutex<VecDeque<LogEntryDto>>,
    app_handle: RwLock<Option<AppHandle>>,
    counter: AtomicU64,
}

static LOGGER_STATE: OnceLock<LoggerState> = OnceLock::new();

fn get_state() -> &'static LoggerState {
    LOGGER_STATE.get_or_init(|| LoggerState {
        buffer: Mutex::new(VecDeque::with_capacity(MAX_LOG_ENTRIES)),
        app_handle: RwLock::new(None),
        counter: AtomicU64::new(1),
    })
}

pub struct RingBufferLogger;

impl log::Log for RingBufferLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let state = get_state();
        let id = state.counter.fetch_add(1, Ordering::Relaxed);
        let entry = LogEntryDto {
            id,
            timestamp,
            level: record.level().to_string(),
            target: record.target().to_string(),
            message: record.args().to_string(),
            data: None,
        };

        #[cfg(debug_assertions)]
        {
            eprintln!(
                "[{}] [{}] {}",
                entry.level, entry.target, entry.message
            );
        }

        {
            let mut buf = state.buffer.lock().unwrap();
            if buf.len() >= MAX_LOG_ENTRIES {
                buf.pop_front();
            }
            buf.push_back(entry.clone());
        }

        if let Ok(app_guard) = state.app_handle.read()
            && let Some(app) = app_guard.as_ref()
        {
            let _ = app.emit("app:log", &entry);
        }
    }

    fn flush(&self) {}
}

static LOGGER_INSTANCE: RingBufferLogger = RingBufferLogger;

pub fn init_logger() {
    let _ = log::set_logger(&LOGGER_INSTANCE);
    log::set_max_level(LevelFilter::Debug);
}

pub fn set_app_handle(app: AppHandle) {
    let state = get_state();
    if let Ok(mut guard) = state.app_handle.write() {
        *guard = Some(app);
    }
}

pub fn record_custom_log(
    level: &str,
    target: &str,
    message: &str,
    data: Option<serde_json::Value>,
) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let state = get_state();
    let id = state.counter.fetch_add(1, Ordering::Relaxed);
    let entry = LogEntryDto {
        id,
        timestamp,
        level: level.to_uppercase(),
        target: target.to_string(),
        message: message.to_string(),
        data,
    };

    #[cfg(debug_assertions)]
    {
        eprintln!(
            "[{}] [{}] {}",
            entry.level, entry.target, entry.message
        );
    }

    {
        let mut buf = state.buffer.lock().unwrap();
        if buf.len() >= MAX_LOG_ENTRIES {
            buf.pop_front();
        }
        buf.push_back(entry.clone());
    }

    if let Ok(app_guard) = state.app_handle.read()
        && let Some(app) = app_guard.as_ref()
    {
        let _ = app.emit("app:log", &entry);
    }
}

pub fn get_recent_logs() -> Vec<LogEntryDto> {
    let state = get_state();
    let buf = state.buffer.lock().unwrap();
    buf.iter().cloned().collect()
}

pub fn clear_logs() {
    let state = get_state();
    let mut buf = state.buffer.lock().unwrap();
    buf.clear();
}

#[tauri::command]
pub fn get_recent_logs_cmd() -> Vec<LogEntryDto> {
    get_recent_logs()
}

#[tauri::command]
pub fn clear_logs_cmd() {
    clear_logs();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_get_logs() {
        clear_logs();
        assert!(get_recent_logs().is_empty());

        record_custom_log(
            "info",
            "test::target",
            "hello world",
            Some(serde_json::json!({ "foo": "bar" })),
        );

        let logs = get_recent_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].level, "INFO");
        assert_eq!(logs[0].target, "test::target");
        assert_eq!(logs[0].message, "hello world");
        assert_eq!(
            logs[0].data.as_ref().unwrap()["foo"],
            "bar"
        );

        clear_logs();
        assert!(get_recent_logs().is_empty());
    }
}

