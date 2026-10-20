//! Format sniffing and strategy routing.
//!
//! This module is the bridge between a raw file and the [`crate::adapters`]
//! trait: given an open stream, [`find_adapter`] walks the supported formats
//! in priority order and returns the adapter whose `detect` accepts it. It
//! also converts between the human-readable strategy names (`"chunk"`,
//! `"pe_codebits"`, ...) and the single-byte `strategy_id` stored in the
//! envelope header.

use crate::adapters::{
    HostAdapter, SeekRead, heif::HeifAdapter, jpeg::JpegAdapter, mkv::MkvAdapter, mp4::Mp4Adapter,
    pdf::PdfAdapter, pe::PeAdapter, png::PngAdapter, wav::WavAdapter, webp::WebpAdapter,
    zip::ZipAdapter,
};
use crate::errors::StrHideError;

/// Formats strhide explicitly recognizes as carriers.
///
/// `EofAdapter` is deliberately NOT in this list: it remains the strategy
/// provider that carriers delegate their `eof` strategy to,
/// but it is no longer a format catch-all. Unrecognized files are rejected
/// instead of being silently appended to, because appending an envelope to
/// an arbitrary file can corrupt it (trailing checksums, embedded offsets,
/// signed containers, ...).
pub static ADAPTERS: &[&dyn HostAdapter] = &[
    &PngAdapter,
    &JpegAdapter,
    &WebpAdapter,
    &HeifAdapter,
    &Mp4Adapter,
    &WavAdapter,
    &ZipAdapter,
    &PdfAdapter,
    &PeAdapter,
    &MkvAdapter,
];

/// Detects the carrier format, or `None` when the stream is not a supported
/// format. Each adapter's `detect` restores the stream position.
pub fn find_adapter(reader: &mut dyn SeekRead) -> Option<&'static dyn HostAdapter> {
    for adapter in ADAPTERS {
        if adapter.detect(reader) {
            return Some(*adapter);
        }
    }
    None
}

/// Like [`find_adapter`], but produces a user-facing rejection error for
/// unrecognized files. `carrier_display` is used in the message only.
pub fn find_adapter_or_reject(
    reader: &mut dyn SeekRead,
    carrier_display: &str,
) -> Result<&'static dyn HostAdapter, StrHideError> {
    if let Some(adapter) = find_adapter(reader) {
        return Ok(adapter);
    }
    // Best-effort magic hint: the first bytes make "why was my file rejected?"
    // answerable without a hex editor.
    let start = reader.stream_position().unwrap_or(0);
    let mut magic = [0u8; 4];
    let hint = if reader.seek(std::io::SeekFrom::Start(0)).is_ok()
        && reader.read_exact(&mut magic).is_ok()
    {
        format!(
            " (file starts with {})",
            magic
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        )
    } else {
        String::new()
    };
    let _ = reader.seek(std::io::SeekFrom::Start(start));
    let supported = ADAPTERS
        .iter()
        .map(|a| a.format_name())
        .collect::<Vec<_>>()
        .join(", ");
    Err(StrHideError::UnsupportedFormat(format!(
        "'{carrier_display}' is not a supported carrier format{hint}. Supported formats: \
         {supported}. strhide only modifies explicitly supported formats and refuses to \
         alter unrecognized files."
    )))
}

/// Single source of truth for strategy names and their on-wire numeric IDs.
pub static STRATEGY_REGISTRY: &[(&str, u8)] = &[
    ("eof", 1),
    ("chunk", 2),
    ("box_uuid", 3),
    ("pre_cd_inject", 4),
    ("app_segment", 5),
    ("incremental", 6),
    ("pe_overlay", 7),
    ("pe_codebits", 8),
    ("pe_slack", 9),
    ("riff_chunk", 10),
    ("ebml_void", 11),
];

/// Map a strategy name to the on-wire `strategy_id` byte stored in the
/// envelope header.
pub fn strategy_to_id(strategy: &str) -> Result<u8, StrHideError> {
    for &(name, id) in STRATEGY_REGISTRY {
        if name == strategy {
            return Ok(id);
        }
    }
    Err(StrHideError::General(format!(
        "Strategy '{strategy}' is not registered in STRATEGY_REGISTRY"
    )))
}

/// Inverse of [`strategy_to_id`]: map a `strategy_id` byte back to its name.
/// Unregistered IDs return `"unknown"`.
pub fn id_to_strategy(id: u8) -> &'static str {
    for &(name, reg_id) in STRATEGY_REGISTRY {
        if reg_id == id {
            return name;
        }
    }
    "unknown"
}
