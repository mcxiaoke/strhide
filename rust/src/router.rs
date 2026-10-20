//! Format sniffing and strategy routing.
//!
//! This module is the bridge between a raw file and the [`crate::adapters`]
//! trait: given an open stream, [`find_adapter`] walks the supported formats
//! in priority order and returns the adapter whose `detect` accepts it. It
//! also converts between the human-readable strategy names (`"chunk"`,
//! `"pe_codebits"`, ...) and the single-byte `strategy_id` stored in the
//! envelope header.

use crate::adapters::{
    HostAdapter, SeekRead, jpeg::JpegAdapter, mp4::Mp4Adapter, pdf::PdfAdapter, pe::PeAdapter,
    png::PngAdapter, zip::ZipAdapter,
};
use crate::errors::StrHideError;

/// Formats strhide explicitly recognizes as carriers.
///
/// `EofAdapter` is deliberately NOT in this list: it remains the strategy
/// provider that PNG/JPEG/MP4/ZIP/PDF/PE delegate their `eof` strategy to,
/// but it is no longer a format catch-all. Unrecognized files are rejected
/// instead of being silently appended to, because appending an envelope to
/// an arbitrary file can corrupt it (trailing checksums, embedded offsets,
/// signed containers, ...).
pub static ADAPTERS: &[&dyn HostAdapter] = &[
    &PngAdapter,
    &JpegAdapter,
    &Mp4Adapter,
    &ZipAdapter,
    &PdfAdapter,
    &PeAdapter,
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

/// Map a strategy name to the on-wire `strategy_id` byte stored in the
/// envelope header. Unknown names default to `1` (`"eof"`).
pub fn strategy_to_id(strategy: &str) -> u8 {
    match strategy {
        "eof" => 1,
        "chunk" => 2,
        "box_uuid" => 3,
        "pre_cd_inject" => 4,
        "app_segment" => 5,
        "incremental" => 6,
        "pe_overlay" => 7,
        "pe_codebits" => 8,
        "pe_slack" => 9,
        _ => 1,
    }
}

/// Inverse of [`strategy_to_id`]: map a `strategy_id` byte back to its name.
/// Unknown IDs map to `"eof"` for forward compatibility.
pub fn id_to_strategy(id: u8) -> &'static str {
    match id {
        1 => "eof",
        2 => "chunk",
        3 => "box_uuid",
        4 => "pre_cd_inject",
        5 => "app_segment",
        6 => "incremental",
        7 => "pe_overlay",
        8 => "pe_codebits",
        9 => "pe_slack",
        _ => "eof",
    }
}
