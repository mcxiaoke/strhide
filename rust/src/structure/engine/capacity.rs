//! Payload-size policy shared by the writer and the capacity report.
//!
//! Both the reader and every advertised strategy capacity are bounded by the
//! same host-relative limit, so a report can never promise more than the
//! writer accepts.

use crate::structure::adapters::{StrategyCapacity, format_bytes};

/// Upper bound on the payload a carrier of `carrier_len` bytes may declare.
///
/// `MAX_VERIFY_PAYLOAD_SIZE` (1 GiB) used to be the only check, and it ran *after*
/// the whole ciphertext had been decrypted into memory. A small carrier holding
/// a high-ratio compressed stream could therefore make the reader allocate up to
/// 1 GiB before rejecting anything. Scale the limit with the physical carrier
/// size instead, keep a 64 MiB floor for legitimate payloads in small carriers,
/// and keep the absolute cap as the ceiling.
pub(super) fn structure_payload_limit(carrier_len: u64) -> u64 {
    const FLOOR: u64 = 64 * 1024 * 1024;
    carrier_len
        .saturating_mul(256)
        .clamp(FLOOR, crate::crypto::MAX_VERIFY_PAYLOAD_SIZE)
}

/// Clamp every advertised strategy capacity to the payload limit the engine
/// actually enforces for a host of `host_len` bytes.
///
/// A strategy whose native ceiling is lower than the engine limit keeps its
/// own value and text; an unbounded (`None`, "file grows") or higher ceiling
/// is rewritten to the effective limit so the report is the number the writer
/// accepts, not the theoretical container maximum.
pub(super) fn apply_engine_payload_limit(strategies: &mut [StrategyCapacity], host_len: u64) {
    let engine_limit = structure_payload_limit(host_len);
    for cap in strategies.iter_mut() {
        // An unavailable strategy has no writable capacity at all; filling in
        // the engine limit here would advertise a number the writer refuses.
        if !cap.available {
            continue;
        }
        let exceeds = match cap.capacity_bytes {
            Some(native) => native > engine_limit,
            None => true,
        };
        if exceeds {
            cap.capacity_bytes = Some(engine_limit);
            cap.limit = format!(
                "<= {} B (engine payload limit for this host)",
                format_bytes(engine_limit)
            );
        }
    }
}
