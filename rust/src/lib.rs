//! strhide: Smart format-preserving lossless data hiding package.
//!
//! Hide text or files inside ordinary host files (PNG, JPEG, MP4, ZIP, PDF,
//! Windows PE, or any file) without changing the host's visible format, and
//! restore the original host bit-for-bit afterwards. Fully cross-compatible
//! with the Python implementation.
//!
//! Typical usage (via the CLI):
//!
//! ```text
//! strhide write carrier.png --data-text "hello" --password pw
//! strhide read carrier.png --output out.txt --password pw
//! strhide inspect carrier.png --password pw
//! ```
//!
//! Library users can call [`engine`](crate::engine) functions directly;
//! all functions return a result type and return [`StrHideError`](crate::errors)
//! subclasses of errors on failure. See [`engine`](crate::engine) for the full
//! keyword reference of each function.

pub mod adapters;
pub mod analysis;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod engine;
pub mod envelope;
pub mod errors;
pub mod rejection;
pub mod router;
