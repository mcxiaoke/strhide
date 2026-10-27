//! Compatibility re-exports for the carrier-sniffing helpers.
//!
//! The implementation moved to [`crate::formats::sniff`] when the three
//! duplicated sniffers were merged; this module keeps the historical
//! `strhide::sniff::*` paths working for downstream code and for the adapters
//! that `pub use` these names.

pub use crate::formats::sniff::{
    HEIF_BRANDS, JPEG_MAGIC, PDF_MAGIC, PNG_MAGIC, ZIP_EOCD_MAGIC, ZIP_LOCAL_MAGIC, ZIP_SPAN_MAGIC,
    is_heif_bytes, is_jpeg_bytes, is_mp4_bytes, is_png_bytes,
};
