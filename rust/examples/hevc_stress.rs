// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! HEVC stress harness: MOV/MP4 video and HEIC/HEIF images, including a
//! decode check that proves the primary photo stream still produces a frame.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use rusty_h265::Decoder;
use strhide::errors::StrHideError;
use strhide::formats::FileFormat;
use strhide::formats::sniff::sniff_bytes;
use strhide::stego::hevc::heif_boxes::parse_heif_targets;
use strhide::stego::{Freshness, probe_carrier_capacity};

#[path = "common/mod.rs"]
mod common;

use common::stress::{self, StressCase};

const PASSWORD_PREFIX: &str = "hevc-stress";
const FIXED_PASSWORD: &str = "hevc-stress-fixed-password-2026";
const EXTENSIONS: &[&str] = &["mp4", "mov", "heic", "heif", "h265", "265"];

struct HevcStress;

impl StressCase for HevcStress {
    /// The carrier itself selects the HEVC mode, so there is no algorithm knob.
    type Algorithm = ();

    fn name(&self) -> &'static str {
        "hevc_stress"
    }

    fn password_prefix(&self) -> &'static str {
        PASSWORD_PREFIX
    }

    fn fixed_password(&self) -> &'static str {
        FIXED_PASSWORD
    }

    fn default_algorithms(&self) -> Vec<()> {
        vec![()]
    }

    fn labels_algorithm(&self) -> bool {
        false
    }

    fn seed_includes_algorithm(&self) -> bool {
        false
    }

    fn collect(&self, path: Option<&Path>) -> Result<Vec<PathBuf>, String> {
        match path {
            Some(path) if path.is_file() => Ok(vec![path.to_path_buf()]),
            Some(path) => stress::collect_by_ext(path, EXTENSIONS, Some("hevc")),
            None => Ok(default_carriers()),
        }
    }

    fn probe(&self, cover: &[u8], _algorithm: &()) -> Result<usize, StrHideError> {
        let info = probe_carrier_capacity(cover, &stress::probe_options())?;
        Ok(if matches!(sniff_bytes(cover), Some(FileFormat::Mp4)) {
            info.recommended_max_bytes
        } else {
            info.max_raw_payload_bytes
        })
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        password: &str,
        freshness: Freshness,
        _algorithm: &(),
    ) -> Result<Vec<u8>, StrHideError> {
        stress::embed_plain(cover, payload, password, freshness)
    }

    fn check_stego(&self, cover_len: usize, stego: &[u8]) -> Result<Option<FileFormat>, String> {
        if stego.len() != cover_len {
            return Err(format!("length changed: {cover_len} -> {}", stego.len()));
        }
        match sniff_bytes(stego) {
            Some(format @ (FileFormat::Mp4 | FileFormat::Heif | FileFormat::HevcAnnexB)) => {
                Ok(Some(format))
            }
            other => Err(format!(
                "format sniffer mismatch: expected MP4/HEIF/HEVC, got {other:?}"
            )),
        }
    }

    fn post_extract(&self, sniffed: Option<FileFormat>, stego: &[u8]) -> Result<(), String> {
        if sniffed == Some(FileFormat::Heif) && !frame_decodes_heif(stego) {
            return Err("HEIF frame no longer decodes after embedding".to_string());
        }
        Ok(())
    }
}

pub fn main() -> ExitCode {
    stress::run(&HevcStress)
}

fn default_carriers() -> Vec<PathBuf> {
    let base_candidates = [
        Path::new("testdata"),
        Path::new("../testdata"),
        Path::new("C:/Home/Projects/strhide/testdata"),
    ];
    let mut out = Vec::new();
    for base in base_candidates {
        if !base.exists() {
            continue;
        }
        for subdir in ["hevc", "heic"] {
            let dir = base.join(subdir);
            if dir.exists()
                && let Ok(mut files) = stress::collect_by_ext(&dir, EXTENSIONS, None)
            {
                out.append(&mut files);
            }
        }
        if !out.is_empty() {
            break;
        }
    }
    if out.is_empty() {
        for fallback in [Path::new("temp/testhevc"), Path::new("../temp/testhevc")] {
            if fallback.exists() {
                if let Ok(mut files) = stress::collect_by_ext(fallback, EXTENSIONS, None) {
                    out.append(&mut files);
                }
                if !out.is_empty() {
                    break;
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Check if a HEIF image can still be decoded into a valid frame by rusty_h265.
fn frame_decodes_heif(carrier: &[u8]) -> bool {
    let Ok(target) = parse_heif_targets(carrier) else {
        return false;
    };
    let mut decoder = Decoder::new();
    for parameter_set in &target.parameter_sets {
        let _ = decoder.push_nal(parameter_set, None);
    }
    for span in &target.slice_spans {
        let _ = decoder.push_nal(&carrier[span.start..span.end()], None);
    }
    decoder.flush();
    decoder
        .next_frame()
        .is_ok_and(|frame| frame.width > 0 && frame.height > 0)
}
