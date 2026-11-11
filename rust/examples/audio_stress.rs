// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Audio stress harness: WAV/FLAC sample-domain embedding. The container must
//! keep its exact length; the shared harness verifies the payload and the
//! wrong-password rejection.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use strhide::errors::StrHideError;
use strhide::formats::FileFormat;
use strhide::stego::{Freshness, probe_carrier_capacity};

#[path = "common/mod.rs"]
mod common;

use common::stress::{self, StressCase};

const PASSWORD_PREFIX: &str = "stress";
const FIXED_PASSWORD: &str = "stress-fixed-password-2026";

struct AudioStress;

impl StressCase for AudioStress {
    /// The carrier extension selects the codec; no algorithm knob is exposed.
    type Algorithm = ();

    fn name(&self) -> &'static str {
        "audio_stress"
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

    fn default_threads(&self) -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get().min(4))
            .unwrap_or(2)
    }

    fn collect(&self, path: Option<&Path>) -> Result<Vec<PathBuf>, String> {
        let dir = match path {
            Some(path) => path.to_path_buf(),
            None => stress::first_existing(&["../temp/testaudio", "temp/testaudio"]),
        };
        stress::collect_by_ext(&dir, &["wav", "flac"], None)
    }

    fn probe(&self, cover: &[u8], _algorithm: &()) -> Result<usize, StrHideError> {
        probe_carrier_capacity(cover, &stress::probe_options())
            .map(|info| info.max_raw_payload_bytes)
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
        Ok(None)
    }
}

pub fn main() -> ExitCode {
    stress::run(&AudioStress)
}
