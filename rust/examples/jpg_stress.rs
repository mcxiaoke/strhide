// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! JPEG stress harness: embed at every fill level, extract, and prove a wrong
//! password cannot read the payload. The shared loop lives in
//! `common::stress`; this file only describes JPEG carriers and tuning.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use strhide::errors::StrHideError;
use strhide::formats::FileFormat;
use strhide::formats::sniff::sniff_bytes;
use strhide::stego::{Freshness, JpegAlgorithm, JpegParams, StegoTuning};

#[path = "common/mod.rs"]
mod common;

use common::stress::{self, StressCase};

const PASSWORD_PREFIX: &str = "jpg-stress";
const FIXED_PASSWORD: &str = "jpg-stress-fixed-password-2026";

struct JpegStress;

impl StressCase for JpegStress {
    type Algorithm = JpegAlgorithm;

    fn name(&self) -> &'static str {
        "jpg_stress"
    }

    fn password_prefix(&self) -> &'static str {
        PASSWORD_PREFIX
    }

    fn fixed_password(&self) -> &'static str {
        FIXED_PASSWORD
    }

    fn default_algorithms(&self) -> Vec<JpegAlgorithm> {
        vec![
            JpegAlgorithm::Uerd,
            JpegAlgorithm::Juniward,
            JpegAlgorithm::Jmipod,
        ]
    }

    fn parse_algorithms(&self, names: &[String]) -> Option<Vec<JpegAlgorithm>> {
        let algorithms: Vec<_> = names
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .filter(|name| name != "all")
            .filter_map(|name| JpegAlgorithm::from_name(&name))
            .collect();
        (!algorithms.is_empty()).then_some(algorithms)
    }

    fn algorithm_id(&self, algorithm: &JpegAlgorithm) -> &'static str {
        algorithm.id()
    }

    fn collect(&self, path: Option<&Path>) -> Result<Vec<PathBuf>, String> {
        let dir = match path {
            Some(path) => path.to_path_buf(),
            None => stress::first_existing(&[
                "testdata/jpg",
                "../testdata/jpg",
                "C:/Home/Projects/strhide/testdata/jpg",
                "temp/testjpg",
                "../temp/testjpg",
            ]),
        };
        stress::collect_by_ext(&dir, &["jpg", "jpeg"], Some("jpg"))
    }

    fn probe(&self, cover: &[u8], algorithm: &JpegAlgorithm) -> Result<usize, StrHideError> {
        stress::probe_with_tuning(
            cover,
            StegoTuning::Jpeg {
                model: algorithm.clone(),
                params: JpegParams::default(),
            },
        )
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        password: &str,
        freshness: Freshness,
        algorithm: &JpegAlgorithm,
    ) -> Result<Vec<u8>, StrHideError> {
        stress::embed_with_tuning(
            cover,
            payload,
            password,
            freshness,
            StegoTuning::Jpeg {
                model: algorithm.clone(),
                params: JpegParams::default(),
            },
        )
    }

    fn check_stego(&self, _cover_len: usize, stego: &[u8]) -> Result<Option<FileFormat>, String> {
        if stego.is_empty() {
            return Err("stego output is empty".to_string());
        }
        match sniff_bytes(stego) {
            Some(FileFormat::Jpeg) => Ok(Some(FileFormat::Jpeg)),
            other => Err(format!(
                "format sniffer mismatch: expected JPEG, got {other:?}"
            )),
        }
    }

    fn short_width(&self) -> usize {
        46
    }
}

pub fn main() -> ExitCode {
    stress::run(&JpegStress)
}
