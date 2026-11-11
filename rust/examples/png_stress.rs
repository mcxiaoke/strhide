// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! PNG stress harness. At 100% fill it leaves a small margin because the PNG
//! writer's own admission needs headroom for the slot table; the rest of the
//! loop is the shared `common::stress` harness.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use strhide::errors::StrHideError;
use strhide::formats::FileFormat;
use strhide::formats::sniff::sniff_bytes;
use strhide::stego::{Freshness, PngParams, SpatialAlgorithm, StegoTuning};

#[path = "common/mod.rs"]
mod common;

use common::stress::{self, StressCase};

const PASSWORD_PREFIX: &str = "png-stress";
const FIXED_PASSWORD: &str = "png-stress-fixed-password-2026";

struct PngStress;

impl StressCase for PngStress {
    type Algorithm = SpatialAlgorithm;

    fn name(&self) -> &'static str {
        "png_stress"
    }

    fn password_prefix(&self) -> &'static str {
        PASSWORD_PREFIX
    }

    fn fixed_password(&self) -> &'static str {
        FIXED_PASSWORD
    }

    fn default_algorithms(&self) -> Vec<SpatialAlgorithm> {
        vec![
            SpatialAlgorithm::Hill,
            SpatialAlgorithm::Suniward,
            SpatialAlgorithm::Mipod,
        ]
    }

    fn parse_algorithms(&self, names: &[String]) -> Option<Vec<SpatialAlgorithm>> {
        let algorithms: Vec<_> = names
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .filter(|name| name != "all")
            .filter_map(|name| SpatialAlgorithm::from_name(&name))
            .collect();
        (!algorithms.is_empty()).then_some(algorithms)
    }

    fn algorithm_id(&self, algorithm: &SpatialAlgorithm) -> &'static str {
        algorithm.id()
    }

    fn collect(&self, path: Option<&Path>) -> Result<Vec<PathBuf>, String> {
        let dir = match path {
            Some(path) => path.to_path_buf(),
            None => stress::first_existing(&[
                "testdata/png",
                "../testdata/png",
                "C:/Home/Projects/strhide/testdata/png",
                "temp/testpng",
                "../temp/testpng",
            ]),
        };
        stress::collect_by_ext(&dir, &["png"], Some("png"))
    }

    fn probe(&self, cover: &[u8], algorithm: &SpatialAlgorithm) -> Result<usize, StrHideError> {
        stress::probe_with_tuning(
            cover,
            StegoTuning::Png {
                model: algorithm.clone(),
                params: PngParams::default(),
            },
        )
    }

    fn bytes_for_fill(&self, capacity: usize, fill: f64) -> usize {
        if fill >= 1.0 {
            capacity.saturating_sub(64).max(1)
        } else {
            ((capacity as f64) * fill).round() as usize
        }
    }

    fn embed(
        &self,
        cover: &[u8],
        payload: &[u8],
        password: &str,
        freshness: Freshness,
        algorithm: &SpatialAlgorithm,
    ) -> Result<Vec<u8>, StrHideError> {
        stress::embed_with_tuning(
            cover,
            payload,
            password,
            freshness,
            StegoTuning::Png {
                model: algorithm.clone(),
                params: PngParams::default(),
            },
        )
    }

    fn check_stego(&self, _cover_len: usize, stego: &[u8]) -> Result<Option<FileFormat>, String> {
        if stego.is_empty() {
            return Err("stego output is empty".to_string());
        }
        match sniff_bytes(stego) {
            Some(FileFormat::Png) => Ok(Some(FileFormat::Png)),
            other => Err(format!(
                "format sniffer mismatch: expected PNG, got {other:?}"
            )),
        }
    }

    fn short_width(&self) -> usize {
        46
    }
}

pub fn main() -> ExitCode {
    stress::run(&PngStress)
}
