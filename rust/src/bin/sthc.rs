// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Domain-specific entry point: container / structure domain
//! (`write`, `read`, `restore`). Logic lives in the shared `strhide` lib crate.

use std::ffi::OsString;

use strhide::cli::{Domain, run_domain_cli};

fn main() {
    let argv: Vec<OsString> = std::env::args_os().collect();
    std::process::exit(run_domain_cli(Domain::Structure, argv));
}
