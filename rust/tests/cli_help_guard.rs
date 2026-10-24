// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Guard: after localization, every CLI argument carries non-empty help text
//! in both languages.
//!
//! The stego-scope arguments get their help exclusively from the i18n message
//! table (the inline clap strings were removed), so a message entry that goes
//! missing would otherwise show up as a blank column in `--help` — silent at
//! compile time, visible only to users. This walks the whole command tree and
//! fails on the first empty help.

use clap::Command;
use clap::CommandFactory;
use strhide::cli::Cli;
use strhide::cli_i18n::localize;
use strhide::i18n::Lang;

fn walk(cmd: &Command, path: &str, failures: &mut Vec<String>) {
    let name = if path.is_empty() {
        cmd.get_name().to_string()
    } else {
        format!("{path} {}", cmd.get_name())
    };

    if cmd
        .get_about()
        .map(|t| t.to_string().is_empty())
        .unwrap_or(true)
    {
        failures.push(format!("{name}: empty about"));
    }
    for arg in cmd.get_arguments() {
        // Positional free-flags (bool switches) may omit help only if they are
        // hidden; anything visible needs text.
        if arg.is_hide_set() {
            continue;
        }
        let help = arg.get_help().or_else(|| arg.get_long_help());
        match help {
            None => failures.push(format!("{name}: argument --{} has no help", arg.get_id())),
            Some(h) if h.to_string().is_empty() => failures.push(format!(
                "{name}: argument --{} has empty help",
                arg.get_id()
            )),
            _ => {}
        }
    }
    for sub in cmd.get_subcommands() {
        walk(sub, &name, failures);
    }
}

#[test]
fn every_localized_argument_has_non_empty_help() {
    for lang in [Lang::En, Lang::Zh] {
        let cmd = localize(Cli::command(), lang);
        let mut failures = Vec::new();
        walk(&cmd, "", &mut failures);
        assert!(
            failures.is_empty(),
            "localized({lang:?}) help gaps: {failures:#?}"
        );
    }
}
