// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Command line: argument binding, dispatch, and rendering.
//!
//! - [`args`] — the clap grammar;
//! - [`helpers`] — password / payload / tuning resolution;
//! - [`render`] — result and error text;
//! - [`cmd_structure`] / [`cmd_stego`] / [`cmd_diag`] — one handler group per
//!   domain;
//! - this file — pre-parse (language detection, config loading) and dispatch.
//!
//! Configuration semantics live in [`crate::core::config`], batch orchestration
//! in [`crate::core::pipeline`], and the message catalogue in
//! [`crate::core::i18n`] — all reusable without the `cli` feature.

pub mod args;
pub mod cmd_diag;
pub mod cmd_stego;
pub mod cmd_structure;
pub mod helpers;
pub mod render;

// The historical flat paths (`strhide::cli::Cli`, `strhide::cli::run_cli`)
// keep working: the split into submodules is an internal reorganisation.
pub use args::{
    BANNER, Cli, Commands, ContainerCommands, DiagCli, DiagCommands, GlobalArgs,
    STRHIDE_BUILD_TIME, STRHIDE_GIT_HASH, STRHIDE_VERSION_INFO, StegoCli, StegoCommands, StructCli,
};
pub use helpers::{prompt_password, resolve_password};
pub use render::print_error;

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches};

/// Which command tree a binary exposes.
///
/// The full entry point keeps all ten verbs; the three domain entry points
/// expose only their own group. All four share the same handlers: a domain's
/// parsed command is converted back into the full [`Commands`] enum before
/// dispatch, so there is exactly one implementation of each verb.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Domain {
    /// `sth` — all ten subcommands.
    All,
    /// `sthc` — `write`, `read`, `restore`.
    Structure,
    /// `sths` — `embed`, `extract`, `capacity`.
    Stego,
    /// `sthv` — `inspect`, `verify`, `scan`, `list`.
    Diagnostics,
}

impl Domain {
    /// Program name used in help, version and error output.
    pub fn name(self) -> &'static str {
        match self {
            Domain::All => "sth",
            Domain::Structure => "sthc",
            Domain::Stego => "sths",
            Domain::Diagnostics => "sthv",
        }
    }

    /// Fresh clap `Command` for this entry point (clap consumes it on parse).
    fn command(self) -> clap::Command {
        match self {
            Domain::All => Cli::command(),
            Domain::Structure => StructCli::command(),
            Domain::Stego => StegoCli::command(),
            Domain::Diagnostics => DiagCli::command(),
        }
    }

    /// Banner line (`--version` and normal status output).
    fn banner(self) -> String {
        format!("{} {}", self.name(), env!("STRHIDE_VERSION_INFO"))
    }
}

use crate::core::config;
use crate::core::i18n;
use crate::facade::StrHide;

use crate::cli::cmd_diag::{handle_inspect, handle_list, handle_scan, handle_verify};
use crate::cli::cmd_stego::{handle_capacity, handle_embed, handle_extract};
use crate::cli::cmd_structure::{handle_read, handle_restore, handle_write};

fn should_print_banner(quiet: bool, command: &Commands) -> bool {
    if quiet {
        return false;
    }
    match command {
        Commands::Inspect(args) if args.json => false,
        Commands::Verify(args) if args.json => false,
        Commands::Scan(args) if args.json => false,
        Commands::List(args) if args.json => false,
        Commands::Read(args) if args.stdout || args.output.is_none() => false,
        Commands::Extract(args) if args.stdout || args.output.is_none() => false,
        Commands::Capacity(args) if args.json => false,
        _ => true,
    }
}

fn scan_lang_flag(argv: &[std::ffi::OsString]) -> Option<&str> {
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        let Some(s) = arg.to_str() else { continue };
        if s == "--" {
            break;
        }
        if s == "--lang" {
            if let Some(val) = iter.next() {
                return val.to_str();
            }
        } else if let Some(val) = s.strip_prefix("--lang=") {
            return Some(val);
        }
    }
    None
}

fn scan_subcommand(argv: &[std::ffi::OsString]) -> Option<&str> {
    const SUBCOMMANDS: &[&str] = &[
        "write", "read", "restore", "inspect", "verify", "scan", "embed", "extract", "list",
    ];
    let mut skip_next = false;
    for arg in argv.iter().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        let Some(s) = arg.to_str() else { continue };
        if s == "--" {
            break;
        }
        if s == "-c" || s == "--config" || s == "--lang" {
            skip_next = true;
            continue;
        }
        if s.starts_with('-') {
            continue;
        }
        if SUBCOMMANDS.contains(&s) {
            return Some(s);
        }
    }
    None
}

fn render_early_error(e: clap::Error, argv: &[std::ffi::OsString], domain: Domain) -> i32 {
    use clap::error::ErrorKind::*;
    let lang = i18n::locale::detect(scan_lang_flag(argv), None);
    i18n::set_lang(lang);

    match e.kind() {
        DisplayHelp | DisplayHelpOnMissingArgumentOrSubcommand | MissingSubcommand => {
            let mut cmd = crate::cli_i18n::localize(domain.command(), lang);
            if let Some(target) = scan_subcommand(argv)
                && let Some(sub) = cmd.find_subcommand_mut(target)
            {
                let _ = sub.print_help();
                println!();
                return e.exit_code();
            }
            let _ = cmd.print_help();
            println!();
            e.exit_code()
        }
        DisplayVersion => {
            println!("{}", domain.banner());
            0
        }
        _ => {
            let mut cmd = crate::cli_i18n::localize(domain.command(), lang);
            if let Err(loc_err) = cmd.try_get_matches_from_mut(argv.to_vec()) {
                let _ = loc_err.print();
                loc_err.exit_code()
            } else {
                let _ = e.print();
                e.exit_code()
            }
        }
    }
}

pub fn run_cli() -> i32 {
    StrHide::new().run_cli_from(std::env::args_os())
}

/// Entry point for a domain-specific binary (`src/bin/strhide-*.rs`).
///
/// `argv` must include the program name as its first element, exactly as
/// [`std::env::args_os`] returns it.
pub fn run_domain_cli(domain: Domain, argv: Vec<OsString>) -> i32 {
    StrHide::new().run_domain_cli_from(domain, argv)
}

pub(crate) fn run_domain_cli_with(engine: &StrHide, domain: Domain, argv: Vec<OsString>) -> i32 {
    #[cfg(feature = "content-base")]
    crate::stego::init_default_thread_pool();

    // 1) 预解析（英文模板，仅用于取得 matches；不触发任何输出）
    let pre = match domain.command().try_get_matches_from(argv.clone()) {
        Ok(m) => m,
        Err(e) => return render_early_error(e, &argv, domain),
    };

    // 2) 加载配置（失败也要按最终语言报错）
    let cfg_path = pre.get_one::<PathBuf>("config");
    let cfg = match config::load(cfg_path.map(|p| p.as_ref())) {
        Ok(c) => c,
        Err(e) => {
            let lang =
                i18n::locale::detect(pre.get_one::<String>("lang").map(String::as_str), None);
            i18n::set_lang(lang);
            print_error(&e);
            return 1;
        }
    };

    // 3) 确定语言并全局生效
    let lang = i18n::locale::detect(
        pre.get_one::<String>("lang").map(String::as_str),
        cfg.lang.as_deref(),
    );
    i18n::set_lang(lang);

    for warn in &cfg.warnings {
        eprintln!("{warn}");
    }

    // 4) 从 matches 构造本入口的 Cli，并归一化为全量 Commands + quiet。
    //    之后所有分派复用同一份实现，域入口不复制任何行为。
    let (command, quiet): (Commands, bool) = match domain {
        Domain::All => match Cli::from_arg_matches(&pre) {
            Ok(c) => (c.command, c.global.quiet),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                return 2;
            }
        },
        Domain::Structure => match StructCli::from_arg_matches(&pre) {
            Ok(c) => (c.command.into(), c.global.quiet),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                return 2;
            }
        },
        Domain::Stego => match StegoCli::from_arg_matches(&pre) {
            Ok(c) => (c.command.into(), c.global.quiet),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                return 2;
            }
        },
        Domain::Diagnostics => match DiagCli::from_arg_matches(&pre) {
            Ok(c) => (c.command.into(), c.global.quiet),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                return 2;
            }
        },
    };

    if should_print_banner(quiet, &command) {
        println!("{}", domain.banner());
        if let Some(path) = &cfg.loaded_from {
            println!("Loaded config: {}", path.display());
        }
    }

    match command {
        Commands::Write(args) => match handle_write(args, &cfg, quiet, engine) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Read(args) => match handle_read(args, &cfg, quiet, engine) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Restore(args) => match handle_restore(args, &cfg, quiet, engine) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Inspect(args) => match handle_inspect(args, &cfg, quiet, engine) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Verify(args) => match handle_verify(args, &cfg, quiet, engine) {
            Ok(code) => code,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        // Like verify, scan owns its exit code: 1 when a scan verdict reaches
        // "likely-hidden" (see handle_scan), 0 otherwise, regardless of quiet.
        Commands::Scan(args) => match handle_scan(args, quiet) {
            Ok(code) => code,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Embed(args) => match handle_embed(args, &cfg, quiet, engine) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Capacity(args) => match handle_capacity(args, &cfg, quiet, engine) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Extract(args) => match handle_extract(args, &cfg, quiet, engine) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        // `list` prints a data table, not status lines, so quiet does not
        // apply; the global flag is accepted but ignored here.
        Commands::List(args) => match handle_list(args) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
    }
}
