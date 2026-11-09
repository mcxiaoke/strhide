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

#[doc(hidden)]
pub mod args;
#[doc(hidden)]
pub mod cmd_diag;
#[doc(hidden)]
pub mod cmd_stego;
#[doc(hidden)]
pub mod cmd_structure;
#[doc(hidden)]
pub mod helpers;
#[doc(hidden)]
pub mod logging;
#[doc(hidden)]
pub mod render;

// The historical flat paths (`strhide::cli::Cli`, `strhide::cli::run_cli`)
// keep working: the split into submodules is an internal reorganisation.
#[doc(hidden)]
pub use args::{
    Cli, Commands, ContainerCommands, DiagCli, DiagCommands, GlobalArgs, STRHIDE_BUILD_TIME,
    STRHIDE_GIT_HASH, STRHIDE_VERSION_INFO, StegoCli, StegoCommands, StructCli,
};
pub use helpers::resolve_password;
use render::print_error;

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::OnceLock;

use clap::{CommandFactory, FromArgMatches};

/// Program name taken from `argv[0]`, so `--version`, usage lines and the JSON
/// banner match the binary the user actually ran (`strhide.exe` vs `sth.exe`).
///
/// Set once per process by [`run_domain_cli_with`]. In-process callers that pass
/// a synthetic argv keep whatever they set; with nothing set it falls back to
/// `sth`, the historical short name.
static PROGRAM: OnceLock<String> = OnceLock::new();

pub(crate) fn set_program_name(name: &str) {
    let _ = PROGRAM.set(name.to_owned());
}

pub(crate) fn program_name() -> &'static str {
    PROGRAM.get().map(String::as_str).unwrap_or("sth")
}

/// `"<program> <version> (commit: …, built: …)"`.
pub(crate) fn banner() -> String {
    format!("{} {}", program_name(), env!("STRHIDE_VERSION_INFO"))
}

/// Which command tree a binary exposes.
///
/// The full entry point keeps all ten verbs; the three domain entry points
/// expose only their own group. All four share the same handlers: a domain's
/// parsed command is converted back into the full [`Commands`] enum before
/// dispatch, so there is exactly one implementation of each verb.
///
/// Named `CliDomain`, not `Domain`, because it appears in the public
/// [`StrHide::run_domain_cli_from`](crate::StrHide::run_domain_cli_from)
/// signature next to [`crate::facade::Domain`]. Two different enums called
/// `Domain` on one page — one `Structure`/`Content`, the other
/// `All`/`Structure`/`Stego`/`Diagnostics` — is a trap for anyone reading the
/// docs or trusting IDE completion; the qualifier says which question each one
/// answers.
///
/// `#[non_exhaustive]` so a fifth binary (say, a content-only `sthg`) can be
/// added without a breaking change.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CliDomain {
    /// `sth` — all ten subcommands.
    All,
    /// `sthc` — `write`, `read`, `restore`.
    Structure,
    /// `sths` — `embed`, `extract`, `capacity`.
    Stego,
    /// `sthv` — `inspect`, `verify`, `scan`, `list`.
    Diagnostics,
}

impl CliDomain {
    /// Program name used in help, version and error output.
    pub fn name(self) -> &'static str {
        match self {
            CliDomain::All => "sth",
            CliDomain::Structure => "sthc",
            CliDomain::Stego => "sths",
            CliDomain::Diagnostics => "sthv",
        }
    }

    /// Fresh clap `Command` for this entry point (clap consumes it on parse).
    fn command(self) -> clap::Command {
        match self {
            CliDomain::All => Cli::command(),
            CliDomain::Structure => StructCli::command(),
            CliDomain::Stego => StegoCli::command(),
            CliDomain::Diagnostics => DiagCli::command(),
        }
    }

    /// `command()` with the runtime program name applied to help/version output.
    fn command_for(self, program: &'static str) -> clap::Command {
        self.command().name(program).bin_name(program)
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
        "write", "w", "read", "r", "restore", "s", "inspect", "verify", "scan", "embed", "e",
        "extract", "x", "capacity", "c", "list", "l",
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

fn render_early_error(e: clap::Error, argv: &[std::ffi::OsString], domain: CliDomain) -> i32 {
    use clap::error::ErrorKind::*;
    let lang = i18n::locale::detect(scan_lang_flag(argv), None);
    i18n::set_lang(lang);

    match e.kind() {
        DisplayHelp | DisplayHelpOnMissingArgumentOrSubcommand | MissingSubcommand => {
            let mut cmd = crate::cli_i18n::localize(domain.command_for(program_name()), lang);
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
            println!("{}", banner());
            0
        }
        _ => {
            let mut cmd = crate::cli_i18n::localize(domain.command_for(program_name()), lang);
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
pub fn run_domain_cli(domain: CliDomain, argv: Vec<OsString>) -> i32 {
    StrHide::new().run_domain_cli_from(domain, argv)
}

pub(crate) fn run_domain_cli_with(engine: &StrHide, domain: CliDomain, argv: Vec<OsString>) -> i32 {
    // 0) Program name from argv[0]. Five binaries share this dispatcher, so the
    //    compile-time `name = "sth"` in the clap derive would otherwise make
    //    `strhide --version` print `sth 0.9.3`.
    if let Some(name) = argv
        .first()
        .map(std::path::Path::new)
        .and_then(|path| path.file_stem())
        .and_then(|stem| stem.to_str())
    {
        set_program_name(name);
    }

    // 1) 预解析（英文模板，仅用于取得 matches；不触发任何输出）
    let pre = match domain
        .command_for(program_name())
        .try_get_matches_from(argv.clone())
    {
        Ok(m) => m,
        Err(e) => return render_early_error(e, &argv, domain),
    };

    // 1b) 装日志。库里的 log::warn!/debug! 在此之前没有任何出口，等于空操作；
    //     这里按 -q / -v 定级，写 stderr，不污染 --json / --stdout。
    logging::install(pre.get_flag("quiet"), pre.get_count("verbose"));

    // 1c) 线程池（CLI 专属的 opt-in：库入口不锁宿主进程的全局 Rayon 池）
    #[cfg(feature = "content-base")]
    crate::stego::init_default_thread_pool();

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

    // `-q` means "no output unless an operation fails"; config warnings are
    // informational, so they must respect it like every other non-error line.
    if !pre.get_flag("quiet") {
        for warn in &cfg.warnings {
            eprintln!("{warn}");
        }
    }

    // 4) 从 matches 构造本入口的 Cli，并归一化为全量 Commands + quiet。
    //    之后所有分派复用同一份实现，域入口不复制任何行为。
    let (command, quiet): (Commands, bool) = match domain {
        CliDomain::All => match Cli::from_arg_matches(&pre) {
            Ok(c) => (c.command, c.global.quiet),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                return 2;
            }
        },
        CliDomain::Structure => match StructCli::from_arg_matches(&pre) {
            Ok(c) => (c.command.into(), c.global.quiet),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                return 2;
            }
        },
        CliDomain::Stego => match StegoCli::from_arg_matches(&pre) {
            Ok(c) => (c.command.into(), c.global.quiet),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                return 2;
            }
        },
        CliDomain::Diagnostics => match DiagCli::from_arg_matches(&pre) {
            Ok(c) => (c.command.into(), c.global.quiet),
            Err(e) => {
                eprintln!("[ERROR] {e}");
                return 2;
            }
        },
    };

    if should_print_banner(quiet, &command) {
        println!("{}", banner());
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
        Commands::Read(args) => match handle_read(args, &cfg, quiet, engine, None) {
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
            Ok(code) => code,
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
        Commands::Extract(args) => match handle_extract(args, &cfg, quiet, engine, None) {
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
