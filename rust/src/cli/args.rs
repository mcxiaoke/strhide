// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Command-line grammar: the clap tree and nothing else.
//!
//! Every struct maps 1:1 to a subcommand or a shared argument group
//! (`PasswordArgs`, `PayloadSourceArgs`, `StegoTuningArgs`); behaviour lives in
//! `cmd_structure` / `cmd_stego` / `cmd_diag`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

pub const STRHIDE_VERSION_INFO: &str = env!("STRHIDE_VERSION_INFO");
pub const STRHIDE_GIT_HASH: &str = env!("STRHIDE_GIT_HASH");
pub const STRHIDE_BUILD_TIME: &str = env!("STRHIDE_BUILD_TIME");
pub const BANNER: &str = concat!("sth ", env!("STRHIDE_VERSION_INFO"));

/// Global options shared by the full entry point and every domain entry point.
///
/// Declared once and flattened into each `Parser`, so `-c/-q/--lang` keep the
/// same ids and semantics everywhere instead of being copied per binary.
#[derive(Args, Debug, Clone)]
pub struct GlobalArgs {
    /// Path to TOML config file (searches <exe_dir>, user config dir, system config dir)
    #[arg(short = 'c', long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[arg(short = 'q', long = "quiet", global = true)]
    pub quiet: bool,

    #[arg(
        long = "lang",
        global = true,
        value_name = "LANG",
        value_parser = ["en", "zh"]
    )]
    pub lang: Option<String>,
}

#[derive(Parser, Debug)]
#[command(
    name = "sth",
    version = STRHIDE_VERSION_INFO,
    about = "Format-preserving lossless data hiding and steganography tool",
    after_help = ROOT_AFTER_HELP
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Commands,
}

/// Group legend for the flat `Commands:` list (see [`Commands`]).
///
/// English fallback; `cli_i18n::localize` replaces it with
/// [`Msg::AfterHelpRoot`](crate::core::i18n::Msg) in the active language.
const ROOT_AFTER_HELP: &str = "Groups:
  Container    write | read | restore            envelope inside the host file
  Media Stego  embed | extract | capacity         payload inside pixels / DCT / CABAC
  Diagnostics  inspect | verify | scan | list      read-only analysis

Run `sth <COMMAND> --help` for the options of one command.";

/// The ten verbs, ordered by group: container, media stego, diagnostics.
///
/// clap renders one flat `Commands:` section and only supports *one* custom
/// heading per list, so grouping is expressed through `display_order` plus the
/// root `after_help` that names the three groups (plan §4.3).
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Hide secret payload into carrier file
    #[command(display_order = 10, visible_alias = "w")]
    Write(WriteArgs),
    /// Read and extract hidden payload from carrier
    #[command(display_order = 11, visible_alias = "r")]
    Read(ReadArgs),
    /// 100% loss-free restoration of the original host file
    #[command(display_order = 12, visible_alias = "s")]
    Restore(RestoreArgs),

    /// Content-adaptive steganography: embed payload into image pixels or DCT coefficients (HILL/UERD)
    #[command(display_order = 20, visible_alias = "e")]
    Embed(EmbedArgs),
    /// Content-adaptive steganography: extract payload from image pixels or DCT coefficients
    #[command(display_order = 21, visible_alias = "x")]
    Extract(ExtractArgs),
    /// Probe maximum embedding capacity of image carrier(s)
    #[command(display_order = 22, visible_alias = "c")]
    Capacity(CapacityArgs),

    /// Inspect carrier structure and envelope metadata
    #[command(display_order = 30)]
    Inspect(InspectArgs),
    /// Diagnostic verification of host, envelope, and crypto
    #[command(display_order = 31)]
    Verify(VerifyArgs),
    /// Black-box steganalysis: scan file(s) for hidden content, known or unknown
    #[command(display_order = 32)]
    Scan(ScanArgs),
    /// List all supported formats, strategies, and their capacity limits
    #[command(display_order = 33, visible_alias = "l")]
    List(ListArgs),
}

// ── Domain-specific command trees ──────────────────────────────────────────
//
// Each enum reuses the very same `WriteArgs`…`ScanArgs` structs as the full
// `Commands` enum — only the variant declarations are repeated. Every domain
// enum converts back into the full `Commands` in `cli::run_domain_cli_with`,
// so all handlers, banner rules and error paths stay shared verbatim.

/// Container / structure domain: envelopes inside the host file.
#[derive(Subcommand, Debug)]
pub enum ContainerCommands {
    /// Hide secret payload into carrier file
    #[command(visible_alias = "w")]
    Write(WriteArgs),
    /// Read and extract hidden payload from carrier
    #[command(visible_alias = "r")]
    Read(ReadArgs),
    /// 100% loss-free restoration of the original host file
    #[command(visible_alias = "s")]
    Restore(RestoreArgs),
}

/// Content / media steganography domain: payload inside pixels / DCT / CABAC.
#[derive(Subcommand, Debug)]
pub enum StegoCommands {
    /// Content-adaptive steganography: embed payload into image pixels or DCT coefficients (HILL/UERD)
    #[command(visible_alias = "e")]
    Embed(EmbedArgs),
    /// Content-adaptive steganography: extract payload from image pixels or DCT coefficients
    #[command(visible_alias = "x")]
    Extract(ExtractArgs),
    /// Probe maximum embedding capacity of image carrier(s)
    #[command(visible_alias = "c")]
    Capacity(CapacityArgs),
}

/// Diagnostics domain: read-only analysis.
#[derive(Subcommand, Debug)]
pub enum DiagCommands {
    /// Inspect carrier structure and envelope metadata
    Inspect(InspectArgs),
    /// Diagnostic verification of host, envelope, and crypto
    Verify(VerifyArgs),
    /// Black-box steganalysis: scan file(s) for hidden content, known or unknown
    Scan(ScanArgs),
    /// List all supported formats, strategies, and their capacity limits
    #[command(visible_alias = "l")]
    List(ListArgs),
}

impl From<ContainerCommands> for Commands {
    fn from(c: ContainerCommands) -> Self {
        match c {
            ContainerCommands::Write(a) => Commands::Write(a),
            ContainerCommands::Read(a) => Commands::Read(a),
            ContainerCommands::Restore(a) => Commands::Restore(a),
        }
    }
}

impl From<StegoCommands> for Commands {
    fn from(c: StegoCommands) -> Self {
        match c {
            StegoCommands::Embed(a) => Commands::Embed(a),
            StegoCommands::Extract(a) => Commands::Extract(a),
            StegoCommands::Capacity(a) => Commands::Capacity(a),
        }
    }
}

impl From<DiagCommands> for Commands {
    fn from(c: DiagCommands) -> Self {
        match c {
            DiagCommands::Inspect(a) => Commands::Inspect(a),
            DiagCommands::Verify(a) => Commands::Verify(a),
            DiagCommands::Scan(a) => Commands::Scan(a),
            DiagCommands::List(a) => Commands::List(a),
        }
    }
}

/// Container-domain entry point (`sthc`).
#[derive(Parser, Debug)]
#[command(name = "sthc", version = STRHIDE_VERSION_INFO)]
pub struct StructCli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: ContainerCommands,
}

/// Content-steganography entry point (`sths`).
#[derive(Parser, Debug)]
#[command(name = "sths", version = STRHIDE_VERSION_INFO)]
pub struct StegoCli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: StegoCommands,
}

/// Diagnostics entry point (`sthv`).
#[derive(Parser, Debug)]
#[command(name = "sthv", version = STRHIDE_VERSION_INFO)]
pub struct DiagCli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: DiagCommands,
}

/// Arguments of the read-only capacity probe.
#[derive(Args, Debug)]
#[command(after_help = CAPACITY_AFTER_HELP)]
pub struct CapacityArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..,

    )]
    pub carrier: Vec<PathBuf>,

    /// Same tuning/credential knobs as `embed`: the capacity answer is only
    /// meaningful for the tuning it was probed with.
    #[command(flatten)]
    pub tuning: StegoTuningArgs,

    #[arg(long = "json")]
    pub json: bool,
}

const CAPACITY_AFTER_HELP: &str = crate::core::i18n::messages::CAPACITY_AFTER_HELP_EN;

/// Password arguments shared by all commands that accept one. Declared once
/// and flattened everywhere so `-p` and `--password-file` are mutually
/// exclusive: `resolve_password` would otherwise silently prefer `-p`.
#[derive(Args, Debug, Clone)]
#[group(required = false, multiple = false)]
pub struct PasswordArgs {
    #[arg(short = 'p', long = "password", value_name = "PASSWORD")]
    pub password: Option<String>,

    #[arg(long = "password-file", value_name = "FILE")]
    pub password_file: Option<PathBuf>,
}

/// `write` payload sources, isolated in their own ArgGroup so clap rejects two
/// sources at once with a parse error. The lookup chain in `handle_write` used
/// to pick the first match silently, which hid one of two supplied sources.
/// The `STRHIDE_TEXT` environment variable is deliberately NOT part of this
/// group: it is only a fallback when no CLI source is given, so the group must
/// stay non-required and the "Must provide either ..." error remains a
/// runtime check.
#[derive(Args, Debug)]
#[group(required = false, multiple = false)]
pub struct PayloadSourceArgs {
    #[arg(short = 'd', long = "data", value_name = "FILE")]
    pub data: Option<PathBuf>,

    #[arg(short = 't', long = "text", value_name = "TEXT")]
    pub text: Option<String>,

    #[arg(long = "text-base64", value_name = "BASE64")]
    pub text_base64: Option<String>,

    #[arg(long = "stdin")]
    pub stdin: bool,
}

#[derive(Args, Debug)]
#[command(after_help = WRITE_AFTER_HELP)]
pub struct WriteArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..
    )]
    pub carrier: Vec<PathBuf>,

    #[command(flatten)]
    pub payload: PayloadSourceArgs,

    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,

    #[arg(long = "in-place", conflicts_with = "output")]
    pub in_place: bool,

    #[arg(long = "overwrite")]
    pub overwrite: bool,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(short = 'e', long = "encrypt")]
    pub encrypt: bool,

    #[arg(
        short = 'H',
        long = "hint",
        alias = "password-hint",
        value_name = "TEXT"
    )]
    pub hint: Option<String>,

    #[arg(short = 's', long = "strategy", value_name = "STRATEGY")]
    pub strategy: Option<String>,

    #[arg(long = "stealth")]
    pub stealth: bool,

    #[arg(long = "no-preserve-time", default_value_t = true, action = clap::ArgAction::SetFalse)]
    pub preserve_time: bool,

    #[arg(long = "no-backup")]
    pub no_backup: bool,

    #[arg(long = "unescape")]
    pub unescape: bool,
}

const WRITE_AFTER_HELP: &str = crate::core::i18n::messages::WRITE_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = READ_AFTER_HELP)]
pub struct ReadArgs {
    #[arg(value_name = "CARRIER", required = true, num_args = 1..)]
    pub carrier: Vec<PathBuf>,

    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(long = "stdout", conflicts_with = "output")]
    pub stdout: bool,

    #[arg(long = "overwrite")]
    pub overwrite: bool,

    #[arg(
        long = "auto",
        help = "Automatically fall back to content steganography extraction if no structure envelope is found"
    )]
    pub auto: bool,
}

const READ_AFTER_HELP: &str = crate::core::i18n::messages::READ_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = EMBED_AFTER_HELP)]
pub struct EmbedArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..
    )]
    pub carrier: Vec<PathBuf>,

    #[command(flatten)]
    pub payload: PayloadSourceArgs,

    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,

    #[arg(long = "in-place", conflicts_with = "output")]
    pub in_place: bool,

    #[arg(long = "overwrite")]
    pub overwrite: bool,

    #[arg(long = "no-backup")]
    pub no_backup: bool,

    #[arg(long = "capacity", conflicts_with = "dry_run")]
    pub capacity: bool,

    #[arg(long = "dry-run")]
    pub dry_run: bool,

    #[arg(short = 'e', long = "encrypt")]
    pub encrypt: bool,

    #[command(flatten)]
    pub tuning: StegoTuningArgs,

    #[arg(
        long = "no-filename",
        help = "Do not store original filename in the carrier"
    )]
    pub no_filename: bool,
}

/// Tuning and credential arguments shared by `embed` and `capacity`.
///
/// Flattened so both verbs expose exactly the same knobs: the capacity probe
/// is credential- and cost-map-dependent, so a read-only capacity answer must
/// be able to repeat the embed-time tuning.
#[derive(Args, Debug)]
pub struct StegoTuningArgs {
    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(short = 'a', long = "algorithm", value_name = "NAME")]
    pub algorithm: Option<String>,

    #[arg(long = "safety", value_name = "LEVEL")]
    pub safety: Option<String>,

    #[arg(long = "enforce-safety")]
    pub enforce_safety: bool,

    #[arg(long = "unescape")]
    pub unescape: bool,

    #[arg(
        long = "exact",
        help = "Disable fast sampling estimation and force exact full-carrier capacity scan"
    )]
    pub exact: bool,

    // --- Fine-tuning, grouped by the format whose cost model it drives: a
    // `--p1-window` means nothing to the DCT engine and `--neighbor-weight`
    // means nothing to the spatial one (plan §4.3). ---
    #[arg(
        long = "exclusion-rate",
        help_heading = "PNG Spatial Tuning",
        value_name = "FLOAT"
    )]
    pub exclusion_rate: Option<f64>,

    #[arg(
        long = "neighbor-weight",
        help_heading = "JPEG DCT Tuning",
        value_name = "FLOAT"
    )]
    pub neighbor_weight: Option<f64>,

    #[arg(
        long = "slot-budget",
        help_heading = "JPEG DCT Tuning",
        hide = true,
        value_name = "INT"
    )]
    pub slot_budget: Option<usize>,

    #[arg(
        long = "cipher-suite",
        help_heading = "JPEG DCT Tuning",
        hide = true,
        value_name = "ID"
    )]
    pub cipher_suite: Option<u16>,

    #[arg(
        long = "p1-window",
        help_heading = "PNG Spatial Tuning",
        value_name = "INT"
    )]
    pub p1_window: Option<usize>,

    #[arg(
        long = "p2-window",
        help_heading = "PNG Spatial Tuning",
        value_name = "INT"
    )]
    pub p2_window: Option<usize>,

    #[arg(long = "stc-h", help_heading = "JPEG DCT Tuning", value_name = "INT")]
    pub stc_h: Option<u8>,

    /// Deterministic embedding seed as 64 hex digits (32 bytes).
    ///
    /// Lays the salt/nonce out from the seed instead of fresh randomness, so
    /// the same carrier + payload + options produce a byte-identical stego
    /// file. Intended for regression baselines and reproducible bug reports;
    /// leave it unset for production, where a repeated salt is a liability.
    #[arg(long = "seed", help_heading = "Reproducibility", value_name = "HEX64")]
    pub seed: Option<String>,
}

const EMBED_AFTER_HELP: &str = crate::core::i18n::messages::EMBED_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = EXTRACT_AFTER_HELP)]
pub struct ExtractArgs {
    #[arg(value_name = "CARRIER", required = true, num_args = 1..)]
    pub carrier: Vec<PathBuf>,

    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,

    #[arg(long = "stdout", conflicts_with = "output")]
    pub stdout: bool,

    #[arg(long = "overwrite")]
    pub overwrite: bool,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(
        long = "auto",
        help = "Automatically fall back to structure-domain read if no content steganography is found"
    )]
    pub auto: bool,
}

const EXTRACT_AFTER_HELP: &str = crate::core::i18n::messages::EXTRACT_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = RESTORE_AFTER_HELP)]
pub struct RestoreArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..
    )]
    pub carrier: Vec<PathBuf>,

    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,

    #[arg(long = "in-place", conflicts_with = "output")]
    pub in_place: bool,

    #[arg(long = "overwrite")]
    pub overwrite: bool,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(long = "no-backup")]
    pub no_backup: bool,
}

const RESTORE_AFTER_HELP: &str = crate::core::i18n::messages::RESTORE_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = INSPECT_AFTER_HELP)]
pub struct InspectArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..
    )]
    pub carrier: Vec<PathBuf>,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    /// Recursively descend into directories.
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,

    #[arg(long = "json")]
    pub json: bool,
}

const INSPECT_AFTER_HELP: &str = crate::core::i18n::messages::INSPECT_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = VERIFY_AFTER_HELP)]
pub struct VerifyArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..
    )]
    pub carrier: Vec<PathBuf>,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    /// Recursively descend into directories.
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,

    #[arg(long = "json")]
    pub json: bool,
}

const VERIFY_AFTER_HELP: &str = crate::core::i18n::messages::VERIFY_AFTER_HELP_EN;

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(long = "json")]
    pub json: bool,
}

/// Black-box steganalysis options. Unlike inspect/verify (which assume a
/// strhide envelope exists and check it), scan treats every input as unknown
/// and reports structural + statistical signs of hidden data from any tool.
#[derive(Args, Debug)]
#[command(after_help = SCAN_AFTER_HELP)]
pub struct ScanArgs {
    /// File(s) or directory(ies) to scan, given positionally: the inputs are
    /// suspects, not necessarily strhide carriers, and directories are walked
    /// according to --recursive.
    #[arg(
        value_name = "FILE",
        required = true,
        num_args = 1..
    )]
    pub input: Vec<PathBuf>,

    /// Recursively descend into directories.
    #[arg(long = "recursive", short = 'r')]
    pub recursive: bool,

    /// Emit a JSON array of per-file reports (machine-readable).
    #[arg(long = "json")]
    pub json: bool,

    /// Exit non-zero when any report reaches this verdict or higher.
    #[arg(
        long = "fail-on",
        value_name = "LEVEL",
        default_value = "likely",
        value_parser = ["low", "suspicious", "likely"]
    )]
    pub fail_on: String,
}

const SCAN_AFTER_HELP: &str = crate::core::i18n::messages::SCAN_AFTER_HELP_EN;
