use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};

use crate::config::{self, FileConfig};
use crate::engine::{
    PayloadSource, RemoveResult, WriteOptions, WriteResult, inspect_carrier, read_carrier_with,
    remove_carrier_with_options, verify_carrier, write_carrier,
};
use crate::errors::StrHideError;
use crate::i18n::{self, Msg, t};
use crate::router::{ADAPTERS, find_adapter_or_reject};

pub const STRHIDE_VERSION_INFO: &str = env!("STRHIDE_VERSION_INFO");
pub const STRHIDE_GIT_HASH: &str = env!("STRHIDE_GIT_HASH");
pub const STRHIDE_BUILD_TIME: &str = env!("STRHIDE_BUILD_TIME");
pub const BANNER: &str = concat!("strhide ", env!("STRHIDE_VERSION_INFO"));

#[derive(Parser, Debug)]
#[command(
    name = "strhide",
    version = STRHIDE_VERSION_INFO,
    about = "Format-preserving lossless data hiding and steganography tool"
)]
pub struct Cli {
    /// Path to TOML config file (default: ./strhide.toml, then ~/.strhide/config.toml)
    #[arg(short = 'c', long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[arg(
        short = 'q',
        long = "quiet",
        global = true,
        help = "Suppress normal status output: [OK]/[INFO] progress, notices, and human-readable reports. Payload data (read), --json/table output, and [ERROR] messages always print; the exit code tells scripts whether the command succeeded."
    )]
    pub quiet: bool,

    #[arg(
        long = "lang",
        global = true,
        value_name = "LANG",
        value_parser = ["en", "zh"],
        help = "Interface language: en or zh (default: STRHIDE_LANG / config / system locale)"
    )]
    pub lang: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Hide secret payload into carrier file
    Write(WriteArgs),
    /// Read and extract hidden payload from carrier
    Read(ReadArgs),
    /// 100% loss-free restoration of the original host file
    Restore(RestoreArgs),
    /// Inspect carrier structure and envelope metadata
    Inspect(InspectArgs),
    /// Diagnostic verification of host, envelope, and crypto
    Verify(VerifyArgs),
    /// Black-box steganalysis: scan file(s) for hidden content, known or unknown
    Scan(ScanArgs),
    /// Content-adaptive steganography: embed payload into image pixels or DCT coefficients (HILL/UERD)
    Embed(EmbedArgs),
    /// Content-adaptive steganography: extract payload from image pixels or DCT coefficients
    Extract(ExtractArgs),
    /// List all supported formats, strategies, and their capacity limits
    List(ListArgs),
}

/// Password arguments shared by all commands that accept one. Declared once
/// and flattened everywhere so `-p` and `--password-file` are mutually
/// exclusive: `resolve_password` would otherwise silently prefer `-p`.
#[derive(Args, Debug)]
#[group(required = false, multiple = false)]
pub struct PasswordArgs {
    #[arg(
        short = 'p',
        long = "password",
        value_name = "PASSWORD",
        help = "Password in plain text (it stays visible in shell history and process listings). Prefer --password-file, STRHIDE_PASSWORD, or the interactive prompt."
    )]
    pub password: Option<String>,

    #[arg(
        long = "password-file",
        value_name = "FILE",
        help = "Read the password from this file (first line; trailing CR/LF is trimmed). Mutually exclusive with -p/--password."
    )]
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
    #[arg(
        short = 'd',
        long = "data",
        value_name = "FILE",
        help = "Hide this file as the payload (any content, binary or text). Mutually exclusive with the other payload sources."
    )]
    pub data: Option<PathBuf>,

    #[arg(
        short = 't',
        long = "text",
        value_name = "TEXT",
        help = "Hide this text as the payload; combine with --unescape for C-style escapes. Mutually exclusive with the other payload sources."
    )]
    pub text: Option<String>,

    #[arg(
        long = "text-file",
        value_name = "FILE",
        help = "Hide the text read from this file (must be UTF-8). Mutually exclusive with the other payload sources."
    )]
    pub text_file: Option<PathBuf>,

    #[arg(
        long = "text-base64",
        value_name = "BASE64",
        help = "Hide this base64-encoded text; it must decode to valid UTF-8 (arbitrary binary belongs in -d/--data). Mutually exclusive with the other payload sources."
    )]
    pub text_base64: Option<String>,

    #[arg(
        long = "stdin",
        help = "Read the payload from standard input, e.g. `cat secret.txt | strhide write photo.png --stdin`. Mutually exclusive with the other payload sources."
    )]
    pub stdin: bool,
}

#[derive(Args, Debug)]
#[command(after_help = WRITE_AFTER_HELP)]
pub struct WriteArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..,
        help = "Carrier file(s) to hide the payload in; give several to embed the same payload into each. Use `--` before a filename that starts with '-'."
    )]
    pub carrier: Vec<PathBuf>,

    #[command(flatten)]
    pub payload: PayloadSourceArgs,

    #[arg(
        short = 'o',
        long = "output",
        value_name = "PATH",
        help = "Write the modified carrier to this path. A single path names the result for one carrier; with several carriers it must be an existing directory and each output keeps its carrier's name. Default: write to <carrier>-out.<ext>."
    )]
    pub output: Option<PathBuf>,

    #[arg(
        long = "in-place",
        conflicts_with = "output",
        help = "Modify carrier file(s) in place (creates .bak backup by default unless --no-backup). Default: write to <carrier>-out.<ext>."
    )]
    pub in_place: bool,

    #[arg(
        long = "overwrite",
        help = "Allow overwriting existing output file(s) without prompt"
    )]
    pub overwrite: bool,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(
        short = 'e',
        long = "encrypt",
        help = "Ask for an encryption password when no password source is given (interactive prompt; fails without a TTY). Note: the payload is always encrypted - without a password a built-in key is used."
    )]
    pub encrypt: bool,

    #[arg(
        short = 'H',
        long = "hint",
        alias = "password-hint",
        value_name = "TEXT",
        help = "Store this password hint inside the envelope (shown to whoever reads the payload later; not secret). Incompatible with --stealth."
    )]
    pub hint: Option<String>,

    #[arg(
        short = 's',
        long = "strategy",
        value_name = "STRATEGY",
        help = "Hiding strategy (auto|ask|<name>; default: auto or config file)"
    )]
    pub strategy: Option<String>,

    #[arg(
        long = "stealth",
        help = "Stealth mode: hide without detectable markers - the envelope signature derives from the password, so this implies password protection and requires one (-p/--password, --password-file, or STRHIDE_PASSWORD). Incompatible with a password hint."
    )]
    pub stealth: bool,

    #[arg(long = "no-preserve-time", default_value_t = true, action = clap::ArgAction::SetFalse, help = "Do not preserve original carrier timestamps (default: preserve)")]
    pub preserve_time: bool,

    #[arg(
        long = "no-backup",
        help = "Do not create a '<carrier>.bak' backup next to a modified carrier (default: a .bak copy is kept; backups only apply to in-place modification)."
    )]
    pub no_backup: bool,

    #[arg(
        long = "unescape",
        help = "Decode C-style escape sequences (\\n, \\r, \\t, \\xHH, \\uNNNN, ...) in the -t/--text payload before hiding; malformed escapes are kept literally."
    )]
    pub unescape: bool,
}

const WRITE_AFTER_HELP: &str = crate::i18n::messages::WRITE_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = READ_AFTER_HELP)]
pub struct ReadArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        help = "Carrier file to extract the hidden payload from. Use `--` before a filename that starts with '-'."
    )]
    pub carrier: PathBuf,

    #[arg(
        short = 'o',
        long = "output",
        value_name = "PATH",
        help = "Write the extracted payload to a file, or into an existing directory keeping the filename stored in the envelope."
    )]
    pub output: Option<PathBuf>,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(
        long = "stdout",
        conflicts_with = "output",
        help = "Print the payload to standard output instead of writing a file (mutually exclusive with -o/--output)."
    )]
    pub stdout: bool,

    #[arg(
        long = "overwrite",
        help = "Allow overwriting an existing file when extracting a payload"
    )]
    pub overwrite: bool,
}

const READ_AFTER_HELP: &str = crate::i18n::messages::READ_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = EMBED_AFTER_HELP)]
pub struct EmbedArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..,
        help = "Carrier image file(s) (PNG or JPEG). Use `--` before a filename that starts with '-'."
    )]
    pub carrier: Vec<PathBuf>,

    #[command(flatten)]
    pub payload: PayloadSourceArgs,

    #[arg(
        short = 'o',
        long = "output",
        value_name = "PATH",
        help = "Write modified carrier to this path (or into an existing directory for multiple carriers). Default: write to <carrier>-out.<ext>."
    )]
    pub output: Option<PathBuf>,

    #[arg(
        long = "in-place",
        conflicts_with = "output",
        help = "Modify carrier image(s) in place (creates .bak backup by default unless --no-backup). Note: content steganography modifies pixels/coefficients and cannot be restored to original bit-for-bit."
    )]
    pub in_place: bool,

    #[arg(
        long = "overwrite",
        help = "Allow overwriting existing output file(s) without prompt"
    )]
    pub overwrite: bool,

    #[arg(
        long = "no-backup",
        help = "Do not create a '<carrier>.bak' backup copy when modifying in place."
    )]
    pub no_backup: bool,

    #[arg(
        long = "capacity",
        help = "Probe and display maximum embedding capacity for the carrier image, then exit without modifying the carrier"
    )]
    pub capacity: bool,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(
        short = 'e',
        long = "encrypt",
        help = "Ask for an encryption password when no password source is given (interactive prompt; fails without a TTY)."
    )]
    pub encrypt: bool,

    #[arg(
        short = 'a',
        long = "algorithm",
        value_name = "NAME",
        help = "Distortion cost algorithm (auto|hill|uerd; default: auto - hill for PNG, uerd for JPEG)"
    )]
    pub algorithm: Option<String>,

    #[arg(
        long = "stego-secret",
        value_name = "SECRET",
        help = "Private stand-in secret for no-password stego envelopes; enables a private dialect that the public built-in key cannot read. Extract must use the same value."
    )]
    pub stego_secret: Option<String>,

    #[arg(
        long = "stego-domain",
        value_name = "DOMAIN",
        help = "Custom domain tag to isolate the HKDF key derivation from the public dialect. Extract must use the same domain."
    )]
    pub stego_domain: Option<String>,

    #[arg(
        long = "safety",
        value_name = "LEVEL",
        help = "Stego capacity safety tier: 'paranoid' (bpp<=0.06), 'high' (bpp<=0.10, default), or 'balanced' (bpp<=0.15)"
    )]
    pub safety: Option<String>,

    #[arg(
        long = "enforce-safety",
        help = "Strictly reject payloads exceeding recommended safety tier instead of advisory warning"
    )]
    pub enforce_safety: bool,

    #[arg(
        long = "unescape",
        help = "Decode C-style escape sequences (\\n, \\r, \\t, ...) in the -t/--text payload before embedding"
    )]
    pub unescape: bool,

    // --- Fine-tuning parameters for custom obfuscation and anti-detection ---
    #[arg(
        long = "exclusion-rate",
        value_name = "FLOAT",
        help = "Fine-tune (Spatial HILL): fraction of smoothest regions excluded from embedding (0.0 .. 0.8; default: 0.30)"
    )]
    pub exclusion_rate: Option<f64>,

    #[arg(
        long = "neighbor-weight",
        value_name = "FLOAT",
        help = "Fine-tune (JPEG UERD): weight applied to 8-neighborhood block energies (default: 0.25)"
    )]
    pub neighbor_weight: Option<f64>,

    #[arg(
        long = "slot-budget",
        value_name = "INT",
        help = "Fine-tune (JPEG V3): trellis slot budget; a larger budget spreads each payload bit over more \
                coefficients (fewer changes per coefficient), at the cost of time and memory. Default: 1200000. \
                Extraction does not need this value."
    )]
    pub slot_budget: Option<usize>,

    #[arg(
        long = "cipher-suite",
        value_name = "ID",
        help = "Fine-tune (JPEG V3): cipher suite written into the carrier header. 1 = pbkdf2-sha256-200k \
                (default), 2 = pbkdf2-sha256-600k (slower, stronger). Extraction identifies it automatically."
    )]
    pub cipher_suite: Option<u16>,

    #[arg(
        long = "p1-window",
        value_name = "INT",
        help = "Fine-tune (Spatial HILL): first-stage low-pass filter window size (odd, default: 3)"
    )]
    pub p1_window: Option<usize>,

    #[arg(
        long = "p2-window",
        value_name = "INT",
        help = "Fine-tune (Spatial HILL): second-stage low-pass filter window size (odd, default: 15)"
    )]
    pub p2_window: Option<usize>,

    #[arg(
        long = "stc-h",
        value_name = "INT",
        help = "Fine-tune (STC): trellis constraint height, 4..=10 (default: 8). Larger is slower and slightly better."
    )]
    pub stc_h: Option<u8>,
}

const EMBED_AFTER_HELP: &str = crate::i18n::messages::EMBED_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = EXTRACT_AFTER_HELP)]
pub struct ExtractArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        help = "Stego image file to extract hidden payload from (PNG or JPEG)."
    )]
    pub carrier: PathBuf,

    #[arg(
        short = 'o',
        long = "output",
        value_name = "PATH",
        help = "Write extracted payload to a file (or into an existing directory). If omitted, text payloads are printed to stdout."
    )]
    pub output: Option<PathBuf>,

    #[arg(
        long = "stdout",
        conflicts_with = "output",
        help = "Print the payload to standard output instead of writing a file (mutually exclusive with -o/--output)."
    )]
    pub stdout: bool,

    #[arg(
        long = "overwrite",
        help = "Allow overwriting an existing file when extracting a payload"
    )]
    pub overwrite: bool,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(
        short = 'a',
        long = "algorithm",
        value_name = "NAME",
        help = "Distortion cost algorithm (auto|hill|uerd; default: auto)"
    )]
    pub algorithm: Option<String>,

    #[arg(
        long = "stego-secret",
        value_name = "SECRET",
        help = "Private stand-in secret for no-password stego envelopes; must equal the value used at embed time."
    )]
    pub stego_secret: Option<String>,

    #[arg(
        long = "stego-domain",
        value_name = "DOMAIN",
        help = "Custom domain tag to isolate the HKDF key derivation from the public dialect; must equal the value used at embed time."
    )]
    pub stego_domain: Option<String>,

    // Fine-tuning parameters matching custom embedding parameters
    #[arg(long = "exclusion-rate", value_name = "FLOAT")]
    pub exclusion_rate: Option<f64>,

    #[arg(long = "neighbor-weight", value_name = "FLOAT")]
    pub neighbor_weight: Option<f64>,

    #[arg(long = "p1-window", value_name = "INT")]
    pub p1_window: Option<usize>,

    #[arg(long = "p2-window", value_name = "INT")]
    pub p2_window: Option<usize>,
}

const EXTRACT_AFTER_HELP: &str = crate::i18n::messages::EXTRACT_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = RESTORE_AFTER_HELP)]
pub struct RestoreArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..,
        help = "Carrier file(s) to restore; give several to strip each one. Use `--` before a filename that starts with '-'."
    )]
    pub carrier: Vec<PathBuf>,

    #[arg(
        short = 'o',
        long = "output",
        value_name = "PATH",
        help = "Write the restored carrier to this path. A single path names the result for one carrier; with several carriers it must be an existing directory. Default: write to <carrier>-out.<ext>."
    )]
    pub output: Option<PathBuf>,

    #[arg(
        long = "in-place",
        conflicts_with = "output",
        help = "Restore carrier file(s) in place (creates .bak backup by default unless --no-backup). Default: write to <carrier>-out.<ext>."
    )]
    pub in_place: bool,

    #[arg(
        long = "overwrite",
        help = "Allow overwriting existing output file(s) without prompt"
    )]
    pub overwrite: bool,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(
        long = "no-backup",
        help = "Do not create a '<carrier>.bak' backup for in-place restoration (default: a .bak copy is kept; backups only apply to in-place restoration)."
    )]
    pub no_backup: bool,
}

const RESTORE_AFTER_HELP: &str = crate::i18n::messages::RESTORE_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = INSPECT_AFTER_HELP)]
pub struct InspectArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..,
        help = "Carrier file(s) or directory(ies) to inspect; reports host format, envelope metadata, and per-strategy capacity. Use `--` before a filename that starts with '-'."
    )]
    pub carrier: Vec<PathBuf>,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    /// Recursively descend into directories.
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,

    #[arg(
        long = "json",
        help = "Print machine-readable JSON report (single object for one file, array for multiple files/directories)."
    )]
    pub json: bool,
}

const INSPECT_AFTER_HELP: &str = crate::i18n::messages::INSPECT_AFTER_HELP_EN;

#[derive(Args, Debug)]
#[command(after_help = VERIFY_AFTER_HELP)]
pub struct VerifyArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        num_args = 1..,
        help = "Carrier file(s) or directory(ies) to verify. Use `--` before a filename that starts with '-'."
    )]
    pub carrier: Vec<PathBuf>,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    /// Recursively descend into directories.
    #[arg(short = 'r', long = "recursive")]
    pub recursive: bool,

    #[arg(
        long = "json",
        help = "Print machine-readable JSON report (single object for one file, array for multiple files/directories)."
    )]
    pub json: bool,
}

const VERIFY_AFTER_HELP: &str = crate::i18n::messages::VERIFY_AFTER_HELP_EN;

#[derive(Args, Debug)]
pub struct ListArgs {
    #[arg(
        long = "json",
        help = "Emit structured JSON output containing formats, strategies, and algorithms"
    )]
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
        num_args = 1..,
        help = "File(s) or directory(ies) to scan. Directories are scanned non-recursively unless --recursive is given. Use `--` before a filename that starts with '-'."
    )]
    pub input: Vec<PathBuf>,

    /// Recursively descend into directories.
    #[arg(long = "recursive", short = 'r')]
    pub recursive: bool,

    /// Emit a JSON array of per-file reports (machine-readable).
    #[arg(long = "json")]
    pub json: bool,
}

const SCAN_AFTER_HELP: &str = crate::i18n::messages::SCAN_AFTER_HELP_EN;

pub fn prompt_password(confirm: bool) -> Result<String, StrHideError> {
    let p1 = t!(Msg::PromptEnterPassword);
    let pwd = rpassword::prompt_password(&p1)
        .map_err(|e| StrHideError::General(format!("Failed to read password: {e}")))?;
    if pwd.is_empty() {
        return Err(StrHideError::Password("Password cannot be empty".into()));
    }
    if confirm {
        let p2 = t!(Msg::PromptConfirmPassword);
        let pwd2 = rpassword::prompt_password(&p2).map_err(|e| {
            StrHideError::General(format!("Failed to read password confirmation: {e}"))
        })?;
        if pwd != pwd2 {
            return Err(StrHideError::Password(t!(Msg::PasswordMismatch)));
        }
    }
    Ok(pwd)
}

pub fn resolve_password(
    pwd_opt: Option<&str>,
    pwd_file: Option<&Path>,
    cfg: &FileConfig,
    encrypt_flag: bool,
    confirm: bool,
) -> Result<Option<String>, StrHideError> {
    if let Some(p) = pwd_opt {
        return Ok(Some(p.to_string()));
    }
    if let Some(pf) = pwd_file {
        // Name the file in the error: the bare OS message ("file not found")
        // does not tell the user WHICH password file failed, and several
        // commands accept one. Mirrors the config branch below.
        let mut s = std::fs::read_to_string(pf).map_err(|e| {
            StrHideError::General(format!(
                "Failed to read password file '{}': {e}",
                pf.display()
            ))
        })?;
        s = s.trim_end_matches(&['\r', '\n'][..]).to_string();
        return Ok(Some(s));
    }
    if let Ok(env_pwd) = std::env::var("STRHIDE_PASSWORD")
        && !env_pwd.is_empty()
    {
        return Ok(Some(env_pwd));
    }
    // Config file sources come after CLI args and the environment variable.
    if let Some(p) = cfg.password.as_deref()
        && !p.is_empty()
    {
        return Ok(Some(p.to_string()));
    }
    if let Some(pf) = cfg.password_file.as_deref() {
        let mut s = std::fs::read_to_string(pf).map_err(|e| {
            StrHideError::General(format!(
                "Failed to read password file from config '{}': {e}",
                pf.display()
            ))
        })?;
        s = s.trim_end_matches(&['\r', '\n'][..]).to_string();
        return Ok(Some(s));
    }
    if encrypt_flag {
        // Only prompt when a terminal is actually attached; both stdin and
        // stdout must be TTYs, since some environments report stdin as a TTY
        // while no console exists (e.g. Git Bash with `< /dev/null`), which
        // would make the password prompt block forever.
        if std::io::IsTerminal::is_terminal(&std::io::stdin())
            && std::io::IsTerminal::is_terminal(&std::io::stdout())
        {
            return Ok(Some(prompt_password(confirm)?));
        }
        return Err(StrHideError::General(
            "Password required but no interactive terminal is available. Use -p/--password, --password-file, or STRHIDE_PASSWORD.".into(),
        ));
    }
    Ok(None)
}

/// Resolve the private stego default secret.
///
/// Precedence mirrors `resolve_password`: CLI flag, then
/// `STRHIDE_STEGO_SECRET`, then the config file. An empty value means "not
/// configured" rather than "empty secret" -- an empty secret would silently
/// fall back to the public constant and defeat the purpose.
fn resolve_stego_secret(explicit: Option<&str>, cfg: &FileConfig) -> Option<String> {
    if let Some(s) = explicit
        && !s.is_empty()
    {
        return Some(s.to_string());
    }
    if let Ok(env_secret) = std::env::var("STRHIDE_STEGO_SECRET")
        && !env_secret.is_empty()
    {
        return Some(env_secret);
    }
    cfg.stego_secret.as_ref().filter(|s| !s.is_empty()).cloned()
}

/// Resolve the custom stego domain tag.
///
/// Precedence mirrors `resolve_stego_secret`: CLI flag, then
/// `STRHIDE_STEGO_DOMAIN`, then the config file. An empty value means "not configured".
fn resolve_stego_domain(explicit: Option<&str>, cfg: &FileConfig) -> Option<String> {
    if let Some(d) = explicit
        && !d.is_empty()
    {
        return Some(d.to_string());
    }
    if let Ok(env_domain) = std::env::var("STRHIDE_STEGO_DOMAIN")
        && !env_domain.is_empty()
    {
        return Some(env_domain);
    }
    cfg.stego_domain.as_ref().filter(|d| !d.is_empty()).cloned()
}

/// Package the resolved private stego secret and domain as a stego-only
/// [`Profile`](crate::params::Profile).
///
/// Only the content-domain half is populated: the CLI does not expose the
/// structure-domain dialect knobs yet, so those stay at their official
/// defaults (an all-default profile is byte-compatible with every release).
fn stego_profile(secret: Option<String>, domain: Option<String>) -> crate::params::Profile {
    let mut profile = crate::params::Profile::default();
    if let Some(secret) = secret {
        profile = profile.with_stego_secret(secret);
    }
    if let Some(domain) = domain {
        profile = profile.with_stego_domain(domain);
    }
    profile
}

fn should_print_banner(cli: &Cli) -> bool {
    if cli.quiet {
        return false;
    }
    match &cli.command {
        Commands::Inspect(args) if args.json => false,
        Commands::Verify(args) if args.json => false,
        Commands::Scan(args) if args.json => false,
        Commands::List(args) if args.json => false,
        Commands::Read(args) if args.stdout || args.output.is_none() => false,
        Commands::Extract(args) if args.stdout || args.output.is_none() => false,
        _ => true,
    }
}

pub fn print_error(e: &StrHideError) {
    let line = match e.category() {
        Some(cat) => t!(
            Msg::ErrorLine,
            prefix = cat.text(i18n::lang()),
            detail = e.detail()
        ),
        None => t!(Msg::ErrorLinePlain, detail = e.detail()),
    };
    eprintln!("{line}");
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

fn render_early_error(e: clap::Error, argv: &[std::ffi::OsString]) -> i32 {
    use clap::error::ErrorKind::*;
    let lang = i18n::locale::detect(scan_lang_flag(argv), &FileConfig::default());
    i18n::set_lang(lang);

    match e.kind() {
        DisplayHelp | DisplayHelpOnMissingArgumentOrSubcommand | MissingSubcommand => {
            let mut cmd = crate::cli_i18n::localize(Cli::command(), lang);
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
            println!("{BANNER}");
            0
        }
        _ => {
            let mut cmd = crate::cli_i18n::localize(Cli::command(), lang);
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
    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();

    // 1) 预解析（英文模板，仅用于取得 matches；不触发任何输出）
    let pre = match Cli::command().try_get_matches_from(argv.clone()) {
        Ok(m) => m,
        Err(e) => return render_early_error(e, &argv),
    };

    // 2) 加载配置（失败也要按最终语言报错）
    let cfg_path = pre.get_one::<PathBuf>("config");
    let cfg = match config::load(cfg_path.map(|p| p.as_ref())) {
        Ok(c) => c,
        Err(e) => {
            let lang = i18n::locale::detect(
                pre.get_one::<String>("lang").map(String::as_str),
                &FileConfig::default(),
            );
            i18n::set_lang(lang);
            print_error(&e);
            return 1;
        }
    };

    // 3) 确定语言并全局生效
    let lang = i18n::locale::detect(pre.get_one::<String>("lang").map(String::as_str), &cfg);
    i18n::set_lang(lang);

    // 4) 从 matches 构造 Cli
    let cli = match Cli::from_arg_matches(&pre) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] {e}");
            return 2;
        }
    };

    if should_print_banner(&cli) {
        println!("{BANNER}");
    }

    match cli.command {
        Commands::Write(args) => match handle_write(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Read(args) => match handle_read(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Restore(args) => match handle_restore(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Inspect(args) => match handle_inspect(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Verify(args) => match handle_verify(args, &cfg, cli.quiet) {
            Ok(code) => code,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        // Like verify, scan owns its exit code: 1 when a scan verdict reaches
        // "likely-hidden" (see handle_scan), 0 otherwise, regardless of quiet.
        Commands::Scan(args) => match handle_scan(args, cli.quiet) {
            Ok(code) => code,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Embed(args) => match handle_embed(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                print_error(&e);
                1
            }
        },
        Commands::Extract(args) => match handle_extract(args, &cfg, cli.quiet) {
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

/// How a payload source is materialised.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PayloadFlavor {
    /// Text payload: every source must be valid UTF-8 and is stored as text.
    Text,
    /// Raw bytes: any source is accepted exactly as it is.
    Bytes,
}

/// A payload source resolved from the CLI.
enum ResolvedPayload {
    /// Read the payload from standard input.
    Stdin,
    /// A payload file (`-d`/`--data`): read as raw bytes.
    File(PathBuf),
    /// A text file (`--text-file`): UTF-8 for [`PayloadFlavor::Text`], raw
    /// bytes for [`PayloadFlavor::Bytes`].
    TextFile(PathBuf),
    /// Text payload, already materialised (`-t`, `STRHIDE_TEXT`).
    Text(String),
    /// Raw bytes, already materialised (`--text-base64`).
    Bytes(Vec<u8>),
}

/// Resolve the payload source shared by `write` and `embed`.
///
/// `write` and `embed` used to carry two copies of the same 40-line resolution
/// chain (`--stdin` / `-d` / `-t` + `--unescape` / `--text-file` /
/// `--text-base64` / `STRHIDE_TEXT`), and they had already drifted: only one of
/// them validated that base64 content decodes to UTF-8, and they disagreed on
/// whether `--text-file` may hold binary data. Both now funnel through here;
/// the difference between them is the explicit [`PayloadFlavor`], not an
/// accidental divergence.
fn resolve_payload(
    payload: &PayloadSourceArgs,
    unescape: bool,
    cfg: &FileConfig,
    flavor: PayloadFlavor,
) -> Result<ResolvedPayload, StrHideError> {
    const MISSING: &str = "Must provide either -d/--data, -t/--text, --text-file, --text-base64, or --stdin (or use --capacity to probe capacity)";

    if payload.stdin {
        return Ok(ResolvedPayload::Stdin);
    }
    if let Some(ref df) = payload.data {
        return Ok(ResolvedPayload::File(df.clone()));
    }
    if let Some(ref tf) = payload.text_file {
        return Ok(ResolvedPayload::TextFile(tf.clone()));
    }
    if let Some(ref b64_str) = payload.text_base64 {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64_str.trim())
            .map_err(|e| StrHideError::General(format!("Invalid base64 string: {e}")))?;
        return Ok(match flavor {
            PayloadFlavor::Text => {
                let text = String::from_utf8(bytes).map_err(|e| {
                    StrHideError::General(format!("Base64 content is not valid UTF-8: {e}"))
                })?;
                ResolvedPayload::Text(text)
            }
            PayloadFlavor::Bytes => ResolvedPayload::Bytes(bytes),
        });
    }
    if let Some(ref t) = payload.text {
        if unescape || cfg.unescape.unwrap_or(false) {
            return Ok(ResolvedPayload::Text(unescape_string(t)));
        }
        return Ok(ResolvedPayload::Text(t.clone()));
    }
    if let Ok(env_text) = std::env::var("STRHIDE_TEXT")
        && !env_text.is_empty()
    {
        return Ok(ResolvedPayload::Text(env_text));
    }
    Err(StrHideError::General(MISSING.to_string()))
}

fn handle_write(args: WriteArgs, cfg: &FileConfig, quiet: bool) -> Result<(), StrHideError> {
    // Config values act as defaults; explicit CLI flags win. --stealth implies
    // encryption (its magics are password-derived); prompt for a password when
    // neither -p nor a password source was supplied.
    let stealth = args.stealth || cfg.stealth.unwrap_or(false);
    let encrypt = args.encrypt || cfg.encrypt.unwrap_or(false);
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        encrypt || stealth,
        true,
    )?;

    let multi = args.carrier.len() > 1;
    // A single file path cannot name every output, so with several carriers
    // -o must be an existing directory.
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "writing to")?;

    let mut strategy = args
        .strategy
        .clone()
        .or_else(|| cfg.strategy.clone())
        .unwrap_or_else(|| "auto".to_string());
    if strategy == "ask" {
        if multi {
            // The prompt answers for one carrier; asking once per file is
            // almost never what a batch user means, so refuse up front rather
            // than interleaving prompts with writes.
            return Err(StrHideError::General(
                "Interactive strategy selection (--strategy ask) cannot be combined with multiple carriers. Use --strategy auto or name a strategy explicitly.".into(),
            ));
        }
        let carrier = &args.carrier[0];
        let mut cf = File::open(carrier)?;
        let adapter = find_adapter_or_reject(&mut cf, &carrier.display().to_string())?;
        let strats = adapter.supported_strategies();
        println!(
            "{}",
            t!(Msg::PromptAvailableStrategies, path = carrier.display())
        );
        for (idx, s) in strats.iter().enumerate() {
            println!("  [{}] {s}", idx + 1);
        }
        print!("{}", t!(Msg::PromptSelectStrategy, max = strats.len()));
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let choice = input.trim();
        if let Ok(c) = choice.parse::<usize>() {
            if c >= 1 && c <= strats.len() {
                strategy = strats[c - 1].to_string();
            } else {
                strategy = strats[0].to_string();
            }
        } else {
            strategy = strats[0].to_string();
        }
    }

    // Resolve payload source (shared with `embed`).
    let text_buf: String;
    let payload_path: PathBuf;
    let payload_source: PayloadSource =
        match resolve_payload(&args.payload, args.unescape, cfg, PayloadFlavor::Text)? {
            ResolvedPayload::Stdin => PayloadSource::Stdin,
            ResolvedPayload::File(f) => {
                payload_path = f;
                PayloadSource::File(&payload_path)
            }
            ResolvedPayload::TextFile(p) => {
                text_buf = std::fs::read_to_string(p)?;
                PayloadSource::Text(&text_buf)
            }
            ResolvedPayload::Text(t) => {
                text_buf = t;
                PayloadSource::Text(&text_buf)
            }
            ResolvedPayload::Bytes(b) => {
                text_buf = String::from_utf8(b).map_err(|e| {
                    StrHideError::General(format!("Base64 content is not valid UTF-8: {e}"))
                })?;
                PayloadSource::Text(&text_buf)
            }
        };

    // Buffer the payload once. Sources are resolved here rather than per
    // carrier because --stdin can only be read once, and because this keeps the
    // stored filename / is_file flags byte-identical to single-carrier writes.
    let (payload, payload_name, payload_is_file) = payload_source.into_buffered()?;

    // Fail before the first carrier is modified when a batch is obviously bad
    // (missing/unrecognized files, duplicate targets, unpermitted overwrites).
    if multi {
        preflight_batch(
            &args.carrier,
            args.in_place,
            args.output.as_deref(),
            output_dir,
            args.overwrite,
        )?;
    } else {
        let carrier = &args.carrier[0];
        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = target {
            check_overwrite(t, args.overwrite)?;
        }
    }

    // A password hint is incompatible with --stealth: stealth mode requires the
    // password to locate the envelope, so nothing can be left in the clear.
    // A hint that only comes from the config file is a default the user did not
    // ask for on this run — drop it instead of failing the write with an error
    // that blames `--stealth`. An explicit `-H` is still passed through so the
    // engine can report the conflict.
    let hint = if stealth && args.hint.is_none() {
        None
    } else {
        args.hint.clone().or_else(|| cfg.hint.clone())
    };
    let preserve_time = args.preserve_time && cfg.preserve_time.unwrap_or(true);
    let backup = !args.no_backup && cfg.backup.unwrap_or(true);

    for_each_carrier(&args.carrier, quiet, |carrier| {
        let output =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = output {
            check_overwrite(t, args.overwrite)?;
        }
        let res = write_carrier(
            carrier,
            PayloadSource::Buffered {
                data: &payload,
                filename: &payload_name,
                is_file: payload_is_file,
            },
            &WriteOptions {
                output_path: output.as_deref(),
                password: password.as_deref(),
                password_hint: hint.as_deref(),
                strategy: &strategy,
                stealth,
                preserve_time,
                backup,
            },
        )?;
        print_write_result(&res, quiet);
        Ok(())
    })
}

fn handle_read(args: ReadArgs, cfg: &FileConfig, quiet: bool) -> Result<(), StrHideError> {
    let mut password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let res = match read_carrier_with(
        &args.carrier,
        args.output.as_deref(),
        password.as_deref(),
        args.overwrite,
    ) {
        Ok(r) => r,
        // Discriminate by error variant, not by message text. A password error
        // with no password supplied means the envelope is encrypted: show the
        // hint (a structured field on the error), then prompt (interactive
        // terminals only) and retry once.
        Err(e @ StrHideError::PasswordWithHint { .. }) if password.is_none() => {
            if !quiet && let Some(hint) = e.hint() {
                println!("{}", t!(Msg::InfoPasswordHint, hint = hint));
            }
            if !(std::io::IsTerminal::is_terminal(&std::io::stdin())
                && std::io::IsTerminal::is_terminal(&std::io::stdout()))
            {
                return Err(StrHideError::Password(
                    "Password required but no interactive terminal is available. Use -p/--password, --password-file, or STRHIDE_PASSWORD.".into(),
                ));
            }
            password = Some(prompt_password(false)?);
            read_carrier_with(
                &args.carrier,
                args.output.as_deref(),
                password.as_deref(),
                args.overwrite,
            )?
        }
        Err(e) => return Err(e),
    };

    // A password was supplied but the envelope is not encrypted: the built-in
    // public key masked it, so the password had no effect. Say so instead of
    // letting the user believe `-p` protected this payload.
    if password.is_some() && !res.is_encrypted && !quiet {
        eprintln!("{}", t!(Msg::WarnEnvelopeNotEncrypted));
    }

    if let Some(wf) = res.written_file {
        if !quiet {
            println!(
                "{}",
                t!(Msg::ReadOkExtracted, path = wf, bytes = res.raw_size)
            );
        }
    } else if args.stdout || !res.is_file {
        if let Ok(text) = std::str::from_utf8(&res.data) {
            print!("{text}");
        } else {
            std::io::stdout().write_all(&res.data)?;
        }
    } else {
        // Default filename in current dir; the metadata filename is untrusted
        // input, so sanitize it to a bare name (no traversal, no absolute path).
        let fn_to_use = if res.filename.is_empty() {
            "extracted.bin".to_string()
        } else {
            crate::engine::sanitize_filename(&res.filename)
        };
        // Same overwrite protection as the explicit-output path: never truncate
        // a file the user did not name.
        if Path::new(&fn_to_use).exists() && !args.overwrite {
            return Err(StrHideError::Rejection(format!(
                "Refusing to overwrite existing file '{fn_to_use}'. Choose another -o path or pass --overwrite."
            )));
        }
        let mut f = File::create(&fn_to_use).map_err(|e| {
            let reason = match e.kind() {
                std::io::ErrorKind::PermissionDenied => "permission denied",
                _ => "the file could not be created",
            };
            StrHideError::General(format!("Cannot create '{fn_to_use}': {reason} [{e}]"))
        })?;
        f.write_all(&res.data)?;
        if !quiet {
            println!(
                "{}",
                t!(Msg::ReadOkExtracted, path = fn_to_use, bytes = res.raw_size)
            );
        }
    }

    Ok(())
}

fn handle_restore(args: RestoreArgs, cfg: &FileConfig, quiet: bool) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let multi = args.carrier.len() > 1;
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "removing hidden data from")?;
    if multi {
        preflight_batch(
            &args.carrier,
            args.in_place,
            args.output.as_deref(),
            output_dir,
            args.overwrite,
        )?;
    } else {
        let carrier = &args.carrier[0];
        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = target {
            check_overwrite(t, args.overwrite)?;
        }
    }
    // Mirror `write`: `remove` also honours the configured backup default
    // (`config.rs` documents `backup` as covering both commands).
    let backup = !args.no_backup && cfg.backup.unwrap_or(true);

    for_each_carrier(&args.carrier, quiet, |carrier| {
        let output =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = output {
            check_overwrite(t, args.overwrite)?;
        }
        // The user has already answered the overwrite question above, so the
        // library-level refusal is bypassed deliberately.
        let res = remove_carrier_with_options(
            carrier,
            output.as_deref(),
            password.as_deref(),
            backup,
            &crate::params::Profile::default(),
            args.overwrite,
        )?;
        print_remove_result(&res, quiet);
        Ok(())
    })
}

fn print_inspect_result(res: &crate::engine::InspectResult) {
    println!("{}", t!(Msg::InspectCarrier, val = res.carrier));
    println!("{}", t!(Msg::InspectFormat, val = res.format));
    println!("{}", t!(Msg::InspectHasHidden, val = res.has_hidden_data));
    if res.has_hidden_data {
        if let Some(s) = &res.strategy {
            println!("{}", t!(Msg::InspectStrategy, val = s));
        }
        if let Some(off) = res.ube_offset {
            println!("{}", t!(Msg::InspectUbeOffset, val = off));
        }
        if let Some(sz) = res.ube_total_size {
            println!("{}", t!(Msg::InspectUbeTotalSize, val = sz));
        }
        if let Some(enc) = res.is_encrypted {
            println!("{}", t!(Msg::InspectEncrypted, val = enc));
        }
        if let Some(stl) = res.is_stealth {
            println!("{}", t!(Msg::InspectStealth, val = stl));
        }
        if let Some(h) = &res.password_hint {
            println!("{}", t!(Msg::InspectPasswordHint, val = h));
        }
        if let Some(sz) = res.orig_host_size {
            println!("{}", t!(Msg::InspectOrigSize, val = sz));
        }
        if let Some(sha) = &res.orig_host_sha256 {
            println!("{}", t!(Msg::InspectOrigSha256, val = sha));
        }
        if let Some(meta) = &res.metadata {
            println!("{}", t!(Msg::InspectMetadata, val = meta));
        }
    }

    let auto_idx = res.strategies.iter().position(|c| c.available);
    println!("{}", t!(Msg::InspectCapacitiesHeader));
    for (idx, c) in res.strategies.iter().enumerate() {
        let auto = if Some(idx) == auto_idx {
            t!(Msg::InspectAutoPreference)
        } else {
            String::new()
        };
        let state = if c.available {
            String::new()
        } else {
            t!(Msg::InspectUnavailable)
        };
        let detail = c.note.as_deref().unwrap_or("");
        if detail.is_empty() {
            println!("  - {}{}{}: {}", c.strategy, auto, state, c.limit);
        } else {
            println!(
                "  - {}{}{}: {} - {}",
                c.strategy, auto, state, c.limit, detail
            );
        }
    }

    if let Some(cap) = &res.content_stego_capacity {
        println!();
        println!("{}", t!(Msg::InspectStegoHeader));
        println!("{}", t!(Msg::InspectStegoAlgorithm, val = cap.algorithm));
        println!("{}", t!(Msg::InspectStegoSlots, val = cap.available_slots));
        let kib = cap.max_raw_payload_bytes as f64 / 1024.0;
        println!(
            "{}",
            t!(
                Msg::InspectStegoMaxRaw,
                bytes = cap.max_raw_payload_bytes,
                kib = format_args!("{kib:.1}")
            )
        );
        let safe_kib = cap.recommended_max_bytes as f64 / 1024.0;
        println!(
            "{}",
            t!(
                Msg::InspectStegoSafeMax,
                bytes = cap.recommended_max_bytes,
                kib = format_args!("{safe_kib:.1}")
            )
        );
    }
}

fn handle_inspect(args: InspectArgs, cfg: &FileConfig, quiet: bool) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let is_batch = args.carrier.len() > 1 || args.carrier.iter().any(|p| p.is_dir());
    let files = expand_input_paths(&args.carrier, args.recursive, quiet)?;
    if files.is_empty() {
        return Err(StrHideError::General(
            "No files to inspect (empty input or empty directory)".into(),
        ));
    }

    if !is_batch && files.len() == 1 {
        let carrier = &files[0];
        let res = inspect_carrier(carrier, password.as_deref())?;
        if args.json {
            let mut val = serde_json::to_value(&res)?;
            if let serde_json::Value::Object(map) = &mut val {
                map.insert(
                    "banner".to_string(),
                    serde_json::Value::String(BANNER.to_string()),
                );
            }
            let json_str = serde_json::to_string_pretty(&val)?;
            println!("{json_str}");
        } else if !quiet {
            print_inspect_result(&res);
        }
        return Ok(());
    }

    let mut reports = Vec::with_capacity(files.len());
    let mut failures = 0usize;
    for carrier in &files {
        match inspect_carrier(carrier, password.as_deref()) {
            Ok(res) => {
                if !args.json && !quiet {
                    println!(
                        "=== [{}/{}] {} ===",
                        reports.len() + 1,
                        files.len(),
                        carrier.display()
                    );
                    print_inspect_result(&res);
                    println!();
                }
                reports.push(res);
            }
            Err(e) => {
                failures += 1;
                if !quiet {
                    eprintln!(
                        "{}",
                        t!(Msg::WarnInspectFailed, path = carrier.display(), err = e)
                    );
                }
            }
        }
    }

    if args.json {
        let mut val = serde_json::to_value(&reports)?;
        if let serde_json::Value::Array(arr) = &mut val {
            for item in arr {
                if let serde_json::Value::Object(map) = item {
                    map.insert(
                        "banner".to_string(),
                        serde_json::Value::String(BANNER.to_string()),
                    );
                }
            }
        }
        println!("{}", serde_json::to_string_pretty(&val)?);
    } else if !quiet {
        let hidden = reports.iter().filter(|r| r.has_hidden_data).count();
        println!(
            "{}",
            t!(
                Msg::InspectSummary,
                total = reports.len(),
                hidden = hidden,
                failed = failures
            )
        );
    }

    Ok(())
}

fn print_verify_result(res: &crate::engine::VerifyResult) {
    println!("{}", t!(Msg::InspectCarrier, val = res.carrier));
    println!("{}", t!(Msg::InspectFormat, val = res.format));
    println!(
        "{}",
        t!(
            Msg::VerifyL1,
            status = if res.level1_host.ok { "OK" } else { "FAIL" },
            detail = res.level1_host.detail
        )
    );
    println!(
        "{}",
        t!(
            Msg::VerifyL2,
            status = if res.level2_envelope.ok { "OK" } else { "FAIL" },
            detail = res.level2_envelope.detail
        )
    );
    println!(
        "{}",
        t!(
            Msg::VerifyL3,
            status = if res.level3_crypto.ok { "OK" } else { "FAIL" },
            detail = res.level3_crypto.detail
        )
    );
}

fn handle_verify(args: VerifyArgs, cfg: &FileConfig, quiet: bool) -> Result<i32, StrHideError> {
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let is_batch = args.carrier.len() > 1 || args.carrier.iter().any(|p| p.is_dir());
    let files = expand_input_paths(&args.carrier, args.recursive, quiet)?;
    if files.is_empty() {
        return Err(StrHideError::General(
            "No files to verify (empty input or empty directory)".into(),
        ));
    }

    if !is_batch && files.len() == 1 {
        let carrier = &files[0];
        let res = verify_carrier(carrier, password.as_deref())?;
        if args.json {
            let mut val = serde_json::to_value(&res)?;
            if let serde_json::Value::Object(map) = &mut val {
                map.insert(
                    "banner".to_string(),
                    serde_json::Value::String(BANNER.to_string()),
                );
            }
            let json_str = serde_json::to_string_pretty(&val)?;
            println!("{json_str}");
        } else if !quiet {
            print_verify_result(&res);
        }
        return Ok(if crate::engine::verify_passed(&res) {
            0
        } else {
            1
        });
    }

    let mut reports = Vec::with_capacity(files.len());
    let mut failures = 0usize;
    let mut any_failed = false;
    for carrier in &files {
        match verify_carrier(carrier, password.as_deref()) {
            Ok(res) => {
                let ok = crate::engine::verify_passed(&res);
                if !ok {
                    any_failed = true;
                }
                if !args.json && !quiet {
                    println!(
                        "=== [{}/{}] {} ===",
                        reports.len() + 1,
                        files.len(),
                        carrier.display()
                    );
                    print_verify_result(&res);
                    println!();
                }
                reports.push(res);
            }
            Err(e) => {
                failures += 1;
                any_failed = true;
                if !quiet {
                    eprintln!(
                        "{}",
                        t!(Msg::WarnVerifyFailed, path = carrier.display(), err = e)
                    );
                }
            }
        }
    }

    if args.json {
        let mut val = serde_json::to_value(&reports)?;
        if let serde_json::Value::Array(arr) = &mut val {
            for item in arr {
                if let serde_json::Value::Object(map) = item {
                    map.insert(
                        "banner".to_string(),
                        serde_json::Value::String(BANNER.to_string()),
                    );
                }
            }
        }
        println!("{}", serde_json::to_string_pretty(&val)?);
    } else if !quiet {
        let passed = reports
            .iter()
            .filter(|r| crate::engine::verify_passed(r))
            .count();
        let failed_cnt = reports.len() - passed;
        println!(
            "{}",
            t!(
                Msg::VerifySummary,
                total = reports.len(),
                passed = passed,
                failed = failed_cnt,
                unreadable = failures
            )
        );
    }

    Ok(if any_failed { 1 } else { 0 })
}

fn handle_scan(args: ScanArgs, quiet: bool) -> Result<i32, StrHideError> {
    use crate::analysis::scan_file;

    // Expand inputs: directories become file lists.
    let files = expand_input_paths(&args.input, args.recursive, quiet)?;

    if files.is_empty() {
        return Err(StrHideError::General(
            "No files to scan (empty input or empty directory)".into(),
        ));
    }

    let mut reports = Vec::with_capacity(files.len());
    let mut failures = 0usize;
    for f in &files {
        match scan_file(f) {
            Ok(r) => reports.push(r),
            Err(e) => {
                failures += 1;
                if !quiet {
                    eprintln!("{}", t!(Msg::WarnScanFailed, path = f.display(), err = e));
                }
            }
        }
    }

    if args.json {
        let mut val = serde_json::to_value(&reports)?;
        if let serde_json::Value::Array(arr) = &mut val {
            for item in arr {
                if let serde_json::Value::Object(map) = item {
                    map.insert(
                        "banner".to_string(),
                        serde_json::Value::String(BANNER.to_string()),
                    );
                }
            }
        }
        println!("{}", serde_json::to_string_pretty(&val)?);
    } else if quiet {
        // The exit code below is the entire quiet output: 1 when any report
        // reached "likely-hidden", 0 otherwise.
    } else {
        for r in &reports {
            let format_label = r.format.as_deref().unwrap_or("unknown");
            println!(
                "[{}] {} ({} - {} bytes) - risk {}/100",
                r.verdict.to_uppercase(),
                r.carrier,
                format_label,
                r.file_size,
                r.risk_score,
            );
            for finding in &r.findings {
                let tag = match finding.severity {
                    crate::analysis::Severity::Info => "-",
                    crate::analysis::Severity::Suspicious => "!",
                    crate::analysis::Severity::Likely => "!!",
                };
                println!("    {tag} [{}] {}", finding.detector, finding.detail);
            }
            for note in &r.notes {
                println!("    ? {note}");
            }
        }
        let findings_cnt = reports.iter().filter(|r| !r.findings.is_empty()).count();
        println!(
            "{}",
            t!(
                Msg::ScanSummary,
                total = reports.len(),
                findings = findings_cnt,
                failed = failures
            )
        );
    }

    // Gate-style exit code, independent of quiet: a "likely-hidden" verdict on
    // any report fails the scan (exit 1); lower confidence ("low"/"suspicious")
    // and per-file scan failures stay at 0 — they are reported in the JSON or
    // in the human summary line instead.
    let likely_hidden = reports.iter().any(|r| r.verdict == "likely-hidden");
    Ok(if likely_hidden { 1 } else { 0 })
}

/// Walk a directory non-recursively.
///
/// Individual entries that cannot be read (permissions, a broken symlink, a
/// device that vanished mid-walk) are skipped with a warning instead of
/// aborting the whole batch: one unreadable file must not cost the user every
/// other report. Same policy as [`expand_input_paths`] for missing paths.
fn walkdir_flat(dir: &Path, quiet: bool) -> Result<Vec<PathBuf>, StrHideError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if !quiet {
                    eprintln!("[WARN] Cannot read an entry in {}: {e}", dir.display());
                }
                continue;
            }
        };
        match entry.file_type() {
            Ok(ft) if ft.is_file() => out.push(entry.path()),
            Ok(_) => {}
            Err(e) => {
                if !quiet {
                    eprintln!("[WARN] Cannot stat {}: {e}", entry.path().display());
                }
            }
        }
    }
    Ok(out)
}

fn walkdir_recursive(dir: &Path, quiet: bool) -> Result<Vec<PathBuf>, StrHideError> {
    let mut out = Vec::new();
    push_files_recursive(dir, &mut out, quiet)?;
    Ok(out)
}

fn push_files_recursive(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    quiet: bool,
) -> Result<(), StrHideError> {
    // `entry.file_type()` does not follow symlinks, so a link to a directory is
    // reported as a file here and is never recursed into: no visited set is
    // needed to rule out cycles.
    for entry in std::fs::read_dir(dir)? {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if !quiet {
                    eprintln!("[WARN] Cannot read an entry in {}: {e}", dir.display());
                }
                continue;
            }
        };
        let path = entry.path();
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => push_files_recursive(&path, out, quiet)?,
            Ok(_) => out.push(path),
            Err(e) => {
                if !quiet {
                    eprintln!("[WARN] Cannot stat {}: {e}", path.display());
                }
            }
        }
    }
    Ok(())
}

fn expand_input_paths(
    inputs: &[PathBuf],
    recursive: bool,
    quiet: bool,
) -> Result<Vec<PathBuf>, StrHideError> {
    let mut files = Vec::new();
    for entry in inputs {
        if entry.is_dir() {
            files.extend(if recursive {
                walkdir_recursive(entry, quiet)?
            } else {
                walkdir_flat(entry, quiet)?
            });
        } else if entry.is_file() {
            files.push(entry.clone());
        } else if !quiet {
            eprintln!("{}", t!(Msg::WarnSkippedMissing, path = entry.display()));
        }
    }
    Ok(files)
}

fn handle_list(args: ListArgs) -> Result<(), StrHideError> {
    if args.json {
        #[derive(serde::Serialize)]
        struct ListStrategyItem {
            strategy: String,
            limit: String,
        }
        #[derive(serde::Serialize)]
        struct ListFormatItem {
            format: String,
            strategies: Vec<ListStrategyItem>,
        }
        #[derive(serde::Serialize)]
        struct ListAlgorithmItem {
            algorithm: String,
            domain: String,
            description: String,
        }
        #[derive(serde::Serialize)]
        struct ListReport {
            banner: String,
            formats: Vec<ListFormatItem>,
            stego_algorithms: Vec<ListAlgorithmItem>,
        }

        let mut formats = Vec::new();
        for adapter in ADAPTERS {
            let format = adapter.format_name().to_string();
            let mut strategies = Vec::new();
            for cap in adapter.strategy_capacities(None) {
                strategies.push(ListStrategyItem {
                    strategy: cap.strategy.to_string(),
                    limit: cap.limit.to_string(),
                });
            }
            formats.push(ListFormatItem { format, strategies });
        }

        let mut stego_algorithms = Vec::new();
        for (id, domain, desc) in crate::stego::CostModelRegistry::list_algorithms() {
            stego_algorithms.push(ListAlgorithmItem {
                algorithm: id.to_string(),
                domain: domain.to_string(),
                description: desc.to_string(),
            });
        }

        let report = ListReport {
            banner: BANNER.to_string(),
            formats,
            stego_algorithms,
        };

        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    // Static reference table: constants come from the adapters themselves (via
    // `strategy_capacities(None)`), so the table cannot drift from the code.
    // Carrier-specific limits are answered by `inspect <carrier>`.
    println!("{:<8} {:<15} Limit", "Format", "Strategy");
    println!("{:-<8} {:-<15} {:-<48}", "", "", "");
    for adapter in ADAPTERS {
        let format = adapter.format_name();
        for cap in adapter.strategy_capacities(None) {
            println!("{format:<8} {:<15} {}", cap.strategy, cap.limit);
        }
    }
    println!();
    println!("{}", t!(Msg::ListCarrierDependentNotice));

    println!("{}", t!(Msg::ListStegoAlgorithmsHeader));
    println!("{:<8} {:<15} Description", "Algorithm", "Target Domain");
    println!("{:-<8} {:-<15} {:-<48}", "", "", "");
    for (id, domain, desc) in crate::stego::CostModelRegistry::list_algorithms() {
        println!("{id:<8} {:<15} {desc}", domain);
    }
    println!();

    Ok(())
}

/// Warn when the caller tuned stego parameters away from their defaults.
///
/// Slot selection depends on the cost map, which depends on these
/// parameters, so extraction only succeeds when they match the embed-time
/// values. The envelope deliberately carries no parameter fingerprint (the
/// salt lives inside the header slots, which are themselves cost-map
/// dependent), so a mismatch is indistinguishable from a wrong password --
/// this warning is the mitigation. It is printed unconditionally, never
/// keyed on the extraction outcome, so the message cannot be used as a
/// detection oracle.
fn warn_nondefault_stego_params(options: &crate::stego::StegoOptions, quiet: bool) {
    if quiet {
        return;
    }
    let sp = &options.spatial_params;
    let d_sp = crate::stego::SpatialParams::default();
    let mut flags: Vec<String> = Vec::new();
    if sp.p1_window != d_sp.p1_window {
        flags.push(format!("--p1-window {}", sp.p1_window));
    }
    if sp.p2_window != d_sp.p2_window {
        flags.push(format!("--p2-window {}", sp.p2_window));
    }
    if sp.exclusion_percentile != d_sp.exclusion_percentile {
        flags.push(format!("--exclusion-rate {}", sp.exclusion_percentile));
    }
    if flags.is_empty() {
        return;
    }
    eprintln!(
        "[WARN] Non-default stego parameters: {}. Extraction succeeds only with the same values; a mismatch fails as 'No valid payload found'.",
        flags.join(" ")
    );
}

/// Apply `--stc-h` to the option set.
fn apply_stc_h(
    options: &mut crate::stego::StegoOptions,
    stc_h: Option<u8>,
) -> Result<(), StrHideError> {
    if let Some(h) = stc_h {
        options.spatial_params.stc_h = h;
        options.jpeg_params.stc_h = h;
    }
    options.spatial_params.validate()?;
    options.jpeg_params.validate()?;
    Ok(())
}

/// Assemble the stego option set for `embed`.
///
/// The `--capacity` probe and the real embed used to build this list twice, and
/// the two copies had drifted: only the embed path applied `--stc-h` and warned
/// about non-default parameters, so a probe could report a capacity for a
/// different configuration than the one that was about to be used. One builder,
/// with the embed-only extras behind `embed_extras`.
fn embed_stego_options(
    args: &EmbedArgs,
    password: Option<&str>,
    quiet: bool,
    embed_extras: bool,
) -> Result<crate::stego::StegoOptions, StrHideError> {
    let mut options = crate::stego::StegoOptions {
        algorithm: args.algorithm.clone(),
        password: password.map(str::to_string),
        stego_domain: args.stego_domain.clone(),
        ..Default::default()
    };

    if let Some(er) = args.exclusion_rate {
        options.spatial_params.exclusion_percentile = er;
    }
    if let Some(nw) = args.neighbor_weight {
        options.jpeg_params.neighbor_weight = nw;
    }
    if let Some(budget) = args.slot_budget {
        options.jpeg_params.slot_budget = Some(budget);
    }
    if let Some(suite) = args.cipher_suite {
        options.jpeg_params.cipher_suite = suite;
    }
    if let Some(p1) = args.p1_window {
        options.spatial_params.p1_window = p1;
    }
    if let Some(p2) = args.p2_window {
        options.spatial_params.p2_window = p2;
    }

    let safety_level = match args.safety.as_deref() {
        Some(s) => match crate::stego::SafetyLevel::parse(s) {
            Some(lvl) => lvl,
            None => {
                return Err(StrHideError::General(format!(
                    "Invalid safety level '{s}'. Supported: 'paranoid', 'high', 'balanced'"
                )));
            }
        },
        None => crate::stego::SafetyLevel::High,
    };
    options.safety_level = safety_level;
    if args.enforce_safety {
        options.safety_enforcement = crate::stego::SafetyEnforcement::Enforced;
    }

    apply_stc_h(&mut options, args.stc_h)?;
    if embed_extras {
        warn_nondefault_stego_params(&options, quiet);
    }
    Ok(options)
}

fn handle_embed(args: EmbedArgs, cfg: &FileConfig, quiet: bool) -> Result<(), StrHideError> {
    if args.capacity {
        // The probe uses the same credentials the embed would: they key the
        // spatial header permutation, which changes which pixels are available
        // to the payload.
        let capacity_password = resolve_password(
            args.passwords.password.as_deref(),
            args.passwords.password_file.as_deref(),
            cfg,
            false,
            false,
        )?;
        for carrier in &args.carrier {
            let carrier_bytes = std::fs::read(carrier)?;
            let options = embed_stego_options(&args, capacity_password.as_deref(), true, false)?;
            let cap = crate::stego::probe_carrier_capacity_with_profile(
                &carrier_bytes,
                &options,
                &crate::params::Profile::default(),
            )?;
            println!("{}", t!(Msg::StegoProbeHeader, path = carrier.display()));
            println!("{}", t!(Msg::StegoProbeFormat, val = cap.format));
            println!("{}", t!(Msg::StegoProbeAlgorithm, val = cap.algorithm));
            println!(
                "{}",
                t!(Msg::StegoProbeTotalElements, val = cap.total_elements)
            );
            println!(
                "{}",
                t!(Msg::StegoProbePayloadSlots, val = cap.available_slots)
            );
            let kib = cap.max_raw_payload_bytes as f64 / 1024.0;
            println!(
                "{}",
                t!(
                    Msg::StegoProbeMaxRaw,
                    bytes = cap.max_raw_payload_bytes,
                    kib = format_args!("{kib:.1}")
                )
            );
            let safe_kib = cap.recommended_max_bytes as f64 / 1024.0;
            println!(
                "{}",
                t!(
                    Msg::StegoProbeRecommended,
                    bytes = cap.recommended_max_bytes,
                    kib = format_args!("{safe_kib:.1}"),
                    level = cap.safety_level,
                    bpp = format_args!("{:.2}", cap.safety_bpp_limit)
                )
            );
            println!(
                "{}",
                t!(Msg::StegoProbeEstChanges, rate = cap.estimated_change_rate)
            );
        }
        return Ok(());
    }

    // 1. Resolve password
    let encrypt = args.encrypt || cfg.encrypt.unwrap_or(false);
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        encrypt,
        true,
    )?;
    let stego_secret = resolve_stego_secret(args.stego_secret.as_deref(), cfg);
    let stego_domain = resolve_stego_domain(args.stego_domain.as_deref(), cfg);
    let profile = stego_profile(stego_secret, stego_domain);

    // 2. Resolve payload bytes (shared with `write`).
    let payload_bytes =
        match resolve_payload(&args.payload, args.unescape, cfg, PayloadFlavor::Bytes)? {
            ResolvedPayload::Stdin => {
                let mut buf = Vec::new();
                std::io::stdin().read_to_end(&mut buf)?;
                buf
            }
            ResolvedPayload::File(f) => std::fs::read(f)?,
            ResolvedPayload::TextFile(p) => std::fs::read(p)?,
            ResolvedPayload::Text(t) => t.into_bytes(),
            ResolvedPayload::Bytes(b) => b,
        };

    if payload_bytes.is_empty() {
        return Err(StrHideError::General("Payload cannot be empty".into()));
    }

    let multi = args.carrier.len() > 1;
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "embedding into")?;
    for carrier in &args.carrier {
        if !carrier.exists() {
            return Err(StrHideError::General(format!(
                "Carrier file '{}' not found",
                carrier.display()
            )));
        }
        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref t) = target {
            check_overwrite(t, args.overwrite)?;
        }
    }

    for_each_carrier(&args.carrier, quiet, |carrier| {
        let carrier_bytes = std::fs::read(carrier)?;

        let options = embed_stego_options(&args, password.as_deref(), quiet, true)?;

        if !quiet
            && options.safety_enforcement == crate::stego::SafetyEnforcement::Advisory
            && let Ok(cap) = crate::stego::probe_carrier_capacity_with_profile(
                &carrier_bytes,
                &options,
                &profile,
            )
            && payload_bytes.len() > cap.recommended_max_bytes
        {
            let bpp = (payload_bytes.len() * 8) as f64 / cap.total_elements as f64;
            eprintln!(
                "[WARN] Payload ({} bytes, bpp {:.4}) exceeds recommended safety threshold ({} bytes, tier: '{}', bpp <= {:.2}). Detection risk is elevated.",
                payload_bytes.len(),
                bpp,
                cap.recommended_max_bytes,
                options.safety_level.as_str(),
                options.safety_level.bpp_limit()
            );
        }

        let stego_bytes = crate::stego::embed_carrier_with_profile(
            &carrier_bytes,
            &payload_bytes,
            &options,
            &profile,
        )?;

        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(ref dest) = target {
            check_overwrite(dest, args.overwrite)?;
        }
        let dest = target.unwrap_or_else(|| carrier.to_path_buf());

        let backup = !args.no_backup && cfg.backup.unwrap_or(true);
        let backup_created =
            crate::engine::commit_carrier_bytes(carrier, &dest, &stego_bytes, backup, true)?;

        if let Some(ref bak) = backup_created
            && !quiet
        {
            println!("{}", t!(Msg::InfoBackupCreated, path = bak.display()));
        }

        if !quiet {
            let is_inplace = crate::engine::same_file(carrier, &dest);
            if is_inplace {
                println!(
                    "{}",
                    t!(
                        Msg::EmbedOkInPlace,
                        bytes = payload_bytes.len(),
                        carrier = carrier.display()
                    )
                );
            } else {
                println!(
                    "{}",
                    t!(
                        Msg::EmbedOkDest,
                        bytes = payload_bytes.len(),
                        carrier = carrier.display(),
                        dest = dest.display()
                    )
                );
            }
        }
        Ok(())
    })
}

fn handle_extract(args: ExtractArgs, cfg: &FileConfig, quiet: bool) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let carrier_bytes = std::fs::read(&args.carrier)?;

    let stego_secret = resolve_stego_secret(args.stego_secret.as_deref(), cfg);
    let stego_domain = resolve_stego_domain(args.stego_domain.as_deref(), cfg);
    let profile = stego_profile(stego_secret, stego_domain);
    let mut options = crate::stego::StegoOptions {
        algorithm: args.algorithm,
        password,
        ..Default::default()
    };

    if let Some(er) = args.exclusion_rate {
        options.spatial_params.exclusion_percentile = er;
    }
    if let Some(nw) = args.neighbor_weight {
        options.jpeg_params.neighbor_weight = nw;
    }
    if let Some(p1) = args.p1_window {
        options.spatial_params.p1_window = p1;
    }
    if let Some(p2) = args.p2_window {
        options.spatial_params.p2_window = p2;
    }
    warn_nondefault_stego_params(&options, quiet);

    let payload = crate::stego::extract_carrier_with_profile(&carrier_bytes, &options, &profile)?;

    if let Some(ref out_path) = args.output {
        let dest = if out_path.is_dir() {
            out_path.join("extracted.bin")
        } else {
            out_path.clone()
        };
        check_overwrite(&dest, args.overwrite)?;
        std::fs::write(&dest, &payload)?;
        if !quiet {
            println!(
                "{}",
                t!(Msg::ExtractOk, bytes = payload.len(), path = dest.display())
            );
        }
    } else if args.stdout {
        std::io::stdout().write_all(&payload)?;
    } else {
        // Output to stdout or default file
        if let Ok(text) = std::str::from_utf8(&payload) {
            print!("{text}");
            if !text.ends_with('\n') {
                println!();
            }
        } else {
            let dest = PathBuf::from("extracted.bin");
            check_overwrite(&dest, args.overwrite)?;
            std::fs::write(&dest, &payload)?;
            if !quiet {
                println!("{}", t!(Msg::ExtractBinaryDetected, bytes = payload.len()));
            }
        }
    }

    Ok(())
}

/// Run `action` over every carrier.
///
/// Single-carrier runs keep the previous output and error reporting exactly:
/// no summary line, and the caller still prints `[ERROR]` once. Multi-carrier
/// runs stop at the first failure and report how far they got — each
/// write/remove is atomic per carrier, so "N succeeded, M not attempted" is
/// accurate, but earlier carriers stay modified.
fn for_each_carrier<F>(carriers: &[PathBuf], quiet: bool, mut action: F) -> Result<(), StrHideError>
where
    F: FnMut(&Path) -> Result<(), StrHideError>,
{
    let total = carriers.len();
    let mut done = 0usize;
    for carrier in carriers {
        match action(carrier) {
            Ok(()) => done += 1,
            Err(e) => {
                if total > 1 && !quiet {
                    eprintln!("{}", t!(Msg::FailCarrier, path = carrier.display()));
                    let unattempted = total - done - 1;
                    println!(
                        "{}",
                        t!(
                            Msg::SummaryBatchPartial,
                            done = done,
                            total = total,
                            unattempted = unattempted
                        )
                    );
                }
                return Err(e);
            }
        }
    }
    if total > 1 && !quiet {
        println!("{}", t!(Msg::SummaryBatchAll, done = done, total = total));
    }
    Ok(())
}

/// Batch `-o` rule: with more than one carrier the target must be an existing
/// directory, because one file path cannot name several outputs.
///
/// An existing directory is accepted for a *single* carrier too and means "put
/// the result inside it, keeping the carrier's name" — the same semantics
/// `read -o <dir>` already had.
fn batch_output_dir<'a>(
    output: Option<&'a Path>,
    multi: bool,
    action: &str,
) -> Result<Option<&'a Path>, StrHideError> {
    let Some(path) = output else {
        return Ok(None);
    };
    if path.is_dir() {
        return Ok(Some(path));
    }
    if multi {
        return Err(StrHideError::General(format!(
            "'-o {}' must be an existing directory when {action} multiple carriers",
            path.display()
        )));
    }
    Ok(None)
}

/// Derive default output path by appending suffix before extension, e.g. "photo.png" -> "photo-out.png"
pub fn derive_default_output_path(carrier: &Path, suffix: &str) -> PathBuf {
    let parent = carrier.parent();
    let file_name = carrier
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let (stem, ext) = match carrier.extension().and_then(|s| s.to_str()) {
        Some(ext) if !ext.is_empty() => {
            let stem = carrier
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(file_name);
            (stem, Some(ext))
        }
        _ => (file_name, None),
    };
    let new_name = match ext {
        Some(ext) => format!("{stem}{suffix}.{ext}"),
        None => format!("{stem}{suffix}"),
    };
    match parent {
        Some(p) if !p.as_os_str().is_empty() => p.join(new_name),
        _ => PathBuf::from(new_name),
    }
}

pub fn check_overwrite(target: &Path, overwrite: bool) -> Result<(), StrHideError> {
    if target.exists() && !overwrite {
        return Err(StrHideError::Rejection(format!(
            "Refusing to overwrite existing file '{}'. Choose another -o path or pass --overwrite.",
            target.display()
        )));
    }
    Ok(())
}

/// Determine where the carrier's output should be written:
/// - If `in_place`: returns `None` (meaning in-place modification).
/// - If `output_dir`: returns `Some(dir.join(carrier.file_name()))`.
/// - If `output`: returns `Some(output.to_path_buf())`.
/// - Default (not in-place, no explicit output): returns `Some(derive_default_output_path(carrier, "-out"))`.
fn resolve_carrier_target(
    carrier: &Path,
    in_place: bool,
    output: Option<&Path>,
    output_dir: Option<&Path>,
) -> Result<Option<PathBuf>, StrHideError> {
    if in_place {
        return Ok(None);
    }
    if let Some(dir) = output_dir {
        let name = carrier.file_name().ok_or_else(|| {
            StrHideError::General(format!(
                "Cannot derive an output filename from '{}'",
                carrier.display()
            ))
        })?;
        return Ok(Some(dir.join(name)));
    }
    if let Some(out) = output {
        return Ok(Some(out.to_path_buf()));
    }
    Ok(Some(derive_default_output_path(carrier, "-out")))
}

/// Validate a whole batch before the first carrier is modified: every carrier
/// must exist, be a regular file, be a supported format, and resolve to a unique
/// output.
fn preflight_batch(
    carriers: &[PathBuf],
    in_place: bool,
    output: Option<&Path>,
    output_dir: Option<&Path>,
    overwrite: bool,
) -> Result<(), StrHideError> {
    let mut seen_carriers = HashSet::new();
    let mut seen_targets = HashSet::new();
    for carrier in carriers {
        if !carrier.exists() {
            return Err(StrHideError::General(format!(
                "Carrier file '{}' not found",
                carrier.display()
            )));
        }
        if carrier.is_dir() {
            return Err(StrHideError::General(format!(
                "'{}' is a directory, not a carrier file",
                carrier.display()
            )));
        }
        {
            let mut f = File::open(carrier)?;
            find_adapter_or_reject(&mut f, &carrier.display().to_string())?;
        }
        let identity = std::fs::canonicalize(carrier).unwrap_or_else(|_| carrier.clone());
        if !seen_carriers.insert(identity.clone()) {
            return Err(StrHideError::General(format!(
                "Carrier '{}' is listed more than once",
                carrier.display()
            )));
        }
        let target = match resolve_carrier_target(carrier, in_place, output, output_dir)? {
            Some(t) => t,
            None => identity,
        };
        if target.exists() && !in_place && !overwrite {
            return Err(StrHideError::Rejection(format!(
                "Refusing to overwrite existing file '{}'. Choose another -o path or pass --overwrite.",
                target.display()
            )));
        }
        if !seen_targets.insert(target.clone()) {
            return Err(StrHideError::General(format!(
                "Two carriers would write to the same file '{}'. Rename one of them or keep them in separate directories.",
                target.display()
            )));
        }
    }
    Ok(())
}

fn print_write_result(res: &WriteResult, quiet: bool) {
    if quiet {
        return;
    }
    println!(
        "{}",
        t!(Msg::WriteOk, carrier = res.carrier, strategy = res.strategy)
    );
    println!(
        "{}",
        t!(Msg::WritePayloadUbe, raw = res.raw_size, ube = res.ube_size)
    );
    if let Some(note) = &res.strategy_note {
        println!("{}", t!(Msg::WriteStrategyNote, note = note));
    }
    if let Some(hint) = &res.password_hint {
        println!("{}", t!(Msg::WritePasswordHint, hint = hint));
    }
    if let Some(bak) = &res.backup_file {
        println!("{}", t!(Msg::WriteBackupNote, path = bak));
    }
    if let Some(warn) = &res.warning {
        eprintln!("{}", t!(Msg::WriteWarningNote, warn = warn));
    }
}

fn print_remove_result(res: &RemoveResult, quiet: bool) {
    if quiet {
        return;
    }
    println!("{}", t!(Msg::RestoreOk, carrier = res.carrier));
    println!("{}", t!(Msg::RestoreSize, bytes = res.restored_size));
    println!("{}", t!(Msg::RestoreSha256, sha = res.restored_sha256));
    if let Some(bak) = &res.backup_file {
        println!("{}", t!(Msg::RestoreBackupNote, path = bak));
    }
}

/// Decode C-style escape sequences, mirroring the Python implementation
/// character for character.
///
/// Supported: `\n \r \t \a \b \f \v \\ \' \"`, octal `\ooo` (1-3 digits, up to
/// U+01FF), `\xHH` (exactly 2 hex digits), `\uHHHH` (exactly 4, surrogate
/// pairs combined, lone surrogates become U+FFFD), `\UHHHHHHHH` (8 hex digits).
/// Malformed or unknown escapes are preserved verbatim. Non-ASCII input is
/// kept as UTF-8 text (the previous Python path re-decoded it through latin-1
/// and mangled it).
fn unescape_string(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c != '\\' || i + 1 >= chars.len() {
            out.push(c);
            i += 1;
            continue;
        }
        let esc = chars[i + 1];
        match esc {
            'n' => {
                out.push('\n');
                i += 2;
            }
            'r' => {
                out.push('\r');
                i += 2;
            }
            't' => {
                out.push('\t');
                i += 2;
            }
            'a' => {
                out.push('\u{07}');
                i += 2;
            }
            'b' => {
                out.push('\u{08}');
                i += 2;
            }
            'f' => {
                out.push('\u{0C}');
                i += 2;
            }
            'v' => {
                out.push('\u{0B}');
                i += 2;
            }
            '\\' => {
                out.push('\\');
                i += 2;
            }
            '\'' => {
                out.push('\'');
                i += 2;
            }
            '"' => {
                out.push('"');
                i += 2;
            }
            '0'..='7' => {
                let mut value = 0u32;
                let mut consumed = 0;
                while consumed < 3 {
                    match chars.get(i + 1 + consumed).and_then(|c| c.to_digit(8)) {
                        Some(d) => {
                            value = value * 8 + d;
                            consumed += 1;
                        }
                        None => break,
                    }
                }
                out.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
                i += 1 + consumed;
            }
            'x' => {
                if let Some(v) = read_hex(&chars, i + 2, 2) {
                    out.push(char::from_u32(v).unwrap_or('\u{FFFD}'));
                    i += 4;
                } else {
                    out.push('\\');
                    i += 1;
                }
            }
            'u' => {
                let Some(v) = read_hex(&chars, i + 2, 4) else {
                    out.push('\\');
                    i += 1;
                    continue;
                };
                let mut code = v;
                let mut consumed = 4;
                // Combine a UTF-16 surrogate pair written as two \u escapes.
                // `consumed` counts characters after the leading "\u": the
                // second escape adds its own 6 characters ("\u" + 4 digits).
                if (0xD800..=0xDBFF).contains(&code)
                    && let Some(low) = read_hex(&chars, i + 8, 4)
                    && (0xDC00..=0xDFFF).contains(&low)
                {
                    code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                    consumed = 10;
                }
                out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                i += 2 + consumed;
            }
            'U' => {
                if let Some(v) = read_hex(&chars, i + 2, 8) {
                    out.push(char::from_u32(v).unwrap_or('\u{FFFD}'));
                    i += 10;
                } else {
                    out.push('\\');
                    i += 1;
                }
            }
            _ => {
                out.push('\\');
                out.push(esc);
                i += 2;
            }
        }
    }
    out
}

/// Read exactly `count` hex digits starting at `start`, or `None`.
fn read_hex(chars: &[char], start: usize, count: usize) -> Option<u32> {
    let mut value = 0u32;
    for k in 0..count {
        let d = chars.get(start + k)?.to_digit(16)?;
        value = value * 16 + d;
    }
    Some(value)
}
