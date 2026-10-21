use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::config::{self, FileConfig};
use crate::engine::{
    PayloadSource, RemoveResult, WriteOptions, WriteResult, inspect_carrier, read_carrier_with,
    remove_carrier, verify_carrier, write_carrier,
};
use crate::errors::StrHideError;
use crate::router::{ADAPTERS, find_adapter_or_reject};

pub const STRHIDE_VERSION_INFO: &str = env!("STRHIDE_VERSION_INFO");
pub const STRHIDE_GIT_HASH: &str = env!("STRHIDE_GIT_HASH");
pub const STRHIDE_BUILD_TIME: &str = env!("STRHIDE_BUILD_TIME");
pub const BANNER: &str = concat!("strhide ", env!("STRHIDE_VERSION_INFO"));

#[derive(Parser, Debug)]
#[command(
    name = "strhide",
    version = STRHIDE_VERSION_INFO,
    about = "Smart multi-format lossless container data hiding tool"
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

const WRITE_AFTER_HELP: &str = "\
Payload sources are mutually exclusive: -d/--data, -t/--text, --text-file,
--text-base64, and --stdin. When none is given, the STRHIDE_TEXT environment
variable is used as a last-resort fallback.

--stealth implies password protection: provide -p/--password, --password-file,
or STRHIDE_PASSWORD; a password hint (-H) is rejected in stealth mode.
The payload is always encrypted in the envelope; -e/--encrypt only controls
what happens when no password source is present (prompt or fail).

Examples:
  strhide write photo.png -t \"meet me at 7\"                 # writes to photo-out.png
  strhide write photo.png -t \"meet me at 7\" --in-place      # writes to photo.png in place
  strhide write report.pdf -d secret.zip -p \"S3cret!\" -H \"my usual one\"
  strhide write photo.png -t \"line1\\nline2\" --unescape
  cat secret.txt | strhide write image.jpg --stdin
  strhide write a.png b.png c.png -t \"secret\" -o done/
  strhide read done/a.png                  # extract the payload again
";

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

const READ_AFTER_HELP: &str = "\
With neither -o/--output nor --stdout:
  * file payloads are written into the current directory under the filename
    stored inside the envelope (reduced to a bare name; an existing file is
    never overwritten without --overwrite);
  * text payloads are printed to standard output.

Examples:
  strhide read photo.png                   # file -> ./<stored name>, text -> stdout
  strhide read photo.png -o recovered.zip  # extraction to an explicit path
  strhide read photo.png --stdout          # always print to standard output
  strhide read locked.png                  # shows the stored hint before prompting
";

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
        long = "unescape",
        help = "Decode C-style escape sequences (\\n, \\r, \\t, ...) in the -t/--text payload before embedding"
    )]
    pub unescape: bool,

    // --- Fine-tuning parameters for custom obfuscation and anti-detection ---
    #[arg(
        long = "exclusion-rate",
        value_name = "FLOAT",
        help = "Fine-tune: fraction of smoothest regions excluded from embedding (0.0 .. 0.8; default 0.30 for PNG, 0.20 for JPEG)"
    )]
    pub exclusion_rate: Option<f64>,

    #[arg(
        long = "neighbor-weight",
        value_name = "FLOAT",
        help = "Fine-tune (JPEG UERD): weight applied to 8-neighborhood block energies (default: 0.25)"
    )]
    pub neighbor_weight: Option<f64>,

    #[arg(
        long = "min-abs-coeff",
        value_name = "INT",
        help = "Fine-tune (JPEG UERD): minimum absolute AC coefficient eligible for embedding (default: 2)"
    )]
    pub min_abs_coeff: Option<i16>,

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
        long = "codec",
        value_name = "NAME",
        help = "Matrix-coding layer for the payload bits, PNG and JPEG alike: hamming (default) or stc. \
                The choice is recorded in the carrier, so extract never needs this flag."
    )]
    pub codec: Option<String>,

    #[arg(
        long = "stc-h",
        value_name = "INT",
        help = "Fine-tune (STC): trellis constraint height, 4..10 (default: 8). Larger is slower and slightly better."
    )]
    pub stc_h: Option<u8>,

    #[arg(
        long = "stc-u",
        value_name = "INT",
        help = "Fine-tune (STC): elements per syndrome row, 1..3 (default: 1). \
                Larger spreads the message over more slots: fewer changed slots and lower weighted \
                distortion, but roughly 1/u of the capacity."
    )]
    pub stc_u: Option<u8>,
}

const EMBED_AFTER_HELP: &str = "\
Content-adaptive steganography (HILL for PNG, UERD for JPEG) embeds data directly
into image texture/coefficients, making it immune to container metadata stripping.
Because pixel/coefficient values are modified, this operation cannot be reversed
to the original carrier bit-for-bit.

Examples:
  strhide embed photo.jpg -t \"secret message\"                 # writes to photo-out.jpg
  strhide embed photo.jpg -t \"secret message\" --in-place      # writes to photo.jpg in place
  strhide embed photo.jpg -t \"secret message\" -o out.jpg
  strhide embed graphic.png -d secret.zip -p \"P@ss!\" -o out.png
  strhide embed photo.jpg -t \"custom tuning\" --exclusion-rate 0.40 -o out.png
";

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

    // Fine-tuning parameters matching custom embedding parameters
    #[arg(long = "exclusion-rate", value_name = "FLOAT")]
    pub exclusion_rate: Option<f64>,

    #[arg(long = "neighbor-weight", value_name = "FLOAT")]
    pub neighbor_weight: Option<f64>,

    #[arg(long = "min-abs-coeff", value_name = "INT")]
    pub min_abs_coeff: Option<i16>,

    #[arg(long = "p1-window", value_name = "INT")]
    pub p1_window: Option<usize>,

    #[arg(long = "p2-window", value_name = "INT")]
    pub p2_window: Option<usize>,
}

const EXTRACT_AFTER_HELP: &str = "\
Extracts payload embedded via content-adaptive steganography (embed).
Format is automatically detected (PNG or JPEG).

Examples:
  strhide extract out.jpg -p \"P@ss!\"               # text prints to stdout
  strhide extract out.jpg -p \"P@ss!\" --stdout      # force stdout
  strhide extract out.png -p \"P@ss!\" -o secret.zip # extracts to file
";

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

const RESTORE_AFTER_HELP: &str = "\
Examples:
  strhide restore photo.png                 # writes clean copy to photo-out.png
  strhide restore photo.png --in-place      # restore in place, keeping photo.png.bak
  strhide restore photo.png -o clean.png    # write the restored copy to 'clean.png'
  strhide restore a.png b.png c.png         # batch restoration to *-out.png
  strhide restore a.png b.png -o clean_dir/ # batch restoration into directory

Restoration is verified loss-free: the restored SHA-256 must match the
original host recorded in the envelope, or the command fails loudly.
";

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

const INSPECT_AFTER_HELP: &str = "\
Examples:
  strhide inspect photo.png             # inspect one carrier
  strhide inspect a.png b.png c.png     # inspect multiple carriers
  strhide inspect dir/ -r               # inspect directory tree recursively
  strhide inspect photo.png --json      # report as JSON object
  strhide inspect a.png b.png --json    # report as JSON array
";

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

const VERIFY_AFTER_HELP: &str = "\
Levels:
  Level 1 - host container format is intact (PNG/JPEG/... structure)
  Level 2 - hidden envelope boundary found and correctly bounded
  Level 3 - envelope contents (crypto + payload) verified; needs a password

Exit codes: 0 when Level 1 and Level 2 pass, 1 otherwise. Level 3 failures are
reported but do not change the exit code, matching the Python CLI.

Examples:
  strhide verify photo.png              # verify one carrier
  strhide verify a.png b.png c.png      # verify multiple carriers
  strhide verify dir/ -r                # verify directory tree recursively
  strhide verify photo.png --json       # report as JSON object
  strhide verify a.png b.png --json     # report as JSON array
";

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

const SCAN_AFTER_HELP: &str = "\
Examples:
  strhide scan photo.png               # one file
  strhide scan dir/ -r                 # a whole directory tree
  strhide scan dir1/ dir2/ --json      # every report as JSON

Exit codes: 0 when no report reaches \"likely-hidden\"; 1 when at least one
does. Lower-confidence findings (\"low\"/\"suspicious\") and per-file scan
failures stay at exit 0 - they show up in the report/--json instead, so use
--json (which includes verdict and risk_score) to gate on them.

Combine with the global -q/--quiet to scan silently and act on the exit code:
  strhide scan downloads/ -r -q || echo suspicious files found

Inputs are treated as unknown suspects, not strhide carriers: findings cover
structural and statistical anomalies from any tool, known or unknown.
";

pub fn prompt_password(confirm: bool) -> Result<String, StrHideError> {
    let pwd = rpassword::prompt_password("Enter password: ")
        .map_err(|e| StrHideError::General(format!("Failed to read password: {e}")))?;
    if pwd.is_empty() {
        return Err(StrHideError::Password("Password cannot be empty".into()));
    }
    if confirm {
        let pwd2 = rpassword::prompt_password("Confirm password: ").map_err(|e| {
            StrHideError::General(format!("Failed to read password confirmation: {e}"))
        })?;
        if pwd != pwd2 {
            return Err(StrHideError::Password("Passwords do not match".into()));
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

/// Package the resolved private stego secret as a stego-only
/// [`Profile`](crate::params::Profile).
///
/// Only the content-domain half is populated: the CLI does not expose the
/// structure-domain dialect knobs yet, so those stay at their official
/// defaults (an all-default profile is byte-compatible with every release).
fn stego_profile(secret: Option<String>) -> crate::params::Profile {
    match secret {
        Some(secret) => crate::params::Profile::default().with_stego_secret(secret),
        None => crate::params::Profile::default(),
    }
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

pub fn run_cli() -> i32 {
    let cli = Cli::parse();

    let cfg = match config::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] {e}");
            return 1;
        }
    };

    if should_print_banner(&cli) {
        println!("{BANNER}");
    }

    match cli.command {
        Commands::Write(args) => match handle_write(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Read(args) => match handle_read(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Restore(args) => match handle_restore(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Inspect(args) => match handle_inspect(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Verify(args) => match handle_verify(args, &cfg, cli.quiet) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        // Like verify, scan owns its exit code: 1 when a scan verdict reaches
        // "likely-hidden" (see handle_scan), 0 otherwise, regardless of quiet.
        Commands::Scan(args) => match handle_scan(args, cli.quiet) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Embed(args) => match handle_embed(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Extract(args) => match handle_extract(args, &cfg, cli.quiet) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        // `list` prints a data table, not status lines, so quiet does not
        // apply; the global flag is accepted but ignored here.
        Commands::List(args) => match handle_list(args) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
    }
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
        println!("Available strategies for '{}':", carrier.display());
        for (idx, s) in strats.iter().enumerate() {
            println!("  [{}] {s}", idx + 1);
        }
        print!("Select strategy [1-{}] (default 1): ", strats.len());
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

    // Resolve payload source
    let payload_source: PayloadSource;
    let text_buf: String;
    let b64_buf: Vec<u8>;

    if args.payload.stdin {
        payload_source = PayloadSource::Stdin;
    } else if let Some(ref df) = args.payload.data {
        payload_source = PayloadSource::File(df);
    } else if let Some(ref tf) = args.payload.text_file {
        text_buf = std::fs::read_to_string(tf)?;
        payload_source = PayloadSource::Text(&text_buf);
    } else if let Some(ref b64_str) = args.payload.text_base64 {
        use base64::Engine;
        b64_buf = base64::engine::general_purpose::STANDARD
            .decode(b64_str.trim())
            .map_err(|e| StrHideError::General(format!("Invalid base64 string: {e}")))?;
        text_buf = String::from_utf8(b64_buf).map_err(|e| {
            StrHideError::General(format!("Base64 content is not valid UTF-8: {e}"))
        })?;
        payload_source = PayloadSource::Text(&text_buf);
    } else if let Some(ref t) = args.payload.text {
        if args.unescape || cfg.unescape.unwrap_or(false) {
            text_buf = unescape_string(t);
            payload_source = PayloadSource::Text(&text_buf);
        } else {
            payload_source = PayloadSource::Text(t);
        }
    } else if let Ok(env_text) = std::env::var("STRHIDE_TEXT") {
        if !env_text.is_empty() {
            text_buf = env_text;
            payload_source = PayloadSource::Text(&text_buf);
        } else {
            return Err(StrHideError::General(
                "Must provide either -d/--data, -t/--text, --text-file, --text-base64, or --stdin"
                    .into(),
            ));
        }
    } else {
        return Err(StrHideError::General(
            "Must provide either -d/--data, -t/--text, --text-file, --text-base64, or --stdin"
                .into(),
        ));
    }

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
        // hint, then prompt (interactive terminals only) and retry once.
        //
        // The engine renders the hint as ` Hint: '<hint>'.` (engine.rs). The
        // hint itself is arbitrary user text and may contain quotes, so strip
        // the exact trailing terminator instead of splitting on `'`.
        Err(e @ StrHideError::Password(_)) if password.is_none() => {
            let msg = e.to_string();
            if !quiet && let Some((_, rest)) = msg.split_once("Hint: '") {
                let hint_part = rest.strip_suffix("'.").unwrap_or(rest);
                println!("[INFO] Password hint: {hint_part}");
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
        eprintln!(
            "[WARNING] This envelope is not encrypted: it was written without a password, so the supplied password was ignored. Re-write the carrier with -p to protect it."
        );
    }

    if let Some(wf) = res.written_file {
        if !quiet {
            println!("[OK] Extracted payload to '{wf}' ({} bytes).", res.raw_size);
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
                "[OK] Extracted payload to '{fn_to_use}' ({} bytes).",
                res.raw_size
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
        let res = remove_carrier(carrier, output.as_deref(), password.as_deref(), backup)?;
        print_remove_result(&res, quiet);
        Ok(())
    })
}

fn print_inspect_result(res: &crate::engine::InspectResult) {
    println!("Carrier: {}", res.carrier);
    println!("Format:  {}", res.format);
    println!("Has Hidden Data: {}", res.has_hidden_data);
    if res.has_hidden_data {
        if let Some(s) = &res.strategy {
            println!("Strategy:        {s}");
        }
        if let Some(off) = res.ube_offset {
            println!("UBE Offset:      {off}");
        }
        if let Some(sz) = res.ube_total_size {
            println!("UBE Total Size:  {sz} bytes");
        }
        if let Some(enc) = res.is_encrypted {
            println!("Encrypted:       {enc}");
        }
        if let Some(stl) = res.is_stealth {
            println!("Stealth Mode:    {stl}");
        }
        if let Some(h) = &res.password_hint {
            println!("Password Hint:   {h}");
        }
        if let Some(sz) = res.orig_host_size {
            println!("Original Size:   {sz} bytes");
        }
        if let Some(sha) = &res.orig_host_sha256 {
            println!("Original SHA256: {sha}");
        }
        if let Some(meta) = &res.metadata {
            println!("Metadata:        {meta}");
        }
    }

    let auto_idx = res.strategies.iter().position(|c| c.available);
    println!("Strategy capacities (max payload size):");
    for (idx, c) in res.strategies.iter().enumerate() {
        let auto = if Some(idx) == auto_idx {
            " [auto preference]"
        } else {
            ""
        };
        let state = if c.available { "" } else { " (unavailable)" };
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
        println!("Content-Adaptive Steganography Capacity (embed):");
        println!("  Algorithm:       {}", cap.algorithm);
        println!("  Available Slots: {} bits", cap.available_slots);
        println!(
            "  Max Raw:         {} bytes ({:.1} KiB)",
            cap.max_raw_payload_bytes,
            cap.max_raw_payload_bytes as f64 / 1024.0
        );
        println!(
            "  Safe Max:        {} bytes ({:.1} KiB) (high stealth)",
            cap.recommended_max_bytes,
            cap.recommended_max_bytes as f64 / 1024.0
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
                    eprintln!("[WARN] failed to inspect '{}': {e}", carrier.display());
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
        println!(
            "Inspected {} file(s), {} with hidden data, {} failed.",
            reports.len(),
            reports.iter().filter(|r| r.has_hidden_data).count(),
            failures
        );
    }

    Ok(())
}

fn print_verify_result(res: &crate::engine::VerifyResult) {
    println!("Carrier: {}", res.carrier);
    println!("Format:  {}", res.format);
    println!(
        "Level 1 (Host Format):      [{}] {}",
        if res.level1_host.ok { "OK" } else { "FAIL" },
        res.level1_host.detail
    );
    println!(
        "Level 2 (Envelope Boundary): [{}] {}",
        if res.level2_envelope.ok { "OK" } else { "FAIL" },
        res.level2_envelope.detail
    );
    println!(
        "Level 3 (Crypto & Payload):  [{}] {}",
        if res.level3_crypto.ok { "OK" } else { "FAIL" },
        res.level3_crypto.detail
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
        return Ok(if res.level1_host.ok && res.level2_envelope.ok {
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
                let ok = res.level1_host.ok && res.level2_envelope.ok;
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
                    eprintln!("[WARN] failed to verify '{}': {e}", carrier.display());
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
            .filter(|r| r.level1_host.ok && r.level2_envelope.ok)
            .count();
        println!(
            "Verified {} file(s): {} passed, {} with verification failures, {} unreadable.",
            reports.len(),
            passed,
            reports.len() - passed,
            failures
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
                    eprintln!("[WARN] failed to scan '{}': {e}", f.display());
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
        println!(
            "\nScanned {} file(s), {} with findings, {} failed.",
            reports.len(),
            reports.iter().filter(|r| !r.findings.is_empty()).count(),
            failures,
        );
    }

    // Gate-style exit code, independent of quiet: a "likely-hidden" verdict on
    // any report fails the scan (exit 1); lower confidence ("low"/"suspicious")
    // and per-file scan failures stay at 0 — they are reported in the JSON or
    // in the human summary line instead.
    let likely_hidden = reports.iter().any(|r| r.verdict == "likely-hidden");
    Ok(if likely_hidden { 1 } else { 0 })
}

fn walkdir_flat(dir: &Path) -> Result<impl Iterator<Item = PathBuf>, StrHideError> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            out.push(entry.path());
        }
    }
    Ok(out.into_iter())
}

fn walkdir_recursive(dir: &Path) -> Result<impl Iterator<Item = PathBuf>, StrHideError> {
    let mut out = Vec::new();
    push_files_recursive(dir, &mut out)?;
    Ok(out.into_iter())
}

fn push_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), StrHideError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            push_files_recursive(&path, out)?;
        } else {
            out.push(path);
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
            let walker: Box<dyn Iterator<Item = PathBuf>> = if recursive {
                Box::new(walkdir_recursive(entry)?)
            } else {
                Box::new(walkdir_flat(entry)?)
            };
            files.extend(walker);
        } else if entry.is_file() {
            files.push(entry.clone());
        } else if !quiet {
            eprintln!("[WARN] '{}' does not exist, skipping", entry.display());
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
    println!("Carrier-dependent limits are measured by `strhide inspect <carrier>`.");

    println!("\nContent-Adaptive Steganography Algorithms (embed / extract):");
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
    let jp = &options.jpeg_params;
    let d_sp = crate::stego::SpatialParams::default();
    let d_jp = crate::stego::JpegParams::default();
    let mut flags: Vec<String> = Vec::new();
    if sp.p1_window != d_sp.p1_window {
        flags.push(format!("--p1-window {}", sp.p1_window));
    }
    if sp.p2_window != d_sp.p2_window {
        flags.push(format!("--p2-window {}", sp.p2_window));
    }
    if sp.exclusion_percentile != d_sp.exclusion_percentile
        || jp.block_exclusion_percentile != d_jp.block_exclusion_percentile
    {
        flags.push(format!("--exclusion-rate {}", sp.exclusion_percentile));
    }
    if jp.neighbor_weight != d_jp.neighbor_weight {
        flags.push(format!("--neighbor-weight {}", jp.neighbor_weight));
    }
    if jp.min_abs_coeff != d_jp.min_abs_coeff {
        flags.push(format!("--min-abs-coeff {}", jp.min_abs_coeff));
    }
    if flags.is_empty() {
        return;
    }
    eprintln!(
        "[WARN] Non-default stego parameters: {}. Extraction succeeds only with the same values; a mismatch fails as 'No valid payload found'.",
        flags.join(" ")
    );
}

/// Apply `--codec` / `--stc-h` / `--stc-u` to the option set.
///
/// Unlike the cost-model knobs, these do **not** need to be repeated at
/// extraction: the codec, its `h` and its `u` are recorded in six spare bits of
/// the envelope header (see `stego::header`), so `extract` recovers them from
/// the carrier itself. The flags exist on `embed` only.
///
/// The same values are applied to both engine families: `--codec` does not
/// depend on whether the carrier turns out to be a PNG or a JPEG, and the
/// caller does not know before the router has sniffed it.
fn apply_codec_options(
    options: &mut crate::stego::StegoOptions,
    codec: Option<&str>,
    stc_h: Option<u8>,
    stc_u: Option<u8>,
) -> Result<(), StrHideError> {
    let parsed = match codec {
        Some(name) => Some(match name.to_ascii_lowercase().as_str() {
            "hamming" => crate::stego::StegoCodec::Hamming,
            "stc" => crate::stego::StegoCodec::Stc,
            other => {
                return Err(StrHideError::General(format!(
                    "Unknown codec '{other}': expected 'hamming' or 'stc'"
                )));
            }
        }),
        None => None,
    };
    {
        let params = &mut options.spatial_params;
        if let Some(codec) = parsed {
            params.codec = codec;
        }
        if let Some(h) = stc_h {
            params.stc_h = h;
        }
        if let Some(u) = stc_u {
            params.stc_u = u;
        }
    }
    {
        let params = &mut options.jpeg_params;
        if let Some(codec) = parsed {
            params.codec = codec;
        }
        if let Some(h) = stc_h {
            params.stc_h = h;
        }
        if let Some(u) = stc_u {
            params.stc_u = u;
        }
    }
    // Reject out-of-range values here rather than as an opaque capacity failure
    // later.
    options.spatial_params.validate()?;
    options.jpeg_params.validate()?;
    Ok(())
}

fn handle_embed(args: EmbedArgs, cfg: &FileConfig, quiet: bool) -> Result<(), StrHideError> {
    if args.capacity {
        for carrier in &args.carrier {
            let carrier_bytes = std::fs::read(carrier)?;
            let mut options = crate::stego::StegoOptions {
                algorithm: args.algorithm.clone(),
                ..Default::default()
            };
            apply_codec_options(&mut options, args.codec.as_deref(), args.stc_h, args.stc_u)?;
            if let Some(er) = args.exclusion_rate {
                options.spatial_params.exclusion_percentile = er;
                options.jpeg_params.block_exclusion_percentile = er;
            }
            if let Some(nw) = args.neighbor_weight {
                options.jpeg_params.neighbor_weight = nw;
            }
            if let Some(min_ac) = args.min_abs_coeff {
                options.jpeg_params.min_abs_coeff = min_ac;
            }
            if let Some(p1) = args.p1_window {
                options.spatial_params.p1_window = p1;
            }
            if let Some(p2) = args.p2_window {
                options.spatial_params.p2_window = p2;
            }
            let cap = crate::stego::probe_carrier_capacity(&carrier_bytes, &options)?;
            println!(
                "Content-Adaptive Steganography Capacity for '{}':",
                carrier.display()
            );
            println!("  Format:          {}", cap.format);
            println!("  Algorithm:       {}", cap.algorithm);
            println!("  Total elements:  {}", cap.total_elements);
            println!(
                "  Payload slots:   {} bits (body only; header slots excluded)",
                cap.available_slots
            );
            println!(
                "  Max raw payload: {} bytes ({:.1} KiB)",
                cap.max_raw_payload_bytes,
                cap.max_raw_payload_bytes as f64 / 1024.0
            );
            println!(
                "  Recommended max: {} bytes ({:.1} KiB) (high stealth)",
                cap.recommended_max_bytes,
                cap.recommended_max_bytes as f64 / 1024.0
            );
            println!(
                "  Est. changes:   ~{:.3} per payload bit (matrix coding); \
                 recommended max is half of max for statistical stealth",
                cap.estimated_change_rate
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
    let profile = stego_profile(stego_secret);

    // 2. Resolve payload bytes
    let payload_bytes = if args.payload.stdin {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        buf
    } else if let Some(ref df) = args.payload.data {
        std::fs::read(df)?
    } else if let Some(ref t) = args.payload.text {
        if args.unescape || cfg.unescape.unwrap_or(false) {
            unescape_string(t).into_bytes()
        } else {
            t.as_bytes().to_vec()
        }
    } else if let Some(ref tf) = args.payload.text_file {
        std::fs::read(tf)?
    } else if let Some(ref b64_str) = args.payload.text_base64 {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(b64_str.trim())
            .map_err(|e| StrHideError::General(format!("Invalid base64 string: {e}")))?
    } else if let Ok(env_text) = std::env::var("STRHIDE_TEXT") {
        if !env_text.is_empty() {
            env_text.into_bytes()
        } else {
            return Err(StrHideError::General(
                "Must provide either -d/--data, -t/--text, --text-file, --text-base64, or --stdin (or use --capacity to probe capacity)"
                    .into(),
            ));
        }
    } else {
        return Err(StrHideError::General(
            "Must provide either -d/--data, -t/--text, --text-file, --text-base64, or --stdin (or use --capacity to probe capacity)"
                .into(),
        ));
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

        let mut options = crate::stego::StegoOptions {
            algorithm: args.algorithm.clone(),
            password: password.clone(),
            ..Default::default()
        };

        if let Some(er) = args.exclusion_rate {
            options.spatial_params.exclusion_percentile = er;
            options.jpeg_params.block_exclusion_percentile = er;
        }
        if let Some(nw) = args.neighbor_weight {
            options.jpeg_params.neighbor_weight = nw;
        }
        if let Some(min_ac) = args.min_abs_coeff {
            options.jpeg_params.min_abs_coeff = min_ac;
        }
        if let Some(p1) = args.p1_window {
            options.spatial_params.p1_window = p1;
        }
        if let Some(p2) = args.p2_window {
            options.spatial_params.p2_window = p2;
        }
        apply_codec_options(&mut options, args.codec.as_deref(), args.stc_h, args.stc_u)?;
        warn_nondefault_stego_params(&options, quiet);

        let stego_bytes = crate::stego::embed_carrier_with_profile(
            &carrier_bytes,
            &payload_bytes,
            &options,
            &profile,
        )?;

        let target =
            resolve_carrier_target(carrier, args.in_place, args.output.as_deref(), output_dir)?;
        if let Some(dest) = target {
            check_overwrite(&dest, args.overwrite)?;
            std::fs::write(&dest, &stego_bytes)?;
            if !quiet {
                println!(
                    "[OK] Embedded {} payload bytes into '{}' -> '{}'",
                    payload_bytes.len(),
                    carrier.display(),
                    dest.display()
                );
            }
        } else {
            if !args.no_backup {
                let bak_path = carrier.with_extension(format!(
                    "{}.bak",
                    carrier.extension().and_then(|s| s.to_str()).unwrap_or("")
                ));
                std::fs::write(&bak_path, &carrier_bytes)?;
                if !quiet {
                    println!("[INFO] Backup created at '{}'", bak_path.display());
                }
            }
            std::fs::write(carrier, &stego_bytes)?;
            if !quiet {
                println!(
                    "[OK] Embedded {} payload bytes in-place into '{}'",
                    payload_bytes.len(),
                    carrier.display()
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
    let profile = stego_profile(stego_secret);
    let mut options = crate::stego::StegoOptions {
        algorithm: args.algorithm,
        password,
        ..Default::default()
    };

    if let Some(er) = args.exclusion_rate {
        options.spatial_params.exclusion_percentile = er;
        options.jpeg_params.block_exclusion_percentile = er;
    }
    if let Some(nw) = args.neighbor_weight {
        options.jpeg_params.neighbor_weight = nw;
    }
    if let Some(min_ac) = args.min_abs_coeff {
        options.jpeg_params.min_abs_coeff = min_ac;
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
                "[OK] Extracted {} bytes to '{}'",
                payload.len(),
                dest.display()
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
                println!(
                    "[OK] Binary payload detected ({} bytes). Extracted to 'extracted.bin'.",
                    payload.len()
                );
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
                    eprintln!("[FAIL] {}", carrier.display());
                    println!(
                        "[SUMMARY] {done}/{total} carriers succeeded; {} not attempted.",
                        total - done - 1
                    );
                }
                return Err(e);
            }
        }
    }
    if total > 1 && !quiet {
        println!("[SUMMARY] {done}/{total} carriers succeeded.");
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
        "[OK] Successfully embedded into '{}' using strategy '{}'.",
        res.carrier, res.strategy
    );
    println!(
        "     Payload: {} bytes -> UBE: {} bytes.",
        res.raw_size, res.ube_size
    );
    if let Some(note) = &res.strategy_note {
        println!("     [STRATEGY] {note}");
    }
    if let Some(hint) = &res.password_hint {
        println!("     Password Hint: '{hint}'.");
    }
    if let Some(bak) = &res.backup_file {
        println!("     [BACKUP] Original carrier backed up to '{bak}'.");
    }
    if let Some(warn) = &res.warning {
        eprintln!("[WARNING] {warn}");
    }
}

fn print_remove_result(res: &RemoveResult, quiet: bool) {
    if quiet {
        return;
    }
    println!(
        "[OK] Successfully stripped hidden data from '{}'.",
        res.carrier
    );
    println!("     Restored size: {} bytes.", res.restored_size);
    println!(
        "     SHA-256: {} (100% verified identical to original).",
        res.restored_sha256
    );
    if let Some(bak) = &res.backup_file {
        println!("     [BACKUP] Prior carrier backed up to '{bak}'.");
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
