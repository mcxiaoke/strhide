use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::config::{self, FileConfig};
use crate::engine::{
    PayloadSource, RemoveResult, WriteOptions, WriteResult, inspect_carrier, read_carrier_with,
    remove_carrier, verify_carrier, write_carrier,
};
use crate::errors::StrHideError;
use crate::router::{ADAPTERS, find_adapter_or_reject};

#[derive(Parser, Debug)]
#[command(
    name = "strhide",
    version,
    about = "Smart multi-format lossless container data hiding tool"
)]
pub struct Cli {
    /// Path to TOML config file (default: ./strhide.toml, then ~/.strhide/config.toml)
    #[arg(long, global = true, value_name = "FILE")]
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
        help = "Read the payload from standard input, e.g. `cat secret.txt | strhide write -c photo.png --stdin`. Mutually exclusive with the other payload sources."
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
        help = "Write the modified carrier to this path. A single path names the result for one carrier; with several carriers it must be an existing directory and each output keeps its carrier's name. Default: modify the carrier in place."
    )]
    pub output: Option<PathBuf>,

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
        help = "Do not create a '<carrier>.bak' backup next to a modified carrier (default: a .bak copy is kept)."
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
  strhide write photo.png -t \"meet me at 7\"
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
        help = "Write the restored carrier to this path instead of restoring in place (the original carrier then stays untouched). A single path names the result for one carrier; with several carriers it must be an existing directory keeping each carrier's name."
    )]
    pub output: Option<PathBuf>,

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
  strhide restore photo.png               # restore in place, keeping photo.png.bak
  strhide restore photo.png -o clean.png  # write the restored copy to 'clean.png'
  strhide restore a.png b.png c.png       # batch restoration in one run

Restoration is verified loss-free: the restored SHA-256 must match the
original host recorded in the envelope, or the command fails loudly.
";

#[derive(Args, Debug)]
#[command(after_help = INSPECT_AFTER_HELP)]
pub struct InspectArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        help = "Carrier file to inspect; reports the host format, any envelope metadata, and per-strategy capacity. Use `--` before a filename that starts with '-'."
    )]
    pub carrier: PathBuf,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(
        long = "json",
        help = "Print a machine-readable JSON report instead of the aligned key/value summary."
    )]
    pub json: bool,
}

const INSPECT_AFTER_HELP: &str = "\
Examples:
  strhide inspect photo.png             # metadata summary + strategy capacities
  strhide inspect photo.png --json      # the same report as JSON
";

#[derive(Args, Debug)]
#[command(after_help = VERIFY_AFTER_HELP)]
pub struct VerifyArgs {
    #[arg(
        value_name = "CARRIER",
        required = true,
        help = "Carrier file to verify. Use `--` before a filename that starts with '-'."
    )]
    pub carrier: PathBuf,

    #[command(flatten)]
    pub passwords: PasswordArgs,

    #[arg(
        long = "json",
        help = "Print a machine-readable JSON report instead of one line per level."
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
  strhide verify photo.png              # readable three-level report
  strhide verify photo.png --json       # machine-readable report
";

#[derive(Args, Debug)]
pub struct ListArgs {}

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

pub fn run_cli() -> i32 {
    let cli = Cli::parse();

    let cfg = match config::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] {e}");
            return 1;
        }
    };

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
    // (missing/unrecognized files, duplicate targets).
    if multi {
        preflight_batch(&args.carrier, output_dir)?;
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
        let output = carrier_output_path(carrier, args.output.as_deref(), output_dir)?;
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
        preflight_batch(&args.carrier, output_dir)?;
    }
    // Mirror `write`: `remove` also honours the configured backup default
    // (`config.rs` documents `backup` as covering both commands).
    let backup = !args.no_backup && cfg.backup.unwrap_or(true);

    for_each_carrier(&args.carrier, quiet, |carrier| {
        let output = carrier_output_path(carrier, args.output.as_deref(), output_dir)?;
        let res = remove_carrier(carrier, output.as_deref(), password.as_deref(), backup)?;
        print_remove_result(&res, quiet);
        Ok(())
    })
}

fn handle_inspect(args: InspectArgs, cfg: &FileConfig, quiet: bool) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let res = inspect_carrier(&args.carrier, password.as_deref())?;

    if args.json {
        let json_str = serde_json::to_string_pretty(&res)?;
        println!("{json_str}");
    } else if quiet {
        // Nothing to print: the JSON form is the machine-readable equivalent.
    } else {
        println!("Carrier: {}", res.carrier);
        println!("Format:  {}", res.format);
        println!("Has Hidden Data: {}", res.has_hidden_data);
        if res.has_hidden_data {
            if let Some(s) = res.strategy {
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
            if let Some(h) = res.password_hint {
                println!("Password Hint:   {h}");
            }
            if let Some(sz) = res.orig_host_size {
                println!("Original Size:   {sz} bytes");
            }
            if let Some(sha) = res.orig_host_sha256 {
                println!("Original SHA256: {sha}");
            }
            if let Some(meta) = res.metadata {
                println!("Metadata:        {meta}");
            }
        }

        // Capacity report (available whether or not an envelope exists).
        // The first available strategy is what `-s auto` would pick for a
        // payload that fits.
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
    }

    Ok(())
}

fn handle_verify(args: VerifyArgs, cfg: &FileConfig, quiet: bool) -> Result<i32, StrHideError> {
    let password = resolve_password(
        args.passwords.password.as_deref(),
        args.passwords.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let res = verify_carrier(&args.carrier, password.as_deref())?;

    if args.json {
        let json_str = serde_json::to_string_pretty(&res)?;
        println!("{json_str}");
    } else if quiet {
        // Result is carried entirely by the exit code below.
    } else {
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

    // Align with the Python CLI: a Level 1 or Level 2 failure exits non-zero so
    // scripts can gate on it; Level 3 (crypto) failures are reported but do not
    // change the exit code.
    Ok(if res.level1_host.ok && res.level2_envelope.ok {
        0
    } else {
        1
    })
}

fn handle_scan(args: ScanArgs, quiet: bool) -> Result<i32, StrHideError> {
    use crate::analysis::scan_file;

    // Expand inputs: directories become file lists.
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in &args.input {
        if entry.is_dir() {
            let walker: Box<dyn Iterator<Item = PathBuf>> = if args.recursive {
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
        println!("{}", serde_json::to_string_pretty(&reports)?);
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

fn handle_list(_args: ListArgs) -> Result<(), StrHideError> {
    // Static reference table: constants come from the adapters themselves (via
    // `strategy_capacities(None)`), so the table cannot drift from the code.
    // Carrier-specific limits are answered by `inspect -c <carrier>`.
    println!("{:<8} {:<15} Limit", "Format", "Strategy");
    println!("{:-<8} {:-<15} {:-<48}", "", "", "");
    for adapter in ADAPTERS {
        let format = adapter.format_name();
        for cap in adapter.strategy_capacities(None) {
            println!("{format:<8} {:<15} {}", cap.strategy, cap.limit);
        }
    }
    println!();
    println!("Carrier-dependent limits are measured by `strhide inspect -c <carrier>`.");

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
/// `read -o <dir>` already had. Previously single-carrier `-o <dir>` fell
/// through to the rename and failed with a bare OS error.
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

/// Where one carrier's result goes: inside the batch directory (keeping the
/// carrier's filename) or to the explicit single-file target.
fn carrier_output_path(
    carrier: &Path,
    output: Option<&Path>,
    output_dir: Option<&Path>,
) -> Result<Option<PathBuf>, StrHideError> {
    if let Some(dir) = output_dir {
        let name = carrier.file_name().ok_or_else(|| {
            StrHideError::General(format!(
                "Cannot derive an output filename from '{}'",
                carrier.display()
            ))
        })?;
        return Ok(Some(dir.join(name)));
    }
    Ok(output.map(Path::to_path_buf))
}

/// Validate a whole batch before the first carrier is modified: every carrier
/// must exist, be a regular file, be a supported format, and resolve to a unique
/// output. Capacity limits and "already contains hidden data" can only be judged
/// by the engine per carrier, so those still surface mid-run.
fn preflight_batch(carriers: &[PathBuf], output_dir: Option<&Path>) -> Result<(), StrHideError> {
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
        // canonicalize() only fails for paths that vanished after the existence
        // check; falling back to the raw path is good enough for dedup.
        let identity = std::fs::canonicalize(carrier).unwrap_or_else(|_| carrier.clone());
        if !seen_carriers.insert(identity.clone()) {
            return Err(StrHideError::General(format!(
                "Carrier '{}' is listed more than once",
                carrier.display()
            )));
        }
        let target = match output_dir {
            Some(dir) => carrier_output_path(carrier, None, Some(dir))?.unwrap_or(identity),
            None => identity,
        };
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
