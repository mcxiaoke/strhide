use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::config::{self, FileConfig};
use crate::engine::{
    PayloadSource, RemoveResult, WriteOptions, WriteResult, inspect_carrier, read_carrier,
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

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Hide secret payload into carrier file
    Write(WriteArgs),
    /// Read and extract hidden payload from carrier
    Read(ReadArgs),
    /// 100% loss-free restoration by removing hidden envelope
    Remove(RemoveArgs),
    /// Inspect carrier structure and envelope metadata
    Inspect(InspectArgs),
    /// Diagnostic verification of host, envelope, and crypto
    Verify(VerifyArgs),
    /// List all supported formats, strategies, and their capacity limits
    ListStrategies(ListStrategiesArgs),
}

#[derive(Args, Debug)]
pub struct WriteArgs {
    #[arg(
        short = 'c',
        long = "carrier",
        required = true,
        num_args = 1..,
        value_name = "CARRIER",
        help = "Carrier file(s). List several to embed the same payload into each."
    )]
    pub carrier: Vec<PathBuf>,

    #[arg(short = 'd', long = "data")]
    pub data: Option<PathBuf>,

    #[arg(short = 't', long = "text")]
    pub text: Option<String>,

    #[arg(long = "text-file")]
    pub text_file: Option<PathBuf>,

    #[arg(long = "text-base64")]
    pub text_base64: Option<String>,

    #[arg(long = "stdin")]
    pub stdin: bool,

    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    #[arg(short = 'p', long = "password")]
    pub password: Option<String>,

    #[arg(long = "password-file")]
    pub password_file: Option<PathBuf>,

    #[arg(short = 'e', long = "encrypt")]
    pub encrypt: bool,

    #[arg(short = 'H', long = "hint", alias = "password-hint")]
    pub hint: Option<String>,

    #[arg(
        short = 's',
        long = "strategy",
        help = "Hiding strategy (auto|ask|<name>; default: auto or config file)"
    )]
    pub strategy: Option<String>,

    #[arg(long = "stealth")]
    pub stealth: bool,

    #[arg(long = "no-preserve-time", default_value_t = true, action = clap::ArgAction::SetFalse, help = "Do not preserve original carrier timestamps (default: preserve)")]
    pub preserve_time: bool,

    #[arg(long = "no-backup")]
    pub no_backup: bool,

    #[arg(long = "unescape")]
    pub unescape: bool,
}

#[derive(Args, Debug)]
pub struct ReadArgs {
    #[arg(short = 'c', long = "carrier", required = true)]
    pub carrier: PathBuf,

    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    #[arg(short = 'p', long = "password")]
    pub password: Option<String>,

    #[arg(long = "password-file")]
    pub password_file: Option<PathBuf>,

    #[arg(long = "stdout")]
    pub stdout: bool,
}

#[derive(Args, Debug)]
pub struct RemoveArgs {
    #[arg(
        short = 'c',
        long = "carrier",
        required = true,
        num_args = 1..,
        value_name = "CARRIER",
        help = "Carrier file(s). List several to strip each one."
    )]
    pub carrier: Vec<PathBuf>,

    #[arg(short = 'o', long = "output")]
    pub output: Option<PathBuf>,

    #[arg(short = 'p', long = "password")]
    pub password: Option<String>,

    #[arg(long = "password-file")]
    pub password_file: Option<PathBuf>,

    #[arg(long = "no-backup")]
    pub no_backup: bool,
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    #[arg(short = 'c', long = "carrier", required = true)]
    pub carrier: PathBuf,

    #[arg(short = 'p', long = "password")]
    pub password: Option<String>,

    #[arg(long = "password-file")]
    pub password_file: Option<PathBuf>,

    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    #[arg(short = 'c', long = "carrier", required = true)]
    pub carrier: PathBuf,

    #[arg(short = 'p', long = "password")]
    pub password: Option<String>,

    #[arg(long = "password-file")]
    pub password_file: Option<PathBuf>,

    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ListStrategiesArgs {}

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
        Commands::Write(args) => match handle_write(args, &cfg) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Read(args) => match handle_read(args, &cfg) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Remove(args) => match handle_remove(args, &cfg) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Inspect(args) => match handle_inspect(args, &cfg) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Verify(args) => match handle_verify(args, &cfg) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::ListStrategies(args) => match handle_list_strategies(args) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
    }
}

fn handle_write(args: WriteArgs, cfg: &FileConfig) -> Result<(), StrHideError> {
    // Config values act as defaults; explicit CLI flags win. --stealth implies
    // encryption (its magics are password-derived); prompt for a password when
    // neither -p nor a password source was supplied.
    let stealth = args.stealth || cfg.stealth.unwrap_or(false);
    let encrypt = args.encrypt || cfg.encrypt.unwrap_or(false);
    let password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
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

    if args.stdin {
        payload_source = PayloadSource::Stdin;
    } else if let Some(ref df) = args.data {
        payload_source = PayloadSource::File(df);
    } else if let Some(ref tf) = args.text_file {
        text_buf = std::fs::read_to_string(tf)?;
        payload_source = PayloadSource::Text(&text_buf);
    } else if let Some(ref b64_str) = args.text_base64 {
        use base64::Engine;
        b64_buf = base64::engine::general_purpose::STANDARD
            .decode(b64_str.trim())
            .map_err(|e| StrHideError::General(format!("Invalid base64 string: {e}")))?;
        text_buf = String::from_utf8(b64_buf).map_err(|e| {
            StrHideError::General(format!("Base64 content is not valid UTF-8: {e}"))
        })?;
        payload_source = PayloadSource::Text(&text_buf);
    } else if let Some(ref t) = args.text {
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

    let hint = args.hint.clone().or_else(|| cfg.hint.clone());
    let preserve_time = args.preserve_time && cfg.preserve_time.unwrap_or(true);
    let backup = !args.no_backup && cfg.backup.unwrap_or(true);

    for_each_carrier(&args.carrier, |carrier| {
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
        print_write_result(&res);
        Ok(())
    })
}

fn handle_read(args: ReadArgs, cfg: &FileConfig) -> Result<(), StrHideError> {
    let mut password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let res = match read_carrier(&args.carrier, args.output.as_deref(), password.as_deref()) {
        Ok(r) => r,
        // Discriminate by error variant, not by message text. A password error
        // with no password supplied means the envelope is encrypted: show the
        // hint, then prompt (interactive terminals only) and retry once.
        Err(e @ StrHideError::Password(_)) if password.is_none() => {
            let msg = e.to_string();
            if let Some(hint_part) = msg
                .split("Hint: '")
                .nth(1)
                .and_then(|s| s.rsplit('\'').nth(1))
            {
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
            read_carrier(&args.carrier, args.output.as_deref(), password.as_deref())?
        }
        Err(e) => return Err(e),
    };

    if let Some(wf) = res.written_file {
        println!("[OK] Extracted payload to '{wf}' ({} bytes).", res.raw_size);
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
        let mut f = File::create(&fn_to_use)?;
        f.write_all(&res.data)?;
        println!(
            "[OK] Extracted payload to '{fn_to_use}' ({} bytes).",
            res.raw_size
        );
    }

    Ok(())
}

fn handle_remove(args: RemoveArgs, cfg: &FileConfig) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let multi = args.carrier.len() > 1;
    let output_dir = batch_output_dir(args.output.as_deref(), multi, "removing hidden data from")?;
    if multi {
        preflight_batch(&args.carrier, output_dir)?;
    }
    let backup = !args.no_backup;

    for_each_carrier(&args.carrier, |carrier| {
        let output = carrier_output_path(carrier, args.output.as_deref(), output_dir)?;
        let res = remove_carrier(carrier, output.as_deref(), password.as_deref(), backup)?;
        print_remove_result(&res);
        Ok(())
    })
}

fn handle_inspect(args: InspectArgs, cfg: &FileConfig) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let res = inspect_carrier(&args.carrier, password.as_deref())?;

    if args.json {
        let json_str = serde_json::to_string_pretty(&res)?;
        println!("{json_str}");
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
                    "  - {}{}{}: {} — {}",
                    c.strategy, auto, state, c.limit, detail
                );
            }
        }
    }

    Ok(())
}

fn handle_verify(args: VerifyArgs, cfg: &FileConfig) -> Result<i32, StrHideError> {
    let password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
        cfg,
        false,
        false,
    )?;

    let res = verify_carrier(&args.carrier, password.as_deref())?;

    if args.json {
        let json_str = serde_json::to_string_pretty(&res)?;
        println!("{json_str}");
    } else {
        println!("Carrier: {}", res.carrier);
        println!("Format:  {}", res.format);
        println!(
            "Level 1 (Host Format):      [{}] {}",
            if res.level1_host.ok { "PASS" } else { "FAIL" },
            res.level1_host.detail
        );
        println!(
            "Level 2 (Envelope Boundary): [{}] {}",
            if res.level2_envelope.ok {
                "PASS"
            } else {
                "FAIL"
            },
            res.level2_envelope.detail
        );
        println!(
            "Level 3 (Crypto & Payload):  [{}] {}",
            if res.level3_crypto.ok { "PASS" } else { "FAIL" },
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

fn handle_list_strategies(_args: ListStrategiesArgs) -> Result<(), StrHideError> {
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
fn for_each_carrier<F>(carriers: &[PathBuf], mut action: F) -> Result<(), StrHideError>
where
    F: FnMut(&Path) -> Result<(), StrHideError>,
{
    let total = carriers.len();
    let mut done = 0usize;
    for carrier in carriers {
        match action(carrier) {
            Ok(()) => done += 1,
            Err(e) => {
                if total > 1 {
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
    if total > 1 {
        println!("[SUMMARY] {done}/{total} carriers succeeded.");
    }
    Ok(())
}

/// Batch `-o` rule: with more than one carrier the target must be an existing
/// directory, because one file path cannot name several outputs. Single-carrier
/// runs return `None` so `-o <file>` keeps its original meaning.
fn batch_output_dir<'a>(
    output: Option<&'a Path>,
    multi: bool,
    action: &str,
) -> Result<Option<&'a Path>, StrHideError> {
    let Some(path) = output else {
        return Ok(None);
    };
    if !multi {
        return Ok(None);
    }
    if !path.is_dir() {
        return Err(StrHideError::General(format!(
            "'-o {}' must be an existing directory when {action} multiple carriers",
            path.display()
        )));
    }
    Ok(Some(path))
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

fn print_write_result(res: &WriteResult) {
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

fn print_remove_result(res: &RemoveResult) {
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
