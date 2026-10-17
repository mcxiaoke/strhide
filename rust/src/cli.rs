use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};

use crate::engine::{
    inspect_carrier, read_carrier, remove_carrier, verify_carrier, write_carrier, PayloadSource,
};
use crate::errors::StrHideError;
use crate::router::{find_adapter, list_all_strategies};

#[derive(Parser, Debug)]
#[command(name = "strhide", version, about = "Smart multi-format lossless container data hiding tool")]
pub struct Cli {
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
    /// List supported injection strategies for a carrier
    ListStrategies(ListStrategiesArgs),
}

#[derive(Args, Debug)]
pub struct WriteArgs {
    #[arg(short = 'c', long = "carrier", required = true)]
    pub carrier: PathBuf,

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

    #[arg(long = "strategy", default_value = "auto")]
    pub strategy: String,

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
    #[arg(short = 'c', long = "carrier", required = true)]
    pub carrier: PathBuf,

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
pub struct ListStrategiesArgs {
    #[arg(short = 'c', long = "carrier", required = true)]
    pub carrier: PathBuf,
}

pub fn prompt_password(confirm: bool) -> Result<String, StrHideError> {
    let pwd = rpassword::prompt_password("Enter password: ")
        .map_err(|e| StrHideError::General(format!("Failed to read password: {e}")))?;
    if pwd.is_empty() {
        return Err(StrHideError::Password("Password cannot be empty".into()));
    }
    if confirm {
        let pwd2 = rpassword::prompt_password("Confirm password: ")
            .map_err(|e| StrHideError::General(format!("Failed to read password confirmation: {e}")))?;
        if pwd != pwd2 {
            return Err(StrHideError::Password("Passwords do not match".into()));
        }
    }
    Ok(pwd)
}

pub fn resolve_password(
    pwd_opt: Option<&str>,
    pwd_file: Option<&Path>,
    encrypt_flag: bool,
    confirm: bool,
) -> Result<Option<String>, StrHideError> {
    if let Some(p) = pwd_opt {
        return Ok(Some(p.to_string()));
    }
    if let Some(pf) = pwd_file {
        let mut s = std::fs::read_to_string(pf)
            .map_err(|e| StrHideError::General(format!("Failed to read password file: {e}")))?;
        s = s.trim_end_matches(&['\r', '\n'][..]).to_string();
        return Ok(Some(s));
    }
    if let Ok(env_pwd) = std::env::var("STRHIDE_PASSWORD") {
        if !env_pwd.is_empty() {
            return Ok(Some(env_pwd));
        }
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

    match cli.command {
        Commands::Write(args) => match handle_write(args) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Read(args) => match handle_read(args) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Remove(args) => match handle_remove(args) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Inspect(args) => match handle_inspect(args) {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("[ERROR] {e}");
                1
            }
        },
        Commands::Verify(args) => match handle_verify(args) {
            Ok(_) => 0,
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

fn handle_write(args: WriteArgs) -> Result<(), StrHideError> {
    // --stealth implies encryption (its magics are password-derived); prompt for
    // a password when neither -p nor a password source was supplied.
    let password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
        args.encrypt || args.stealth,
        true,
    )?;

    let mut strategy = args.strategy;
    if strategy == "ask" {
        let mut cf = File::open(&args.carrier)?;
        let strats = list_all_strategies(&mut cf);
        println!("Available strategies for '{}':", args.carrier.display());
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
        text_buf = String::from_utf8(b64_buf)
            .map_err(|e| StrHideError::General(format!("Base64 content is not valid UTF-8: {e}")))?;
        payload_source = PayloadSource::Text(&text_buf);
    } else if let Some(ref t) = args.text {
        if args.unescape {
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
                "Must provide either -d/--data, -t/--text, --text-file, --text-base64, or --stdin".into(),
            ));
        }
    } else {
        return Err(StrHideError::General(
            "Must provide either -d/--data, -t/--text, --text-file, --text-base64, or --stdin".into(),
        ));
    }

    let res = write_carrier(
        &args.carrier,
        payload_source,
        args.output.as_deref(),
        password.as_deref(),
        args.hint.as_deref(),
        &strategy,
        args.stealth,
        args.preserve_time,
        !args.no_backup,
    )?;

    println!(
        "[OK] Successfully embedded into '{}' using strategy '{}'.",
        res.carrier, res.strategy
    );
    println!("     Payload: {} bytes -> UBE: {} bytes.", res.raw_size, res.ube_size);
    if let Some(note) = res.strategy_note {
        println!("     [STRATEGY] {note}");
    }
    if let Some(hint) = res.password_hint {
        println!("     Password Hint: '{hint}'.");
    }
    if let Some(bak) = res.backup_file {
        println!("     [BACKUP] Original carrier backed up to '{bak}'.");
    }
    if let Some(warn) = res.warning {
        eprintln!("[WARNING] {warn}");
    }

    Ok(())
}

fn handle_read(args: ReadArgs) -> Result<(), StrHideError> {
    let mut password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
        false,
        false,
    )?;

    let res = match read_carrier(&args.carrier, args.output.as_deref(), password.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("Password required") && password.is_none() {
                if msg.contains("Hint: '") {
                    if let Some(hint_part) = msg.split("Hint: '").nth(1).and_then(|s| s.rsplit('\'').nth(1)) {
                        println!("[INFO] Password hint: {hint_part}");
                    }
                }
                password = Some(prompt_password(false)?);
                read_carrier(&args.carrier, args.output.as_deref(), password.as_deref())?
            } else {
                return Err(e);
            }
        }
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
        println!("[OK] Extracted payload to '{fn_to_use}' ({} bytes).", res.raw_size);
    }

    Ok(())
}

fn handle_remove(args: RemoveArgs) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
        false,
        false,
    )?;

    let res = remove_carrier(
        &args.carrier,
        args.output.as_deref(),
        password.as_deref(),
        !args.no_backup,
    )?;

    println!("[OK] Successfully stripped hidden data from '{}'.", res.carrier);
    println!("     Restored size: {} bytes.", res.restored_size);
    println!("     SHA-256: {} (100% verified identical to original).", res.restored_sha256);
    if let Some(bak) = res.backup_file {
        println!("     [BACKUP] Prior carrier backed up to '{bak}'.");
    }

    Ok(())
}

fn handle_inspect(args: InspectArgs) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
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
        } else if let Some(strats) = res.supported_strategies {
            println!("Supported Strategies: {}", strats.join(", "));
        }
    }

    Ok(())
}

fn handle_verify(args: VerifyArgs) -> Result<(), StrHideError> {
    let password = resolve_password(
        args.password.as_deref(),
        args.password_file.as_deref(),
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
            if res.level2_envelope.ok { "PASS" } else { "FAIL" },
            res.level2_envelope.detail
        );
        println!(
            "Level 3 (Crypto & Payload):  [{}] {}",
            if res.level3_crypto.ok { "PASS" } else { "FAIL" },
            res.level3_crypto.detail
        );
    }

    Ok(())
}

fn handle_list_strategies(args: ListStrategiesArgs) -> Result<(), StrHideError> {
    let mut cf = File::open(&args.carrier)?;
    let adapter = find_adapter(&mut cf);
    let strats = adapter.supported_strategies();

    println!(
        "Supported strategies for '{}' (Format: {}):",
        args.carrier.display(),
        adapter.format_name()
    );
    for s in strats {
        println!("  - {s}");
    }

    Ok(())
}

fn unescape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(&next) = chars.peek() {
                chars.next();
                match next {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    '\\' => out.push('\\'),
                    '\"' => out.push('\"'),
                    '\'' => out.push('\''),
                    _ => {
                        out.push('\\');
                        out.push(next);
                    }
                }
            } else {
                out.push('\\');
            }
        } else {
            out.push(c);
        }
    }
    out
}
