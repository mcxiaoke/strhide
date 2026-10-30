// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Argument-to-value resolution shared by the subcommand handlers.
//!
//! Passwords, payload sources, and content-domain tuning all follow a
//! precedence chain (explicit flag -> environment -> prompt; content tuning
//! also falls back to config) that must be identical for every verb; keeping
//! them here is what stops `write` and `embed` from drifting apart.

use std::fs::File;
use std::path::{Path, PathBuf};

use crate::core::config::FileConfig;
use crate::core::i18n::Msg;
use crate::errors::StrHideError;
use crate::formats::FileFormat;
use crate::stego::{
    EmbedOptions, HevcMode, JpegAlgorithm, JpegParams, PngParams, ProbeOptions, SafetyEnforcement,
    SafetyLevel, SafetyPolicy, SpatialAlgorithm, StegoTuning,
};
use crate::structure::registry::find_adapter_or_reject;
use crate::t;

use super::args::{PayloadSourceArgs, StegoTuningArgs};

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
    encrypt_flag: bool,
    confirm: bool,
) -> Result<Option<String>, StrHideError> {
    if let Some(p) = pwd_opt {
        if p.is_empty() {
            return Err(StrHideError::Password("Password cannot be empty".into()));
        }
        return Ok(Some(p.to_string()));
    }
    if let Some(pf) = pwd_file {
        // Name the file in the error: the bare OS message ("file not found")
        // does not tell the user WHICH password file failed, and several
        // commands accept one.
        let s = std::fs::read_to_string(pf).map_err(|e| {
            StrHideError::General(format!(
                "Failed to read password file '{}': {e}",
                pf.display()
            ))
        })?;
        let first_line = s
            .lines()
            .next()
            .unwrap_or_default()
            .trim_end_matches(&['\r', '\n'][..]);
        if first_line.is_empty() {
            return Err(StrHideError::Password("Password cannot be empty".into()));
        }
        return Ok(Some(first_line.to_string()));
    }
    if let Ok(env_pwd) = std::env::var("STRHIDE_PASSWORD") {
        let env_trimmed = env_pwd.trim_end_matches(&['\r', '\n'][..]);
        if !env_trimmed.is_empty() {
            return Ok(Some(env_trimmed.to_string()));
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

/// How a payload source is materialised.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadFlavor {
    /// Text payload: every source must be valid UTF-8 and is stored as text.
    Text,
    /// Raw bytes: any source is accepted exactly as it is.
    Bytes,
}

/// A payload source resolved from the CLI.
pub(crate) enum ResolvedPayload {
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
pub(crate) fn resolve_payload(
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

/// Whether any per-format tuning flag was given.
///
/// A tuning arm can only be built once the carrier format is known, so this
/// decides whether an unsniffable carrier is an error ("you asked for a PNG
/// filter window, but this file is not an image") or just "use the defaults".
pub(crate) fn has_per_format_flags(args: &StegoTuningArgs) -> bool {
    args.exclusion_rate.is_some()
        || args.neighbor_weight.is_some()
        || args.slot_budget.is_some()
        || args.cipher_suite.is_some()
        || args.p1_window.is_some()
        || args.p2_window.is_some()
        || args.stc_h.is_some()
}

/// Build the [`StegoTuning`] the flags ask for.
///
/// The format has to be known here: a tuning arm names one format's cost model
/// and parameters, and `--stc-h` / `--exclusion-rate` mean different structs
/// depending on which arm they land in. `None` therefore means "the user asked
/// for per-format tuning on a file whose format we cannot sniff", which is an
/// error rather than a silently ignored flag.
pub(crate) fn stego_tuning(
    args: &StegoTuningArgs,
    format: Option<FileFormat>,
    cfg: &FileConfig,
) -> Result<StegoTuning, StrHideError> {
    // An explicit `--algorithm` picks the arm on its own: naming a model is
    // already a statement about which format it belongs to. A `[stego]
    // algorithm` from the config file acts as the same statement when no flag
    // was given.
    let configured = cfg.stego.as_ref().and_then(|s| s.algorithm.as_deref());
    if let Some(name) = args.algorithm.as_deref().or(configured) {
        let name = name.trim();
        if name != "auto" {
            if let Some(model) = SpatialAlgorithm::from_name(name) {
                let mut params = PngParams::default();
                apply_png_flags(&mut params, args);
                return Ok(StegoTuning::Png { model, params });
            }
            if let Some(model) = JpegAlgorithm::from_name(name) {
                let mut params = JpegParams::default();
                apply_jpeg_flags(&mut params, args);
                return Ok(StegoTuning::Jpeg { model, params });
            }
            if let Some(mode) = HevcMode::from_name(name) {
                return Ok(StegoTuning::hevc(mode));
            }
            return Err(StrHideError::General(format!(
                "Unknown algorithm '{name}'. Supported: hill, suniward (PNG), uerd, juniward (JPEG), \
                 hevc, cabac (HEIF/HEVC), auto"
            )));
        }
        // `auto` with format-level tuning flags must still honour them; only a
        // bare "auto" means "let every format use its defaults".
        if !has_per_format_flags(args) {
            return Ok(StegoTuning::Auto);
        }
    }

    if !has_per_format_flags(args) {
        return Ok(StegoTuning::Auto);
    }

    let Some(format) = format else {
        return Err(StrHideError::General(
            "Tuning flags such as --stc-h need to know the carrier format, and this file \
             could not be recognised as a PNG, JPEG, HEIF/HEIC, or HEVC carrier"
                .into(),
        ));
    };

    match format {
        FileFormat::Png => {
            let mut params = PngParams::default();
            apply_png_flags(&mut params, args);
            Ok(StegoTuning::Png {
                model: SpatialAlgorithm::default(),
                params,
            })
        }
        FileFormat::Jpeg => {
            let mut params = JpegParams::default();
            apply_jpeg_flags(&mut params, args);
            Ok(StegoTuning::Jpeg {
                model: JpegAlgorithm::default(),
                params,
            })
        }
        // HEVC has no per-call tuning yet, so these flags carry nothing to
        // apply. They stay accepted (and ignored) exactly as before rather than
        // turning a working command line into an error.
        _ => Ok(StegoTuning::Auto),
    }
}

/// Apply the spatial-only flags.
pub(crate) fn apply_png_flags(params: &mut PngParams, args: &StegoTuningArgs) {
    if let Some(er) = args.exclusion_rate {
        params.exclusion_percentile = er;
    }
    if let Some(p1) = args.p1_window {
        params.p1_window = p1;
    }
    if let Some(p2) = args.p2_window {
        params.p2_window = p2;
    }
    if let Some(h) = args.stc_h {
        params.stc_h = h;
    }
}

/// Apply the DCT-only flags.
pub(crate) fn apply_jpeg_flags(params: &mut JpegParams, args: &StegoTuningArgs) {
    if let Some(nw) = args.neighbor_weight {
        params.neighbor_weight = nw;
    }
    if let Some(budget) = args.slot_budget {
        params.slot_budget = Some(budget);
    }
    if let Some(suite) = args.cipher_suite {
        params.cipher_suite = suite;
    }
    if let Some(h) = args.stc_h {
        params.stc_h = h;
    }
}

/// Parse `--safety` and `--enforce-safety` into one policy.
pub(crate) fn stego_safety(
    args: &StegoTuningArgs,
    cfg: &FileConfig,
) -> Result<SafetyPolicy, StrHideError> {
    // Flag wins over `[stego] safety`, which wins over the built-in default.
    let configured = cfg.stego.as_ref().and_then(|s| s.safety.as_deref());
    let level = match args.safety.as_deref().or(configured) {
        Some(s) => match SafetyLevel::parse(s) {
            Some(lvl) => lvl,
            None => {
                return Err(StrHideError::General(format!(
                    "Invalid safety level '{s}'. Supported: 'paranoid', 'high', 'balanced'"
                )));
            }
        },
        None => SafetyLevel::High,
    };
    Ok(SafetyPolicy {
        level,
        enforcement: if args.enforce_safety
            || cfg
                .stego
                .as_ref()
                .and_then(|s| s.enforce_safety)
                .unwrap_or(false)
        {
            SafetyEnforcement::Enforced
        } else {
            SafetyEnforcement::Advisory
        },
    })
}

/// Assemble the option sets for `embed` and the capacity probe.
///
/// The `--capacity` probe and the real embed used to build this list twice, and
/// the two copies had drifted: only the embed path applied `--stc-h`, so a probe
/// could report a capacity for a different configuration than the one that was
/// about to be used. One builder now serves both callers and returns both typed
/// option sets, so neither has to borrow the other's fields.
///
/// The only credential it carries is the user password; a private no-password
/// dialect (secret, domain, wire-format identity) is compile-time
/// [`Dialect`](crate::facade::Dialect) territory, not a CLI flag.
pub(crate) fn stego_options<'a>(
    args: &StegoTuningArgs,
    password: Option<&'a str>,
    format: Option<FileFormat>,
    cfg: &FileConfig,
) -> Result<(EmbedOptions<'a>, ProbeOptions<'a>), StrHideError> {
    let tuning = stego_tuning(args, format, cfg)?;
    let safety = stego_safety(args, cfg)?;
    let mut embed = EmbedOptions {
        password,
        safety,
        tuning: tuning.clone(),
        exact: args.exact,
        ..Default::default()
    };
    if let Some(seed_hex) = args.seed.as_deref() {
        embed.freshness = crate::stego::Freshness::Seeded(parse_seed_hex(seed_hex)?);
    }
    let probe = ProbeOptions {
        password,
        safety,
        tuning,
        exact: args.exact,
        ..Default::default()
    };
    Ok((embed, probe))
}

/// The carrier's sniffed format, for tuning build-out.
pub(crate) fn carrier_format(bytes: &[u8]) -> Option<FileFormat> {
    crate::formats::sniff::sniff_bytes(bytes)
}

/// Parse a 64-hex-digit deterministic seed for `--seed`.
///
/// A short or non-hex seed is rejected instead of being padded or hashed:
/// silently deriving a seed from arbitrary text would make two "same" seeds
/// produce different carriers, which is exactly the failure mode the flag
/// exists to prevent.
pub(crate) fn parse_seed_hex(text: &str) -> Result<[u8; 32], StrHideError> {
    let digits = text.trim();
    let digits = digits.strip_prefix("0x").unwrap_or(digits);
    if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(StrHideError::General(
            "--seed must be exactly 64 hex digits (32 bytes), e.g. \
             --seed 000102...3e3f"
                .into(),
        ));
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&digits[i * 2..i * 2 + 2], 16)
            .map_err(|e| StrHideError::General(format!("--seed is not valid hex: {e}")))?;
    }
    Ok(out)
}

/// Carrier validator handed to [`crate::core::pipeline::preflight_batch`].
///
/// Format knowledge stays in the CLI (and in the structure domain); `core`
/// receives it as a callback so the batch rules remain format-agnostic.
pub(crate) fn validate_carrier_format(carrier: &Path) -> Result<(), StrHideError> {
    let mut f = File::open(carrier)?;
    find_adapter_or_reject(&mut f, &carrier.display().to_string())?;
    Ok(())
}

/// Stego carrier validator handed to [`crate::core::pipeline::preflight_batch`].
pub(crate) fn validate_stego_carrier_format(carrier: &Path) -> Result<(), StrHideError> {
    let Some(format) = crate::formats::sniff_file(carrier)? else {
        return Err(StrHideError::UnsupportedFormat(
            "Content-adaptive steganography requires a PNG, JPEG, HEIF/HEIC, or HEVC carrier (Annex-B or MP4/MOV)".into(),
        ));
    };
    crate::stego::engine::engine_for(format)
        .ok_or_else(|| crate::stego::unsupported_carrier(format))?;
    Ok(())
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
pub(crate) fn unescape_string(s: &str) -> String {
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
pub(crate) fn read_hex(chars: &[char], start: usize, count: usize) -> Option<u32> {
    let mut value = 0u32;
    for k in 0..count {
        let d = chars.get(start + k)?.to_digit(16)?;
        value = value * 16 + d;
    }
    Some(value)
}

/// Format large counts (elements, slots, etc.) into human-readable units (K, M, G, T).
pub(crate) fn format_count(n: u64) -> String {
    let f = n as f64;
    if n < 1_000 {
        format!("{n}")
    } else if n < 1_000_000 {
        format!("{:.2}K", f / 1_000.0)
    } else if n < 1_000_000_000 {
        format!("{:.2}M", f / 1_000_000.0)
    } else if n < 1_000_000_000_000 {
        format!("{:.2}G", f / 1_000_000_000.0)
    } else {
        format!("{:.2}T", f / 1_000_000_000_000.0)
    }
}

/// Format byte counts into human-readable binary units (B, KiB, MiB, GiB, TiB).
pub(crate) fn format_size(bytes: u64) -> String {
    let f = bytes as f64;
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const TIB: f64 = 1024.0 * 1024.0 * 1024.0 * 1024.0;

    if bytes < 1024 {
        format!("{bytes} B")
    } else if f < MIB {
        format!("{:.2} KiB", f / KIB)
    } else if f < GIB {
        format!("{:.2} MiB", f / MIB)
    } else if f < TIB {
        format!("{:.2} GiB", f / GIB)
    } else {
        format!("{:.2} TiB", f / TIB)
    }
}

/// Format elapsed time into human-friendly duration strings.
pub(crate) fn format_duration(d: std::time::Duration) -> String {
    let secs_f = d.as_secs_f64();
    if secs_f < 1.0 {
        format!("{}ms", d.as_millis())
    } else if secs_f < 60.0 {
        format!("{:.2}s", secs_f)
    } else {
        let total_secs = d.as_secs();
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{mins}m {secs}s")
    }
}

/// Summarise steganography algorithm name and relevant hyper-parameters.
pub(crate) fn format_stego_algorithm(
    tuning: &StegoTuning,
    safety: &SafetyPolicy,
    format: Option<FileFormat>,
    cap_algo: Option<&str>,
) -> String {
    let safety_str = safety.level.as_str();
    match tuning {
        #[cfg(feature = "content-png")]
        StegoTuning::Png { model, params } => {
            format!(
                "{} (stc_h: {}, safety: {})",
                model.id(),
                params.stc_h,
                safety_str
            )
        }
        #[cfg(feature = "content-jpeg")]
        StegoTuning::Jpeg { model, params } => {
            format!(
                "{} (stc_h: {}, safety: {})",
                model.id(),
                params.stc_h,
                safety_str
            )
        }
        #[cfg(feature = "content-hevc")]
        StegoTuning::Hevc { .. } => {
            let name = cap_algo.unwrap_or("HEVC-CABAC-InPlace");
            format!("{name} (safety: {safety_str})")
        }
        StegoTuning::Auto => match format {
            #[cfg(feature = "content-png")]
            Some(FileFormat::Png) => {
                let name = cap_algo.unwrap_or("hill");
                format!(
                    "{name} (stc_h: {}, safety: {safety_str})",
                    crate::stego::coding::DEFAULT_STC_H
                )
            }
            #[cfg(feature = "content-jpeg")]
            Some(FileFormat::Jpeg) => {
                let name = cap_algo.unwrap_or("uerd");
                format!(
                    "{name} (stc_h: {}, safety: {safety_str})",
                    crate::stego::coding::DEFAULT_STC_H
                )
            }
            #[cfg(feature = "content-hevc")]
            Some(FileFormat::Mp4 | FileFormat::Heif | FileFormat::HevcAnnexB) => {
                let name = cap_algo.unwrap_or("HEVC-CABAC-InPlace");
                format!("{name} (safety: {safety_str})")
            }
            _ => {
                if let Some(algo) = cap_algo {
                    format!("{algo} (safety: {safety_str})")
                } else {
                    format!("auto (safety: {safety_str})")
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(0), "0");
        assert_eq!(format_count(999), "999");
        assert_eq!(format_count(1_000), "1.00K");
        assert_eq!(format_count(12_500), "12.50K");
        assert_eq!(format_count(559_362_333), "559.36M");
        assert_eq!(format_count(71_443_814_400), "71.44G");
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.00 KiB");
        assert_eq!(format_size(100 * 1024), "100.00 KiB");
        assert_eq!(format_size(1_500_122), "1.43 MiB");
        assert_eq!(format_size(34_960_095), "33.34 MiB");
        assert_eq!(format_size(1024 * 1024 * 1024 * 2), "2.00 GiB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_millis(42)), "42ms");
        assert_eq!(format_duration(Duration::from_millis(999)), "999ms");
        assert_eq!(format_duration(Duration::from_millis(1250)), "1.25s");
        assert_eq!(format_duration(Duration::from_secs(65)), "1m 5s");
        assert_eq!(format_duration(Duration::from_secs(135)), "2m 15s");
    }

    #[test]
    fn test_format_stego_algorithm() {
        let safety = SafetyPolicy::default(); // high
        let s = format_stego_algorithm(
            &StegoTuning::Auto,
            &safety,
            Some(FileFormat::Mp4),
            Some("HEVC-CABAC-InPlace"),
        );
        assert_eq!(s, "HEVC-CABAC-InPlace (safety: high)");

        let s2 = format_stego_algorithm(&StegoTuning::Auto, &safety, Some(FileFormat::Jpeg), None);
        assert_eq!(
            s2,
            format!(
                "uerd (stc_h: {}, safety: high)",
                crate::stego::coding::DEFAULT_STC_H
            ),
            "the capacity banner must advertise the real default height"
        );
    }
}
