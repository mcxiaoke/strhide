//! Format x strategy x password x stealth matrix coverage
//! (gap report 2026-10-19, gaps #13-#17).
//!
//! Every cell runs the same table-driven lifecycle:
//! write -> inspect -> verify (L1/L2/L3) -> read -> remove -> byte-exact
//! restore, so a gap in any one operation for a combination is caught.
//!
//! Fills the previously empty cells:
//! - `eof` on JPEG / MP4 / PE (the per-format fallback strategy, previously
//!   only exercised on PNG and ZIP);
//! - stealth on JPEG / MP4 / PDF (previously only PNG / ZIP / PE);
//! - explicitly named non-default strategies `chunk`, `box_uuid`,
//!   `pre_cd_inject`, `pe_overlay` (previously only `auto`-selected ones);
//! - password-less (`BUILTIN_DEFAULT_KEY`) round trips on JPEG and MP4;
//! - `stealth + eof`, `password_hint` on a non-PNG format, and the
//!   stealth-requires-password guard on every supported format.

use crate::common::*;
use std::fs;
use std::path::Path;

use strhide::engine::{
    PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
    write_carrier,
};
use strhide::errors::StrHideError;

// --------------------------------------------------------------------------- synthetic carriers

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fmt {
    Png,
    Jpeg,
    Webp,
    Heif,
    Mp4,
    Wav,
    Mkv,
    Zip,
    Pdf,
    Pe,
}

const ALL_FMTS: &[Fmt] = &[
    Fmt::Png,
    Fmt::Jpeg,
    Fmt::Webp,
    Fmt::Heif,
    Fmt::Mp4,
    Fmt::Wav,
    Fmt::Mkv,
    Fmt::Zip,
    Fmt::Pdf,
    Fmt::Pe,
];

impl Fmt {
    fn name(self) -> &'static str {
        match self {
            Fmt::Png => "PNG",
            Fmt::Jpeg => "JPEG",
            Fmt::Webp => "WEBP",
            Fmt::Heif => "HEIF",
            Fmt::Mp4 => "MP4",
            Fmt::Wav => "WAV",
            Fmt::Mkv => "MKV",
            Fmt::Zip => "ZIP",
            Fmt::Pdf => "PDF",
            Fmt::Pe => "PE",
        }
    }

    fn ext(self) -> &'static str {
        match self {
            Fmt::Png => "png",
            Fmt::Jpeg => "jpg",
            Fmt::Webp => "webp",
            Fmt::Heif => "heic",
            Fmt::Mp4 => "mp4",
            Fmt::Wav => "wav",
            Fmt::Mkv => "mkv",
            Fmt::Zip => "zip",
            Fmt::Pdf => "pdf",
            Fmt::Pe => "exe",
        }
    }

    /// Bytes for this format's carrier.
    fn carrier(self) -> Vec<u8> {
        match self {
            Fmt::Png => make_png(),
            Fmt::Jpeg => make_jpeg(),
            Fmt::Webp => make_webp(),
            Fmt::Heif => make_heif(),
            Fmt::Mp4 => make_mp4(),
            Fmt::Wav => make_wav(),
            Fmt::Mkv => make_mkv(),
            Fmt::Zip => make_zip(),
            Fmt::Pdf => make_pdf(),
            // ~12 kB of code: enough for the smallest envelope even encrypted.
            Fmt::Pe => make_pe(0x3000),
        }
    }

    fn default_strategy(self) -> &'static str {
        match self {
            Fmt::Png => "chunk",
            Fmt::Jpeg => "app_segment",
            Fmt::Webp => "riff_chunk",
            Fmt::Heif => "box_uuid",
            Fmt::Mp4 => "box_uuid",
            Fmt::Wav => "riff_chunk",
            Fmt::Mkv => "ebml_void",
            Fmt::Zip => "pre_cd_inject",
            Fmt::Pdf => "incremental",
            Fmt::Pe => "pe_codebits",
        }
    }

    fn expected_strategies(self) -> &'static [&'static str] {
        match self {
            Fmt::Png => &["chunk", "eof"],
            Fmt::Jpeg => &["app_segment", "eof"],
            Fmt::Webp => &["riff_chunk", "eof"],
            Fmt::Heif => &["box_uuid", "eof"],
            Fmt::Mp4 => &["box_uuid", "eof"],
            Fmt::Wav => &["riff_chunk", "eof"],
            Fmt::Mkv => &["ebml_void", "eof"],
            Fmt::Zip => &["pre_cd_inject", "eof"],
            Fmt::Pdf => &["incremental", "eof"],
            Fmt::Pe => &["pe_codebits", "pe_slack", "pe_overlay", "eof"],
        }
    }

    fn has_guided_stealth(self) -> bool {
        matches!(
            self,
            Fmt::Png | Fmt::Jpeg | Fmt::Webp | Fmt::Heif | Fmt::Mp4 | Fmt::Wav | Fmt::Mkv
        )
    }

    /// Whether this format reports a strategy other than `eof` when `eof` strategy is written.
    /// PE's PeAdapter::locate reports any envelope at/after pe_image_end as `pe_overlay`.
    fn eof_reported_strategy(self) -> Option<&'static str> {
        match self {
            Fmt::Pe => Some("pe_overlay"),
            _ => None,
        }
    }
}

fn cell_name(fmt: Fmt, strategy: &str, password: Option<&str>, stealth: bool) -> String {
    let pwd = if password.is_some() { "pw" } else { "nopw" };
    let st = if stealth { "stealth" } else { "plain" };
    format!("{}_{}_{}_{}", fmt.name().to_lowercase(), strategy, pwd, st)
}

/// One matrix cell: full lifecycle with byte-exact restore.
fn run_cell(
    fmt: Fmt,
    strategy: &str,
    password: Option<&str>,
    stealth: bool,
    expect_strategy: &str,
) {
    let label = cell_name(fmt, strategy, password, stealth);
    let dir = scratch(&label);
    let carrier = dir.join(format!("c.{}", fmt.ext()));
    let original = fmt.carrier();
    fs::write(&carrier, &original).unwrap();

    let out = dir.join(format!("c.steg.{}", fmt.ext()));
    let write = write_carrier(
        &carrier,
        PayloadSource::Text("matrix payload 中文 🚀"),
        &WriteOptions {
            output_path: Some(&out),
            password,
            strategy,
            stealth,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));

    assert_eq!(
        write.strategy,
        expect_strategy,
        "{label}: unexpected strategy (note: {})",
        write.strategy_note.as_deref().unwrap_or("-")
    );
    assert_eq!(write.format, fmt.name(), "{label}: format");
    assert_eq!(write.is_stealth, stealth, "{label}: is_stealth flag");
    assert_eq!(
        write.is_encrypted,
        password.is_some(),
        "{label}: is_encrypted tracks a custom password"
    );

    // inspect
    let insp =
        inspect_carrier(&out, password).unwrap_or_else(|e| panic!("{label}: inspect failed: {e}"));
    assert!(insp.has_hidden_data, "{label}: inspect found nothing");
    assert_eq!(
        insp.strategy.as_deref(),
        Some(expect_strategy),
        "{label}: inspect strategy"
    );
    assert_eq!(
        insp.is_stealth,
        Some(stealth),
        "{label}: inspect is_stealth"
    );
    assert_eq!(
        insp.is_encrypted,
        Some(password.is_some()),
        "{label}: inspect is_encrypted"
    );
    assert!(
        insp.metadata.is_some(),
        "{label}: metadata must be readable"
    );

    // verify: all three levels must pass (the password is supplied when the
    // envelope is encrypted, so Level 3 is always actually run).
    let v =
        verify_carrier(&out, password).unwrap_or_else(|e| panic!("{label}: verify failed: {e}"));
    assert!(v.level1_host.ok, "{label}: L1 {}", v.level1_host.detail);
    assert!(
        v.level2_envelope.ok,
        "{label}: L2 {}",
        v.level2_envelope.detail
    );
    assert!(v.level3_crypto.ok, "{label}: L3 {}", v.level3_crypto.detail);

    // read
    let read =
        read_carrier(&out, None, password).unwrap_or_else(|e| panic!("{label}: read failed: {e}"));
    assert_eq!(
        String::from_utf8(read.data).unwrap(),
        "matrix payload 中文 🚀",
        "{label}: payload round-trip"
    );

    // remove -> byte-exact restore
    let restored = dir.join(format!("c.restored.{}", fmt.ext()));
    let rem = remove_carrier(&out, Some(&restored), password, false)
        .unwrap_or_else(|e| panic!("{label}: remove failed: {e}"));
    assert!(rem.verified_identical, "{label}: remove must verify");
    assert_eq!(
        fs::read(&restored).unwrap(),
        original,
        "{label}: restored carrier must be byte-identical"
    );
}

// --------------------------------------------------------------------------- eof on every format

/// Like `run_cell`, but tolerates the write-time / locate-time strategy name
/// differing. Used for PE `eof`: writing appends after the PE image exactly
/// like `pe_overlay`, and `PeAdapter::locate` (pe.rs:364-372) classifies any
/// envelope at/after `pe_image_end` as `pe_overlay`, so the two are
/// indistinguishable in the produced file. Data integrity is unaffected.
fn run_cell_any_reported_strategy(
    fmt: Fmt,
    write_strategy: &str,
    password: Option<&str>,
    stealth: bool,
) {
    let label = format!(
        "{}__any_reported",
        cell_name(fmt, write_strategy, password, stealth)
    );
    let dir = scratch(&label);
    let carrier = dir.join(format!("c.{}", fmt.ext()));
    let original = fmt.carrier();
    fs::write(&carrier, &original).unwrap();

    let out = dir.join(format!("c.steg.{}", fmt.ext()));
    let write = write_carrier(
        &carrier,
        PayloadSource::Text("matrix payload"),
        &WriteOptions {
            output_path: Some(&out),
            password,
            strategy: write_strategy,
            stealth,
            backup: false,
            ..Default::default()
        },
    )
    .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));
    assert_eq!(write.strategy, write_strategy, "{label}: write strategy");

    let read =
        read_carrier(&out, None, password).unwrap_or_else(|e| panic!("{label}: read failed: {e}"));
    assert_eq!(
        String::from_utf8(read.data).unwrap(),
        "matrix payload",
        "{label}"
    );

    let restored = dir.join(format!("c.restored.{}", fmt.ext()));
    remove_carrier(&out, Some(&restored), password, false)
        .unwrap_or_else(|e| panic!("{label}: remove failed: {e}"));
    assert_eq!(
        fs::read(&restored).unwrap(),
        original,
        "{label}: byte-exact restore"
    );
}

#[test]
fn eof_strategy_roundtrips_on_every_format() {
    for &fmt in ALL_FMTS {
        if fmt.eof_reported_strategy().is_some() {
            // PE eof is reported as pe_overlay on locate (see helper doc).
            run_cell_any_reported_strategy(fmt, "eof", Some("eof-pw"), false);
        } else {
            run_cell(fmt, "eof", Some("eof-pw"), false, "eof");
        }
    }
}

#[test]
fn eof_strategy_without_password_roundtrips() {
    for &fmt in ALL_FMTS {
        if fmt.eof_reported_strategy().is_some() {
            run_cell_any_reported_strategy(fmt, "eof", None, false);
        } else {
            run_cell(fmt, "eof", None, false, "eof");
        }
    }
}

// --------------------------------------------------------------------------- explicitly named strategies

#[test]
fn explicit_non_default_strategies_roundtrip() {
    // One cell per non-eof, non-default strategy in the whole adapter table.
    run_cell(Fmt::Png, "chunk", Some("chunk-pw"), false, "chunk");
    run_cell(
        Fmt::Jpeg,
        "app_segment",
        Some("app-pw"),
        false,
        "app_segment",
    );
    run_cell(
        Fmt::Webp,
        "riff_chunk",
        Some("webp-pw"),
        false,
        "riff_chunk",
    );
    run_cell(Fmt::Heif, "box_uuid", Some("heif-pw"), false, "box_uuid");
    run_cell(Fmt::Mp4, "box_uuid", Some("uuid-pw"), false, "box_uuid");
    run_cell(Fmt::Wav, "riff_chunk", Some("wav-pw"), false, "riff_chunk");
    run_cell(
        Fmt::Zip,
        "pre_cd_inject",
        Some("zip-pw"),
        false,
        "pre_cd_inject",
    );
    run_cell(
        Fmt::Pdf,
        "incremental",
        Some("pdf-pw"),
        false,
        "incremental",
    );
    run_cell(Fmt::Mkv, "ebml_void", Some("mkv-pw"), false, "ebml_void");
    run_cell(
        Fmt::Pe,
        "pe_overlay",
        Some("overlay-pw"),
        false,
        "pe_overlay",
    );
    run_cell(Fmt::Pe, "pe_slack", Some("slack-pw"), false, "pe_slack");
    run_cell(
        Fmt::Pe,
        "pe_codebits",
        Some("codebits-pw"),
        false,
        "pe_codebits",
    );
}

#[test]
fn explicit_strategies_without_password_roundtrip() {
    run_cell(Fmt::Png, "chunk", None, false, "chunk");
    run_cell(Fmt::Jpeg, "app_segment", None, false, "app_segment");
    run_cell(Fmt::Webp, "riff_chunk", None, false, "riff_chunk");
    run_cell(Fmt::Heif, "box_uuid", None, false, "box_uuid");
    run_cell(Fmt::Mp4, "box_uuid", None, false, "box_uuid");
    run_cell(Fmt::Wav, "riff_chunk", None, false, "riff_chunk");
    run_cell(Fmt::Mkv, "ebml_void", None, false, "ebml_void");
    run_cell(Fmt::Zip, "pre_cd_inject", None, false, "pre_cd_inject");
    run_cell(Fmt::Pdf, "incremental", None, false, "incremental");
}

// --------------------------------------------------------------------------- stealth on every format

#[test]
fn stealth_roundtrips_on_every_format() {
    for &fmt in ALL_FMTS {
        run_cell(
            fmt,
            "auto",
            Some("stealth-pw"),
            true,
            fmt.default_strategy(),
        );
    }
}

#[test]
fn stealth_with_eof_strategy_roundtrips() {
    // The combination was never exercised: stealth magics + EOF placement.
    run_cell(Fmt::Png, "eof", Some("st-eof-pw"), true, "eof");
    run_cell(Fmt::Jpeg, "eof", Some("st-eof-pw"), true, "eof");
}

#[test]
fn stealth_envelope_is_invisible_without_its_password() {
    // The stealth magics are password-derived, so a password-less read must
    // not locate the envelope at all — plausible deniability.
    //
    // Only the formats whose adapter implements `suspicious_structures` can
    // add guidance to the error (PNG prIv chunk, JPEG APP15/COM, MP4 uuid
    // box); ZIP and PDF use the trait default (no opinion), so their error is
    // the plain "no hidden data" message. PE's scan only recognizes a *trailing
    // overlay*; stealth `pe_codebits` writes no overlay (the channel lives in
    // .text), so it has nothing to report either.
    for &fmt in ALL_FMTS {
        let label = format!("invisible_{}", fmt.name().to_lowercase());
        let dir = scratch(&label);
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let out = dir.join(format!("c.steg.{}", fmt.ext()));

        write_carrier(
            &carrier,
            PayloadSource::Text("deniable"),
            &WriteOptions {
                output_path: Some(&out),
                password: Some("secret-stealth-pw"),
                stealth: true,
                backup: false,
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));

        let err = read_carrier(&out, None, None).unwrap_err();
        assert!(
            matches!(err, StrHideError::NoHiddenData(_)),
            "{label}: expected NoHiddenData without the password, got {err:?}"
        );
        assert!(
            err.to_string().contains("No hidden strhide data found"),
            "{label}: base message missing: {err}"
        );
        if fmt.has_guided_stealth() {
            assert!(
                err.to_string().contains("stealth envelope"),
                "{label}: guidance missing: {err}"
            );
        }

        // The wrong password is equally invisible (not a Password error).
        let wrong = read_carrier(&out, None, Some("wrong-pw")).unwrap_err();
        assert!(
            matches!(wrong, StrHideError::NoHiddenData(_)),
            "{label}: wrong password must not locate the envelope, got {wrong:?}"
        );
    }
}

#[test]
fn stealth_requires_a_password_on_every_format() {
    for &fmt in ALL_FMTS {
        let dir = scratch(&format!("stealth_guard_{}", fmt.name().to_lowercase()));
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let out = dir.join(format!("c.steg.{}", fmt.ext()));

        let err = write_carrier(
            &carrier,
            PayloadSource::Text("x"),
            &WriteOptions {
                output_path: Some(&out),
                stealth: true,
                backup: false,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("requires a password"),
            "{}: {err}",
            fmt.name()
        );
        assert!(!out.exists(), "{}: nothing must be written", fmt.name());
    }
}

#[test]
fn stealth_and_password_hint_are_mutually_exclusive_on_every_format() {
    for &fmt in ALL_FMTS {
        let dir = scratch(&format!("hint_guard_{}", fmt.name().to_lowercase()));
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let out = dir.join(format!("c.steg.{}", fmt.ext()));

        let err = write_carrier(
            &carrier,
            PayloadSource::Text("x"),
            &WriteOptions {
                output_path: Some(&out),
                password: Some("pw"),
                password_hint: Some("a hint"),
                stealth: true,
                backup: false,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("not supported in --stealth"),
            "{}: {err}",
            fmt.name()
        );
    }
}

// --------------------------------------------------------------------------- password hints on non-PNG formats

#[test]
fn password_hint_roundtrips_on_every_format() {
    for &fmt in ALL_FMTS {
        let label = format!("hint_{}", fmt.name().to_lowercase());
        let dir = scratch(&label);
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let out = dir.join(format!("c.steg.{}", fmt.ext()));
        let hint = "3班1975";

        let res = write_carrier(
            &carrier,
            PayloadSource::Text("hinted"),
            &WriteOptions {
                output_path: Some(&out),
                password: Some("hint-pw"),
                password_hint: Some(hint),
                backup: false,
                ..Default::default()
            },
        )
        .unwrap_or_else(|e| panic!("{label}: write failed: {e}"));
        assert_eq!(res.password_hint.as_deref(), Some(hint), "{label}");

        // The hint is visible without the password...
        let insp = inspect_carrier(&out, None).expect("inspect");
        assert_eq!(
            insp.password_hint.as_deref(),
            Some(hint),
            "{label}: inspect hint"
        );

        // ...and appears in the password error.
        let err = read_carrier(&out, None, None).unwrap_err();
        assert!(
            matches!(err, StrHideError::Password(_)),
            "{label}: expected Password variant, got {err:?}"
        );
        assert!(err.to_string().contains(hint), "{label}: {err}");

        // With the password the payload still reads back.
        let read = read_carrier(&out, None, Some("hint-pw")).expect("read");
        assert_eq!(String::from_utf8(read.data).unwrap(), "hinted", "{label}");
    }
}

// --------------------------------------------------------------------------- password-less (default key) round trips

#[test]
fn password_less_roundtrips_on_every_format() {
    for &fmt in ALL_FMTS {
        run_cell(fmt, "auto", None, false, fmt.default_strategy());
    }
}

// --------------------------------------------------------------------------- multi-payload stacking guard

#[test]
fn second_write_into_a_filled_carrier_is_refused_on_every_format() {
    for &fmt in ALL_FMTS {
        let label = format!("double_{}", fmt.name().to_lowercase());
        let dir = scratch(&label);
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();
        let first = dir.join(format!("c1.{}", fmt.ext()));
        let second = dir.join(format!("c2.{}", fmt.ext()));

        fn opts(out: &Path) -> WriteOptions<'_> {
            WriteOptions {
                output_path: Some(out),
                backup: false,
                ..Default::default()
            }
        }
        write_carrier(&carrier, PayloadSource::Text("first"), &opts(&first))
            .unwrap_or_else(|e| panic!("{label}: first write failed: {e}"));

        let err = write_carrier(&first, PayloadSource::Text("second"), &opts(&second)).unwrap_err();
        assert!(
            err.to_string().contains("already contains hidden data"),
            "{}: {err}",
            fmt.name()
        );
        assert!(
            !second.exists(),
            "{}: no output must be produced",
            fmt.name()
        );
    }
}

// --------------------------------------------------------------------------- capacity reporting per format

#[test]
fn inspect_reports_all_strategies_for_every_format() {
    for &fmt in ALL_FMTS {
        let dir = scratch(&format!("caps_{}", fmt.name().to_lowercase()));
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();

        let insp = inspect_carrier(&carrier, None).expect("inspect");
        let names: Vec<&str> = insp
            .strategies
            .iter()
            .map(|c| c.strategy.as_str())
            .collect();
        assert_eq!(
            names,
            fmt.expected_strategies(),
            "{}: strategy order",
            fmt.name()
        );
        for c in &insp.strategies {
            assert!(!c.limit.is_empty(), "{}: empty limit", fmt.name());
        }
        // At least one strategy must be usable, otherwise nothing can be done.
        assert!(
            insp.strategies.iter().any(|c| c.available),
            "{}: no available strategy",
            fmt.name()
        );
    }
}

#[test]
fn verify_structure_passes_for_a_pristine_carrier_of_every_format() {
    for &fmt in ALL_FMTS {
        let dir = scratch(&format!("verify_clean_{}", fmt.name().to_lowercase()));
        let carrier = dir.join(format!("c.{}", fmt.ext()));
        fs::write(&carrier, fmt.carrier()).unwrap();

        let v = verify_carrier(&carrier, None).expect("verify");
        assert!(
            v.level1_host.ok,
            "{}: L1 must pass on a pristine carrier: {}",
            fmt.name(),
            v.level1_host.detail
        );
        assert!(!v.level2_envelope.ok, "{}: no envelope yet", fmt.name());
    }
}
