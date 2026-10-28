// Copyright (c) 2026 strhide developers
// SPDX-License-Identifier: Apache-2.0

//! Facade ([`StrHide`]) integration tests: the verb × carrier matrix.
//!
//! These verify the two sub-facades ([`StructureFacade`] / [`StegoFacade`])
//! forward correctly across both domains and both carrier forms (path / bytes),
//! that the option structs (`ReadOptions` / `RestoreOptions`) drive the
//! overwrite behaviour, and that a private dialect bound on an engine is
//! isolated from the official engine.

use strhide::core::payload::Payload;
use strhide::facade::{Dialect, StrHide};
use strhide::stego::params::StegoProfile;
use strhide::stego::{EmbedOptions, ExtractOptions, ProbeOptions};
use strhide::structure::params::StructureProfile;
use strhide::structure::{PayloadSource, ReadOptions, RestoreOptions, WriteOptions};

use crate::common::scratch;

const PNG: &[u8] = include_bytes!("../assets/minimal.png");
const JPG: &[u8] = include_bytes!("../assets/small.jpg");

const STRUCT_PAYLOAD: &[u8] = b"facade structure payload";
const CONTENT_PAYLOAD: &[u8] = b"facade content payload";

// ───────────────────────── structure domain · bytes ─────────────────────────

#[test]
fn structure_bytes_write_read_restore_roundtrip() {
    let engine = StrHide::new();
    let options = WriteOptions::default();

    let (stego, write) = engine
        .structure()
        .write_bytes(PNG, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("write_bytes");
    assert!(write.ube_size > 0);
    assert_ne!(stego, PNG);

    let read = engine
        .structure()
        .read_bytes(&stego, None)
        .expect("read_bytes");
    assert_eq!(read.data, STRUCT_PAYLOAD);

    let (restored, _remove) = engine
        .structure()
        .restore_bytes(&stego, None)
        .expect("restore_bytes");
    assert_eq!(
        restored, PNG,
        "restore_bytes must recover the original carrier"
    );
}

#[test]
fn structure_bytes_inspect_and_verify() {
    let engine = StrHide::new();
    let options = WriteOptions::default();
    let (stego, _) = engine
        .structure()
        .write_bytes(PNG, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("write_bytes");

    let inspect = engine
        .structure()
        .inspect_bytes(&stego, None)
        .expect("inspect_bytes");
    assert!(inspect.has_hidden_data, "inspect must report hidden data");

    let verify = engine
        .structure()
        .verify_bytes(&stego, None)
        .expect("verify_bytes");
    assert!(
        strhide::structure::verify_passed(&verify),
        "verify must pass"
    );
}

// ───────────────────────── structure domain · path ──────────────────────────

#[test]
fn structure_path_write_read_restore_roundtrip() {
    let dir = scratch("facade_struct_path");
    let carrier = dir.join("carrier.png");
    std::fs::write(&carrier, PNG).expect("seed carrier");

    let engine = StrHide::new();
    let options = WriteOptions {
        backup: false,
        ..WriteOptions::default()
    };

    engine
        .structure()
        .write_file(&carrier, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("write");

    let read = engine
        .structure()
        .read_file(&carrier, &ReadOptions::default())
        .expect("read");
    assert_eq!(read.data, STRUCT_PAYLOAD);

    engine
        .structure()
        .restore_file(&carrier, &RestoreOptions::default())
        .expect("restore");
    assert_eq!(
        std::fs::read(&carrier).expect("read carrier"),
        PNG,
        "restore must recover the original carrier on disk"
    );
}

#[test]
fn structure_path_inspect_and_verify() {
    let dir = scratch("facade_struct_inspect");
    let carrier = dir.join("carrier.png");
    std::fs::write(&carrier, PNG).expect("seed carrier");

    let engine = StrHide::new();
    let options = WriteOptions {
        backup: false,
        ..WriteOptions::default()
    };
    engine
        .structure()
        .write_file(&carrier, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("write");

    let inspect = engine
        .structure()
        .inspect_file(&carrier, None)
        .expect("inspect");
    assert!(inspect.has_hidden_data);

    let verify = engine
        .structure()
        .verify_file(&carrier, None)
        .expect("verify");
    assert!(strhide::structure::verify_passed(&verify));
}

// ───────────────────────── content domain · bytes ───────────────────────────

#[test]
fn content_bytes_embed_extract_roundtrip() {
    let engine = StrHide::new();
    let options = EmbedOptions::default();

    let stego = engine
        .stego()
        .embed(JPG, &Payload::bytes(CONTENT_PAYLOAD), &options)
        .expect("embed");
    assert_ne!(stego, JPG);

    let extracted = engine
        .stego()
        .extract(&stego, &options.extract_options())
        .expect("extract");
    assert_eq!(extracted.data.as_ref(), CONTENT_PAYLOAD);
}

#[test]
fn content_bytes_probe_reports_capacity() {
    let engine = StrHide::new();
    let options = ProbeOptions::default();
    let cap = engine.stego().probe(JPG, &options).expect("probe");
    assert!(cap.recommended_max_bytes > 0);
}

// ───────────────────────── content domain · file ────────────────────────────

#[test]
fn content_file_embed_and_extract_roundtrip() {
    let dir = scratch("facade_content_file");
    let carrier = dir.join("carrier.jpg");
    std::fs::write(&carrier, JPG).expect("seed carrier");
    let output = dir.join("extracted.bin");

    let engine = StrHide::new();
    let options = EmbedOptions::default();

    let target_cfg = strhide::commit::FileTarget {
        output_path: None,
        backup: false,
        preserve_time: true,
        overwrite: true,
    };
    engine
        .stego()
        .embed_file(
            &carrier,
            &Payload::bytes(CONTENT_PAYLOAD),
            &options,
            &target_cfg,
        )
        .expect("embed_file");

    engine
        .stego()
        .extract_file(&carrier, &output, &ExtractOptions::default(), false)
        .expect("extract_file");
    assert_eq!(
        std::fs::read(&output).expect("read output"),
        CONTENT_PAYLOAD
    );
}

#[test]
fn content_file_embed_to_target_leaves_original_untouched() {
    let dir = scratch("facade_content_target");
    let carrier = dir.join("carrier.jpg");
    std::fs::write(&carrier, JPG).expect("seed carrier");
    let target = dir.join("target.jpg");

    let engine = StrHide::new();
    let options = EmbedOptions::default();
    let target_cfg = strhide::commit::FileTarget {
        output_path: Some(&target),
        backup: false,
        preserve_time: true,
        overwrite: true,
    };
    engine
        .stego()
        .embed_file(
            &carrier,
            &Payload::bytes(CONTENT_PAYLOAD),
            &options,
            &target_cfg,
        )
        .expect("embed_file to target");

    assert_eq!(std::fs::read(&carrier).expect("read carrier"), JPG);
    assert!(target.exists());
}

// ───────────────────────── private dialect isolation ────────────────────────

#[test]
fn private_dialect_engine_is_isolated_from_official() {
    const PRIVATE_ENGINE: StrHide =
        StrHide::new().with_dialect(Dialect::new().with_structure_profile(
            StructureProfile::new().with_default_secret("facade-private-key"),
        ));
    assert!(!PRIVATE_ENGINE.dialect().structure.is_official());

    let options = WriteOptions::default();
    let (stego, _) = PRIVATE_ENGINE
        .structure()
        .write_bytes(PNG, PayloadSource::Bytes(STRUCT_PAYLOAD), &options)
        .expect("private write");

    // The official engine cannot read a carrier written under the private dialect.
    let official = StrHide::new();
    assert!(
        official.structure().read_bytes(&stego, None).is_err(),
        "official engine must not read a private carrier"
    );

    // The private engine still reads its own carrier.
    let read = PRIVATE_ENGINE
        .structure()
        .read_bytes(&stego, None)
        .expect("private read");
    assert_eq!(read.data, STRUCT_PAYLOAD);
}

#[test]
fn one_dialect_secret_applies_to_both_domains() {
    // `Dialect::with_default_secret` is the one-line private deployment knob:
    // it must key both halves, so neither the envelope nor the image carrier is
    // readable with an official build.
    let dialect = Dialect::new().with_default_secret("one-key-both-domains");
    assert!(!dialect.is_official());
    assert_eq!(dialect.structure.secret(), "one-key-both-domains");
    assert_eq!(dialect.stego.secret(), Some("one-key-both-domains"));

    let private = StrHide::new().with_dialect(dialect);

    // Structure half: unreadable by the official engine.
    let (stego_png, _) = private
        .structure()
        .write_bytes(
            PNG,
            PayloadSource::Bytes(STRUCT_PAYLOAD),
            &WriteOptions::default(),
        )
        .expect("private structure write");
    assert!(
        StrHide::new()
            .structure()
            .read_bytes(&stego_png, None)
            .is_err()
    );

    // Content half: unreadable by the official engine.
    let options = EmbedOptions::default();
    let stego_jpg = private
        .stego()
        .embed(JPG, &Payload::bytes(CONTENT_PAYLOAD), &options)
        .expect("private content embed");
    assert!(
        StrHide::new()
            .stego()
            .extract(&stego_jpg, &options.extract_options())
            .is_err(),
        "official engine must not extract a private content carrier"
    );
    let back = private
        .stego()
        .extract(&stego_jpg, &options.extract_options())
        .expect("private extract");
    assert_eq!(back.data.as_ref(), CONTENT_PAYLOAD);

    // A dialect that only customises the content half stays official for the
    // structure domain: the two halves are independent.
    let stego_only =
        Dialect::new().with_stego_profile(StegoProfile::new().with_default_secret("k"));
    assert!(!stego_only.is_official());
    assert!(stego_only.structure.is_official());
}

#[test]
fn per_op_local_params_override_does_not_mutate_engine() {
    use strhide::params::{CompressionStrategy, LocalParams};

    let engine = StrHide::new();
    let original = *engine.local_params();

    // A per-call override runs on a copied engine; the original is unchanged.
    let tuned =
        engine.with_local_params(LocalParams::new().with_compression(CompressionStrategy::Never));
    assert_eq!(*engine.local_params(), original);
    assert_eq!(tuned.local_params().compression, CompressionStrategy::Never);
}

// ───────────────────── run_cli_from (engine-driven CLI) ─────────────────────

#[cfg(feature = "cli")]
#[test]
fn run_cli_from_version_returns_zero() {
    let engine = StrHide::new();
    let code = engine.run_cli_from(["strhide", "--version"]);
    assert_eq!(code, 0);
}

#[cfg(feature = "cli")]
#[test]
fn run_cli_from_help_returns_zero() {
    let engine = StrHide::new();
    let code = engine.run_cli_from(["strhide", "--help"]);
    assert_eq!(code, 0);
}

#[cfg(feature = "cli")]
#[test]
fn run_cli_from_private_dialect_isolation() {
    let dir = scratch("facade_cli_private");
    let carrier = dir.join("carrier.png");
    std::fs::write(&carrier, PNG).expect("seed carrier");

    const PRIVATE: StrHide = StrHide::new()
        .with_dialect(Dialect::new().with_structure_profile(
            StructureProfile::new().with_default_secret("cli-private-key"),
        ));
    assert!(!PRIVATE.dialect().structure.is_official());

    // The private engine writes through its own command line.
    let carrier_str = carrier.to_str().expect("utf-8 path");
    let write_code = PRIVATE.run_cli_from([
        "strhide",
        "write",
        carrier_str,
        "-t",
        "cli private payload",
        "--in-place",
        "--no-backup",
    ]);
    assert_eq!(write_code, 0, "private write via CLI must succeed");

    // The official engine cannot read the private carrier through its CLI.
    let official = StrHide::new();
    let read_official = official.run_cli_from(["strhide", "read", carrier_str, "--stdout"]);
    assert_ne!(
        read_official, 0,
        "official CLI read must fail on a private carrier"
    );

    // The private engine reads its own carrier.
    let read_private = PRIVATE.run_cli_from(["strhide", "read", carrier_str, "--stdout"]);
    assert_eq!(read_private, 0, "private CLI read must succeed");
}

#[cfg(feature = "cli")]
#[test]
fn run_cli_from_content_domain_private_isolation() {
    let dir = scratch("facade_cli_content");
    let carrier = dir.join("carrier.jpg");
    std::fs::write(&carrier, JPG).expect("seed carrier");

    // A private stego dialect (custom domain + secret).
    const PRIVATE: StrHide = StrHide::new().with_dialect(
        Dialect::new().with_stego_profile(
            StegoProfile::new()
                .with_default_secret("cli-stego-key")
                .with_stego_domain("cli-stego-domain"),
        ),
    );

    let carrier_str = carrier.to_str().expect("utf-8 path");
    let embed_code = PRIVATE.run_cli_from([
        "strhide",
        "embed",
        carrier_str,
        "-t",
        "cli stego payload",
        "--in-place",
        "--no-backup",
    ]);
    assert_eq!(embed_code, 0, "private embed via CLI must succeed");

    // Official extraction must fail on the private stego carrier.
    let official = StrHide::new();
    let extract_official = official.run_cli_from(["strhide", "extract", carrier_str, "--stdout"]);
    assert_ne!(
        extract_official, 0,
        "official CLI extract must fail on a private stego carrier"
    );

    // Private extraction succeeds.
    let extract_private = PRIVATE.run_cli_from(["strhide", "extract", carrier_str, "--stdout"]);
    assert_eq!(extract_private, 0, "private CLI extract must succeed");
}

// ───────────────────────── overwrite policy ─────────────────────────

/// `read` / `restore` used to hard-code `overwrite = false` on the facade, so a
/// caller could not replace an existing destination without dropping down to a
/// positional free function. Both now take an option struct, and the refusing
/// default must leave the existing file untouched.
#[test]
fn structure_read_and_restore_honour_the_overwrite_flag() {
    use strhide::errors::StrHideError;

    let dir = scratch("facade_overwrite");
    let engine = StrHide::new();
    let carrier = dir.join("carrier.png");
    std::fs::write(&carrier, PNG).expect("seed carrier");

    engine
        .structure()
        .write_file(
            &carrier,
            PayloadSource::Bytes(STRUCT_PAYLOAD),
            &WriteOptions::default(),
        )
        .expect("write");

    let out = dir.join("payload.bin");
    std::fs::write(&out, b"stale").expect("seed output");

    let err = engine
        .structure()
        .read_file(&carrier, &ReadOptions::new().with_output(&out))
        .expect_err("read must refuse an existing destination");
    assert!(
        matches!(err, StrHideError::Rejection(_)),
        "expected Rejection, got {err:?}"
    );
    assert_eq!(
        std::fs::read(&out).expect("read back"),
        b"stale",
        "a refused read must not truncate the existing file"
    );

    engine
        .structure()
        .read_file(
            &carrier,
            &ReadOptions::new().with_output(&out).with_overwrite(true),
        )
        .expect("read with overwrite");
    assert_eq!(std::fs::read(&out).expect("read back"), STRUCT_PAYLOAD);

    let restored = dir.join("restored.png");
    std::fs::write(&restored, b"stale").expect("seed restore target");

    let err = engine
        .structure()
        .restore_file(&carrier, &RestoreOptions::new().with_output(&restored))
        .expect_err("restore must refuse an existing destination");
    assert!(
        matches!(err, StrHideError::Rejection(_)),
        "expected Rejection, got {err:?}"
    );

    engine
        .structure()
        .restore_file(
            &carrier,
            &RestoreOptions::new()
                .with_output(&restored)
                .with_overwrite(true),
        )
        .expect("restore with overwrite");
    assert_eq!(
        std::fs::read(&restored).expect("read back"),
        PNG,
        "restored carrier must be bit-identical to the original"
    );
}

// ───────────────────────── GUI front-end smoke ─────────────────────────

/// The three things a GUI needs from the library without depending on `cli`:
/// progress events, a working cancel token, and an error it can render in its
/// own language.
#[test]
fn gui_front_end_smoke() {
    use std::sync::Mutex;

    use strhide::core::control::{CancelToken, Control, Event, Progress};
    use strhide::core::i18n::Lang;
    use strhide::errors::StrHideError;

    /// Collects events so the test can assert they were reported.
    #[derive(Default)]
    struct Recorder {
        events: Mutex<Vec<Event>>,
    }

    impl Progress for Recorder {
        fn report(&self, event: Event) {
            self.events.lock().unwrap().push(event);
        }
    }

    // 1. Progress: an embed reports at least one stage event.
    let recorder = Recorder::default();
    let control = Control::with_progress(&recorder);
    let options = EmbedOptions {
        control,
        ..Default::default()
    };
    let _ = StrHide::new()
        .stego()
        .embed(JPG, &Payload::bytes(CONTENT_PAYLOAD), &options)
        .expect("embed with progress");
    assert!(
        !recorder.events.lock().unwrap().is_empty(),
        "a GUI would show nothing if no stage event was reported"
    );

    // 2. Cancellation: a pre-cancelled token stops before any output.
    let token = CancelToken::new();
    token.cancel();
    let cancelled_options = EmbedOptions {
        control: Control::with_cancel(&token),
        ..Default::default()
    };
    let err = StrHide::new()
        .stego()
        .embed(JPG, &Payload::bytes(CONTENT_PAYLOAD), &cancelled_options)
        .expect_err("a cancelled embed must not succeed");
    assert!(
        matches!(err, StrHideError::Cancelled),
        "expected Cancelled, got {err:?}"
    );

    // 3. Localized error rendering, without the CLI's thread-local language.
    let zh = StrHideError::Password("wrong password".into())
        .detail_i18n()
        .render(Lang::Zh);
    assert!(
        zh.contains("密码"),
        "a Chinese UI must get a Chinese category label, got: {zh}"
    );
    assert!(zh.contains("wrong password"), "detail must survive: {zh}");

    let en = StrHideError::Password("wrong password".into())
        .detail_i18n()
        .render(Lang::En);
    assert!(en.contains("Password error"), "got: {en}");
}

#[test]
fn test_inspect_any_and_smart_extract_cross_domain() {
    let dir = scratch("inspect_any_smart_extract");
    let carrier = dir.join("carrier.png");
    std::fs::write(&carrier, PNG).expect("seed png");

    let engine = StrHide::new();

    // 1. Initial carrier: no hidden data
    let diag = engine
        .inspect_any(&carrier, &strhide::facade::DualOptions::default())
        .expect("inspect_any on clean carrier");
    assert!(!diag.structure.has_hidden_data);
    assert!(diag.content.is_none());

    // 2. Inject structural payload
    let source = PayloadSource::Text("structure secret");
    let write_opts = WriteOptions {
        output_path: None,
        ..Default::default()
    };
    engine
        .structure()
        .write_file(&carrier, source, &write_opts)
        .expect("structure write_file");

    // 3. inspect_any detects structure envelope
    let diag = engine
        .inspect_any(&carrier, &strhide::facade::DualOptions::default())
        .expect("inspect_any on stego carrier");
    assert!(diag.structure.has_hidden_data);

    // 4. smart_extract automatically picks structure domain and extracts payload
    let outcome = engine
        .smart_extract(&carrier, &strhide::facade::SmartExtractOptions::default())
        .expect("smart_extract");
    assert_eq!(outcome.source, strhide::facade::Domain::Structure);
    assert_eq!(outcome.payload.as_bytes(), b"structure secret");
    assert!(outcome.also_present.is_none());
}

#[test]
fn test_stego_file_symmetry_probe_inspect_verify() {
    let dir = scratch("stego_file_symmetry");
    let carrier = dir.join("carrier.jpg");
    std::fs::write(&carrier, JPG).expect("seed jpg");

    let engine = StrHide::new();
    let probe_opts = ProbeOptions::default();
    let cap = engine
        .stego()
        .probe_file(&carrier, &probe_opts)
        .expect("probe_file");
    assert!(cap.recommended_max_bytes > 0);

    let inspect_opts = strhide::stego::InspectOptions::default();
    let info = engine
        .stego()
        .inspect_file(&carrier, &inspect_opts)
        .expect("inspect_file");
    assert!(!info.has_hidden_data);

    let verify_opts = strhide::stego::VerifyOptions::default();
    let v_res = engine
        .stego()
        .verify_file(&carrier, &verify_opts)
        .expect("verify_file");
    assert!(v_res.levels[0].ok);
}

#[test]
fn test_progress_writer_and_cancellation() {
    use std::io::Write;
    use std::sync::Mutex;
    use strhide::core::control::{
        CancelToken, Control, Event, Progress, ProgressWriter, Stage, map_io_cancel,
    };
    use strhide::errors::StrHideError;

    struct TestProgress(Mutex<Vec<Event>>);
    impl Progress for TestProgress {
        fn report(&self, e: Event) {
            self.0.lock().unwrap().push(e);
        }
    }

    let progress = TestProgress(Mutex::new(Vec::new()));
    let cancel = CancelToken::new();
    let control = Control {
        progress: &progress,
        cancel: Some(&cancel),
    };

    let mut dest = Vec::new();
    let mut pw = ProgressWriter::new(&mut dest, control, Stage::Write, 100);

    // Cancel before write
    cancel.cancel();
    let err = pw.write(b"hello world").expect_err("should be cancelled");
    assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);

    let strhide_err = StrHideError::Io(err);
    let mapped = map_io_cancel(&control, strhide_err);
    assert!(matches!(mapped, StrHideError::Cancelled));
}

#[test]
#[cfg(feature = "analysis")]
fn facade_analysis_scan_bytes_and_file() {
    let engine = StrHide::new();
    let report = engine.analysis().scan_bytes(PNG, "memory.png");
    assert_eq!(report.carrier, "memory.png");
    assert_eq!(report.file_size, PNG.len() as u64);
    assert!(!report.verdict.is_empty());

    let dir = scratch("facade_analysis");
    let carrier_path = dir.join("carrier.png");
    std::fs::write(&carrier_path, PNG).expect("write carrier");

    let file_report = engine
        .analysis()
        .scan_file(&carrier_path)
        .expect("scan file");
    assert_eq!(file_report.file_size, PNG.len() as u64);
    assert_eq!(file_report.verdict, report.verdict);
}

#[test]
#[cfg(all(feature = "content-jpeg", feature = "structure-base"))]
fn facade_embed_stats_populated() {
    let engine = StrHide::new();
    let dir = scratch("facade_embed_stats");
    let carrier = dir.join("carrier.jpg");
    std::fs::write(&carrier, JPG).expect("write carrier");

    let options = EmbedOptions {
        password: Some("pw"),
        ..EmbedOptions::default()
    };
    let target = strhide::core::commit::FileTarget {
        output_path: None,
        backup: false,
        preserve_time: false,
        overwrite: true,
    };

    let res = engine
        .stego()
        .embed_file(
            &carrier,
            &Payload::bytes(CONTENT_PAYLOAD),
            &options,
            &target,
        )
        .expect("embed");

    let stats = res.stats.expect("embed stats must be populated");
    assert!(stats.modified_slots > 0, "must modify at least 1 slot");
    assert!(
        stats.total_candidate_slots > 0,
        "total candidate slots must be non-zero"
    );
    assert!(
        stats.modified_slots <= stats.total_candidate_slots,
        "modified slots cannot exceed candidate slots"
    );
}
