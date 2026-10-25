//! Local/large-corpus and external-tool tests for HEIF and HEVC carriers.
//!
//! All tests in this module require external tools (ffmpeg, python pylibheif)
//! or a local corpus (temp/testhevc) and are ignored by default.

pub mod heif_hidden_item {
    // Copyright (c) 2026 strhide developers
    // SPDX-License-Identifier: Apache-2.0

    use std::fs;
    use std::path::{Path, PathBuf};

    use strhide::engine::{
        PayloadSource, WriteOptions, inspect_carrier, read_carrier, remove_carrier, verify_carrier,
        write_carrier,
    };

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("strhide_test_heif_{name}_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn resolve_hevc_corpus() -> Option<PathBuf> {
        if let Ok(val) = std::env::var("STRHIDE_HEVC_CORPUS") {
            let p = PathBuf::from(val);
            if p.is_dir() {
                return Some(p);
            }
        }
        let p1 = Path::new("..").join("temp").join("testhevc");
        if p1.is_dir() {
            return Some(p1);
        }
        let p2 = Path::new("temp").join("testhevc");
        if p2.is_dir() {
            return Some(p2);
        }
        None
    }

    #[test]
    #[ignore = "requires local temp/testhevc corpus: run with cargo test --test test_heif_hidden_item -- --ignored"]
    pub fn local_heif_item_hidden_and_free_box_real_samples() {
        let test_dir = match resolve_hevc_corpus() {
            Some(d) => d,
            None => {
                eprintln!(
                    "[SKIP] HEVC test corpus not found (checked temp/testhevc and $STRHIDE_HEVC_CORPUS)"
                );
                return;
            }
        };

        let samples = [
            "test.heic",
            "test.heif",
            "test_nclx.heif",
            "IMG_0874.HEIC",
            "IMG_20261018_113710.HEIC",
        ];

        let scratch = scratch_dir("real_heic");
        let payload = b"Hidden HEIF payload for testing item_hidden & free_box";

        for sample_name in samples {
            let sample_path = test_dir.join(sample_name);
            if !sample_path.exists() {
                continue;
            }

            let orig_bytes = fs::read(&sample_path).unwrap();
            let orig_hash = {
                let h = strhide::crypto::compute_sha256(&orig_bytes);
                h.iter().map(|b| format!("{b:02x}")).collect::<String>()
            };

            // 1. Test strategy: item_hidden
            {
                let target_path = scratch.join(format!("hidden_{sample_name}"));
                fs::copy(&sample_path, &target_path).unwrap();

                let write_res = write_carrier(
                    &target_path,
                    PayloadSource::Bytes(payload),
                    &WriteOptions {
                        password: Some("heif-pass"),
                        strategy: "item_hidden",
                        ..Default::default()
                    },
                )
                .unwrap_or_else(|e| panic!("Failed to write item_hidden into {sample_name}: {e}"));

                assert_eq!(write_res.strategy, "item_hidden");

                // Verify structure
                let verify_res = verify_carrier(&target_path, None).expect("verify");
                assert!(
                    verify_res.level1_host.ok,
                    "Structure verify failed for {sample_name}: {}",
                    verify_res.level1_host.detail
                );

                // Inspect
                let insp = inspect_carrier(&target_path, None).expect("inspect");
                assert_eq!(insp.strategy.as_deref(), Some("item_hidden"));

                // Read
                let read_res = read_carrier(&target_path, None, Some("heif-pass")).expect("read");
                assert_eq!(read_res.data, payload);

                // Strip / remove and check 100% bit-exact restoration
                let remove_res = remove_carrier(&target_path, None, None, false).expect("remove");
                assert!(remove_res.verified_identical);

                let restored_bytes = fs::read(&target_path).unwrap();
                let restored_hash = {
                    let h = strhide::crypto::compute_sha256(&restored_bytes);
                    h.iter().map(|b| format!("{b:02x}")).collect::<String>()
                };
                assert_eq!(
                    restored_hash, orig_hash,
                    "Bit-exact restore failed for {sample_name} with item_hidden"
                );
            }

            // 2. Test strategy: free_box
            {
                let target_path = scratch.join(format!("free_{sample_name}"));
                fs::copy(&sample_path, &target_path).unwrap();

                let write_res = write_carrier(
                    &target_path,
                    PayloadSource::Bytes(payload),
                    &WriteOptions {
                        password: Some("heif-pass"),
                        strategy: "free_box",
                        ..Default::default()
                    },
                )
                .unwrap_or_else(|e| panic!("Failed to write free_box into {sample_name}: {e}"));

                assert_eq!(write_res.strategy, "free_box");

                let read_res = read_carrier(&target_path, None, Some("heif-pass")).expect("read");
                assert_eq!(read_res.data, payload);

                let remove_res = remove_carrier(&target_path, None, None, false).expect("remove");
                assert!(remove_res.verified_identical);

                let restored_bytes = fs::read(&target_path).unwrap();
                let restored_hash = {
                    let h = strhide::crypto::compute_sha256(&restored_bytes);
                    h.iter().map(|b| format!("{b:02x}")).collect::<String>()
                };
                assert_eq!(
                    restored_hash, orig_hash,
                    "Bit-exact restore failed for {sample_name} with free_box"
                );
            }

            // 3. Test strategy: auto (should automatically choose item_hidden for real HEIF with meta)
            {
                let target_path = scratch.join(format!("auto_{sample_name}"));
                fs::copy(&sample_path, &target_path).unwrap();

                let write_res = write_carrier(
                    &target_path,
                    PayloadSource::Bytes(payload),
                    &WriteOptions {
                        password: Some("heif-pass"),
                        strategy: "auto",
                        ..Default::default()
                    },
                )
                .unwrap_or_else(|e| panic!("Failed to write auto into {sample_name}: {e}"));

                assert_eq!(
                    write_res.strategy, "item_hidden",
                    "Auto strategy should choose item_hidden for {sample_name}"
                );

                let read_res = read_carrier(&target_path, None, Some("heif-pass")).expect("read");
                assert_eq!(read_res.data, payload);
            }
        }

        let _ = fs::remove_dir_all(&scratch);
    }
}

pub mod heif_bridge {
    use std::fs;
    use std::path::{Path, PathBuf};

    use strhide::errors::StrHideError;
    use strhide::params::Profile;
    use strhide::stego::heif::{
        embed_heif_bridge, extract_heif_bridge, probe_heif_bridge_capacity,
    };
    use strhide::stego::{StegoOptions, embed_carrier, extract_carrier, probe_carrier_capacity};

    fn resolve_hevc_corpus() -> Option<PathBuf> {
        if let Ok(val) = std::env::var("STRHIDE_HEVC_CORPUS") {
            let p = PathBuf::from(val);
            if p.is_dir() {
                return Some(p);
            }
        }
        let p1 = Path::new("..").join("temp").join("testhevc");
        if p1.is_dir() {
            return Some(p1);
        }
        let p2 = Path::new("temp").join("testhevc");
        if p2.is_dir() {
            return Some(p2);
        }
        None
    }

    fn find_python_command() -> Option<String> {
        if let Ok(p) = std::env::var("PYTHON") {
            return Some(p);
        }
        if cfg!(windows) && Path::new("C:\\Home\\Develop\\venv\\Scripts\\python.exe").exists() {
            return Some("C:\\Home\\Develop\\venv\\Scripts\\python.exe".into());
        }
        for candidate in &["python3", "python"] {
            if let Ok(out) = std::process::Command::new(candidate)
                .arg("--version")
                .output()
                && out.status.success()
            {
                return Some((*candidate).into());
            }
        }
        None
    }

    #[test]
    #[ignore = "requires local temp/testhevc corpus: run with cargo test --test test_heif_stego_bridge -- --ignored"]
    pub fn local_heif_jpeg_thumbnail_bridge_lifecycle() {
        let corpus = match resolve_hevc_corpus() {
            Some(d) => d,
            None => {
                eprintln!("[SKIP] HEVC corpus not found");
                return;
            }
        };
        let sample_path = corpus.join("IMG_20261018_113710.HEIC");
        if !sample_path.exists() {
            eprintln!("Sample {:?} does not exist, skipping test.", sample_path);
            return;
        }

        // The router prefers Scheme C (HEVC CABAC) and only falls back to the
        // bridge, so the bridge's own contract is exercised through its own
        // API. Router-level priority is pinned by
        // `local_heif_router_prefers_scheme_c` below.
        let profile = Profile::default();
        let orig_bytes = fs::read(sample_path).expect("read original HEIC");

        // 1. Probe capacity
        let options = StegoOptions::default();
        let cap = probe_heif_bridge_capacity(&orig_bytes, &options, &profile)
            .expect("probe bridge capacity");
        assert_eq!(cap.format, "HEIF (JPEG Thumbnail Bridge)");
        assert!(
            cap.available_slots > 500,
            "Should have sufficient slots for embedding"
        );
        assert!(cap.max_raw_payload_bytes > 32);

        // 2. Embed payload
        let payload = b"Hello from strhide content-domain bridge steganography in HEIC thumbnail!";
        let embed_opts = StegoOptions {
            password: Some("bridge_pass_2026".into()),
            ..Default::default()
        };

        let stego_bytes = embed_heif_bridge(&orig_bytes, payload, &embed_opts, &profile)
            .expect("embed carrier into HEIF thumbnail bridge");

        assert!(!stego_bytes.is_empty());
        // Primary content is preserved; file size should remain close to original (slight delta for JPEG Huffman re-encoding)
        let delta = (stego_bytes.len() as i64) - (orig_bytes.len() as i64);
        assert!(
            delta.abs() < 10000,
            "Length change should be modest, got {}",
            delta
        );

        // 3. Extract payload with matching password
        let extract_opts = StegoOptions {
            password: Some("bridge_pass_2026".into()),
            ..Default::default()
        };
        let extracted = extract_heif_bridge(&stego_bytes, &extract_opts, &profile)
            .expect("extract with correct password");
        assert_eq!(
            extracted, payload,
            "Extracted payload must match original 100%"
        );

        // 4. Extract with wrong password must fail cleanly as NoHiddenData
        let wrong_opts = StegoOptions {
            password: Some("wrong_password".into()),
            ..Default::default()
        };
        let wrong_res = extract_heif_bridge(&stego_bytes, &wrong_opts, &profile);
        assert!(
            matches!(wrong_res, Err(StrHideError::NoHiddenData(_))),
            "Wrong password must report NoHiddenData, got {:?}",
            wrong_res
        );

        // 5. Structure domain orthogonality: no suspicious UUID or trailing junk
        let mut cursor = std::io::Cursor::new(&stego_bytes);
        let warnings = strhide::adapters::isobmff::isobmff_suspicious_structures(&mut cursor);
        assert!(
            warnings.is_empty(),
            "Stego HEIF must have zero suspicious structural warnings, got: {:?}",
            warnings
        );
    }

    /// The router must write Scheme C (HEVC CABAC in place) and only fall back
    /// to the thumbnail bridge. The discriminator is an explicit Scheme C
    /// extraction: it never falls back, so it can only succeed when the payload
    /// really lives in the CABAC stream -- and the bridge must simultaneously
    /// report nothing, which proves the thumbnail was left alone.
    #[test]
    #[ignore = "requires local temp/testhevc corpus: run with cargo test --test test_heif_stego_bridge -- --ignored"]
    pub fn local_heif_router_prefers_scheme_c() {
        let corpus = match resolve_hevc_corpus() {
            Some(d) => d,
            None => {
                eprintln!("[SKIP] HEVC corpus not found");
                return;
            }
        };
        let sample_path = corpus.join("IMG_20261018_113710.HEIC");
        if !sample_path.exists() {
            eprintln!("Sample {:?} does not exist, skipping test.", sample_path);
            return;
        }
        let orig_bytes = fs::read(sample_path).expect("read original HEIC");
        let profile = Profile::default();
        let payload = b"router-prefers-scheme-c-2026";
        let opts = StegoOptions {
            password: Some("scheme_c_priority".into()),
            ..Default::default()
        };

        let cap = probe_carrier_capacity(&orig_bytes, &opts).expect("probe capacity");
        assert_eq!(
            cap.format, "HEIF/HEVC",
            "router must advertise the Scheme C carrier, not the bridge"
        );

        let stego = embed_carrier(&orig_bytes, payload, &opts).expect("embed");
        assert_eq!(
            stego.len(),
            orig_bytes.len(),
            "Scheme C rewrites CABAC bins in place; the file size must not move"
        );

        let explicit = StegoOptions {
            algorithm: Some("hevc".into()),
            ..opts.clone()
        };
        let cabac = extract_carrier(&stego, &explicit)
            .expect("explicit Scheme C extraction must find the payload");
        assert_eq!(cabac, payload);

        let bridge = extract_heif_bridge(&stego, &opts, &profile);
        assert!(
            matches!(bridge, Err(StrHideError::NoHiddenData(_))),
            "the thumbnail bridge must stay empty, got {bridge:?}"
        );

        let auto = extract_carrier(&stego, &opts).expect("default extraction agrees");
        assert_eq!(auto, payload);
    }

    #[test]
    #[ignore = "requires local temp/testhevc corpus: run with cargo test --test test_heif_stego_bridge -- --ignored"]
    pub fn local_heif_jpeg_thumbnail_bridge_multiple_samples() {
        let corpus = match resolve_hevc_corpus() {
            Some(d) => d,
            None => {
                eprintln!("[SKIP] HEVC corpus not found");
                return;
            }
        };

        let sample_names = &[
            "IMG_20261018_113710.HEIC",
            "IMG_20261018_113725.HEIC",
            "IMG_20261007_174602.HEIC",
            "IMG_20261016_115109.HEIC",
            "IMG_20260101_151231.HEIC",
        ];

        let mut tested_count = 0;

        for &name in sample_names {
            let sample_path = corpus.join(name);
            if !sample_path.exists() {
                continue;
            }

            let orig_bytes = fs::read(&sample_path).expect("read sample");
            let payload = format!("Batch test payload for {}", name).into_bytes();

            let embed_opts = StegoOptions {
                password: Some("batch_test_pass".into()),
                ..Default::default()
            };

            let stego_bytes = embed_carrier(&orig_bytes, &payload, &embed_opts)
                .unwrap_or_else(|e| panic!("Failed to embed in {}: {}", name, e));

            let extract_opts = StegoOptions {
                password: Some("batch_test_pass".into()),
                ..Default::default()
            };
            let extracted = extract_carrier(&stego_bytes, &extract_opts)
                .unwrap_or_else(|e| panic!("Failed to extract from {}: {}", name, e));

            assert_eq!(extracted, payload, "Payload mismatch for {}", name);
            tested_count += 1;
        }

        println!(
            "Successfully tested {} real camera HEIC samples",
            tested_count
        );
        assert!(
            tested_count >= 2,
            "Should test at least 2 real camera samples"
        );
    }

    #[test]
    #[ignore = "requires local temp/testhevc corpus and python pylibheif: run with cargo test --test test_heif_stego_bridge -- --ignored"]
    pub fn local_heif_bridge_bit_exact_primary_decode() {
        let corpus = match resolve_hevc_corpus() {
            Some(d) => d,
            None => {
                eprintln!("[SKIP] HEVC corpus not found");
                return;
            }
        };
        let sample_path = corpus.join("IMG_20261018_113710.HEIC");
        if !sample_path.exists() {
            return;
        }
        let orig_bytes = fs::read(&sample_path).expect("read original HEIC");

        let payload = b"Bit-exact visual fidelity test";
        let opts = StegoOptions {
            password: Some("fidelity_pw".into()),
            ..Default::default()
        };
        // Bridge API, not the router: the router prefers Scheme C, which by
        // design perturbs the primary image. "Primary stays bit-exact" is the
        // bridge's own guarantee and has to be tested where it is implemented.
        let stego_bytes =
            embed_heif_bridge(&orig_bytes, payload, &opts, &Profile::default()).expect("embed");

        let py_bin = match find_python_command() {
            Some(bin) => bin,
            None => {
                println!("[SKIP] Python not found; skipping pylibheif decode verification");
                return;
            }
        };

        let temp_dir =
            std::env::temp_dir().join(format!("strhide_heif_verify_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let orig_file = temp_dir.join("orig_verify.heic");
        let stego_file = temp_dir.join("stego_verify.heic");

        fs::write(&orig_file, &orig_bytes).expect("write orig");
        fs::write(&stego_file, &stego_bytes).expect("write stego");

        let orig_str = orig_file.to_string_lossy().replace('\\', "/");
        let stego_str = stego_file.to_string_lossy().replace('\\', "/");

        let py_cmd = format!(
            r#"
try:
    import pylibheif, numpy as np, sys
except ImportError:
    print("[SKIP] pylibheif or numpy not installed", file=sys.stderr)
    sys.exit(3)

def get_pixels(path):
    ctx = pylibheif.HeifContext()
    ctx.read_from_file(path)
    h = ctx.get_primary_image_handle()
    return h.decode_to_srgb()

try:
    orig = get_pixels("{orig_str}")
    stego = get_pixels("{stego_str}")
    diff = np.max(np.abs(orig.astype(np.int32) - stego.astype(np.int32)))
    if diff != 0:
        print(f"PIXEL MISMATCH: {{diff}}", file=sys.stderr)
        sys.exit(1)
    print("PIXELS BIT-EXACT")
except Exception as e:
    print(f"Python decode error: {{e}}", file=sys.stderr)
    sys.exit(2)
"#
        );

        let output = std::process::Command::new(&py_bin)
            .arg("-c")
            .arg(&py_cmd)
            .output();

        if let Ok(out) = output {
            if out.status.success() {
                println!("pylibheif verified primary image pixels bit-exact!");
            } else if out.status.code() == Some(3) {
                println!("pylibheif not installed in Python environment, skipping check");
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                panic!("pylibheif verification failed: {}", stderr);
            }
        } else {
            println!("Failed to spawn Python process; skipping pylibheif external check");
        }

        let _ = fs::remove_file(orig_file);
        let _ = fs::remove_file(stego_file);
        let _ = fs::remove_dir(temp_dir);
    }
}

pub mod hevc_stego {
    use std::fs;
    use std::path::Path;

    use rusty_h265::Decoder;
    use strhide::stego::hevc::heif_boxes::parse_heif_targets;
    use strhide::stego::hevc::{embed_hevc, extract_hevc, probe_hevc_capacity};

    /// Verify that an HEIC file can be decoded to a valid frame by rusty_h265.
    fn verify_frame_decodes(carrier_bytes: &[u8]) {
        let target = parse_heif_targets(carrier_bytes).expect("parse targets");
        let mut decoder = Decoder::new();
        for ps in &target.parameter_sets {
            let _ = decoder.push_nal(ps, None);
        }
        for span in &target.slice_spans {
            let _ = decoder.push_nal(&carrier_bytes[span.start..span.end()], None);
        }
        // A picture is only handed out once the decoder sees the *next* one
        // start, so a still image needs `flush` before `next_frame` yields.
        decoder.flush();
        let frame = decoder
            .next_frame()
            .expect("Failed to decode at least one full frame from carrier!");
        assert!(frame.width > 0 && frame.height > 0);
    }

    #[test]
    #[ignore = "requires local testhevc corpus"]
    pub fn local_hevc_corpus_real_photos_batch() {
        let corpus_files = [
            "../temp/testhevc/test.heic",
            "../temp/testhevc/IMG_5887.HEIC",
            "../temp/testhevc/IMG_1904.HEIC",
            "../temp/testhevc/IMG_0874.HEIC",
            "../temp/testhevc/IMG_2887.HEIC",
        ];

        let payload = b"StrHide HEVC Scheme C Certified Zero-Expansion In-Place Steganography";
        let password = "CorpusBatchTestPassword#2026";

        for path in corpus_files {
            if !Path::new(path).exists() {
                println!("Skipping missing: {}", path);
                continue;
            }
            let orig = fs::read(path).expect("read");
            let orig_len = orig.len();
            let cap = probe_hevc_capacity(&orig, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
                .expect("probe capacity");
            println!(
                "File: {}, size = {} bytes, capacity = {} bytes",
                path, orig_len, cap
            );

            if cap < payload.len() {
                println!(
                    "  Carrier capacity {} < payload {}, skipping embed",
                    cap,
                    payload.len()
                );
                continue;
            }

            let stego = embed_hevc(
                &orig,
                payload,
                Some(password),
                None,
                &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                strhide::stego::Freshness::Random,
            )
            .expect("embed");
            assert_eq!(stego.len(), orig_len, "Length must be bit-exact identical!");

            let extracted = extract_hevc(
                &stego,
                Some(password),
                None,
                &strhide::stego::format::DEFAULT_HEVC_FORMAT,
            )
            .expect("extract");
            assert_eq!(extracted, payload);

            verify_frame_decodes(&stego);
            println!("  100% roundtrip & frame decode OK for {}", path);
        }
    }

    #[test]
    #[ignore = "requires local testhevc corpus"]
    pub fn local_hevc_img_1842_payload_32k() {
        let path = "../temp/testhevc/IMG_1842.HEIC";
        let payload_path = "../temp/testpayload/payload-32k.bin";
        if !Path::new(path).exists() || !Path::new(payload_path).exists() {
            return;
        }
        let orig = fs::read(path).expect("read");
        let payload = fs::read(payload_path).expect("read payload");
        let password = "StrHide-Matrix-Benchmark-Password#2026";

        let stego = embed_hevc(
            &orig,
            &payload,
            Some(password),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
            strhide::stego::Freshness::Random,
        )
        .expect("embed 32k into IMG_1842");
        assert_eq!(stego.len(), orig.len(), "Carrier len must be bit-exact!");

        let extracted = extract_hevc(
            &stego,
            Some(password),
            None,
            &strhide::stego::format::DEFAULT_HEVC_FORMAT,
        )
        .expect("extract 32k from IMG_1842");
        assert_eq!(extracted, payload, "Payload must match bit-for-bit!");

        verify_frame_decodes(&stego);
        println!("IMG_1842 with 32KB payload PASSED 100%!");
    }
}

pub mod hevc_external {
    // Copyright (c) 2026 strhide developers
    // SPDX-License-Identifier: Apache-2.0

    //! Independent validation of the HEVC Scheme C output with a *real* decoder.
    //!
    //! The in-tree `h265::Decoder` is also the recorder that produced the operation
    //! journal the embedder replays, so the two can only ever prove that they agree
    //! with each other. If the recorder misreads a syntax element, embedding and
    //! extraction would still round-trip perfectly while the file is undecodable by
    //! an actual player. This test uses `ffmpeg` as the outside oracle: it must
    //! decode the stego carrier without a single error, its PSNR against the cover
    //! must stay high, and — most importantly — both files must decode to the
    //! **same geometry** with only a sparse set of visibly changed samples.
    //!
    //! ```text
    //! cargo test --release --test test_hevc_external -- --ignored --nocapture
    //! ```

    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use strhide::stego::hevc::{embed_hevc, probe_hevc_capacity};

    const PASSWORD: &str = "ExternalValidationPassword#2026";

    /// Minimum accepted PSNR (dB) between cover and stego frames. Flipping a
    /// sparse set of transform-coefficient signs costs a fraction of a dB at
    /// these rates; anything below this means the bitstream changed far more
    /// than intended.
    const MIN_PSNR_DB: f64 = 30.0;

    /// A sample deviation of this many levels or more counts as "visibly
    /// changed". Below it the difference is at most a rounding-level wobble.
    const LARGE_DELTA: u8 = 16;

    /// Upper bound on the fraction of samples that may deviate by more than
    /// [`LARGE_DELTA`].
    ///
    /// Measured on the local corpus at ~12% of capacity the observed values are
    /// 1.2% .. 4.4%; the limit is set at 12% so the test catches a genuinely
    /// damaged bitstream (where the deviation is not sparse at all) without
    /// flaking on content that is simply busy.
    const MAX_LARGE_FRACTION: f64 = 0.12;

    /// Absolute ceiling on the single worst sample deviation.
    ///
    /// 255 is the maximum possible value for an 8-bit sample, so this only
    /// rejects a completely corrupted reconstruction. Measured maxima on the
    /// local corpus are 51 .. 110.
    const MAX_ABS_SAMPLE_DELTA: u8 = 200;

    /// PSNR floor for the deterministic 50%-capacity case.
    ///
    /// Measured after the magnitude-aware cost model (2026-10-25): 36.47 ..
    /// 38.51 dB across two carriers and three seeds, up from 26.03 .. 31.75 dB
    /// with the frequency-only model.
    const DET_MIN_PSNR_DB: f64 = 34.0;

    /// Single-sample ceiling for the deterministic 50%-capacity case.
    ///
    /// The cost model prices one flip at ≤ 32 levels; the measured maxima are
    /// 24 .. 31, and the extra headroom covers two flips landing in one
    /// transform block.
    const DET_MAX_ABS_SAMPLE_DELTA: u8 = 48;

    /// Fraction of samples allowed to move by more than [`LARGE_DELTA`] in the
    /// deterministic case. Measured 0.0003 .. 0.0027 (was 0.028 .. 0.099 with
    /// the frequency-only model).
    const DET_MAX_LARGE_FRACTION: f64 = 0.01;

    fn ffmpeg_available() -> bool {
        Command::new("ffmpeg")
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn corpus_dir() -> Option<PathBuf> {
        let dir = std::env::var("STRHIDE_HEVC_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("../temp/testhevc"));
        dir.is_dir().then_some(dir)
    }

    /// Decode both files with ffmpeg and return `(average PSNR, decoder complaints)`.
    fn decode_and_compare(
        reference: &Path,
        candidate: &Path,
    ) -> Result<(f64, Vec<String>), String> {
        let out = Command::new("ffmpeg")
            .args(["-hide_banner", "-nostdin", "-i"])
            .arg(reference)
            .args(["-i"])
            .arg(candidate)
            .args(["-lavfi", "[0:v][1:v]psnr", "-f", "null", "-"])
            .output()
            .map_err(|e| format!("cannot run ffmpeg: {e}"))?;

        let log = String::from_utf8_lossy(&out.stderr).to_string();
        let noise: Vec<String> = log
            .lines()
            .filter(|line| {
                let lower = line.to_ascii_lowercase();
                // ffmpeg reports stream/decoder trouble on stderr; a clean decode
                // leaves only the PSNR summary and container chatter.
                [
                    "error", "invalid", "corrupt", "missing", "truncat", "failed",
                ]
                .iter()
                .any(|needle| lower.contains(needle))
                    && !lower.contains("psnr")
            })
            .map(str::to_string)
            .collect();

        let psnr = log
            .lines()
            .filter_map(|line| line.split("average:").nth(1))
            .filter_map(|tail| tail.split_whitespace().next())
            .filter_map(|value| value.parse::<f64>().ok())
            .next_back()
            .ok_or_else(|| format!("ffmpeg produced no PSNR summary:\n{log}"))?;

        Ok((psnr, noise))
    }

    /// Decode a file to raw YUV420p and return the raw plane bytes.
    ///
    /// Comparing the *decoded pixels* (not just a PSNR summary) is a much
    /// stronger statement than a single aggregate number: it proves that both
    /// files decode to the same geometry — same frame count, same dimensions —
    /// and that the per-sample deviation stays inside a tight bound. A PSNR
    /// average can hide a handful of catastrophically wrong pixels.
    fn decode_raw_yuv(path: &Path) -> Result<Vec<u8>, String> {
        let out = Command::new("ffmpeg")
            .args(["-hide_banner", "-nostdin", "-loglevel", "error", "-i"])
            .arg(path)
            .args(["-f", "rawvideo", "-pix_fmt", "yuv420p", "-"])
            .output()
            .map_err(|e| format!("cannot run ffmpeg: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "ffmpeg failed to decode {}: {}",
                path.display(),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(out.stdout)
    }

    /// Result of a pixel-level comparison between cover and stego frames.
    struct PixelDiff {
        max_abs_diff: u8,
        large_fraction: f64,
        psnr: f64,
    }

    fn compare_pixels(cover: &[u8], stego: &[u8]) -> Result<PixelDiff, String> {
        if cover.len() != stego.len() {
            return Err(format!(
                "decoded size mismatch: cover {} bytes, stego {} bytes \
             (different frame count or dimensions)",
                cover.len(),
                stego.len()
            ));
        }
        if cover.is_empty() {
            return Err("decoded no samples at all".to_string());
        }
        let mut max_abs_diff = 0u8;
        let mut large = 0usize;
        let mut sse = 0u64;
        for (a, b) in cover.iter().zip(stego.iter()) {
            let d = a.abs_diff(*b);
            sse += (d as u64) * (d as u64);
            if d > max_abs_diff {
                max_abs_diff = d;
            }
            if d > LARGE_DELTA {
                large += 1;
            }
        }
        let mse = sse as f64 / cover.len() as f64;
        let psnr = if mse == 0.0 {
            f64::INFINITY
        } else {
            10.0 * (255.0 * 255.0 / mse).log10()
        };
        Ok(PixelDiff {
            max_abs_diff,
            large_fraction: large as f64 / cover.len() as f64,
            psnr,
        })
    }

    /// Deterministic high-payload regression for the magnitude-aware cost model.
    ///
    /// Sign flips are priced by the decoded coefficient magnitude now, so a
    /// 50%-of-capacity payload must stay inside a tight per-sample bound instead
    /// of riding on `x_c + y_c` alone. Before the model (2026-10-25) the same
    /// inputs produced max|d| 98..173 and whole-frame PSNR 26..32 dB.
    ///
    /// `Freshness::Seeded` keeps this reproducible; a random nonce turned the
    /// bound into a coin flip.
    #[test]
    #[ignore = "requires ffmpeg on PATH and the local testhevc corpus"]
    pub fn local_hevc_deterministic_high_payload_max_delta_bound() {
        if !ffmpeg_available() {
            eprintln!("[SKIP] ffmpeg not found on PATH");
            return;
        }
        let Some(dir) = corpus_dir() else {
            eprintln!("[SKIP] testhevc corpus not found");
            return;
        };

        for name in ["IMG_0874.HEIC", "IMG_1904.HEIC"] {
            let cover_path = dir.join(name);
            if !cover_path.exists() {
                continue;
            }
            let cover = fs::read(&cover_path).expect("read cover");
            let capacity =
                probe_hevc_capacity(&cover, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
                    .expect("probe capacity");

            // Half the advertised capacity pushes the trellis well past the
            // cheapest slots, which is exactly where a magnitude-blind cost
            // model starts flipping large coefficients.
            let payload_len = (capacity / 2).clamp(1024, 64 * 1024);
            let payload: Vec<u8> = (0..payload_len).map(|i| (i * 131 % 251) as u8).collect();

            for seed_byte in [1u8, 7u8, 42u8] {
                let stego = embed_hevc(
                    &cover,
                    &payload,
                    Some(PASSWORD),
                    None,
                    &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                    strhide::stego::Freshness::Seeded([seed_byte; 32]),
                )
                .unwrap_or_else(|e| panic!("{name} (seed {seed_byte}): embed failed: {e}"));

                let stego_path = std::env::temp_dir().join(format!(
                    "strhide-hevc-det-{seed_byte}-{}-{name}.heic",
                    std::process::id()
                ));
                fs::write(&stego_path, &stego).expect("write stego carrier");

                let cover_raw =
                    decode_raw_yuv(&cover_path).unwrap_or_else(|e| panic!("{name}: {e}"));
                let stego_raw =
                    decode_raw_yuv(&stego_path).unwrap_or_else(|e| panic!("{name}: {e}"));
                let diff = compare_pixels(&cover_raw, &stego_raw)
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                let _ = fs::remove_file(&stego_path);

                println!(
                    "[DET seed={seed_byte}] {name}: payload={payload_len}/{capacity} B, \
                 PSNR={:.2} dB, max|d|={}, large_frac={:.4}",
                    diff.psnr, diff.max_abs_diff, diff.large_fraction
                );

                assert!(
                    diff.psnr >= DET_MIN_PSNR_DB,
                    "{name} (seed {seed_byte}): PSNR {:.2} dB is below the {DET_MIN_PSNR_DB:.0} dB floor",
                    diff.psnr
                );
                assert!(
                    diff.max_abs_diff <= DET_MAX_ABS_SAMPLE_DELTA,
                    "{name} (seed {seed_byte}): a sample moved by {} (limit {DET_MAX_ABS_SAMPLE_DELTA})",
                    diff.max_abs_diff
                );
                assert!(
                    diff.large_fraction <= DET_MAX_LARGE_FRACTION,
                    "{name} (seed {seed_byte}): {:.4} of samples moved by more than {LARGE_DELTA} \
                 (limit {DET_MAX_LARGE_FRACTION})",
                    diff.large_fraction
                );
            }
        }
    }

    #[test]
    #[ignore = "requires ffmpeg on PATH and the local testhevc corpus"]
    pub fn local_hevc_stego_carriers_decode_in_ffmpeg_with_high_psnr() {
        if !ffmpeg_available() {
            eprintln!("[SKIP] ffmpeg not found on PATH");
            return;
        }
        let Some(dir) = corpus_dir() else {
            eprintln!("[SKIP] testhevc corpus not found");
            return;
        };

        let mut checked = 0usize;
        let mut skipped = 0usize;

        for name in [
            "test.heic",
            "IMG_5887.HEIC",
            "IMG_1904.HEIC",
            "IMG_0874.HEIC",
            "IMG_1842.HEIC",
        ] {
            let cover_path = dir.join(name);
            if !cover_path.exists() {
                continue;
            }
            let cover = fs::read(&cover_path).expect("read cover");
            let capacity =
                match probe_hevc_capacity(&cover, &strhide::stego::format::DEFAULT_HEVC_FORMAT) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("[SKIP] {name}: not a Scheme C carrier ({e})");
                        skipped += 1;
                        continue;
                    }
                };
            // ~12% of capacity: a representative "real" payload rather than a
            // capacity stress. The PSNR floor below is what separates a genuine
            // sign-flip embedding from a mangled bitstream.
            let payload_len = (capacity / 8).clamp(512, 64 * 1024);
            let payload = vec![0xA5u8; payload_len];

            let stego = embed_hevc(
                &cover,
                &payload,
                Some(PASSWORD),
                None,
                &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                strhide::stego::Freshness::Random,
            )
            .expect("embed");

            let stego_path = std::env::temp_dir().join(format!(
                "strhide-hevc-ext-{}-{name}.heic",
                std::process::id()
            ));
            fs::write(&stego_path, &stego).expect("write stego carrier");

            let result = decode_and_compare(&cover_path, &stego_path);
            let (psnr, complaints) = result.unwrap_or_else(|e| panic!("{name}: {e}"));

            // Pixel-level equivalence: the two files must decode to the very same
            // geometry, and the deviation must stay small in absolute terms.
            let cover_raw = decode_raw_yuv(&cover_path).unwrap_or_else(|e| panic!("{name}: {e}"));
            let stego_raw = decode_raw_yuv(&stego_path).unwrap_or_else(|e| panic!("{name}: {e}"));
            let diff =
                compare_pixels(&cover_raw, &stego_raw).unwrap_or_else(|e| panic!("{name}: {e}"));

            let _ = fs::remove_file(&stego_path);

            assert!(
                complaints.is_empty(),
                "{name}: ffmpeg complained while decoding the stego carrier:\n{}",
                complaints.join("\n")
            );
            assert!(
                psnr >= MIN_PSNR_DB || diff.psnr >= MIN_PSNR_DB,
                "{name}: cover/stego PSNR ({psnr:.2} dB, whole-frame {:.2} dB) is below the {MIN_PSNR_DB:.0} dB floor",
                diff.psnr
            );
            assert!(
                diff.max_abs_diff <= MAX_ABS_SAMPLE_DELTA,
                "{name}: a decoded sample moved by {} (limit {}), which is more than a \
             coefficient-sign flip should ever cause",
                diff.max_abs_diff,
                MAX_ABS_SAMPLE_DELTA
            );
            assert!(
                diff.large_fraction <= MAX_LARGE_FRACTION,
                "{name}: {:.4} of all decoded samples moved by more than {LARGE_DELTA} \
             (limit {:.4}) — the change is not sparse enough to be a sign flip",
                diff.large_fraction,
                MAX_LARGE_FRACTION
            );
            println!(
                "[OK] {name}: payload {payload_len} B of {capacity} B, ffmpeg clean, \
             PSNR {psnr:.2} dB, {:.4} samples moved > {LARGE_DELTA} (max |d| = {})",
                diff.large_fraction, diff.max_abs_diff
            );
            checked += 1;
        }

        assert!(
            checked > 0,
            "no carrier was validated ({skipped} skipped) — the corpus or ffmpeg is missing"
        );
    }
}

/// Real Annex-B streams: sniff coverage and an end-to-end round-trip.
///
/// The corpus is built by `scripts/fetch_hevc_samples.py` (gitignored under
/// `temp/testhevc/annexb`) from the PhotoPrism HEVC sample set plus ffmpeg
/// derivations. Its point is variety the unit tests cannot invent: VPS-first,
/// IDR-first, bare `TRAIL_R` frames, open-GOP `RASL` frames, 10-bit, HDR10 and
/// 4:4:4 encodes. `is_hevc_annexb` used to accept only ten NAL types, so any
/// file whose first NAL was a TSA/STSA/RADL/RASL/BLA was reported as "not
/// HEVC" -- a real risk for cut segments and frame extractors.
pub mod annexb_sniff {
    // Copyright (c) 2026 strhide developers
    // SPDX-License-Identifier: Apache-2.0

    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    use strhide::stego::hevc::sniff::is_hevc_annexb;
    use strhide::stego::{StegoOptions, embed_carrier, extract_carrier, probe_carrier_capacity};

    fn corpus_dir() -> Option<PathBuf> {
        if let Ok(val) = std::env::var("STRHIDE_HEVC_ANNEXB_DIR") {
            let p = PathBuf::from(val);
            if p.is_dir() {
                return Some(p);
            }
        }
        [
            Path::new("..").join("temp").join("testhevc").join("annexb"),
            Path::new("temp").join("testhevc").join("annexb"),
        ]
        .into_iter()
        .find(|candidate| candidate.is_dir())
    }

    /// `(start-code offset, NAL header offset)` for every Annex-B NAL.
    fn nal_units(data: &[u8]) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        while i + 3 < data.len() {
            if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
                out.push((i, i + 3));
                i += 3;
            } else if i + 4 < data.len() && data[i..i + 4] == [0, 0, 0, 1] {
                out.push((i, i + 4));
                i += 4;
            } else {
                i += 1;
            }
        }
        out
    }

    fn first_nal_type(data: &[u8]) -> Option<u8> {
        let units = nal_units(data);
        let (_, header) = *units.first()?;
        data.get(header).map(|b| (b >> 1) & 0x3F)
    }

    /// H.265 Table 7-1 defines every value outside the reserved ranges.
    fn is_defined_nal_type(t: u8) -> bool {
        matches!(t, 0..=9 | 16..=21 | 32..=40)
    }

    #[test]
    #[ignore = "requires the local temp/testhevc/annexb corpus: run with cargo test local_hevc_annexb_sniff -- --ignored"]
    fn local_hevc_annexb_sniff_accepts_every_real_stream() {
        let dir = match corpus_dir() {
            Some(d) => d,
            None => {
                eprintln!(
                    "[SKIP] Annex-B corpus not found (temp/testhevc/annexb); run scripts/fetch_hevc_samples.py"
                );
                return;
            }
        };

        let mut checked = 0usize;
        let mut first_types = BTreeSet::new();
        for entry in fs::read_dir(&dir).expect("read corpus dir") {
            let path = entry.expect("dir entry").path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !(name.ends_with(".hevc") || name.ends_with(".hevc10")) {
                continue;
            }
            let bytes = fs::read(&path).unwrap_or_else(|e| panic!("{name}: read failed: {e}"));
            assert!(
                is_hevc_annexb(&bytes),
                "{name}: a real Annex-B stream must sniff as HEVC"
            );
            let nal_type = first_nal_type(&bytes)
                .unwrap_or_else(|| panic!("{name}: no Annex-B start code found"));
            assert!(
                is_defined_nal_type(nal_type),
                "{name}: first NAL type {nal_type} is reserved/unspecified"
            );
            first_types.insert(nal_type);
            checked += 1;
        }

        assert!(
            checked >= 8,
            "only {checked} Annex-B streams found; the corpus looks incomplete"
        );
        // The whole reason the accepted set was widened: real files can open on
        // a plain VCL NAL (frame extractors, cut segments), not just on VPS/SPS.
        assert!(
            first_types.iter().any(|t| *t <= 9),
            "corpus must cover a non-parameter-set VCL start, got {first_types:?}"
        );
        println!("sniffed {checked} real streams, first NAL types {first_types:?}");
    }

    #[test]
    #[ignore = "requires the local temp/testhevc/annexb corpus: run with cargo test local_hevc_annexb_roundtrip -- --ignored"]
    fn local_hevc_annexb_roundtrip_on_a_real_stream() {
        let dir = match corpus_dir() {
            Some(d) => d,
            None => {
                eprintln!("[SKIP] Annex-B corpus not found (temp/testhevc/annexb)");
                return;
            }
        };

        let payload = b"annexb-real-stream-roundtrip-2026";
        let options = StegoOptions {
            password: Some("annexb#corpus".into()),
            ..StegoOptions::default()
        };

        // The frame-type gate (non-reference pictures only) leaves a short
        // clip such as `bear.hevc` (320x180, 15 non-reference frames, 368
        // slots) below the 40-byte header, so pick the first stream in the
        // corpus that can actually carry the payload instead of pinning one
        // file name. `test-25fps.hevc` advertises ~2.3 KiB.
        let mut chosen = None;
        for name in ["test-25fps.hevc", "bbb.hevc", "bear.hevc"] {
            let candidate = dir.join(name);
            if !candidate.is_file() {
                continue;
            }
            let bytes = fs::read(&candidate).expect("read carrier");
            match probe_carrier_capacity(&bytes, &options) {
                Ok(info) if info.max_raw_payload_bytes >= payload.len() => {
                    chosen = Some((name, bytes, info));
                    break;
                }
                Ok(info) => eprintln!(
                    "[SKIP] {name}: gated capacity {} B cannot carry {} B",
                    info.max_raw_payload_bytes,
                    payload.len()
                ),
                Err(e) => eprintln!("[SKIP] {name}: {e}"),
            }
        }
        let Some((name, bytes, info)) = chosen else {
            eprintln!("[SKIP] no corpus stream with enough capacity for {payload:?}");
            return;
        };
        println!(
            "[ANNEXB] {name}: slots={}, capacity={} B",
            info.available_slots, info.max_raw_payload_bytes
        );

        let stego = embed_carrier(&bytes, payload, &options).expect("embed into a real stream");
        assert_eq!(
            stego.len(),
            bytes.len(),
            "Annex-B embed must not resize the stream"
        );
        assert!(
            is_hevc_annexb(&stego),
            "the stego stream must still sniff as HEVC"
        );
        let recovered = extract_carrier(&stego, &options).expect("extract");
        assert_eq!(recovered, payload, "round-trip must be byte-exact");
    }
}

/// MP4/MOV container carriers (Scheme C over the ISO-BMFF sample table).
///
/// The engine core is container-agnostic; what these tests pin down is the
/// container layer: sample-table arithmetic (stsz/stco/co64/stsc), the
/// `hvcC` parameter sets, the frame-type gate and the guarantee that an
/// embedding never touches `moov`.
pub mod mp4_container {
    // Copyright (c) 2026 strhide developers
    // SPDX-License-Identifier: Apache-2.0

    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use strhide::stego::Freshness;
    use strhide::stego::hevc::mp4_boxes::parse_mp4_targets;
    use strhide::stego::hevc::{embed_hevc, extract_hevc, probe_hevc_capacity};

    const PASSWORD: &str = "Mp4CorpusValidation#2026";

    /// Floor for the whole-file PSNR against the cover.
    ///
    /// These carriers are gated to non-reference pictures (or, for the
    /// all-`TRAIL_R` stream, priced by the magnitude-aware model), and a
    /// 2 KiB payload touches a tiny fraction of the sign bits: measured PSNR
    /// is 53..60 dB. 30 dB is the "the bitstream was not damaged" floor, not
    /// the expected value.
    const MIN_PSNR_DB: f64 = 30.0;

    /// Real-world corpus: iPhone 4K (`hev1`, `stco`), iPhone MOV (`qt` brand,
    /// open GOP), Android 1080p60 (`hvc1`, `co64`, every picture a reference
    /// picture) and two encoder samples (extra `hvcC` arrays).
    const CORPUS: [&str; 6] = [
        "VID_20250228_120825_C.mp4",
        "IMG_0033.MOV",
        "IMG_0892.MOV",
        "VID_20261002_154545.mp4",
        "SDRSample.mp4",
        "HDRSample.mp4",
    ];

    fn corpus_dir() -> Option<PathBuf> {
        if let Ok(val) = std::env::var("STRHIDE_HEVC_DIR") {
            let p = PathBuf::from(val);
            if p.is_dir() {
                return Some(p);
            }
        }
        let dir = PathBuf::from("../temp/testhevc");
        dir.is_dir().then_some(dir)
    }

    fn ffmpeg_available() -> bool {
        Command::new("ffmpeg")
            .arg("-version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Average PSNR between two files and every decoder complaint ffmpeg made.
    fn psnr_and_complaints(cover: &Path, stego: &Path) -> Result<(f64, Vec<String>), String> {
        let out = Command::new("ffmpeg")
            .args(["-hide_banner", "-nostdin", "-i"])
            .arg(cover)
            .args(["-i"])
            .arg(stego)
            .args(["-lavfi", "[0:v][1:v]psnr", "-f", "null", "-"])
            .output()
            .map_err(|e| format!("cannot run ffmpeg: {e}"))?;
        let log = String::from_utf8_lossy(&out.stderr).to_string();
        let noise: Vec<String> = log
            .lines()
            .filter(|line| {
                // Indented lines are the container's metadata dump: these
                // carriers carry the encoder command line in their `comment`
                // tag, which contains "-v error" and would otherwise read as a
                // decoder complaint. Real diagnostics are never indented.
                if line.starts_with(' ') || line.starts_with('\t') {
                    return false;
                }
                let lower = line.to_ascii_lowercase();
                [
                    "error", "invalid", "corrupt", "missing", "truncat", "failed",
                ]
                .iter()
                .any(|needle| lower.contains(needle))
                    && !lower.contains("psnr")
            })
            .map(str::to_string)
            .collect();
        let psnr = log
            .lines()
            .filter_map(|line| line.split("average:").nth(1))
            .filter_map(|tail| tail.split_whitespace().next())
            .filter_map(|value| value.parse::<f64>().ok())
            .next_back()
            .ok_or_else(|| format!("ffmpeg produced no PSNR summary:\n{log}"))?;
        Ok((psnr, noise))
    }

    /// `(tag, box_start, payload_start, box_end)` for the direct children of
    /// `[start, end)`. Independent of the parser under test: the point of the
    /// check below is that `moov` is byte-identical, so it must be located
    /// without reusing that parser's box walk.
    fn top_level_boxes(data: &[u8]) -> Vec<(String, usize, usize, usize)> {
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos + 8 <= data.len() {
            let size32 =
                u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let tag = String::from_utf8_lossy(&data[pos + 4..pos + 8]).to_string();
            let (hdr, size) = if size32 == 1 {
                let mut b = [0u8; 8];
                b.copy_from_slice(data.get(pos + 8..pos + 16).unwrap_or(&[0u8; 8]));
                (16usize, u64::from_be_bytes(b) as usize)
            } else if size32 == 0 {
                (8usize, data.len() - pos)
            } else {
                (8usize, size32 as usize)
            };
            if size < hdr || pos + size > data.len() {
                break;
            }
            out.push((tag, pos, pos + hdr, pos + size));
            pos += size;
        }
        out
    }

    fn payload_offset(data: &[u8], tag: &[u8; 4]) -> Option<usize> {
        data.windows(4).position(|w| w == tag).map(|i| i + 4)
    }

    /// Probe -> embed -> extract over the real corpus.
    ///
    /// Asserts what the container layer promises: byte-exact round-trip, an
    /// unchanged file length (Δ = 0) and a bitstream ffmpeg still decodes
    /// without complaint.
    #[test]
    #[ignore = "requires ffmpeg on PATH and the local temp/testhevc corpus"]
    pub fn local_hevc_mp4_corpus_roundtrip() {
        if !ffmpeg_available() {
            eprintln!("[SKIP] ffmpeg not found on PATH");
            return;
        }
        let Some(dir) = corpus_dir() else {
            eprintln!("[SKIP] testhevc corpus not found");
            return;
        };

        let payload: Vec<u8> = (0..2048u32).map(|i| ((i * 37 + 11) % 256) as u8).collect();
        for name in CORPUS {
            let cover_path = dir.join(name);
            if !cover_path.is_file() {
                continue;
            }
            let cover = fs::read(&cover_path).unwrap_or_else(|e| panic!("{name}: {e}"));
            let capacity =
                probe_hevc_capacity(&cover, &strhide::stego::format::DEFAULT_HEVC_FORMAT)
                    .unwrap_or_else(|e| panic!("{name}: capacity probe failed: {e}"));
            assert!(
                capacity >= payload.len(),
                "{name}: capacity {capacity} B cannot hold {} B",
                payload.len()
            );

            let stego = embed_hevc(
                &cover,
                &payload,
                Some(PASSWORD),
                None,
                &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                Freshness::Random,
            )
            .unwrap_or_else(|e| panic!("{name}: embed failed: {e}"));
            assert_eq!(
                stego.len(),
                cover.len(),
                "{name}: an MP4 embed must not resize the container (Delta = 0)"
            );

            let recovered = extract_hevc(
                &stego,
                Some(PASSWORD),
                None,
                &strhide::stego::format::DEFAULT_HEVC_FORMAT,
            )
            .unwrap_or_else(|e| panic!("{name}: extract failed: {e}"));
            assert_eq!(recovered, payload, "{name}: round-trip must be byte-exact");

            let stego_path = std::env::temp_dir()
                .join(format!("strhide-hevc-mp4-{}-{name}", std::process::id()));
            fs::write(&stego_path, &stego).expect("write stego carrier");
            let (psnr, noise) = psnr_and_complaints(&cover_path, &stego_path)
                .unwrap_or_else(|e| panic!("{name}: ffmpeg: {e}"));
            let _ = fs::remove_file(&stego_path);

            println!("[MP4] {name}: capacity={capacity} B, PSNR={psnr:.2} dB");
            assert!(
                noise.is_empty(),
                "{name}: ffmpeg reported trouble decoding the stego carrier: {noise:?}"
            );
            assert!(
                psnr >= MIN_PSNR_DB,
                "{name}: PSNR {psnr:.2} dB is below the {MIN_PSNR_DB:.0} dB floor"
            );
        }
    }

    /// The whole point of Δ = 0 in a container: `moov` (sample sizes, chunk
    /// offsets, `hvcC`) is byte-identical, only `mdat` moved.
    #[test]
    #[ignore = "requires the local temp/testhevc corpus"]
    pub fn local_hevc_mp4_container_tables_untouched() {
        let Some(dir) = corpus_dir() else {
            eprintln!("[SKIP] testhevc corpus not found");
            return;
        };

        for name in CORPUS {
            let cover_path = dir.join(name);
            if !cover_path.is_file() {
                continue;
            }
            let cover = fs::read(&cover_path).unwrap_or_else(|e| panic!("{name}: {e}"));
            let payload = b"strhide mp4 container tables must not move".repeat(32);

            let stego = embed_hevc(
                &cover,
                &payload,
                Some(PASSWORD),
                None,
                &strhide::stego::format::DEFAULT_HEVC_FORMAT,
                Freshness::Seeded([7u8; 32]),
            )
            .unwrap_or_else(|e| panic!("{name}: embed failed: {e}"));
            assert_eq!(stego.len(), cover.len(), "{name}: file length changed");

            let cover_boxes = top_level_boxes(&cover);
            let stego_boxes = top_level_boxes(&stego);
            assert_eq!(
                cover_boxes.len(),
                stego_boxes.len(),
                "{name}: the top-level box layout changed"
            );
            for ((tag, _, cp, ce), (_, _, sp, se)) in cover_boxes.iter().zip(stego_boxes.iter()) {
                let identical = cover[*cp..*ce] == stego[*sp..*se];
                if tag == "mdat" {
                    assert!(!identical, "{name}: mdat must carry the payload");
                } else {
                    assert!(identical, "{name}: box `{tag}` must be byte-identical");
                }
            }
        }
    }

    /// Fragmented files and the compact size table are rejected explicitly
    /// instead of producing spans from tables the parser cannot resolve.
    #[test]
    #[ignore = "requires the local temp/testhevc corpus"]
    pub fn local_hevc_mp4_rejects_unsupported_variants() {
        let Some(dir) = corpus_dir() else {
            eprintln!("[SKIP] testhevc corpus not found");
            return;
        };
        let cover_path = dir.join(CORPUS[0]);
        if !cover_path.is_file() {
            eprintln!("[SKIP] {} missing", CORPUS[0]);
            return;
        }
        let cover = fs::read(&cover_path).expect("read cover");
        assert!(parse_mp4_targets(&cover).is_ok());

        // A `moof` at the top level: samples live in fragments.
        let mut fragmented = cover.clone();
        let mut moof = 16u32.to_be_bytes().to_vec();
        moof.extend_from_slice(b"moof");
        moof.extend_from_slice(&[0u8; 8]);
        fragmented.extend_from_slice(&moof);
        assert!(
            parse_mp4_targets(&fragmented).is_err(),
            "a fragmented MP4 must be rejected"
        );

        // `stsz` renamed to `stz2`: the only size table present is the
        // compact form the parser refuses.
        let mut compact = cover.clone();
        let stsz = payload_offset(&compact, b"stsz").expect("stsz present");
        compact[stsz - 4..stsz].copy_from_slice(b"stz2");
        assert!(
            parse_mp4_targets(&compact).is_err(),
            "an stz2-only sample table must be rejected"
        );
    }
}
