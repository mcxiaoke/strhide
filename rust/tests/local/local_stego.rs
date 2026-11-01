//! Local steganography regression tests.
//!
//! Run with:
//! ```text
//! cargo test --release --test local_tests local_v3 -- --ignored --nocapture
//! ```

pub mod v3_corpus {
    use rayon::prelude::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use strhide::core::payload::Payload;
    use strhide::errors::StrHideError;
    use strhide::stego::{
        EmbedOptions, JpegAlgorithm, JpegParams, StegoTuning, embed_carrier, extract_carrier,
    };

    fn corpus(rel: &str) -> Option<PathBuf> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let local = root.join("temp").join(rel);
        if local.exists() {
            return Some(local);
        }
        for key in ["STRHIDE_CORPUS", "STRHIDE_STEGO_CORPUS"] {
            if let Ok(dir) = std::env::var(key) {
                let p = PathBuf::from(&dir).join(rel);
                if p.exists() {
                    return Some(p);
                }
                if let Some(name) = std::path::Path::new(rel).file_name() {
                    let p = PathBuf::from(&dir).join(name);
                    if p.exists() {
                        return Some(p);
                    }
                }
            }
        }
        None
    }

    fn incompressible(len: usize, seed: u64) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ seed;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    fn password_options(password: &str) -> EmbedOptions<'_> {
        EmbedOptions {
            password: Some(password),
            ..Default::default()
        }
    }

    #[test]
    #[ignore]
    pub fn local_v3_payload_matrix_twenty_images() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("temp")
            .join("images")
            .join("jpg");
        let mut files: Vec<PathBuf> = match std::fs::read_dir(&root) {
            Ok(entries) => entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("jpg")))
                .collect(),
            Err(_) => return,
        };
        files.sort();
        files.truncate(20);
        if files.is_empty() {
            return;
        }

        let password = "MatrixGate#2026";
        let opts = EmbedOptions {
            tuning: StegoTuning::Jpeg {
                model: JpegAlgorithm::Uerd,
                params: JpegParams::default(),
            },
            password: Some(password),
            ..Default::default()
        };
        let done = AtomicUsize::new(0);
        files.par_iter().for_each(|path| {
            let cover = std::fs::read(path).expect("read cover");
            for size in [4096usize, 16384, 65536] {
                let payload = incompressible(size, (size as u64) ^ 0x5EED);
                let stego = match embed_carrier(&cover, &Payload::bytes(&payload), &opts) {
                    Ok(stego) => stego,
                    Err(StrHideError::General(message))
                        if message.contains("Capacity exceeded") =>
                    {
                        continue;
                    }
                    Err(e) => panic!("{}: {size} B: embed failed: {e}", path.display()),
                };
                let recovered =
                    extract_carrier(&stego, &opts.extract_options()).unwrap_or_else(|e| {
                        panic!("{}: {size} B: extract failed: {e}", path.display())
                    });
                assert_eq!(recovered, payload, "{}: {size} B", path.display());
                done.fetch_add(1, Ordering::Relaxed);
            }
        });
        let done_count = done.load(Ordering::Relaxed);
        println!("{done_count} roundtrips across {} carriers", files.len());
        assert!(
            done_count >= 30,
            "expected at least 30 roundtrips, got {done_count}"
        );
    }

    #[test]
    #[ignore]
    pub fn local_v3_huffman_corpus_roundtrips() {
        let Some(std_dir) = corpus("jpeg_huffman/std") else {
            return;
        };
        let Some(opt_dir) = corpus("jpeg_huffman/opt") else {
            return;
        };
        let payload = incompressible(4096, 0xC0FFEE);
        let password = "HuffmanCorpus#1";

        let mut checked = 0usize;
        let mut groups: Vec<(Vec<PathBuf>, Option<bool>)> = Vec::new();
        for (dir, expect_complete) in [(std_dir, true), (opt_dir, false)] {
            let mut files: Vec<PathBuf> = fs::read_dir(&dir)
                .expect("read dir")
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("jpg")))
                .collect();
            files.sort();
            assert!(!files.is_empty(), "no JPEGs in {}", dir.display());
            groups.push((files, Some(expect_complete)));
        }
        let extras: Vec<PathBuf> = ["testfiles/file-08.jpg", "real_samples/sample.jpg"]
            .iter()
            .filter_map(|rel| corpus(rel))
            .collect();
        if !extras.is_empty() {
            groups.push((extras, None));
        }

        for (files, expect_complete) in groups {
            for path in files {
                let cover = fs::read(&path).expect("read");
                let symbols =
                    strhide::stego::jpeg::dht::luma_ac_symbols(&cover).expect("parse DHT");
                if let Some(expected) = expect_complete {
                    assert_eq!(
                        symbols.is_complete(),
                        expected,
                        "{}: table completeness",
                        path.display()
                    );
                }
                let stego = embed_carrier(
                    &cover,
                    &Payload::bytes(&payload),
                    &password_options(password),
                )
                .unwrap_or_else(|e| panic!("{}: embed failed: {e}", path.display()));
                let recovered =
                    extract_carrier(&stego, &password_options(password).extract_options())
                        .unwrap_or_else(|e| panic!("{}: extract failed: {e}", path.display()));
                assert_eq!(recovered, payload, "{}", path.display());
                checked += 1;
            }
        }
        println!("{checked} over-optimised/standard table carriers round-tripped");
    }
}
