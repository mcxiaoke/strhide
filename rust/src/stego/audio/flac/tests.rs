use super::*;

fn hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn md5_of(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    hex(&hasher.finish())
}

/// The writer rewrites the STREAMINFO MD5 at the fixed `MD5_OFFSET`, so a
/// stream whose STREAMINFO sits anywhere else must be refused: patching its
/// MD5 at offset 26 would overwrite the first block's payload and leave the
/// real MD5 stale, giving a carrier that embeds fine and never extracts.
#[test]
fn streaminfo_must_be_the_first_metadata_block() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"fLaC");
    bytes.push(0x04); // VORBIS_COMMENT, not last, length 0
    bytes.extend_from_slice(&[0, 0, 0]);
    bytes.push(0x80); // STREAMINFO, last
    bytes.extend_from_slice(&[0, 0, 34]);
    bytes.extend_from_slice(&[7u8; 34]);

    let err = parse_stream_info(&bytes).expect_err("non-leading STREAMINFO must be refused");
    assert!(
        matches!(err, StrHideError::CorruptedData(_)),
        "unexpected error: {err:?}"
    );

    // A leading STREAMINFO of the wrong length cannot be trusted either.
    let mut short = Vec::new();
    short.extend_from_slice(b"fLaC");
    short.push(0x80);
    short.extend_from_slice(&[0, 0, 33]);
    short.extend_from_slice(&[7u8; 34]);
    let err = parse_stream_info(&short).expect_err("short STREAMINFO must be refused");
    assert!(
        matches!(err, StrHideError::CorruptedData(_)),
        "unexpected error: {err:?}"
    );
}

#[test]
fn flac_metadata_malformed_branches_are_rejected() {
    // Helper to construct a valid 34-byte STREAMINFO block
    let make_streaminfo = |min_bs: u16, max_bs: u16, bps: u8| -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"fLaC");
        v.push(0x80); // STREAMINFO, last
        v.extend_from_slice(&[0, 0, 34]);
        let mut info = [0u8; 34];
        info[0..2].copy_from_slice(&min_bs.to_be_bytes());
        info[2..4].copy_from_slice(&max_bs.to_be_bytes());
        // packed: sample_rate (20), channels - 1 (3), bps - 1 (5), samples (36)
        let sample_rate = 44100u64;
        let channels = 2u64;
        let bits = bps.saturating_sub(1) as u64;
        let packed = (sample_rate << 44) | ((channels - 1) << 41) | (bits << 36) | 1000;
        info[10..18].copy_from_slice(&packed.to_be_bytes());
        v.extend_from_slice(&info);
        v
    };

    // 1. Block runs past the end of file (second block declared 100 bytes, only 5 present)
    let mut past_eof = make_streaminfo(4096, 4096, 16);
    past_eof[4] &= 0x7F; // STREAMINFO not last
    past_eof.push(0x84); // VORBIS_COMMENT, last
    past_eof.extend_from_slice(&[0, 0, 100]); // declared 100 bytes
    past_eof.extend_from_slice(&[0u8; 5]); // only 5 bytes
    let err = parse_stream_info(&past_eof).expect_err("block past EOF");
    assert!(matches!(err, StrHideError::CorruptedData(_)));

    // 2. Zero block size
    let zero_bs = make_streaminfo(0, 4096, 16);
    let err = parse_stream_info(&zero_bs).expect_err("zero min block size");
    assert!(matches!(err, StrHideError::CorruptedData(_)));

    // 3. Invalid bit depth (< 4 or > 32)
    let invalid_bps = make_streaminfo(4096, 4096, 2);
    let err = parse_stream_info(&invalid_bps).expect_err("bps < 4");
    assert!(matches!(err, StrHideError::UnsupportedFormat(_)));
}

#[test]
fn md5_matches_known_vectors() {
    assert_eq!(md5_of(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5_of(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        md5_of(b"The quick brown fox jumps over the lazy dog"),
        "9e107d9d372bb6826bd81d3542a419d6"
    );
    // A multi-block message exercises the 64-byte path and the padding.
    let long = vec![b'a'; 1000];
    assert_eq!(md5_of(&long), "cabe45dcc9ae5b66ba86600cca6b8ba8");
}

#[test]
fn md5_absorb_matches_a_flat_byte_stream() {
    // Interleaved little-endian samples must hash exactly like the byte
    // stream a decoder would feed the same MD5.
    let left = vec![1i64, -2, 300];
    let right = vec![-1i64, 2, -300];
    let mut hasher = Md5::new();
    hasher.absorb(&[left.clone(), right.clone()], 2);
    let mut flat = Vec::new();
    for i in 0..3 {
        flat.extend_from_slice(&(left[i] as i16).to_le_bytes());
        flat.extend_from_slice(&(right[i] as i16).to_le_bytes());
    }
    assert_eq!(hasher.finish(), {
        let mut h = Md5::new();
        h.update(&flat);
        h.finish()
    });
}

/// Corpus harness: decodes every `*.flac` under `STRHIDE_FLAC_CORPUS` and
/// reports, per file, whether the decoded PCM matches `STREAMINFO`.
///
/// Ignored by default (it needs a corpus on disk); run with
/// `STRHIDE_FLAC_CORPUS=<dir> cargo test --all-features --lib flac_corpus -- --ignored --nocapture`.
#[test]
#[ignore]
fn flac_corpus_validates() {
    let dir = match std::env::var("STRHIDE_FLAC_CORPUS") {
        Ok(dir) => dir,
        Err(_) => return,
    };
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("corpus dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "flac"))
        .collect();
    files.sort();

    let mut ok = 0usize;
    let mut failed = Vec::new();
    for path in &files {
        let bytes = std::fs::read(path).expect("read");
        let info = match parse_stream_info(&bytes) {
            Ok(info) => info,
            Err(e) => {
                failed.push(format!("{}: {e}", path.display()));
                continue;
            }
        };
        match analyse(&bytes, &info) {
            Ok(analysis) => {
                if analysis.pcm_md5 == info.md5 || info.md5 == [0u8; 16] {
                    ok += 1;
                    println!(
                        "OK   {} ({} slots, {} samples)",
                        path.display(),
                        analysis.slots,
                        info.total_samples
                    );
                } else {
                    failed.push(format!("{}: MD5 mismatch", path.display()));
                }
            }
            Err(e) => failed.push(format!("{}: {e}", path.display())),
        }
    }
    println!(
        "
{ok} / {} files validated",
        files.len()
    );
    for line in &failed {
        println!("FAIL {line}");
    }
    assert!(
        failed.is_empty(),
        "{} of {} FLAC files could not be validated",
        failed.len(),
        files.len()
    );
}

#[test]
fn rejects_a_file_without_the_flac_marker() {
    let err = parse_stream_info(b"RIFF....WAVE................").unwrap_err();
    assert!(err.to_string().contains("fLaC"));
}

#[test]
fn slot_offsets_keep_bits_above_u32() {
    // Simulating a >512 MiB carrier: a 16-bit mono stream stores one bit
    // per sample in the residual domain, so offsets above 2^32 only occur
    // past ~512 MiB. Writing such a file in a unit test is wasteful, and
    // the arithmetic under test (`usize` -> slot offset) is identical at
    // any magnitude, so a synthetic offset just over u32::MAX stands in
    // for the real one. The old `as u32` wrapped here and addressed the
    // wrong codeword.
    let big = u32::MAX as usize + 8;
    let parsed = frame::ParsedFrame {
        start: 0,
        samples: vec![vec![0i64; 4]],
        wasted: vec![0],
        crc16_offset: 0,
        slots: Vec::new(),
        comps: vec![frame::Compensation {
            bit_offset: big,
            k: 0,
            value: 0,
            plus: 0,
            minus: 0,
            rice: true,
        }],
        tails: Vec::new(),
    };
    let slot = frame::ResidualSlot {
        bit_offset: big,
        k: 0,
        value: 0,
        channel: 0,
        sample_index: 0,
        comp_start: 0,
        comp_len: 1,
    };
    let scale = PcmScale::new(16, 0);
    let made = make_slot(&slot, &parsed, &scale).expect("slot");
    assert_eq!(made.bit_offset, big as u64);
    assert_eq!(made.comp[0].bit_offset, big as u64);
}
